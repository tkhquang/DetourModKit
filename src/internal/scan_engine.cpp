/**
 * @file internal/scan_engine.cpp
 * @brief Raw AOB matching engine: anchor selection, the memchr-prefiltered SIMD match loop, parse_aob, and runtime
 *        SIMD-tier detection.
 * @details The matcher is logger-free and backend-free: the public scan module screens inputs and reports diagnostics;
 *          this engine only finds bytes. The SIMD verify tiers (SSE2 baseline, runtime-gated AVX2, opt-in runtime-gated
 *          AVX-512) sit behind an ASan-safe self-provided memchr prefilter, so the hot path never calls into a libc
 *          interceptor that would inspect the scanner's deliberate cross-region reads.
 */

#include "internal/scan_engine.hpp"

#include "DetourModKit/detail/pattern_core.hpp"

#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <vector>

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#define DMK_HAS_SSE2 1
#include <emmintrin.h>
#endif

// AVX2 support: compile-time header + runtime CPUID detection. On GCC/Clang, AVX2 intrinsics require either -mavx2
// globally or
// __attribute__((target("avx2"))) per function. We use the latter so the rest of the TU stays SSE2-only and runs on any
// x86-64 CPU. On MSVC, intrinsics are always available; runtime CPUID gates usage.
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#define DMK_HAS_AVX2 1
#include <immintrin.h>
#include <cpuid.h>
#define DMK_AVX2_TARGET __attribute__((target("avx2")))
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#define DMK_HAS_AVX2 1
#include <immintrin.h>
#include <intrin.h>
#define DMK_AVX2_TARGET
#endif

// AVX-512 verify tier: opt-in, off by default. Gated behind the DMK_ENABLE_AVX512 build option rather than a global
// /arch:AVX512 or -mavx512 flag, because enabling it must NOT let the compiler emit AVX-512 across the whole TU -- that
// would fault with #UD on the majority of CPUs that lack AVX-512. When the option is on, the verify tier is compiled
// with a per-function target attribute on GCC/Clang (exactly like the AVX2 tier), so the rest of the TU stays
// AVX2-only and runs anywhere; the tier is reached only after the runtime cpu_has_avx512() gate confirms both the CPU
// and the OS support it. Byte-granular masked compare (_mm512_test_epi8_mask) is an AVX-512BW instruction, so the gate
// requires AVX-512F + AVX-512BW, not F alone.
#if defined(DMK_ENABLE_AVX512) && defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#define DMK_HAS_AVX512 1
#include <immintrin.h>
#define DMK_AVX512_TARGET __attribute__((target("avx512f,avx512bw")))
#elif defined(DMK_ENABLE_AVX512) && defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#define DMK_HAS_AVX512 1
#include <immintrin.h>
#define DMK_AVX512_TARGET
#endif

// AddressSanitizer poisons the shadow of this process's own committed, readable memory -- the redzones around stack
// locals and instrumented globals. The AOB scanner deliberately reads across whole readable regions, so under ASan its
// in-bounds, never-faulting reads land on poisoned shadow and are reported as overflows. DMK_NO_SANITIZE_ADDRESS
// removes the compiler's load instrumentation from such a function, so the read runs exactly as a release build does.
// It does NOT stop ASan's libc interceptors (memchr/memcpy are hot-patched at runtime); the scanner therefore routes
// the prefilter through a self-provided dmk_memchr that does its own byte comparisons and never calls into libc. The
// attribute also covers the verify path's instrumented SIMD/scalar loads. ASan links only under MSVC here (mingw-w64
// ships no sanitizer runtime), so the attribute is the MSVC __declspec form; the macro is empty in every other build,
// leaving release codegen unchanged.
#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)
#define DMK_NO_SANITIZE_ADDRESS __declspec(no_sanitize_address)
#else
#define DMK_NO_SANITIZE_ADDRESS
#endif

namespace DetourModKit
{
    namespace
    {
#if defined(DMK_HAS_AVX2) || defined(DMK_HAS_AVX512)
        constexpr unsigned int CPUID_ECX_XSAVE = 1u << 26;
        constexpr unsigned int CPUID_ECX_OSXSAVE = 1u << 27;
        constexpr unsigned int CPUID_ECX_AVX = 1u << 28;
        constexpr unsigned int XCR0_SSE = 1u << 1;
        constexpr unsigned int XCR0_AVX = 1u << 2;
        constexpr unsigned int XCR0_OPMASK = 1u << 5;
        constexpr unsigned int XCR0_ZMM_HI256 = 1u << 6;
        constexpr unsigned int XCR0_HI16_ZMM = 1u << 7;
        constexpr unsigned int XCR0_AVX512_STATE = XCR0_SSE | XCR0_AVX | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;

        /**
         * @brief Tests CPUID leaf 1 ECX feature bits.
         * @param required_bits Bit mask that must be present in ECX.
         * @return True when every requested leaf 1 ECX feature bit is set.
         */
        bool cpu_leaf1_ecx_has(unsigned int required_bits) noexcept
        {
#if defined(__GNUC__) || defined(__clang__)
            unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
            if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
                return false;
            return (ecx & required_bits) == required_bits;
#elif defined(_MSC_VER)
            int cpui[4]{};
            __cpuidex(cpui, 1, 0);
            const unsigned int ecx = static_cast<unsigned int>(cpui[2]);
            return (ecx & required_bits) == required_bits;
#else
            return false;
#endif
        }

        /**
         * @brief Tests whether the OS has enabled the requested XCR0 SIMD register state.
         * @param required_mask XCR0 bit mask that must be enabled by the OS.
         * @return True when XGETBV is legal to execute and XCR0 contains every requested bit.
         */
        bool xcr0_has_enabled_state(unsigned int required_mask) noexcept
        {
            if (!cpu_leaf1_ecx_has(CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE))
            {
                return false;
            }

#if defined(__GNUC__) || defined(__clang__)
            unsigned int xcr0_lo = 0, xcr0_hi = 0;
            __asm__ volatile("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
            (void)xcr0_hi;
            return (xcr0_lo & required_mask) == required_mask;
#elif defined(_MSC_VER)
            const unsigned long long xcr0 = _xgetbv(0);
            return (xcr0 & required_mask) == required_mask;
#else
            return false;
#endif
        }
#endif

#ifdef DMK_HAS_AVX2
        /**
         * @brief Detects AVX2 support at runtime via CPUID.
         * @details Checks CPUID leaf 1 ECX bit 28 (AVX) plus CPUID leaf 7 subleaf 0 EBX bit 5 (AVX2), then verifies
         * that
         *          the OS has enabled SSE and AVX register state in XCR0. Result is cached in a function-local static.
         */
        bool cpu_has_avx2() noexcept
        {
            static const bool result = []() -> bool
            {
#if defined(__GNUC__) || defined(__clang__)
                unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
                if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
                    return false;
                const bool avx2_flag = (ebx & (1u << 5)) != 0;

                return cpu_leaf1_ecx_has(CPUID_ECX_AVX) && avx2_flag && xcr0_has_enabled_state(XCR0_SSE | XCR0_AVX);
#elif defined(_MSC_VER)
                int cpui[4]{};
                __cpuidex(cpui, 7, 0);
                const bool avx2_flag = (cpui[1] & (1 << 5)) != 0;

                return cpu_leaf1_ecx_has(CPUID_ECX_AVX) && avx2_flag && xcr0_has_enabled_state(XCR0_SSE | XCR0_AVX);
#else
                return false;
#endif
            }();
            return result;
        }
        /**
         * @brief Verifies a pattern match using AVX2 (32 bytes per iteration).
         * @param pattern_start Start of the candidate region in memory.
         * @param pattern The compiled pattern to verify against.
         * @param start_offset Byte offset to start verification from (may be non-zero if a previous tier partially
         *                     verified).
         * @return The next byte offset to resume verification from on success (equal to pattern.size() when the AVX2
         * tier
         *         covered the whole pattern), or std::nullopt when a 32-byte chunk did not match and the caller must
         *         abandon this candidate position.
         * @note This function is compiled with AVX2 codegen via target attribute on
         *       GCC/Clang. On MSVC, intrinsics are always available.
         */
        DMK_AVX2_TARGET
        DMK_NO_SANITIZE_ADDRESS
        std::optional<std::size_t> verify_pattern_avx2(const std::byte *pattern_start,
                                                       const detail::EnginePattern &pattern,
                                                       std::size_t start_offset) noexcept
        {
            const std::size_t pattern_size = pattern.size();
            std::size_t j = start_offset;

            for (; j + 32 <= pattern_size; j += 32)
            {
                const __m256i mem = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(pattern_start + j));
                const __m256i pat = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(pattern.bytes.data() + j));
                const __m256i msk = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(pattern.mask.data() + j));

                const __m256i xored = _mm256_xor_si256(mem, pat);
                const __m256i masked = _mm256_and_si256(xored, msk);
                const __m256i cmp = _mm256_cmpeq_epi8(masked, _mm256_setzero_si256());

                if (static_cast<unsigned int>(_mm256_movemask_epi8(cmp)) != 0xFFFFFFFFu)
                {
                    return std::nullopt;
                }
            }

            return j;
        }
#endif // DMK_HAS_AVX2

#ifdef DMK_HAS_AVX512
        /**
         * @brief Detects AVX-512F + AVX-512BW support at runtime via CPUID and XGETBV.
         * @details Checks CPUID leaf 7 subleaf 0, EBX bit 16 (AVX-512F) and bit 30 (AVX-512BW). Byte-granular masked
         *          compare is a BW instruction, so both are required. Also verifies the OS has enabled the full opmask
         *          / ZMM register state via XGETBV (XCR0 bits 1,2,5,6,7); a CPU that reports AVX-512 while the OS has
         *          not enabled the state must fail closed. Result is cached in a function-local static.
         */
        bool cpu_has_avx512() noexcept
        {
            static const bool result = []() -> bool
            {
#if defined(__GNUC__) || defined(__clang__)
                unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
                if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
                    return false;
                const bool avx512f = (ebx & (1u << 16)) != 0;
                const bool avx512bw = (ebx & (1u << 30)) != 0;

                return cpu_leaf1_ecx_has(CPUID_ECX_AVX) && avx512f && avx512bw &&
                       xcr0_has_enabled_state(XCR0_AVX512_STATE);
#elif defined(_MSC_VER)
                int cpui[4]{};
                __cpuidex(cpui, 7, 0);
                const bool avx512f = (cpui[1] & (1 << 16)) != 0;
                const bool avx512bw = (cpui[1] & (1 << 30)) != 0;

                return cpu_leaf1_ecx_has(CPUID_ECX_AVX) && avx512f && avx512bw &&
                       xcr0_has_enabled_state(XCR0_AVX512_STATE);
#else
                return false;
#endif
            }();
            return result;
        }

        /**
         * @brief Verifies a pattern match using AVX-512 (64 bytes per iteration).
         * @param pattern_start Start of the candidate region in memory.
         * @param pattern The compiled pattern to verify against.
         * @param start_offset Byte offset to start verification from (may be non-zero if a previous tier partially
         *                     verified).
         * @return The next byte offset to resume verification from on success (equal to start_offset plus a multiple of
         *         64 once the AVX-512 tier covered whole 64-byte chunks), or std::nullopt when a 64-byte chunk did not
         *         match and the caller must abandon this candidate position.
         * @note Compiled with AVX-512F + AVX-512BW codegen via target attribute on GCC/Clang; on MSVC the intrinsics
         * are
         *       always available. Only entered after cpu_has_avx512() has confirmed CPU and OS support.
         */
        DMK_AVX512_TARGET
        DMK_NO_SANITIZE_ADDRESS
        std::optional<std::size_t> verify_pattern_avx512(const std::byte *pattern_start,
                                                         const detail::EnginePattern &pattern,
                                                         std::size_t start_offset) noexcept
        {
            const std::size_t pattern_size = pattern.size();
            std::size_t j = start_offset;

            for (; j + 64 <= pattern_size; j += 64)
            {
                const __m512i mem = _mm512_loadu_si512(reinterpret_cast<const void *>(pattern_start + j));
                const __m512i pat = _mm512_loadu_si512(reinterpret_cast<const void *>(pattern.bytes.data() + j));
                const __m512i msk = _mm512_loadu_si512(reinterpret_cast<const void *>(pattern.mask.data() + j));

                // (mem ^ pat) & mask is zero in every matching byte: a wildcard lane (mask 0x00) clears to zero, and a
                // literal lane (mask 0xFF) keeps the xor, which is zero only on an exact byte match. test_epi8_mask
                // sets a bit per byte whose masked value is nonzero -- i.e. a mismatch -- so any nonzero result fails
                // the chunk.
                const __m512i xored = _mm512_xor_si512(mem, pat);
                const __m512i masked = _mm512_and_si512(xored, msk);
                if (_mm512_test_epi8_mask(masked, masked) != 0)
                {
                    return std::nullopt;
                }
            }

            return j;
        }
#endif // DMK_HAS_AVX512

        /**
         * @brief Picks the rarest fully-known byte's index in segment 0 of a compiled pattern.
         * @return The byte index in segment 0 with the lowest frequency score, or `pattern.size()` when segment 0 has
         * no
         *         fully-known literal byte (every position is a wildcard or only partially masked).
         * @details Confined to segment 0 (the fixed run before the first bounded jump; the whole pattern when
         * jump-free)
         *          because the matcher locates that run first and extends across the variable gaps, so only a segment-0
         *          byte sits at a fixed offset the memchr prefilter can sweep for.
         */
        std::size_t select_pattern_anchor(const detail::EnginePattern &pattern) noexcept
        {
            const std::size_t pattern_size = pattern.size();
            const std::size_t segment0_end = pattern.jumps.empty() ? pattern_size : pattern.jumps.front().position;
            std::size_t best = pattern_size;
            std::uint8_t best_score = UINT8_MAX;
            for (std::size_t i = 0; i < segment0_end; ++i)
            {
                // Only a fully-known byte (mask 0xFF) can anchor the memchr / SIMD prefilter, which searches for one
                // exact byte value. A wildcard (mask 0x00) or a partially-masked nibble byte (0xF0 / 0x0F) carries no
                // single byte value to scan for, so it is never an anchor candidate.
                if (pattern.mask[i] != std::byte{0xFF})
                {
                    continue;
                }
                const std::uint8_t score =
                    detail::byte_frequency_class(std::to_integer<std::uint8_t>(pattern.bytes[i]));
                if (best == pattern_size || score < best_score)
                {
                    best = i;
                    best_score = score;
                    if (score == 0)
                    {
                        break;
                    }
                }
            }
            return best;
        }
    } // anonymous namespace

    void detail::EnginePattern::compile_anchor() noexcept
    {
        anchor = select_pattern_anchor(*this);
    }

    bool detail::pattern_has_literal_byte(const detail::EnginePattern &pattern) noexcept
    {
        for (const std::byte mask_byte : pattern.mask)
        {
            if (mask_byte != std::byte{0x00})
                return true;
        }
        return false;
    }

    namespace
    {
        // Heap-backed storage sink for the runtime AOB parse. It drives the one shared grammar
        // (detail::parse_pattern_into) so the runtime engine and the compile-time scan::Pattern can never diverge on
        // the DSL, but -- unlike the fixed-array compile-time sink -- it imposes no byte cap: the growable
        // EnginePattern has none, so a long runtime pattern (for example the byte pattern find_string_xref builds from
        // a long search string) compiles here even though the same length would overflow the literal Pattern's
        // MAX_PATTERN_BYTES inline storage. The jump count is still capped at MAX_PATTERN_JUMPS because the segmented
        // matcher indexes a fixed-size segment-start array bounded by it.
        struct EnginePatternSink
        {
            detail::EnginePattern pattern;

            [[nodiscard]] std::size_t length() const noexcept { return pattern.bytes.size(); }
            [[nodiscard]] std::size_t jump_count() const noexcept { return pattern.jumps.size(); }

            [[nodiscard]] bool add_byte(std::byte value, std::byte mask)
            {
                pattern.bytes.push_back(value);
                pattern.mask.push_back(mask);
                return true;
            }

            [[nodiscard]] bool add_jump(std::size_t position, std::size_t min_skip, std::size_t max_skip)
            {
                if (pattern.jumps.size() >= detail::MAX_PATTERN_JUMPS)
                {
                    return false;
                }
                pattern.jumps.push_back(detail::PatternJump{position, min_skip, max_skip});
                return true;
            }

            void set_offset(std::size_t position) noexcept { pattern.offset = static_cast<std::ptrdiff_t>(position); }
        };
    } // namespace

    std::optional<detail::EnginePattern> detail::parse_aob(std::string_view aob_str)
    {
        // Parse through the shared grammar into a heap-backed sink so the runtime engine and scan::Pattern accept the
        // same DSL, while long runtime patterns keep using growable storage instead of the literal type's fixed cap.
        // The heap-backed sink grows the pattern vectors as it parses, so an adversarial or very long AOB (a string of
        // arbitrary length routed here by find_string_xref) can exhaust memory. Catch that here and fail closed to
        // nullopt rather than letting bad_alloc escape -- parse_aob's callers already treat nullopt as an unusable
        // pattern, so this degrades to a clean scan miss instead of terminating the host.
        try
        {
            EnginePatternSink sink;
            if (detail::parse_pattern_into(aob_str, sink) != detail::PatternStatus::Ok)
            {
                return std::nullopt;
            }
            // The anchor is storage-specific, so it is computed here rather than in the shared grammar: select it over
            // segment 0 with the engine's size() "no fully-known byte" sentinel.
            sink.pattern.compile_anchor();
            return std::move(sink.pattern);
        }
        catch (const std::bad_alloc &)
        {
            return std::nullopt;
        }
    }

    detail::EnginePattern detail::engine_pattern_from(const scan::Pattern &pattern, std::size_t anchor_index)
    {
        const std::span<const std::byte> bytes = pattern.bytes();
        const std::span<const std::byte> mask = pattern.mask();
        const detail::PatternBuffer &data = detail::pattern_buffer(pattern);
        const std::span<const detail::PatternJump> jumps(data.jumps.data(), data.jump_count);
        EnginePattern compiled;
        compiled.bytes.assign(bytes.begin(), bytes.end());
        compiled.mask.assign(mask.begin(), mask.end());
        compiled.jumps.assign(jumps.begin(), jumps.end());
        compiled.offset = static_cast<std::ptrdiff_t>(pattern.offset());
        compiled.anchor = anchor_index;
        return compiled;
    }

    namespace
    {
        // Self-provided memchr over [haystack, haystack + n) for the anchor byte. Routing the prefilter through libc
        // memchr works in release, but under AddressSanitizer the runtime interceptor inspects the whole range against
        // ASan's shadow and reports a false overflow when the scanner walks this process's own committed, readable
        // memory (the poisoned shadow around stack locals and instrumented globals). The runtime interceptor bypasses
        // any no_sanitize_address attribute on the caller, so a per-function escape hatch is not enough: the function
        // itself must do the byte comparisons.
        //
        // The needle search is tiered the same way the verify path is. On x86-64 the SSE2 body (16 bytes per iteration)
        // is always available -- SSE2 is part of the x86-64 baseline, so no runtime gate is needed -- and an AVX2 body
        // (32 bytes per iteration) is selected at runtime through the same cpu_has_avx2() gate the verify tier uses.
        // Each SIMD body broadcasts the needle into every lane, compares a whole vector against it with one PCMPEQB,
        // and collapses the per-byte result to a movemask bitmask; count-trailing-zeros on the first nonzero mask gives
        // the lane index of the first match, so the search keeps libc memchr's "lowest address wins" contract. A scalar
        // byte loop finishes the sub-vector tail and is the only body on targets without SSE2 (32-bit x86 built without
        // it). None of the tiers call into libc, so the ASan interceptor never sees the read; the explicit intrinsics
        // also use unaligned loads, so there is no type-punned qword load for clang-cl's strict-aliasing TBAA to
        // miscompile.

#if defined(DMK_HAS_SSE2) || defined(DMK_HAS_AVX2)
        /// Count-trailing-zeros over a known-nonzero movemask result; yields the first matching byte's lane index.
        inline unsigned dmk_movemask_first_index(unsigned int mask) noexcept
        {
#if defined(_MSC_VER) && !defined(__clang__)
            unsigned long index = 0;
            _BitScanForward(&index, mask);
            return static_cast<unsigned>(index);
#else
            return static_cast<unsigned>(__builtin_ctz(mask));
#endif
        }
#endif // DMK_HAS_SSE2 || DMK_HAS_AVX2

#ifdef DMK_HAS_SSE2
        // SSE2 needle search over [p, p + n): a 16-byte body plus a scalar tail. No runtime gate -- DMK_HAS_SSE2
        // implies the target is x86-64 (or x86 built with SSE2), where these instructions are always legal.
        DMK_NO_SANITIZE_ADDRESS
        const unsigned char *dmk_memchr_sse2(const unsigned char *p, unsigned char needle, std::size_t n) noexcept
        {
            const __m128i needle_vec = _mm_set1_epi8(static_cast<char>(needle));
            for (; n >= 16; p += 16, n -= 16)
            {
                const __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i *>(p));
                const unsigned int mask =
                    static_cast<unsigned int>(_mm_movemask_epi8(_mm_cmpeq_epi8(chunk, needle_vec)));
                if (mask != 0)
                {
                    return p + dmk_movemask_first_index(mask);
                }
            }
            for (; n > 0; ++p, --n)
            {
                if (*p == needle)
                {
                    return p;
                }
            }
            return nullptr;
        }
#endif // DMK_HAS_SSE2

#ifdef DMK_HAS_AVX2
        // AVX2 needle search over [p, p + n): a 32-byte body plus a scalar tail. Compiled with AVX2 codegen via the
        // target attribute on GCC/Clang so the rest of the TU stays SSE2-only, and only entered after cpu_has_avx2()
        // has confirmed both the CPU and the OS support the instructions. The tail is scalar rather than an SSE2 call
        // so the body emits no legacy-SSE encoding and the compiler has no VEX/legacy transition to reconcile on the
        // way out.
        DMK_AVX2_TARGET
        DMK_NO_SANITIZE_ADDRESS
        const unsigned char *dmk_memchr_avx2(const unsigned char *p, unsigned char needle, std::size_t n) noexcept
        {
            const __m256i needle_vec = _mm256_set1_epi8(static_cast<char>(needle));
            for (; n >= 32; p += 32, n -= 32)
            {
                const __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(p));
                const unsigned int mask =
                    static_cast<unsigned int>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, needle_vec)));
                if (mask != 0)
                {
                    return p + dmk_movemask_first_index(mask);
                }
            }
            for (; n > 0; ++p, --n)
            {
                if (*p == needle)
                {
                    return p;
                }
            }
            return nullptr;
        }
#endif // DMK_HAS_AVX2

        // use_avx2 is hoisted by find_pattern_raw so the per-anchor-hit sweep never re-reads the cpu_has_avx2() static.
        DMK_NO_SANITIZE_ADDRESS
        const void *dmk_memchr(const void *haystack, unsigned char needle, std::size_t n,
                               [[maybe_unused]] bool use_avx2) noexcept
        {
            if (n == 0)
            {
                return nullptr;
            }
            const auto *p = static_cast<const unsigned char *>(haystack);

#ifdef DMK_HAS_AVX2
            // The 32-byte body only pays for itself once a full vector is in play; shorter spans skip straight to the
            // SSE2/scalar bodies, which avoids the target-switch on the tail of a sweep that has nearly run out.
            if (use_avx2 && n >= 32)
            {
                return dmk_memchr_avx2(p, needle, n);
            }
#endif
#ifdef DMK_HAS_SSE2
            return dmk_memchr_sse2(p, needle, n);
#else
            for (; n > 0; ++p, --n)
            {
                if (*p == needle)
                {
                    return p;
                }
            }
            return nullptr;
#endif
        }

        // memchr over [begin, end] for the anchor byte. Routes through the self-provided dmk_memchr above so the ASan
        // runtime cannot intercept the call. dmk_memchr returns a pointer into the range or nullptr; the wrapper
        // re-establishes the [begin, end] inclusive contract the scanner expects. use_avx2 is the caller's hoisted
        // cpu_has_avx2() result, threaded through so the prefilter does not re-read the static on every anchor hit.
        DMK_NO_SANITIZE_ADDRESS
        const std::byte *scan_for_byte(const std::byte *begin, const std::byte *end, unsigned char target,
                                       bool use_avx2) noexcept
        {
            const std::size_t n = static_cast<std::size_t>(end - begin + 1);
            return static_cast<const std::byte *>(dmk_memchr(begin, target, n, use_avx2));
        }
    } // anonymous namespace

    // Flat single-segment matcher: the memchr-anchored SIMD body, returning the match START (no offset applied).
    // Every jump-free pattern dispatches here, so the overwhelmingly common case runs the direct fixed-width fast path.
    DMK_NO_SANITIZE_ADDRESS
    static const std::byte *find_pattern_flat_start(const std::byte *start_address, std::size_t region_size,
                                                    const detail::EnginePattern &pattern) noexcept
    {
        const std::size_t pattern_size = pattern.size();

        if (pattern_size == 0 || !start_address || region_size < pattern_size)
        {
            return nullptr;
        }

        // Anchor selection: parse_aob() pre-populates pattern.anchor, so the common path is a single load. Manually
        // constructed patterns fall back to inline selection without mutating the input (preserves the
        // const-by-design contract).
        const std::size_t best_anchor =
            (pattern.anchor <= pattern_size) ? pattern.anchor : select_pattern_anchor(pattern);

        // No fully-known byte to anchor on. Two sub-cases:
        //   - The pattern is entirely wildcards (no mask bit set anywhere): the search degenerates to
        //     "always match at region start", the defined result for an all-wildcard pattern.
        //   - The pattern carries only partially-masked (nibble) bytes: there is no exact byte for the
        //     memchr / SIMD prefilter, so fall back to a masked compare at every candidate position. This
        //     path is rare -- a real signature almost always carries at least one full literal byte -- so a
        //     scalar verify is acceptable; correctness, not throughput, is the concern here.
        if (best_anchor == pattern_size)
        {
            if (!pattern_has_literal_byte(pattern))
            {
                return start_address;
            }
            const std::byte *const last_start = start_address + (region_size - pattern_size);
            for (const std::byte *pos = start_address; pos <= last_start; ++pos)
            {
                bool match_found = true;
                for (std::size_t j = 0; j < pattern_size; ++j)
                {
                    const auto mem = std::to_integer<unsigned>(pos[j]);
                    const auto pat = std::to_integer<unsigned>(pattern.bytes[j]);
                    const auto msk = std::to_integer<unsigned>(pattern.mask[j]);
                    if (((mem ^ pat) & msk) != 0)
                    {
                        match_found = false;
                        break;
                    }
                }
                if (match_found)
                {
                    return pos;
                }
            }
            return nullptr;
        }

        const std::byte target_byte = pattern.bytes[best_anchor];
        const unsigned char target_val = static_cast<unsigned char>(target_byte);

        const std::byte *search_start = start_address + best_anchor;
        const std::byte *const search_end = start_address + (region_size - pattern_size) + best_anchor;

        // Hoist runtime CPU detection. The query itself is a function-local static behind a one-shot init, but
        // reading it on every memchr hit and every verify adds an indirect load per false candidate. Caching it
        // once here lets both the prefilter sweep and the per-candidate verify branch use a register-resident bool.
        // It is defined unconditionally (false without an AVX2 build) because the prefilter takes it on every call.
#ifdef DMK_HAS_AVX2
        const bool use_avx2 = cpu_has_avx2();
#else
        const bool use_avx2 = false;
#endif
#ifdef DMK_HAS_AVX512
        const bool use_avx512 = cpu_has_avx512();
#endif

        while (search_start <= search_end)
        {
            const std::byte *current_scan_ptr = scan_for_byte(search_start, search_end, target_val, use_avx2);

            if (!current_scan_ptr)
            {
                break;
            }
            const std::byte *pattern_start = current_scan_ptr - best_anchor;

            // Verify the full pattern at this position. SIMD tiers run widest-first: AVX-512 (64B) -> AVX2 (32B) ->
            // SSE2 (16B) -> scalar (1B). Each tier resumes from the offset the previous one reached (start_offset
            // j), so the widest available tiers cover the bulk and the scalar loop only ever finishes a sub-16-byte
            // tail.
            bool match_found = true;
            std::size_t j = 0;

#ifdef DMK_HAS_AVX512
            if (use_avx512)
            {
                const auto next_j = verify_pattern_avx512(pattern_start, pattern, j);
                if (next_j.has_value())
                {
                    j = *next_j;
                }
                else
                {
                    match_found = false;
                }
            }
#endif // DMK_HAS_AVX512

#ifdef DMK_HAS_AVX2
            if (match_found && use_avx2)
            {
                const auto next_j = verify_pattern_avx2(pattern_start, pattern, j);
                if (next_j.has_value())
                {
                    j = *next_j;
                }
                else
                {
                    match_found = false;
                }
            }
#endif // DMK_HAS_AVX2

#ifdef DMK_HAS_SSE2
            for (; match_found && j + 16 <= pattern_size; j += 16)
            {
                const __m128i mem = _mm_loadu_si128(reinterpret_cast<const __m128i *>(pattern_start + j));
                const __m128i pat = _mm_loadu_si128(reinterpret_cast<const __m128i *>(pattern.bytes.data() + j));
                const __m128i msk = _mm_loadu_si128(reinterpret_cast<const __m128i *>(pattern.mask.data() + j));

                const __m128i xored = _mm_xor_si128(mem, pat);
                const __m128i masked = _mm_and_si128(xored, msk);
                const __m128i cmp = _mm_cmpeq_epi8(masked, _mm_setzero_si128());

                if (_mm_movemask_epi8(cmp) != 0xFFFF)
                {
                    match_found = false;
                    break;
                }
            }
#endif // DMK_HAS_SSE2

            for (; match_found && j < pattern_size; ++j)
            {
                // Masked compare so a partially-masked nibble byte checks only its known nibble: (mem ^ pat) & mask
                // is zero exactly when every bit the mask selects agrees. A wildcard (mask 0x00) is trivially
                // satisfied, a full literal (0xFF) compares the whole byte, and a nibble (0xF0 / 0x0F) compares one
                // nibble.
                const auto mem = std::to_integer<unsigned>(pattern_start[j]);
                const auto pat = std::to_integer<unsigned>(pattern.bytes[j]);
                const auto msk = std::to_integer<unsigned>(pattern.mask[j]);
                if (((mem ^ pat) & msk) != 0)
                {
                    match_found = false;
                }
            }

            if (match_found)
            {
                return pattern_start;
            }

            // No match, continue searching from next position.
            search_start = current_scan_ptr + 1;
        }

        return nullptr;
    }

    // Masked-compares one fixed segment run [body_begin, body_end) of the pattern against memory at addr. The caller
    // guarantees [addr, addr + (body_end - body_begin)) is inside the scanned region, so this does no bounds check. The
    // per-byte test is the same (mem ^ pat) & mask == 0 the flat verify uses, so wildcard and nibble bytes behave
    // identically here.
    DMK_NO_SANITIZE_ADDRESS
    static bool segment_run_matches(const std::byte *addr, const detail::EnginePattern &pattern, std::size_t body_begin,
                                    std::size_t body_end) noexcept
    {
        for (std::size_t i = body_begin; i < body_end; ++i)
        {
            const auto mem = std::to_integer<unsigned>(addr[i - body_begin]);
            const auto pat = std::to_integer<unsigned>(pattern.bytes[i]);
            const auto msk = std::to_integer<unsigned>(pattern.mask[i]);
            if (((mem ^ pat) & msk) != 0)
            {
                return false;
            }
        }
        return true;
    }

    // Backtracking segment extension for a bounded-jump pattern. Tries to place segment `segment_index` (and every
    // segment after it) starting at `addr`, staying within [.., region_end). On success it records each segment's
    // absolute start in segment_starts and returns true. Gap widths are tried in ascending order, so the first success
    // is the leftmost feasible placement; backtracking is required because a nearer gap position can strand a later
    // segment a farther position would satisfy. Recursion DEPTH is bounded by the segment count (<= jumps + 1); total
    // WORK is bounded by @p steps, a shared node-visit counter for this one extension tree that fails the whole tree
    // closed once it passes detail::SEGMENT_MATCH_STEP_BUDGET. Each segment run fails fast on its first literal byte,
    // so a real signature prunes to near-linear and never approaches the budget.
    DMK_NO_SANITIZE_ADDRESS
    static bool extend_segments(const detail::EnginePattern &pattern, const std::byte *addr,
                                const std::byte *region_end, std::size_t segment_index,
                                const std::byte **segment_starts, std::size_t &steps) noexcept
    {
        // Count this node and fail the extension closed once the per-position budget is spent. Fail-closed is safe
        // here: a truncated position reports no match, and the outer sweep continues to the next segment-0 candidate.
        if (++steps > detail::SEGMENT_MATCH_STEP_BUDGET)
        {
            return false;
        }

        const std::size_t jump_count = pattern.jumps.size();
        const std::size_t segment_begin = (segment_index == 0) ? 0 : pattern.jumps[segment_index - 1].position;
        const std::size_t segment_end =
            (segment_index < jump_count) ? pattern.jumps[segment_index].position : pattern.size();
        const std::size_t segment_length = segment_end - segment_begin;

        // The segment run must fit in the bytes that remain before region_end.
        if (segment_length > static_cast<std::size_t>(region_end - addr))
        {
            return false;
        }
        if (!segment_run_matches(addr, pattern, segment_begin, segment_end))
        {
            return false;
        }
        segment_starts[segment_index] = addr;
        if (segment_index == jump_count)
        {
            // The last segment matched, so the whole pattern is placed.
            return true;
        }

        const std::byte *const after = addr + segment_length;
        const detail::PatternJump &gap = pattern.jumps[segment_index];
        const std::size_t available = static_cast<std::size_t>(region_end - after);
        for (std::size_t skip = gap.min_skip; skip <= gap.max_skip; ++skip)
        {
            // Once the gap alone overruns the region no larger skip can fit either. Checking skip against the available
            // bytes before forming the pointer keeps the arithmetic in-bounds (never past region_end).
            if (skip > available)
            {
                break;
            }
            if (extend_segments(pattern, after + skip, region_end, segment_index + 1, segment_starts, steps))
            {
                return true;
            }
            // Propagate a budget-exhausted verdict up the whole tree rather than trying wider skips: once the shared
            // counter is spent, every further placement would immediately fail closed, so stop instead of spinning.
            if (steps > detail::SEGMENT_MATCH_STEP_BUDGET)
            {
                return false;
            }
        }
        return false;
    }

    // Resolves the offset-applied result point and the one-past-end pointer for a placed bounded-jump match. The `|`
    // marker records a fixed-byte index; the run-time point is the address of that fixed byte, which lives in whichever
    // segment contains the index (or the end when the marker is trailing). `end` is one past the final segment's last
    // byte -- the match's true span, which varies with the gap widths chosen.
    static detail::RawMatch segmented_result(const detail::EnginePattern &pattern,
                                             const std::byte *const *segment_starts) noexcept
    {
        const std::size_t jump_count = pattern.jumps.size();
        const std::size_t last_index = jump_count; // segment count is jump_count + 1
        const std::size_t last_begin = pattern.jumps.back().position;
        const std::byte *const end = segment_starts[last_index] + (pattern.size() - last_begin);

        const std::size_t marker = static_cast<std::size_t>(pattern.offset);
        const std::byte *point = end; // trailing marker (offset == size()) resolves to the end
        if (marker < pattern.size())
        {
            for (std::size_t segment_index = 0; segment_index <= jump_count; ++segment_index)
            {
                const std::size_t segment_begin = (segment_index == 0) ? 0 : pattern.jumps[segment_index - 1].position;
                const std::size_t segment_end =
                    (segment_index < jump_count) ? pattern.jumps[segment_index].position : pattern.size();
                if (marker >= segment_begin && marker < segment_end)
                {
                    point = segment_starts[segment_index] + (marker - segment_begin);
                    break;
                }
            }
        }
        return detail::RawMatch{segment_starts[0], end, point};
    }

    // Segmented backtracking matcher for a bounded-jump pattern. Locates segment 0 with the same memchr anchor sweep
    // the flat matcher uses (or scans every start position when segment 0 has no literal anchor), then extends across
    // the gaps. Returns the leftmost match: the smallest segment-0 start that admits a full placement.
    DMK_NO_SANITIZE_ADDRESS
    static detail::RawMatch find_pattern_segmented(const std::byte *start_address, std::size_t region_size,
                                                   const detail::EnginePattern &pattern, bool use_avx2) noexcept
    {
        const std::size_t min_length = pattern.min_match_length();
        if (region_size < min_length)
        {
            return detail::RawMatch{};
        }
        const std::byte *const region_end = start_address + region_size;
        // A segment-0 start must leave room for at least a minimum-length match.
        const std::byte *const last_candidate = start_address + (region_size - min_length);
        const std::size_t segment0_end = pattern.jumps.front().position;

        // Segment count is bounded by MAX_PATTERN_JUMPS + 1, so a fixed local array avoids any allocation on the match
        // path. Value-initialized so a compiler cannot flag a maybe-uninitialized read through the recursive fill:
        // segmented_result runs only after extend_segments has written every index, but that write crosses a call
        // boundary the optimizer may not see through.
        const std::byte *segment_starts[detail::MAX_PATTERN_JUMPS + 1] = {};

        const std::size_t anchor = pattern.anchor;
        if (anchor < segment0_end)
        {
            // Anchored sweep: memchr for the segment-0 anchor byte, then try to extend from each hit. The anchor sits
            // `anchor` bytes into segment 0, so a hit at H means a candidate segment-0 start at H - anchor.
            const auto target = static_cast<unsigned char>(pattern.bytes[anchor]);
            const std::byte *const search_hi = last_candidate + anchor; // inclusive, mirrors the flat matcher
            const std::byte *search_start = start_address + anchor;
            while (search_start <= search_hi)
            {
                const std::byte *const hit = scan_for_byte(search_start, search_hi, target, use_avx2);
                if (!hit)
                {
                    break;
                }
                const std::byte *const candidate = hit - anchor;
                // The work budget is per segment-0 candidate: reset it at each start so one position's pathological
                // backtracking can never starve a later, genuine match. The outer sweep stays region-linear.
                std::size_t steps = 0;
                if (extend_segments(pattern, candidate, region_end, 0, segment_starts, steps))
                {
                    return segmented_result(pattern, segment_starts);
                }
                search_start = hit + 1;
            }
            return detail::RawMatch{};
        }

        // No literal byte in segment 0 (all wildcard or nibble-only): fall back to trying every start position. Rare --
        // a real signature almost always carries a literal byte in its leading run.
        for (const std::byte *candidate = start_address; candidate <= last_candidate; ++candidate)
        {
            // Per-candidate work budget (see the anchored sweep above): reset at each start position.
            std::size_t steps = 0;
            if (extend_segments(pattern, candidate, region_end, 0, segment_starts, steps))
            {
                return segmented_result(pattern, segment_starts);
            }
        }
        return detail::RawMatch{};
    }

    detail::RawMatch detail::find_pattern_raw(const std::byte *start_address, std::size_t region_size,
                                              const detail::EnginePattern &pattern) noexcept
    {
        const std::size_t pattern_size = pattern.size();
        if (pattern_size == 0 || !start_address || region_size < pattern_size)
        {
            return RawMatch{};
        }

        if (pattern.jumps.empty())
        {
            // Plain pattern: the flat fixed-width fast path. end is the fixed span; point applies the constant
            // offset.
            const std::byte *const start = find_pattern_flat_start(start_address, region_size, pattern);
            if (!start)
            {
                return RawMatch{};
            }
            return RawMatch{start, start + pattern_size, start + pattern.offset};
        }

        // Bounded-jump pattern: hoist the AVX2 gate once for the segmented sweep's memchr, then run the segmented
        // matcher, which applies the offset itself because a jump match's marker delta is not a constant.
#ifdef DMK_HAS_AVX2
        const bool use_avx2 = cpu_has_avx2();
#else
        const bool use_avx2 = false;
#endif
        return find_pattern_segmented(start_address, region_size, pattern, use_avx2);
    }

    const std::byte *detail::find_pattern(const std::byte *start_address, std::size_t region_size,
                                          const detail::EnginePattern &pattern)
    {
        if (pattern.empty() || !start_address)
        {
            return nullptr;
        }

        // find_pattern_raw bakes the offset into point (constant for a plain pattern, gap-dependent for a jump one), so
        // point is the final result address and is nullptr when there is no match.
        return find_pattern_raw(start_address, region_size, pattern).point;
    }

    const std::byte *detail::find_pattern(const std::byte *start_address, std::size_t region_size,
                                          const detail::EnginePattern &pattern, std::size_t occurrence)
    {
        if (occurrence == 0)
        {
            return nullptr;
        }
        if (pattern.empty() || !start_address)
        {
            return nullptr;
        }

        const std::byte *cursor = start_address;
        std::size_t remaining = region_size;
        std::size_t found_count = 0;

        // Iterate via the raw helper so the continuation advances past each match START (RawMatch::start), which is
        // correct regardless of the pattern's offset marker or its variable jump span. The offset-applied result
        // (RawMatch::point) is returned only for the Nth hit. A jump pattern needs at least min_match_length() bytes;
        // the weaker size() loop guard is a safe lower bound, and find_pattern_raw fails closed on a short tail.
        while (remaining >= pattern.size())
        {
            const RawMatch match = find_pattern_raw(cursor, remaining, pattern);
            if (!match.start)
            {
                break;
            }
            if (++found_count == occurrence)
            {
                return match.point;
            }
            const std::size_t advance = static_cast<std::size_t>(match.start - cursor) + 1;
            cursor += advance;
            remaining -= advance;
        }

        return nullptr;
    }

    scan::SimdLevel detail::active_simd_level() noexcept
    {
#ifdef DMK_HAS_AVX512
        if (cpu_has_avx512())
            return scan::SimdLevel::Avx512;
#endif
#ifdef DMK_HAS_AVX2
        if (cpu_has_avx2())
            return scan::SimdLevel::Avx2;
#endif
#ifdef DMK_HAS_SSE2
        return scan::SimdLevel::Sse2;
#else
        return scan::SimdLevel::Scalar;
#endif
    }
} // namespace DetourModKit
