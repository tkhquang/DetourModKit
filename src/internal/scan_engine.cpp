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

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
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
         * @brief Picks the rarest fully-known byte's index in a compiled pattern.
         * @return The byte index in `[0, pattern.size())` with the lowest frequency score, or `pattern.size()` when no
         *         position is a fully-known literal byte (every position is a wildcard or only partially masked).
         */
        std::size_t select_pattern_anchor(const detail::EnginePattern &pattern) noexcept
        {
            const std::size_t pattern_size = pattern.size();
            std::size_t best = pattern_size;
            std::uint8_t best_score = UINT8_MAX;
            for (std::size_t i = 0; i < pattern_size; ++i)
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

    namespace
    {
        /// Converts a single hex character to its numeric value, or -1 if not a valid hex digit.
        constexpr int hex_char_to_int(char c) noexcept
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            return -1;
        }
    } // anonymous namespace

    bool detail::pattern_has_literal_byte(const detail::EnginePattern &pattern) noexcept
    {
        for (const std::byte mask_byte : pattern.mask)
        {
            if (mask_byte != std::byte{0x00})
                return true;
        }
        return false;
    }

    std::optional<detail::EnginePattern> detail::parse_aob(std::string_view aob_str)
    {
        auto is_ws = [](char c) noexcept
        { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v'; };

        // Trim leading/trailing whitespace without allocating.
        std::string_view input = aob_str;
        while (!input.empty() && is_ws(input.front()))
            input.remove_prefix(1);
        while (!input.empty() && is_ws(input.back()))
            input.remove_suffix(1);

        if (input.empty())
        {
            return std::nullopt;
        }

        EnginePattern result;
        bool offset_set = false;

        std::size_t pos = 0;
        while (pos < input.size())
        {
            // Skip whitespace between tokens.
            while (pos < input.size() && is_ws(input[pos]))
                ++pos;
            if (pos >= input.size())
                break;

            // Find token end.
            const std::size_t token_start = pos;
            while (pos < input.size() && !is_ws(input[pos]))
                ++pos;
            const std::string_view token = input.substr(token_start, pos - token_start);

            if (token == "|")
            {
                if (offset_set)
                {
                    return std::nullopt;
                }
                result.offset = static_cast<std::ptrdiff_t>(result.bytes.size());
                offset_set = true;
            }
            else if (token == "??" || token == "?")
            {
                result.bytes.push_back(std::byte{0x00});
                result.mask.push_back(std::byte{0x00});
            }
            else if (token.length() == 2)
            {
                const char hi_char = token[0];
                const char lo_char = token[1];
                const int hi = hex_char_to_int(hi_char);
                const int lo = hex_char_to_int(lo_char);
                if (hi >= 0 && lo >= 0)
                {
                    result.bytes.push_back(static_cast<std::byte>((hi << 4) | lo));
                    result.mask.push_back(std::byte{0xFF});
                }
                else if (hi >= 0 && lo_char == '?')
                {
                    // High-nibble token (e.g. "4?"): the high nibble is fixed and the low nibble is a wildcard. Store
                    // the known nibble in place with a zeroed wildcard nibble and a 0xF0 mask, so the masked compare
                    // (mem ^ pat) & mask checks only the high nibble.
                    result.bytes.push_back(static_cast<std::byte>(hi << 4));
                    result.mask.push_back(std::byte{0xF0});
                }
                else if (hi_char == '?' && lo >= 0)
                {
                    // Low-nibble token (e.g. "?5"): the low nibble is fixed and the high nibble is a wildcard. A 0x0F
                    // mask checks only the low nibble.
                    result.bytes.push_back(static_cast<std::byte>(lo));
                    result.mask.push_back(std::byte{0x0F});
                }
                else
                {
                    return std::nullopt;
                }
            }
            else
            {
                return std::nullopt;
            }
        }

        if (result.empty())
        {
            return std::nullopt;
        }

        result.compile_anchor();
        return result;
    }

    detail::EnginePattern detail::engine_pattern_from(const scan::Pattern &pattern, std::size_t anchor_index)
    {
        const std::span<const std::byte> bytes = pattern.bytes();
        const std::span<const std::byte> mask = pattern.mask();
        EnginePattern compiled;
        compiled.bytes.assign(bytes.begin(), bytes.end());
        compiled.mask.assign(mask.begin(), mask.end());
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

    DMK_NO_SANITIZE_ADDRESS
    const std::byte *detail::find_pattern_raw(const std::byte *start_address, std::size_t region_size,
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
        //     "always match at region start", preserved for backward compatibility.
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

    const std::byte *detail::find_pattern(const std::byte *start_address, std::size_t region_size,
                                          const detail::EnginePattern &pattern)
    {
        if (pattern.empty() || !start_address)
        {
            return nullptr;
        }

        const std::byte *match = find_pattern_raw(start_address, region_size, pattern);
        if (!match)
            return nullptr;
        return match + pattern.offset;
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

        // Iterate via the raw helper so the `match + 1` continuation stays correct regardless of the pattern's offset
        // marker. Offset is applied exactly once when we return the Nth hit.
        while (remaining >= pattern.size())
        {
            const std::byte *match = find_pattern_raw(cursor, remaining, pattern);
            if (!match)
            {
                break;
            }
            if (++found_count == occurrence)
            {
                return match + pattern.offset;
            }
            const std::size_t advance = static_cast<std::size_t>(match - cursor) + 1;
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
