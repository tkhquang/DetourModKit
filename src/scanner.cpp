/**
 * @file scanner.cpp
 * @brief Implementation of Array-of-Bytes (AOB) parsing, scanning, and RIP-relative resolution.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/format.hpp"

#include "scanner_internal.hpp"
#include "memory_internal.hpp"

#include <windows.h>
#include <vector>
#include <string>
#include <cctype>
#include <stdexcept>
#include <cstddef>
#include <cstdint>
#include <cassert>
#include <cstring>
#include <optional>

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

using namespace DetourModKit;

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
     * @details Checks CPUID leaf 1 ECX bit 28 (AVX) plus CPUID leaf 7 subleaf 0 EBX bit 5 (AVX2), then verifies that
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
     * @return The next byte offset to resume verification from on success (equal to pattern.size() when the AVX2 tier
     *         covered the whole pattern), or std::nullopt when a 32-byte chunk did not match and the caller must
     *         abandon this candidate position.
     * @note This function is compiled with AVX2 codegen via target attribute on
     *       GCC/Clang. On MSVC, intrinsics are always available.
     */
    DMK_AVX2_TARGET
    DMK_NO_SANITIZE_ADDRESS
    std::optional<size_t> verify_pattern_avx2(const std::byte *pattern_start, const Scanner::CompiledPattern &pattern,
                                              size_t start_offset) noexcept
    {
        const size_t pattern_size = pattern.size();
        size_t j = start_offset;

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
     *          compare is a BW instruction, so both are required. Also verifies the OS has enabled the full opmask /
     *          ZMM register state via XGETBV (XCR0 bits 1,2,5,6,7); a CPU that reports AVX-512 while the OS has not
     *          enabled the state must fail closed. Result is cached in a function-local static.
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

            return cpu_leaf1_ecx_has(CPUID_ECX_AVX) && avx512f && avx512bw && xcr0_has_enabled_state(XCR0_AVX512_STATE);
#elif defined(_MSC_VER)
            int cpui[4]{};
            __cpuidex(cpui, 7, 0);
            const bool avx512f = (cpui[1] & (1 << 16)) != 0;
            const bool avx512bw = (cpui[1] & (1 << 30)) != 0;

            return cpu_leaf1_ecx_has(CPUID_ECX_AVX) && avx512f && avx512bw && xcr0_has_enabled_state(XCR0_AVX512_STATE);
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
     * @return The next byte offset to resume verification from on success (equal to start_offset plus a multiple of 64
     *         once the AVX-512 tier covered whole 64-byte chunks), or std::nullopt when a 64-byte chunk did not match
     *         and the caller must abandon this candidate position.
     * @note Compiled with AVX-512F + AVX-512BW codegen via target attribute on GCC/Clang; on MSVC the intrinsics are
     *       always available. Only entered after cpu_has_avx512() has confirmed CPU and OS support.
     */
    DMK_AVX512_TARGET
    DMK_NO_SANITIZE_ADDRESS
    std::optional<size_t> verify_pattern_avx512(const std::byte *pattern_start, const Scanner::CompiledPattern &pattern,
                                                size_t start_offset) noexcept
    {
        const size_t pattern_size = pattern.size();
        size_t j = start_offset;

        for (; j + 64 <= pattern_size; j += 64)
        {
            const __m512i mem = _mm512_loadu_si512(reinterpret_cast<const void *>(pattern_start + j));
            const __m512i pat = _mm512_loadu_si512(reinterpret_cast<const void *>(pattern.bytes.data() + j));
            const __m512i msk = _mm512_loadu_si512(reinterpret_cast<const void *>(pattern.mask.data() + j));

            // (mem ^ pat) & mask is zero in every matching byte: a wildcard lane (mask 0x00) clears to zero, and a
            // literal lane (mask 0xFF) keeps the xor, which is zero only on an exact byte match. test_epi8_mask sets a
            // bit per byte whose masked value is nonzero -- i.e. a mismatch -- so any nonzero result fails the chunk.
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
     * @brief Returns a commonality score for a byte value in typical x64 PE code sections.
     * @details Higher scores indicate bytes that appear more frequently, making them poor candidates for anchor-based
     *          scanning.
     */
    constexpr uint8_t byte_frequency_class(uint8_t byte_value) noexcept
    {
        switch (byte_value)
        {
        case 0x00:
            return 10; // null padding, very common
        case 0xCC:
            return 9; // INT3, debug padding
        case 0x90:
            return 9; // NOP
        case 0xFF:
            return 8; // call/jmp indirect, common
        case 0x48:
            return 8; // REX.W prefix, ubiquitous in x64
        case 0x8B:
            return 7; // MOV reg, r/m
        case 0x89:
            return 7; // MOV r/m, reg
        case 0x0F:
            return 7; // two-byte opcode escape
        case 0xE8:
            return 6; // CALL rel32
        case 0xE9:
            return 6; // JMP rel32
        case 0x83:
            return 6; // arithmetic imm8
        case 0xC3:
            return 5; // RET
        default:
            return 0; // uncommon, ideal anchor
        }
    }

    /**
     * @brief Picks the rarest fully-known byte's index in a compiled pattern.
     * @return The byte index in `[0, pattern.size())` with the lowest score, or `pattern.size()` when no position is a
     *         fully-known literal byte (every position is a wildcard or only partially masked).
     */
    size_t select_pattern_anchor(const Scanner::CompiledPattern &pattern) noexcept
    {
        const size_t pattern_size = pattern.size();
        size_t best = pattern_size;
        uint8_t best_score = UINT8_MAX;
        for (size_t i = 0; i < pattern_size; ++i)
        {
            // Only a fully-known byte (mask 0xFF) can anchor the memchr / SIMD prefilter, which searches for one exact
            // byte value. A wildcard (mask 0x00) or a partially-masked nibble byte (0xF0 / 0x0F) carries no single byte
            // value to scan for, so it is never an anchor candidate.
            if (pattern.mask[i] != std::byte{0xFF})
            {
                continue;
            }
            const uint8_t score = byte_frequency_class(static_cast<uint8_t>(pattern.bytes[i]));
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

void DetourModKit::Scanner::CompiledPattern::compile_anchor() noexcept
{
    anchor = select_pattern_anchor(*this);
}

namespace
{
    /**
     * @brief Converts a single hex character to its numeric value.
     * @return The value 0-15, or -1 if not a valid hex digit.
     */
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

std::optional<Scanner::CompiledPattern> DetourModKit::Scanner::parse_aob(std::string_view aob_str)
{
    Logger &logger = Logger::get_instance();

    auto is_ws = [](char c) noexcept
    { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v'; };

    // Trim leading/trailing whitespace without allocating
    std::string_view input = aob_str;
    while (!input.empty() && is_ws(input.front()))
        input.remove_prefix(1);
    while (!input.empty() && is_ws(input.back()))
        input.remove_suffix(1);

    if (input.empty())
    {
        if (!aob_str.empty())
        {
            logger.debug("AOB Parser: Input string became empty after trimming.");
        }
        return std::nullopt;
    }

    CompiledPattern result;
    size_t token_idx = 0;
    bool offset_set = false;

    size_t pos = 0;
    while (pos < input.size())
    {
        // Skip whitespace between tokens
        while (pos < input.size() && is_ws(input[pos]))
            ++pos;
        if (pos >= input.size())
            break;

        // Find token end
        const size_t token_start = pos;
        while (pos < input.size() && !is_ws(input[pos]))
            ++pos;
        const std::string_view token = input.substr(token_start, pos - token_start);

        token_idx++;
        if (token == "|")
        {
            if (offset_set)
            {
                logger.error("AOB Parser: Multiple '|' offset markers at position {}.", token_idx);
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
                // High-nibble token (e.g. "4?"): the high nibble is fixed and the low nibble is a wildcard. Store the
                // known nibble in place with a zeroed wildcard nibble and a 0xF0 mask, so the masked compare
                // (mem ^ pat) & mask checks only the high nibble.
                result.bytes.push_back(static_cast<std::byte>(hi << 4));
                result.mask.push_back(std::byte{0xF0});
            }
            else if (hi_char == '?' && lo >= 0)
            {
                // Low-nibble token (e.g. "?5"): the low nibble is fixed and the high nibble is a wildcard. A 0x0F mask
                // checks only the low nibble.
                result.bytes.push_back(static_cast<std::byte>(lo));
                result.mask.push_back(std::byte{0x0F});
            }
            else
            {
                // Split the literal around '??' to dodge the C++ trigraph
                // ??'  (interpreted as a `|`), which trips -Wtrigraphs on
                // GCC and would otherwise require disabling the warning TU-wide.
                logger.error("AOB Parser: Invalid token '{}' at position {}. "
                             "Expected hex byte (e.g., FF), a per-nibble form (e.g. '4?' or '?5'), '?', or '?"
                             "?'.",
                             token, token_idx);
                return std::nullopt;
            }
        }
        else
        {
            logger.error("AOB Parser: Invalid token '{}' at position {}. "
                         "Expected hex byte (e.g., FF), a per-nibble form (e.g. '4?' or '?5'), '?', or '?"
                         "?'.",
                         token, token_idx);
            return std::nullopt;
        }
    }

    if (result.empty())
    {
        if (token_idx > 0)
        {
            logger.error("AOB Parser: Processed tokens but resulting pattern is empty.");
        }
        return std::nullopt;
    }

    result.compile_anchor();
    return result;
}

namespace
{
    // Internal scan primitive: returns the match *start* without applying pattern.offset. The public find_pattern
    // wrappers apply the offset exactly once on top of this result; scan_executable_regions also calls this directly so
    // its own final offset-application remains correct.
    DMK_NO_SANITIZE_ADDRESS
    const std::byte *find_pattern_raw(const std::byte *start_address, size_t region_size,
                                      const Scanner::CompiledPattern &pattern) noexcept;

    // Shared guard for "pattern has no literal bytes". Returning start_address preserves backwards compatibility for
    // callers that rely on the degenerate "all wildcards matches anywhere" behaviour, but the call site is almost
    // always a bug. Logging once per public entry (rather than per internal find_pattern_raw iteration) keeps the
    // warning visible without flooding logs when the Nth-occurrence overload or scan_executable_regions loops.
    bool pattern_has_literal_byte(const Scanner::CompiledPattern &pattern) noexcept
    {
        for (const std::byte mask_byte : pattern.mask)
        {
            if (mask_byte != std::byte{0x00})
                return true;
        }
        return false;
    }

    // Shared precondition check for the public find_pattern overloads. Returns false when the caller must short-circuit
    // with nullptr (empty pattern or null start_address). Emits the all-wildcard warning itself so callers do not
    // duplicate it; in that case the caller still continues scanning.
    bool validate_find_pattern_inputs(const std::byte *start_address, const Scanner::CompiledPattern &pattern) noexcept
    {
        Logger &logger = Logger::get_instance();
        if (pattern.empty())
        {
            logger.error("find_pattern: Pattern is empty. Cannot scan.");
            return false;
        }
        if (!start_address)
        {
            logger.error("find_pattern: Start address is null. Cannot scan.");
            return false;
        }
        if (!pattern_has_literal_byte(pattern))
        {
            logger.warning("find_pattern: pattern contains no literal bytes "
                           "(all wildcards); returning region start unchanged");
        }
        return true;
    }
} // anonymous namespace

const std::byte *DetourModKit::Scanner::find_pattern(const std::byte *start_address, size_t region_size,
                                                     const CompiledPattern &pattern)
{
    if (!validate_find_pattern_inputs(start_address, pattern))
    {
        return nullptr;
    }

    const std::byte *match = find_pattern_raw(start_address, region_size, pattern);
    if (!match)
        return nullptr;
    return match + pattern.offset;
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
    // (32 bytes per iteration) is selected at runtime through the same cpu_has_avx2() gate the verify tier uses. Each
    // SIMD body broadcasts the needle into every lane, compares a whole vector against it with one PCMPEQB, and
    // collapses the per-byte result to a movemask bitmask; count-trailing-zeros on the first nonzero mask gives the
    // lane index of the first match, so the search keeps libc memchr's "lowest address wins" contract. A scalar byte
    // loop finishes the sub-vector tail and is the only body on targets without SSE2 (32-bit x86 built without it).
    // None of the tiers call into libc, so the ASan interceptor never sees the read; the explicit intrinsics also use
    // unaligned loads, so there is no type-punned qword load for clang-cl's strict-aliasing TBAA to miscompile.

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
    // SSE2 needle search over [p, p + n): a 16-byte body plus a scalar tail. No runtime gate -- DMK_HAS_SSE2 implies
    // the target is x86-64 (or x86 built with SSE2), where these instructions are always legal.
    DMK_NO_SANITIZE_ADDRESS
    const unsigned char *dmk_memchr_sse2(const unsigned char *p, unsigned char needle, size_t n) noexcept
    {
        const __m128i needle_vec = _mm_set1_epi8(static_cast<char>(needle));
        for (; n >= 16; p += 16, n -= 16)
        {
            const __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i *>(p));
            const unsigned int mask = static_cast<unsigned int>(_mm_movemask_epi8(_mm_cmpeq_epi8(chunk, needle_vec)));
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
    // AVX2 needle search over [p, p + n): a 32-byte body plus a scalar tail. Compiled with AVX2 codegen via the target
    // attribute on GCC/Clang so the rest of the TU stays SSE2-only, and only entered after cpu_has_avx2() has
    // confirmed both the CPU and the OS support the instructions. The tail is scalar rather than an SSE2 call so the
    // body emits no legacy-SSE encoding and the compiler has no VEX/legacy transition to reconcile on the way out.
    DMK_AVX2_TARGET
    DMK_NO_SANITIZE_ADDRESS
    const unsigned char *dmk_memchr_avx2(const unsigned char *p, unsigned char needle, size_t n) noexcept
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
    const void *dmk_memchr(const void *haystack, unsigned char needle, size_t n,
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
        const size_t n = static_cast<size_t>(end - begin + 1);
        return static_cast<const std::byte *>(dmk_memchr(begin, target, n, use_avx2));
    }

    DMK_NO_SANITIZE_ADDRESS
    const std::byte *find_pattern_raw(const std::byte *start_address, size_t region_size,
                                      const Scanner::CompiledPattern &pattern) noexcept
    {
        const size_t pattern_size = pattern.size();

        if (pattern_size == 0 || !start_address || region_size < pattern_size)
        {
            return nullptr;
        }

        // Anchor selection: parse_aob() pre-populates pattern.anchor, so the common path is a single load. Manually
        // constructed patterns fall back to inline selection without mutating the input (preserves the const-by-design
        // contract).
        const size_t best_anchor = (pattern.anchor <= pattern_size) ? pattern.anchor : select_pattern_anchor(pattern);

        // No fully-known byte to anchor on. Two sub-cases:
        //   - The pattern is entirely wildcards (no mask bit set anywhere): the search degenerates to "always match at
        //     region start", preserved for backward compatibility. The public wrappers log the warning once per call.
        //   - The pattern carries only partially-masked (nibble) bytes: there is no exact byte for the memchr / SIMD
        //     prefilter, so fall back to a masked compare at every candidate position. This path is rare -- a real
        //     signature almost always carries at least one full literal byte -- so a scalar verify is acceptable;
        //     correctness, not throughput, is the concern here.
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
                for (size_t j = 0; j < pattern_size; ++j)
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

        // Hoist runtime CPU detection. The query itself is a function-local static behind a one-shot init, but reading
        // it on every memchr hit and every verify adds an indirect load per false candidate. Caching it once here lets
        // both the prefilter sweep and the per-candidate verify branch use a register-resident bool. It is defined
        // unconditionally (false without an AVX2 build) because the prefilter takes it on every call.
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
            // SSE2 (16B) -> scalar (1B). Each tier resumes from the offset the previous one reached (start_offset j),
            // so the widest available tiers cover the bulk and the scalar loop only ever finishes a sub-16-byte tail.
            bool match_found = true;
            size_t j = 0;

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
                // Masked compare so a partially-masked nibble byte checks only its known nibble: (mem ^ pat) & mask is
                // zero exactly when every bit the mask selects agrees. A wildcard (mask 0x00) is trivially satisfied, a
                // full literal (0xFF) compares the whole byte, and a nibble (0xF0 / 0x0F) compares one nibble.
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

            // No match, continue searching from next position
            search_start = current_scan_ptr + 1;
        }

        return nullptr;
    }
} // anonymous namespace

const std::byte *DetourModKit::Scanner::find_pattern(const std::byte *start_address, size_t region_size,
                                                     const CompiledPattern &pattern, size_t occurrence)
{
    if (occurrence == 0)
    {
        return nullptr;
    }

    if (!validate_find_pattern_inputs(start_address, pattern))
    {
        return nullptr;
    }

    const std::byte *cursor = start_address;
    size_t remaining = region_size;
    size_t found_count = 0;

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
        const size_t advance = static_cast<size_t>(match - cursor) + 1;
        cursor += advance;
        remaining -= advance;
    }

    return nullptr;
}

std::expected<uintptr_t, DetourModKit::RipResolveError>
DetourModKit::Scanner::resolve_rip_relative(const std::byte *instruction_address, size_t displacement_offset,
                                            size_t instruction_length)
{
    if (!instruction_address)
    {
        return std::unexpected(RipResolveError::NullInput);
    }

    const std::byte *disp_ptr = instruction_address + displacement_offset;
    // Read the displacement under a single SEH fault guard instead of is_readable + raw memcpy. is_readable is a
    // time-of-check/time-of-use illusion -- the page can change protection or unmap between the check and the copy --
    // so an unguarded memcpy could fault the host.
    const auto displacement = Memory::seh_read<int32_t>(reinterpret_cast<uintptr_t>(disp_ptr));
    if (!displacement)
    {
        return std::unexpected(RipResolveError::UnreadableDisplacement);
    }

    // Compute the target in unsigned modular arithmetic so the math stays well-defined on every input, including
    // kernel-range instruction addresses (where intptr_t would be negative and signed overflow is UB). The displacement
    // is sign-extended first so negative disp32 values wrap to the correct 64-bit offset.
    const uintptr_t base = reinterpret_cast<uintptr_t>(instruction_address);
    const uintptr_t disp_sext = static_cast<uintptr_t>(static_cast<int64_t>(*displacement));
    const uintptr_t target = base + instruction_length + disp_sext;

    // Fail closed on a target that cannot be a real in-process address. A corrupt or hostile displacement can resolve
    // to 0, a low guard-page address, or a kernel-range value; returning that as "success" would hand the caller a
    // pointer that faults on first use. plausible_userspace_ptr is pure arithmetic, so this guard adds no syscall and
    // no memory access.
    if (!Memory::plausible_userspace_ptr(target))
    {
        return std::unexpected(RipResolveError::ImplausibleTarget);
    }
    return target;
}

std::expected<uintptr_t, DetourModKit::RipResolveError>
DetourModKit::Scanner::find_and_resolve_rip_relative(const std::byte *search_start, size_t search_length,
                                                     std::span<const std::byte> opcode_prefix,
                                                     size_t instruction_length)
{
    if (!search_start || opcode_prefix.empty())
    {
        return std::unexpected(RipResolveError::NullInput);
    }

    const size_t prefix_len = opcode_prefix.size();
    const size_t min_bytes = prefix_len + sizeof(int32_t);
    if (search_length < min_bytes)
    {
        return std::unexpected(RipResolveError::RegionTooSmall);
    }

    const size_t scan_limit = search_length - min_bytes;
    const std::byte first = opcode_prefix[0];

    for (size_t i = 0; i <= scan_limit; ++i)
    {
        if (search_start[i] != first)
        {
            continue;
        }

        if (prefix_len > 1 && std::memcmp(&search_start[i + 1], opcode_prefix.data() + 1, prefix_len - 1) != 0)
        {
            continue;
        }

        return resolve_rip_relative(&search_start[i], prefix_len, instruction_length);
    }

    return std::unexpected(RipResolveError::PrefixNotFound);
}

namespace
{
    // Scan one protection-gated region for the next needed match, decrementing matches_remaining for each non-self
    // match. Returns the resolved address (match + pattern.offset) when the Nth match lands in this region, or nullptr
    // when the region is exhausted first. This is the body the TOCTOU fault guard wraps (see scan_region_guarded): it
    // performs the unguarded find_pattern_raw reads (memchr prefilter + SIMD verify) across [region_start, +scan_size).
    const std::byte *scan_region_for_match(const std::byte *region_start, size_t scan_size,
                                           const Scanner::CompiledPattern &pattern, uintptr_t needle_lo,
                                           uintptr_t needle_hi, size_t &matches_remaining) noexcept
    {
        const std::byte *match = find_pattern_raw(region_start, scan_size, pattern);
        while (match != nullptr)
        {
            const auto match_addr = reinterpret_cast<uintptr_t>(match);
            const bool self_match = match_addr < needle_hi && (match_addr + pattern.size()) > needle_lo;
            if (!self_match)
            {
                --matches_remaining;
                if (matches_remaining == 0)
                    return match + pattern.offset;
            }

            // Continue scanning past the current match.
            const size_t consumed = static_cast<size_t>(match - region_start) + 1;
            if (consumed >= scan_size)
                break;
            match = find_pattern_raw(match + 1, scan_size - consumed, pattern);
        }
        return nullptr;
    }

    // Region-granular TOCTOU fault guard around scan_region_for_match. The caller's per-region VirtualQuery only proves
    // the region was committed and readable at gate time; a concurrent decommit / reprotect before these unguarded
    // reads complete would otherwise fault the host. On MSVC the body runs inside a __try / __except that swallows
    // exactly the foreign-read faults (Memory::detail::is_guarded_read_fault) and reports the region as faulted, so the
    // sweep skips it and continues -- the same skip-the-region contract seh_read_bytes follows. MinGW has no structured
    // exception handling, so the body runs directly and the per-region VirtualQuery gate is the only guard available
    // there. *out_faulted is set true only when a fault was swallowed.
    const std::byte *scan_region_guarded(const std::byte *region_start, size_t scan_size,
                                         const Scanner::CompiledPattern &pattern, uintptr_t needle_lo,
                                         uintptr_t needle_hi, size_t &matches_remaining, bool &out_faulted) noexcept
    {
        out_faulted = false;
#ifdef _MSC_VER
        const size_t original_matches_remaining = matches_remaining;
        __try
        {
            return scan_region_for_match(region_start, scan_size, pattern, needle_lo, needle_hi, matches_remaining);
        }
        __except (Memory::detail::is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                                                            : EXCEPTION_CONTINUE_SEARCH)
        {
            // Treat a faulted region as skipped, not partially scanned. Matches observed before the fault cannot be
            // trusted for Nth-occurrence accounting because unreadable tail bytes may hide additional matches.
            matches_remaining = original_matches_remaining;
            out_faulted = true;
            return nullptr;
        }
#else
        return scan_region_for_match(region_start, scan_size, pattern, needle_lo, needle_hi, matches_remaining);
#endif
    }

    // Region-walking AOB scan shared by scan_executable_regions, scan_readable_regions, and the module-scoped
    // detail::scan_module_* entry points. Walks the committed regions of [window_lo, window_hi) via VirtualQuery and
    // runs the per-region scan (scan_region_for_match, behind the fault guard) against every region whose base
    // protection is present in accept_mask, returning the Nth match (1-based, adjusted by pattern.offset) or nullptr.
    // The whole-process scanners pass [0, UINTPTR_MAX); the module-scoped scan passes the image's [base, end) so only
    // one contiguous image is searched.
    //
    // Guard, no-access, and uncommitted regions are always skipped: PAGE_GUARD raises STATUS_GUARD_PAGE_VIOLATION on
    // the first touch and PAGE_NOACCESS faults even for reads, so neither is safe to dereference. The Windows base
    // protections (PAGE_READONLY, PAGE_READWRITE, ... , PAGE_EXECUTE_WRITECOPY) are mutually exclusive single bits, so
    // a bitwise-AND against a mask of the acceptable bases is a sound membership test. PAGE_GUARD is a modifier bit
    // OR-ed onto a base value (a guarded read-only page reads as PAGE_READONLY |
    // PAGE_GUARD), so it must be excluded separately or it would satisfy the mask and be scanned.
    //
    // Each region is scanned through the raw helper so the final `+ pattern.offset` applies exactly once (the public
    // find_pattern already applies offset; calling it here would double-apply). To find a signature that straddles a
    // protection split -- two adjacent accepted regions VirtualQuery reports separately because their base protections
    // differ (a sibling VirtualProtect carving part of .text into PAGE_EXECUTE_READWRITE is the canonical case;
    // VirtualQuery never coalesces regions with differing attributes) -- each accepted region's scan is extended back
    // by up to pattern_size - 1 bytes into the contiguous run of already-accepted regions it abuts. The overlap is
    // capped at pattern_size - 1 so a match lying wholly inside the previous region (already counted there) can never
    // be re-counted here, and bounded by the run start so it never reads past the bytes the per-region gate proved
    // readable.
    const std::byte *scan_regions_filtered(const Scanner::CompiledPattern &pattern, size_t occurrence,
                                           DWORD accept_mask, uintptr_t window_lo, uintptr_t window_hi) noexcept
    {
        // The compiled pattern's own bytes buffer lives in readable heap memory, so a whole-process readable sweep
        // would match the needle against itself and could return the caller's pattern storage instead of the intended
        // target. Exclude any match that overlaps that buffer. The executable sweep never reaches pattern.bytes (the
        // heap is not executable), so this is a no-op there and keeps both scanners
        // consistent: a scan never matches the needle's own storage. The needle
        // is the caller's allocation, so no real target can share its range.
        const auto needle_lo = reinterpret_cast<uintptr_t>(pattern.bytes.data());
        const auto needle_hi = needle_lo + pattern.size();

        size_t matches_remaining = occurrence;
        size_t faulted_regions = 0;
        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = window_lo;

        // Contiguous-accepted-run tracking for the cross-boundary overlap (see the function comment). prev_accept_hi is
        // the end of the previous accepted region; run_lo is the start of the run of contiguous accepted regions the
        // current region belongs to. A gap (a skipped, guarded, or non-readable region) breaks the run because the
        // bytes across it are not proven readable.
        bool prev_accepted = false;
        uintptr_t prev_accept_hi = 0;
        uintptr_t run_lo = 0;

        while (addr < window_hi && VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
        {
            const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
            const auto region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t region_end = region_base + mbi.RegionSize;

            // Clamp the region to the requested window so a region that straddles window_lo / window_hi is inspected
            // only where it intersects. For a whole-process sweep the window is [0, UINTPTR_MAX), so the clamp is a
            // no-op and the scanned span equals the region. For a module-scoped sweep this is what keeps the scan
            // inside [base, end) even when a
            // VirtualQuery region (e.g. a section straddling the image boundary) extends past it.
            const uintptr_t scan_lo = region_base < window_lo ? window_lo : region_base;
            const uintptr_t scan_hi = region_end > window_hi ? window_hi : region_end;

            if (mbi.State == MEM_COMMIT && (mbi.Protect & accept_mask) != 0 && !protection_unsafe && scan_hi > scan_lo)
            {
                // Continue the accepted run only when this region begins exactly where the previous accepted one ended;
                // otherwise restart it here. Done before computing the overlap so run_lo reflects the run scan_lo
                // joins.
                if (!prev_accepted || prev_accept_hi != scan_lo)
                {
                    run_lo = scan_lo;
                }

                // Extend the scan back by up to pattern_size - 1 bytes into the contiguous accepted run so a match that
                // begins in the previous region's tail and ends in this one is found. Bounded by run_lo so the read
                // stays inside already-gated bytes; capped at pattern_size - 1 so an interior match is not re-counted.
                uintptr_t effective_scan_lo = scan_lo;
                if (pattern.size() > 1 && scan_lo > run_lo)
                {
                    const uintptr_t max_overlap = static_cast<uintptr_t>(pattern.size() - 1);
                    const uintptr_t available = scan_lo - run_lo;
                    effective_scan_lo = scan_lo - ((max_overlap < available) ? max_overlap : available);
                }

                const size_t scan_size = static_cast<size_t>(scan_hi - effective_scan_lo);
                if (scan_size >= pattern.size())
                {
                    const auto *region_start = reinterpret_cast<const std::byte *>(effective_scan_lo);

                    // The protection gate above proved the region readable at gate time; scan_region_guarded backstops
                    // a concurrent decommit / reprotect that could fault the read after the gate (a TOCTOU the gate
                    // cannot close). A faulted region is skipped and counted, not fatal.
                    bool region_faulted = false;
                    const std::byte *result = scan_region_guarded(region_start, scan_size, pattern, needle_lo,
                                                                  needle_hi, matches_remaining, region_faulted);
                    if (result != nullptr)
                        return result;
                    if (region_faulted)
                        ++faulted_regions;
                }

                prev_accepted = true;
                prev_accept_hi = scan_hi;
            }
            else
            {
                prev_accepted = false;
            }

            assert(region_end > addr && "VirtualQuery returned a non-advancing region");
            if (region_end <= addr)
                break; // Overflow guard.
            addr = region_end;
        }

        if (faulted_regions > 0)
        {
            // Best-effort diagnosis only; the sweep already skipped each faulted region and continued. try_log keeps
            // this noexcept path honest when the Debug level is enabled.
            (void)Logger::get_instance().try_log(
                LogLevel::Debug, "Scanner: skipped {} region(s) that faulted mid-scan (concurrent decommit/reprotect).",
                faulted_regions);
        }

        return nullptr;
    }

    // Base protections accepted by the executable-only sweeps: the three page variants that grant execute *and* read.
    // Bare PAGE_EXECUTE (execute without a read bit) is excluded because dereferencing it raises an access violation;
    // PAGE_GUARD / PAGE_NOACCESS are filtered separately inside scan_regions_filtered. This is the scope for code-only
    // scans: the whole-process scan_executable_regions and the prologue-recovery fallback, whose rebuilt near-JMP can
    // only ever overwrite a code prologue.
    constexpr DWORD EXECUTABLE_PAGE_FLAGS = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    // Base protections accepted by the readable sweep and the data-capable module-scoped cascade: the
    // executable-readable set plus the non-executable readable pages (.rdata / .data and read-only heaps). This reaches
    // C++ vtables, RTTI type descriptors, and other read-only metadata the executable-only sweep cannot see.
    constexpr DWORD READABLE_PAGE_FLAGS = EXECUTABLE_PAGE_FLAGS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;

} // anonymous namespace

// Module-scoped siblings of scan_executable_regions / scan_readable_regions:
// each searches only the mapped image [range.base, range.end) and returns the
// Nth match (1-based, adjusted by pattern.offset) or nullptr. They are the internal entry points the cascade resolver
// (its own TU) calls instead of reaching the page-protection masks directly. Both reuse scan_regions_filtered's
// per-region VirtualQuery protection gate, so a non-readable interior page (a section-alignment gap, a guard page, a
// sibling VirtualProtect on part of the image) is skipped instead of dereferenced. find_pattern_raw itself does an
// unguarded memchr / SIMD compare; on the no-fault path the gate is what makes that safe, and scan_region_guarded
// backstops the gate against a concurrent decommit / reprotect that would fault the read after the gate passed.
const std::byte *Scanner::detail::scan_module_executable(const Scanner::CompiledPattern &pattern,
                                                         Memory::ModuleRange range, std::size_t occurrence) noexcept
{
    // EXECUTABLE_PAGE_FLAGS confines the match to code: the prologue-recovery fallback's rebuilt near-JMP can only ever
    // overwrite a code prologue, so a data-page hit would be a false positive.
    if (pattern.empty() || occurrence == 0 || !range.valid())
    {
        return nullptr;
    }
    return scan_regions_filtered(pattern, occurrence, EXECUTABLE_PAGE_FLAGS, range.base, range.end);
}

const std::byte *Scanner::detail::scan_module_readable(const Scanner::CompiledPattern &pattern,
                                                       Memory::ModuleRange range, std::size_t occurrence) noexcept
{
    // READABLE_PAGE_FLAGS lets one pass cover both .text and .rdata / .data candidates, which is why the in-module
    // cascade needs no ScannerKind split.
    if (pattern.empty() || occurrence == 0 || !range.valid())
    {
        return nullptr;
    }
    return scan_regions_filtered(pattern, occurrence, READABLE_PAGE_FLAGS, range.base, range.end);
}

// Centralizes the executable-page protection gate for out-of-TU callers (the string-xref backend): one VirtualQuery
// walk over [range.base, range.end) that returns each committed, execute-readable region clamped to the range, using
// the identical mask scan_module_executable applies. The per-region gate (MEM_COMMIT, EXECUTABLE_PAGE_FLAGS, not
// PAGE_GUARD / PAGE_NOACCESS) guarantees the window is readable at gate time; the caller still wraps its reads of the
// window in a fault guard so a concurrent decommit / reprotect between gate and read cannot fault the host, exactly as
// scan_region_guarded backstops the in-TU sweeps.
std::vector<Scanner::detail::ExecutableWindow> Scanner::detail::collect_executable_windows(Memory::ModuleRange range)
{
    std::vector<ExecutableWindow> windows;
    if (!range.valid())
    {
        return windows;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = range.base;
    while (addr < range.end && VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
    {
        const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
        const auto region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t region_end = region_base + mbi.RegionSize;
        const uintptr_t scan_lo = region_base < range.base ? range.base : region_base;
        const uintptr_t scan_hi = region_end > range.end ? range.end : region_end;

        if (mbi.State == MEM_COMMIT && (mbi.Protect & EXECUTABLE_PAGE_FLAGS) != 0 && !protection_unsafe &&
            scan_hi > scan_lo)
        {
            windows.push_back(ExecutableWindow{scan_lo, static_cast<std::size_t>(scan_hi - scan_lo)});
        }

        if (region_end <= addr)
        {
            break; // Overflow guard, mirroring scan_regions_filtered.
        }
        addr = region_end;
    }
    return windows;
}

// Single-address sibling of the executable-page gate scan_regions_filtered applies per region. One VirtualQuery,
// matched against the identical mask (MEM_COMMIT, EXECUTABLE_PAGE_FLAGS, not PAGE_GUARD / PAGE_NOACCESS), so the
// prologue-recovery fallback can vet a decoded E9 destination without re-deriving the Windows page masks or
// constraining it to a loaded module (a sibling mod's trampoline is VirtualAlloc'd outside every image).
bool Scanner::detail::is_executable_address(std::uintptr_t address) noexcept
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
    {
        return false;
    }
    const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
    return mbi.State == MEM_COMMIT && (mbi.Protect & EXECUTABLE_PAGE_FLAGS) != 0 && !protection_unsafe;
}

const std::byte *DetourModKit::Scanner::scan_executable_regions(const CompiledPattern &pattern, size_t occurrence)
{
    if (pattern.empty() || occurrence == 0)
        return nullptr;

    Logger &logger = Logger::get_instance();

    if (!pattern_has_literal_byte(pattern))
    {
        logger.warning("scan_executable_regions: pattern contains no literal "
                       "bytes (all wildcards); returning first readable region "
                       "start unchanged");
    }

    // EXECUTABLE_PAGE_FLAGS keeps the sweep to pages we can actually *read*; bare
    // PAGE_EXECUTE grants execute without read, so dereferencing such a page would raise an access violation.
    // Whole-process sweep: the window spans the entire user address space, so the clamp in scan_regions_filtered is a
    // no-op and the walk stops only when VirtualQuery runs off the end of the address space.
    return scan_regions_filtered(pattern, occurrence, EXECUTABLE_PAGE_FLAGS, 0, UINTPTR_MAX);
}

const std::byte *DetourModKit::Scanner::scan_readable_regions(const CompiledPattern &pattern, size_t occurrence)
{
    if (pattern.empty() || occurrence == 0)
        return nullptr;

    Logger &logger = Logger::get_instance();

    if (!pattern_has_literal_byte(pattern))
    {
        logger.warning("scan_readable_regions: pattern contains no literal "
                       "bytes (all wildcards); returning first readable region "
                       "start unchanged");
    }

    // READABLE_PAGE_FLAGS is a superset of the executable-only mask: every committed region we can read, including
    // .rdata / .data (PAGE_READONLY /
    // PAGE_READWRITE / PAGE_WRITECOPY) and read-only heaps, plus the execute-readable variants. The semantic is "find
    // this pattern anywhere readable", so execute-readable code pages are intentionally included rather than
    // deduplicated against scan_executable_regions; callers wanting non-code matches post-filter. The window spans the
    // whole address space.
    return scan_regions_filtered(pattern, occurrence, READABLE_PAGE_FLAGS, 0, UINTPTR_MAX);
}

Scanner::SimdLevel DetourModKit::Scanner::active_simd_level() noexcept
{
#ifdef DMK_HAS_AVX512
    if (cpu_has_avx512())
        return SimdLevel::Avx512;
#endif
#ifdef DMK_HAS_AVX2
    if (cpu_has_avx2())
        return SimdLevel::Avx2;
#endif
#ifdef DMK_HAS_SSE2
    return SimdLevel::Sse2;
#else
    return SimdLevel::Scalar;
#endif
}

bool DetourModKit::Scanner::is_likely_function_prologue(std::uintptr_t addr) noexcept
{
    if (addr == 0)
    {
        return false;
    }

    // Read the first opcode byte under a fault guard rather than is_readable + a raw dereference. is_readable is a
    // TOCTOU illusion (the page can change or unmap between the check and the read), and the bare dereference would
    // then fault the host. seh_read returns nullopt on any fault.
    const auto b0 = Memory::seh_read<std::uint8_t>(addr);
    if (!b0)
    {
        return false;
    }

    // Reject bytes that never begin a real function prologue, so an AOB match that landed in inter-function padding or
    // past a function's end is filtered out instead of accepted as a target:
    //   0x00 -- zero fill / uninitialized page (decodes as `add [rax], al`)
    //   0xCC -- INT3, the alignment padding linkers insert between functions
    //   0xC3 -- RET (near return): a function epilogue, not a prologue
    //   0xC2 -- RET imm16: likewise a return, not a prologue
    return *b0 != 0x00 && *b0 != 0xCC && *b0 != 0xC2 && *b0 != 0xC3;
}
