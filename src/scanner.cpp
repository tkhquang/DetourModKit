/**
 * @file scanner.cpp
 * @brief Implementation of Array-of-Bytes (AOB) parsing, scanning, and RIP-relative resolution.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/format.hpp"
#include "x86_decode.hpp"

#include <windows.h>
#include <vector>
#include <string>
#include <cctype>
#include <stdexcept>
#include <cstddef>
#include <cstdint>
#include <cassert>
#include <cstring>

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#define DMK_HAS_SSE2 1
#include <emmintrin.h>
#endif

// AVX2 support: compile-time header + runtime CPUID detection.
// On GCC/Clang, AVX2 intrinsics require either -mavx2 globally or
// __attribute__((target("avx2"))) per function. We use the latter so
// the rest of the TU stays SSE2-only and runs on any x86-64 CPU.
// On MSVC, intrinsics are always available; runtime CPUID gates usage.
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

using namespace DetourModKit;
using namespace DetourModKit::String;

namespace
{
#ifdef DMK_HAS_AVX2
    /**
     * @brief Detects AVX2 support at runtime via CPUID.
     * @details Checks CPUID leaf 7 subleaf 0, EBX bit 5 (AVX2) and also
     *          verifies that the OS has enabled AVX state saving (XGETBV).
     *          Result is cached in a function-local static for zero-cost
     *          repeated queries.
     */
    bool cpu_has_avx2() noexcept
    {
        static const bool result = []() -> bool
        {
#if defined(__GNUC__) || defined(__clang__)
            // Check CPUID is supported and query leaf 7
            unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
            if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
                return false;
            const bool avx2_flag = (ebx & (1u << 5)) != 0;

            // Verify OS has enabled AVX state saving via XGETBV (ECX=0, bit 2)
            unsigned int xcr0_lo = 0, xcr0_hi = 0;
            __asm__ volatile("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
            const bool os_avx = (xcr0_lo & 0x06) == 0x06; // SSE + AVX state

            return avx2_flag && os_avx;
#elif defined(_MSC_VER)
            int cpui[4]{};
            __cpuidex(cpui, 7, 0);
            const bool avx2_flag = (cpui[1] & (1 << 5)) != 0;

            // Verify OS has enabled AVX state saving
            const unsigned long long xcr0 = _xgetbv(0);
            const bool os_avx = (xcr0 & 0x06) == 0x06;

            return avx2_flag && os_avx;
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
     * @param start_offset Byte offset to start verification from (may be non-zero
     *                     if a previous tier partially verified).
     * @return The byte offset where verification stopped. If equal to pattern size,
     *         the AVX2 tier found no mismatches in its range.
     * @note This function is compiled with AVX2 codegen via target attribute on
     *       GCC/Clang. On MSVC, intrinsics are always available.
     */
    DMK_AVX2_TARGET
    size_t verify_pattern_avx2(const std::byte *pattern_start,
                               const Scanner::CompiledPattern &pattern,
                               size_t start_offset) noexcept
    {
        const size_t pattern_size = pattern.size();
        size_t j = start_offset;

        for (; j + 32 <= pattern_size; j += 32)
        {
            const __m256i mem = _mm256_loadu_si256(
                reinterpret_cast<const __m256i *>(pattern_start + j));
            const __m256i pat = _mm256_loadu_si256(
                reinterpret_cast<const __m256i *>(pattern.bytes.data() + j));
            const __m256i msk = _mm256_loadu_si256(
                reinterpret_cast<const __m256i *>(pattern.mask.data() + j));

            const __m256i xored = _mm256_xor_si256(mem, pat);
            const __m256i masked = _mm256_and_si256(xored, msk);
            const __m256i cmp = _mm256_cmpeq_epi8(masked, _mm256_setzero_si256());

            if (static_cast<unsigned int>(_mm256_movemask_epi8(cmp)) != 0xFFFFFFFFu)
            {
                return 0; // Mismatch sentinel
            }
        }

        return j;
    }
#endif // DMK_HAS_AVX2

    /**
     * @brief Returns a commonality score for a byte value in typical x64 PE code sections.
     * @details Higher scores indicate bytes that appear more frequently, making them
     *          poor candidates for anchor-based scanning.
     */
    static constexpr uint8_t byte_frequency_class(uint8_t b) noexcept
    {
        switch (b)
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
} // anonymous namespace

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
            const int hi = hex_char_to_int(token[0]);
            const int lo = hex_char_to_int(token[1]);
            if (hi >= 0 && lo >= 0)
            {
                result.bytes.push_back(static_cast<std::byte>((hi << 4) | lo));
                result.mask.push_back(std::byte{0xFF});
            }
            else
            {
                // Split the literal around '??' to dodge the C++ trigraph
                // ??'  (interpreted as a `|`), which trips -Wtrigraphs on
                // GCC and would otherwise require disabling the warning TU-wide.
                logger.error("AOB Parser: Invalid token '{}' at position {}. "
                             "Expected hex byte (e.g., FF), '?', or '?"
                             "?'.",
                             token, token_idx);
                return std::nullopt;
            }
        }
        else
        {
            logger.error("AOB Parser: Invalid token '{}' at position {}. "
                         "Expected hex byte (e.g., FF), '?', or '?"
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

    return result;
}

namespace
{
    // Internal scan primitive: returns the match *start* without applying
    // pattern.offset. The public find_pattern wrappers apply the offset
    // exactly once on top of this result; scan_executable_regions also calls
    // this directly so its own final offset-application remains correct.
    const std::byte *find_pattern_raw(const std::byte *start_address, size_t region_size,
                                      const Scanner::CompiledPattern &pattern) noexcept;

    // Shared guard for "pattern has no literal bytes". Returning start_address
    // preserves backwards compatibility for callers that rely on the degenerate
    // "all wildcards matches anywhere" behaviour, but the call site is almost
    // always a bug. Logging once per public entry (rather than per internal
    // find_pattern_raw iteration) keeps the warning visible without flooding
    // logs when the Nth-occurrence overload or scan_executable_regions loops.
    bool pattern_has_literal_byte(const Scanner::CompiledPattern &pattern) noexcept
    {
        for (const std::byte m : pattern.mask)
        {
            if (m != std::byte{0x00})
                return true;
        }
        return false;
    }

    // Shared precondition check for the public find_pattern overloads. Returns
    // false when the caller must short-circuit with nullptr (empty pattern or
    // null start_address). Emits the all-wildcard warning itself so callers
    // do not duplicate it; in that case the caller still continues scanning.
    bool validate_find_pattern_inputs(const std::byte *start_address,
                                      const Scanner::CompiledPattern &pattern,
                                      Logger &logger) noexcept
    {
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
    Logger &logger = Logger::get_instance();
    if (!validate_find_pattern_inputs(start_address, pattern, logger))
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
    const std::byte *find_pattern_raw(const std::byte *start_address, size_t region_size,
                                      const Scanner::CompiledPattern &pattern) noexcept
    {
        const size_t pattern_size = pattern.size();

        if (pattern_size == 0 || !start_address || region_size < pattern_size)
        {
            return nullptr;
        }

        // Select the best anchor byte: the non-wildcard byte with the lowest
        // frequency score. Ties are broken by first occurrence for deterministic
        // behavior.
        size_t best_anchor = pattern_size; // invalid = all wildcards
        uint8_t best_score = UINT8_MAX;
        for (size_t i = 0; i < pattern_size; ++i)
        {
            if (pattern.mask[i] != std::byte{0x00})
            {
                const uint8_t score = byte_frequency_class(static_cast<uint8_t>(pattern.bytes[i]));
                if (best_anchor == pattern_size || score < best_score)
                {
                    best_anchor = i;
                    best_score = score;
                    if (score == 0)
                    {
                        break; // Cannot improve on score 0
                    }
                }
            }
        }

        // All wildcards: the pattern has no literal bytes to anchor on, so the
        // search degenerates to "always match at region start". The public
        // wrappers log the warning exactly once per call; repeated internal
        // iterations (Nth occurrence, per-region scans) stay quiet.
        if (best_anchor == pattern_size)
        {
            return start_address;
        }

        const std::byte target_byte = pattern.bytes[best_anchor];
        const unsigned char target_val = static_cast<unsigned char>(target_byte);

        const std::byte *search_start = start_address + best_anchor;
        const std::byte *const search_end = start_address + (region_size - pattern_size) + best_anchor;

        while (search_start <= search_end)
        {
            const void *found = memchr(search_start, static_cast<int>(target_val),
                                       static_cast<size_t>(search_end - search_start + 1));

            if (!found)
            {
                break;
            }

            const std::byte *current_scan_ptr = static_cast<const std::byte *>(found);
            const std::byte *pattern_start = current_scan_ptr - best_anchor;

            // Verify the full pattern at this position.
            // Three-tier SIMD: AVX2 (32B) -> SSE2 (16B) -> scalar (1B).
            bool match_found = true;
            size_t j = 0;

#ifdef DMK_HAS_AVX2
            if (cpu_has_avx2())
            {
                j = verify_pattern_avx2(pattern_start, pattern, 0);
                if (j == 0 && pattern_size >= 32)
                {
                    // Mismatch in AVX2 range
                    match_found = false;
                }
            }
#endif // DMK_HAS_AVX2

#ifdef DMK_HAS_SSE2
            for (; match_found && j + 16 <= pattern_size; j += 16)
            {
                const __m128i mem = _mm_loadu_si128(
                    reinterpret_cast<const __m128i *>(pattern_start + j));
                const __m128i pat = _mm_loadu_si128(
                    reinterpret_cast<const __m128i *>(pattern.bytes.data() + j));
                const __m128i msk = _mm_loadu_si128(
                    reinterpret_cast<const __m128i *>(pattern.mask.data() + j));

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
                if (pattern.mask[j] != std::byte{0x00} && pattern_start[j] != pattern.bytes[j])
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

    Logger &logger = Logger::get_instance();
    if (!validate_find_pattern_inputs(start_address, pattern, logger))
    {
        return nullptr;
    }

    const std::byte *cursor = start_address;
    size_t remaining = region_size;
    size_t found_count = 0;

    // Iterate via the raw helper so the `match + 1` continuation stays
    // correct regardless of the pattern's offset marker. Offset is applied
    // exactly once when we return the Nth hit.
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

std::expected<uintptr_t, DetourModKit::RipResolveError> DetourModKit::Scanner::resolve_rip_relative(
    const std::byte *instruction_address,
    size_t displacement_offset,
    size_t instruction_length)
{
    if (!instruction_address)
    {
        return std::unexpected(RipResolveError::NullInput);
    }

    const std::byte *disp_ptr = instruction_address + displacement_offset;
    if (!Memory::is_readable(disp_ptr, sizeof(int32_t)))
    {
        return std::unexpected(RipResolveError::UnreadableDisplacement);
    }

    int32_t displacement;
    std::memcpy(&displacement, disp_ptr, sizeof(int32_t));

    // Compute the target in unsigned modular arithmetic so the math stays
    // well-defined on every input, including kernel-range instruction
    // addresses (where intptr_t would be negative and signed overflow is UB).
    // The displacement is sign-extended first so negative disp32 values wrap
    // to the correct 64-bit offset.
    const uintptr_t base = reinterpret_cast<uintptr_t>(instruction_address);
    const uintptr_t disp_sext = static_cast<uintptr_t>(static_cast<int64_t>(displacement));
    return base + instruction_length + disp_sext;
}

std::expected<uintptr_t, DetourModKit::RipResolveError> DetourModKit::Scanner::find_and_resolve_rip_relative(
    const std::byte *search_start,
    size_t search_length,
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

    // Only scan pages we can actually *read*. Bare PAGE_EXECUTE grants execute
    // rights without read, so dereferencing such a page raises an access
    // violation. Omitting it keeps find_pattern safe on all walked regions.
    constexpr DWORD READABLE_EXEC_FLAGS = PAGE_EXECUTE_READ |
                                          PAGE_EXECUTE_READWRITE |
                                          PAGE_EXECUTE_WRITECOPY;

    size_t matches_remaining = occurrence;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;

    while (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
    {
        // Skip non-readable / hostile protection states regardless of the
        // execute bits: guard pages trigger STATUS_GUARD_PAGE_VIOLATION on
        // access, and PAGE_NOACCESS will AV even for reads.
        const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
        const bool execute_only = (mbi.Protect & PAGE_EXECUTE) != 0 &&
                                  (mbi.Protect & READABLE_EXEC_FLAGS) == 0;

        if (execute_only && !protection_unsafe && mbi.State == MEM_COMMIT)
        {
            if (logger.is_enabled(LogLevel::Trace))
            {
                logger.trace("scan_executable_regions: skipping pure-execute "
                             "region at {} (size {}) - not readable",
                             Format::format_address(reinterpret_cast<uintptr_t>(mbi.BaseAddress)),
                             mbi.RegionSize);
            }
        }

        if (mbi.State == MEM_COMMIT && (mbi.Protect & READABLE_EXEC_FLAGS) != 0 &&
            !protection_unsafe && mbi.RegionSize >= pattern.size())
        {
            const auto *region_start = reinterpret_cast<const std::byte *>(mbi.BaseAddress);

            // Use the raw helper so our own `+ pattern.offset` at the final
            // return applies exactly once (the public find_pattern already
            // applies offset; calling it here would double-apply).
            const std::byte *match = find_pattern_raw(region_start, mbi.RegionSize, pattern);
            while (match != nullptr)
            {
                --matches_remaining;
                if (matches_remaining == 0)
                    return match + pattern.offset;

                // Continue scanning past the current match
                const size_t consumed = static_cast<size_t>(match - region_start) + 1;
                if (consumed >= mbi.RegionSize)
                    break;
                match = find_pattern_raw(match + 1, mbi.RegionSize - consumed, pattern);
            }
        }

        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        assert(next > addr && "VirtualQuery returned a non-advancing region");
        if (next <= addr)
            break; // Overflow guard
        addr = next;
    }

    return nullptr;
}

Scanner::SimdLevel DetourModKit::Scanner::active_simd_level() noexcept
{
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

namespace
{
    std::uintptr_t resolve_candidate_match(std::uintptr_t match_addr,
                                           const DetourModKit::Scanner::AddrCandidate &c) noexcept
    {
        using DetourModKit::Scanner::ResolveMode;
        if (c.mode == ResolveMode::Direct)
        {
            return match_addr + static_cast<std::uintptr_t>(c.disp_offset);
        }
        const auto *disp_ptr = reinterpret_cast<const std::int32_t *>(match_addr +
                                                                      static_cast<std::uintptr_t>(c.disp_offset));
        return static_cast<std::uintptr_t>(
            static_cast<std::int64_t>(match_addr + static_cast<std::uintptr_t>(c.instr_end_offset)) +
            *disp_ptr);
    }

    // Minimum number of literal (non-wildcard) bytes the tail of the pattern
    // must contain after dropping the first 5 prologue tokens. Without this
    // floor the rebuilt pattern devolves into near-JMP-matches-everything and
    // yields false hits in any large .text region.
    constexpr int kPrologueFallbackMinTailLiterals = 5;

    // Upper bound on hits the rebuilt fallback pattern may produce across the
    // process's executable regions before we reject it as ambiguous.
    constexpr std::size_t kPrologueFallbackMaxHits = 4;

    bool is_wildcard_token(std::string_view token) noexcept
    {
        return token == "?" || token == "??";
    }

    // Walks the AOB token stream and splits it into (first 5 byte-tokens, tail).
    // The `|` anchor marker is stripped because the rebuilt pattern targets
    // the hooked-prologue start. Returns false if the source has fewer than
    // 5 byte-tokens.
    struct PrologueSplit
    {
        std::vector<std::string_view> tail_tokens;
        int literal_tail_count{0};
    };

    bool split_prologue(std::string_view orig, PrologueSplit &out) noexcept
    {
        std::size_t i = 0;
        int byte_tokens = 0;
        while (i < orig.size())
        {
            while (i < orig.size() && (orig[i] == ' ' || orig[i] == '\t' ||
                                       orig[i] == '\n' || orig[i] == '\r'))
            {
                ++i;
            }
            if (i >= orig.size())
            {
                break;
            }
            if (orig[i] == '|')
            {
                ++i;
                continue;
            }
            const std::size_t tok_start = i;
            while (i < orig.size() && orig[i] != ' ' && orig[i] != '\t' &&
                   orig[i] != '\n' && orig[i] != '\r' && orig[i] != '|')
            {
                ++i;
            }
            const std::string_view tok = orig.substr(tok_start, i - tok_start);
            if (tok.empty())
            {
                continue;
            }
            if (byte_tokens >= 5)
            {
                out.tail_tokens.push_back(tok);
                if (!is_wildcard_token(tok))
                {
                    ++out.literal_tail_count;
                }
            }
            ++byte_tokens;
        }
        return byte_tokens >= 5;
    }

    std::string build_hooked_prologue_pattern(std::string_view orig)
    {
        if (orig.empty())
        {
            return {};
        }
        PrologueSplit split;
        if (!split_prologue(orig, split))
        {
            return {};
        }
        if (split.literal_tail_count < kPrologueFallbackMinTailLiterals)
        {
            return {};
        }
        std::string out = "E9 ?? ?? ?? ??";
        for (const auto &tok : split.tail_tokens)
        {
            out.push_back(' ');
            out.append(tok);
        }
        return out;
    }

    // Returns true if `addr` lies inside any currently loaded module's
    // executable image range. Used to reject E9-rel32 destinations that
    // resolve into unmapped or data-only memory.
    bool is_address_in_module(std::uintptr_t addr) noexcept
    {
        if (addr == 0)
        {
            return false;
        }
        HMODULE mod = nullptr;
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(addr), &mod) ||
            mod == nullptr)
        {
            return false;
        }
        return true;
    }

    // Counts up to (max_hits + 1) occurrences of `pattern` across executable
    // regions. Returning max_hits+1 signals "too many to be unique".
    std::size_t count_pattern_hits_bounded(const DetourModKit::Scanner::CompiledPattern &pattern,
                                           std::size_t max_hits) noexcept
    {
        std::size_t hits = 0;
        for (std::size_t n = 1; n <= max_hits + 1; ++n)
        {
            const auto *match = DetourModKit::Scanner::scan_executable_regions(pattern, n);
            if (match == nullptr)
            {
                break;
            }
            ++hits;
        }
        return hits;
    }

    struct CascadeAttempt
    {
        std::uintptr_t address{0};
        size_t index{0};
        bool success{false};
    };

    CascadeAttempt scan_candidates(std::span<const DetourModKit::Scanner::AddrCandidate> candidates,
                                   bool &all_parse_failed,
                                   DetourModKit::Logger &logger)
    {
        all_parse_failed = true;
        for (size_t i = 0; i < candidates.size(); ++i)
        {
            const auto &c = candidates[i];
            auto compiled = DetourModKit::Scanner::parse_aob(c.pattern);
            if (!compiled)
            {
                logger.warning("Scanner: Failed to parse AOB for candidate '{}'.",
                               c.name.empty() ? std::string_view{"<unnamed>"} : c.name);
                continue;
            }
            all_parse_failed = false;
            const auto *match = DetourModKit::Scanner::scan_executable_regions(*compiled);
            if (match != nullptr)
            {
                const auto addr = resolve_candidate_match(
                    reinterpret_cast<std::uintptr_t>(match), c);
                return CascadeAttempt{addr, i, true};
            }
        }
        return CascadeAttempt{0, 0, false};
    }

    struct PrologueFallbackResult
    {
        CascadeAttempt attempt{};
        bool not_applicable{true};
    };

    PrologueFallbackResult scan_candidates_hooked_prologue(
        std::span<const DetourModKit::Scanner::AddrCandidate> candidates,
        DetourModKit::Logger &logger)
    {
        using DetourModKit::Scanner::ResolveMode;
        PrologueFallbackResult out;
        for (size_t i = 0; i < candidates.size(); ++i)
        {
            const auto &c = candidates[i];
            if (c.mode != ResolveMode::Direct)
            {
                continue;
            }
            auto hooked = build_hooked_prologue_pattern(c.pattern);
            if (hooked.empty())
            {
                logger.debug("Scanner: prologue fallback skipped for '{}' (insufficient literal tail bytes)",
                             c.name.empty() ? std::string_view{"<unnamed>"} : c.name);
                continue;
            }
            auto compiled = DetourModKit::Scanner::parse_aob(hooked);
            if (!compiled)
            {
                continue;
            }
            out.not_applicable = false;
            const std::size_t hits =
                count_pattern_hits_bounded(*compiled, kPrologueFallbackMaxHits);
            if (hits == 0)
            {
                continue;
            }
            if (hits > kPrologueFallbackMaxHits)
            {
                logger.debug(
                    "Scanner: prologue fallback rejected for '{}': {} hits exceed uniqueness ceiling ({})",
                    c.name.empty() ? std::string_view{"<unnamed>"} : c.name,
                    hits, kPrologueFallbackMaxHits);
                continue;
            }
            const auto *match = DetourModKit::Scanner::scan_executable_regions(*compiled);
            if (match == nullptr)
            {
                continue;
            }

            const auto match_addr = reinterpret_cast<std::uintptr_t>(match);
            const auto decoded = DetourModKit::detail::decode_e9_rel32(match_addr);
            if (!decoded)
            {
                continue;
            }
            const auto jmp_destination = *decoded;
            if (!is_address_in_module(jmp_destination))
            {
                logger.debug(
                    "Scanner: prologue fallback rejected for '{}': E9 destination {} not in any module",
                    c.name.empty() ? std::string_view{"<unnamed>"} : c.name,
                    jmp_destination);
                continue;
            }

            const auto addr = resolve_candidate_match(match_addr, c);
            out.attempt = CascadeAttempt{addr, i, true};
            return out;
        }
        return out;
    }
} // anonymous namespace

std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
DetourModKit::Scanner::resolve_cascade(std::span<const AddrCandidate> candidates,
                                       std::string_view label)
{
    auto &logger = Logger::get_instance();

    if (candidates.empty())
    {
        logger.warning("Scanner: resolve_cascade for '{}' called with no candidates.", label);
        return std::unexpected(ResolveError::EmptyCandidates);
    }

    bool all_parse_failed = true;
    const auto attempt = scan_candidates(candidates, all_parse_failed, logger);
    if (attempt.success)
    {
        const auto &winner = candidates[attempt.index];
        logger.info("{} resolved via '{}' at {}", label,
                    winner.name.empty() ? std::string_view{"<unnamed>"} : winner.name,
                    Format::format_address(attempt.address));
        return ResolveHit{attempt.address, winner.name};
    }

    if (all_parse_failed)
    {
        logger.error("{}: every candidate pattern failed to parse.", label);
        return std::unexpected(ResolveError::AllPatternsInvalid);
    }

    logger.warning("{}: cascade AOB scan failed (no candidate matched).", label);
    return std::unexpected(ResolveError::NoMatch);
}

std::expected<DetourModKit::Scanner::ResolveHit, DetourModKit::Scanner::ResolveError>
DetourModKit::Scanner::resolve_cascade_with_prologue_fallback(
    std::span<const AddrCandidate> candidates, std::string_view label)
{
    auto &logger = Logger::get_instance();

    if (candidates.empty())
    {
        logger.warning("Scanner: resolve_cascade_with_prologue_fallback for '{}' called with no candidates.", label);
        return std::unexpected(ResolveError::EmptyCandidates);
    }

    bool all_parse_failed = true;
    auto attempt = scan_candidates(candidates, all_parse_failed, logger);
    if (attempt.success)
    {
        const auto &winner = candidates[attempt.index];
        logger.info("{} resolved via '{}' at {}", label,
                    winner.name.empty() ? std::string_view{"<unnamed>"} : winner.name,
                    Format::format_address(attempt.address));
        return ResolveHit{attempt.address, winner.name};
    }

    const auto hooked = scan_candidates_hooked_prologue(candidates, logger);
    if (hooked.attempt.success)
    {
        const auto &winner = candidates[hooked.attempt.index];
        logger.info(
            "{} resolved via '{}' at {} (pre-hooked prologue; reusing target)",
            label,
            winner.name.empty() ? std::string_view{"<unnamed>"} : winner.name,
            Format::format_address(hooked.attempt.address));
        return ResolveHit{hooked.attempt.address, winner.name};
    }

    if (all_parse_failed)
    {
        logger.error("{}: every candidate pattern failed to parse.", label);
        return std::unexpected(ResolveError::AllPatternsInvalid);
    }

    if (hooked.not_applicable)
    {
        logger.warning("{}: cascade AOB scan failed; prologue fallback not applicable (insufficient literal tail bytes).",
                       label);
        return std::unexpected(ResolveError::PrologueFallbackNotApplicable);
    }

    logger.warning("{}: cascade AOB scan failed (including prologue fallback).", label);
    return std::unexpected(ResolveError::NoMatch);
}
