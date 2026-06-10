/**
 * @file scanner.cpp
 * @brief Implementation of Array-of-Bytes (AOB) parsing, scanning, and RIP-relative resolution.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/format.hpp"

#include "scanner_internal.hpp"

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
     * @return The next byte offset to resume verification from on success
     *         (equal to pattern.size() when the AVX2 tier covered the whole
     *         pattern), or std::nullopt when a 32-byte chunk did not match
     *         and the caller must abandon this candidate position.
     * @note This function is compiled with AVX2 codegen via target attribute on
     *       GCC/Clang. On MSVC, intrinsics are always available.
     */
    DMK_AVX2_TARGET
    std::optional<size_t> verify_pattern_avx2(const std::byte *pattern_start,
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
                return std::nullopt;
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
    static constexpr uint8_t byte_frequency_class(uint8_t byte_value) noexcept
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
     * @brief Picks the rarest literal byte's index in a compiled pattern.
     * @return The byte index in `[0, pattern.size())` with the lowest score,
     *         or `pattern.size()` when every position is a wildcard.
     */
    size_t select_pattern_anchor(const Scanner::CompiledPattern &pattern) noexcept
    {
        const size_t pattern_size = pattern.size();
        size_t best = pattern_size;
        uint8_t best_score = UINT8_MAX;
        for (size_t i = 0; i < pattern_size; ++i)
        {
            if (pattern.mask[i] == std::byte{0x00})
            {
                continue;
            }
            const uint8_t score =
                byte_frequency_class(static_cast<uint8_t>(pattern.bytes[i]));
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

    result.compile_anchor();
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
        for (const std::byte mask_byte : pattern.mask)
        {
            if (mask_byte != std::byte{0x00})
                return true;
        }
        return false;
    }

    // Shared precondition check for the public find_pattern overloads. Returns
    // false when the caller must short-circuit with nullptr (empty pattern or
    // null start_address). Emits the all-wildcard warning itself so callers
    // do not duplicate it; in that case the caller still continues scanning.
    bool validate_find_pattern_inputs(const std::byte *start_address,
                                      const Scanner::CompiledPattern &pattern) noexcept
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
    const std::byte *find_pattern_raw(const std::byte *start_address, size_t region_size,
                                      const Scanner::CompiledPattern &pattern) noexcept
    {
        const size_t pattern_size = pattern.size();

        if (pattern_size == 0 || !start_address || region_size < pattern_size)
        {
            return nullptr;
        }

        // Anchor selection: parse_aob() pre-populates pattern.anchor, so the
        // common path is a single load. Manually constructed patterns fall
        // back to inline selection without mutating the input (preserves the
        // const-by-design contract).
        const size_t best_anchor = (pattern.anchor <= pattern_size)
                                       ? pattern.anchor
                                       : select_pattern_anchor(pattern);

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

        // Hoist runtime CPU detection. The query itself is a function-local
        // static behind a one-shot init, but reading it on every memchr hit
        // adds an indirect load per false candidate. Caching it once here
        // lets the per-hit branch use a register-resident bool.
#ifdef DMK_HAS_AVX2
        const bool use_avx2 = cpu_has_avx2();
#endif

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
            if (use_avx2)
            {
                const auto next_j = verify_pattern_avx2(pattern_start, pattern, 0);
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

    if (!validate_find_pattern_inputs(start_address, pattern))
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
    // Read the displacement under a single SEH fault guard instead of
    // is_readable + raw memcpy. is_readable is a time-of-check/time-of-use
    // illusion -- the page can change protection or unmap between the check
    // and the copy -- so an unguarded memcpy could fault the host.
    const auto displacement = Memory::seh_read<int32_t>(reinterpret_cast<uintptr_t>(disp_ptr));
    if (!displacement)
    {
        return std::unexpected(RipResolveError::UnreadableDisplacement);
    }

    // Compute the target in unsigned modular arithmetic so the math stays
    // well-defined on every input, including kernel-range instruction
    // addresses (where intptr_t would be negative and signed overflow is UB).
    // The displacement is sign-extended first so negative disp32 values wrap
    // to the correct 64-bit offset.
    const uintptr_t base = reinterpret_cast<uintptr_t>(instruction_address);
    const uintptr_t disp_sext = static_cast<uintptr_t>(static_cast<int64_t>(*displacement));
    const uintptr_t target = base + instruction_length + disp_sext;

    // Fail closed on a target that cannot be a real in-process address. A
    // corrupt or hostile displacement can resolve to 0, a low guard-page
    // address, or a kernel-range value; returning that as "success" would hand
    // the caller a pointer that faults on first use. plausible_userspace_ptr is
    // pure arithmetic, so this guard adds no syscall and no memory access.
    if (!Memory::plausible_userspace_ptr(target))
    {
        return std::unexpected(RipResolveError::ImplausibleTarget);
    }
    return target;
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

namespace
{
    // Region-walking AOB scan shared by scan_executable_regions,
    // scan_readable_regions, and the module-scoped detail::scan_module_* entry
    // points. Walks the committed regions
    // of [window_lo, window_hi) via VirtualQuery and runs find_pattern_raw
    // against every region whose base protection is present in accept_mask,
    // returning the Nth match (1-based, adjusted by pattern.offset) or nullptr.
    // The whole-process scanners pass [0, UINTPTR_MAX); the module-scoped scan
    // passes the image's [base, end) so only one contiguous image is searched.
    //
    // Guard, no-access, and uncommitted regions are always skipped: PAGE_GUARD
    // raises STATUS_GUARD_PAGE_VIOLATION on the first touch and PAGE_NOACCESS
    // faults even for reads, so neither is safe to dereference. The Windows base
    // protections (PAGE_READONLY, PAGE_READWRITE, ... , PAGE_EXECUTE_WRITECOPY)
    // are mutually exclusive single bits, so a bitwise-AND against a mask of the
    // acceptable bases is a sound membership test. PAGE_GUARD is a modifier bit
    // OR-ed onto a base value (a guarded read-only page reads as PAGE_READONLY |
    // PAGE_GUARD), so it must be excluded separately or it would satisfy the
    // mask and be scanned.
    //
    // Each region is scanned through the raw helper so the final
    // `+ pattern.offset` applies exactly once (the public find_pattern already
    // applies offset; calling it here would double-apply). A pattern straddling
    // two adjacent VAD entries is therefore not found; PE-loaded sections are
    // contiguous, so normal module scanning is unaffected.
    const std::byte *scan_regions_filtered(const Scanner::CompiledPattern &pattern,
                                           size_t occurrence, DWORD accept_mask,
                                           uintptr_t window_lo, uintptr_t window_hi) noexcept
    {
        // The compiled pattern's own bytes buffer lives in readable heap memory,
        // so a whole-process readable sweep would match the needle against
        // itself and could return the caller's pattern storage instead of the
        // intended target. Exclude any match that overlaps that buffer. The
        // executable sweep never reaches pattern.bytes (the heap is not
        // executable), so this is a no-op there and keeps both scanners
        // consistent: a scan never matches the needle's own storage. The needle
        // is the caller's allocation, so no real target can share its range.
        const auto needle_lo = reinterpret_cast<uintptr_t>(pattern.bytes.data());
        const auto needle_hi = needle_lo + pattern.size();

        size_t matches_remaining = occurrence;
        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = window_lo;

        while (addr < window_hi && VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
        {
            const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
            const auto region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t region_end = region_base + mbi.RegionSize;

            // Clamp the region to the requested window so a region that straddles
            // window_lo / window_hi is inspected only where it intersects. For a
            // whole-process sweep the window is [0, UINTPTR_MAX), so the clamp is
            // a no-op and the scanned span equals the region. For a module-scoped
            // sweep this is what keeps the scan inside [base, end) even when a
            // VirtualQuery region (e.g. a section straddling the image boundary)
            // extends past it.
            const uintptr_t scan_lo = region_base < window_lo ? window_lo : region_base;
            const uintptr_t scan_hi = region_end > window_hi ? window_hi : region_end;

            if (mbi.State == MEM_COMMIT && (mbi.Protect & accept_mask) != 0 &&
                !protection_unsafe && scan_hi > scan_lo)
            {
                const size_t scan_size = static_cast<size_t>(scan_hi - scan_lo);
                if (scan_size >= pattern.size())
                {
                    const auto *region_start = reinterpret_cast<const std::byte *>(scan_lo);

                    const std::byte *match = find_pattern_raw(region_start, scan_size, pattern);
                    while (match != nullptr)
                    {
                        const auto match_addr = reinterpret_cast<uintptr_t>(match);
                        const bool self_match = match_addr < needle_hi &&
                                                (match_addr + pattern.size()) > needle_lo;
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
                }
            }

            assert(region_end > addr && "VirtualQuery returned a non-advancing region");
            if (region_end <= addr)
                break; // Overflow guard.
            addr = region_end;
        }

        return nullptr;
    }

    // Base protections accepted by the executable-only sweeps: the three page
    // variants that grant execute *and* read. Bare PAGE_EXECUTE (execute without
    // a read bit) is excluded because dereferencing it raises an access
    // violation; PAGE_GUARD / PAGE_NOACCESS are filtered separately inside
    // scan_regions_filtered. This is the scope for code-only scans: the
    // whole-process scan_executable_regions and the prologue-recovery fallback,
    // whose rebuilt near-JMP can only ever overwrite a code prologue.
    constexpr DWORD EXECUTABLE_PAGE_FLAGS = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                            PAGE_EXECUTE_WRITECOPY;

    // Base protections accepted by the readable sweep and the data-capable
    // module-scoped cascade: the executable-readable set plus the non-executable
    // readable pages (.rdata / .data and read-only heaps). This reaches C++
    // vtables, RTTI type descriptors, and other read-only metadata the
    // executable-only sweep cannot see.
    constexpr DWORD READABLE_PAGE_FLAGS = EXECUTABLE_PAGE_FLAGS |
                                          PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;

} // anonymous namespace

// Module-scoped siblings of scan_executable_regions / scan_readable_regions:
// each searches only the mapped image [range.base, range.end) and returns the
// Nth match (1-based, adjusted by pattern.offset) or nullptr. They are the
// internal entry points the cascade resolver (its own TU) calls instead of
// reaching the page-protection masks directly. Both reuse scan_regions_filtered's
// per-region VirtualQuery protection gate, so a non-readable interior page (a
// section-alignment gap, a guard page, a sibling VirtualProtect on part of the
// image) is skipped instead of dereferenced; find_pattern_raw itself does an
// unguarded memchr / SIMD compare, so that region filter is what keeps a single
// contiguous scan from faulting the host.
const std::byte *Scanner::detail::scan_module_executable(const Scanner::CompiledPattern &pattern,
                                                         Memory::ModuleRange range,
                                                         std::size_t occurrence) noexcept
{
    // EXECUTABLE_PAGE_FLAGS confines the match to code: the prologue-recovery
    // fallback's rebuilt near-JMP can only ever overwrite a code prologue, so a
    // data-page hit would be a false positive.
    if (pattern.empty() || occurrence == 0 || !range.valid())
    {
        return nullptr;
    }
    return scan_regions_filtered(pattern, occurrence, EXECUTABLE_PAGE_FLAGS,
                                 range.base, range.end);
}

const std::byte *Scanner::detail::scan_module_readable(const Scanner::CompiledPattern &pattern,
                                                       Memory::ModuleRange range,
                                                       std::size_t occurrence) noexcept
{
    // READABLE_PAGE_FLAGS lets one pass cover both .text and .rdata / .data
    // candidates, which is why the in-module cascade needs no ScannerKind split.
    if (pattern.empty() || occurrence == 0 || !range.valid())
    {
        return nullptr;
    }
    return scan_regions_filtered(pattern, occurrence, READABLE_PAGE_FLAGS,
                                 range.base, range.end);
}

// Centralizes the executable-page protection gate for out-of-TU callers (the
// string-xref backend): one VirtualQuery walk over [range.base, range.end) that
// returns each committed, execute-readable region clamped to the range, using the
// identical mask scan_module_executable applies. Reading the returned windows
// without a fault guard is safe for the same reason scan_regions_filtered's
// unguarded compare is: the per-region gate (MEM_COMMIT, EXECUTABLE_PAGE_FLAGS,
// not PAGE_GUARD / PAGE_NOACCESS) is what guarantees readability.
std::vector<Scanner::detail::ExecutableWindow>
Scanner::detail::collect_executable_windows(Memory::ModuleRange range)
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

        if (mbi.State == MEM_COMMIT && (mbi.Protect & EXECUTABLE_PAGE_FLAGS) != 0 &&
            !protection_unsafe && scan_hi > scan_lo)
        {
            windows.push_back(
                ExecutableWindow{scan_lo, static_cast<std::size_t>(scan_hi - scan_lo)});
        }

        if (region_end <= addr)
        {
            break; // Overflow guard, mirroring scan_regions_filtered.
        }
        addr = region_end;
    }
    return windows;
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
    // PAGE_EXECUTE grants execute without read, so dereferencing such a page would
    // raise an access violation. Whole-process sweep: the window spans the entire
    // user address space, so the clamp in scan_regions_filtered is a no-op and the
    // walk stops only when VirtualQuery runs off the end of the address space.
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

    // READABLE_PAGE_FLAGS is a superset of the executable-only mask: every
    // committed region we can read, including .rdata / .data (PAGE_READONLY /
    // PAGE_READWRITE / PAGE_WRITECOPY) and read-only heaps, plus the
    // execute-readable variants. The semantic is "find this pattern anywhere
    // readable", so execute-readable code pages are intentionally included
    // rather than deduplicated against scan_executable_regions; callers wanting
    // non-code matches post-filter. The window spans the whole address space.
    return scan_regions_filtered(pattern, occurrence, READABLE_PAGE_FLAGS, 0, UINTPTR_MAX);
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

bool DetourModKit::Scanner::is_likely_function_prologue(std::uintptr_t addr) noexcept
{
    if (addr == 0)
    {
        return false;
    }

    // Read the first opcode byte under a fault guard rather than is_readable +
    // a raw dereference. is_readable is a TOCTOU illusion (the page can change
    // or unmap between the check and the read), and the bare dereference would
    // then fault the host. seh_read returns nullopt on any fault.
    const auto b0 = Memory::seh_read<std::uint8_t>(addr);
    if (!b0)
    {
        return false;
    }

    // Reject bytes that never begin a real function prologue, so an AOB match
    // that landed in inter-function padding or past a function's end is filtered
    // out instead of accepted as a target:
    //   0x00 -- zero fill / uninitialized page (decodes as `add [rax], al`)
    //   0xCC -- INT3, the alignment padding linkers insert between functions
    //   0xC3 -- RET (near return): a function epilogue, not a prologue
    //   0xC2 -- RET imm16: likewise a return, not a prologue
    return *b0 != 0x00 && *b0 != 0xCC && *b0 != 0xC2 && *b0 != 0xC3;
}
