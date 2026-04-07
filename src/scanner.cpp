/**
 * @file scanner.cpp
 * @brief Implementation of Array-of-Bytes (AOB) parsing, scanning, and RIP-relative resolution.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/format.hpp"

#include <windows.h>
#include <vector>
#include <string>
#include <cctype>
#include <stdexcept>
#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#define DMK_HAS_SSE2 1
#include <emmintrin.h>
#endif

using namespace DetourModKit;
using namespace DetourModKit::String;

namespace
{
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
            logger.warning("AOB Parser: Input string became empty after trimming.");
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
            result.offset = result.bytes.size();
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
                logger.error("AOB Parser: Invalid token '{}' at position {}."
                             " Expected hex byte (e.g., FF), '?' or '?\?'.",
                             token, token_idx);
                return std::nullopt;
            }
        }
        else
        {
            logger.error("AOB Parser: Invalid token '{}' at position {}."
                         " Expected hex byte (e.g., FF), '?' or '?\?'.",
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

const std::byte *DetourModKit::Scanner::find_pattern(const std::byte *start_address, size_t region_size,
                                                     const CompiledPattern &pattern)
{
    Logger &logger = Logger::get_instance();
    const size_t pattern_size = pattern.size();

    if (pattern_size == 0)
    {
        logger.error("find_pattern: Pattern is empty. Cannot scan.");
        return nullptr;
    }
    if (!start_address)
    {
        logger.error("find_pattern: Start address is null. Cannot scan.");
        return nullptr;
    }
    if (region_size < pattern_size)
    {
        return nullptr;
    }

    // Select the best anchor byte: the non-wildcard byte with the lowest frequency score.
    // Ties are broken by first occurrence for deterministic behavior.
    size_t best_anchor = pattern_size; // invalid = all wildcards
    uint8_t best_score = UINT8_MAX;
    for (size_t i = 0; i < pattern_size; ++i)
    {
        if (pattern.mask[i] != std::byte{0x00})
        {
            uint8_t score = byte_frequency_class(static_cast<uint8_t>(pattern.bytes[i]));
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

    // All wildcards: matches immediately at start
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

        // Verify the full pattern at this position
        bool match_found = true;
        size_t j = 0;

#ifdef DMK_HAS_SSE2
        for (; j + 16 <= pattern_size; j += 16)
        {
            __m128i mem = _mm_loadu_si128(reinterpret_cast<const __m128i *>(pattern_start + j));
            __m128i pat = _mm_loadu_si128(reinterpret_cast<const __m128i *>(pattern.bytes.data() + j));
            __m128i msk = _mm_loadu_si128(reinterpret_cast<const __m128i *>(pattern.mask.data() + j));

            __m128i xored = _mm_xor_si128(mem, pat);
            __m128i masked = _mm_and_si128(xored, msk);
            __m128i cmp = _mm_cmpeq_epi8(masked, _mm_setzero_si128());

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

const std::byte *DetourModKit::Scanner::find_pattern(const std::byte *start_address, size_t region_size,
                                                     const CompiledPattern &pattern, size_t occurrence)
{
    if (occurrence == 0)
    {
        return nullptr;
    }

    const std::byte *cursor = start_address;
    size_t remaining = region_size;
    size_t found_count = 0;

    while (remaining >= pattern.size())
    {
        const std::byte *match = find_pattern(cursor, remaining, pattern);
        if (!match)
        {
            break;
        }
        if (++found_count == occurrence)
        {
            return match;
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

    auto base = reinterpret_cast<uintptr_t>(instruction_address);
    return base + instruction_length + static_cast<uintptr_t>(static_cast<intptr_t>(displacement));
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

    constexpr DWORD EXEC_FLAGS = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    size_t matches_remaining = occurrence;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;

    while (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
    {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & EXEC_FLAGS) != 0 &&
            (mbi.Protect & PAGE_GUARD) == 0 && mbi.RegionSize >= pattern.size())
        {
            const auto *region_start = reinterpret_cast<const std::byte *>(mbi.BaseAddress);

            const std::byte *match = find_pattern(region_start, mbi.RegionSize, pattern);
            while (match != nullptr)
            {
                --matches_remaining;
                if (matches_remaining == 0)
                    return match + pattern.offset;

                // Continue scanning past the current match
                const size_t consumed = static_cast<size_t>(match - region_start) + 1;
                if (consumed >= mbi.RegionSize)
                    break;
                match = find_pattern(match + 1, mbi.RegionSize - consumed, pattern);
            }
        }

        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr)
            break; // Overflow guard
        addr = next;
    }

    return nullptr;
}
