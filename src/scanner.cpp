/**
 * @file scanner.cpp
 * @brief Implementation of Array-of-Bytes (AOB) parsing, scanning, and RIP-relative resolution.
 */

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/format.hpp"

#include <vector>
#include <string>
#include <sstream>
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

std::optional<Scanner::CompiledPattern> DetourModKit::Scanner::parse_aob(std::string_view aob_str)
{
    Logger &logger = Logger::get_instance();

    std::string trimmed_aob = trim(std::string(aob_str));
    if (trimmed_aob.empty())
    {
        if (!aob_str.empty())
        {
            logger.warning("AOB Parser: Input string became empty after trimming.");
        }
        return std::nullopt;
    }

    CompiledPattern result;
    std::istringstream iss(trimmed_aob);
    std::string token;
    size_t token_idx = 0;

    bool offset_set = false;

    while (iss >> token)
    {
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
        else if (token.length() == 2 && std::isxdigit(static_cast<unsigned char>(token[0])) && std::isxdigit(static_cast<unsigned char>(token[1])))
        {
            try
            {
                unsigned long ulong_val = std::stoul(token, nullptr, 16);
                if (ulong_val > 0xFF)
                {
                    throw std::out_of_range("Value parsed exceeds byte range (0xFF).");
                }
                result.bytes.push_back(static_cast<std::byte>(ulong_val));
                result.mask.push_back(std::byte{0xFF});
            }
            catch (const std::out_of_range &oor)
            {
                logger.error("AOB Parser: Hex conversion out of range for '{}' (Pos {}): {}", token, token_idx, oor.what());
                return std::nullopt;
            }
            catch (const std::invalid_argument &ia)
            {
                logger.error("AOB Parser: Invalid argument for hex conversion '{}' (Pos {}): {}", token, token_idx, ia.what());
                return std::nullopt;
            }
        }
        else
        {
            std::ostringstream oss_err;
            oss_err << "AOB Parser: Invalid token '" << token << "' at position " << token_idx
                    << ". Expected hex byte (e.g., FF), '?' or '?\?'.";
            logger.log(LogLevel::Error, oss_err.str());
            return std::nullopt;
        }
    }

    if (result.empty())
    {
        if (token_idx > 0)
        {
            logger.error("AOB Parser: Processed tokens but resulting pattern is empty.");
        }
        else if (!trimmed_aob.empty())
        {
            logger.warning("AOB: Parsing AOB string '{}' resulted in an empty pattern.", aob_str);
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

std::optional<uintptr_t> DetourModKit::Scanner::resolve_rip_relative(const std::byte *instruction_address,
                                                                     size_t displacement_offset,
                                                                     size_t instruction_length)
{
    if (!instruction_address)
    {
        return std::nullopt;
    }

    const std::byte *disp_ptr = instruction_address + displacement_offset;
    if (!Memory::is_readable(disp_ptr, sizeof(int32_t)))
    {
        return std::nullopt;
    }

    int32_t displacement;
    std::memcpy(&displacement, disp_ptr, sizeof(int32_t));

    auto base = reinterpret_cast<uintptr_t>(instruction_address);
    return base + instruction_length + static_cast<uintptr_t>(static_cast<intptr_t>(displacement));
}

std::optional<uintptr_t> DetourModKit::Scanner::find_and_resolve_rip_relative(const std::byte *search_start,
                                                                              size_t search_length,
                                                                              std::span<const std::byte> opcode_prefix,
                                                                              size_t instruction_length)
{
    if (!search_start || opcode_prefix.empty())
    {
        return std::nullopt;
    }

    const size_t prefix_len = opcode_prefix.size();
    const size_t min_bytes = prefix_len + sizeof(int32_t);
    if (search_length < min_bytes)
    {
        return std::nullopt;
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

    return std::nullopt;
}
