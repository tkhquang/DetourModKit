#ifndef DETOURMODKIT_DETAIL_PATTERN_CORE_HPP
#define DETOURMODKIT_DETAIL_PATTERN_CORE_HPP

/**
 * @file pattern_core.hpp
 * @brief Logger-free, heap-free constexpr core that parses the AOB mini-DSL and selects a rarest-byte anchor.
 * @details The public scan::Pattern type needs to parse the same "48 8B ?? E8 ? ? ? ?" DSL in two very different
 *          contexts: scan::Pattern::compile() at run time (from a configuration string, returning a Result) and
 *          scan::Pattern::literal() at COMPILE time (from an in-source string literal, where a typo must be a build
 *          error). A single parser cannot serve both if it touches the heap (a consteval result may not own
 *          non-transient heap storage) or the logging singleton (not constexpr-callable). This core is therefore a
 *          pure constexpr function that writes into fixed-size arrays and reports failure through a status enum, with
 *          no std::vector and no Logger anywhere in its body. Both Pattern entry points call it and only differ in how
 *          they react to a non-Ok status (compile() maps it to an Error, literal() turns it into a hard compile error).
 *
 *          The byte/mask encoding, the match semantics, and the rarest-byte anchor heuristic are reproduced exactly
 *          from the runtime scan engine so a pattern compiled here resolves identically to one parsed by the legacy
 *          path; the engine's runtime haystack-frequency selection may later OVERRIDE this compile-time anchor, which
 *          serves as the fallback when no haystack histogram is available.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace DetourModKit::detail
{
    /**
     * @brief Inline-storage cap for a compiled pattern, in bytes.
     * @details The cap is baked into the std::array member type so that a compiled Pattern is a literal type a
     *          consteval result can return by value (a value owning heap storage cannot be returned from consteval).
     *          Game AOB signatures are short; 128 covers every shipped consumer literal with wide headroom and also
     *          admits the longest exercised runtime patterns, since literal() and compile() share this one storage.
     */
    inline constexpr std::size_t MAX_PATTERN_BYTES = 128;

    /**
     * @brief Anchor sentinel meaning "no fully-known byte exists to anchor on".
     * @details Set to the cap so it is always one past any valid index. An all-wildcard or nibble-only pattern has no
     *          full byte the prefilter can memchr for and resolves through a masked compare at every position instead.
     */
    inline constexpr std::size_t NO_ANCHOR = MAX_PATTERN_BYTES;

    /**
     * @enum PatternStatus
     * @brief Outcome of parsing an AOB DSL string in the constexpr core.
     */
    enum class PatternStatus : std::uint8_t
    {
        /// Parsed successfully into at least one byte.
        Ok,
        /// The input held no byte tokens (empty, whitespace-only, or only an offset marker).
        Empty,
        /// A token was not a recognized DSL form.
        InvalidToken,
        /// The pattern exceeded MAX_PATTERN_BYTES byte tokens.
        TooLong,
        /// More than one offset marker was present.
        DuplicateOffset
    };

    /**
     * @struct PatternBuffer
     * @brief The compiled byte/mask representation plus the offset marker and the selected anchor index.
     * @details A literal-type aggregate (no heap): @ref bytes and @ref mask are fixed arrays sized to the cap, and
     *          only the first @ref length entries are meaningful. @ref offset is the "point of interest" the optional
     *          `|` marker records (0 when absent, which coincides with the match start). @ref anchor is the index of
     *          the rarest fully-known byte, or @ref NO_ANCHOR when none exists.
     */
    struct PatternBuffer
    {
        /// Pattern byte values; only entries [0, length) are valid.
        std::array<std::byte, MAX_PATTERN_BYTES> bytes{};
        /// Per-byte match mask (0xFF literal, 0x00 wildcard, 0xF0 high nibble, 0x0F low nibble).
        std::array<std::byte, MAX_PATTERN_BYTES> mask{};
        /// Number of valid byte entries.
        std::size_t length{0};
        /// Result offset recorded by the `|` marker; 0 when no marker is present.
        std::size_t offset{0};
        /// Index of the rarest fully-known byte, or NO_ANCHOR when the pattern has no full byte.
        std::size_t anchor{NO_ANCHOR};
    };

    /**
     * @struct PatternParse
     * @brief A parse status paired with the buffer it produced (valid only when status == Ok).
     */
    struct PatternParse
    {
        /// Parse outcome.
        PatternStatus status{PatternStatus::Empty};
        /// The compiled representation; meaningful only when @ref status is Ok.
        PatternBuffer buffer{};
    };

    /// Maps a hex digit to its value 0-15, or -1 if @p ch is not a hex digit.
    [[nodiscard]] constexpr int hex_digit(char ch) noexcept
    {
        if (ch >= '0' && ch <= '9')
        {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f')
        {
            return ch - 'a' + 10;
        }
        if (ch >= 'A' && ch <= 'F')
        {
            return ch - 'A' + 10;
        }
        return -1;
    }

    /// True for the token separators the DSL splits on (space, tab, CR, LF, form feed, vertical tab).
    [[nodiscard]] constexpr bool is_token_space(char ch) noexcept
    {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f' || ch == '\v';
    }

    /**
     * @brief Scores how common a byte is in typical x64 .text; lower means rarer and a better scan anchor.
     * @param value The fully-known byte to score.
     * @return A frequency class where 0 is the rarest (any byte outside the common-opcode table).
     * @details Reproduces the runtime engine's table verbatim so the compile-time anchor matches the byte the engine
     *          would have chosen. The listed bytes are the usual high-frequency suspects (padding, INT3/NOP fill, REX
     *          prefixes, common MOV/two-byte-opcode/branch leads); anything else is treated as rare and preferred.
     */
    [[nodiscard]] constexpr std::uint8_t byte_frequency_class(std::uint8_t value) noexcept
    {
        switch (value)
        {
        case 0x00:
            return 10;
        case 0xCC:
            return 9;
        case 0x90:
            return 9;
        case 0xFF:
            return 8;
        case 0x48:
            return 8;
        case 0x8B:
            return 7;
        case 0x89:
            return 7;
        case 0x0F:
            return 7;
        case 0xE8:
            return 6;
        case 0xE9:
            return 6;
        case 0x83:
            return 6;
        case 0xC3:
            return 5;
        default:
            return 0;
        }
    }

    /**
     * @brief Picks the index of the rarest fully-known byte to drive the prefilter.
     * @param buffer A parsed buffer (only [0, length) is inspected).
     * @return The index of the lowest-frequency 0xFF-masked byte, or NO_ANCHOR if the pattern has no full byte.
     * @details Only a fully-known byte can anchor, because the prefilter sweeps with a single-byte memchr that cannot
     *          search for a partial nibble. The scan keeps the lowest-scoring candidate seen so far and stops early
     *          once it finds a rarest-class byte (score 0), since no later byte can beat it.
     */
    [[nodiscard]] constexpr std::size_t select_anchor(const PatternBuffer &buffer) noexcept
    {
        std::size_t best = NO_ANCHOR;
        std::uint8_t best_score = 0xFF;
        for (std::size_t index = 0; index < buffer.length; ++index)
        {
            if (buffer.mask[index] != std::byte{0xFF})
            {
                continue;
            }
            const std::uint8_t score = byte_frequency_class(std::to_integer<std::uint8_t>(buffer.bytes[index]));
            if (score < best_score)
            {
                best = index;
                best_score = score;
                if (score == 0)
                {
                    break;
                }
            }
        }
        return best;
    }

    /**
     * @brief Parses an AOB DSL string into a PatternBuffer at compile time or run time.
     * @param dsl The whitespace-separated token string, e.g. "48 8B 05 ?? ?? ?? ??".
     * @return A PatternParse whose status is Ok (with a filled buffer) or a specific failure.
     * @details Tokens are split on whitespace; leading/trailing whitespace is ignored. Recognized tokens:
     *          - two hex digits (`48`)       -> that byte, mask 0xFF (fully known)
     *          - `??` or `?`                 -> any byte, mask 0x00 (full wildcard)
     *          - hex digit then `?` (`4?`)   -> high nibble fixed, mask 0xF0
     *          - `?` then hex digit (`?5`)   -> low nibble fixed, mask 0x0F
     *          - `|`                         -> offset marker: records the position of the NEXT byte (or the length
     *                                           when trailing) as the result offset; permitted at most once
     *          Any other token shape fails with InvalidToken. An input with no byte tokens fails with Empty. Exceeding
     *          MAX_PATTERN_BYTES fails with TooLong. On Ok, the rarest-byte anchor is computed and cached.
     */
    [[nodiscard]] constexpr PatternParse parse_pattern(std::string_view dsl) noexcept
    {
        PatternParse result{};
        PatternBuffer &buffer = result.buffer;
        bool offset_marked = false;

        std::size_t cursor = 0;
        const std::size_t end = dsl.size();
        while (cursor < end)
        {
            if (is_token_space(dsl[cursor]))
            {
                ++cursor;
                continue;
            }

            const std::size_t token_start = cursor;
            while (cursor < end && !is_token_space(dsl[cursor]))
            {
                ++cursor;
            }
            const std::string_view token = dsl.substr(token_start, cursor - token_start);

            // Offset marker: the position of interest is wherever the next byte lands. Placed at the very end, that is
            // one past the final byte (offset == length), which is exactly the value the loop already holds.
            if (token.size() == 1 && token[0] == '|')
            {
                if (offset_marked)
                {
                    result.status = PatternStatus::DuplicateOffset;
                    return result;
                }
                offset_marked = true;
                buffer.offset = buffer.length;
                continue;
            }

            std::byte byte_value{0x00};
            std::byte mask_value{0x00};
            const bool double_wildcard = token.size() == 2 && token[0] == '?' && token[1] == '?';
            const bool single_wildcard = token.size() == 1 && token[0] == '?';
            if (double_wildcard || single_wildcard)
            {
                // Full wildcard: any byte matches, so both value and mask stay zero.
            }
            else if (token.size() == 2)
            {
                const int high = hex_digit(token[0]);
                const int low = hex_digit(token[1]);
                if (high >= 0 && low >= 0)
                {
                    byte_value = static_cast<std::byte>(static_cast<unsigned char>((high << 4) | low));
                    mask_value = std::byte{0xFF};
                }
                else if (high >= 0 && token[1] == '?')
                {
                    byte_value = static_cast<std::byte>(static_cast<unsigned char>(high << 4));
                    mask_value = std::byte{0xF0};
                }
                else if (token[0] == '?' && low >= 0)
                {
                    byte_value = static_cast<std::byte>(static_cast<unsigned char>(low));
                    mask_value = std::byte{0x0F};
                }
                else
                {
                    result.status = PatternStatus::InvalidToken;
                    return result;
                }
            }
            else
            {
                result.status = PatternStatus::InvalidToken;
                return result;
            }

            if (buffer.length >= MAX_PATTERN_BYTES)
            {
                result.status = PatternStatus::TooLong;
                return result;
            }
            buffer.bytes[buffer.length] = byte_value;
            buffer.mask[buffer.length] = mask_value;
            ++buffer.length;
        }

        if (buffer.length == 0)
        {
            result.status = PatternStatus::Empty;
            return result;
        }

        buffer.anchor = select_anchor(buffer);
        result.status = PatternStatus::Ok;
        return result;
    }

} // namespace DetourModKit::detail

#endif // DETOURMODKIT_DETAIL_PATTERN_CORE_HPP
