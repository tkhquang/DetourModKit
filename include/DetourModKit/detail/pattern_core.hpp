#ifndef DETOURMODKIT_DETAIL_PATTERN_CORE_HPP
#define DETOURMODKIT_DETAIL_PATTERN_CORE_HPP

/**
 * @file pattern_core.hpp
 * @brief Logger-free, heap-free constexpr core that parses the AOB mini-DSL and selects a rarest-byte anchor.
 * @details `scan::Pattern::compile()` and the consteval `scan::Pattern::literal()` both parse through this core. It
 *          uses fixed-size arrays because a consteval result cannot own heap storage. The runtime scan engine shares
 *          its grammar and byte/mask encoding. A scan can replace this anchor with a haystack-based one.
 * @note `scan.hpp` includes this header. docs/design/public-api.md owns the `detail/` placement rule.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace DetourModKit::detail
{
    /** @brief Inline-storage cap for a compiled pattern, in bytes. `literal()` and `compile()` share this cap. */
    inline constexpr std::size_t MAX_PATTERN_BYTES = 128;

    /** @brief Anchor sentinel for "segment 0 has no fully-known byte", one past any valid index. */
    inline constexpr std::size_t NO_ANCHOR = MAX_PATTERN_BYTES;

    /** @brief Cap on bounded-jump gaps in one pattern. A pattern with more gaps fails at parse with TooManyJumps. */
    inline constexpr std::size_t MAX_PATTERN_JUMPS = 8;

    /** @brief Cap on the maximum skip of one jump gap, in bytes. The parser rejects a larger bound. */
    inline constexpr std::size_t MAX_JUMP_SPAN = 256;

    /** @brief Per-start-position cap on matcher node visits. Past the cap, that placement reports no match. */
    inline constexpr std::size_t SEGMENT_MATCH_STEP_BUDGET = 1u << 16;
    static_assert(
        SEGMENT_MATCH_STEP_BUDGET >= MAX_PATTERN_JUMPS * MAX_JUMP_SPAN,
        "The per-position work budget must exceed the linear per-position cost of a well-formed pattern."
    );

    /**
     * @brief One bounded gap between two fixed byte runs (segments) of a compiled pattern.
     * @details @ref position lies strictly inside `(0, length)`. An exact `[N]` jump has `min_skip == max_skip`.
     */
    struct PatternJump
    {
        /// Index in the fixed byte stream that the gap precedes: the boundary between segment i and segment i+1.
        std::size_t position{0};
        /// Fewest bytes the gap can skip before the following segment.
        std::size_t min_skip{0};
        /// Most bytes the gap can skip before the following segment, in [min_skip, MAX_JUMP_SPAN].
        std::size_t max_skip{0};
    };

    /** @brief Outcome of an AOB DSL parse in the constexpr core. */
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
        DuplicateOffset,
        /// A `[...]` jump token was malformed, out of range, or illegally placed (leading, trailing, or adjacent).
        InvalidJump,
        /// The pattern named more bounded jumps than MAX_PATTERN_JUMPS.
        TooManyJumps
    };

    /** @brief A compiled pattern: segment bytes and masks with no gap bytes, plus offset, jumps, and anchor. */
    struct PatternBuffer
    {
        /// Pattern byte values. Only entries [0, length) are valid.
        std::array<std::byte, MAX_PATTERN_BYTES> bytes{};
        /// Per-byte match mask (0xFF fully known, 0x00 wildcard, 0xF0 high nibble, 0x0F low nibble).
        std::array<std::byte, MAX_PATTERN_BYTES> mask{};
        /// Number of valid byte entries: all segments concatenated, gaps excluded.
        std::size_t length{0};
        /// Result offset that the `|` marker records, or 0 (the match start) when no marker is present.
        std::size_t offset{0};
        /// Index of the rarest fully-known byte in segment 0, or NO_ANCHOR when segment 0 has none.
        std::size_t anchor{NO_ANCHOR};
        /// Bounded-jump gaps in ascending position order. Only entries [0, jump_count) are valid.
        std::array<PatternJump, MAX_PATTERN_JUMPS> jumps{};
        /// Number of valid jump gaps, 0 for a plain (single-segment) pattern.
        std::size_t jump_count{0};
    };

    /** @brief A parse status paired with the buffer it produced. */
    struct PatternParse
    {
        /// Parse outcome.
        PatternStatus status{PatternStatus::Empty};
        /// The compiled representation, meaningful only when @ref status is Ok.
        PatternBuffer buffer{};
    };

    /// Maps a hex digit to its value 0 to 15, or -1 if @p ch is not a hex digit.
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

    /// True for a character that separates DSL tokens.
    [[nodiscard]] constexpr bool is_token_space(char ch) noexcept
    {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f' || ch == '\v';
    }

    /**
     * @brief Scores how common @p value is in typical x64 .text. A lower score is a rarer byte, and 0 is the rarest.
     * @details The runtime scan engine and `sighealth` score with this same table.
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
     * @brief Picks the rarest fully-known byte in segment 0 (the run before the first jump) as the prefilter anchor.
     * @return Its index (the lowest index on a score tie), or NO_ANCHOR when segment 0 has no fully-known byte.
     */
    [[nodiscard]] constexpr std::size_t select_anchor(const PatternBuffer &buffer) noexcept
    {
        const std::size_t segment0_end = (buffer.jump_count > 0) ? buffer.jumps[0].position : buffer.length;
        std::size_t best = NO_ANCHOR;
        std::uint8_t best_score = 0xFF;
        for (std::size_t index = 0; index < segment0_end; ++index)
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

    /** @brief Parse outcome of one `[...]` bounded-jump token: a validity flag plus the resolved skip bounds. */
    struct JumpParse
    {
        /// True when the token was a well-formed, in-range bounded jump.
        bool ok{false};
        /// Fewest bytes the gap skips.
        std::size_t min_skip{0};
        /// Most bytes the gap skips.
        std::size_t max_skip{0};
    };

    /**
     * @brief Parses a whitespace-stripped bounded-jump token: `[X]` (exact, `[0]` is a valid no-op) or `[X-Y]` (range).
     * @details It rejects missing brackets, empty or non-decimal content, trailing junk, an inverted range, a bound
     *          above MAX_JUMP_SPAN, and the unbounded `[X-]` form.
     */
    [[nodiscard]] constexpr JumpParse parse_jump_token(std::string_view token) noexcept
    {
        JumpParse result{};
        if (token.size() < 3 || token.front() != '[' || token.back() != ']')
        {
            return result;
        }
        const std::string_view inner = token.substr(1, token.size() - 2);

        std::size_t cursor = 0;
        // A jump always names at least one number.
        if (cursor >= inner.size() || inner[cursor] < '0' || inner[cursor] > '9')
        {
            return result;
        }
        std::size_t min_value = 0;
        while (cursor < inner.size() && inner[cursor] >= '0' && inner[cursor] <= '9')
        {
            min_value = min_value * 10 + static_cast<std::size_t>(inner[cursor] - '0');
            if (min_value > MAX_JUMP_SPAN)
            {
                // This early exit also keeps the accumulator far from overflow.
                return result;
            }
            ++cursor;
        }

        std::size_t max_value = min_value;
        if (cursor < inner.size())
        {
            if (inner[cursor] != '-')
            {
                return result;
            }
            ++cursor;
            // A dash with no digits after it is the unbounded `[X-]` form, which the parser rejects.
            if (cursor >= inner.size() || inner[cursor] < '0' || inner[cursor] > '9')
            {
                return result;
            }
            max_value = 0;
            while (cursor < inner.size() && inner[cursor] >= '0' && inner[cursor] <= '9')
            {
                max_value = max_value * 10 + static_cast<std::size_t>(inner[cursor] - '0');
                if (max_value > MAX_JUMP_SPAN)
                {
                    return result;
                }
                ++cursor;
            }
        }

        if (cursor != inner.size() || max_value < min_value)
        {
            // Trailing junk after the bounds, or an inverted range.
            return result;
        }
        result.ok = true;
        result.min_skip = min_value;
        result.max_skip = max_value;
        return result;
    }

    /** @brief The fixed-array sink of @ref parse_pattern, capped at MAX_PATTERN_BYTES and MAX_PATTERN_JUMPS. */
    struct PatternBufferSink
    {
        /// The buffer that the parse fills, meaningful only after the parse returns Ok.
        PatternBuffer buffer{};

        /// Fixed bytes appended so far.
        [[nodiscard]] constexpr std::size_t length() const noexcept { return buffer.length; }
        /// Jump gaps appended so far.
        [[nodiscard]] constexpr std::size_t jump_count() const noexcept { return buffer.jump_count; }

        /// Appends one fixed byte, or returns false at the byte cap (the parser reports TooLong).
        [[nodiscard]] constexpr bool add_byte(std::byte value, std::byte mask) noexcept
        {
            if (buffer.length >= MAX_PATTERN_BYTES)
            {
                return false;
            }
            buffer.bytes[buffer.length] = value;
            buffer.mask[buffer.length] = mask;
            ++buffer.length;
            return true;
        }

        /// Records a gap, or returns false at the jump cap (the parser reports TooManyJumps).
        [[nodiscard]] constexpr bool add_jump(std::size_t position, std::size_t min_skip, std::size_t max_skip) noexcept
        {
            if (buffer.jump_count >= MAX_PATTERN_JUMPS)
            {
                return false;
            }
            buffer.jumps[buffer.jump_count] = PatternJump{position, min_skip, max_skip};
            ++buffer.jump_count;
            return true;
        }

        /// Records the `|` marker position in the fixed byte stream.
        constexpr void set_offset(std::size_t position) noexcept { buffer.offset = position; }
    };

    /**
     * @brief The single AOB DSL grammar, which parses into any storage sink (fixed-array or heap-backed).
     * @param sink A sink that provides add_byte, add_jump, set_offset, length, and jump_count.
     * @return On Ok, the sink holds the bytes, mask, jumps, and offset. The caller selects the anchor.
     * @details Whitespace splits the tokens. Recognized tokens:
     *          - two hex digits (`48`): that byte, mask 0xFF (fully known).
     *          - `??` or `?`: any byte, mask 0x00 (full wildcard).
     *          - hex digit then `?` (`4?`): high nibble known, mask 0xF0.
     *          - `?` then hex digit (`?5`): low nibble known, mask 0x0F.
     *          - `[X]` or `[X-Y]`: a bounded jump that skips exactly X, or X to Y, bytes before the next segment.
     *          - `|`: the offset marker, at most once. The result offset is the position of the next byte, or the
     *            length when the marker trails.
     *
     *          Any other token fails with InvalidToken. A malformed token that opens with `[` fails with InvalidJump.
     *          An input with only whitespace and at most one `|` fails with Empty. A sink that rejects an append fails
     *          with TooLong (byte cap) or TooManyJumps (jump cap).
     *
     *          Every segment must be a non-empty fixed run, so a jump cannot lead, trail, or be adjacent to another
     *          jump. A violation is InvalidJump. The `|` marker records a position in the fixed byte stream. When the
     *          pattern also has jumps, the runtime scan engine adds the actual gap bytes at match time.
     * @note It propagates an exception that the sink throws. `parse_aob` catches the `bad_alloc` of its heap-backed
     *       sink and returns `OutOfMemory`. docs/design/resolution.md owns the noexcept rule.
     */
    template <class Sink> [[nodiscard]] constexpr PatternStatus parse_pattern_into(std::string_view dsl, Sink &sink)
    {
        bool offset_marked = false;

        // The fixed length at the most recent jump, or 0. A new jump needs a fixed byte after this boundary, which
        // rejects a leading jump and two adjacent jumps. The end-of-parse check against it rejects a trailing jump.
        std::size_t last_boundary = 0;

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

            // Offset marker.
            if (token.size() == 1 && token[0] == '|')
            {
                if (offset_marked)
                {
                    return PatternStatus::DuplicateOffset;
                }
                offset_marked = true;
                sink.set_offset(sink.length());
                continue;
            }

            // Bounded jump.
            if (!token.empty() && token.front() == '[')
            {
                const JumpParse jump = parse_jump_token(token);
                if (!jump.ok)
                {
                    return PatternStatus::InvalidJump;
                }
                if (sink.length() == 0 || sink.length() == last_boundary)
                {
                    return PatternStatus::InvalidJump;
                }
                if (!sink.add_jump(sink.length(), jump.min_skip, jump.max_skip))
                {
                    return PatternStatus::TooManyJumps;
                }
                last_boundary = sink.length();
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
                    return PatternStatus::InvalidToken;
                }
            }
            else
            {
                return PatternStatus::InvalidToken;
            }

            if (!sink.add_byte(byte_value, mask_value))
            {
                return PatternStatus::TooLong;
            }
        }

        if (sink.length() == 0)
        {
            return PatternStatus::Empty;
        }

        // A trailing jump, as in "48 8B [2-5]", leaves last_boundary equal to the fixed length.
        if (sink.jump_count() > 0 && last_boundary == sink.length())
        {
            return PatternStatus::InvalidJump;
        }

        return PatternStatus::Ok;
    }

    /** @brief Parses @p dsl through @ref parse_pattern_into into scan::Pattern storage, then selects its anchor. */
    [[nodiscard]] constexpr PatternParse parse_pattern(std::string_view dsl) noexcept
    {
        PatternParse result{};
        PatternBufferSink sink{};
        result.status = parse_pattern_into(dsl, sink);
        if (result.status == PatternStatus::Ok)
        {
            result.buffer = sink.buffer;
            result.buffer.anchor = select_anchor(result.buffer);
        }
        return result;
    }

    /** @brief The fewest bytes any match of @p buffer can occupy: fixed bytes plus every gap's minimum skip. */
    [[nodiscard]] constexpr std::size_t min_match_length(const PatternBuffer &buffer) noexcept
    {
        std::size_t total = buffer.length;
        for (std::size_t i = 0; i < buffer.jump_count; ++i)
        {
            total += buffer.jumps[i].min_skip;
        }
        return total;
    }

    /**
     * @brief The fewest physical bytes from the offset-applied result point through the end of any match.
     * @details Only gaps after the marker position add their minimum skip. A gap at the marker position precedes the
     *          result point.
     */
    [[nodiscard]] constexpr std::size_t min_match_suffix_length(const PatternBuffer &buffer) noexcept
    {
        if (buffer.offset > buffer.length)
        {
            return 0;
        }
        std::size_t total = buffer.length - buffer.offset;
        for (std::size_t i = 0; i < buffer.jump_count; ++i)
        {
            if (buffer.jumps[i].position > buffer.offset)
            {
                total += buffer.jumps[i].min_skip;
            }
        }
        return total;
    }

    /** @brief The most bytes any match of @p buffer can occupy: fixed bytes plus every gap's maximum skip. */
    [[nodiscard]] constexpr std::size_t max_match_length(const PatternBuffer &buffer) noexcept
    {
        std::size_t total = buffer.length;
        for (std::size_t i = 0; i < buffer.jump_count; ++i)
        {
            total += buffer.jumps[i].max_skip;
        }
        return total;
    }

    /**
     * @brief Masked-compares fixed bytes [@p body_begin, @p body_end) against @p window at offset @p window_pos.
     * @return True when the run fits in the window and `(memory ^ pattern) & mask == 0` for every byte of the run.
     */
    [[nodiscard]] constexpr bool run_matches_at(
        const PatternBuffer &buffer,
        std::span<const std::byte> window,
        std::size_t window_pos,
        std::size_t body_begin,
        std::size_t body_end
    ) noexcept
    {
        const std::size_t run_length = body_end - body_begin;
        if (window_pos > window.size() || run_length > window.size() - window_pos)
        {
            return false;
        }
        for (std::size_t i = 0; i < run_length; ++i)
        {
            const std::byte masked_diff =
                (window[window_pos + i] ^ buffer.bytes[body_begin + i]) & buffer.mask[body_begin + i];
            if (masked_diff != std::byte{0x00})
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief Tests whether segment @p segment_index and every later segment match at @p window_pos. It backtracks.
     * @param steps The node-visit count for this start position. Start it at 0. See SEGMENT_MATCH_STEP_BUDGET.
     * @details Recursion depth is at most MAX_PATTERN_JUMPS + 1.
     */
    [[nodiscard]] constexpr bool try_segments_at(
        const PatternBuffer &buffer,
        std::span<const std::byte> window,
        std::size_t segment_index,
        std::size_t window_pos,
        std::size_t &steps
    ) noexcept
    {
        if (++steps > SEGMENT_MATCH_STEP_BUDGET)
        {
            return false;
        }

        const std::size_t segment_begin = (segment_index == 0) ? 0 : buffer.jumps[segment_index - 1].position;
        const std::size_t segment_end =
            (segment_index < buffer.jump_count) ? buffer.jumps[segment_index].position : buffer.length;
        if (!run_matches_at(buffer, window, window_pos, segment_begin, segment_end))
        {
            return false;
        }
        if (segment_index == buffer.jump_count)
        {
            return true;
        }
        const std::size_t after = window_pos + (segment_end - segment_begin);
        const PatternJump &gap = buffer.jumps[segment_index];
        const std::size_t available = window.size() - after;
        for (std::size_t skip = gap.min_skip; skip <= gap.max_skip; ++skip)
        {
            if (skip > available)
            {
                break;
            }
            if (try_segments_at(buffer, window, segment_index + 1, after + skip, steps))
            {
                return true;
            }
            if (steps > SEGMENT_MATCH_STEP_BUDGET)
            {
                return false;
            }
        }
        return false;
    }

    /**
     * @brief Tests whether @p buffer, bounded jumps included, matches at the start of @p window.
     * @return True when a search within SEGMENT_MATCH_STEP_BUDGET finds a placement of every segment and gap that fits
     *         in the window and matches every masked byte.
     */
    [[nodiscard]] constexpr bool
    matches_buffer_at(const PatternBuffer &buffer, std::span<const std::byte> window) noexcept
    {
        if (buffer.length == 0)
        {
            return false;
        }
        if (window.size() < min_match_length(buffer))
        {
            return false;
        }
        std::size_t steps = 0;
        return try_segments_at(buffer, window, 0, 0, steps);
    }

} // namespace DetourModKit::detail

#endif // DETOURMODKIT_DETAIL_PATTERN_CORE_HPP
