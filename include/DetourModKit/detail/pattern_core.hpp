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
 *          The byte/mask encoding, the match semantics, and the rarest-byte anchor heuristic are shared with the
 *          heap-backed runtime scan engine so every parser entry point resolves the same DSL identically; the engine's
 *          runtime haystack-frequency selection can override this compile-time anchor, which serves as the fallback when
 *          no haystack histogram is available.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
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
     * @brief Maximum number of bounded-jump gaps a single pattern may carry.
     * @details A bounded jump (`[X-Y]`) splits the fixed byte stream into segments; each jump records one gap between
     *          two fixed runs. `PatternBuffer::jumps` is a fixed `std::array` sized to this cap, and every value Pattern
     *          (and every Candidate that holds one) carries it inline, so the cap is kept to a small handful of gaps: a
     *          real signature anchors on a few stable points and rarely needs more than one or two gaps. A pattern that
     *          names more gaps fails closed at parse with TooManyJumps rather than silently truncating.
     */
    inline constexpr std::size_t MAX_PATTERN_JUMPS = 8;

    /**
     * @brief Upper bound on a single jump gap's maximum skip, in bytes.
     * @details A jump range is deliberately bounded (this is a bounded-jump dialect, not YARA's unbounded `[X-]`): the
     *          gap consumes match-window bytes and each extra byte of span multiplies the backtracking matcher's work,
     *          so an unbounded gap could turn a scan into a region-wide sweep. Capping the span bounds each gap's
     *          contribution to that work (see try_segments_at for the full cost profile). A gap whose upper bound
     *          exceeds this is rejected at parse.
     */
    inline constexpr std::size_t MAX_JUMP_SPAN = 256;

    /**
     * @struct PatternJump
     * @brief One bounded gap between two fixed byte runs (segments) of a compiled pattern.
     * @details A jump lets a pattern tolerate a variable-length span between two stable anchors (an instruction whose
     *          encoding size shifts when the compiler's output moves), which a fixed run of wildcards cannot: `?? ?? ??`
     *          matches exactly three bytes, while `[2-5]` matches any two-to-five-byte gap. @ref position is the index in
     *          the concatenated fixed byte stream that the gap precedes (strictly inside `(0, length)`, since a jump can
     *          neither lead nor trail the pattern nor sit adjacent to another jump). @ref min_skip / @ref max_skip bound
     *          the gap; `min_skip == max_skip` is an exact `[N]` jump.
     */
    struct PatternJump
    {
        /// Index in the fixed byte stream the gap precedes; the boundary between segment i and segment i+1.
        std::size_t position{0};
        /// Fewest bytes the gap may skip before the following segment.
        std::size_t min_skip{0};
        /// Most bytes the gap may skip before the following segment; >= min_skip and <= MAX_JUMP_SPAN.
        std::size_t max_skip{0};
    };

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
        DuplicateOffset,
        /// A `[...]` jump token was malformed, out of range, or illegally placed (leading, trailing, or adjacent).
        InvalidJump,
        /// The pattern named more bounded jumps than MAX_PATTERN_JUMPS.
        TooManyJumps
    };

    /**
     * @struct PatternBuffer
     * @brief The compiled byte/mask representation plus the offset marker, bounded-jump gaps, and the selected anchor.
     * @details A literal-type aggregate (no heap): @ref bytes and @ref mask are fixed arrays sized to the cap, and
     *          only the first @ref length entries are meaningful. @ref offset is the "point of interest" the optional
     *          `|` marker records (0 when absent, which coincides with the match start). @ref anchor is the index of
     *          the rarest fully-known byte, or @ref NO_ANCHOR when none exists.
     *
     *          A pattern with bounded jumps splits its fixed byte stream into segments. @ref bytes / @ref mask hold the
     *          segments concatenated with no gap bytes; @ref jumps records where a gap sits and how wide it may be. A
     *          jump-free pattern has @ref jump_count == 0 and takes the same single fixed-width match path. The anchor is
     *          deliberately confined to segment 0 (the bytes before the first jump), because the matcher locates that
     *          first fixed run and then extends across the variable gaps: a byte in a later segment sits at an address
     *          that shifts with the gap, so it cannot drive the memchr prefilter.
     */
    struct PatternBuffer
    {
        /// Pattern byte values; only entries [0, length) are valid.
        std::array<std::byte, MAX_PATTERN_BYTES> bytes{};
        /// Per-byte match mask (0xFF literal, 0x00 wildcard, 0xF0 high nibble, 0x0F low nibble).
        std::array<std::byte, MAX_PATTERN_BYTES> mask{};
        /// Number of valid byte entries (all segments concatenated, gaps excluded).
        std::size_t length{0};
        /// Result offset recorded by the `|` marker; 0 when no marker is present.
        std::size_t offset{0};
        /// Index of the rarest fully-known byte in segment 0, or NO_ANCHOR when segment 0 has no full byte.
        std::size_t anchor{NO_ANCHOR};
        /// Bounded-jump gaps in ascending position order; only entries [0, jump_count) are valid.
        std::array<PatternJump, MAX_PATTERN_JUMPS> jumps{};
        /// Number of valid jump gaps; 0 for a plain (single-segment) pattern.
        std::size_t jump_count{0};
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
     * @brief Picks the index of the rarest fully-known byte in segment 0 to drive the prefilter.
     * @param buffer A parsed buffer (only segment 0, i.e. [0, segment-0 end), is inspected).
     * @return The index of the lowest-frequency 0xFF-masked byte in segment 0, or NO_ANCHOR if it has no full byte.
     * @details Only a fully-known byte can anchor, because the prefilter sweeps with a single-byte memchr that cannot
     *          search for a partial nibble. The search is confined to segment 0 (the fixed run before the first bounded
     *          jump): the matcher finds that run first and extends across the variable gaps, so a byte in a later
     *          segment lands at a gap-dependent address the memchr prefilter cannot target. The scan keeps the
     *          lowest-scoring candidate seen so far and stops early once it finds a rarest-class byte (score 0), since no
     *          later byte can beat it.
     */
    [[nodiscard]] constexpr std::size_t select_anchor(const PatternBuffer &buffer) noexcept
    {
        // Segment 0 spans [0, first-jump position); with no jumps it is the whole pattern, so a plain pattern anchors
        // over its entire length.
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

    /**
     * @struct JumpParse
     * @brief Outcome of parsing one `[...]` bounded-jump token: a validity flag plus the resolved skip bounds.
     */
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
     * @brief Parses a whitespace-stripped bounded-jump token: `[X]` (exact) or `[X-Y]` (range).
     * @param token The token including its brackets, e.g. "[2-5]".
     * @return A JumpParse with ok == true and the resolved bounds, or ok == false on any malformed / out-of-range form.
     * @details Rejects (returns ok == false) anything that is not a faithful bounded jump: missing brackets, empty or
     *          non-decimal content, trailing junk after the number(s), an inverted range (max < min), a bound above
     *          MAX_JUMP_SPAN, and YARA's unbounded `[X-]` form (this dialect is deliberately bounded so every match
     *          attempt stays a predictable cost). `[N]` is the exact-skip shorthand for `[N-N]`, including the harmless
     *          no-op `[0]`.
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
        // The minimum bound is mandatory: a jump always names at least one number.
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
                // Also guards against integer overflow: any in-range bound is <= MAX_JUMP_SPAN, so bailing here keeps
                // the accumulator far from wrapping.
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
            // A dash with no following digits is YARA's unbounded `[X-]`, which this bounded dialect does not admit.
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

    /**
     * @struct PatternBufferSink
     * @brief The fixed-array storage sink for the compile-time parse: caps at MAX_PATTERN_BYTES / MAX_PATTERN_JUMPS.
     * @details The compile-time Pattern must be a literal type a consteval result can return, so its byte / mask / jump
     *          storage is a fixed array and appending past the cap fails (a TooLong / TooManyJumps parse). The shared
     *          parser (@ref parse_pattern_into) writes every token through a sink so the grammar has one implementation;
     *          the runtime engine supplies its own heap-backed sink with no byte cap, which is why the same grammar
     *          serves both without imposing the literal-storage cap on runtime patterns.
     */
    struct PatternBufferSink
    {
        /// The compiled buffer being filled; only meaningful once the parse returns Ok.
        PatternBuffer buffer{};

        /// Fixed bytes appended so far.
        [[nodiscard]] constexpr std::size_t length() const noexcept { return buffer.length; }
        /// Jump gaps appended so far.
        [[nodiscard]] constexpr std::size_t jump_count() const noexcept { return buffer.jump_count; }

        /// Appends one fixed byte; returns false when the fixed-array cap is reached (parser maps this to TooLong).
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

        /// Records a gap; returns false when the jump cap is reached (parser maps this to TooManyJumps).
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
     * @brief The single AOB DSL grammar, parsing into any storage sink (fixed-array or heap-backed).
     * @param dsl The whitespace-separated token string, e.g. "48 8B 05 ?? ?? ?? ??".
     * @param sink The storage sink; its add_byte / add_jump / set_offset / length / jump_count drive where tokens land.
     * @return The parse status. On Ok the sink holds the compiled bytes / mask / jumps / offset (the anchor, which is
     *         storage-specific, is computed by the caller afterwards).
     * @details This is the one implementation of the grammar, so the compile-time Pattern and the runtime EnginePattern
     *          can never drift apart on what the DSL means or where a cap applies. Tokens are split on whitespace;
     *          leading/trailing whitespace is ignored. Recognized tokens:
     *          - two hex digits (`48`)       -> that byte, mask 0xFF (fully known)
     *          - `??` or `?`                 -> any byte, mask 0x00 (full wildcard)
     *          - hex digit then `?` (`4?`)   -> high nibble fixed, mask 0xF0
     *          - `?` then hex digit (`?5`)   -> low nibble fixed, mask 0x0F
     *          - `[X]` / `[X-Y]`             -> bounded jump: skip exactly X, or between X and Y, bytes before the next
     *                                           segment; splits the pattern into segments recorded as jumps
     *          - `|`                         -> offset marker: records the position of the NEXT byte (or the length
     *                                           when trailing) as the result offset; permitted at most once
     *          Any other token shape fails with InvalidToken. An input with no byte tokens fails with Empty. A sink that
     *          rejects an append fails with TooLong (byte cap) or TooManyJumps (jump cap).
     *
     *          Jump placement follows the YARA hex-string rule so every segment is a non-empty fixed run: a jump may not
     *          lead or trail the pattern and two jumps may not be adjacent (there is always at least one fixed byte
     *          between gaps). A violation is InvalidJump. The `|` marker records a position in the fixed byte stream;
     *          when a pattern also carries jumps the resolver adds the actual gap bytes at match time, so the marker
     *          still points at the right run.
     */
    template <class Sink>
    [[nodiscard]] constexpr PatternStatus parse_pattern_into(std::string_view dsl, Sink &sink) noexcept
    {
        bool offset_marked = false;

        // Index of the most recent segment boundary: 0 at the start, then the fixed length at each jump. A jump is only
        // legal once at least one fixed byte has been added since this boundary, which enforces "no leading jump" and
        // "no two adjacent jumps" in one check, and the end-of-parse comparison against it catches a trailing jump.
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

            // Offset marker: the position of interest is wherever the next byte lands. Placed at the very end, that is
            // one past the final byte (offset == length), which is exactly the value the sink already holds.
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

            // Bounded jump: `[X]` or `[X-Y]`. A token that opens with `[` is always intended as a jump, so a malformed
            // bracket form is a hard InvalidJump rather than falling through to the byte-token parser (which would
            // otherwise misreport it as a generic InvalidToken).
            if (!token.empty() && token.front() == '[')
            {
                const JumpParse jump = parse_jump_token(token);
                if (!jump.ok)
                {
                    return PatternStatus::InvalidJump;
                }
                // A jump must sit between two non-empty fixed runs: reject a leading jump (no byte yet) and a jump
                // adjacent to the previous one (no byte added since the last boundary). Both collapse to this one test.
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

        // A trailing jump leaves an empty final segment (no fixed byte was added after the last gap). last_boundary
        // still equals the fixed length in that case, so this catches "48 8B [2-5]" without a separate flag.
        if (sink.jump_count() > 0 && last_boundary == sink.length())
        {
            return PatternStatus::InvalidJump;
        }

        return PatternStatus::Ok;
    }

    /**
     * @brief Parses an AOB DSL string into a fixed-array PatternBuffer (the compile-time / value-Pattern storage).
     * @param dsl The whitespace-separated token string, e.g. "48 8B 05 ?? ?? ?? ??".
     * @return A PatternParse whose status is Ok (with a filled buffer) or a specific failure; a pattern with more than
     *         MAX_PATTERN_BYTES fixed bytes fails with TooLong (the fixed-array cap the literal type imposes).
     * @details A thin wrapper over @ref parse_pattern_into with the capped fixed-array sink, plus the segment-0
     *          rarest-byte anchor computed on success. The runtime engine parses the same grammar through a heap-backed
     *          sink that has no byte cap, so a long runtime pattern is not bound by this literal-storage limit.
     */
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

    /**
     * @brief The fewest bytes any match of @p buffer can occupy (fixed bytes plus every gap's minimum skip).
     * @details A jump-free pattern's minimum span is just its length. With gaps the shortest possible match still
     *          consumes each gap's lower bound, so this is the true minimum window a match needs.
     */
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
     * @brief The most bytes any match of @p buffer can occupy (fixed bytes plus every gap's maximum skip).
     * @details The upper bound on a match's span. The page-gated scanner uses it to size the cross-region carry so a
     *          match straddling a protection boundary is still found, and to bound the needle self-exclusion window.
     */
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
     * @brief Masked-compares one fixed segment run against a window at a given position.
     * @param buffer The compiled pattern.
     * @param window The candidate byte window.
     * @param window_pos Offset into @p window at which the run must appear.
     * @param body_begin First fixed-byte index of the run (inclusive).
     * @param body_end One-past-last fixed-byte index of the run.
     * @return True when the run fits in the window from @p window_pos and every masked byte agrees.
     * @details The per-byte test is the same `(memory ^ pattern) & mask == 0` the scan engine uses, so a wildcard byte
     *          always agrees and a nibble mask compares only its fixed nibble. A run that would read past the window end
     *          cannot match.
     */
    [[nodiscard]] constexpr bool run_matches_at(const PatternBuffer &buffer, std::span<const std::byte> window,
                                                std::size_t window_pos, std::size_t body_begin,
                                                std::size_t body_end) noexcept
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
     * @brief Backtracking segment match: does segment @p segment_index (and all that follow) match at @p window_pos?
     * @details Matches the segment's fixed run, then for the gap that follows tries every skip in [min, max] in
     *          ascending order, recursing into the next segment. Ascending-skip order makes the overall match the
     *          leftmost feasible placement. Backtracking is required because a greedy choice for one segment can strand a
     *          later one: an earlier gap position that lets the tail match must be found even if a nearer position fails.
     *          Recursion DEPTH is bounded by the segment count (<= MAX_PATTERN_JUMPS + 1), but the total WORK is not
     *          memoized: on a miss the search can explore every skip of every gap, so the worst case is the product of
     *          the gap spans. In practice each segment run fails fast on its first literal byte, so a real signature
     *          (few gaps, literal-anchored segments) prunes to near-linear; only a pathological all-wildcard, wide-gap
     *          pattern approaches the product bound, and patterns are author-written so such a cost is self-inflicted.
     */
    [[nodiscard]] constexpr bool try_segments_at(const PatternBuffer &buffer, std::span<const std::byte> window,
                                                 std::size_t segment_index, std::size_t window_pos) noexcept
    {
        const std::size_t segment_begin = (segment_index == 0) ? 0 : buffer.jumps[segment_index - 1].position;
        const std::size_t segment_end =
            (segment_index < buffer.jump_count) ? buffer.jumps[segment_index].position : buffer.length;
        if (!run_matches_at(buffer, window, window_pos, segment_begin, segment_end))
        {
            return false;
        }
        if (segment_index == buffer.jump_count)
        {
            // The last segment matched, so the whole pattern matched at this start position.
            return true;
        }
        const std::size_t after = window_pos + (segment_end - segment_begin);
        const PatternJump &gap = buffer.jumps[segment_index];
        for (std::size_t skip = gap.min_skip; skip <= gap.max_skip; ++skip)
        {
            if (try_segments_at(buffer, window, segment_index + 1, after + skip))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Tests whether @p buffer matches at the start of @p window, honoring any bounded jumps.
     * @return True when a placement of every segment and gap fits in the window with all masked bytes agreeing.
     * @details For a jump-free pattern this is exactly the single fixed-width masked compare (one segment covering the
     *          whole length); a pattern with gaps runs the backtracking search (see try_segments_at for its cost
     *          profile). A window shorter than the pattern's minimum span can never match.
     */
    [[nodiscard]] constexpr bool matches_buffer_at(const PatternBuffer &buffer,
                                                   std::span<const std::byte> window) noexcept
    {
        if (buffer.length == 0)
        {
            return false;
        }
        return try_segments_at(buffer, window, 0, 0);
    }

} // namespace DetourModKit::detail

#endif // DETOURMODKIT_DETAIL_PATTERN_CORE_HPP
