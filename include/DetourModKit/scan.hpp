#ifndef DETOURMODKIT_SCAN_HPP
#define DETOURMODKIT_SCAN_HPP

/**
 * @file scan.hpp
 * @brief The v4 scanning surface, centered on the value-semantic compiled AOB Pattern.
 * @details A Pattern is the compiled form of an AOB mini-DSL string ("48 8B 05 ?? ?? ?? ??"): it owns its bytes and
 *          mask inline (no heap), caches the rarest-byte scan anchor, and remembers the optional `|` result offset.
 *          Two entry points construct one. compile() parses a runtime string and returns a Result, so a bad pattern
 *          is a recoverable error rather than undefined behaviour. literal() parses an in-source string literal at
 *          COMPILE time and returns a Pattern by value, so a typo in a hard-coded signature is a build error and an
 *          in-source candidate ladder stays a constexpr-friendly value with no Result to unwrap.
 */

#include "DetourModKit/defines.hpp"
#include "DetourModKit/detail/pattern_core.hpp"
#include "DetourModKit/error.hpp"

#include <cstddef>
#include <span>
#include <string_view>

namespace DetourModKit::scan
{
    /**
     * @class Pattern
     * @brief A value-semantic compiled AOB pattern that owns its bytes and mask inline.
     * @details Construct with compile() (runtime, returns Result) or literal() (compile-time, returns by value). The
     *          compiled form exposes its bytes, mask, result offset, and the cached compile-time anchor so the scan
     *          engine can prefilter and verify without re-parsing, and matches_at() applies the same masked compare
     *          the engine uses for a single position. Copyable and trivially comparable in cost to its inline arrays.
     */
    class Pattern
    {
    public:
        /**
         * @brief Compiles a runtime AOB DSL string.
         * @param dsl The whitespace-separated pattern, e.g. "48 8B 05 ?? ?? ?? ??".
         * @return A Pattern on success, or Error{ErrorCode::BadPattern} when the string is malformed/empty/over-cap.
         * @details Never undefined behaviour on bad input: a parse failure becomes a recoverable Error. The specific
         *          parse status is stashed in the Error's extra slot so a caller can distinguish, for example, an
         *          over-long pattern from an invalid token without the resolver surface growing more error codes.
         * @note Setup/control-plane only -- compile patterns at init, not inside a hot callback.
         */
        [[nodiscard]] static Result<Pattern> compile(std::string_view dsl)
        {
            const detail::PatternParse parsed = detail::parse_pattern(dsl);
            if (parsed.status != detail::PatternStatus::Ok)
            {
                return std::unexpected(
                    Error{ErrorCode::BadPattern, "scan::compile", 0, static_cast<std::uint32_t>(parsed.status)});
            }
            return Pattern{parsed.buffer};
        }

        /**
         * @brief Compiles an in-source AOB DSL literal at compile time.
         * @param dsl A constant-expression pattern string.
         * @return The compiled Pattern by value.
         * @details consteval, so a malformed literal is a compile error rather than a runtime Result to deref. On any
         *          non-Ok parse status the throw below is evaluated during constant evaluation, which makes the call a
         *          non-constant expression and fails the build at the offending literal site. A valid literal never
         *          reaches the throw and compiles to a plain Pattern value, keeping hard-coded candidate ladders
         *          constexpr-friendly.
         */
        [[nodiscard]] static consteval Pattern literal(std::string_view dsl)
        {
            const detail::PatternParse parsed = detail::parse_pattern(dsl);
            if (parsed.status != detail::PatternStatus::Ok)
            {
                throw "DetourModKit: scan::Pattern::literal() received a malformed AOB pattern";
            }
            return Pattern{parsed.buffer};
        }

        /// Number of bytes in the compiled pattern.
        [[nodiscard]] constexpr std::size_t size() const noexcept { return m_data.length; }

        /// The `|` result offset (0 when the pattern carries no offset marker).
        [[nodiscard]] constexpr std::size_t offset() const noexcept { return m_data.offset; }

        /// View over the compiled pattern bytes (length == size()).
        [[nodiscard]] constexpr std::span<const std::byte> bytes() const noexcept
        {
            return std::span<const std::byte>(m_data.bytes.data(), m_data.length);
        }

        /// View over the per-byte match mask (length == size()).
        [[nodiscard]] constexpr std::span<const std::byte> mask() const noexcept
        {
            return std::span<const std::byte>(m_data.mask.data(), m_data.length);
        }

        /// True when the pattern has at least one fully-known byte the prefilter can anchor on.
        [[nodiscard]] constexpr bool has_anchor() const noexcept { return m_data.anchor < m_data.length; }

        /// Index of the rarest fully-known byte; only meaningful when has_anchor() is true.
        [[nodiscard]] constexpr std::size_t anchor_index() const noexcept { return m_data.anchor; }

        /// The anchor byte value, or a zero byte when has_anchor() is false.
        [[nodiscard]] constexpr std::byte anchor_byte() const noexcept
        {
            return has_anchor() ? m_data.bytes[m_data.anchor] : std::byte{0x00};
        }

        /**
         * @brief Tests whether the pattern matches the bytes at the start of @p window.
         * @param window The candidate byte window; must be at least size() bytes to match.
         * @return True when every masked byte agrees.
         * @details Applies the same compare the scan engine uses, expressed per byte: a position matches when
         *          (memory ^ pattern) & mask is zero for every byte, so wildcard bytes (mask 0x00) always agree and a
         *          nibble mask (0xF0 / 0x0F) compares only the fixed nibble. A window shorter than the pattern cannot
         *          match.
         */
        [[nodiscard]] constexpr bool matches_at(std::span<const std::byte> window) const noexcept
        {
            if (window.size() < m_data.length)
            {
                return false;
            }
            for (std::size_t index = 0; index < m_data.length; ++index)
            {
                const std::byte masked_diff = (window[index] ^ m_data.bytes[index]) & m_data.mask[index];
                if (masked_diff != std::byte{0x00})
                {
                    return false;
                }
            }
            return true;
        }

    private:
        // Private so the only ways to obtain a Pattern are the validating factories; a default-constructed or
        // arbitrary-buffer Pattern can never exist.
        constexpr explicit Pattern(const detail::PatternBuffer &data) noexcept : m_data{data} {}

        detail::PatternBuffer m_data{};
    };

} // namespace DetourModKit::scan

#endif // DETOURMODKIT_SCAN_HPP
