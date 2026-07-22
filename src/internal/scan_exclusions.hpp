#ifndef DETOURMODKIT_INTERNAL_SCAN_EXCLUSIONS_HPP
#define DETOURMODKIT_INTERNAL_SCAN_EXCLUSIONS_HPP

/**
 * @file internal/scan_exclusions.hpp
 * @brief The scan-time set of address spans a match may not come from: DMK's own query storage plus caller-declared
 *        copies of it.
 * @details Never installed. A page-gated readable sweep reads every committed page of its scope, including the heap and
 *          stack the caller's own query material lives on, so without this set a scan can find its needle in its own
 *          haystack and report the query's storage as the target. The set is built per call from live objects (the
 *          value Pattern, the compiled EnginePattern, ladder storage, string-query buffers) and consulted once per
 *          candidate match, so it costs nothing per scanned byte.
 */

#include "internal/scan_engine.hpp"

#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @class ScanExclusions
         * @brief A bounded, self-merging set of half-open address spans a scan must not match inside.
         * @details Fixed capacity and allocation-free, so it is usable from the noexcept scan paths. Adding a span that
         *          touches or overlaps a stored one widens that entry instead of consuming a slot, which keeps the
         *          common case (a pattern's bytes and mask from the same allocation run) at one or two entries. When
         *          capacity is genuinely exhausted the set latches @ref overflowed rather than dropping a span
         *          silently: a caller whose uniqueness verdict depends on complete exclusion must then fail closed.
         */
        class ScanExclusions
        {
        public:
            /// Slot count. A ladder contributes one span for its array plus one per owned string, so this is generous.
            static constexpr std::size_t MAX_SPANS = 32;

            /**
             * @brief Ignores every span that lies wholly outside [@p lo, @p hi) from here on.
             * @details Set to the range the scan will actually read. A caller's heap or stack copy of the query cannot
             *          be matched by a sweep that never reads it, so storing it would only consume a slot and push a
             *          span that IS in range toward overflow. Applies to subsequent additions, not retroactively.
             */
            constexpr void restrict_to(std::uintptr_t lo, std::uintptr_t hi) noexcept
            {
                m_window_lo = lo;
                m_window_hi = hi;
            }

            /**
             * @brief Adds the half-open span [@p address, @p address + @p size).
             * @details A zero size or a null address is ignored. An end that would wrap latches overflow because the
             *          requested exclusion cannot be represented safely. Touching and overlapping spans are fully
             *          coalesced, including a new span that bridges multiple existing entries.
             */
            constexpr void add(std::uintptr_t address, std::size_t size) noexcept
            {
                if (address == 0 || size == 0)
                {
                    return;
                }
                if (size > UINTPTR_MAX - address)
                {
                    m_overflow = true;
                    return;
                }
                insert(address, address + size);
            }

            /// Adds the storage an object span occupies.
            template <typename T> void add_object_span(std::span<const T> objects) noexcept
            {
                add(reinterpret_cast<std::uintptr_t>(objects.data()), objects.size_bytes());
            }

            /// Adds the storage a borrowed text view occupies.
            void add_text(std::string_view text) noexcept
            {
                add(reinterpret_cast<std::uintptr_t>(text.data()), text.size());
            }

            /**
             * @brief True when [@p lo, @p hi) intersects any stored span.
             * @details The scan calls this once per candidate match with the match's true start and end, so a
             *          variable-length bounded-jump match is tested against the bytes it actually occupies.
             */
            [[nodiscard]] constexpr bool overlaps(std::uintptr_t lo, std::uintptr_t hi) const noexcept
            {
                for (std::size_t i = 0; i < m_count; ++i)
                {
                    if (lo < m_spans[i].hi && hi > m_spans[i].lo)
                    {
                        return true;
                    }
                }
                return false;
            }

            /// True when a span could not be stored, so exclusion is incomplete and a uniqueness verdict is unsafe.
            [[nodiscard]] constexpr bool overflowed() const noexcept { return m_overflow; }

        private:
            struct Span
            {
                std::uintptr_t lo = 0;
                std::uintptr_t hi = 0;
            };

            constexpr void insert(std::uintptr_t lo, std::uintptr_t hi) noexcept
            {
                if (hi <= m_window_lo || lo >= m_window_hi)
                {
                    return;
                }
                lo = (lo < m_window_lo) ? m_window_lo : lo;
                hi = (hi > m_window_hi) ? m_window_hi : hi;

                std::size_t i = 0;
                while (i < m_count)
                {
                    if (lo <= m_spans[i].hi && hi >= m_spans[i].lo)
                    {
                        lo = (lo < m_spans[i].lo) ? lo : m_spans[i].lo;
                        hi = (hi > m_spans[i].hi) ? hi : m_spans[i].hi;
                        --m_count;
                        m_spans[i] = m_spans[m_count];
                        continue;
                    }
                    ++i;
                }
                if (m_count == MAX_SPANS)
                {
                    m_overflow = true;
                    return;
                }
                m_spans[m_count] = Span{lo, hi};
                ++m_count;
            }

            std::array<Span, MAX_SPANS> m_spans{};
            std::size_t m_count = 0;
            std::uintptr_t m_window_lo = 0;
            std::uintptr_t m_window_hi = UINTPTR_MAX;
            bool m_overflow = false;
        };

        /**
         * @brief Adds the value Pattern's own storage.
         * @details The Pattern object holds the query bytes inline, so its storage IS query material wherever it lives,
         *          including a Pattern the compiler placed in read-only data. This covers only the live object: a
         *          separate initializer image the compiler materialized for a `consteval` construction sits at another
         *          address, is not enumerable, and stays visible to the sweep.
         */
        inline void add_pattern_storage(ScanExclusions &exclusions, const scan::Pattern &pattern) noexcept
        {
            exclusions.add(reinterpret_cast<std::uintptr_t>(&pattern), sizeof(scan::Pattern));
        }

        /**
         * @brief Adds caller-declared copies of the query.
         * @details DMK can enumerate only the query representations it owns. A caller that keeps its own copy of the
         *          pattern bytes alive during the scan declares them here; that declaration is what lets an otherwise
         *          unprovable readable sweep return an authoritative result.
         */
        inline void add_regions(ScanExclusions &exclusions, std::span<const Region> regions) noexcept
        {
            for (const Region &region : regions)
            {
                exclusions.add(region.base.raw(), region.size);
            }
        }

        /// Adds a compiled pattern's heap-backed bytes and mask buffers.
        inline void add_engine_pattern_storage(ScanExclusions &exclusions, const EnginePattern &pattern) noexcept
        {
            exclusions.add(reinterpret_cast<std::uintptr_t>(pattern.bytes.data()), pattern.bytes.size());
            exclusions.add(reinterpret_cast<std::uintptr_t>(pattern.mask.data()), pattern.mask.size());
        }
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_SCAN_EXCLUSIONS_HPP
