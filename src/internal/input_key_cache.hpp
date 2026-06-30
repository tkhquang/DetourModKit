#ifndef DETOURMODKIT_INTERNAL_INPUT_KEY_CACHE_HPP
#define DETOURMODKIT_INTERNAL_INPUT_KEY_CACHE_HPP

/**
 * @file input_key_cache.hpp
 * @brief Internal per-poll-cycle memoization of virtual-key down-state.
 * @details Poll-thread-private helper used by InputPoller's binding-evaluation pass. Windows-agnostic and
 *          allocation-free so it can be unit-tested off a live message queue (the down-state probe is injected),
 *          mirroring the src/internal engine-header pattern. Not installed.
 */

#include <array>
#include <cstddef>
#include <cstdint>

namespace DetourModKit::detail
{
    /**
     * @class KeyStateCache
     * @brief Memoizes a virtual key's down-state for the span of one poll cycle.
     * @details A single cycle reads the same modifier/trigger VK many times: once per binding that references it,
     *          plus the strict known-modifier rescan that rejects bindings holding an unrelated modifier. Probing
     *          each distinct VK at most once per cycle collapses that fan-out to one read per VK and hands every read
     *          this cycle a single coherent snapshot, matching the cycle-scoped gamepad and wheel snapshots.
     *
     *          GetAsyncKeyState reads the global asynchronous key state, not a thread-specific message queue, so it is
     *          the correct primitive for a poll thread that does not pump messages. Memoization deliberately makes the
     *          poll loop cycle-coherent: a transition that happens after a VK's first probe is observed on the next
     *          cycle rather than splitting two bindings in the same cycle. The probe is injected as a callable so the
     *          poll loop binds it to GetAsyncKeyState while tests drive it deterministically and count invocations.
     */
    class KeyStateCache
    {
    public:
        /// Clears every sample; call once at the start of each poll cycle so the next cycle re-probes.
        void reset() noexcept { m_state.fill(UNKNOWN); }

        /**
         * @brief Returns whether @p vk is down, invoking @p probe at most once per cycle for each distinct VK.
         * @tparam Probe Callable `bool(int vk)` returning the live down-state; must not throw.
         * @param vk Windows virtual-key code (keyboard or mouse button). Codes outside 0..255 read as not pressed
         *           and are never probed.
         * @param probe Down-state probe, called only on the first read of @p vk this cycle.
         * @return The cycle's cached down-state for @p vk.
         */
        template <typename Probe> [[nodiscard]] bool pressed(int vk, Probe &&probe) noexcept
        {
            const auto index = static_cast<unsigned>(vk);
            if (index >= m_state.size())
            {
                return false;
            }
            if (m_state[index] == UNKNOWN)
            {
                m_state[index] = probe(vk) ? PRESSED : RELEASED;
            }
            return m_state[index] == PRESSED;
        }

    private:
        static constexpr std::size_t VK_COUNT = 256;
        static constexpr uint8_t UNKNOWN = 0;
        static constexpr uint8_t PRESSED = 1;
        static constexpr uint8_t RELEASED = 2;

        // Tri-state per VK indexed by code (0..255): unknown, probed down, or probed up. The "probed up" state is
        // distinct from "unknown" so a released key is not re-probed within the cycle.
        std::array<uint8_t, VK_COUNT> m_state{};
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_INPUT_KEY_CACHE_HPP
