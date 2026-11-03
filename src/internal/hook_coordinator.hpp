#ifndef DETOURMODKIT_INTERNAL_HOOK_COORDINATOR_HPP
#define DETOURMODKIT_INTERNAL_HOOK_COORDINATOR_HPP

/**
 * @file internal/hook_coordinator.hpp
 * @brief Backend-free hold on the process route coordinator for translation units outside the hook island.
 * @details The backend serializes every patch transaction, including its trap window, through one process
 *          coordinator. A read of a code page outside that coordinator can record the transient trap protection
 *          (`[B-18]`, `[B-66]`, `[B-109]`). src/hook.cpp defines the hold, so this header names no backend type.
 */

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace DetourModKit::detail
{
    /// Why a @ref BackendCoordinatorHold holds nothing.
    enum class CoordinatorHoldRefusal : std::uint8_t
    {
        None,
        /// Another thread held the coordinator for one backend wait slice. Only this cause clears by itself.
        Timeout,
        Poisoned,
        Incompatible,
        Unavailable,
    };

    /// The log fragment that names @p refusal.
    [[nodiscard]] constexpr std::string_view
    coordinator_hold_refusal_description(CoordinatorHoldRefusal refusal) noexcept
    {
        switch (refusal)
        {
        case CoordinatorHoldRefusal::Timeout:
            return "the process coordinator wait timed out";
        case CoordinatorHoldRefusal::Poisoned:
            return "the process coordinator is poisoned";
        case CoordinatorHoldRefusal::Incompatible:
            return "the process coordinator is incompatible";
        case CoordinatorHoldRefusal::Unavailable:
            return "the process coordinator is unavailable";
        case CoordinatorHoldRefusal::None:
            break;
        }
        return {};
    }

    /// Selects the @ref BackendCoordinatorHold form that waits until held. The names label its one wait line.
    struct WaitUntilHeld
    {
        std::string_view where;
        std::string_view name;
    };

    /**
     * @class BackendCoordinatorHold
     * @brief RAII acquisition of the backend process coordinator.
     * @details The owning thread acquires again without a wait. A refused hold reports false and holds nothing.
     *          Position 4 of the hook lock order (docs/design/hooking.md `[B-109]`): a holder must not wait for a
     *          HookLedger target slot or reservation, take a counted module reference, or run a consumer callable.
     *          `HookInstallCoordinator.InstallToggleAndRetireKeepTheLockOrder` pins the order.
     */
    class BackendCoordinatorHold
    {
    public:
        /// Waits for one bounded backend wait slice.
        BackendCoordinatorHold() noexcept;

        /**
         * @brief Repeats the bounded backend wait while the cause is @ref CoordinatorHoldRefusal::Timeout, with no
         *        attempt count and no time cap. Any other cause refuses at once.
         * @details After the first timed-out slice, logs one Warning that names @p wait and the holder thread. The
         *          line runs while this object holds no coordinator, so a wait that never ends stays visible.
         */
        explicit BackendCoordinatorHold(WaitUntilHeld wait) noexcept;

        ~BackendCoordinatorHold() noexcept;
        BackendCoordinatorHold(const BackendCoordinatorHold &) = delete;
        BackendCoordinatorHold &operator=(const BackendCoordinatorHold &) = delete;

        /// True while this object holds the coordinator.
        [[nodiscard]] explicit operator bool() const noexcept { return m_held; }

        /// Why construction holds nothing, or @ref CoordinatorHoldRefusal::None.
        [[nodiscard]] CoordinatorHoldRefusal refusal() const noexcept { return m_refusal; }

        /// Releases the coordinator before scope exit. A second call is a no-op.
        void release() noexcept;

        /// Bytes reserved for the backend object. src/hook.cpp asserts the backend's size and alignment against it.
        static constexpr std::size_t STORAGE_BYTES = 2 * sizeof(void *);

    private:
        /// Constructs the backend coordinator for one bounded wait and records the outcome.
        void acquire() noexcept;

        alignas(void *) unsigned char m_storage[STORAGE_BYTES]{};
        bool m_constructed{false};
        bool m_held{false};
        CoordinatorHoldRefusal m_refusal{CoordinatorHoldRefusal::None};
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_HOOK_COORDINATOR_HPP
