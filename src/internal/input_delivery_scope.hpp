#ifndef DETOURMODKIT_INTERNAL_INPUT_DELIVERY_SCOPE_HPP
#define DETOURMODKIT_INTERNAL_INPUT_DELIVERY_SCOPE_HPP

/**
 * @file input_delivery_scope.hpp
 * @brief Per-thread marker for "this thread is inside an input-gate callback", used to break cross-binding teardown.
 * @details A binding gate runs the user callback outside its own mutex and, for a control-plane release, blocks until
 *          any in-flight delivery has drained so the caller can safely destroy captured state. That blocking rundown
 *          must NOT run when the release is reached from inside a callback: a self-release, or a callback that releases
 *          a second binding's guard, would otherwise wait on a delivery that is (transitively) waiting on it, which is
 *          the cross-binding ABBA. This marker lets a gate distinguish the two: a release at depth zero blocks; a
 *          release at depth greater than zero defers its rundown to the in-flight delivery's unwind.
 *
 *          The answer is exact per thread. It is never widened to "some thread somewhere might be in a callback",
 *          because a control-plane release on an unrelated thread would then skip the rundown its public contract
 *          promises and let its caller destroy state a live callback is still reading. Exactness is bought by
 *          refusing a delivery whose frame cannot be recorded rather than admitting it untracked.
 *
 *          Backed by a reserved Win32 TLS slot rather than thread_local because MinGW lowers thread_local to
 *          __emutls_get_address, which allocates on first use per thread and abort()s uncatchably under OOM (see
 *          mid_hook_adapter.hpp and event_dispatcher.cpp for the same reservation). Not installed.
 */

#include <cstdint>

namespace DetourModKit::detail
{
    /// Returns the allocation-free Win32 identity of the calling thread.
    [[nodiscard]] std::uint32_t current_native_thread_id() noexcept;

#if defined(DMK_ENABLE_TEST_SEAMS)
    /// Seam signature; see set_delivery_scope_reservation_seam_for_test.
    using DeliveryScopeReservationSeam = void (*)() noexcept;

    /// Runs a probe after the first reservation check and before its serialized recheck.
    void set_delivery_scope_reservation_seam_for_test(DeliveryScopeReservationSeam seam) noexcept;

    /**
     * @brief Makes the reserved slot's depth store report failure for the calling thread.
     * @details A store into a reserved index past the TEB's inline slots is backed by a lazily heap-allocated
     *          expansion array, so it can fail on a thread that has never used a high index while the reservation
     *          itself stays valid. No host can provoke that heap state on demand, and refusing the frame is the only
     *          branch a caller's correctness depends on, so it is driven here instead of guessed at.
     */
    void set_delivery_scope_store_failure_for_test(bool fail) noexcept;
#endif

    /**
     * @brief Reserves the delivery marker's Win32 TLS slot before callbacks can run.
     * @return false when the process has no slot available, after which every delivery is refused.
     * @note Setup/control-plane only.
     */
    [[nodiscard]] bool reserve_delivery_scope_tls() noexcept;

    /**
     * @brief Reports whether the calling thread is currently executing an input-gate callback.
     * @details Exact for the calling thread and silent about every other one. False therefore means "this thread is
     *          not inside a gate callback", which is what entitles a control-plane caller to run its blocking rundown.
     */
    [[nodiscard]] bool current_thread_in_delivery() noexcept;

    /**
     * @class DeliveryScope
     * @brief RAII marker bracketing one user-callback invocation inside a gate; nesting-safe and noexcept.
     * @details Construct it immediately before invoking the user callback and let it destruct immediately after, with
     *          no gate mutex held. Nested deliveries on one thread increment the depth.
     * @note Construction can fail (see @ref admitted). A delivery path must treat a refused scope as "do not run the
     *       callback" and undo whatever it had already committed for this edge.
     */
    class DeliveryScope
    {
    public:
        DeliveryScope() noexcept;
        ~DeliveryScope() noexcept;

        DeliveryScope(const DeliveryScope &) = delete;
        DeliveryScope &operator=(const DeliveryScope &) = delete;
        DeliveryScope(DeliveryScope &&) = delete;
        DeliveryScope &operator=(DeliveryScope &&) = delete;

        /**
         * @brief Whether this frame is recorded, so the thread now reads as in-delivery.
         * @return false when the reserved slot is unavailable or the per-thread store failed under host OOM.
         */
        [[nodiscard]] bool admitted() const noexcept { return m_admitted; }

    private:
        bool m_admitted;
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_INPUT_DELIVERY_SCOPE_HPP
