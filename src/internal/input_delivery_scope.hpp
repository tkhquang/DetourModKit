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
 *          Backed by a reserved Win32 TLS slot rather than thread_local because MinGW lowers thread_local to
 *          __emutls_get_address, which allocates on first use per thread and abort()s uncatchably under OOM (see
 *          mid_hook_adapter.hpp and event_dispatcher.cpp for the same reservation). Not installed.
 */

namespace DetourModKit::detail
{
    /**
     * @brief Reserves the delivery marker's Win32 TLS slot before callbacks can run.
     * @return false when the process has no slot available; deliveries then use the fail-closed untracked count.
     * @note Setup/control-plane only.
     */
    [[nodiscard]] bool reserve_delivery_scope_tls() noexcept;

    /**
     * @brief Reports whether the calling thread is currently executing an input-gate callback.
     * @details Fail-closed: if the reserved TLS slot cannot be provisioned, or a frame could not be recorded under
     *          host OOM, this returns true so an ambiguous caller defers its rundown rather than risk the ABBA a
     *          blocking wait would create. A false result therefore reliably means "not in a callback"; a true result
     *          means "in a callback, or unable to prove otherwise".
     */
    [[nodiscard]] bool current_thread_in_delivery() noexcept;

    /**
     * @class DeliveryScope
     * @brief RAII marker bracketing one user-callback invocation inside a gate; nesting-safe and noexcept.
     * @details Construct it immediately before invoking the user callback and let it destruct immediately after, with
     *          no gate mutex held. Nested deliveries on one thread increment the depth.
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

    private:
        // Whether this frame was recorded in TLS. False marks the fail-closed fallback (slot unavailable or a
        // TlsSetValue failure), which instead pins a process-wide untracked count so every release defers.
        bool m_tracked;
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_INPUT_DELIVERY_SCOPE_HPP
