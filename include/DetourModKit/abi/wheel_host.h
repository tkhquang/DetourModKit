#ifndef DETOURMODKIT_WHEEL_HOST_H
#define DETOURMODKIT_WHEEL_HOST_H

/**
 * @file wheel_host.h
 * @brief Versioned C ABI for the opt-in resident mouse-wheel host.
 *
 * @details A loader module starts one host and passes the returned @ref WheelHostTable to each logic generation.
 *          The host owns one thread-scoped WH_GETMESSAGE hook. It also owns counters, remainders, the capture epoch,
 *          owner, consume mask, TTL, and route identity. A logic generation opens one lease, publishes capture state,
 *          drains whole-notch counts, reads route status, controls retargets, and closes the lease. After a lease
 *          closes, resident code holds no logic pointer, callback, or destructor from the generation.
 *
 *          The loader and each logic generation are separate modules with independent static storage. The ABI uses
 *          fixed-width integers, opaque tokens, and one declared calling convention. It exposes no C++ type,
 *          exception, allocator, or DMK object. The header includes only <stdint.h>.
 *
 *          Thread and loader rules:
 *          - Start the host on the loader control thread before the first logic load.
 *          - Call every function in this ABI outside the loader lock.
 *          - The host serializes concurrent ABI calls with a non-recursive lock. Never invoke an ABI function
 *            recursively.
 *          - The host and the target UI thread must belong to the same process.
 *          - The host takes one process-lifetime reference on the module that contains the resident hook before it
 *            publishes the hook. Hook removal is host cleanup, never logic-unmap authorization.
 *          - The host installs the hook from a host-owned thread. A mount established through start or retarget
 *            survives the exit of the thread that requested it.
 *          - A resident loader with an older wheel-host ABI requires a process restart. Version negotiation is exact.
 *            A version-2 host rejects a version-1 request. Version-2 logic rejects a version-1 table.
 *          - A status query can settle physical mount health after its target-thread liveness check. It never expires,
 *            cancels, or completes a control transaction.
 */

#include <stdint.h>

#if defined(_WIN32)
/** @brief The one calling convention every function in this ABI uses. */
#define DMK_WHEELHOST_CALL __stdcall
#else
#define DMK_WHEELHOST_CALL
#endif

#if defined(__cplusplus)
/** @brief Applies the non-throwing contract to C++ declarations without changing the C ABI. */
#define DMK_WHEELHOST_NOEXCEPT noexcept
#else
#define DMK_WHEELHOST_NOEXCEPT
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief ABI revision of this header. A host writes it into @ref WheelHostTable::abi_version. */
#define DMK_WHEELHOST_ABI_VERSION 2u

/**
 * @name Capability bits
 * @brief Host-advertised capabilities in @ref WheelHostTable::capability_bits. A logic generation must tolerate a
 *        host that clears a bit it does not implement.
 * @{
 */
#define DMK_WHEELHOST_CAP_VERTICAL (UINT64_C(1) << 0)   /**< The host captures WM_MOUSEWHEEL. */
#define DMK_WHEELHOST_CAP_HORIZONTAL (UINT64_C(1) << 1) /**< The host captures WM_MOUSEHWHEEL. */
#define DMK_WHEELHOST_CAP_CONSUME (UINT64_C(1) << 2)    /**< The host can swallow an owned wheel message. */
#define DMK_WHEELHOST_CAP_ROUTE (UINT64_C(1) << 3)      /**< The host implements route_status and retarget. */
/** @} */

/**
 * @name Status codes
 * @brief Every ABI function returns one of these as an int32_t. Zero is success. Every negative value is a distinct,
 *        stable failure reason.
 * @{
 */
#define DMK_WHEELHOST_OK 0              /**< The call succeeded. */
#define DMK_WHEELHOST_ERR_ABI (-1)      /**< A table or snapshot capacity is short, or the abi_version differs. */
#define DMK_WHEELHOST_ERR_INVALID (-2)  /**< A required pointer argument is null, or an argument is out of range. */
#define DMK_WHEELHOST_ERR_BUSY (-3)     /**< A lease is already active. Version 2 allows one lease per host. */
#define DMK_WHEELHOST_ERR_NO_LEASE (-4) /**< The operation needs an open lease and none is open. */
#define DMK_WHEELHOST_ERR_STALE (-5)    /**< The lease token does not match the open lease. */
#define DMK_WHEELHOST_ERR_THREAD (-6)   /**< The target thread is invalid, or a hook mount or removal failed. */
#define DMK_WHEELHOST_ERR_STATE (-7)    /**< The current host lifecycle state does not permit the operation. */
#define DMK_WHEELHOST_ERR_DRAIN (-8)    /**< Admitted callback phases did not drain in the bound. Retry the call. */
#define DMK_WHEELHOST_ERR_PENDING (-9)  /**< A control call is pending. Use an authorized retry, close, or Stop. */
/** @} */

/**
 * @name Route states
 * @brief @ref WheelHostRouteStatus::route_state carries one value below. The value reports physical mount health
 *        only. A mounted route can remain ready while a pending control transaction blocks capture. Read control_state
 *        and capture_armable for data-plane availability. A dead or migrated target never reports ready.
 * @{
 */
#define DMK_WHEELHOST_ROUTE_TARGET_WAIT 0u     /**< No target is selected. Retarget mounts the first hook. */
#define DMK_WHEELHOST_ROUTE_READY 1u           /**< The hook is mounted and the target thread is alive. */
#define DMK_WHEELHOST_ROUTE_RETRYABLE 2u       /**< The route was lost. Zero hooks are active. Retarget remounts. */
#define DMK_WHEELHOST_ROUTE_CLEANUP_BLOCKED 3u /**< Old-hook removal failed on a live thread. Mounts are blocked. */
/** @} */

/**
 * @name Control states
 * @brief @ref WheelHostRouteStatus::control_state carries one value below. Each non-idle value names a pending
 *        control transaction. The transaction keeps the lease data plane unavailable until an authorized call ends
 *        it.
 * @{
 */
#define DMK_WHEELHOST_CONTROL_IDLE 0u             /**< No control transaction is pending. */
#define DMK_WHEELHOST_CONTROL_RETARGET_PENDING 1u /**< A retarget failed. The matching lease must retry or close. */
#define DMK_WHEELHOST_CONTROL_CLOSE_PENDING 2u    /**< A close failed its drain. Its exact retry or Stop ends it. */
#define DMK_WHEELHOST_CONTROL_STOP_PENDING 3u     /**< A stop failed. Retry Stop. */
/** @} */

/**
 * @name Wheel direction indices
 * @brief Index the count array @ref WheelHostTable::drain_counts writes.
 * @{
 */
#define DMK_WHEEL_UP 0         /**< Vertical, positive delta. */
#define DMK_WHEEL_DOWN 1       /**< Vertical, negative delta. */
#define DMK_WHEEL_LEFT 2       /**< Horizontal, negative delta. */
#define DMK_WHEEL_RIGHT 3      /**< Horizontal, positive delta. */
#define DMK_WHEEL_DIRECTIONS 4 /**< The number of directions and the length of the count array. */
/** @} */

/**
 * @name Consume mask bits
 * @brief Select directions to swallow in @ref WheelHostTable::publish_capture. The bit index equals the direction
 *        index above.
 * @{
 */
#define DMK_WHEEL_CONSUME_UP (1u << DMK_WHEEL_UP)
#define DMK_WHEEL_CONSUME_DOWN (1u << DMK_WHEEL_DOWN)
#define DMK_WHEEL_CONSUME_LEFT (1u << DMK_WHEEL_LEFT)
#define DMK_WHEEL_CONSUME_RIGHT (1u << DMK_WHEEL_RIGHT)
/** @} */

/**
 * @name Capture flags
 * @brief Flag bits for the capture_enabled argument of @ref WheelHostTable::publish_capture.
 * @{
 */
/** @brief Capture-enable flag. Zero disables counting. */
#define DMK_WHEEL_CAPTURE_ENABLED 1u
/** @brief Focus gate. The resident callback checks process focus at count admission and consume finalization. */
#define DMK_WHEEL_CAPTURE_REQUIRE_FOCUS 2u
    /** @} */

    // clang-format off

/** @brief Opaque lease token. A successful open writes a non-zero value. */
typedef uint64_t WheelHostLease;

/**
 * @struct WheelHostRouteStatus
 * @brief One lease-qualified snapshot of the host route and control plane.
 * @details The host writes struct_size. route_state reports physical mount health only. Read capture_armable to check
 *          whether the qualified lease can arm capture.
 */
typedef struct WheelHostRouteStatus
{
    /** @brief The snapshot size known to the host. */
    uint32_t struct_size;
    /** @brief One DMK_WHEELHOST_ROUTE_* value. Physical mount health only. */
    uint32_t route_state;
    /** @brief One DMK_WHEELHOST_CONTROL_* value. */
    uint32_t control_state;
    /** @brief Non-zero when the queried lease can arm capture now. An unqualified snapshot reports zero. */
    uint32_t capture_armable;
    /** @brief The mounted target thread id, or zero while unmounted. */
    uint32_t mounted_thread_id;
    /** @brief Reserved. The host writes zero. */
    uint32_t reserved;
    /** @brief The mount generation. A successful migration increments it once. */
    uint64_t mount_generation;
} WheelHostRouteStatus;

/**
 * @struct WheelHostTable
 * @brief The host surface a loader passes to each logic generation.
 * @details A generation must check struct_size, abi_version, DMK_WHEELHOST_CAP_ROUTE, host_context, and every
 *          function pointer before it calls a function pointer.
 */
typedef struct WheelHostTable
{
    /** @brief The table size known to the host. */
    uint32_t struct_size;
    /** @brief The host ABI revision. */
    uint32_t abi_version;
    /** @brief The bitwise OR of the DMK_WHEELHOST_CAP_* bits the host implements. */
    uint64_t capability_bits;
    /** @brief Non-zero identity unique to this host instance. It survives a successful retarget. */
    uint64_t host_identity;
    /** @brief Opaque host state. Pass it unchanged to each function below. */
    void *host_context;

    /**
     * @brief Opens the single lease for owner and generation.
     * @param host_context The table's host_context value.
     * @param owner Caller-chosen owner identity.
     * @param generation Caller-chosen generation identity.
     * @param out_lease Receives a non-zero lease on success. Must not be null.
     * @return A DMK_WHEELHOST_* status code. With valid arguments, a pending transaction reports
     *         DMK_WHEELHOST_ERR_PENDING. An active lease without a transaction reports DMK_WHEELHOST_ERR_BUSY.
     * @note A lease can open while the route is unmounted. Count and consume stay disabled until the first
     *       successful retarget.
     * @note Setup/control-plane only.
     */
    int32_t (DMK_WHEELHOST_CALL *open_lease)(void *host_context, uint64_t owner, uint64_t generation,
                                             WheelHostLease *out_lease) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Publishes capture and consume state for an open lease.
     * @param host_context The table's host_context value.
     * @param lease The token from open_lease.
     * @param capture_enabled The bitwise OR of the DMK_WHEEL_CAPTURE_* flags, or zero to stop counting.
     * @param consume_mask The bitwise OR of the DMK_WHEEL_CONSUME_* bits to swallow.
     * @param ttl_ms The consume lease duration. Zero clears the consume mask.
     * @return A DMK_WHEELHOST_* status code.
     * @note The caller must refresh a non-zero consume mask before ttl_ms elapses.
     * @note The consume is best effort. A hook installed after the host can restore the wheel message after the host
     *       returns, so a masked direction can still reach the window.
     * @note Setup/control-plane only.
     */
    int32_t (DMK_WHEELHOST_CALL *publish_capture)(void *host_context, WheelHostLease lease,
                                                  uint32_t capture_enabled, uint32_t consume_mask,
                                                  uint32_t ttl_ms) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Drains the accumulated whole-notch counts and zeros them.
     * @param host_context The table's host_context value.
     * @param lease The token from open_lease.
     * @param out_counts Receives DMK_WHEEL_DIRECTIONS direction counts. Must not be null.
     * @return A DMK_WHEELHOST_* status code.
     * @note Setup/control-plane only.
     */
    int32_t (DMK_WHEELHOST_CALL *drain_counts)(void *host_context, WheelHostLease lease,
                                               uint32_t out_counts[DMK_WHEEL_DIRECTIONS])
        DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Closes the matching lease, invalidates its capture state, and drains admitted callback phases.
     * @param host_context The table's host_context value.
     * @param lease The token from open_lease.
     * @param owner The owner passed to open_lease.
     * @param generation The generation passed to open_lease.
     * @return A DMK_WHEELHOST_* status code. DMK_WHEELHOST_ERR_DRAIN keeps the lease in a disabled close-pending state
     *         and reports DMK_WHEELHOST_CONTROL_CLOSE_PENDING. The exact retry finishes the close, and a successor
     *         open is refused until it does. wheel_host_stop supersedes it.
     * @note A successful close proves resident code holds no admitted decision and no logic pointer. It does not
     *       authorize an unload by itself.
     * @note Setup/control-plane only.
     */
    int32_t (DMK_WHEELHOST_CALL *close_lease)(void *host_context, WheelHostLease lease, uint64_t owner,
                                              uint64_t generation) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Reads one snapshot of the route and the control plane.
     * @param host_context The table's host_context value.
     * @param lease The token from open_lease, or zero to request an unqualified snapshot.
     * @param status_capacity The available out_status bytes. Pass sizeof(WheelHostRouteStatus).
     * @param out_status Receives the snapshot. Must not be null.
     * @return A DMK_WHEELHOST_* status code. A short capacity reports DMK_WHEELHOST_ERR_ABI. A non-zero lease without
     *         an active match reports DMK_WHEELHOST_ERR_STALE. A stopped host reports DMK_WHEELHOST_ERR_STATE.
     * @note The query rechecks target-thread liveness, so a dead target reports DMK_WHEELHOST_ROUTE_RETRYABLE and a
     *       cleanup-blocked route whose old thread exited becomes retryable. It never ends a control transaction.
     * @note A zero lease reports capture_armable as zero, because the snapshot qualified no lease.
     * @note Setup/control-plane only. The host serializes this call with every other ABI call.
     */
    int32_t (DMK_WHEELHOST_CALL *route_status)(void *host_context, WheelHostLease lease, uint32_t status_capacity,
                                               WheelHostRouteStatus *out_status) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Moves the resident hook to a new target UI thread for an open lease.
     * @param host_context The table's host_context value.
     * @param lease The token from open_lease.
     * @param target_thread_id The new target thread id. It must belong to this process and be alive.
     * @return A DMK_WHEELHOST_* status code. A success increments the mount generation once and preserves the host
     *         identity and the lease. DMK_WHEELHOST_ERR_DRAIN and DMK_WHEELHOST_ERR_THREAD leave
     *         DMK_WHEELHOST_CONTROL_RETARGET_PENDING with a matching-lease retry owed. A matching close cancels that
     *         transaction. Nothing else ends it: quiescence alone never does.
     * @note A retry converges on the target_thread_id of that retry, not on the original destination.
     * @note The old hook is removed before the new hook mounts. Hooks never overlap. A removal failure on a live
     *       thread publishes DMK_WHEELHOST_ROUTE_CLEANUP_BLOCKED and blocks the new mount until that thread exits.
     * @note A retarget to the currently mounted, live thread is a success, keeps the mount generation, and cancels
     *       an abandoned migration.
     * @note Setup/control-plane only. Never call it from a hook callback or under a loader lock.
     */
    int32_t (DMK_WHEELHOST_CALL *retarget)(void *host_context, WheelHostLease lease,
                                           uint32_t target_thread_id) DMK_WHEELHOST_NOEXCEPT;
} WheelHostTable;

/**
 * @brief Starts the process host and fills out_table.
 * @param target_thread_id The target UI thread id, or zero to start unmounted in target-wait state. A non-zero id
 *                         must belong to this process.
 * @param requested_abi_version The accepted ABI version. Pass DMK_WHEELHOST_ABI_VERSION. Any other value is
 *                              rejected.
 * @param table_capacity The available out_table bytes. Pass sizeof(WheelHostTable).
 * @param out_table Receives the host table on success. Must not be null.
 * @return A DMK_WHEELHOST_* status code.
 * @note Call this outside a loader lock before the first logic generation loads.
 * @note Setup/control-plane only.
 */
int32_t DMK_WHEELHOST_CALL wheel_host_start(uint32_t target_thread_id, uint32_t requested_abi_version,
                                              uint32_t table_capacity, WheelHostTable *out_table)
    DMK_WHEELHOST_NOEXCEPT;

/**
 * @brief Removes the host hook, drains admitted callback phases, and stops the host.
 * @return A DMK_WHEELHOST_* status code. DMK_WHEELHOST_ERR_BUSY reports an open lease unless
 *         DMK_WHEELHOST_CONTROL_CLOSE_PENDING or DMK_WHEELHOST_CONTROL_STOP_PENDING is active. An
 *         DMK_WHEELHOST_ERR_BUSY result changes nothing. DMK_WHEELHOST_ERR_DRAIN keeps the host started and disabled.
 *         Retry Stop to finish.
 * @note Stop is the loader authority over a host it started, so it supersedes DMK_WHEELHOST_CONTROL_CLOSE_PENDING
 *       from a generation that already asked to leave. That is the in-process recovery from a wedged close.
 * @note A failed hook removal keeps the host started with capture disabled. Retry Stop before Start.
 * @note The process-lifetime module reference remains because a selected callback can resume after hook removal.
 * @note Setup/control-plane only.
 */
int32_t DMK_WHEELHOST_CALL wheel_host_stop(void) DMK_WHEELHOST_NOEXCEPT;

    // clang-format on

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETOURMODKIT_WHEEL_HOST_H */
