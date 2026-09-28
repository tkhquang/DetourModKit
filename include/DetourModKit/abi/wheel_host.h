#ifndef DETOURMODKIT_WHEEL_HOST_H
#define DETOURMODKIT_WHEEL_HOST_H

/**
 * @file wheel_host.h
 * @brief Versioned C ABI for the opt-in resident mouse-wheel host.
 * @details A loader module starts one host and passes the returned @ref WheelHostTable to each logic generation. The
 *          host owns one thread-scoped WH_GETMESSAGE hook and all capture and route state. Thread and loader rules:
 *          - Call every ABI function outside the loader lock. A non-recursive host lock serializes concurrent calls.
 *            Never invoke an ABI function recursively.
 *          - The host installs the hook from a host-owned thread. A mount from start or retarget survives the exit of
 *            the thread that requested it.
 *          - Before it publishes the hook, the host takes one process-lifetime reference on the module that contains
 *            the hook. Hook removal is host cleanup, never logic-unmap authorization.
 *          - Version negotiation is exact. A resident loader with a different ABI version requires a process restart.
 */

#include <stdint.h>

#if defined(_WIN32)
/** @brief The one calling convention that every function in this ABI uses. */
#define DMK_WHEELHOST_CALL __stdcall
#else
#define DMK_WHEELHOST_CALL
#endif

#if defined(__cplusplus)
/** @brief Adds `noexcept` to each C++ declaration. The C ABI stays the same. */
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
 * @brief Host-advertised bits in @ref WheelHostTable::capability_bits. A logic generation must tolerate a cleared bit.
 * @{
 */
#define DMK_WHEELHOST_CAP_VERTICAL (UINT64_C(1) << 0)   /**< The host captures WM_MOUSEWHEEL. */
#define DMK_WHEELHOST_CAP_HORIZONTAL (UINT64_C(1) << 1) /**< The host captures WM_MOUSEHWHEEL. */
#define DMK_WHEELHOST_CAP_CONSUME (UINT64_C(1) << 2)    /**< The host can consume a masked wheel message. */
#define DMK_WHEELHOST_CAP_ROUTE (UINT64_C(1) << 3)      /**< The host implements route_status and retarget. */
/** @} */

/**
 * @name Status codes
 * @brief Every ABI function returns one of these. Zero is success. Each negative value is a stable failure reason.
 * @{
 */
#define DMK_WHEELHOST_OK 0              /**< The call succeeded. */
#define DMK_WHEELHOST_ERR_ABI (-1)      /**< A table or snapshot capacity is short, or the abi_version differs. */
#define DMK_WHEELHOST_ERR_INVALID (-2)  /**< A required pointer argument is null, or an argument is out of range. */
#define DMK_WHEELHOST_ERR_BUSY (-3)     /**< A lease is already open. The host allows one open lease. */
#define DMK_WHEELHOST_ERR_NO_LEASE (-4) /**< The operation needs an open lease and none is open. */
#define DMK_WHEELHOST_ERR_STALE (-5)    /**< The lease token does not match the open lease. */
#define DMK_WHEELHOST_ERR_THREAD (-6)   /**< The target thread is invalid, or a hook mount or removal failed. */
#define DMK_WHEELHOST_ERR_STATE (-7)    /**< The current host lifecycle state does not permit the operation. */
#define DMK_WHEELHOST_ERR_DRAIN (-8)    /**< Admitted callback phases did not drain in time. Retry the call. */
#define DMK_WHEELHOST_ERR_PENDING (-9)  /**< A control transaction is pending. See DMK_WHEELHOST_CONTROL_*. */
/** @} */

/**
 * @name Route states
 * @brief Values of @ref WheelHostRouteStatus::route_state. They report physical mount health only, and a dead target
 *        never reports ready. Read control_state and capture_armable for data-plane availability.
 * @{
 */
#define DMK_WHEELHOST_ROUTE_TARGET_WAIT 0u     /**< The host has no target. Retarget mounts the first hook. */
#define DMK_WHEELHOST_ROUTE_READY 1u           /**< The hook is mounted and the target thread is alive. */
#define DMK_WHEELHOST_ROUTE_RETRYABLE 2u       /**< The host lost the route. No hook is active. Retarget remounts. */
#define DMK_WHEELHOST_ROUTE_CLEANUP_BLOCKED 3u /**< Old-hook removal failed on a live thread. Retarget retries it. */
/** @} */

/**
 * @name Control states
 * @brief Values of @ref WheelHostRouteStatus::control_state. Each non-idle value names a pending control transaction
 *        that keeps the lease data plane unavailable until an authorized call ends it.
 * @{
 */
#define DMK_WHEELHOST_CONTROL_IDLE 0u             /**< No control transaction is pending. */
#define DMK_WHEELHOST_CONTROL_RETARGET_PENDING 1u /**< A retarget failed. The matching lease must retry or close. */
#define DMK_WHEELHOST_CONTROL_CLOSE_PENDING 2u    /**< A close failed its drain. See close_lease. */
#define DMK_WHEELHOST_CONTROL_STOP_PENDING 3u     /**< A wheel_host_stop call failed. Retry it. */
/** @} */

/**
 * @name Wheel direction indices
 * @brief Indices into the count array that @ref WheelHostTable::drain_counts writes.
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
 * @brief Directions to consume in @ref WheelHostTable::publish_capture. Each bit index equals its direction index.
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
/** @brief Enables counting and consume. Without this flag, the host neither counts nor consumes. */
#define DMK_WHEEL_CAPTURE_ENABLED 1u
/** @brief With this flag, the host counts and consumes only while this process owns the foreground window. */
#define DMK_WHEEL_CAPTURE_REQUIRE_FOCUS 2u
    /** @} */

    // clang-format off

/** @brief Opaque lease token. A successful open writes a non-zero value. */
typedef uint64_t WheelHostLease;

/** @brief One snapshot of the host route and control plane. */
typedef struct WheelHostRouteStatus
{
    /** @brief The snapshot size known to the host. The host writes it. */
    uint32_t struct_size;
    /** @brief One DMK_WHEELHOST_ROUTE_* value. */
    uint32_t route_state;
    /** @brief One DMK_WHEELHOST_CONTROL_* value. */
    uint32_t control_state;
    /** @brief Non-zero when the queried lease can arm capture now. An unqualified snapshot reports zero. */
    uint32_t capture_armable;
    /** @brief The mounted target thread id, or zero while unmounted. */
    uint32_t mounted_thread_id;
    /** @brief Reserved. The host writes zero. */
    uint32_t reserved;
    /** @brief The mount generation. Each successful hook mount increments it once. */
    uint64_t mount_generation;
} WheelHostRouteStatus;

/**
 * @brief The host surface a loader passes to each logic generation.
 * @details Before its first call, a generation must check struct_size, abi_version, DMK_WHEELHOST_CAP_ROUTE,
 *          host_context, and every function pointer.
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
     * @brief Opens the single lease for a non-zero owner and generation, and writes its token to non-null out_lease.
     * @return With valid arguments, a pending transaction reports DMK_WHEELHOST_ERR_PENDING. An open lease without a
     *         pending transaction reports DMK_WHEELHOST_ERR_BUSY.
     * @note Setup/control-plane only. A lease can open while the route is unmounted. Count and consume stay disabled
     *       until publish_capture runs on a DMK_WHEELHOST_ROUTE_READY route.
     */
    int32_t (DMK_WHEELHOST_CALL *open_lease)(void *host_context, uint64_t owner, uint64_t generation,
                                             WheelHostLease *out_lease) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Publishes the capture flags and the consume mask for an open lease.
     * @param ttl_ms The consume mask lifetime in milliseconds. Zero clears the consume mask. Refresh a non-zero mask
     *               before ttl_ms elapses.
     * @note Setup/control-plane only. The consume is best effort. A hook installed after the host can restore the wheel
     *       message after the host returns, so a masked direction can still reach the window.
     */
    int32_t (DMK_WHEELHOST_CALL *publish_capture)(void *host_context, WheelHostLease lease,
                                                  uint32_t capture_enabled, uint32_t consume_mask,
                                                  uint32_t ttl_ms) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Drains the accumulated whole-notch counts into non-null out_counts and zeros them.
     * @note Setup/control-plane only.
     */
    int32_t (DMK_WHEELHOST_CALL *drain_counts)(void *host_context, WheelHostLease lease,
                                               uint32_t out_counts[DMK_WHEEL_DIRECTIONS])
        DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Closes the lease that open_lease opened for owner and generation, and drains admitted callback phases.
     * @return DMK_WHEELHOST_ERR_DRAIN leaves the lease disabled in DMK_WHEELHOST_CONTROL_CLOSE_PENDING. Only the exact
     *         retry or wheel_host_stop ends it, and the host refuses a successor open until then.
     * @note Setup/control-plane only. A successful close proves that resident code holds no admitted decision, logic
     *       pointer, callback, or destructor from the generation. It does not authorize an unload by itself.
     */
    int32_t (DMK_WHEELHOST_CALL *close_lease)(void *host_context, WheelHostLease lease, uint64_t owner,
                                              uint64_t generation) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Writes one snapshot of the route and the control plane to non-null out_status.
     * @param lease The token from open_lease, or zero to request an unqualified snapshot.
     * @param status_capacity The available out_status bytes. Pass sizeof(WheelHostRouteStatus).
     * @return A short capacity reports DMK_WHEELHOST_ERR_ABI. A non-zero lease that does not match the open lease
     *         reports DMK_WHEELHOST_ERR_STALE. A stopped host reports DMK_WHEELHOST_ERR_STATE.
     * @note Setup/control-plane only. The query rechecks target-thread liveness, so a dead target reports
     *       DMK_WHEELHOST_ROUTE_RETRYABLE. A cleanup-blocked route whose old thread exited becomes retryable. The
     *       query never expires, cancels, or completes a control transaction.
     */
    int32_t (DMK_WHEELHOST_CALL *route_status)(void *host_context, WheelHostLease lease, uint32_t status_capacity,
                                               WheelHostRouteStatus *out_status) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Moves the resident hook to a new target UI thread for an open lease.
     * @param target_thread_id A non-zero id of a live thread in this process. A retry converges on its own
     *                         target_thread_id, not on the original destination.
     * @return DMK_WHEELHOST_ERR_DRAIN and DMK_WHEELHOST_ERR_THREAD leave DMK_WHEELHOST_CONTROL_RETARGET_PENDING. Only a
     *         matching-lease retry or close ends it. A success keeps the lease open.
     * @note Setup/control-plane only. Never call it from a hook callback. The host removes the old hook before the new
     *       hook mounts, so hooks never overlap. A removal failure on a live thread publishes
     *       DMK_WHEELHOST_ROUTE_CLEANUP_BLOCKED, and each retry repeats the removal. On a DMK_WHEELHOST_ROUTE_READY
     *       route, a retarget to the mounted thread keeps the mount generation, and its success ends a pending
     *       retarget. A retarget that mounts a new hook discards undrained counts and disables capture until the next
     *       publish_capture call.
     */
    int32_t (DMK_WHEELHOST_CALL *retarget)(void *host_context, WheelHostLease lease,
                                           uint32_t target_thread_id) DMK_WHEELHOST_NOEXCEPT;
} WheelHostTable;

/**
 * @brief Starts the process host and, on success, fills non-null out_table.
 * @param target_thread_id The target UI thread id, or zero to start in DMK_WHEELHOST_ROUTE_TARGET_WAIT. A non-zero id
 *                         must name a live thread of this process.
 * @param requested_abi_version Pass DMK_WHEELHOST_ABI_VERSION. Any other value reports DMK_WHEELHOST_ERR_ABI.
 * @param table_capacity The available out_table bytes. Pass sizeof(WheelHostTable).
 * @note Setup/control-plane only. Call it on the loader control thread before the first logic generation loads.
 */
int32_t DMK_WHEELHOST_CALL wheel_host_start(uint32_t target_thread_id, uint32_t requested_abi_version,
                                              uint32_t table_capacity, WheelHostTable *out_table)
    DMK_WHEELHOST_NOEXCEPT;

/**
 * @brief Removes the host hook, drains admitted callback phases, and stops the host.
 * @return DMK_WHEELHOST_ERR_BUSY reports an open lease unless DMK_WHEELHOST_CONTROL_CLOSE_PENDING or
 *         DMK_WHEELHOST_CONTROL_STOP_PENDING is pending, and it changes nothing. DMK_WHEELHOST_ERR_DRAIN and
 *         DMK_WHEELHOST_ERR_THREAD keep the host started and disabled. Until a retry of wheel_host_stop succeeds,
 *         wheel_host_start reports DMK_WHEELHOST_ERR_STATE.
 * @note Setup/control-plane only.
 */
int32_t DMK_WHEELHOST_CALL wheel_host_stop(void) DMK_WHEELHOST_NOEXCEPT;

    // clang-format on

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETOURMODKIT_WHEEL_HOST_H */
