#ifndef DETOURMODKIT_WHEEL_HOST_H
#define DETOURMODKIT_WHEEL_HOST_H

/**
 * @file wheel_host.h
 * @brief Versioned C ABI for the opt-in resident mouse-wheel host.
 *
 * @details A loader module starts one host and passes the resulting @ref DmkWheelHostTable to each logic generation.
 *          The host owns one thread-scoped WH_GETMESSAGE hook and the resident wheel data plane (counters,
 *          remainders, capture epoch, owner, consume mask, TTL, route identity). A logic generation opens one lease,
 *          publishes capture state, drains whole-notch counts, drives route health and retarget, and closes the
 *          lease. The host stores no logic pointer, callback, or destructor, so a closed lease proves resident code
 *          holds nothing from the generation.
 *
 *          This is a C boundary on purpose. The loader and each logic generation are separately linked modules with
 *          independent static storage, so the wheel host cannot cross that boundary with C++ types. Every value here
 *          is a fixed-width integer or an opaque token, every function uses one declared calling convention, and no
 *          C++ enum, bool, STL type, exception, allocator, or DMK object appears. The header includes only
 *          <stdint.h>; it names no Windows type and no DMK backend.
 *
 *          Thread and loader rules:
 *          - Start the host on the loader control thread before the first logic load. Never install the hook under a
 *            loader lock.
 *          - The host and the target UI thread must belong to the same process.
 *          - The host takes one process-lifetime reference on the module that contains the resident hook before it
 *            publishes the hook. Hook removal is host cleanup, never logic-unmap authorization.
 *          - A resident loader that carries an older wheel-host ABI requires a process restart to replace. Version
 *            negotiation is exact: a version-2 host rejects a version-1 request, and version-2 logic rejects a
 *            version-1 table.
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

/** @brief ABI revision of this header. A host writes it into @ref DmkWheelHostTable::abi_version. */
#define DMK_WHEELHOST_ABI_VERSION 2u

/**
 * @name Capability bits
 * @brief Host-advertised capabilities in @ref DmkWheelHostTable::capability_bits. A logic generation must tolerate a
 *        host that clears a bit it does not implement.
 * @{
 */
#define DMK_WHEELHOST_CAP_VERTICAL (UINT64_C(1) << 0)   /**< The host captures WM_MOUSEWHEEL. */
#define DMK_WHEELHOST_CAP_HORIZONTAL (UINT64_C(1) << 1) /**< The host captures WM_MOUSEHWHEEL. */
#define DMK_WHEELHOST_CAP_CONSUME (UINT64_C(1) << 2)    /**< The host can swallow an owned wheel message. */
#define DMK_WHEELHOST_CAP_ROUTE (UINT64_C(1) << 3)      /**< The host implements route_health and retarget. */
/** @} */

/**
 * @name Status codes
 * @brief Every ABI function returns one of these as an int32_t. Zero is success. Every negative value is a distinct,
 *        stable failure reason.
 * @{
 */
#define DMK_WHEELHOST_OK 0              /**< The call succeeded. */
#define DMK_WHEELHOST_ERR_ABI (-1)      /**< The table capacity is short, or the abi_version differs. */
#define DMK_WHEELHOST_ERR_INVALID (-2)  /**< A required pointer argument is null, or an argument is out of range. */
#define DMK_WHEELHOST_ERR_BUSY (-3)     /**< A lease is already active. Version 2 allows one lease per host. */
#define DMK_WHEELHOST_ERR_NO_LEASE (-4) /**< The operation needs an open lease and none is open. */
#define DMK_WHEELHOST_ERR_STALE (-5)    /**< The lease token does not match the open lease. */
#define DMK_WHEELHOST_ERR_THREAD (-6)   /**< The target thread is invalid, or a hook mount or removal failed. */
#define DMK_WHEELHOST_ERR_STATE (-7)    /**< The host is already started, or a stop found no started host. */
#define DMK_WHEELHOST_ERR_DRAIN (-8)    /**< Admitted callback phases did not drain in the bound. Retry the call. */
#define DMK_WHEELHOST_ERR_PENDING (-9)  /**< A control op is pending. Use its matching retry or authorized close. */
/** @} */

/**
 * @name Route health states
 * @brief Values @ref DmkWheelHostTable::route_health writes. A dead or migrated target cannot report ready.
 * @{
 */
#define DMK_WHEELHOST_ROUTE_TARGET_WAIT 0u     /**< No target is selected. Retarget mounts the first hook. */
#define DMK_WHEELHOST_ROUTE_READY 1u           /**< The hook is mounted and the target thread is alive. */
#define DMK_WHEELHOST_ROUTE_RETRYABLE 2u       /**< The route was lost. Zero hooks are active. Retarget remounts. */
#define DMK_WHEELHOST_ROUTE_CLEANUP_BLOCKED 3u /**< Old-hook removal failed on a live thread. Mounts are blocked. */
/** @} */

/**
 * @name Wheel direction indices
 * @brief Index the count array @ref DmkWheelHostTable::drain_counts writes.
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
 * @brief Select directions to swallow in @ref DmkWheelHostTable::publish_capture. The bit index equals the direction
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
 * @brief Flag bits for the capture_enabled argument of @ref DmkWheelHostTable::publish_capture.
 * @{
 */
/** @brief Capture-enable flag. Zero disables counting. */
#define DMK_WHEEL_CAPTURE_ENABLED 1u
/** @brief Focus gate. The resident callback checks process focus at count admission and consume finalization. */
#define DMK_WHEEL_CAPTURE_REQUIRE_FOCUS 2u
/** @} */

    // clang-format off

/** @brief Opaque lease token. A successful open writes a non-zero value. */
typedef uint64_t DmkWheelLease;

/**
 * @struct DmkWheelHostTable
 * @brief The host surface a loader passes to each logic generation.
 * @details A generation must check struct_size, abi_version, DMK_WHEELHOST_CAP_ROUTE, host_context, and every
 *          function pointer before it calls a function pointer.
 */
typedef struct DmkWheelHostTable
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
     * @return A DMK_WHEELHOST_* status code. A lease retained by a failed close reports DMK_WHEELHOST_ERR_BUSY.
     * @note A lease can open while the route is unmounted. Count and consume stay disabled until the first
     *       successful retarget.
     * @note Setup/control-plane only.
     */
    int32_t (DMK_WHEELHOST_CALL *open_lease)(void *host_context, uint64_t owner, uint64_t generation,
                                             DmkWheelLease *out_lease) DMK_WHEELHOST_NOEXCEPT;

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
    int32_t (DMK_WHEELHOST_CALL *publish_capture)(void *host_context, DmkWheelLease lease,
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
    int32_t (DMK_WHEELHOST_CALL *drain_counts)(void *host_context, DmkWheelLease lease,
                                               uint32_t out_counts[DMK_WHEEL_DIRECTIONS])
        DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Closes the matching lease, invalidates its capture state, and drains admitted callback phases.
     * @param host_context The table's host_context value.
     * @param lease The token from open_lease.
     * @param owner The owner passed to open_lease.
     * @param generation The generation passed to open_lease.
     * @return A DMK_WHEELHOST_* status code. DMK_WHEELHOST_ERR_DRAIN keeps the lease in a disabled Closing state.
     *         The exact retry finishes the close. A successor open is refused until it does.
     * @note A successful close proves resident code holds no admitted decision and no logic pointer. It does not
     *       authorize an unload by itself.
     * @note Setup/control-plane only.
     */
    int32_t (DMK_WHEELHOST_CALL *close_lease)(void *host_context, DmkWheelLease lease, uint64_t owner,
                                              uint64_t generation) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Reads the typed route health.
     * @param host_context The table's host_context value.
     * @param out_state Receives one DMK_WHEELHOST_ROUTE_* value. Must not be null.
     * @param out_thread_id Receives the mounted target thread id, or zero while unmounted. Null skips the write.
     * @param out_mount_generation Receives the mount generation. Null skips the write.
     * @return A DMK_WHEELHOST_* status code.
     * @note The query rechecks target-thread liveness, so a dead target reports DMK_WHEELHOST_ROUTE_RETRYABLE and a
     *       cleanup-blocked route whose old thread exited becomes retryable.
     * @note Setup/control-plane only. Reentrant with publish, drain, and close.
     */
    int32_t (DMK_WHEELHOST_CALL *route_health)(void *host_context, uint32_t *out_state, uint32_t *out_thread_id,
                                               uint64_t *out_mount_generation) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Moves the resident hook to a new target UI thread for an open lease.
     * @param host_context The table's host_context value.
     * @param lease The token from open_lease.
     * @param target_thread_id The new target thread id. It must belong to this process and be alive.
     * @return A DMK_WHEELHOST_* status code. A success increments the mount generation once and preserves the host
     *         identity and the lease. DMK_WHEELHOST_ERR_DRAIN and DMK_WHEELHOST_ERR_THREAD can leave the route
     *         disabled with a matching-lease retry pending. A matching close can cancel that transaction.
     * @note The old hook is removed before the new hook mounts. Hooks never overlap. A removal failure on a live
     *       thread publishes DMK_WHEELHOST_ROUTE_CLEANUP_BLOCKED and blocks the new mount until that thread exits.
     * @note A retarget to the currently mounted, live thread is a success and does not change the mount generation.
     * @note Setup/control-plane only. Never call it from a hook callback or under a loader lock.
     */
    int32_t (DMK_WHEELHOST_CALL *retarget)(void *host_context, DmkWheelLease lease,
                                           uint32_t target_thread_id) DMK_WHEELHOST_NOEXCEPT;
} DmkWheelHostTable;

/**
 * @brief Starts the process host and fills out_table.
 * @param target_thread_id The target UI thread id, or zero to start unmounted in target-wait state. A non-zero id
 *                         must belong to this process.
 * @param requested_abi_version The accepted ABI version. Pass DMK_WHEELHOST_ABI_VERSION. Any other value is
 *                              rejected.
 * @param table_capacity The available out_table bytes. Pass sizeof(DmkWheelHostTable).
 * @param out_table Receives the host table on success. Must not be null.
 * @return A DMK_WHEELHOST_* status code.
 * @note Call this outside a loader lock before the first logic generation loads.
 * @note Setup/control-plane only.
 */
int32_t DMK_WHEELHOST_CALL wheel_host_start(uint32_t target_thread_id, uint32_t requested_abi_version,
                                              uint32_t table_capacity, DmkWheelHostTable *out_table)
    DMK_WHEELHOST_NOEXCEPT;

/**
 * @brief Removes the host hook, drains admitted callback phases, and stops the host.
 * @return A DMK_WHEELHOST_* status code. DMK_WHEELHOST_ERR_BUSY reports an open lease and changes nothing.
 *         DMK_WHEELHOST_ERR_DRAIN keeps the host started and disabled. Retry Stop to finish.
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
