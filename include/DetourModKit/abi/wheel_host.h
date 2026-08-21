#ifndef DETOURMODKIT_WHEEL_HOST_H
#define DETOURMODKIT_WHEEL_HOST_H

/**
 * @file wheel_host.h
 * @brief Versioned C ABI for the opt-in resident mouse-wheel host.
 *
 * @details A loader module starts one host on its UI thread and passes the resulting @ref DmkWheelHostTable to each
 *          logic generation. The host owns one thread-scoped WH_GETMESSAGE hook and the resident wheel data plane
 *          (counters, remainders, capture epoch, owner, consume mask, TTL). A logic generation opens one lease,
 *          publishes capture state, drains whole-notch counts, and closes the lease. The host stores no logic pointer,
 *          callback, or destructor, so a closed lease proves resident code holds nothing from the generation.
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
#define DMK_WHEELHOST_ABI_VERSION 1u

/**
 * @name Capability bits
 * @brief Host-advertised capabilities in @ref DmkWheelHostTable::capability_bits. A logic generation must tolerate a
 *        host that clears a bit it does not implement.
 * @{
 */
#define DMK_WHEELHOST_CAP_VERTICAL (UINT64_C(1) << 0)   /**< The host captures WM_MOUSEWHEEL. */
#define DMK_WHEELHOST_CAP_HORIZONTAL (UINT64_C(1) << 1) /**< The host captures WM_MOUSEHWHEEL. */
#define DMK_WHEELHOST_CAP_CONSUME (UINT64_C(1) << 2)    /**< The host can swallow an owned wheel message. */
/** @} */

/**
 * @name Status codes
 * @brief Every ABI function returns one of these as an int32_t. Zero is success. Every negative value is a distinct,
 *        stable failure reason.
 * @{
 */
#define DMK_WHEELHOST_OK 0            /**< The call succeeded. */
#define DMK_WHEELHOST_ERR_ABI -1      /**< The table capacity is short, or the abi_version differs. */
#define DMK_WHEELHOST_ERR_INVALID -2  /**< A required pointer argument is null, or an argument is out of range. */
#define DMK_WHEELHOST_ERR_BUSY -3     /**< A lease is already active. Version 1 allows one lease per host. */
#define DMK_WHEELHOST_ERR_NO_LEASE -4 /**< The operation needs an open lease and none is open. */
#define DMK_WHEELHOST_ERR_STALE -5    /**< The lease token does not match the open lease. */
#define DMK_WHEELHOST_ERR_THREAD -6   /**< The target thread is invalid, or the hook did not mount. */
#define DMK_WHEELHOST_ERR_STATE -7    /**< The host is already started, or a stop found no started host. */
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

/** @brief Capture-enable flag for @ref DmkWheelHostTable::publish_capture. Zero disables counting. */
#define DMK_WHEEL_CAPTURE_ENABLED 1u

    // clang-format off

/** @brief Opaque lease token. A successful open writes a non-zero value. */
typedef uint64_t DmkWheelLease;

/**
 * @struct DmkWheelHostTable
 * @brief The host surface a loader passes to each logic generation.
 * @details A generation must check struct_size and abi_version before it calls a function pointer.
 */
typedef struct DmkWheelHostTable
{
    /** @brief The table size known to the host. */
    uint32_t struct_size;
    /** @brief The host ABI revision. */
    uint32_t abi_version;
    /** @brief The bitwise OR of the DMK_WHEELHOST_CAP_* bits the host implements. */
    uint64_t capability_bits;
    /** @brief Non-zero identity unique to this host instance. */
    uint64_t host_identity;
    /** @brief Opaque host state. Pass it unchanged to each function below. */
    void *host_context;

    /**
     * @brief Opens the single lease for owner and generation.
     * @param host_context The table's host_context value.
     * @param owner Caller-chosen owner identity.
     * @param generation Caller-chosen generation identity.
     * @param out_lease Receives a non-zero lease on success. Must not be null.
     * @return A DMK_WHEELHOST_* status code.
     * @note Setup/control-plane only.
     */
    int32_t (DMK_WHEELHOST_CALL *open_lease)(void *host_context, uint64_t owner, uint64_t generation,
                                             DmkWheelLease *out_lease) DMK_WHEELHOST_NOEXCEPT;

    /**
     * @brief Publishes capture and consume state for an open lease.
     * @param host_context The table's host_context value.
     * @param lease The token from open_lease.
     * @param capture_enabled DMK_WHEEL_CAPTURE_ENABLED to count, or zero to stop counting.
     * @param consume_mask The bitwise OR of the DMK_WHEEL_CONSUME_* bits to swallow.
     * @param ttl_ms The consume lease duration. Zero clears the consume mask.
     * @return A DMK_WHEELHOST_* status code.
     * @note The caller must refresh a non-zero consume mask before ttl_ms elapses.
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
     * @brief Closes the matching lease and invalidates its capture state.
     * @param host_context The table's host_context value.
     * @param lease The token from open_lease.
     * @param owner The owner passed to open_lease.
     * @param generation The generation passed to open_lease.
     * @return A DMK_WHEELHOST_* status code.
     * @note A successful close proves resident code holds no logic pointer. It does not authorize an unload by itself.
     * @note Setup/control-plane only.
     */
    int32_t (DMK_WHEELHOST_CALL *close_lease)(void *host_context, DmkWheelLease lease, uint64_t owner,
                                              uint64_t generation) DMK_WHEELHOST_NOEXCEPT;
} DmkWheelHostTable;

/**
 * @brief Starts the process host and fills out_table.
 * @param target_thread_id The target UI thread id. It must belong to this process.
 * @param requested_abi_version The accepted ABI version. Pass DMK_WHEELHOST_ABI_VERSION.
 * @param table_capacity The available out_table bytes. Pass sizeof(DmkWheelHostTable).
 * @param out_table Receives the host table on success. Must not be null.
 * @return A DMK_WHEELHOST_* status code.
 * @note Call this outside a loader lock before the first logic generation loads.
 * @note Setup/control-plane only.
 */
int32_t DMK_WHEELHOST_CALL DmkWheelHost_Start(uint32_t target_thread_id, uint32_t requested_abi_version,
                                              uint32_t table_capacity, DmkWheelHostTable *out_table)
    DMK_WHEELHOST_NOEXCEPT;

/**
 * @brief Removes the host hook and clears its lease.
 * @return A DMK_WHEELHOST_* status code.
 * @note A failed hook removal keeps the host started with capture disabled. Retry Stop before Start.
 * @note The process-lifetime module reference remains because a selected callback can resume after hook removal.
 * @note Setup/control-plane only.
 */
int32_t DMK_WHEELHOST_CALL DmkWheelHost_Stop(void) DMK_WHEELHOST_NOEXCEPT;

    // clang-format on

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETOURMODKIT_WHEEL_HOST_H */
