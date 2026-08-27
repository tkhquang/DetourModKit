/**
 * @file wheel_host.cpp
 * @brief Implements the resident broker behind the wheel host C ABI.
 */

#include "DetourModKit/abi/wheel_host.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <limits>

namespace
{
    constexpr std::uint64_t CAPTURE_ENABLED_BIT = 1u;
    constexpr std::uint64_t CAPTURE_FOCUS_BIT = 2u;
    constexpr std::uint64_t CAPTURE_FLAG_MASK = CAPTURE_ENABLED_BIT | CAPTURE_FOCUS_BIT;
    constexpr int CAPTURE_EPOCH_SHIFT = 2;
    constexpr int COUNT_BITS = 11;
    constexpr std::uint64_t COUNT_MASK = (std::uint64_t{1} << COUNT_BITS) - 1u;
    constexpr std::uint32_t MAX_COUNT = 1024;
    constexpr int REMAINDER_BITS = 8;
    constexpr std::uint64_t REMAINDER_MASK = (std::uint64_t{1} << REMAINDER_BITS) - 1u;
    constexpr std::uint64_t REMAINDER_OWNED_BIT = std::uint64_t{1} << REMAINDER_BITS;
    constexpr int REMAINDER_EPOCH_SHIFT = REMAINDER_BITS + 1;
    // pack_remainder biases by WHEEL_DELTA, so the encoded value spans 0 through 2 * WHEEL_DELTA - 1.
    static_assert(2 * WHEEL_DELTA <= (1 << REMAINDER_BITS), "a biased sub-notch remainder must fit the value field");
    constexpr int CONSUME_EPOCH_SHIFT = 4;
    constexpr std::uint32_t CONSUME_MASK = (1u << DMK_WHEEL_DIRECTIONS) - 1u;
    constexpr std::uint64_t MAX_EPOCH = std::numeric_limits<std::uint64_t>::max() >> COUNT_BITS;

    /// Bounds every control-plane wait for admitted callback phases.
    constexpr std::uint32_t DEFAULT_DRAIN_TIMEOUT_MS = 2000;

    class ControlLock
    {
    public:
        explicit ControlLock(SRWLOCK &lock) noexcept : m_lock(&lock) { AcquireSRWLockExclusive(m_lock); }
        ~ControlLock() noexcept { ReleaseSRWLockExclusive(m_lock); }

        ControlLock(const ControlLock &) = delete;
        ControlLock &operator=(const ControlLock &) = delete;

    private:
        SRWLOCK *m_lock;
    };

    [[nodiscard]] std::uint64_t next_nonzero(std::uint64_t value, std::uint64_t maximum) noexcept
    {
        return value >= maximum ? 1u : value + 1u;
    }

    [[nodiscard]] constexpr std::uint64_t pack_capture(std::uint64_t epoch, std::uint64_t flags) noexcept
    {
        return (epoch << CAPTURE_EPOCH_SHIFT) | (flags & CAPTURE_FLAG_MASK);
    }

    [[nodiscard]] std::uint64_t capture_epoch(std::uint64_t state) noexcept
    {
        return state >> CAPTURE_EPOCH_SHIFT;
    }

    [[nodiscard]] constexpr std::uint64_t pack_count(std::uint64_t epoch, std::uint32_t count) noexcept
    {
        return (epoch << COUNT_BITS) | std::min(count, MAX_COUNT);
    }

    [[nodiscard]] std::uint64_t count_epoch(std::uint64_t state) noexcept
    {
        return state >> COUNT_BITS;
    }

    [[nodiscard]] std::uint32_t unpack_count(std::uint64_t state) noexcept
    {
        return static_cast<std::uint32_t>(state & COUNT_MASK);
    }

    [[nodiscard]] constexpr std::uint64_t pack_remainder(std::uint64_t epoch, bool owned, int remainder) noexcept
    {
        const int shifted = remainder + WHEEL_DELTA;
        const auto encoded = static_cast<std::uint64_t>(shifted);
        return (epoch << REMAINDER_EPOCH_SHIFT) | (owned ? REMAINDER_OWNED_BIT : 0u) | encoded;
    }

    [[nodiscard]] std::uint64_t remainder_epoch(std::uint64_t state) noexcept
    {
        return state >> REMAINDER_EPOCH_SHIFT;
    }

    [[nodiscard]] bool remainder_owned(std::uint64_t state) noexcept
    {
        return (state & REMAINDER_OWNED_BIT) != 0;
    }

    [[nodiscard]] int unpack_remainder(std::uint64_t state) noexcept
    {
        return static_cast<int>(state & REMAINDER_MASK) - WHEEL_DELTA;
    }

    [[nodiscard]] constexpr std::uint64_t pack_consume(std::uint64_t epoch, std::uint32_t mask) noexcept
    {
        return (epoch << CONSUME_EPOCH_SHIFT) | (mask & CONSUME_MASK);
    }

    /// The control operation whose failure left a transaction pending. control_state_of() names each one.
    enum class PendingOp : std::uint8_t
    {
        None,
        Close,
        Retarget,
        Stop
    };

    struct HostState
    {
        SRWLOCK control_lock = SRWLOCK_INIT;
        bool started = false;
        bool stopping = false;
        HHOOK hook = nullptr;
        HANDLE target_thread = nullptr;
        std::uint32_t target_thread_id = 0;
        std::uint32_t route_state = DMK_WHEELHOST_ROUTE_TARGET_WAIT;
        std::uint64_t mount_generation = 0;
        std::uint64_t host_identity = 0;
        std::uint64_t lease = 0;
        std::uint64_t owner = 0;
        std::uint64_t generation = 0;
        std::uint64_t epoch = 1;
        std::uint64_t lease_counter = 0;
        std::uint64_t identity_counter = 0;
        PendingOp pending_op = PendingOp::None;
        std::uint64_t pending_lease = 0;
        std::uint64_t pending_owner = 0;
        std::uint64_t pending_generation = 0;
        // The host owns the mount worker and its request-response rendezvous. See mount_resident_hook().
        HANDLE mount_thread = nullptr;
        HANDLE mount_request = nullptr;
        HANDLE mount_done = nullptr;
        std::uint32_t mount_request_tid = 0;
        HHOOK mount_result = nullptr;
        // Counts resident callback frames inside an admission phase. Nested message loops can hold several at once.
        std::atomic<std::uint32_t> admitted_phases{0};
        std::atomic<std::uint64_t> capture_state{pack_capture(1, 0)};
        std::atomic<std::uint64_t> consume_state{pack_consume(1, 0)};
        std::atomic<std::uint64_t> consume_deadline_ms{0};
        std::array<std::atomic<std::uint64_t>, 2> remainder{pack_remainder(1, false, 0), pack_remainder(1, false, 0)};
        std::array<std::atomic<std::uint64_t>, DMK_WHEEL_DIRECTIONS>
            counts{pack_count(1, 0), pack_count(1, 0), pack_count(1, 0), pack_count(1, 0)};

        void reset_data_plane(std::uint64_t active_epoch) noexcept
        {
            for (auto &slot : remainder)
            {
                slot.store(pack_remainder(active_epoch, false, 0), std::memory_order_release);
            }
            for (auto &slot : counts)
            {
                slot.store(pack_count(active_epoch, 0), std::memory_order_release);
            }
        }

        void invalidate_capture() noexcept
        {
            epoch = next_nonzero(epoch, MAX_EPOCH);
            capture_state.store(pack_capture(epoch, 0), std::memory_order_seq_cst);
            consume_state.store(pack_consume(epoch, 0), std::memory_order_release);
            consume_deadline_ms.store(0, std::memory_order_relaxed);
            reset_data_plane(epoch);
        }
    };

    constinit HostState g_host;

#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
    using HookProbe = void(DMK_WHEELHOST_CALL *)(void);
    std::atomic<HookProbe> g_hook_probe{nullptr};
    std::atomic<HookProbe> g_finalize_probe{nullptr};
    std::atomic<bool> g_force_unhook_failure{false};
    std::atomic<std::uint32_t> g_drain_timeout_override_ms{0};
    std::atomic<std::int32_t> g_process_focus_override{-1};
#endif

    [[nodiscard]] std::uint32_t drain_timeout_ms() noexcept
    {
#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
        const std::uint32_t override_ms = g_drain_timeout_override_ms.load(std::memory_order_acquire);
        if (override_ms != 0)
        {
            return override_ms;
        }
#endif
        return DEFAULT_DRAIN_TIMEOUT_MS;
    }

    /**
     * @brief Waits, bounded, for every admitted callback phase to leave.
     * @details Runs only on the control plane, after invalidate_capture() advanced the epoch. A parked lower-hook
     *          frame holds no phase, so this waits only on the short allocation-free admission windows.
     * @note Requires g_host.control_lock.
     */
    [[nodiscard]] bool drain_admitted_phases() noexcept
    {
        const std::uint64_t deadline_ms = GetTickCount64() + drain_timeout_ms();
        while (g_host.admitted_phases.load(std::memory_order_seq_cst) != 0)
        {
            if (GetTickCount64() >= deadline_ms)
            {
                return false;
            }
            Sleep(0);
        }
        return true;
    }

    /// Projects the internal transaction onto the ABI control state. Every PendingOp value is nameable.
    [[nodiscard]] constexpr std::uint32_t control_state_of(PendingOp op) noexcept
    {
        switch (op)
        {
        case PendingOp::Close:
            return DMK_WHEELHOST_CONTROL_CLOSE_PENDING;
        case PendingOp::Retarget:
            return DMK_WHEELHOST_CONTROL_RETARGET_PENDING;
        case PendingOp::Stop:
            return DMK_WHEELHOST_CONTROL_STOP_PENDING;
        case PendingOp::None:
            break;
        }
        return DMK_WHEELHOST_CONTROL_IDLE;
    }

    /// Requires g_host.control_lock. Clears any pending control transaction.
    void clear_pending() noexcept
    {
        g_host.pending_op = PendingOp::None;
        g_host.pending_lease = 0;
        g_host.pending_owner = 0;
        g_host.pending_generation = 0;
    }

    [[nodiscard]] bool valid_context(void *host_context) noexcept
    {
        return host_context == &g_host;
    }

    [[nodiscard]] bool is_wheel(UINT message) noexcept
    {
        return message == WM_MOUSEWHEEL || message == WM_MOUSEHWHEEL;
    }

    /// Reports whether this process owns the foreground window.
    [[nodiscard]] bool process_owns_foreground() noexcept
    {
#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
        if (const std::int32_t override_value = g_process_focus_override.load(std::memory_order_acquire);
            override_value >= 0)
        {
            return override_value != 0;
        }
#endif
        const HWND foreground = GetForegroundWindow();
        if (foreground == nullptr)
        {
            return false;
        }
        DWORD pid = 0;
        GetWindowThreadProcessId(foreground, &pid);
        return pid == GetCurrentProcessId();
    }

    [[nodiscard]] bool direction_consumed(std::uint64_t epoch, std::uint32_t direction_bit) noexcept
    {
        const std::uint64_t state = g_host.consume_state.load(std::memory_order_acquire);
        if ((state >> CONSUME_EPOCH_SHIFT) != epoch || (state & direction_bit) == 0)
        {
            return false;
        }
        return GetTickCount64() < g_host.consume_deadline_ms.load(std::memory_order_relaxed);
    }

    /// Brackets one admitted callback phase. Allocation-free, nonblocking, and free of host locks.
    class PhaseGuard
    {
    public:
        PhaseGuard() noexcept { g_host.admitted_phases.fetch_add(1, std::memory_order_seq_cst); }
        ~PhaseGuard() noexcept { g_host.admitted_phases.fetch_sub(1, std::memory_order_seq_cst); }
        PhaseGuard(const PhaseGuard &) = delete;
        PhaseGuard &operator=(const PhaseGuard &) = delete;
    };

    [[nodiscard]] int fold_axis(std::atomic<std::uint64_t> &slot, std::uint64_t epoch, bool owned, int delta) noexcept
    {
        std::uint64_t observed = slot.load(std::memory_order_acquire);
        for (;;)
        {
            if (remainder_epoch(observed) != epoch)
            {
                return 0;
            }
            const int prior = remainder_owned(observed) == owned ? unpack_remainder(observed) : 0;
            const int total = prior + delta;
            const int notches = total / WHEEL_DELTA;
            const std::uint64_t desired = pack_remainder(epoch, owned, total % WHEEL_DELTA);
            if (slot.compare_exchange_weak(observed, desired, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return notches;
            }
        }
    }

    void bump_count(std::size_t direction, std::uint64_t epoch, std::uint32_t increment) noexcept
    {
        auto &slot = g_host.counts[direction];
        std::uint64_t observed = slot.load(std::memory_order_acquire);
        for (;;)
        {
            if (count_epoch(observed) != epoch)
            {
                return;
            }
            const std::uint32_t current = unpack_count(observed);
            const std::uint32_t next = std::min<std::uint32_t>(MAX_COUNT, current + increment);
            const std::uint64_t desired = pack_count(epoch, next);
            if (slot.compare_exchange_weak(observed, desired, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                return;
            }
        }
    }

    void count_direction(bool horizontal, std::uint64_t epoch, int notches) noexcept
    {
        if (notches > 0)
        {
            bump_count(horizontal ? DMK_WHEEL_RIGHT : DMK_WHEEL_UP, epoch, static_cast<std::uint32_t>(notches));
        }
        else if (notches < 0)
        {
            bump_count(horizontal ? DMK_WHEEL_LEFT : DMK_WHEEL_DOWN, epoch, static_cast<std::uint32_t>(-notches));
        }
    }

    /**
     * @brief The resident WH_GETMESSAGE callback.
     * @details Order contract (v2): count admission runs before CallNextHookEx and mutates nothing in the message,
     *          so older hooks see the original record. CallNextHookEx runs exactly once. Consume finalization runs
     *          after it returns and writes WM_NULL only when the saved intent, epoch, consume mask, TTL, and focus
     *          gate all remain current. A newer hook can rewrite the message after this returns; the consume stays
     *          best effort. Each admitted phase is counted so the control plane can drain decisions.
     */
    LRESULT CALLBACK resident_hook(int code, WPARAM wparam, LPARAM lparam) noexcept
    {
        if (code != HC_ACTION)
        {
            return CallNextHookEx(nullptr, code, wparam, lparam);
        }

        MSG *const message = reinterpret_cast<MSG *>(lparam);
        if (message == nullptr || !is_wheel(message->message))
        {
            return CallNextHookEx(nullptr, code, wparam, lparam);
        }

        // Save the original fields and the entry epoch before any decision.
        const MSG original = *message;
        const std::uint64_t capture = g_host.capture_state.load(std::memory_order_seq_cst);
        if ((capture & CAPTURE_ENABLED_BIT) == 0)
        {
            return CallNextHookEx(nullptr, code, wparam, lparam);
        }

        const bool horizontal = original.message == WM_MOUSEHWHEEL;
        const int delta = static_cast<short>(HIWORD(original.wParam));
        if (delta == 0 || wparam != PM_REMOVE)
        {
            // PM_NOREMOVE passes through without a counter, remainder, ownership, epoch, or consume change.
            return CallNextHookEx(nullptr, code, wparam, lparam);
        }

        const std::uint32_t direction_bit = horizontal ? (delta > 0 ? DMK_WHEEL_CONSUME_RIGHT : DMK_WHEEL_CONSUME_LEFT)
                                                       : (delta > 0 ? DMK_WHEEL_CONSUME_UP : DMK_WHEEL_CONSUME_DOWN);
        const std::uint64_t epoch = capture_epoch(capture);
        // Count admission: fold, count, and snapshot the consume intent, all before CallNextHookEx.
        bool consume_intent = false;
        {
            const PhaseGuard phase;
#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
            if (const HookProbe probe = g_hook_probe.load(std::memory_order_acquire); probe != nullptr)
            {
                probe();
            }
#endif
            const std::uint64_t recheck = g_host.capture_state.load(std::memory_order_seq_cst);
            const bool current = capture_epoch(recheck) == epoch && (recheck & CAPTURE_ENABLED_BIT) != 0;
            const bool focus_ok = (recheck & CAPTURE_FOCUS_BIT) == 0 || process_owns_foreground();
            if (current && focus_ok)
            {
                const bool owned = direction_consumed(epoch, direction_bit);
                const int notches = fold_axis(g_host.remainder[horizontal ? 1u : 0u], epoch, owned, delta);
                count_direction(horizontal, epoch, notches);
                consume_intent = owned;
            }
        }

        // Pass the original record to older hooks with no DMK mutation, exactly once.
        const LRESULT result = CallNextHookEx(nullptr, code, wparam, lparam);

        if (!consume_intent)
        {
            return result;
        }

        // Consume finalization: the write happens only while every admission condition still holds.
        {
            const PhaseGuard phase;
#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
            if (const HookProbe probe = g_finalize_probe.load(std::memory_order_acquire); probe != nullptr)
            {
                probe();
            }
#endif
            const std::uint64_t recheck = g_host.capture_state.load(std::memory_order_seq_cst);
            const bool current = capture_epoch(recheck) == epoch && (recheck & CAPTURE_ENABLED_BIT) != 0;
            const bool focus_ok = (recheck & CAPTURE_FOCUS_BIT) == 0 || process_owns_foreground();
            if (current && focus_ok && direction_consumed(epoch, direction_bit))
            {
                message->message = WM_NULL;
                message->wParam = 0;
                message->lParam = 0;
            }
        }
        return result;
    }

    int32_t DMK_WHEELHOST_CALL
    open_lease(void *host_context, std::uint64_t owner, std::uint64_t generation, WheelHostLease *out_lease) noexcept
    {
        if (!valid_context(host_context) || out_lease == nullptr || owner == 0 || generation == 0)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        *out_lease = 0;
        const ControlLock lock(g_host.control_lock);
        if (g_host.pending_op != PendingOp::None)
        {
            return DMK_WHEELHOST_ERR_PENDING;
        }
        if (!g_host.started || g_host.stopping)
        {
            return DMK_WHEELHOST_ERR_STATE;
        }
        if (g_host.lease != 0)
        {
            return DMK_WHEELHOST_ERR_BUSY;
        }

        g_host.lease_counter = next_nonzero(g_host.lease_counter, std::numeric_limits<std::uint64_t>::max());
        g_host.invalidate_capture();
        g_host.lease = g_host.lease_counter;
        g_host.owner = owner;
        g_host.generation = generation;
        *out_lease = g_host.lease;
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL publish_capture(
        void *host_context,
        WheelHostLease lease,
        std::uint32_t capture_enabled,
        std::uint32_t consume_mask,
        std::uint32_t ttl_ms
    ) noexcept
    {
        if (!valid_context(host_context) || (capture_enabled & ~CAPTURE_FLAG_MASK) != 0 ||
            (consume_mask & ~CONSUME_MASK) != 0)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        const ControlLock lock(g_host.control_lock);
        if (g_host.pending_op != PendingOp::None)
        {
            return DMK_WHEELHOST_ERR_PENDING;
        }
        if (g_host.stopping)
        {
            return DMK_WHEELHOST_ERR_STATE;
        }
        if (g_host.lease == 0)
        {
            return DMK_WHEELHOST_ERR_NO_LEASE;
        }
        if (lease != g_host.lease)
        {
            return DMK_WHEELHOST_ERR_STALE;
        }

        const bool consume_active = ttl_ms != 0 && consume_mask != 0;
        if (consume_active)
        {
            const std::uint64_t now = GetTickCount64();
            const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
            g_host.consume_deadline_ms.store(
                now > maximum - ttl_ms ? maximum : now + ttl_ms,
                std::memory_order_relaxed
            );
        }
        else
        {
            g_host.consume_deadline_ms.store(0, std::memory_order_relaxed);
        }
        g_host.consume_state.store(
            pack_consume(g_host.epoch, consume_active ? consume_mask : 0u),
            std::memory_order_release
        );
        // Capture arms only through a mounted, ready route. An unmounted lease keeps counting disabled.
        const std::uint64_t flags =
            g_host.route_state == DMK_WHEELHOST_ROUTE_READY ? (capture_enabled & CAPTURE_FLAG_MASK) : 0u;
        g_host.capture_state.store(pack_capture(g_host.epoch, flags), std::memory_order_seq_cst);
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL
    drain_counts(void *host_context, WheelHostLease lease, std::uint32_t out_counts[DMK_WHEEL_DIRECTIONS]) noexcept
    {
        if (!valid_context(host_context) || out_counts == nullptr)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        const ControlLock lock(g_host.control_lock);
        if (g_host.pending_op != PendingOp::None)
        {
            return DMK_WHEELHOST_ERR_PENDING;
        }
        if (g_host.stopping)
        {
            return DMK_WHEELHOST_ERR_STATE;
        }
        if (g_host.lease == 0)
        {
            return DMK_WHEELHOST_ERR_NO_LEASE;
        }
        if (lease != g_host.lease)
        {
            return DMK_WHEELHOST_ERR_STALE;
        }

        for (std::size_t i = 0; i < DMK_WHEEL_DIRECTIONS; ++i)
        {
            const std::uint64_t state =
                g_host.counts[i].exchange(pack_count(g_host.epoch, 0), std::memory_order_acq_rel);
            out_counts[i] = count_epoch(state) == g_host.epoch ? unpack_count(state) : 0;
        }
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL
    close_lease(void *host_context, WheelHostLease lease, std::uint64_t owner, std::uint64_t generation) noexcept
    {
        if (!valid_context(host_context))
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        const ControlLock lock(g_host.control_lock);
        if (g_host.pending_op != PendingOp::None)
        {
            if (g_host.pending_op == PendingOp::Retarget)
            {
                const bool matching_lease =
                    lease == g_host.pending_lease && owner == g_host.owner && generation == g_host.generation;
                if (!matching_lease)
                {
                    return DMK_WHEELHOST_ERR_PENDING;
                }
                // An authorized close supersedes the disabled retarget transaction and drains the same lease below.
                clear_pending();
            }
            else if (g_host.pending_op == PendingOp::Close)
            {
                const bool exact_retry = lease == g_host.pending_lease && owner == g_host.pending_owner &&
                                         generation == g_host.pending_generation;
                if (!exact_retry)
                {
                    return DMK_WHEELHOST_ERR_PENDING;
                }
                // The Closing lease is already invalidated. The retry only has to finish the drain.
                if (!drain_admitted_phases())
                {
                    return DMK_WHEELHOST_ERR_DRAIN;
                }
                clear_pending();
                g_host.lease = 0;
                g_host.owner = 0;
                g_host.generation = 0;
                return DMK_WHEELHOST_OK;
            }
            else
            {
                return DMK_WHEELHOST_ERR_PENDING;
            }
        }
        if (g_host.stopping)
        {
            return DMK_WHEELHOST_ERR_STATE;
        }
        if (g_host.lease == 0)
        {
            return DMK_WHEELHOST_ERR_NO_LEASE;
        }
        if (lease != g_host.lease || owner != g_host.owner || generation != g_host.generation)
        {
            return DMK_WHEELHOST_ERR_STALE;
        }

        g_host.invalidate_capture();
        if (!drain_admitted_phases())
        {
            // Closing state: the lease is retained and disabled. Only the exact retry can finish it, and a
            // successor open is refused until it does.
            g_host.pending_op = PendingOp::Close;
            g_host.pending_lease = lease;
            g_host.pending_owner = owner;
            g_host.pending_generation = generation;
            return DMK_WHEELHOST_ERR_DRAIN;
        }
        g_host.lease = 0;
        g_host.owner = 0;
        g_host.generation = 0;
        return DMK_WHEELHOST_OK;
    }

    DWORD WINAPI mount_thread_main(LPVOID) noexcept
    {
        for (;;)
        {
            if (WaitForSingleObject(g_host.mount_request, INFINITE) != WAIT_OBJECT_0)
            {
                return 0;
            }
            if (g_host.mount_request_tid == 0)
            {
                return 0;
            }
            g_host.mount_result = SetWindowsHookExW(WH_GETMESSAGE, &resident_hook, nullptr, g_host.mount_request_tid);
            if (SetEvent(g_host.mount_done) == 0)
            {
                return 0;
            }
        }
    }

    /**
     * @brief Releases the handles for a terminated mount worker.
     * @note Requires g_host.control_lock.
     */
    void clear_mount_thread() noexcept
    {
        CloseHandle(g_host.mount_thread);
        CloseHandle(g_host.mount_request);
        CloseHandle(g_host.mount_done);
        g_host.mount_thread = nullptr;
        g_host.mount_request = nullptr;
        g_host.mount_done = nullptr;
        g_host.mount_request_tid = 0;
        g_host.mount_result = nullptr;
    }

    /**
     * @brief Stops the mount worker and releases its handles.
     * @note Requires g_host.control_lock.
     */
    [[nodiscard]] bool stop_mount_thread() noexcept
    {
        if (g_host.mount_thread == nullptr)
        {
            return true;
        }

        g_host.mount_request_tid = 0;
        if (SetEvent(g_host.mount_request) == 0 && WaitForSingleObject(g_host.mount_thread, 0) != WAIT_OBJECT_0)
        {
            return false;
        }
        if (WaitForSingleObject(g_host.mount_thread, INFINITE) != WAIT_OBJECT_0)
        {
            return false;
        }
        clear_mount_thread();
        return true;
    }

    /**
     * @brief Requires g_host.control_lock. Installs the resident hook from the host-owned mount thread.
     * @details Win32 removes a hook when the thread that installed it exits.
     *          A transient poller can therefore leave a false ready route after its thread exits.
     *          The host worker lasts until wheel_host_stop.
     */
    [[nodiscard]] HHOOK mount_resident_hook(std::uint32_t target_thread_id) noexcept
    {
        if (g_host.mount_thread == nullptr)
        {
            const HANDLE request = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            const HANDLE done = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            HANDLE thread = nullptr;
            if (request != nullptr && done != nullptr)
            {
                g_host.mount_request = request;
                g_host.mount_done = done;
                thread = CreateThread(
                    nullptr,
                    static_cast<SIZE_T>(64u) * 1024u,
                    &mount_thread_main,
                    nullptr,
                    STACK_SIZE_PARAM_IS_A_RESERVATION,
                    nullptr
                );
            }
            if (thread == nullptr)
            {
                if (request != nullptr)
                {
                    CloseHandle(request);
                }
                if (done != nullptr)
                {
                    CloseHandle(done);
                }
                g_host.mount_request = nullptr;
                g_host.mount_done = nullptr;
                return nullptr;
            }
            g_host.mount_thread = thread;
        }
        g_host.mount_request_tid = target_thread_id;
        g_host.mount_result = nullptr;
        if (SetEvent(g_host.mount_request) == 0)
        {
            if (WaitForSingleObject(g_host.mount_thread, 0) == WAIT_OBJECT_0)
            {
                clear_mount_thread();
            }
            return nullptr;
        }
        const std::array<HANDLE, 2> wait_handles = {
            g_host.mount_done,
            g_host.mount_thread,
        };
        const DWORD wait_result =
            WaitForMultipleObjects(static_cast<DWORD>(wait_handles.size()), wait_handles.data(), FALSE, INFINITE);
        if (wait_result != WAIT_OBJECT_0)
        {
            if (wait_result == WAIT_OBJECT_0 + 1)
            {
                clear_mount_thread();
            }
            return nullptr;
        }
        return g_host.mount_result;
    }

    [[nodiscard]] bool pin_host_module() noexcept
    {
        HMODULE module = nullptr;
        return GetModuleHandleExW(
                   GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                   reinterpret_cast<LPCWSTR>(&resident_hook),
                   &module
               ) != 0;
    }

    [[nodiscard]] HANDLE open_target_thread(std::uint32_t target_thread_id) noexcept
    {
        HANDLE thread = OpenThread(SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION, FALSE, target_thread_id);
        if (thread == nullptr)
        {
            return nullptr;
        }
        if (GetProcessIdOfThread(thread) != GetCurrentProcessId() || WaitForSingleObject(thread, 0) == WAIT_OBJECT_0)
        {
            CloseHandle(thread);
            return nullptr;
        }
        return thread;
    }

    [[nodiscard]] bool remove_hook(HHOOK hook) noexcept
    {
#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
        if (g_force_unhook_failure.load(std::memory_order_acquire))
        {
            return false;
        }
#endif
        return UnhookWindowsHookEx(hook) != 0;
    }

    /// Requires g_host.control_lock. Reports whether the mounted target thread exited.
    [[nodiscard]] bool target_thread_exited() noexcept
    {
        return g_host.target_thread != nullptr && WaitForSingleObject(g_host.target_thread, 0) == WAIT_OBJECT_0;
    }

    /// Requires g_host.control_lock. Drops the mounted route state. Thread exit is authoritative hook retirement.
    void retire_route_after_thread_exit() noexcept
    {
        if (g_host.hook != nullptr)
        {
            // The hook died with its thread. The call only releases the handle; its result carries no authority.
            (void)UnhookWindowsHookEx(g_host.hook);
            g_host.hook = nullptr;
        }
        if (g_host.target_thread != nullptr)
        {
            CloseHandle(g_host.target_thread);
            g_host.target_thread = nullptr;
        }
        g_host.target_thread_id = 0;
        g_host.invalidate_capture();
        g_host.route_state = DMK_WHEELHOST_ROUTE_RETRYABLE;
    }

    /**
     * @brief Requires g_host.control_lock. Rechecks target-thread liveness and settles the route state.
     * @details A dead target cannot remain ready, and a cleanup-blocked route whose old thread exited becomes
     *          retryable. Runs from route_status and before every retarget attempt.
     */
    void settle_route_state() noexcept
    {
        if (g_host.hook != nullptr && target_thread_exited())
        {
            retire_route_after_thread_exit();
        }
    }

    int32_t DMK_WHEELHOST_CALL route_status(
        void *host_context,
        WheelHostLease lease,
        std::uint32_t status_capacity,
        WheelHostRouteStatus *out_status
    ) noexcept
    {
        if (!valid_context(host_context) || out_status == nullptr)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        if (status_capacity < sizeof(WheelHostRouteStatus))
        {
            return DMK_WHEELHOST_ERR_ABI;
        }
        const ControlLock lock(g_host.control_lock);
        if (!g_host.started)
        {
            return DMK_WHEELHOST_ERR_STATE;
        }
        // A zero lease is an unqualified probe, so a loader can read the route before it hands the table out.
        const bool lease_matches = lease != 0 && lease == g_host.lease;
        if (lease != 0 && !lease_matches)
        {
            return DMK_WHEELHOST_ERR_STALE;
        }
        // Liveness recheck only. The query settles physical mount health and never ends a control transaction.
        settle_route_state();

        WheelHostRouteStatus status{};
        status.struct_size = static_cast<std::uint32_t>(sizeof(WheelHostRouteStatus));
        status.route_state = g_host.route_state;
        status.control_state = control_state_of(g_host.pending_op);
        // The host owns its own precondition lattice so no client re-derives it.
        status.capture_armable = !g_host.stopping && g_host.pending_op == PendingOp::None && lease_matches &&
                                         g_host.route_state == DMK_WHEELHOST_ROUTE_READY
                                     ? 1u
                                     : 0u;
        status.mounted_thread_id = g_host.hook != nullptr ? g_host.target_thread_id : 0;
        status.mount_generation = g_host.mount_generation;
        *out_status = status;
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL
    retarget(void *host_context, WheelHostLease lease, std::uint32_t target_thread_id) noexcept
    {
        if (!valid_context(host_context) || target_thread_id == 0)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        const ControlLock lock(g_host.control_lock);
        const bool retrying = g_host.pending_op == PendingOp::Retarget && lease == g_host.pending_lease;
        if (g_host.pending_op != PendingOp::None && !retrying)
        {
            return DMK_WHEELHOST_ERR_PENDING;
        }
        if (g_host.stopping || !g_host.started)
        {
            return DMK_WHEELHOST_ERR_STATE;
        }
        if (g_host.lease == 0)
        {
            return DMK_WHEELHOST_ERR_NO_LEASE;
        }
        if (lease != g_host.lease)
        {
            return DMK_WHEELHOST_ERR_STALE;
        }

        settle_route_state();

        // Same-thread retarget of a live mount keeps the mount and its generation. Queue-wide admission needs no
        // republish for a window change on the same thread.
        if (g_host.hook != nullptr && g_host.target_thread_id == target_thread_id &&
            g_host.route_state == DMK_WHEELHOST_ROUTE_READY)
        {
            if (retrying)
            {
                if (!drain_admitted_phases())
                {
                    return DMK_WHEELHOST_ERR_DRAIN;
                }
                clear_pending();
            }
            return DMK_WHEELHOST_OK;
        }

        // Disable capture and consume, advance the epoch, and drain admitted decisions before route replacement.
        g_host.invalidate_capture();
        const auto fail_pending = [&](std::uint32_t state, int32_t status) noexcept -> int32_t
        {
            g_host.route_state = state;
            g_host.pending_op = PendingOp::Retarget;
            g_host.pending_lease = lease;
            return status;
        };
        if (!drain_admitted_phases())
        {
            const std::uint32_t state =
                g_host.hook != nullptr ? DMK_WHEELHOST_ROUTE_READY : DMK_WHEELHOST_ROUTE_RETRYABLE;
            return fail_pending(state, DMK_WHEELHOST_ERR_DRAIN);
        }

        // Remove the old hook before the new hook mounts. Hooks never overlap.
        if (g_host.hook != nullptr)
        {
            if (target_thread_exited())
            {
                retire_route_after_thread_exit();
            }
            else if (!remove_hook(g_host.hook))
            {
                return fail_pending(DMK_WHEELHOST_ROUTE_CLEANUP_BLOCKED, DMK_WHEELHOST_ERR_THREAD);
            }
            else
            {
                g_host.hook = nullptr;
                if (g_host.target_thread != nullptr)
                {
                    CloseHandle(g_host.target_thread);
                    g_host.target_thread = nullptr;
                }
                g_host.target_thread_id = 0;
            }
        }

        HANDLE new_thread = open_target_thread(target_thread_id);
        if (new_thread == nullptr)
        {
            return fail_pending(DMK_WHEELHOST_ROUTE_RETRYABLE, DMK_WHEELHOST_ERR_THREAD);
        }
        const HHOOK new_hook = mount_resident_hook(target_thread_id);
        if (new_hook == nullptr)
        {
            CloseHandle(new_thread);
            return fail_pending(DMK_WHEELHOST_ROUTE_RETRYABLE, DMK_WHEELHOST_ERR_THREAD);
        }

        g_host.hook = new_hook;
        g_host.target_thread = new_thread;
        g_host.target_thread_id = target_thread_id;
        g_host.mount_generation = next_nonzero(g_host.mount_generation, std::numeric_limits<std::uint64_t>::max());
        g_host.route_state = DMK_WHEELHOST_ROUTE_READY;
        clear_pending();
        return DMK_WHEELHOST_OK;
    }
} // namespace

int32_t DMK_WHEELHOST_CALL wheel_host_start(
    uint32_t target_thread_id,
    uint32_t requested_abi_version,
    uint32_t table_capacity,
    WheelHostTable *out_table
) noexcept
{
    if (out_table == nullptr)
    {
        return DMK_WHEELHOST_ERR_INVALID;
    }
    if (requested_abi_version != DMK_WHEELHOST_ABI_VERSION || table_capacity < sizeof(WheelHostTable))
    {
        return DMK_WHEELHOST_ERR_ABI;
    }

    const ControlLock lock(g_host.control_lock);
    if (g_host.started)
    {
        return DMK_WHEELHOST_ERR_STATE;
    }
    if (!pin_host_module())
    {
        return DMK_WHEELHOST_ERR_THREAD;
    }

    HANDLE target_thread = nullptr;
    HHOOK hook = nullptr;
    if (target_thread_id != 0)
    {
        target_thread = open_target_thread(target_thread_id);
        if (target_thread == nullptr)
        {
            return DMK_WHEELHOST_ERR_THREAD;
        }
        hook = mount_resident_hook(target_thread_id);
        if (hook == nullptr)
        {
            CloseHandle(target_thread);
            (void)stop_mount_thread();
            return DMK_WHEELHOST_ERR_THREAD;
        }
    }

    g_host.hook = hook;
    g_host.target_thread = target_thread;
    g_host.target_thread_id = hook != nullptr ? target_thread_id : 0;
    g_host.route_state = hook != nullptr ? DMK_WHEELHOST_ROUTE_READY : DMK_WHEELHOST_ROUTE_TARGET_WAIT;
    if (hook != nullptr)
    {
        g_host.mount_generation = next_nonzero(g_host.mount_generation, std::numeric_limits<std::uint64_t>::max());
    }
    g_host.started = true;
    g_host.stopping = false;
    g_host.lease = 0;
    g_host.owner = 0;
    g_host.generation = 0;
    clear_pending();
    g_host.invalidate_capture();
    g_host.identity_counter = next_nonzero(g_host.identity_counter, std::numeric_limits<std::uint64_t>::max());
    g_host.host_identity = g_host.identity_counter;

    WheelHostTable table{};
    table.struct_size = static_cast<std::uint32_t>(sizeof(WheelHostTable));
    table.abi_version = DMK_WHEELHOST_ABI_VERSION;
    table.capability_bits =
        DMK_WHEELHOST_CAP_VERTICAL | DMK_WHEELHOST_CAP_HORIZONTAL | DMK_WHEELHOST_CAP_CONSUME | DMK_WHEELHOST_CAP_ROUTE;
    table.host_identity = g_host.host_identity;
    table.host_context = &g_host;
    table.open_lease = &open_lease;
    table.publish_capture = &publish_capture;
    table.drain_counts = &drain_counts;
    table.close_lease = &close_lease;
    table.route_status = &route_status;
    table.retarget = &retarget;
    *out_table = table;
    return DMK_WHEELHOST_OK;
}

int32_t DMK_WHEELHOST_CALL wheel_host_stop(void) noexcept
{
    const ControlLock lock(g_host.control_lock);
    if (!g_host.started)
    {
        return DMK_WHEELHOST_ERR_STATE;
    }
    // Stop is the loader authority over a host it started. It retries its own pending Stop and supersedes a
    // pending Close, whose generation already asked to leave and can no longer be required to retry. A lease whose
    // holder still wants it stays BUSY, which includes a pending Retarget: that generation can still close it.
    if (g_host.pending_op != PendingOp::Stop && g_host.pending_op != PendingOp::Close && g_host.lease != 0)
    {
        // Busy without mutation: the lease keeps its owner, generation, token, route, and capture state.
        return DMK_WHEELHOST_ERR_BUSY;
    }

    if (!g_host.stopping)
    {
        g_host.stopping = true;
        g_host.invalidate_capture();
    }
    if (!drain_admitted_phases())
    {
        // The host stays started and disabled through the exact Stop retry.
        g_host.pending_op = PendingOp::Stop;
        return DMK_WHEELHOST_ERR_DRAIN;
    }
    if (g_host.hook != nullptr && !remove_hook(g_host.hook) && !target_thread_exited())
    {
        g_host.pending_op = PendingOp::Stop;
        return DMK_WHEELHOST_ERR_THREAD;
    }
    g_host.hook = nullptr;
    g_host.route_state = DMK_WHEELHOST_ROUTE_TARGET_WAIT;
    if (!stop_mount_thread())
    {
        g_host.pending_op = PendingOp::Stop;
        return DMK_WHEELHOST_ERR_THREAD;
    }

    if (g_host.target_thread != nullptr)
    {
        CloseHandle(g_host.target_thread);
        g_host.target_thread = nullptr;
    }
    g_host.target_thread_id = 0;
    g_host.route_state = DMK_WHEELHOST_ROUTE_TARGET_WAIT;
    g_host.lease = 0;
    g_host.owner = 0;
    g_host.generation = 0;
    clear_pending();
    g_host.started = false;
    g_host.stopping = false;
    return DMK_WHEELHOST_OK;
}

#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
extern "C" void DMK_WHEELHOST_CALL wheel_host_test_set_hook_probe(void(DMK_WHEELHOST_CALL *probe)(void)) noexcept
{
    g_hook_probe.store(probe, std::memory_order_release);
}

extern "C" void DMK_WHEELHOST_CALL wheel_host_test_set_finalize_probe(void(DMK_WHEELHOST_CALL *probe)(void)) noexcept
{
    g_finalize_probe.store(probe, std::memory_order_release);
}

extern "C" void DMK_WHEELHOST_CALL wheel_host_test_force_unhook_failure(uint32_t enabled) noexcept
{
    g_force_unhook_failure.store(enabled != 0, std::memory_order_release);
}

extern "C" void DMK_WHEELHOST_CALL wheel_host_test_set_drain_timeout(uint32_t timeout_ms) noexcept
{
    g_drain_timeout_override_ms.store(timeout_ms, std::memory_order_release);
}

extern "C" void DMK_WHEELHOST_CALL wheel_host_test_set_process_focus(int32_t focused) noexcept
{
    g_process_focus_override.store(focused, std::memory_order_release);
}

extern "C" void DMK_WHEELHOST_CALL wheel_host_test_snapshot(
    uint32_t *mounted_hooks,
    uint32_t *thread_handles,
    uint32_t *active_leases,
    uint64_t *mount_generation
) noexcept
{
    const ControlLock lock(g_host.control_lock);
    if (mounted_hooks != nullptr)
    {
        *mounted_hooks = g_host.hook != nullptr ? 1u : 0u;
    }
    if (thread_handles != nullptr)
    {
        *thread_handles = (g_host.target_thread != nullptr ? 1u : 0u) + (g_host.mount_thread != nullptr ? 1u : 0u);
    }
    if (active_leases != nullptr)
    {
        *active_leases = g_host.lease != 0 ? 1u : 0u;
    }
    if (mount_generation != nullptr)
    {
        *mount_generation = g_host.mount_generation;
    }
}
#endif
