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
    constexpr int CAPTURE_EPOCH_SHIFT = 1;
    constexpr int COUNT_BITS = 11;
    constexpr std::uint64_t COUNT_MASK = (std::uint64_t{1} << COUNT_BITS) - 1u;
    constexpr std::uint32_t MAX_COUNT = 1024;
    constexpr int REMAINDER_BITS = 8;
    constexpr std::uint64_t REMAINDER_MASK = (std::uint64_t{1} << REMAINDER_BITS) - 1u;
    constexpr std::uint64_t REMAINDER_OWNED_BIT = std::uint64_t{1} << REMAINDER_BITS;
    constexpr int REMAINDER_EPOCH_SHIFT = REMAINDER_BITS + 1;
    constexpr int CONSUME_EPOCH_SHIFT = 4;
    constexpr std::uint32_t CONSUME_MASK = (1u << DMK_WHEEL_DIRECTIONS) - 1u;
    constexpr std::uint64_t MAX_EPOCH = std::numeric_limits<std::uint64_t>::max() >> COUNT_BITS;

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

    [[nodiscard]] constexpr std::uint64_t pack_capture(std::uint64_t epoch, bool enabled) noexcept
    {
        return (epoch << CAPTURE_EPOCH_SHIFT) | (enabled ? CAPTURE_ENABLED_BIT : 0u);
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
        const auto encoded = static_cast<std::uint64_t>(remainder + WHEEL_DELTA);
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

    struct HostState
    {
        SRWLOCK control_lock = SRWLOCK_INIT;
        bool started = false;
        bool stopping = false;
        HHOOK hook = nullptr;
        HANDLE target_thread = nullptr;
        std::uint32_t target_thread_id = 0;
        std::uint64_t mount_generation = 0;
        std::uint64_t host_identity = 0;
        std::uint64_t lease = 0;
        std::uint64_t owner = 0;
        std::uint64_t generation = 0;
        std::uint64_t epoch = 1;
        std::uint64_t lease_counter = 0;
        std::uint64_t identity_counter = 0;
        std::atomic<std::uint64_t> capture_state{pack_capture(1, false)};
        std::atomic<std::uint64_t> consume_state{pack_consume(1, 0)};
        std::atomic<std::uint64_t> consume_deadline_ms{0};
        std::array<std::atomic<std::uint64_t>, 2> remainder{pack_remainder(1, false, 0), pack_remainder(1, false, 0)};
        std::array<std::atomic<std::uint64_t>, DMK_WHEEL_DIRECTIONS> counts{pack_count(1, 0), pack_count(1, 0),
                                                                            pack_count(1, 0), pack_count(1, 0)};

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
            capture_state.store(pack_capture(epoch, false), std::memory_order_release);
            consume_state.store(pack_consume(epoch, 0), std::memory_order_release);
            consume_deadline_ms.store(0, std::memory_order_relaxed);
            reset_data_plane(epoch);
        }
    };

    constinit HostState g_host;

#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
    using HookProbe = void(DMK_WHEELHOST_CALL *)(void);
    std::atomic<HookProbe> g_hook_probe{nullptr};
    std::atomic<bool> g_force_unhook_failure{false};
#endif

    [[nodiscard]] bool valid_context(void *host_context) noexcept
    {
        return host_context == &g_host;
    }

    [[nodiscard]] bool is_wheel(UINT message) noexcept
    {
        return message == WM_MOUSEWHEEL || message == WM_MOUSEHWHEEL;
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

        const MSG original = *message;
        const std::uint64_t capture = g_host.capture_state.load(std::memory_order_acquire);
        if ((capture & CAPTURE_ENABLED_BIT) == 0)
        {
            return CallNextHookEx(nullptr, code, wparam, lparam);
        }

        const bool horizontal = original.message == WM_MOUSEHWHEEL;
        const int delta = static_cast<short>(HIWORD(original.wParam));
        if (delta == 0)
        {
            return CallNextHookEx(nullptr, code, wparam, lparam);
        }

        const std::uint32_t direction_bit = horizontal ? (delta > 0 ? DMK_WHEEL_CONSUME_RIGHT : DMK_WHEEL_CONSUME_LEFT)
                                                       : (delta > 0 ? DMK_WHEEL_CONSUME_UP : DMK_WHEEL_CONSUME_DOWN);
        const std::uint64_t epoch = capture_epoch(capture);
        const bool owned = direction_consumed(epoch, direction_bit);
        if (wparam != PM_REMOVE)
        {
            return CallNextHookEx(nullptr, code, wparam, lparam);
        }

#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
        if (const HookProbe probe = g_hook_probe.load(std::memory_order_acquire); probe != nullptr)
        {
            probe();
        }
#endif

        const int notches = fold_axis(g_host.remainder[horizontal ? 1u : 0u], epoch, owned, delta);
        count_direction(horizontal, epoch, notches);
        if (!owned)
        {
            return CallNextHookEx(nullptr, code, wparam, lparam);
        }

        message->message = WM_NULL;
        message->wParam = 0;
        message->lParam = 0;
        const LRESULT result = CallNextHookEx(nullptr, code, wparam, lparam);
        message->message = WM_NULL;
        message->wParam = 0;
        message->lParam = 0;
        return result;
    }

    int32_t DMK_WHEELHOST_CALL open_lease(void *host_context, std::uint64_t owner, std::uint64_t generation,
                                          DmkWheelLease *out_lease) noexcept
    {
        if (!valid_context(host_context) || out_lease == nullptr || owner == 0 || generation == 0)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        *out_lease = 0;
        const ControlLock lock(g_host.control_lock);
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

    int32_t DMK_WHEELHOST_CALL publish_capture(void *host_context, DmkWheelLease lease, std::uint32_t capture_enabled,
                                               std::uint32_t consume_mask, std::uint32_t ttl_ms) noexcept
    {
        if (!valid_context(host_context) || (capture_enabled & ~DMK_WHEEL_CAPTURE_ENABLED) != 0 ||
            (consume_mask & ~CONSUME_MASK) != 0)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        const ControlLock lock(g_host.control_lock);
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
            g_host.consume_deadline_ms.store(now > maximum - ttl_ms ? maximum : now + ttl_ms,
                                             std::memory_order_relaxed);
        }
        else
        {
            g_host.consume_deadline_ms.store(0, std::memory_order_relaxed);
        }
        g_host.consume_state.store(pack_consume(g_host.epoch, consume_active ? consume_mask : 0u),
                                   std::memory_order_release);
        g_host.capture_state.store(pack_capture(g_host.epoch, (capture_enabled & DMK_WHEEL_CAPTURE_ENABLED) != 0),
                                   std::memory_order_release);
        return DMK_WHEELHOST_OK;
    }

    int32_t DMK_WHEELHOST_CALL drain_counts(void *host_context, DmkWheelLease lease,
                                            std::uint32_t out_counts[DMK_WHEEL_DIRECTIONS]) noexcept
    {
        if (!valid_context(host_context) || out_counts == nullptr)
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        const ControlLock lock(g_host.control_lock);
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

    int32_t DMK_WHEELHOST_CALL close_lease(void *host_context, DmkWheelLease lease, std::uint64_t owner,
                                           std::uint64_t generation) noexcept
    {
        if (!valid_context(host_context))
        {
            return DMK_WHEELHOST_ERR_INVALID;
        }
        const ControlLock lock(g_host.control_lock);
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
        g_host.lease = 0;
        g_host.owner = 0;
        g_host.generation = 0;
        return DMK_WHEELHOST_OK;
    }

    [[nodiscard]] bool pin_host_module() noexcept
    {
        HMODULE module = nullptr;
        return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                                  reinterpret_cast<LPCWSTR>(&resident_hook), &module) != 0;
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
} // namespace

int32_t DMK_WHEELHOST_CALL DmkWheelHost_Start(uint32_t target_thread_id, uint32_t requested_abi_version,
                                              uint32_t table_capacity, DmkWheelHostTable *out_table) noexcept
{
    if (out_table == nullptr || target_thread_id == 0)
    {
        return DMK_WHEELHOST_ERR_INVALID;
    }
    if (requested_abi_version != DMK_WHEELHOST_ABI_VERSION || table_capacity < sizeof(DmkWheelHostTable))
    {
        return DMK_WHEELHOST_ERR_ABI;
    }

    const ControlLock lock(g_host.control_lock);
    if (g_host.started)
    {
        return DMK_WHEELHOST_ERR_STATE;
    }

    HANDLE target_thread = open_target_thread(target_thread_id);
    if (target_thread == nullptr)
    {
        return DMK_WHEELHOST_ERR_THREAD;
    }
    if (!pin_host_module())
    {
        CloseHandle(target_thread);
        return DMK_WHEELHOST_ERR_THREAD;
    }

    const HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, &resident_hook, nullptr, target_thread_id);
    if (hook == nullptr)
    {
        CloseHandle(target_thread);
        return DMK_WHEELHOST_ERR_THREAD;
    }

    g_host.hook = hook;
    g_host.target_thread = target_thread;
    g_host.target_thread_id = target_thread_id;
    g_host.mount_generation = next_nonzero(g_host.mount_generation, std::numeric_limits<std::uint64_t>::max());
    g_host.started = true;
    g_host.stopping = false;
    g_host.lease = 0;
    g_host.owner = 0;
    g_host.generation = 0;
    g_host.invalidate_capture();
    g_host.identity_counter = next_nonzero(g_host.identity_counter, std::numeric_limits<std::uint64_t>::max());
    g_host.host_identity = g_host.identity_counter;

    DmkWheelHostTable table{};
    table.struct_size = static_cast<std::uint32_t>(sizeof(DmkWheelHostTable));
    table.abi_version = DMK_WHEELHOST_ABI_VERSION;
    table.capability_bits = DMK_WHEELHOST_CAP_VERTICAL | DMK_WHEELHOST_CAP_HORIZONTAL | DMK_WHEELHOST_CAP_CONSUME;
    table.host_identity = g_host.host_identity;
    table.host_context = &g_host;
    table.open_lease = &open_lease;
    table.publish_capture = &publish_capture;
    table.drain_counts = &drain_counts;
    table.close_lease = &close_lease;
    *out_table = table;
    return DMK_WHEELHOST_OK;
}

int32_t DMK_WHEELHOST_CALL DmkWheelHost_Stop(void) noexcept
{
    const ControlLock lock(g_host.control_lock);
    if (!g_host.started)
    {
        return DMK_WHEELHOST_ERR_STATE;
    }

    if (!g_host.stopping)
    {
        g_host.stopping = true;
        g_host.invalidate_capture();
    }
    if (g_host.hook != nullptr && !remove_hook(g_host.hook) &&
        WaitForSingleObject(g_host.target_thread, 0) != WAIT_OBJECT_0)
    {
        return DMK_WHEELHOST_ERR_THREAD;
    }

    g_host.hook = nullptr;
    if (g_host.target_thread != nullptr)
    {
        CloseHandle(g_host.target_thread);
        g_host.target_thread = nullptr;
    }
    g_host.target_thread_id = 0;
    g_host.lease = 0;
    g_host.owner = 0;
    g_host.generation = 0;
    g_host.started = false;
    g_host.stopping = false;
    return DMK_WHEELHOST_OK;
}

#if defined(DMK_WHEELHOST_ENABLE_TEST_SEAMS)
extern "C" void DMK_WHEELHOST_CALL DmkWheelHost_TestSetHookProbe(void(DMK_WHEELHOST_CALL *probe)(void)) noexcept
{
    g_hook_probe.store(probe, std::memory_order_release);
}

extern "C" void DMK_WHEELHOST_CALL DmkWheelHost_TestForceUnhookFailure(uint32_t enabled) noexcept
{
    g_force_unhook_failure.store(enabled != 0, std::memory_order_release);
}

extern "C" void DMK_WHEELHOST_CALL DmkWheelHost_TestSnapshot(uint32_t *mounted_hooks, uint32_t *thread_handles,
                                                             uint32_t *active_leases,
                                                             uint64_t *mount_generation) noexcept
{
    const ControlLock lock(g_host.control_lock);
    if (mounted_hooks != nullptr)
    {
        *mounted_hooks = g_host.hook != nullptr ? 1u : 0u;
    }
    if (thread_handles != nullptr)
    {
        *thread_handles = g_host.target_thread != nullptr ? 1u : 0u;
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
