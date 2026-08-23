/**
 * @file logic_callback_dll.cpp
 * @brief A Logic DLL that contributes only callables, so unmapping it is a real test of DetourModKit's teardown.
 * @details This translation unit does not link the DetourModKit archive. A second library instance could add process
 *          state and install-time module self-references unrelated to the property under test. The host owns the
 *          library, every Hook, every binding, and every config registration; this module owns only code the host asks
 *          the library to hold.
 *
 *          The callable factories return a functor with an observable nontrivial destructor. The erased invoker,
 *          manager, and target destructor are instantiated in this translation unit, so copying, invoking, or
 *          destroying the target reaches this module regardless of whether a standard-library implementation stores
 *          it inline or on the heap.
 */

#include "logic_dll_protocol.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <new>
#include <type_traits>

#include <windows.h>

namespace
{
    using logic_dll::Channel;
    using logic_dll::Counter;

    constexpr std::size_t COUNTER_COUNT = static_cast<std::size_t>(Counter::Count);
    constexpr std::size_t CHANNEL_COUNT = static_cast<std::size_t>(Channel::Count);

    std::atomic<std::uint64_t> s_counters[COUNTER_COUNT];

    /// One park per channel. `entered` lets the host observe that a body is inside; `release` lets it out again.
    struct Park
    {
        std::atomic<bool> armed{false};
        HANDLE entered = nullptr;
        HANDLE release = nullptr;
    };

    Park s_parks[CHANNEL_COUNT];
    std::once_flag s_park_init;
    std::atomic<bool> s_fail_next_callable_factory{false};

    /// The trampoline the inline detour chains to. The host publishes it after the hook is created, before arming.
    std::atomic<logic_dll::TargetFn> s_inline_original{nullptr};

    void bump(Counter counter) noexcept
    {
        s_counters[static_cast<std::size_t>(counter)].fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] bool channel_in_range(int channel) noexcept
    {
        return channel >= 0 && static_cast<std::size_t>(channel) < CHANNEL_COUNT;
    }

    void provision_parks() noexcept
    {
        try
        {
            std::call_once(
                s_park_init,
                []() noexcept
                {
                    for (Park &park : s_parks)
                    {
                        // Manual reset on both: the host may observe entry after the body already signalled,
                        // and one release must let every waiter on that channel out rather than just the
                        // first.
                        park.entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
                        park.release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
                    }
                }
            );
        }
        catch (...)
        {
            // A missing park makes the host report setup failure instead of crossing the C ABI with an exception.
        }
    }

    /**
     * @brief Signals entry and waits for the host's release when @p channel is armed.
     * @details The wait is bounded so a proof whose release never arrives exits through its own diagnostic rather
     *          than wedging until the CTest timeout kills it with no output.
     */
    void park_if_armed(Channel channel) noexcept
    {
        Park &park = s_parks[static_cast<std::size_t>(channel)];
        if (!park.armed.load(std::memory_order_acquire) || park.entered == nullptr || park.release == nullptr)
        {
            return;
        }

        ::SetEvent(park.entered);
        (void)::WaitForSingleObject(park.release, logic_dll::PARK_WAIT_LIMIT_MS);
    }

    /**
     * @struct CallableProbe
     * @brief A callable whose copy and destroy paths are emitted here, so the library holding one holds DLL code.
     * @details Every constructor tallies a construction and the destructor tallies a destruction, so the host can
     *          read how many live copies the library still owns. The counter pair, not a boolean, is what makes a
     *          parked drain distinguishable from a completed one.
     */
    template <Counter INVOKED, Channel CHANNEL> struct CallableProbe
    {
        CallableProbe() noexcept { bump(Counter::CallableConstructed); }
        CallableProbe(const CallableProbe &) noexcept { bump(Counter::CallableConstructed); }
        CallableProbe(CallableProbe &&) noexcept { bump(Counter::CallableConstructed); }
        CallableProbe &operator=(const CallableProbe &) = delete;
        CallableProbe &operator=(CallableProbe &&) = delete;
        ~CallableProbe() noexcept { bump(Counter::CallableDestroyed); }

        void run() const noexcept
        {
            bump(INVOKED);
            park_if_armed(CHANNEL);
        }
    };

    struct PressProbe : CallableProbe<Counter::PressInvoked, Channel::Press>
    {
        void operator()() const noexcept { run(); }
    };

    struct HoldProbe : CallableProbe<Counter::HoldInvoked, Channel::Hold>
    {
        void operator()(bool) const noexcept { run(); }
    };

    struct SetterProbe : CallableProbe<Counter::SetterInvoked, Channel::Setter>
    {
        void operator()(int) const noexcept { run(); }
    };

    struct ReloadProbe : CallableProbe<Counter::ReloadInvoked, Channel::Reload>
    {
        void operator()(bool) const noexcept { run(); }
    };

    template <class Signature, class Probe> void assign_callable(std::function<Signature> *out) noexcept
    {
        if (out == nullptr)
        {
            return;
        }
        try
        {
            if (s_fail_next_callable_factory.exchange(false, std::memory_order_acq_rel))
            {
                throw std::bad_alloc{};
            }
            *out = Probe{};
        }
        catch (...)
        {
            // The host treats an empty callable as setup failure.
            *out = nullptr;
        }
    }
} // namespace

extern "C"
{
    /// The unmap oracle. Its address outlives the module handle, which the host cannot use after FreeLibrary.
    __declspec(dllexport) extern const unsigned char dmk_logic_marker[16] =
        {0x2F, 0x91, 0xC4, 0x0B, 0x6D, 0xA8, 0x13, 0x57, 0xE2, 0x74, 0x38, 0xBC, 0x05, 0x9A, 0xF6, 0x41};

    __declspec(dllexport) void dmk_logic_reset() noexcept
    {
        provision_parks();
        for (std::atomic<std::uint64_t> &counter : s_counters)
        {
            counter.store(0, std::memory_order_relaxed);
        }
        for (Park &park : s_parks)
        {
            park.armed.store(false, std::memory_order_release);
            if (park.entered != nullptr)
            {
                ::ResetEvent(park.entered);
            }
            if (park.release != nullptr)
            {
                ::ResetEvent(park.release);
            }
        }
        s_inline_original.store(nullptr, std::memory_order_release);
        s_fail_next_callable_factory.store(false, std::memory_order_release);
    }

    __declspec(dllexport) std::uint64_t dmk_logic_counter(int counter) noexcept
    {
        if (counter < 0 || static_cast<std::size_t>(counter) >= COUNTER_COUNT)
        {
            return 0;
        }
        return s_counters[static_cast<std::size_t>(counter)].load(std::memory_order_relaxed);
    }

    __declspec(dllexport) void dmk_logic_arm_park(int channel) noexcept
    {
        if (!channel_in_range(channel))
        {
            return;
        }
        provision_parks();
        Park &park = s_parks[static_cast<std::size_t>(channel)];
        ::ResetEvent(park.entered);
        ::ResetEvent(park.release);
        park.armed.store(true, std::memory_order_release);
    }

    __declspec(dllexport) void dmk_logic_release_park(int channel) noexcept
    {
        if (!channel_in_range(channel))
        {
            return;
        }
        Park &park = s_parks[static_cast<std::size_t>(channel)];
        // Disarm before releasing so a body that has not entered yet runs straight through instead of parking behind
        // a release the host has already spent.
        park.armed.store(false, std::memory_order_release);
        if (park.release != nullptr)
        {
            ::SetEvent(park.release);
        }
    }

    __declspec(dllexport) int dmk_logic_wait_parked(int channel, std::uint32_t timeout_ms) noexcept
    {
        if (!channel_in_range(channel))
        {
            return 0;
        }
        Park &park = s_parks[static_cast<std::size_t>(channel)];
        if (park.entered == nullptr)
        {
            return 0;
        }
        return ::WaitForSingleObject(park.entered, timeout_ms) == WAIT_OBJECT_0 ? 1 : 0;
    }

    __declspec(dllexport) void dmk_logic_make_press_callable(std::function<void()> *out) noexcept
    {
        assign_callable<void(), PressProbe>(out);
    }

    __declspec(dllexport) void dmk_logic_make_hold_callable(std::function<void(bool)> *out) noexcept
    {
        assign_callable<void(bool), HoldProbe>(out);
    }

    __declspec(dllexport) void dmk_logic_make_setter_callable(std::function<void(int)> *out) noexcept
    {
        assign_callable<void(int), SetterProbe>(out);
    }

    __declspec(dllexport) void dmk_logic_make_reload_callable(std::function<void(bool)> *out) noexcept
    {
        assign_callable<void(bool), ReloadProbe>(out);
    }

    __declspec(dllexport) void dmk_logic_fail_next_callable_factory() noexcept
    {
        s_fail_next_callable_factory.store(true, std::memory_order_release);
    }

    __declspec(dllexport) void dmk_logic_set_inline_original(logic_dll::TargetFn original) noexcept
    {
        s_inline_original.store(original, std::memory_order_release);
    }

    /// Tallies and parks. It never touches the context, which is why this module needs no DetourModKit definition.
    __declspec(dllexport) void dmk_logic_mid_detour(DetourModKit::hook::MidContext &) noexcept
    {
        bump(Counter::MidInvoked);
        park_if_armed(Channel::Mid);
    }

    __declspec(dllexport) int dmk_logic_inline_detour(int base, int modifier) noexcept
    {
        bump(Counter::InlineInvoked);
        park_if_armed(Channel::Inline);

        const logic_dll::TargetFn original = s_inline_original.load(std::memory_order_acquire);
        return original != nullptr ? original(base, modifier) : logic_dll::UNCHAINED_RESULT;
    }
}

static_assert(std::is_same_v<decltype(&dmk_logic_reset), logic_dll::ResetFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_counter), logic_dll::CounterFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_arm_park), logic_dll::ArmParkFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_release_park), logic_dll::ReleaseParkFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_wait_parked), logic_dll::WaitParkedFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_make_press_callable), logic_dll::MakePressCallableFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_make_hold_callable), logic_dll::MakeHoldCallableFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_make_setter_callable), logic_dll::MakeSetterCallableFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_make_reload_callable), logic_dll::MakeReloadCallableFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_fail_next_callable_factory), logic_dll::FailNextCallableFactoryFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_set_inline_original), logic_dll::SetInlineOriginalFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_mid_detour), logic_dll::MidDetourFn>);
static_assert(std::is_same_v<decltype(&dmk_logic_inline_detour), logic_dll::InlineDetourFn>);

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}
