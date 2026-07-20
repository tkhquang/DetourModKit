// Both diagnostic dispatchers are reachable from code that runs after ordinary static teardown has begun: a hook owned
// by a namespace-scope object emits a Removed transition from its destructor, and a scan driven from such a destructor
// or from a still-running pinned thread emits a scanner fault. Cross-TU static destruction order is unspecified, so a
// Meyers-singleton dispatcher can be destroyed first and the late emit would then dispatch through a destroyed mutex
// and subscriber list -- undefined behaviour no try/catch can contain.
//
// The oracle is delivery, not survival: a destroyed dispatcher has already released its subscriber snapshot, so the
// late emit reaches no handler and the exit code says so even in a build where touching the freed storage happens not
// to fault.
//
// The two arms rest on different orderings. scanner_faults() has no static-init toucher anywhere in the library, so
// main's subscribe is its first touch: its would-be destructor would be registered after s_late_emitter's and would
// therefore run first, which makes that arm a strict ordering proof. hook_lifecycle() is first touched by the
// library's own permanent HookPopulation subscription during diagnostics.cpp's dynamic initialization, so this
// translation unit cannot order itself against it; that arm asserts only that an emit issued from a destructor
// running at static-teardown time is still delivered.

#include "DetourModKit/diagnostics.hpp"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>

namespace
{
    using DetourModKit::diagnostics::HookKind;
    using DetourModKit::diagnostics::HookLifecycleEvent;
    using DetourModKit::diagnostics::HookTransition;
    using DetourModKit::diagnostics::ScannerFaultEvent;

    // Constant-initialized and trivially destructible, so the counters themselves are alive for the late emit.
    int s_scanner_deliveries{0};
    int s_hook_deliveries{0};

    alignas(DetourModKit::Subscription) std::byte s_scanner_subscription_storage[sizeof(DetourModKit::Subscription)];
    alignas(DetourModKit::Subscription) std::byte s_hook_subscription_storage[sizeof(DetourModKit::Subscription)];

    /**
     * @brief Emits into both dispatchers from static-teardown time.
     * @details The user-provided constructor precludes constant initialization, so the namespace-scope instance is
     *          dynamically initialized and its destructor is registered during this translation unit's initialization,
     *          ahead of any function-local static main goes on to construct.
     */
    struct LateEmitter
    {
        LateEmitter() noexcept {}

        ~LateEmitter() noexcept
        {
            const int scanner_before = s_scanner_deliveries;
            const int hook_before = s_hook_deliveries;

            DetourModKit::diagnostics::scanner_faults().emit_safe(
                ScannerFaultEvent{.faulted_regions = 7, .window_low = 0x1000, .window_high = 0x2000});
            DetourModKit::diagnostics::hook_lifecycle().emit_safe(
                HookLifecycleEvent{.name = "late_teardown",
                                   .ledger_id = 99,
                                   .kind = HookKind::Inline,
                                   .transition = HookTransition::Removed});

            if (s_scanner_deliveries != scanner_before + 1)
            {
                std::fputs("FAIL: the late scanner-fault emit reached no subscriber; the dispatcher did not survive "
                           "static teardown\n",
                           stderr);
                std::_Exit(30);
            }
            if (s_hook_deliveries != hook_before + 1)
            {
                std::fputs("FAIL: the late hook-lifecycle emit reached no subscriber; the dispatcher did not survive "
                           "static teardown\n",
                           stderr);
                std::_Exit(31);
            }
            std::fputs("diagnostics-late-emitter: both late emits were delivered after static teardown began\n",
                       stdout);
        }
    };

    LateEmitter s_late_emitter;
} // namespace

int main()
{
    // Subscribing is the first touch of scanner_faults(), so its storage is constructed here, after s_late_emitter was
    // initialized, which is what puts its teardown ahead of that destructor.
    //
    // The subscriptions are deliberately never destroyed: this proof isolates the late EMIT path, and a Subscription
    // destroyed at teardown would retire the handler before the late emit could observe it.
    auto *const scanner_subscription = ::new (static_cast<void *>(s_scanner_subscription_storage))
        DetourModKit::Subscription(DetourModKit::diagnostics::scanner_faults().subscribe(
            [](const ScannerFaultEvent &) noexcept { ++s_scanner_deliveries; }));
    auto *const hook_subscription = ::new (static_cast<void *>(s_hook_subscription_storage))
        DetourModKit::Subscription(DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [](const HookLifecycleEvent &) noexcept { ++s_hook_deliveries; }));
    if (!scanner_subscription->active() || !hook_subscription->active())
    {
        std::fputs("FAIL: diagnostics subscription setup failed\n", stderr);
        return 1;
    }

    // Live control: without it, a subscription that never took would make the teardown check fail for the wrong
    // reason, and a delivery failure at exit could not be attributed to teardown order.
    DetourModKit::diagnostics::scanner_faults().emit_safe(
        ScannerFaultEvent{.faulted_regions = 1, .window_low = 0, .window_high = 0x10});
    DetourModKit::diagnostics::hook_lifecycle().emit_safe(HookLifecycleEvent{
        .name = "live", .ledger_id = 1, .kind = HookKind::Inline, .transition = HookTransition::Created});

    if (s_scanner_deliveries != 1)
    {
        std::fputs("FAIL: the live scanner-fault emit was not delivered\n", stderr);
        return 2;
    }
    if (s_hook_deliveries != 1)
    {
        std::fputs("FAIL: the live hook-lifecycle emit was not delivered\n", stderr);
        return 3;
    }

    std::fputs("diagnostics-late-emitter: live emits delivered; the verdict is the exit code after static teardown\n",
               stdout);
    return 0;
}
