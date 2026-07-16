// A namespace-scope hook owner registers its destructor before the ledger and the backend allocator hold exist: both
// are constructed lazily inside the first hook creation, which this host performs from main(). By reverse order of
// completed construction they would therefore be destroyed BEFORE the owner, so a hook torn down from that owner's
// destructor reaches them after they died unless their storage outlives the process. This host populates the owner in
// main(), then verifies its destructor can still restore the target and emit the removal event. The exit code is the
// behavioral oracle.

#include "DetourModKit/address.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace
{
#if defined(_MSC_VER)
#define DMK_PROOF_NOINLINE __declspec(noinline)
#else
#define DMK_PROOF_NOINLINE __attribute__((noinline))
#endif

    DMK_PROOF_NOINLINE int static_order_target(int x)
    {
        volatile int result = x;
        return result;
    }

    int static_order_detour(int x)
    {
        return x + 7;
    }

    /// Calls through a volatile indirection so the optimizer cannot fold the call past the patched entry.
    int call_unfolded(int (*function)(int), int value)
    {
        int (*const volatile indirect)(int) = function;
        return indirect(value);
    }

    bool s_armed = false;
    // Set when the teardown emits its Removed transition. ~Hook emits AFTER restoring, through
    // diagnostics::hook_lifecycle() and into hook_population(). Restoring correctly does not prove that emit path
    // stayed valid, so it gets its own witness.
    bool s_removed_delivered = false;

    /**
     * @brief Owns the late hook and validates its teardown from the same namespace-scope destructor.
     * @details Keeping ownership and verification in one object avoids relying on cross-object destruction order.
     */
    class StaticOwner
    {
    public:
        StaticOwner() = default;
        ~StaticOwner() noexcept
        {
            if (!s_armed)
            {
                // The trap was never set: a passing run would be vacuous.
                std::fputs("FAIL: hook was never armed; the static-order trap did not arm\n", stderr);
                std::fflush(stderr);
                std::_Exit(5);
            }
            // The teardown under test: ~Hook reaches the ledger and the backend allocator hold, both constructed after
            // this object registered, plus the diagnostics singletons, whose order against it is only link order.
            m_stack.clear();

            if (call_unfolded(&static_order_target, 5) != 5)
            {
                std::fputs("FAIL: static-order teardown did not restore the target\n", stderr);
                std::fflush(stderr);
                std::_Exit(6);
            }
            if (!s_removed_delivered)
            {
                std::fputs("FAIL: the late teardown's Removed event never reached the subscriber\n", stderr);
                std::fflush(stderr);
                std::_Exit(7);
            }
            std::fputs("OK: static-order hook teardown restored the target and emitted\n", stdout);
            std::fflush(stdout);
        }

        StaticOwner(const StaticOwner &) = delete;
        StaticOwner &operator=(const StaticOwner &) = delete;
        StaticOwner(StaticOwner &&) = delete;
        StaticOwner &operator=(StaticOwner &&) = delete;

        void set_subscription(DetourModKit::Subscription subscription) noexcept
        {
            m_subscription = std::move(subscription);
        }

        void push(DetourModKit::hook::Hook hook) { m_stack.push(std::move(hook)); }

    private:
        DetourModKit::hook::HookStack m_stack;
        DetourModKit::Subscription m_subscription;
    };

    StaticOwner s_owner;
} // namespace

int main()
{
    using namespace DetourModKit;

    if (call_unfolded(&static_order_target, 5) != 5)
    {
        std::fputs("FAIL: target is not pristine before install\n", stderr);
        return 2;
    }

    // The subscription is what makes the Removed witness below observable. It does NOT order the dispatcher: the
    // diagnostics singletons are constructed by that TU's own pre-main forcing initializer, so their position relative
    // to s_owner is link order, not something this host controls. Only the ledger and the allocator hold are provably
    // constructed after s_owner registers, and they are what the exit-6 oracle pins.
    s_owner.set_subscription(diagnostics::hook_lifecycle().subscribe(
        [](const diagnostics::HookLifecycleEvent &event)
        {
            if (event.transition == diagnostics::HookTransition::Removed)
            {
                s_removed_delivered = true;
            }
        }));

    // This first creation is what constructs the ledger and the allocator hold, after s_owner registered.
    Result<hook::Hook> created =
        hook::inline_at(hook::InlineRequest{.name = "StaticOrder",
                                            .target = Address{reinterpret_cast<std::uintptr_t>(&static_order_target)}},
                        &static_order_detour);
    if (!created.has_value())
    {
        std::fputs("FAIL: inline_at failed\n", stderr);
        return 3;
    }
    if (!created->enable().has_value())
    {
        std::fputs("FAIL: enable failed\n", stderr);
        return 4;
    }
    if (call_unfolded(&static_order_target, 5) != 12)
    {
        std::fputs("FAIL: detour is not reachable after enable\n", stderr);
        return 4;
    }

    s_owner.push(std::move(*created));
    s_armed = true;
    // The process exits successfully only if ~s_owner completes every teardown assertion and returns.
    return 0;
}
