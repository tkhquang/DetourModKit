// A namespace-scope VmtHook owner registers before main constructs the process VMT object gate.
// Reverse destruction runs any gate destructor before the owner.
// The owner must lock the gate, restore the object vptr, and emit the removal event (`[B-47]`).
// The exit code is the behavioral oracle.

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <utility>

#if defined(_MSC_VER)
#define DMK_PROOF_NOINLINE __declspec(noinline)
#else
#define DMK_PROOF_NOINLINE __attribute__((noinline))
#endif

// The seed type keeps external linkage and dispatches through an out-of-line helper. An internal-linkage hierarchy
// with one implementation lets a Release build devirtualize the call, which never reads the cloned slot and makes the
// proof vacuous. tests/test_hook.cpp uses this same shape for the same reason.
class LateInterface
{
public:
    virtual ~LateInterface() = default;
    virtual int transform(int x) = 0;
};

class LateTarget : public LateInterface
{
public:
    int transform(int x) override { return x * 2; }
};

DMK_PROOF_NOINLINE int call_unfolded(LateInterface *object, int value)
{
    return object->transform(value);
}

namespace
{
    // The vtable index counts virtual functions only.
    // Itanium (MinGW) emits two destructor slots before the first declared method. MSVC emits one.
#if defined(_MSC_VER)
    constexpr std::size_t LATE_TRANSFORM_INDEX = 1;
#else
    constexpr std::size_t LATE_TRANSFORM_INDEX = 2;
#endif

    constexpr int LATE_INPUT = 5;
    constexpr int LATE_ORIGINAL_RESULT = LATE_INPUT * 2;
    constexpr int LATE_DETOUR_RESULT = 0x5EED;

    int late_transform_detour(void *, int)
    {
        return LATE_DETOUR_RESULT;
    }

    bool s_hooked = false;
    // The removal event sets this witness. A restored vptr alone does not prove that the emit path remained valid.
    bool s_removed_delivered = false;

    [[nodiscard]] std::uintptr_t read_object_vptr(const LateTarget &object) noexcept
    {
        std::uintptr_t value{};
        std::memcpy(&value, std::addressof(object), sizeof(value));
        return value;
    }

    /**
     * @brief Owns and verifies the late VMT hook.
     * @details One owner controls lifetime and verification. Cross-object destruction
     *          order cannot affect the proof.
     */
    class StaticOwner
    {
    public:
        StaticOwner() = default;
        ~StaticOwner() noexcept
        {
            if (!s_hooked)
            {
                std::fputs("FAIL: the late-owner trap did not arm a VMT hook.\n", stderr);
                std::fflush(stderr);
                std::_Exit(5);
            }
            namespace diag = DetourModKit::diagnostics;
            const std::size_t leaks_before = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);

            // The VmtHook destructor locks the process gate that main constructed after this owner.
            // It also reaches the ledger and diagnostics dispatcher.
            m_hook.reset();

            const std::uintptr_t restored = read_object_vptr(*m_object);
            if (restored != m_original_vptr)
            {
                std::fputs("FAIL: late VMT teardown left the object on the clone\n", stderr);
                std::fflush(stderr);
                std::_Exit(6);
            }
            if (call_unfolded(m_object.get(), LATE_INPUT) != LATE_ORIGINAL_RESULT)
            {
                std::fputs("FAIL: late VMT teardown left the detour reachable\n", stderr);
                std::fflush(stderr);
                std::_Exit(7);
            }
            const std::size_t leaks_after = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);
            if (leaks_after != leaks_before)
            {
                std::fprintf(stderr,
                             "FAIL: late VMT teardown booked %zu intentional leak(s), expected a clean restore\n",
                             leaks_after - leaks_before);
                std::fflush(stderr);
                std::_Exit(8);
            }
            if (!s_removed_delivered)
            {
                std::fputs("FAIL: the late VMT teardown's Removed event never reached the subscriber\n", stderr);
                std::fflush(stderr);
                std::_Exit(9);
            }
            std::fputs("OK: late VMT teardown took the gate, restored the vptr, and emitted the removal event.\n",
                       stdout);
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

        LateTarget *adopt_object(std::unique_ptr<LateTarget> object) noexcept
        {
            m_object = std::move(object);
            m_original_vptr = read_object_vptr(*m_object);
            return m_object.get();
        }

        void adopt_hook(DetourModKit::hook::VmtHook hook) noexcept { m_hook.emplace(std::move(hook)); }

    private:
        std::unique_ptr<LateTarget> m_object;
        std::optional<DetourModKit::hook::VmtHook> m_hook;
        std::uintptr_t m_original_vptr{0};
        DetourModKit::Subscription m_subscription;
    };

    StaticOwner s_owner;
} // namespace

int main()
{
    using namespace DetourModKit;

    LateTarget *const object = s_owner.adopt_object(std::make_unique<LateTarget>());
    if (call_unfolded(object, LATE_INPUT) != LATE_ORIGINAL_RESULT)
    {
        std::fputs("FAIL: the object is not pristine before the clone\n", stderr);
        return 2;
    }

    s_owner.set_subscription(diagnostics::hook_lifecycle().subscribe(
        [](const diagnostics::HookLifecycleEvent &event)
        {
            if (event.transition == diagnostics::HookTransition::Removed)
            {
                s_removed_delivered = true;
            }
        }));

    // This first VMT operation is what constructs the process object gate, after s_owner registered.
    Result<hook::VmtHook> created = hook::vmt_for("LateVmtOwner", object);
    if (!created.has_value())
    {
        std::fputs("FAIL: vmt_for failed\n", stderr);
        return 3;
    }
    hook::VmtHook clone = std::move(*created);
    if (!clone.hook_method(LATE_TRANSFORM_INDEX, &late_transform_detour).has_value())
    {
        std::fputs("FAIL: hook_method failed\n", stderr);
        return 4;
    }
    if (call_unfolded(object, LATE_INPUT) != LATE_DETOUR_RESULT)
    {
        std::fputs("FAIL: the detour is not reachable after hook_method\n", stderr);
        return 4;
    }

    s_owner.adopt_hook(std::move(clone));
    s_hooked = true;
    // The process exits successfully only if ~s_owner completes every teardown assertion and returns.
    return 0;
}
