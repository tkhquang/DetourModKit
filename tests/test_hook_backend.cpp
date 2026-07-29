/**
 * @file test_hook_backend.cpp
 * @brief Proofs for the hook/backend transaction boundary: post-commit failures and byte ownership.
 *
 * The backend writes its patch inside a thread-trapping transaction whose final page-protection restore can still
 * fail, so a returned error can sit over a fully committed patch (and over a fully committed restore). No host action
 * reaches that window -- decommitting the target aborts the transaction before it writes anything, which is what
 * test_hook.cpp's InlineHookFaultProof cases cover -- so these tests drive it through a backend seam that substitutes
 * the transaction's reported outcome after the write has landed. The remaining cases cover the other half of the same
 * mechanism: bytes at the target that belong to neither this hook nor its original prologue.
 */

#include <gtest/gtest.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"

#include "fixtures/scratch_page.hpp"

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    void set_backend_reprotect_failure_target(void *target) noexcept;
    extern bool (*g_hook_enable_witness_override)(bool) noexcept;
#endif
} // namespace DetourModKit::detail

namespace
{
    using DetourModKit::Address;
    using DetourModKit::ErrorCode;
    using DetourModKit::Result;
    using DetourModKit::hook::Hook;
    using DetourModKit::hook::inline_at;
    using DetourModKit::hook::InlineRequest;

    using LeafFn = int (*)();

    /// The value the planted leaf returns, and the value the detour returns in its place.
    constexpr int LEAF_RESULT = 1;
    constexpr int DETOUR_RESULT = 0x5EED;

    int detour_leaf() noexcept
    {
        return DETOUR_RESULT;
    }

    /// Plants `mov eax, 1; ret` at offset 0: a complete leaf function, long enough for either patch form.
    void plant_leaf(dmk_test::ScratchPage &page) noexcept
    {
        page.put(0, {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3});
    }

    Result<Hook> install_leaf(dmk_test::ScratchPage &page, const char *name)
    {
        return inline_at(InlineRequest{.name = name, .target = Address{page.addr(0)}},
                         reinterpret_cast<void (*)()>(&detour_leaf));
    }

    /// A volatile indirection forces the call to reach the patched entry even when the optimizer can see the callee.
    int call_target(dmk_test::ScratchPage &page) noexcept
    {
        const LeafFn volatile indirect = reinterpret_cast<LeafFn>(page.addr(0));
        return indirect();
    }

    std::size_t armed_population() noexcept
    {
        return DetourModKit::diagnostics::collect().hooks_active;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    /// Arms the backend's post-commit transaction seam for one address, and always disarms it.
    class BackendReprotectFailureScope
    {
    public:
        explicit BackendReprotectFailureScope(std::uintptr_t target) noexcept
        {
            DetourModKit::detail::set_backend_reprotect_failure_target(reinterpret_cast<void *>(target));
        }
        ~BackendReprotectFailureScope() noexcept
        {
            DetourModKit::detail::set_backend_reprotect_failure_target(nullptr);
        }
        BackendReprotectFailureScope(const BackendReprotectFailureScope &) = delete;
        BackendReprotectFailureScope &operator=(const BackendReprotectFailureScope &) = delete;
        BackendReprotectFailureScope(BackendReprotectFailureScope &&) = delete;
        BackendReprotectFailureScope &operator=(BackendReprotectFailureScope &&) = delete;
    };
#endif

    /// Overwrites the target's first bytes with a jmp no DMK hook in this process emitted.
    void plant_foreign_patch(dmk_test::ScratchPage &page) noexcept
    {
        DWORD previous = 0;
        if (::VirtualProtect(page.base(), dmk_test::ScratchPage::PAGE_SIZE, PAGE_EXECUTE_READWRITE, &previous) == FALSE)
        {
            return;
        }
        // E9 rel32 back to the page's own second half: a well-formed patch whose bytes match neither the saved
        // prologue nor anything the backend emitted for this target.
        page.put(0, {0xE9, 0x7B, 0x00, 0x00, 0x00, 0x90});
        DWORD ignored = 0;
        (void)::VirtualProtect(page.base(), dmk_test::ScratchPage::PAGE_SIZE, previous, &ignored);
    }

    std::array<std::uint8_t, 6> read_prologue(const dmk_test::ScratchPage &page) noexcept
    {
        std::array<std::uint8_t, 6> bytes{};
        std::memcpy(bytes.data(), reinterpret_cast<const void *>(page.addr(0)), bytes.size());
        return bytes;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    /// The page the witness override below plants on. The seam is a plain function pointer, so it cannot capture.
    dmk_test::ScratchPage *g_witness_override_page = nullptr;

    /**
     * @brief Stands in for a third party that takes the window between the backend's committed patch and DMK's
     *        witness of it: the arm really landed, and by the time DMK looks the bytes belong to somebody else.
     */
    bool plant_foreign_then_reject(bool) noexcept
    {
        if (g_witness_override_page != nullptr)
        {
            plant_foreign_patch(*g_witness_override_page);
        }
        return false;
    }

    /// Arms the enable-witness seam, and always disarms it.
    class HookEnableWitnessOverrideScope
    {
    public:
        HookEnableWitnessOverrideScope(bool (*override_fn)(bool) noexcept, dmk_test::ScratchPage &page) noexcept
        {
            g_witness_override_page = &page;
            DetourModKit::detail::g_hook_enable_witness_override = override_fn;
        }
        ~HookEnableWitnessOverrideScope() noexcept
        {
            DetourModKit::detail::g_hook_enable_witness_override = nullptr;
            g_witness_override_page = nullptr;
        }
        HookEnableWitnessOverrideScope(const HookEnableWitnessOverrideScope &) = delete;
        HookEnableWitnessOverrideScope &operator=(const HookEnableWitnessOverrideScope &) = delete;
        HookEnableWitnessOverrideScope(HookEnableWitnessOverrideScope &&) = delete;
        HookEnableWitnessOverrideScope &operator=(HookEnableWitnessOverrideScope &&) = delete;
    };
#endif
} // namespace

#if defined(DMK_ENABLE_TEST_SEAMS)

// The transaction wrote the jmp and then reported a failure. The patch is live, so publishing Disabled would leave the
// detour dispatching behind a handle that denies it and a call gate that never opens. Mutation: reverting the backend's
// `if (committed) m_enabled = true;` hoist below its early returns restores the pre-fix behaviour and fails this.
TEST(HookBackendTransaction, EnableCommittedThenReportedFailurePublishesArmed)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    ASSERT_EQ(call_target(page), LEAF_RESULT);

    Result<Hook> installed = install_leaf(page, "EnableCommitFailure");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);

    // Consumers learn about this transition through the event stream, so it has to be observed here: publishing Active
    // while telling subscribers the opposite is invisible to every other assertion below.
    std::size_t enabled_events = 0;
    auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
        [&enabled_events](const DetourModKit::diagnostics::HookLifecycleEvent &event)
        {
            if (event.name == "EnableCommitFailure" && event.kind == DetourModKit::diagnostics::HookKind::Inline &&
                event.transition == DetourModKit::diagnostics::HookTransition::Enabled)
            {
                ++enabled_events;
            }
        });

    const std::size_t armed_before = armed_population();
    Result<void> enabled{};
    {
        const BackendReprotectFailureScope seam{page.addr(0)};
        enabled = hook.enable();
    }

    ASSERT_FALSE(enabled.has_value());
    EXPECT_EQ(enabled.error().code, ErrorCode::BackendFailed);
    // Every published surface agrees with the bytes: the hook is armed and the detour is reachable.
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(call_target(page), DETOUR_RESULT);
    EXPECT_EQ(armed_population(), armed_before + 1);
    EXPECT_TRUE(hook.original<LeafFn>() != nullptr);
    // original<>() reads the backend trampoline directly; try_call goes through the call gate, which is the surface a
    // detour actually chains on. A branch that published Active without opening the gate passes every check above.
    const Result<int> guarded_original = hook.try_call<int>();
    ASSERT_TRUE(guarded_original.has_value()) << guarded_original.error().message();
    EXPECT_EQ(*guarded_original, LEAF_RESULT);
    EXPECT_EQ(enabled_events, 1u);

    // The hook is genuinely armed, so an ordinary disable takes it back down.
    ASSERT_TRUE(hook.disable().has_value());
    EXPECT_EQ(call_target(page), LEAF_RESULT);
}

// The mirror: the transaction restored the prologue and then reported a failure. The target no longer redirects, so
// republishing Active would point the call gate at a trampoline nothing jumps to. Mutation: restoring the `&&`
// short-circuit in Hook::disable fails this. The backend's `if (committed) m_enabled = false;` hoist does NOT gate
// this case; it is owned by CommittedDisableFailureLeavesTheHookReArmable below.
TEST(HookBackendTransaction, DisableCommittedThenReportedFailurePublishesDisabled)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "DisableCommitFailure");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_TRUE(hook.enable().has_value());
    ASSERT_EQ(call_target(page), DETOUR_RESULT);

    // Subscribed after the arming enable, so only the disarm this case drives is counted.
    std::size_t disabled_events = 0;
    auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
        [&disabled_events](const DetourModKit::diagnostics::HookLifecycleEvent &event)
        {
            if (event.name == "DisableCommitFailure" && event.kind == DetourModKit::diagnostics::HookKind::Inline &&
                event.transition == DetourModKit::diagnostics::HookTransition::Disabled)
            {
                ++disabled_events;
            }
        });

    const std::size_t armed_before = armed_population();
    Result<void> disabled{};
    {
        const BackendReprotectFailureScope seam{page.addr(0)};
        disabled = hook.disable();
    }

    // The disarm took effect; the error reports the transaction outcome rather than hiding it.
    ASSERT_FALSE(disabled.has_value());
    EXPECT_EQ(disabled.error().code, ErrorCode::BackendFailed);
    EXPECT_FALSE(hook.is_enabled());
    EXPECT_EQ(call_target(page), LEAF_RESULT);
    EXPECT_EQ(armed_population(), armed_before - 1);
    // The gate closes with the state. Leaving it open would keep handing callers a trampoline the target no longer
    // jumps to, which none of the assertions above can distinguish from a correct disarm.
    EXPECT_FALSE(hook.try_call<int>().has_value());
    EXPECT_EQ(disabled_events, 1u);
}

// After a committed restore that reported failure, the hook must still be re-armable. DMK's own state is driven by the
// bytes and is already correct here, so what this pins is the BACKEND's flag: if it stays enabled over a restored
// target, the next backend enable() takes its "already enabled" fast path and returns success without patching
// anything, leaving the hook permanently unable to arm. Mutation: reverting the backend's
// `if (committed) m_enabled = false;` hoist fails this and nothing else.
TEST(HookBackendTransaction, CommittedDisableFailureLeavesTheHookReArmable)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "DisableCommitReArm");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_TRUE(hook.enable().has_value());

    {
        const BackendReprotectFailureScope seam{page.addr(0)};
        EXPECT_FALSE(hook.disable().has_value());
    }
    ASSERT_FALSE(hook.is_enabled());
    ASSERT_EQ(call_target(page), LEAF_RESULT);

    // The seam is gone; an ordinary enable must arm the target again.
    const Result<void> rearmed = hook.enable();
    ASSERT_TRUE(rearmed.has_value()) << rearmed.error().message();
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(call_target(page), DETOUR_RESULT);
}

// A committed enable whose transaction failed must still tear down cleanly: the bytes are ours, so teardown restores
// them and frees the backend rather than pinning it.
TEST(HookBackendTransaction, CommittedEnableFailureStillTearsDownWithoutLeaking)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const std::array<std::uint8_t, 6> pristine = read_prologue(page);

    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    {
        Result<Hook> installed = install_leaf(page, "CommitFailureTeardown");
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        {
            const BackendReprotectFailureScope seam{page.addr(0)};
            EXPECT_FALSE(hook.enable().has_value());
        }
        ASSERT_TRUE(hook.is_enabled());
    }

    EXPECT_EQ(read_prologue(page), pristine);
    EXPECT_EQ(DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
              leaks_before);
}

#endif // DMK_ENABLE_TEST_SEAMS

// A third party owns the prologue. The backend's disable copies its saved bytes back unconditionally, so DMK has to
// refuse BEFORE the call or the foreign patch is silently clobbered. Mutation: collapsing OwnedPatch and Foreign into
// one Patched state makes the foreign bytes read as ours and the refusal disappears.
TEST(HookBackendOwnership, ForeignPrologueIsNotOverwrittenByDisable)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    std::array<std::uint8_t, 6> foreign{};
    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    {
        Result<Hook> installed = install_leaf(page, "ForeignDisable");
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        ASSERT_TRUE(hook.enable().has_value());

        plant_foreign_patch(page);
        foreign = read_prologue(page);

        const Result<void> disabled = hook.disable();
        ASSERT_FALSE(disabled.has_value());
        EXPECT_EQ(disabled.error().code, ErrorCode::DisableFailed);
        // The refusal happened before the backend ran, so the foreign bytes are exactly as they were left.
        EXPECT_EQ(read_prologue(page), foreign);
        // The hook never claimed a disarm it did not perform.
        EXPECT_TRUE(hook.is_enabled());
    }

    // Teardown must fail closed too: the target is not restorable, so the backend is pinned rather than freed, and the
    // foreign writer's bytes survive that as well.
    EXPECT_EQ(DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
              leaks_before + 1);
    EXPECT_EQ(read_prologue(page), foreign);
}

// The enable direction of the same rule: the backend emits its jmp over whatever is present, so a foreign prologue has
// to refuse the arm while the hook is still exactly as the caller left it.
TEST(HookBackendOwnership, ForeignPrologueIsNotOverwrittenByEnable)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "ForeignEnable");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);

    plant_foreign_patch(page);
    const std::array<std::uint8_t, 6> foreign = read_prologue(page);

    const Result<void> enabled = hook.enable();
    ASSERT_FALSE(enabled.has_value());
    EXPECT_EQ(enabled.error().code, ErrorCode::EnableFailed);
    EXPECT_EQ(read_prologue(page), foreign);
    EXPECT_FALSE(hook.is_enabled());

    // Restoring the prologue by hand makes the hook usable again: the refusal is a property of the bytes, not a latch.
    plant_leaf(page);
    EXPECT_TRUE(hook.enable().has_value());
    EXPECT_TRUE(hook.is_enabled());
}

#if defined(DMK_ENABLE_TEST_SEAMS)
// The third toggle site. enable() also disarms: when the arm lands but the witness cannot attribute the bytes, it runs
// a compensating disable() before it may publish Disabled. That disable copies this hook's saved prologue back
// unconditionally, exactly like the one Hook::disable() drives, so it needs the same ownership refusal or a writer who
// took the window between the patch and the witness has its bytes destroyed by the rollback. The other two ownership
// cases cannot see this: both refuse at the entry gate and never reach a backend call at all.
//
// Mutation: dropping the witness_permits_write guard on the rollback makes the saved prologue overwrite the foreign
// patch, so read_prologue() comes back as the original leaf and the error code becomes EnableFailed.
TEST(HookBackendOwnership, EnableRollbackDoesNotOverwriteForeignPrologue)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    std::array<std::uint8_t, 6> foreign{};
    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    {
        Result<Hook> installed = install_leaf(page, "ForeignRollback");
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);

        Result<void> enabled;
        {
            const HookEnableWitnessOverrideScope scope(&plant_foreign_then_reject, page);
            enabled = hook.enable();
        }
        foreign = read_prologue(page);
        // The seam only runs once the backend's enable committed, so reaching a non-original prologue at all proves
        // the arm landed and the override fired; a vacuous run would still read the planted leaf here.
        EXPECT_EQ(foreign, (std::array<std::uint8_t, 6>{0xE9, 0x7B, 0x00, 0x00, 0x00, 0x90}));

        // The rollback was refused, so the foreign writer's bytes are still exactly what it wrote.
        ASSERT_FALSE(enabled.has_value());
        EXPECT_EQ(enabled.error().code, ErrorCode::DisableFailed);
        // Nothing proved this hook disarmed, so it keeps reporting the truthful active state and its trampoline stays
        // reachable for the caller to quiesce.
        EXPECT_TRUE(hook.is_enabled());
    }

    // Teardown sees the same foreign window and pins rather than restoring, so the bytes survive that too.
    EXPECT_EQ(DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
              leaks_before + 1);
    EXPECT_EQ(read_prologue(page), foreign);
}
#endif // DMK_ENABLE_TEST_SEAMS
