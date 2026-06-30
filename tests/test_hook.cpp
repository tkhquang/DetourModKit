#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

using namespace DetourModKit;
// The SafetyHook backend is confined to the library: a detour names only these DMK-owned hook types, exactly as a
// shipping consumer would. There is no HookManager, no registry, no HookError/HookStatus/HookType enums.
using namespace DetourModKit::hook;

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

// ----------------------------------------------------------------------------
// Real, hookable functions used as inline/mid hook targets. DMK_TEST_NOINLINE plus a volatile result forces a real call
// to the patched entry, so a post-teardown call observes the restored prologue rather than a constant-folded value.
// ----------------------------------------------------------------------------
namespace
{
    DMK_TEST_NOINLINE int echo(int x)
    {
        volatile int r = x;
        return r;
    }

    DMK_TEST_NOINLINE int real_hook_target_add(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_TEST_NOINLINE int real_hook_target_mul(int a, int b)
    {
        volatile int r = a * b;
        return r;
    }

    // Dedicated targets for the release()/leak tests. release() intentionally leaks an installed detour for the process
    // lifetime, so a leaked hook must never land on a target a later test expects to be clean. Each leak test uses its
    // own function here, touched by no other test.
    DMK_TEST_NOINLINE int leak_target_inline(int x)
    {
        volatile int r = x;
        return r;
    }

    DMK_TEST_NOINLINE int leak_target_disengaged(int x)
    {
        volatile int r = x;
        return r;
    }

    DMK_TEST_NOINLINE int leak_target_mid(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_TEST_NOINLINE int leak_target_lifecycle(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    std::atomic<int> s_real_detour_calls{0};

    DMK_TEST_NOINLINE int real_hook_detour_add(int a, int b)
    {
        s_real_detour_calls.fetch_add(1, std::memory_order_relaxed);
        return a + b + 1000;
    }

    using EchoFn = int (*)(int);

    // Detour for echo: returns x + 100 so a hooked echo(7) == 107 while the trampoline still yields the original 7.
    int echo_detour(int x)
    {
        return x + 100;
    }

    std::atomic<int> s_mid_detour_calls{0};

    // Builds an Address from a free function pointer via the uintptr form (a function pointer does not implicitly
    // convert to void*).
    template <class Fn> [[nodiscard]] Address addr_of(Fn *fn) noexcept
    {
        return Address{reinterpret_cast<std::uintptr_t>(fn)};
    }
} // namespace

// ----------------------------------------------------------------------------
// INLINE create + validation
// ----------------------------------------------------------------------------

TEST(HookInline, CreateSuccessAutoEnabled)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "InlineCreate", .target = addr_of(&real_hook_target_add)},
                               &real_hook_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();

    Hook h = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(h));
    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(h.name(), "InlineCreate");
}

TEST(HookInline, CreateInvalidTargetAddress)
{
    Result<Hook> r =
        inline_at(InlineRequest{.name = "BadTarget", .target = Address{std::uintptr_t{0}}}, &real_hook_detour_add);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidTargetAddress);
}

TEST(HookInline, CreateNullDetour)
{
    EchoFn null_detour = nullptr;
    Result<Hook> r =
        inline_at(InlineRequest{.name = "NullDetour", .target = addr_of(&real_hook_target_add)}, null_detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidDetourFunction);
}

TEST(HookInline, CreateEmptyName)
{
    Result<Hook> r =
        inline_at(InlineRequest{.name = "", .target = addr_of(&real_hook_target_add)}, &real_hook_detour_add);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidArg);
}

// ----------------------------------------------------------------------------
// INLINE typed trampoline + enable/disable
// ----------------------------------------------------------------------------

TEST(HookInline, TypedTrampolineCallsOriginal)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "Trampoline", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    // The detour is active: echo(7) routes through echo_detour -> 107.
    EXPECT_EQ(echo(7), 107);

    // The typed trampoline reaches the original body, so it yields the unmodified 7.
    auto *orig = h.original<EchoFn>();
    ASSERT_NE(orig, nullptr);
    EXPECT_EQ(orig(7), 7);
}

TEST(HookInline, EnableDisableTogglesDetour)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "Toggle", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(echo(7), 107);

    ASSERT_TRUE(h.disable().has_value());
    EXPECT_FALSE(h.is_enabled());
    EXPECT_EQ(echo(7), 7); // original body restored while disabled

    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(echo(7), 107);
}

TEST(HookInline, EnableDisableAreIdempotent)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "Idempotent", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    ASSERT_TRUE(h.enable().has_value()); // already enabled
    EXPECT_TRUE(h.is_enabled());
    ASSERT_TRUE(h.disable().has_value());
    ASSERT_TRUE(h.disable().has_value()); // already disabled
    EXPECT_FALSE(h.is_enabled());
}

// A moved-from inline handle is a mid-hook-style nullptr for original<Fn>() too, but the primary inert guarantee is in
// the RAII teardown test below. Here we pin that the typed trampoline is non-null only for a live inline hook.
TEST(HookInline, OriginalNullForDisengagedHandle)
{
    // Uses a dedicated leak target: release() leaves the detour installed for the process lifetime.
    Result<Hook> r =
        inline_at(InlineRequest{.name = "Disengaged", .target = addr_of(&leak_target_disengaged)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    h.release(); // detach: handle becomes disengaged
    EXPECT_FALSE(static_cast<bool>(h));
    EXPECT_EQ(h.original<EchoFn>(), nullptr);
}

// ----------------------------------------------------------------------------
// INLINE prologue policy
// ----------------------------------------------------------------------------
namespace
{
    // Synthetic prologue buffers for the inline/mid prologue pre-flight. const (read-only) and alignas(16) so the
    // planted first byte sits at a deterministic, readable address across toolchains. The Fail-policy create refuses at
    // the prologue pre-flight, so these need not be relocatable code -- only the first byte is classified, and the hook
    // target is the buffer's address.
    alignas(16) const std::uint8_t CALL_PROLOGUE_BYTES[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90};
    alignas(16) const std::uint8_t INT3_PROLOGUE_BYTES[] = {0xCC, 0xC3, 0x90, 0x90};
    alignas(16) const std::uint8_t INTN_PROLOGUE_BYTES[] = {0xCD, 0x03, 0xC3, 0x90};
    // Dedicated buffer for the Relocate-leak test: it installs and releases (leaks) a hook here, which patches the
    // first byte, so it must not share a buffer with the prologue-refusal tests that need a clean leading 0xE8.
    alignas(16) std::uint8_t RELOCATE_CALL_PROLOGUE_BYTES[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90,
                                                               0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

    void noop_detour() noexcept {}
} // namespace

// The default policy is Prologue::Fail (safe-by-default). A leading 0xE8 (call rel32) prologue is unsafe to
// inline-hook: the relocated trampoline copy can dispatch a relative call to the wrong absolute target. The default
// create must refuse with TargetPrologueUnsafe.
TEST(HookInlinePrologue, DefaultFailsOnLeadingCallPrologue)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "CallPrologue", .target = addr_of(CALL_PROLOGUE_BYTES)},
                               reinterpret_cast<void (*)()>(&noop_detour));
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// A leading 0xCC (int3) prologue is already a breakpoint -- a foreign hook's stub, a patched byte, or padding -- not a
// real function body. The default Fail policy must refuse.
TEST(HookInlinePrologue, DefaultFailsOnInt3Prologue)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "Int3Prologue", .target = addr_of(INT3_PROLOGUE_BYTES)},
                               reinterpret_cast<void (*)()>(&noop_detour));
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// A leading 0xCD (int n) prologue is the two-byte breakpoint form; classifying on the first byte alone is sufficient.
TEST(HookInlinePrologue, DefaultFailsOnIntNPrologue)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "IntNPrologue", .target = addr_of(INTN_PROLOGUE_BYTES)},
                               reinterpret_cast<void (*)()>(&noop_detour));
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// The default policy must never refuse a normal real-function target: a normal prologue installs with no false
// TargetPrologueUnsafe.
TEST(HookInlinePrologue, DefaultInstallsOnNormalTarget)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "NormalPrologue", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << "Default policy must not refuse a normal function prologue: " << r.error().message();
    EXPECT_TRUE(static_cast<bool>(*r));
}

// Prologue::Relocate opts back in to the install-anyway behaviour: it logs and installs even on a leading-call
// prologue.
TEST(HookInlinePrologue, RelocateInstallsOnUnsafePrologue)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "RelocateCall",
                                             .target = addr_of(RELOCATE_CALL_PROLOGUE_BYTES),
                                             .options = Options{.prologue = Prologue::Relocate}},
                               reinterpret_cast<void (*)()>(&noop_detour));
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(h));
    h.release(); // the synthetic buffer is not relocatable code; leak the clone rather than restore it
}

// ----------------------------------------------------------------------------
// INLINE duplicate detection (Options::fail_if_already_hooked + is_target_hooked)
// ----------------------------------------------------------------------------

TEST(HookInline, FailIfAlreadyHookedRefusesSecondHook)
{
    Result<Hook> first =
        inline_at(InlineRequest{.name = "DupBase", .target = addr_of(&real_hook_target_add)}, &real_hook_detour_add);
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook base = std::move(*first);

    Result<Hook> second = inline_at(InlineRequest{.name = "DupSecond",
                                                  .target = addr_of(&real_hook_target_add),
                                                  .options = Options{.fail_if_already_hooked = true}},
                                    &real_hook_detour_add);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::TargetAlreadyHookedInProcess);
}

TEST(HookInline, DefaultModeLayersSecondHook)
{
    Result<Hook> first =
        inline_at(InlineRequest{.name = "LayerBase", .target = addr_of(&real_hook_target_mul)}, &real_hook_detour_add);
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook base = std::move(*first);

    // Default mode (fail_if_already_hooked = false): the second hook simply layers on top.
    Result<Hook> second = inline_at(InlineRequest{.name = "LayerSecond", .target = addr_of(&real_hook_target_mul)},
                                    &real_hook_detour_add);
    ASSERT_TRUE(second.has_value()) << second.error().message();
    Hook layer = std::move(*second);
    // Teardown is newest-first by natural reverse-order destruction: layer (declared last) is destroyed before base.
}

// ----------------------------------------------------------------------------
// is_target_hooked(Address)
// ----------------------------------------------------------------------------

TEST(HookLedger, IsTargetHookedFalseForZero)
{
    EXPECT_FALSE(is_target_hooked(Address{std::uintptr_t{0}}));
}

TEST(HookLedger, IsTargetHookedTrueWhileLiveFalseAfterDrop)
{
    const Address target = addr_of(&real_hook_target_mul);
    EXPECT_FALSE(is_target_hooked(target));
    {
        Result<Hook> r = inline_at(InlineRequest{.name = "LedgerLive", .target = target}, &real_hook_detour_add);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        EXPECT_TRUE(is_target_hooked(target));
    }
    // The hook handle dropped, restoring the prologue and clearing the ledger entry.
    EXPECT_FALSE(is_target_hooked(target));
}

// ----------------------------------------------------------------------------
// Hook::call<Ret>(args): the guarded trampoline call, with the by-value-ABI lvalue case
// ----------------------------------------------------------------------------

TEST(HookCall, GuardedCallReachesOriginalThroughTrampoline)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "GuardedCall", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    // The detour is active so a direct echo(7) is 107; the guarded call routes through the trampoline to the
    // original 7.
    EXPECT_EQ(echo(7), 107);
    EXPECT_EQ(h.call<int>(7), 7);
}

// CRITICAL by-value-ABI case: passing an lvalue int must still go BY VALUE. A forwarding-reference call() would deduce
// a reference type and reconstruct a reference-parameter function pointer, passing a hidden pointer where the by-value
// trampoline expects the scalar -- silent, value-category-dependent ABI UB. By value, an lvalue argument round-trips.
TEST(HookCall, GuardedCallPassesLvalueByValue)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "GuardedLvalue", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    int lv = 7;
    EXPECT_EQ(h.call<int>(lv), 7) << "lvalue int must be passed by value through the trampoline";
}

// After disable(), call() observes an inactive hook and returns a value-initialized Ret (0 for int).
TEST(HookCall, GuardedCallReturnsValueInitWhenInactive)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "GuardedInactive", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(h.call<int>(7), int{});
}

// ----------------------------------------------------------------------------
// release(): detach but stay installed for the process lifetime
// ----------------------------------------------------------------------------

TEST(HookRelease, ReleaseLeavesHookInstalledAndFiring)
{
    // Dedicated leak target: this detour stays installed for the process lifetime, so no other test may share it.
    const Address target = addr_of(&leak_target_inline);
    EXPECT_EQ(leak_target_inline(7), 7); // sanity: clean before the hook
    Result<Hook> r = inline_at(InlineRequest{.name = "Released", .target = target}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    h.release();
    EXPECT_FALSE(static_cast<bool>(h));    // handle disengaged
    EXPECT_TRUE(is_target_hooked(target)); // still installed (leaked intentionally; that is the contract)
    EXPECT_EQ(leak_target_inline(7), 107); // the detour still fires
    // No restore: leak_target_inline stays hooked for the process lifetime. Intentional leak.
}

// ----------------------------------------------------------------------------
// RAII teardown + moved-from inertness
// ----------------------------------------------------------------------------

TEST(HookTeardown, DestructorRestoresPrologue)
{
    EXPECT_EQ(echo(7), 7); // sanity: unhooked
    {
        Result<Hook> r = inline_at(InlineRequest{.name = "TeardownRestore", .target = addr_of(&echo)}, &echo_detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        EXPECT_EQ(echo(7), 107); // hooked
    }
    EXPECT_EQ(echo(7), 7); // prologue restored on scope exit
}

TEST(HookTeardown, MovedFromHandleIsInert)
{
    EXPECT_EQ(echo(7), 7);
    {
        Result<Hook> r = inline_at(InlineRequest{.name = "MovedFrom", .target = addr_of(&echo)}, &echo_detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook a = std::move(*r);
        Hook b = std::move(a);
        // Only b owns the live hook now; a is inert and must not double-unhook or crash.
        EXPECT_FALSE(static_cast<bool>(a));
        EXPECT_TRUE(static_cast<bool>(b));
        // call() through a disengaged handle must be a defined no-op returning the inactive default, not a null
        // dereference of the moved-out Impl (the guarded twin of original<Fn>(), which is already inert here).
        EXPECT_EQ(a.call<int>(7), int{});
        EXPECT_EQ(echo(7), 107);
    } // only b unhooks; a's destructor is a no-op
    EXPECT_EQ(echo(7), 7);
}

// ----------------------------------------------------------------------------
// MID create / lifecycle (the MidContext-accessor semantics live in test_mid_hook_context.cpp)
// ----------------------------------------------------------------------------

TEST(HookMid, CreateSuccessAutoEnabled)
{
    auto detour = [](MidContext &) { s_mid_detour_calls.fetch_add(1, std::memory_order_relaxed); };
    Result<Hook> r = mid_at(MidRequest{.name = "MidCreate", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(h));
    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(h.name(), "MidCreate");
}

TEST(HookMid, CreateInvalidTargetAddress)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidBadTarget", .target = Address{std::uintptr_t{0}}}, detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidTargetAddress);
}

TEST(HookMid, CreateNullDetour)
{
    MidHookFn null_detour = nullptr;
    Result<Hook> r = mid_at(MidRequest{.name = "MidNullDetour", .target = addr_of(&real_hook_target_add)}, null_detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidDetourFunction);
}

TEST(HookMid, CreateEmptyName)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidArg);
}

TEST(HookMid, EnableDisableToggles)
{
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(MidRequest{.name = "MidToggle", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    EXPECT_TRUE(h.is_enabled());
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_FALSE(h.is_enabled());
    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
}

// A mid hook has no callable original; original<Fn>() is nullptr for it.
TEST(HookMid, OriginalIsNullForMidHook)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidNoOriginal", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    EXPECT_EQ(h.original<EchoFn>(), nullptr);
}

TEST(HookMid, FailIfAlreadyHookedRefusesSecondMid)
{
    auto detour = [](MidContext &) {};
    Result<Hook> first = mid_at(MidRequest{.name = "MidDupBase", .target = addr_of(&real_hook_target_mul)}, detour);
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook base = std::move(*first);

    Result<Hook> second = mid_at(MidRequest{.name = "MidDupSecond",
                                            .target = addr_of(&real_hook_target_mul),
                                            .options = Options{.fail_if_already_hooked = true}},
                                 detour);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::TargetAlreadyHookedInProcess);
}

// Cross-type duplicate detection: a mid hook over an existing inline hook on the same target is refused under strict
// mode (the ledger check is type-agnostic, overlapping the same prologue bytes).
TEST(HookMid, FailIfAlreadyHookedRefusesOverInline)
{
    Result<Hook> inl = inline_at(InlineRequest{.name = "MidOverInlineBase", .target = addr_of(&real_hook_target_add)},
                                 &real_hook_detour_add);
    ASSERT_TRUE(inl.has_value()) << inl.error().message();
    Hook base = std::move(*inl);

    auto detour = [](MidContext &) {};
    Result<Hook> mid = mid_at(MidRequest{.name = "MidOverInline",
                                         .target = addr_of(&real_hook_target_add),
                                         .options = Options{.fail_if_already_hooked = true}},
                              detour);
    ASSERT_FALSE(mid.has_value());
    EXPECT_EQ(mid.error().code, ErrorCode::TargetAlreadyHookedInProcess);
}

TEST(HookMid, DefaultFailsOnLeadingCallPrologue)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidCallPrologue", .target = addr_of(CALL_PROLOGUE_BYTES)}, detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

TEST(HookMid, DefaultFailsOnInt3Prologue)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidInt3Prologue", .target = addr_of(INT3_PROLOGUE_BYTES)}, detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

TEST(HookMid, RealCreateModifiesArgViaRcx)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    // A mid hook installed at the entry overwrites rcx (the first integer arg) before the body homes it.
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(MidRequest{.name = "MidRealCreate", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    // unhooked add(2, 3) == 5; with rcx := 1000 the resumed body computes 1000 + 3.
    EXPECT_EQ(real_hook_target_add(2, 3), 1000 + 3);
}

TEST(HookMid, RealCreateDisabledRestoresOriginal)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(MidRequest{.name = "MidRealDisabled", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    EXPECT_EQ(real_hook_target_add(2, 3), 1000 + 3);
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(real_hook_target_add(2, 3), 5); // original body again
}

TEST(HookMid, TeardownRestoresOriginal)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    EXPECT_EQ(real_hook_target_mul(4, 5), 20);
    {
        auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 10; };
        Result<Hook> r = mid_at(MidRequest{.name = "MidTeardown", .target = addr_of(&real_hook_target_mul)}, detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        EXPECT_EQ(real_hook_target_mul(4, 5), 10 * 5);
    }
    EXPECT_EQ(real_hook_target_mul(4, 5), 20); // prologue restored
}

TEST(HookMid, ReleaseLeavesMidInstalled)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    // Dedicated leak target: the released mid hook stays installed for the process lifetime.
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(MidRequest{.name = "MidReleased", .target = addr_of(&leak_target_mid)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    h.release();
    EXPECT_FALSE(static_cast<bool>(h));
    EXPECT_TRUE(is_target_hooked(addr_of(&leak_target_mid)));
    EXPECT_EQ(leak_target_mid(2, 3), 1000 + 3); // still fires
}

TEST(HookMid, MovedFromMidHandleIsInert)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    EXPECT_EQ(real_hook_target_mul(4, 5), 20);
    {
        auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 10; };
        Result<Hook> r = mid_at(MidRequest{.name = "MidMovedFrom", .target = addr_of(&real_hook_target_mul)}, detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook a = std::move(*r);
        Hook b = std::move(a);
        EXPECT_FALSE(static_cast<bool>(a));
        EXPECT_TRUE(static_cast<bool>(b));
        EXPECT_EQ(real_hook_target_mul(4, 5), 10 * 5);
    }
    EXPECT_EQ(real_hook_target_mul(4, 5), 20);
}

// ----------------------------------------------------------------------------
// install_all: declarative table with severity + ordering + rollback
// ----------------------------------------------------------------------------
namespace
{
    // Real, hookable functions used as install_all scan targets. Their first bytes are scanned by AOB so the deferred
    // OwnedScanRequest resolves to the function entry. DMK_TEST_NOINLINE keeps them out of line so they have a real
    // prologue to hook.
    DMK_TEST_NOINLINE int install_target_one(int x)
    {
        volatile int r = x + 1;
        return r;
    }

    DMK_TEST_NOINLINE int install_target_two(int x)
    {
        volatile int r = x + 2;
        return r;
    }

    int install_detour_one(int x)
    {
        return x + 1000;
    }
    int install_detour_two(int x)
    {
        return x + 2000;
    }

    // Builds an AOB string from the first @p count bytes at @p addr, so a Direct candidate over a Region covering that
    // address resolves uniquely to the function entry.
    [[nodiscard]] std::string aob_of(std::uintptr_t addr, std::size_t count)
    {
        const auto *bytes = reinterpret_cast<const unsigned char *>(addr);
        std::string aob;
        for (std::size_t i = 0; i < count; ++i)
        {
            if (i > 0)
            {
                aob += ' ';
            }
            char hex[4];
            std::snprintf(hex, sizeof(hex), "%02X", bytes[i]);
            aob += hex;
        }
        return aob;
    }

    // An OwnedScanRequest whose Direct candidate resolves uniquely to @p fn's entry, scoped to @p fn's own body. The
    // function pointer is reinterpret_cast to an integer address since a function pointer does not convert to void*.
    [[nodiscard]] scan::OwnedScanRequest resolvable_request(std::string name, EchoFn fn, std::size_t aob_len = 16)
    {
        const auto addr = reinterpret_cast<std::uintptr_t>(fn);
        scan::OwnedScanRequest req;
        req.ladder.push_back(
            scan::Candidate::direct(std::move(name), scan::Pattern::compile(aob_of(addr, aob_len)).value()));
        req.scope = Region{Address{addr}, aob_len + 16};
        return req;
    }

    // An OwnedScanRequest that cannot resolve: a Direct candidate for a byte pattern that is absent from its scope.
    [[nodiscard]] scan::OwnedScanRequest unresolvable_request(std::string name)
    {
        scan::OwnedScanRequest req;
        req.ladder.push_back(scan::Candidate::direct(
            std::move(name), scan::Pattern::compile("FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF").value()));
        req.scope = Region{Address{reinterpret_cast<std::uintptr_t>(&install_target_one)}, 32};
        return req;
    }
} // namespace

TEST(HookInstallAll, TwoMandatoryRowsBothResolve)
{
    const HookSpec table[] = {
        HookSpec::inline_hook("RowOne", resolvable_request("RowOnePat", &install_target_one), &install_detour_one,
                              Severity::Mandatory),
        HookSpec::inline_hook("RowTwo", resolvable_request("RowTwoPat", &install_target_two), &install_detour_two,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_TRUE(res.has_value()) << res.error().message();
    ASSERT_EQ(res->size(), 2u);

    EXPECT_EQ((*res)[0].name, "RowOne");
    EXPECT_EQ((*res)[0].severity, Severity::Mandatory);
    EXPECT_TRUE((*res)[0].hook.has_value()) << (*res)[0].hook.error().message();

    EXPECT_EQ((*res)[1].name, "RowTwo");
    EXPECT_TRUE((*res)[1].hook.has_value()) << (*res)[1].hook.error().message();
}

TEST(HookInstallAll, MandatoryMissFailsWholeCall)
{
    const HookSpec table[] = {
        HookSpec::inline_hook("MandHit", resolvable_request("MandHitPat", &install_target_one), &install_detour_one,
                              Severity::Mandatory),
        HookSpec::inline_hook("MandMiss", unresolvable_request("MandMissPat"), &install_detour_two,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::NoMatch);
    // The prior Mandatory row that landed is rolled back; nothing stays installed.
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_one)));
}

TEST(HookInstallAll, BestEffortMissStillSucceedsWithMandatoryHit)
{
    const HookSpec table[] = {
        HookSpec::inline_hook("BeMiss", unresolvable_request("BeMissPat"), &install_detour_one, Severity::BestEffort),
        HookSpec::inline_hook("MandHit2", resolvable_request("MandHit2Pat", &install_target_two), &install_detour_two,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_TRUE(res.has_value()) << res.error().message();
    ASSERT_EQ(res->size(), 2u);

    // The best-effort row missed: its outcome carries an Error but the call still succeeded.
    EXPECT_EQ((*res)[0].name, "BeMiss");
    EXPECT_EQ((*res)[0].severity, Severity::BestEffort);
    EXPECT_FALSE((*res)[0].hook.has_value());
    EXPECT_EQ((*res)[0].hook.error().code, ErrorCode::NoMatch);

    // The mandatory row landed.
    EXPECT_EQ((*res)[1].name, "MandHit2");
    EXPECT_TRUE((*res)[1].hook.has_value()) << (*res)[1].hook.error().message();
}

// ----------------------------------------------------------------------------
// VMT object hooking (RAII VmtHook)
// ----------------------------------------------------------------------------

class VmtTestInterface
{
public:
    virtual ~VmtTestInterface() = default;
    virtual int compute(int a, int b) = 0;
    virtual int transform(int x) = 0;
};

class VmtTestTarget : public VmtTestInterface
{
public:
    int compute(int a, int b) override { return a + b; }
    int transform(int x) override { return x * 2; }
};

// VMT METHOD-HOOK TEST FIXTURES are deferred along with the per-method API they exercise (the typed per-method VMT
// surface). The vtable-index constants, the captured VmHook pointer, and the method-detour subclass all name the
// SafetyHook backend (safetyhook::VmHook) or feed only the deferred per-method API, so they are guarded out until that
// API is reintroduced. The object-level VMT tests below stay live.
#if 0
// Vtable layout differs between MSVC (single destructor slot) and
// Itanium ABI (two destructor slots used by GCC/MinGW).
#if defined(_MSC_VER)
static constexpr size_t VMT_COMPUTE_INDEX = 1;
static constexpr size_t VMT_TRANSFORM_INDEX = 2;
#else
static constexpr size_t VMT_COMPUTE_INDEX = 2;
static constexpr size_t VMT_TRANSFORM_INDEX = 3;
#endif

static safetyhook::VmHook *s_compute_vm_hook = nullptr;

class VmtTestHook : public VmtTestTarget
{
public:
    int hooked_compute(int a, int b) { return s_compute_vm_hook->thiscall<int>(this, a, b) + 1000; }
};
#endif // VMT method-hook fixtures deferred until the per-method VMT API is reintroduced

TEST(HookVmt, CreateSuccess)
{
    auto target = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("TestVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(vh));
    EXPECT_EQ(vh.name(), "TestVmt");
}

TEST(HookVmt, CreateNullObject)
{
    Result<VmtHook> r = vmt_for("NullVmt", nullptr);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
}

// fail_if_already_hooked refuses a second clone of an object already on a clone owned by this kit.
TEST(HookVmt, FailIfAlreadyHookedRefusesDoubleCreate)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> first = vmt_for("FirstVmt", target.get(), VmtOptions{.fail_if_already_hooked = true});
    ASSERT_TRUE(first.has_value()) << first.error().message();
    VmtHook vh = std::move(*first);

    Result<VmtHook> second = vmt_for("SecondVmt", target.get(), VmtOptions{.fail_if_already_hooked = true});
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::HookAlreadyExists);
}

// The destructor restores the original vptr (the remove-entire-hook equivalent is dropping the handle).
TEST(HookVmt, DestructorRestoresVptr)
{
    auto target = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(target.get());
    EXPECT_EQ(target->compute(1, 2), 3);

    {
        Result<VmtHook> r = vmt_for("RestoreVmt", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook vh = std::move(*r);
        EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr); // on the clone now
    }

    // Dropping the handle restored the original vptr.
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr);
    EXPECT_EQ(target->compute(1, 2), 3);
}

// apply_to puts the clone onto an additional object; remove_from restores it. Newest-first restore on destruction.
TEST(HookVmt, ApplyToAndRemoveFromMultipleObjects)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();
    const auto vptr2_original = *reinterpret_cast<std::uintptr_t *>(target2.get());

    Result<VmtHook> r = vmt_for("MultiVmt", target1.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    ASSERT_TRUE(vh.apply_to(target2.get()).has_value());
    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(target2.get()), vptr2_original); // target2 on the clone

    ASSERT_TRUE(vh.remove_from(target2.get()).has_value());
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(target2.get()), vptr2_original); // restored
}

// Re-applying onto the handle's OWN clone is a success no-op; applying an object held by another live clone fails.
TEST(HookVmt, ApplyToOwnCloneIsNoOpAnotherCloneFails)
{
    auto target_a = std::make_unique<VmtTestTarget>();
    auto target_b = std::make_unique<VmtTestTarget>();

    Result<VmtHook> ra = vmt_for("CloneOwnerA", target_a.get());
    ASSERT_TRUE(ra.has_value()) << ra.error().message();
    VmtHook va = std::move(*ra);

    Result<VmtHook> rb = vmt_for("CloneOwnerB", target_b.get());
    ASSERT_TRUE(rb.has_value()) << rb.error().message();
    VmtHook vb = std::move(*rb);

    // target_b is already on vb's clone. Applying va onto target_b with fail_if_already_hooked must be refused.
    Result<void> cross = va.apply_to(target_b.get(), VmtOptions{.fail_if_already_hooked = true});
    ASSERT_FALSE(cross.has_value());
    EXPECT_EQ(cross.error().code, ErrorCode::HookAlreadyExists);
}

TEST(HookVmt, ApplyNullObject)
{
    auto target = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("ApplyNullVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    Result<void> applied = vh.apply_to(nullptr);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code, ErrorCode::InvalidObject);
}

TEST(HookVmt, RemoveFromNullObject)
{
    auto target = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("RemNullVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    Result<void> removed = vh.remove_from(nullptr);
    EXPECT_FALSE(removed.has_value());
}

TEST(HookVmt, MovedFromVmtHandleIsInert)
{
    auto target = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(target.get());
    {
        Result<VmtHook> r = vmt_for("MovedVmt", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook a = std::move(*r);
        VmtHook b = std::move(a);
        EXPECT_FALSE(static_cast<bool>(a)); // a is inert; only b restores on destruction
        EXPECT_TRUE(static_cast<bool>(b));
    }
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr);
}

// VMT slot pre-flight: refuse to clone an object whose vtable's first slot is an int3 padding/breakpoint byte, or a
// same-module jump stub; accept a real function prologue. The pre-flight is opt-in (fail_on_non_function_pointer).
namespace
{
    // Aligned to a 16-byte boundary so the byte at offset 0 is the absolute function-pointer target the pre-flight
    // decoder reads. The page the buffer lives in is committed and readable.
    alignas(16) const std::uint8_t INT3_SLOT_BYTES[] = {0xCC, 0xCC, 0xC3, 0x90};
    alignas(16) const std::uint8_t RET_SLOT_BYTES[] = {0xC3, 0x90, 0x90, 0x90};

    // First byte E9 (jmp rel32) with a displacement landing a few bytes ahead inside this same buffer. The buffer lives
    // in the test image, so the slot and the resolved jump target map to the same module: a same-module jump stub.
    alignas(16) const std::uint8_t JMP_STUB_SLOT_BYTES[] = {0xE9, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90,
                                                            0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

    // First byte 0x48 (REX.W prefix opening a standard x64 prologue, here sub rsp, 0x28): the decoder must classify the
    // slot as a function body.
    alignas(16) const std::uint8_t PROLOGUE_SLOT_BYTES[] = {0x48, 0x83, 0xEC, 0x28, 0xC3, 0x90, 0x90, 0x90};
} // namespace

TEST(HookVmt, PreFlightRefusesInt3FirstSlot)
{
    struct Int3VTable
    {
        void *methods[2];
    };
    Int3VTable vtable{};
    vtable.methods[0] = const_cast<void *>(static_cast<const void *>(INT3_SLOT_BYTES));
    vtable.methods[1] = const_cast<void *>(static_cast<const void *>(RET_SLOT_BYTES));
    void *vptr = &vtable;

    Result<VmtHook> r = vmt_for("Int3Vmt", &vptr, VmtOptions{.fail_on_non_function_pointer = true});
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);

    // The refused create did not touch the vptr: it still points at our local vtable.
    EXPECT_EQ(vptr, static_cast<void *>(&vtable));
}

TEST(HookVmt, PreFlightAcceptsFunctionPrologue)
{
    // Slot 0 carries a normal x64 prologue first byte (0x48), so pre-flight with fail_on_non_function_pointer=true must
    // accept the vtable and the create must succeed. The rtti member sits at vptr[-1]: the clone copies the RTTI slot
    // ahead of the vtable, so the vptr must point past an in-bounds leading member.
    struct PrologueVTable
    {
        void *rtti;
        void *methods[2];
    };
    PrologueVTable vtable{};
    vtable.methods[0] = const_cast<void *>(static_cast<const void *>(PROLOGUE_SLOT_BYTES));
    void *vptr = &vtable.methods[0];

    Result<VmtHook> r = vmt_for("PrologueVmt", &vptr, VmtOptions{.fail_on_non_function_pointer = true});
    ASSERT_TRUE(r.has_value()) << r.error().message();
    {
        VmtHook vh = std::move(*r);
        EXPECT_EQ(vh.name(), "PrologueVmt");
    }
    // The accepted create swapped the vptr onto the clone; dropping the handle restores the original vtable pointer.
    EXPECT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));
}

TEST(HookVmt, PreFlightOffByDefault)
{
    // The default options (fail_on_non_function_pointer = false) do not run the pre-flight, so a synthetic vtable with
    // a null first slot still creates successfully -- the new check is opt-in, not on-by-default. The rtti member sits
    // at vptr[-1].
    struct NullVTable
    {
        void *rtti;
        void *methods[2];
    };
    NullVTable vtable{};
    void *vptr = &vtable.methods[0];

    Result<VmtHook> r = vmt_for("NullSlotVmt", &vptr);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r); // dropped at scope end, restoring the vptr
    (void)vh;
}

TEST(HookVmt, PreFlightRefusesSameModuleJumpStub)
{
    struct StubVTable
    {
        void *methods[2];
    };
    StubVTable vtable{};
    vtable.methods[0] = const_cast<void *>(static_cast<const void *>(JMP_STUB_SLOT_BYTES));
    vtable.methods[1] = const_cast<void *>(static_cast<const void *>(RET_SLOT_BYTES));
    void *vptr = &vtable;

    Result<VmtHook> r = vmt_for("JmpStubVmt", &vptr, VmtOptions{.fail_on_non_function_pointer = true});
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
    EXPECT_EQ(vptr, static_cast<void *>(&vtable));
}

TEST(HookVmt, ApplyPreFlightRefusesInt3FirstSlot)
{
    // The apply path runs the same slot-0 pre-flight as create: applying onto an object whose current vtable starts
    // with an int3 slot must be refused.
    auto seed = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("ApplyPreFlightVmt", seed.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    struct Int3VTable
    {
        void *methods[2];
    };
    Int3VTable vtable{};
    vtable.methods[0] = const_cast<void *>(static_cast<const void *>(INT3_SLOT_BYTES));
    vtable.methods[1] = const_cast<void *>(static_cast<const void *>(RET_SLOT_BYTES));
    void *vptr = &vtable;

    Result<void> applied = vh.apply_to(&vptr, VmtOptions{.fail_on_non_function_pointer = true});
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(vptr, static_cast<void *>(&vtable));
}

TEST(HookVmt, ReleaseLeavesCloneInstalled)
{
    auto target = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(target.get());

    Result<VmtHook> r = vmt_for("ReleasedVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    vh.release();

    EXPECT_FALSE(static_cast<bool>(vh));
    // No vptr restore: the clone is leaked for the process lifetime, so the vptr still points at the clone.
    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr);
    // Manually restore so the stack object does not dispatch through a leaked clone after this scope.
    *reinterpret_cast<std::uintptr_t *>(target.get()) = original_vptr;
}

// ----------------------------------------------------------------------------
// Lifecycle events: typed transitions on the diagnostic bus
// ----------------------------------------------------------------------------
namespace
{
    struct CapturedLifecycle
    {
        std::string name;
        Diagnostics::HookKind kind;
        Diagnostics::HookTransition transition;
    };
} // namespace

TEST(HookLifecycle, InlineEventsAreEmitted)
{
    std::vector<CapturedLifecycle> events;
    auto sub =
        Diagnostics::hook_lifecycle().subscribe([&events](const Diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    {
        Result<Hook> r = inline_at(InlineRequest{.name = "LifecycleHook", .target = addr_of(&echo)}, &echo_detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        // Created on install, then a real disable -> enable transition pair, then Removed when h leaves scope.
        ASSERT_TRUE(h.disable().has_value());
        ASSERT_TRUE(h.enable().has_value());
    }

    ASSERT_EQ(events.size(), 4u);
    EXPECT_EQ(events[0].transition, Diagnostics::HookTransition::Created);
    EXPECT_EQ(events[1].transition, Diagnostics::HookTransition::Disabled);
    EXPECT_EQ(events[2].transition, Diagnostics::HookTransition::Enabled);
    EXPECT_EQ(events[3].transition, Diagnostics::HookTransition::Removed);
    for (const auto &e : events)
    {
        EXPECT_EQ(e.name, "LifecycleHook");
        EXPECT_EQ(e.kind, Diagnostics::HookKind::Inline);
    }
}

TEST(HookLifecycle, MidEventReportsMidKind)
{
    std::vector<CapturedLifecycle> events;
    auto sub =
        Diagnostics::hook_lifecycle().subscribe([&events](const Diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidLifecycleHook", .target = addr_of(&real_hook_target_mul)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    ASSERT_GE(events.size(), 1u);
    EXPECT_EQ(events[0].transition, Diagnostics::HookTransition::Created);
    EXPECT_EQ(events[0].kind, Diagnostics::HookKind::Mid);
}

TEST(HookLifecycle, VmtEventReportsVmtKind)
{
    auto target = std::make_unique<VmtTestTarget>();
    std::vector<CapturedLifecycle> events;
    auto sub =
        Diagnostics::hook_lifecycle().subscribe([&events](const Diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    {
        Result<VmtHook> r = vmt_for("VmtLifecycleHook", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook vh = std::move(*r);
    }

    ASSERT_EQ(events.size(), 2u);
    EXPECT_EQ(events[0].name, "VmtLifecycleHook");
    EXPECT_EQ(events[0].kind, Diagnostics::HookKind::Vmt);
    EXPECT_EQ(events[0].transition, Diagnostics::HookTransition::Created);
    EXPECT_EQ(events[1].name, "VmtLifecycleHook");
    EXPECT_EQ(events[1].kind, Diagnostics::HookKind::Vmt);
    EXPECT_EQ(events[1].transition, Diagnostics::HookTransition::Removed);
}

TEST(HookLifecycle, NotEmittedForFailedCreate)
{
    int count = 0;
    auto sub = Diagnostics::hook_lifecycle().subscribe([&count](const Diagnostics::HookLifecycleEvent &) { ++count; });

    // A failed create (null object) is not a transition, so nothing is emitted.
    Result<VmtHook> r = vmt_for("FailedVmtLifecycleHook", nullptr);
    EXPECT_FALSE(r.has_value());
    EXPECT_EQ(count, 0);
}

TEST(HookLifecycle, NotEmittedForNoOpTransition)
{
    std::vector<CapturedLifecycle> events;
    auto sub =
        Diagnostics::hook_lifecycle().subscribe([&events](const Diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    // Dedicated leak target: this test ends with release(), leaking the detour for the process lifetime.
    Result<Hook> r = inline_at(InlineRequest{.name = "NoOpLifecycleHook", .target = addr_of(&leak_target_lifecycle)},
                               &real_hook_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_EQ(events.size(), 1u); // Created only

    // The hook is already enabled, so a second enable() is a no-op and emits nothing.
    ASSERT_TRUE(h.enable().has_value());
    EXPECT_EQ(events.size(), 1u);
    h.release(); // detach without a Removed transition path through teardown
}
