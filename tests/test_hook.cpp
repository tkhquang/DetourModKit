#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include "internal/hook_ledger.hpp"

#include "test_alloc_probe.hpp"

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

// Real, hookable functions used as inline/mid hook targets. DMK_TEST_NOINLINE plus a volatile result forces a real call
// to the patched entry, so a post-teardown call observes the restored prologue rather than a constant-folded value.
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

// INLINE create + validation

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

// INLINE typed trampoline + enable/disable

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

// INLINE prologue policy
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

// INLINE duplicate detection (Options::fail_if_already_hooked + is_target_hooked)

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

// A foreign inline hook can redirect a prologue with a `mov rax, imm64; jmp rax` absolute-jump trampoline
// (48 B8 <imm64> FF E0) when its detour is beyond rel32 reach and it does not use the FF 25 RIP-relative form. The
// pre-flight foreign-JMP heuristic must decode that shape and, under fail_if_already_hooked, refuse.
TEST(HookInline, FailIfAlreadyHookedDetectsAbsJumpTrampoline)
{
    // Destination in a different module (kernel32) so the redirect classifies as HookedByOtherModule (foreign).
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(kernel32, nullptr);
    const auto foreign_destination = reinterpret_cast<std::uintptr_t>(GetProcAddress(kernel32, "Sleep"));
    ASSERT_NE(foreign_destination, 0u);

    // Plant 48 B8 <foreign_destination> FF E0 into a readable buffer and hook its address. The create fails at the
    // foreign-JMP pre-flight, before any backend touches the buffer, so a plain stack buffer is a valid target here.
    alignas(16) std::array<std::uint8_t, 16> abs_jump{};
    abs_jump[0] = 0x48; // REX.W
    abs_jump[1] = 0xB8; // mov rax, imm64
    std::memcpy(abs_jump.data() + 2, &foreign_destination, sizeof(foreign_destination));
    abs_jump[10] = 0xFF; // jmp
    abs_jump[11] = 0xE0; // rax

    Result<Hook> r = inline_at(InlineRequest{.name = "AbsJumpForeign",
                                             .target = Address{reinterpret_cast<std::uintptr_t>(abs_jump.data())},
                                             .options = Options{.fail_if_already_hooked = true}},
                               &echo_detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetAlreadyHookedInProcess);
}

// is_target_hooked(Address)

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

TEST(HookLedger, SameTargetReservationsWaitForCommit)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();
    static int target_marker = 0;
    const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(&target_marker);

    const DetourModKit::detail::HookLedger::Reservation first = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(first.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ASSERT_NE(first.id, 0u);

    std::atomic<bool> second_started{false};
    std::atomic<bool> second_returned{false};
    std::atomic<bool> allow_second_cleanup{false};
    std::uint64_t second_id = 0;

    auto wait_for_flag = [](const std::atomic<bool> &flag, int attempts) -> bool
    {
        for (int i = 0; i < attempts; ++i)
        {
            if (flag.load(std::memory_order_acquire))
            {
                return true;
            }
            Sleep(1);
        }
        return flag.load(std::memory_order_acquire);
    };

    std::thread waiter(
        [&]
        {
            second_started.store(true, std::memory_order_release);
            const DetourModKit::detail::HookLedger::Reservation second = ledger.try_reserve_hook(target, false);
            EXPECT_EQ(second.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
            EXPECT_TRUE(second.preexisting);
            second_id = second.id;
            second_returned.store(true, std::memory_order_release);
            while (!allow_second_cleanup.load(std::memory_order_acquire))
            {
                Sleep(1);
            }
            ledger.commit_hook(target, second.id);
            (void)ledger.release_hook(target, second.id);
        });

    // Wait for the waiter to enter try_reserve_hook. If it does not start in time, tear it down safely before
    // failing: an early return here would destroy a still-joinable std::thread and call std::terminate. Committing
    // first unblocks the waiter's pending reservation so the join cannot hang, and allow_second_cleanup releases its
    // post-reservation cleanup loop.
    if (!wait_for_flag(second_started, 100))
    {
        ledger.commit_hook(target, first.id);
        allow_second_cleanup.store(true, std::memory_order_release);
        waiter.join();
        (void)ledger.release_hook(target, first.id);
        FAIL() << "waiter thread did not start within the timeout";
    }
    EXPECT_FALSE(wait_for_flag(second_returned, 20));

    ledger.commit_hook(target, first.id);
    const bool second_completed = wait_for_flag(second_returned, 1000);
    EXPECT_TRUE(second_completed);
    EXPECT_NE(second_id, 0u);
    if (second_completed)
    {
        EXPECT_EQ(ledger.release_hook(target, first.id), 1u);
    }
    else
    {
        (void)ledger.release_hook(target, first.id);
    }

    allow_second_cleanup.store(true, std::memory_order_release);
    waiter.join();
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// Hook::call<Ret>(args): the guarded trampoline call, with the by-value-ABI lvalue case

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

// operator=(Hook&&) is the second teardown entry point the shared call gate must cover: adopting the source's hook
// transfers its gate atomically, tears down the overwritten hook (restoring its old target), and leaves the moved-into
// handle's guarded call() dispatching through the SOURCE's trampoline while the moved-from source is inert.
TEST(HookCall, MoveAssignTransfersGuardedCallAndTearsDownOld)
{
    Result<Hook> first = inline_at(InlineRequest{.name = "MoveAssignOld", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook dest = std::move(*first);
    EXPECT_EQ(echo(7), 107); // echo hooked by dest

    Result<Hook> second = inline_at(InlineRequest{.name = "MoveAssignNew", .target = addr_of(&real_hook_target_add)},
                                    &real_hook_detour_add);
    ASSERT_TRUE(second.has_value()) << second.error().message();
    Hook src = std::move(*second);

    // Move-assign src over dest: dest's old echo hook is torn down (echo restored) and dest adopts src's hook + gate.
    dest = std::move(src);
    EXPECT_EQ(echo(7), 7);                // dest's overwritten echo hook was restored by the discard teardown
    EXPECT_FALSE(static_cast<bool>(src)); // src is moved-from / inert
    EXPECT_EQ(src.call<int>(3), int{});   // a guarded call on the moved-from handle is a defined no-op (empty gate)

    ASSERT_TRUE(static_cast<bool>(dest));
    EXPECT_EQ(real_hook_target_add(2, 3), 2 + 3 + 1000); // dest's adopted detour is active
    EXPECT_EQ(dest.call<int>(2, 3), 5);                  // guarded call reaches the original through the trampoline
}

// release(): detach but stay installed for the process lifetime

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

// RAII teardown + moved-from inertness

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

// MID create / lifecycle (the MidContext-accessor semantics live in test_mid_hook_context.cpp)

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

// install_all: declarative table with severity + ordering + rollback
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

// install_all shares the never-terminate contract with scan::resolve_batch: it is noexcept and, under true
// out-of-memory, reports the failure in its own result shape rather than terminating the host. Its shape is a
// single Result<vector<InstallOutcome>>, so a container-allocation failure surfaces as unexpected(Error{OutOfMemory}),
// not an empty vector. Pin the noexcept property at compile time so a signature change cannot silently drop it.
static_assert(noexcept(install_all(std::span<const HookSpec>{})),
              "hook::install_all must be noexcept: it degrades under OOM rather than terminating the host.");

TEST(HookInstallAll, AllocFailureReturnsOutOfMemoryWithoutEscaping)
{
    const HookSpec table[] = {
        HookSpec::inline_hook("OomRow", resolvable_request("OomRowPat", &install_target_one), &install_detour_one,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res;
    {
        // Budget 0: the first allocation (the outcomes container reserve) fails before any row is attempted, so
        // install_all catches the bad_alloc at its noexcept boundary and reports Error{OutOfMemory}.
        dmk_test::AllocFailScope fail(0);
        res = install_all(table);
    }

    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::OutOfMemory);
    // The container failed before the first row, so nothing was installed.
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_one)));
}

// On a mandatory miss, install_all rolls the already-installed rows back NEWEST-FIRST. A std::vector<InstallOutcome>
// unwind would destroy them oldest-first (forward), which for hooks layered on one target restores an older hook's
// prologue over a newer hook's live trampoline (a use-after-free); install_all's InstallRollback guard pops back-to-
// front instead. The Removed lifecycle events make the teardown order observable without forcing a faulting repro.
TEST(HookInstallAll, MandatoryMissRollsBackNewestFirst)
{
    std::vector<std::string> removed;
    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&removed](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.transition == diagnostics::HookTransition::Removed)
            {
                removed.emplace_back(e.name);
            }
        });

    const HookSpec table[] = {
        HookSpec::inline_hook("RollbackOlder", resolvable_request("RbOlderPat", &install_target_one),
                              &install_detour_one, Severity::Mandatory),
        HookSpec::inline_hook("RollbackNewer", resolvable_request("RbNewerPat", &install_target_two),
                              &install_detour_two, Severity::Mandatory),
        HookSpec::inline_hook("RollbackMiss", unresolvable_request("RbMissPat"), &install_detour_one,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::NoMatch);

    // Both installed rows rolled back cleanly...
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_one)));
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_two)));
    // ...and newest-first: RollbackNewer (installed second) was torn down before RollbackOlder.
    ASSERT_EQ(removed.size(), 2u);
    EXPECT_EQ(removed[0], "RollbackNewer");
    EXPECT_EQ(removed[1], "RollbackOlder");
}

// VMT object hooking (RAII VmtHook)

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

// VMT method-hook test fixtures. The per-method surface installs a detour straight into a cloned vtable slot, so a
// detour models the virtual method's real ABI: the object arrives as the leading integer argument (`this` in rcx under
// the Win64 ABI) with no calling-convention decoration, because x64 has a single convention. The detour reaches the
// original through the handle's typed original<Fn>(index) snapshot, so nothing here names the SafetyHook backend.
//
// The vtable index counts virtual functions only and excludes the ABI header, but the leading destructor slots are
// counted: the Itanium ABI (GCC/MinGW) emits two destructor entries (complete + deleting) ahead of the first declared
// method, while MSVC emits one, so compute/transform sit one slot higher under Itanium.
#if defined(_MSC_VER)
static constexpr std::size_t VMT_COMPUTE_INDEX = 1;
static constexpr std::size_t VMT_TRANSFORM_INDEX = 2;
#else
static constexpr std::size_t VMT_COMPUTE_INDEX = 2;
static constexpr std::size_t VMT_TRANSFORM_INDEX = 3;
#endif

using VmtComputeFn = int (*)(void *self, int a, int b);
using VmtTransformFn = int (*)(void *self, int x);

// The detours reach the original virtual method through the handle, so the fixtures publish the live VmtHook* the way
// the inline-hook detours publish their Hook*. A null handle means "unhooked", so the detour falls back to a plain
// marker rather than dereferencing a stale pointer.
static VmtHook *s_method_vmt = nullptr;

class MethodVmtScope
{
public:
    explicit MethodVmtScope(VmtHook &hook) noexcept;

    ~MethodVmtScope() noexcept;

    MethodVmtScope(const MethodVmtScope &) = delete;
    MethodVmtScope &operator=(const MethodVmtScope &) = delete;
    MethodVmtScope(MethodVmtScope &&) = delete;
    MethodVmtScope &operator=(MethodVmtScope &&) = delete;

private:
    VmtHook *m_previous;
};

MethodVmtScope::MethodVmtScope(VmtHook &hook) noexcept : m_previous(s_method_vmt)
{
    s_method_vmt = &hook;
}

MethodVmtScope::~MethodVmtScope() noexcept
{
    s_method_vmt = m_previous;
}

// Hooked compute: original(this, a, b) + 1000.
int vmt_detour_compute(void *self, int a, int b)
{
    if (s_method_vmt == nullptr)
    {
        return -1;
    }
    const VmtComputeFn original = s_method_vmt->original<VmtComputeFn>(VMT_COMPUTE_INDEX);
    if (original == nullptr)
    {
        return -1;
    }
    return original(self, a, b) + 1000;
}

// Hooked transform: original(this, x) + 500, used to prove two independent slots hook without cross-talk.
int vmt_detour_transform(void *self, int x)
{
    if (s_method_vmt == nullptr)
    {
        return -1;
    }
    const VmtTransformFn original = s_method_vmt->original<VmtTransformFn>(VMT_TRANSFORM_INDEX);
    if (original == nullptr)
    {
        return -1;
    }
    return original(self, x) + 500;
}

// Dispatch the hook-sensitive checks through the VmtTestInterface base at a DMK_TEST_NOINLINE boundary. A VMT hook
// only takes effect through the object's (swapped) vtable, so a call the optimizer can devirtualize to the concrete
// VmtTestTarget would bypass the clone and silently stop testing the hook. Passing a base-class pointer into a
// noinline function that only sees VmtTestInterface forces the real runtime vtable dispatch, exactly as a game
// engine's polymorphic call would, on both the debug and any optimized test build.
DMK_TEST_NOINLINE int dispatch_compute(VmtTestInterface *object, int a, int b)
{
    return object->compute(a, b);
}

DMK_TEST_NOINLINE int dispatch_transform(VmtTestInterface *object, int x)
{
    return object->transform(x);
}

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

// A corrupted or forged vptr can point at an arbitrarily long run of executable-looking qwords. count_vmt_method_slots
// hard-caps the slot walk (mirroring the bounded RTTI walkers) so it cannot spin unbounded, failing closed on the
// malformed seed object -- which vmt_for surfaces as InvalidObject. Filling well past the internal cap with an
// executable address makes every slot read as callable, so the walk terminates only at the cap.
TEST(HookVmt, SlotWalkHardCapRejectsMalformedVtable)
{
    constexpr std::size_t OVER_CAP = 5000; // exceeds the internal MAX_VMT_SLOTS (4096)
    static std::vector<std::uintptr_t> fake_vtable(OVER_CAP, reinterpret_cast<std::uintptr_t>(&echo));
    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(fake_vtable.data())};

    Result<VmtHook> r = vmt_for("MalformedVtable", &object);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
}

// vmt_for must RELEASE the process-wide object gate BEFORE dispatching its Created lifecycle event: emit_lifecycle
// runs arbitrary subscriber code (CP.22 -- never call unknown code under a lock), and holding the non-recursive
// object mutex across it would let a subscriber that re-enters a VMT operation deadlock. This confirms the gate is
// free during the emit: a subscriber launches a concurrent VMT op on another object and it completes promptly. If the
// gate were still held, the concurrent op would block on it for the whole wait window (a regression fails this
// EXPECT_TRUE rather than hanging the suite -- the probe is on a separate thread with a bounded wait).
TEST(HookVmt, ObjectGateReleasedBeforeCreateLifecycleEmit)
{
    auto outer_target = std::make_unique<VmtTestTarget>();
    auto inner_target = std::make_unique<VmtTestTarget>();

    std::atomic<bool> reentered{false};
    std::atomic<bool> inner_done{false};
    std::atomic<bool> inner_ok{false};
    std::atomic<bool> inner_done_in_window{false};
    std::thread inner_thread;

    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.kind != diagnostics::HookKind::Vmt || e.transition != diagnostics::HookTransition::Created)
            {
                return;
            }
            // The concurrent vmt_for below also emits Created (on inner_thread); re-enter the probe only once.
            if (reentered.exchange(true))
            {
                return;
            }
            inner_thread = std::thread(
                [&]
                {
                    Result<VmtHook> inner = vmt_for("InnerConcurrent", inner_target.get());
                    inner_ok.store(inner.has_value(), std::memory_order_release);
                    inner_done.store(true, std::memory_order_release);
                    // `inner` (if present) destructs here, restoring inner_target's vptr under the free object gate.
                });
            // A released gate lets the concurrent vmt_for finish in microseconds; a still-held gate blocks it for the
            // whole window (this thread holds the gate, so it could only proceed after this outer vmt_for returns).
            for (int i = 0; i < 500 && !inner_done.load(std::memory_order_acquire); ++i)
            {
                Sleep(1);
            }
            inner_done_in_window.store(inner_done.load(std::memory_order_acquire), std::memory_order_release);
        });

    Result<VmtHook> outer = vmt_for("OuterConcurrent", outer_target.get());
    ASSERT_TRUE(outer.has_value()) << outer.error().message();
    VmtHook outer_hold = std::move(*outer);

    if (inner_thread.joinable())
    {
        inner_thread.join();
    }
    EXPECT_TRUE(reentered.load(std::memory_order_acquire)) << "the Created lifecycle event was never observed";
    EXPECT_TRUE(inner_done_in_window.load(std::memory_order_acquire))
        << "vmt_for held the object gate across its Created emit; a concurrent VMT op could not proceed";
    EXPECT_TRUE(inner_ok.load(std::memory_order_acquire)) << "the concurrent re-entrant vmt_for failed";
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

// VMT per-method hooking (hook_method / original<Fn>(index) / remove_method)

// A method hook redirects one vtable slot in the clone, and original<Fn>(index) reaches the pre-hook method: a hooked
// compute returns original + 1000, and the typed snapshot yields the unmodified sum.
TEST(HookVmtMethod, HookMethodRedirectsSlotAndOriginalReachesPreHook)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(dispatch_compute(target.get(), 3, 4), 7);

    Result<VmtHook> r = vmt_for("MethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());

    // Dispatch through the object now routes to the detour: original(3, 4) + 1000.
    EXPECT_EQ(dispatch_compute(target.get(), 3, 4), 1007);

    // The typed snapshot reaches the original body directly, so it yields the unmodified 7.
    auto *orig = vh.original<VmtComputeFn>(VMT_COMPUTE_INDEX);
    ASSERT_NE(orig, nullptr);
    EXPECT_EQ(orig(target.get(), 3, 4), 7);
}

// Two independent slots hook without cross-talk, and each original<Fn>(index) resolves to its own method.
TEST(HookVmtMethod, MultipleSlotsHookIndependently)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(dispatch_compute(target.get(), 2, 3), 5);
    EXPECT_EQ(dispatch_transform(target.get(), 6), 12);

    Result<VmtHook> r = vmt_for("MultiSlotVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    ASSERT_TRUE(vh.hook_method(VMT_TRANSFORM_INDEX, &vmt_detour_transform).has_value());

    EXPECT_EQ(dispatch_compute(target.get(), 2, 3), 1005);
    EXPECT_EQ(dispatch_transform(target.get(), 6), 512);
}

// Hooking the same slot twice is refused: a second install would read the first detour as the "original".
TEST(HookVmtMethod, DuplicateMethodHookFails)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("DupMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());

    Result<void> second = vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::MethodAlreadyHooked);
}

// A null detour is rejected before it can be stored into a vtable slot.
TEST(HookVmtMethod, NullDetourRejected)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("NullDetourVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    VmtComputeFn null_detour = nullptr;
    Result<void> hooked = vh.hook_method(VMT_COMPUTE_INDEX, null_detour);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidArg);
}

// An out-of-range index is rejected before the backend can index through the cloned vtable.
TEST(HookVmtMethod, OutOfRangeIndexRejected)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("OutOfRangeMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    constexpr std::size_t INVALID_INDEX = VMT_TRANSFORM_INDEX + 1;
    Result<void> hooked = vh.hook_method(INVALID_INDEX, &vmt_detour_compute);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidArg);
    EXPECT_EQ(dispatch_compute(target.get(), 4, 5), 9);
    EXPECT_EQ(vh.original<VmtComputeFn>(INVALID_INDEX), nullptr);
}

// remove_method restores the cloned slot; a second removal reports MethodNotFound.
TEST(HookVmtMethod, RemoveMethodRestoresSlot)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("RemMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    EXPECT_EQ(dispatch_compute(target.get(), 5, 5), 1010);

    ASSERT_TRUE(vh.remove_method(VMT_COMPUTE_INDEX).has_value());
    EXPECT_EQ(dispatch_compute(target.get(), 5, 5), 10);
    EXPECT_EQ(vh.original<VmtComputeFn>(VMT_COMPUTE_INDEX), nullptr);

    Result<void> re_remove = vh.remove_method(VMT_COMPUTE_INDEX);
    ASSERT_FALSE(re_remove.has_value());
    EXPECT_EQ(re_remove.error().code, ErrorCode::MethodNotFound);
}

// Dropping the whole handle restores the original method (the remove-entire-hook path for method hooks).
TEST(HookVmtMethod, DroppingHandleRestoresMethod)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(dispatch_compute(target.get(), 1, 2), 3);

    {
        Result<VmtHook> r = vmt_for("DropMethodVmt", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook vh = std::move(*r);
        MethodVmtScope method_scope(vh);

        ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
        EXPECT_EQ(dispatch_compute(target.get(), 1, 2), 1003);
    }

    // The handle's destructor restored the original vptr, so the method hook is gone with it.
    EXPECT_EQ(dispatch_compute(target.get(), 1, 2), 3);
}

// A method hook lives in one clone, so an object added later via apply_to inherits it; remove_from restores that
// object without disturbing the seed.
TEST(HookVmtMethod, MethodHookAppliesToAdditionalObjects)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("MultiObjMethodVmt", target1.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    EXPECT_EQ(dispatch_compute(target1.get(), 1, 1), 1002);
    EXPECT_EQ(dispatch_compute(target2.get(), 1, 1), 2);

    ASSERT_TRUE(vh.apply_to(target2.get()).has_value());
    EXPECT_EQ(dispatch_compute(target2.get(), 1, 1), 1002);

    ASSERT_TRUE(vh.remove_from(target2.get()).has_value());
    EXPECT_EQ(dispatch_compute(target2.get(), 1, 1), 2);
    EXPECT_EQ(dispatch_compute(target1.get(), 1, 1), 1002);
}

// original<Fn>(index) is a null snapshot for a slot that was never hooked.
TEST(HookVmtMethod, OriginalForUnhookedSlotIsNull)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("UnhookedSlotVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    EXPECT_EQ(vh.original<VmtComputeFn>(VMT_COMPUTE_INDEX), nullptr);
}

// A disengaged (moved-from) handle fails every per-method entry point closed: InvalidHookState for the mutators and a
// null snapshot for the reader, mirroring the flat Hook's moved-from contract.
TEST(HookVmtMethod, DisengagedHandleFailsClosed)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("DisengagedMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook a = std::move(*r);
    VmtHook b = std::move(a);
    EXPECT_TRUE(static_cast<bool>(b));

    Result<void> hooked = a.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidHookState);

    Result<void> removed = a.remove_method(VMT_COMPUTE_INDEX);
    ASSERT_FALSE(removed.has_value());
    EXPECT_EQ(removed.error().code, ErrorCode::InvalidHookState);

    EXPECT_EQ(a.original<VmtComputeFn>(VMT_COMPUTE_INDEX), nullptr);
}

// Lifecycle events: typed transitions on the diagnostic bus
namespace
{
    struct CapturedLifecycle
    {
        std::string name;
        diagnostics::HookKind kind;
        diagnostics::HookTransition transition;
    };
} // namespace

TEST(HookLifecycle, InlineEventsAreEmitted)
{
    std::vector<CapturedLifecycle> events;
    auto sub =
        diagnostics::hook_lifecycle().subscribe([&events](const diagnostics::HookLifecycleEvent &e)
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
    EXPECT_EQ(events[0].transition, diagnostics::HookTransition::Created);
    EXPECT_EQ(events[1].transition, diagnostics::HookTransition::Disabled);
    EXPECT_EQ(events[2].transition, diagnostics::HookTransition::Enabled);
    EXPECT_EQ(events[3].transition, diagnostics::HookTransition::Removed);
    for (const auto &e : events)
    {
        EXPECT_EQ(e.name, "LifecycleHook");
        EXPECT_EQ(e.kind, diagnostics::HookKind::Inline);
    }
}

TEST(HookLifecycle, MidEventReportsMidKind)
{
    std::vector<CapturedLifecycle> events;
    auto sub =
        diagnostics::hook_lifecycle().subscribe([&events](const diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidLifecycleHook", .target = addr_of(&real_hook_target_mul)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    ASSERT_GE(events.size(), 1u);
    EXPECT_EQ(events[0].transition, diagnostics::HookTransition::Created);
    EXPECT_EQ(events[0].kind, diagnostics::HookKind::Mid);
}

TEST(HookLifecycle, VmtEventReportsVmtKind)
{
    auto target = std::make_unique<VmtTestTarget>();
    std::vector<CapturedLifecycle> events;
    auto sub =
        diagnostics::hook_lifecycle().subscribe([&events](const diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    {
        Result<VmtHook> r = vmt_for("VmtLifecycleHook", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook vh = std::move(*r);
    }

    ASSERT_EQ(events.size(), 2u);
    EXPECT_EQ(events[0].name, "VmtLifecycleHook");
    EXPECT_EQ(events[0].kind, diagnostics::HookKind::Vmt);
    EXPECT_EQ(events[0].transition, diagnostics::HookTransition::Created);
    EXPECT_EQ(events[1].name, "VmtLifecycleHook");
    EXPECT_EQ(events[1].kind, diagnostics::HookKind::Vmt);
    EXPECT_EQ(events[1].transition, diagnostics::HookTransition::Removed);
}

TEST(HookLifecycle, NotEmittedForFailedCreate)
{
    int count = 0;
    auto sub = diagnostics::hook_lifecycle().subscribe([&count](const diagnostics::HookLifecycleEvent &) { ++count; });

    // A failed create (null object) is not a transition, so nothing is emitted.
    Result<VmtHook> r = vmt_for("FailedVmtLifecycleHook", nullptr);
    EXPECT_FALSE(r.has_value());
    EXPECT_EQ(count, 0);
}

TEST(HookLifecycle, NotEmittedForNoOpTransition)
{
    std::vector<CapturedLifecycle> events;
    auto sub =
        diagnostics::hook_lifecycle().subscribe([&events](const diagnostics::HookLifecycleEvent &e)
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

// Concurrency + reentrancy: the per-hook status machine and the call() guard under thread stress and self-reentry. The
// per-hook recursive_mutex is held across call(), and disable()/~Hook must drain that mutex before the trampoline can
// be restored or freed. These tests pin the caller-visible guarantees directly, including a parked original that keeps
// the guard held until the test releases it.
namespace
{
    // Reentrancy fixture: a recursive target whose self-call re-enters the hooked prologue, so a detour that forwards
    // through call() is invoked again on the SAME thread while call() already holds the per-hook guard.
    std::atomic<int> s_reentrant_detour_calls{0};
    Hook *s_reentrant_hook = nullptr;

    DMK_TEST_NOINLINE int reentrant_target(int n)
    {
        if (n <= 0)
        {
            return 0;
        }
        // The recursive call resolves to reentrant_target's patched entry, so each level re-enters the detour.
        return reentrant_target(n - 1) + 1;
    }

    int reentrant_detour(int n)
    {
        s_reentrant_detour_calls.fetch_add(1, std::memory_order_relaxed);
        // Forward to the original through the guarded call(): it re-acquires the per-hook recursive_mutex. The original
        // recurses back into this detour on the same thread, so the guard MUST be recursive or this self-deadlocks.
        return s_reentrant_hook->call<int>(n);
    }

    // Drain fixture: an original that parks inside call() (so call() keeps holding the guard) until the test releases
    // it, giving a second thread a window to attempt disable() and observe that it waits for the in-flight call.
    std::atomic<bool> s_original_parked{false};
    std::atomic<bool> s_release_original{false};

    DMK_TEST_NOINLINE int parking_original(int x)
    {
        s_original_parked.store(true, std::memory_order_release);
        while (!s_release_original.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        volatile int r = x;
        return r;
    }
} // namespace

TEST(HookConcurrency, ConcurrentEnableDisableIsRaceSafe)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "ConcEnableDisable", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    // Several threads hammer enable()/disable() on the same hook. The per-hook guard and status machine must fold the
    // storm into legal transitions, and the backend must remain callable afterward.
    constexpr int THREADS = 6;
    constexpr int ITERATIONS = 500;
    std::atomic<bool> go{false};
    std::vector<std::thread> pool;
    pool.reserve(THREADS);
    for (int t = 0; t < THREADS; ++t)
    {
        pool.emplace_back(
            [&h, &go, t]()
            {
                while (!go.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                for (int i = 0; i < ITERATIONS; ++i)
                {
                    if (((t + i) & 1) == 0)
                    {
                        (void)h.enable();
                    }
                    else
                    {
                        (void)h.disable();
                    }
                }
            });
    }
    go.store(true, std::memory_order_release);
    for (std::thread &worker : pool)
    {
        worker.join();
    }

    // The hook survived the storm: brought to a known state, both dispatch paths still work end to end.
    ASSERT_TRUE(h.enable().has_value());
    EXPECT_EQ(echo(7), 107);      // enabled: the detour adds 100
    EXPECT_EQ(h.call<int>(7), 7); // original body through the trampoline
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(echo(7), 7); // disabled: original prologue restored
}

TEST(HookConcurrency, ReentrantCallFromDetourRequiresRecursiveGuard)
{
    Result<Hook> r =
        inline_at(InlineRequest{.name = "Reentrant", .target = addr_of(&reentrant_target)}, &reentrant_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    s_reentrant_hook = &h;
    s_reentrant_detour_calls.store(0, std::memory_order_relaxed);

    // Invoking the hooked entry fires the detour, which forwards through the guarded call(); the original recurses into
    // the hooked entry, re-entering the detour on the same thread. call() holds a per-hook recursive_mutex across the
    // whole invocation, so the nested call() re-locks instead of self-deadlocking. A plain mutex would hang this line.
    const int result = reentrant_target(4);
    EXPECT_EQ(result, 4);                                                   // recursion adds 1 four times down to 0
    EXPECT_EQ(s_reentrant_detour_calls.load(std::memory_order_relaxed), 5); // detour fired at depths 4,3,2,1,0

    s_reentrant_hook = nullptr;
}

TEST(HookConcurrency, DisableDrainsAnInFlightCall)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "DrainCall", .target = addr_of(&parking_original)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    s_original_parked.store(false, std::memory_order_release);
    s_release_original.store(false, std::memory_order_release);

    // Thread A enters call(), which acquires the per-hook guard and runs the original; the original parks, so the guard
    // stays held for as long as the test wants.
    std::thread caller([&h]() { (void)h.call<int>(7); });
    while (!s_original_parked.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // Thread B attempts disable() while the call is parked. disable() acquires the SAME guard, so it MUST block until
    // the call releases it -- it must never free the trampoline out from under the in-flight original.
    std::atomic<bool> disable_started{false};
    std::atomic<bool> disable_returned{false};
    std::thread disabler(
        [&h, &disable_started, &disable_returned]()
        {
            disable_started.store(true, std::memory_order_release);
            (void)h.disable();
            disable_returned.store(true, std::memory_order_release);
        });
    while (!disable_started.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // While the original is parked the guard is physically held, so disable() must not complete. A broken drain
    // (disable freeing the trampoline without waiting) can flip this flag before the release below.
    for (int spin = 0; spin < 1000; ++spin)
    {
        ASSERT_FALSE(disable_returned.load(std::memory_order_acquire))
            << "disable() completed while a guarded call() was still in flight (drain violated)";
        std::this_thread::yield();
    }

    // Release the original; the call returns, the guard drops, and disable() drains through to completion.
    s_release_original.store(true, std::memory_order_release);
    disabler.join();
    caller.join();
    EXPECT_TRUE(disable_returned.load(std::memory_order_acquire));
    EXPECT_FALSE(h.is_enabled());
}
