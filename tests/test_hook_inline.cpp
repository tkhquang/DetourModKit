#include <gtest/gtest.h>
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "DetourModKit/hook.hpp"

#include "fixtures/proof_section.hpp"
#include "fixtures/scratch_page.hpp"
#include "fixtures/hook_fixture.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace dmk_test::hook_fixture;

namespace
{
    // Move-only by-value parameter target. A copy-constructible parameter cannot expose the guarded-dispatch defect:
    // only a move-only type makes an lvalue dispatch ill-formed at the call site.
    using OwnedIntFn = int (*)(std::unique_ptr<int>);

    DMK_PROOF_TARGET int consume_owned_int(std::unique_ptr<int> owned) noexcept
    {
        volatile int r = owned ? *owned : -1;
        return r;
    }

    int consume_owned_int_detour(std::unique_ptr<int> owned) noexcept
    {
        return owned ? *owned + 100 : -1;
    }

    struct CopyOnlyInt
    {
        int value;

        explicit CopyOnlyInt(int initial) noexcept : value(initial) {}
        CopyOnlyInt(const CopyOnlyInt &) = default;
        CopyOnlyInt &operator=(const CopyOnlyInt &) = default;
        CopyOnlyInt(CopyOnlyInt &&) = delete;
        CopyOnlyInt &operator=(CopyOnlyInt &&) = delete;
        ~CopyOnlyInt() noexcept = default;
    };

    using CopyOnlyIntFn = int (*)(CopyOnlyInt);

    DMK_PROOF_TARGET int consume_copy_only_int(CopyOnlyInt owned) noexcept
    {
        volatile int result = owned.value;
        return result;
    }

    int consume_copy_only_int_detour(CopyOnlyInt owned) noexcept
    {
        return owned.value + 100;
    }
} // namespace

// INLINE create + validation

TEST(HookInline, CreateSucceedsDisabled)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "InlineCreate",
            .target = addr_of(&real_hook_target_add),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();

    Hook h = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(h));
    EXPECT_FALSE(h.is_enabled()); // [B-83] governs the disabled install.
    EXPECT_EQ(h.name(), "InlineCreate");

    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
}

TEST(HookInline, CreateInvalidTargetAddress)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "BadTarget",
            .target = Address{std::uintptr_t{0}},
        },
        &real_hook_detour_add
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidTargetAddress);
}

TEST(HookInline, CreateNullDetour)
{
    EchoFn null_detour = nullptr;
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "NullDetour",
            .target = addr_of(&real_hook_target_add),
        },
        null_detour
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidDetourFunction);
}

TEST(HookInline, CreateEmptyName)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "",
            .target = addr_of(&real_hook_target_add),
        },
        &real_hook_detour_add
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidArg);
}

// INLINE typed trampoline + enable/disable

TEST(HookInline, TypedTrampolineCallsOriginal)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "Trampoline",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    // The detour is active: echo(7) routes through echo_detour -> 107.
    EXPECT_EQ(call_unfolded(&echo, 7), 107);

    // The typed trampoline reaches the original body, so it yields the unmodified 7.
    auto *orig = h.original<EchoFn>();
    ASSERT_NE(orig, nullptr);
    EXPECT_EQ(orig(7), 7);
}

TEST(HookInline, EnableDisableTogglesDetour)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "Toggle",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&echo, 7), 107);

    ASSERT_TRUE(h.disable().has_value());
    EXPECT_FALSE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&echo, 7), 7); // original body restored while disabled

    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&echo, 7), 107);
}

TEST(HookInline, EnableDisableAreIdempotent)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "Idempotent",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    ASSERT_TRUE(h.enable().has_value());
    ASSERT_TRUE(h.enable().has_value()); // already enabled
    EXPECT_TRUE(h.is_enabled());
    ASSERT_TRUE(h.disable().has_value());
    ASSERT_TRUE(h.disable().has_value()); // already disabled
    EXPECT_FALSE(h.is_enabled());
}

// A moved-from inline handle is a mid-hook-style nullptr for original<Fn>() too, but the primary inert guarantee is in
// HookTeardown.MovedFromHandleIsInert (test_hook_teardown.cpp). Here we pin that the typed trampoline is non-null only
// for a live inline hook.
TEST(HookInline, OriginalNullForDisengagedHandle)
{
    // Uses a dedicated leak target: release() leaves the detour installed for the process lifetime.
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "Disengaged",
            .target = addr_of(&leak_target_disengaged),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    h.release(); // detach: handle becomes disengaged
    EXPECT_FALSE(static_cast<bool>(h));
    EXPECT_EQ(h.original<EchoFn>(), nullptr);
}

// INLINE prologue policy
namespace
{
    // Plants a prologue at the start of a fresh executable page and returns the install result.
    Result<Hook> install_on_planted_prologue(
        dmk_test::ScratchPage &page,
        const char *name,
        std::initializer_list<std::uint8_t> prologue,
        Options options = {}
    )
    {
        page.put(0, prologue);
        return inline_at(
            InlineRequest{
                .name = name,
                .target = Address{page.addr(0)},
                .options = options,
            },
            reinterpret_cast<void (*)()>(&noop_detour)
        );
    }

    //   +0x000  E8 <rel32 to +0x100>   call callee
    //   +0x005  C3                     ret            (returns the callee's EAX)
    //   +0x100  B8 <imm32> C3          mov eax, MAGIC; ret
    //
    // The callee shares the target page, so a nearby trampoline remains within rel32 reach. Separate allocations make
    // relocation depend on OS placement.
    constexpr std::size_t LEADING_CALL_CALLEE_OFFSET = 0x100;

    void plant_leading_call_fixture(dmk_test::ScratchPage &page) noexcept
    {
        const std::int32_t disp =
            static_cast<std::int32_t>(LEADING_CALL_CALLEE_OFFSET) - 5; // rel32 is relative to the next instruction
        page.put(
            0,
            {0xE8,
             static_cast<std::uint8_t>(disp & 0xFF),
             static_cast<std::uint8_t>((disp >> 8) & 0xFF),
             static_cast<std::uint8_t>((disp >> 16) & 0xFF),
             static_cast<std::uint8_t>((disp >> 24) & 0xFF),
             0xC3}
        );
        page.put(
            LEADING_CALL_CALLEE_OFFSET,
            {0xB8,
             static_cast<std::uint8_t>(LEADING_CALL_CALLEE_VALUE & 0xFF),
             static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 8) & 0xFF),
             static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 16) & 0xFF),
             static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 24) & 0xFF),
             0xC3}
        );
        FlushInstructionCache(GetCurrentProcess(), page.base(), dmk_test::ScratchPage::PAGE_SIZE);
    }
} // namespace

// A leading 0xCC (int3) prologue is already a breakpoint (a foreign hook's stub, a patched byte, or padding), not a
// real function body. The default Fail policy must refuse. Planted on an executable page so the refusal is proven to
// come from the breakpoint classifier and not from the steal-window gate ahead of it.
TEST(HookInlinePrologue, DefaultFailsOnInt3Prologue)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    Result<Hook> r = install_on_planted_prologue(page, "Int3Prologue", {0xCC, 0xC3, 0x90, 0x90});
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// The leading 0xCD identifies the two-byte breakpoint form.
TEST(HookInlinePrologue, DefaultFailsOnIntNPrologue)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    Result<Hook> r = install_on_planted_prologue(page, "IntNPrologue", {0xCD, 0x03, 0xC3, 0x90});
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// The default policy must never refuse a normal real-function target: a normal prologue installs with no false
// TargetPrologueUnsafe.
TEST(HookInlinePrologue, DefaultInstallsOnNormalTarget)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "NormalPrologue",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << "Default policy must not refuse a normal function prologue: " << r.error().message();
    EXPECT_TRUE(static_cast<bool>(*r));
}

// The backend relocates the leading rel32 call. The target and trampoline must preserve their distinct results.
TEST(HookInlinePrologue, LeadingRel32CallUsesBackendCapability)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leading_call_fixture(page);

    auto target = reinterpret_cast<int (*)()>(page.addr(0));

    // Control: unhooked, the leading call reaches the callee and the target returns its value.
    ASSERT_EQ(target(), LEADING_CALL_CALLEE_VALUE);

    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "LeadingRel32Call",
            .target = Address{page.addr(0)},
        },
        reinterpret_cast<void (*)()>(&leading_call_detour)
    );
    ASSERT_TRUE(r.has_value()) << "A backend-relocatable leading E8 rel32 call must not be refused by DMK under the "
                                  "default policy: "
                               << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(static_cast<bool>(h));
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    // The detour runs instead of the target, proving the patch is live rather than merely reported.
    EXPECT_EQ(target(), LEADING_CALL_DETOUR_VALUE);

    // The relocated prologue still dispatches its call to the same callee.
    auto original = h.original<int (*)()>();
    ASSERT_NE(original, nullptr);
    EXPECT_EQ(original(), LEADING_CALL_CALLEE_VALUE)
        << "The relocated leading call must still dispatch to its original callee.";

    // Restoring must put the original prologue back and re-expose the callee's value.
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(target(), LEADING_CALL_CALLEE_VALUE);
}

// Prologue::Relocate changes shape policy. It cannot authorize non-executable or uncommitted bytes.
TEST(HookInlinePrologue, RelocatePolicyStillRefusesNonExecutableTarget)
{
    alignas(16) static std::uint8_t data_prologue[32] = {0x90, 0x90, 0x90, 0x90, 0x90, 0xC3};
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "RelocateData",
            .target = addr_of(data_prologue),
            .options = Options{.prologue = Prologue::Relocate},
        },
        reinterpret_cast<void (*)()>(&noop_detour)
    );
    ASSERT_FALSE(r.has_value()) << "Prologue::Relocate must not authorize a non-executable target.";
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// INLINE duplicate detection (Options::fail_if_already_hooked + is_target_hooked)

TEST(HookInline, FailIfAlreadyHookedRefusesSecondHook)
{
    Result<Hook> first = inline_at(
        InlineRequest{
            .name = "DupBase",
            .target = addr_of(&real_hook_target_add),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook base = std::move(*first);

    Result<Hook> second = inline_at(
        InlineRequest{
            .name = "DupSecond",
            .target = addr_of(&real_hook_target_add),
            .options = Options{.fail_if_already_hooked = true},
        },
        &real_hook_detour_add
    );
    ASSERT_FALSE(second.has_value());
    // The ledger refuses before the prologue decode runs, so this is the same-kit mechanism, not the foreign one.
    EXPECT_EQ(second.error().code, ErrorCode::TargetAlreadyHookedByThisKit);
    EXPECT_EQ(to_string(second.error().code), "TargetAlreadyHookedByThisKit");
}

TEST(HookInline, DefaultModeLayersSecondHook)
{
    Result<Hook> first = inline_at(
        InlineRequest{
            .name = "LayerBase",
            .target = addr_of(&real_hook_target_mul),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook base = std::move(*first);

    // Default mode (fail_if_already_hooked = false): the second hook simply layers on top.
    Result<Hook> second = inline_at(
        InlineRequest{
            .name = "LayerSecond",
            .target = addr_of(&real_hook_target_mul),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(second.has_value()) << second.error().message();
    Hook layer = std::move(*second);
    // Teardown is newest-first by natural reverse-order destruction: layer (declared last) is destroyed before base.
}

// The foreign `mov rax, imm64; jmp rax` uses 48 B8 <imm64> FF E0 instead of FF 25. Strict duplicate policy must
// recognize it.
TEST(HookInline, FailIfAlreadyHookedDetectsAbsJumpTrampoline)
{
    // Destination in a different module (kernel32) so the redirect classifies as HookedByOtherModule (foreign).
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(kernel32, nullptr);
    const auto foreign_destination = reinterpret_cast<std::uintptr_t>(GetProcAddress(kernel32, "Sleep"));
    ASSERT_NE(foreign_destination, 0u);

    // Executable memory passes the code gate before foreign-hook classification. A ledger-free address isolates that
    // classifier from same-kit refusal. No hook installs on this page.
    std::vector<std::unique_ptr<dmk_test::ScratchPage>> pages;
    dmk_test::ScratchPage *page = acquire_ledger_free_page(pages);
    ASSERT_NE(page, nullptr) << "no scratch page could be committed free of a ledger record, so the decode could not "
                                "be isolated as the only possible refuser";

    // Plant 48 B8 <foreign_destination> FF E0.
    page->put(0, {0x48, 0xB8}); // mov rax, imm64
    std::memcpy(reinterpret_cast<void *>(page->addr(2)), &foreign_destination, sizeof(foreign_destination));
    page->put(10, {0xFF, 0xE0}); // jmp rax

    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "AbsJumpForeign",
            .target = Address{page->addr(0)},
            .options = Options{.fail_if_already_hooked = true},
        },
        &echo_detour
    );
    ASSERT_FALSE(r.has_value());
    // The ledger was asserted blind to this address above, so only the foreign-JMP decode can be the refuser.
    EXPECT_EQ(r.error().code, ErrorCode::TargetAlreadyHookedByAnotherModule);
    EXPECT_EQ(to_string(r.error().code), "TargetAlreadyHookedByAnotherModule");
}

// The detour destination belongs to no module. A comparison that requires two distinct module handles misses this
// private-trampoline case.
TEST(HookInline, FailIfAlreadyHookedDetectsAJumpIntoModulelessMemory)
{
    dmk_test::ScratchPage destination;
    ASSERT_TRUE(destination.ok());
    HMODULE owner = nullptr;
    ASSERT_FALSE(GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(destination.addr(0)),
        &owner
    )) << "a private page must belong to no module, or this case degenerates into the kernel32 one above";

    // Same ledger-blindness requirement as the case above.
    std::vector<std::unique_ptr<dmk_test::ScratchPage>> pages;
    dmk_test::ScratchPage *page = acquire_ledger_free_page(pages);
    ASSERT_NE(page, nullptr) << "no scratch page could be committed free of a ledger record, so the decode could not "
                                "be isolated as the only possible refuser";

    const std::uintptr_t moduleless_destination = destination.addr(0);
    page->put(0, {0x48, 0xB8}); // mov rax, imm64
    std::memcpy(reinterpret_cast<void *>(page->addr(2)), &moduleless_destination, sizeof(moduleless_destination));
    page->put(10, {0xFF, 0xE0}); // jmp rax

    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "AbsJumpModuleless",
            .target = Address{page->addr(0)},
            .options = Options{.fail_if_already_hooked = true},
        },
        &echo_detour
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetAlreadyHookedByAnotherModule);
}

// Hook::call<Ret>(args): the guarded trampoline call, with the by-value-ABI lvalue case

TEST(HookCall, GuardedCallReachesOriginalThroughTrampoline)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "GuardedCall",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    // A direct echo(7) returns 107. The guarded call reaches the original result, 7.
    EXPECT_EQ(call_unfolded(&echo, 7), 107);
    EXPECT_EQ(h.call<int>(7), 7);
}

// An lvalue must retain the by-value ABI. A reference-parameter function pointer passes an address where the trampoline
// expects a scalar.
TEST(HookCall, GuardedCallPassesLvalueByValue)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "GuardedLvalue",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    int lv = 7;
    EXPECT_EQ(h.call<int>(lv), 7) << "lvalue int must be passed by value through the trampoline";
}

// After disable(), call() observes an inactive hook and returns a value-initialized Ret (0 for int).
TEST(HookCall, GuardedCallReturnsValueInitWhenInactive)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "GuardedInactive",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(h.call<int>(7), int{});
}

// Move assignment transfers the source gate and restores the replaced target. The moved-from handle stays inert,
// and the destination calls through the source trampoline.
TEST(HookCall, MoveAssignTransfersGuardedCallAndTearsDownOld)
{
    Result<Hook> first = inline_at(
        InlineRequest{
            .name = "MoveAssignOld",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook dest = std::move(*first);
    ASSERT_TRUE(dest.enable().has_value()) << "dest enable failed";
    EXPECT_EQ(call_unfolded(&echo, 7), 107); // echo hooked by dest

    Result<Hook> second = inline_at(
        InlineRequest{
            .name = "MoveAssignNew",
            .target = addr_of(&real_hook_target_add),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(second.has_value()) << second.error().message();
    Hook src = std::move(*second);
    ASSERT_TRUE(src.enable().has_value()) << "src enable failed";

    // Move-assign src over dest: dest's old echo hook is torn down (echo restored) and dest adopts src's hook + gate.
    dest = std::move(src);
    // dest's overwritten echo hook was restored by the discard teardown
    EXPECT_EQ(call_unfolded(&echo, 7), 7);
    EXPECT_FALSE(static_cast<bool>(src)); // src is moved-from / inert
    EXPECT_EQ(src.call<int>(3), int{});   // a guarded call on the moved-from handle is a defined no-op (empty gate)

    ASSERT_TRUE(static_cast<bool>(dest));
    EXPECT_EQ(call_unfolded(&real_hook_target_add, 2, 3), 2 + 3 + 1000); // dest's adopted detour is active
    EXPECT_EQ(dest.call<int>(2, 3), 5); // guarded call reaches the original through the trampoline
}

// try_call distinguishes a suppressed call from a genuine value-initialized result through Result<Ret>.
TEST(HookCall, TryCallReachesOriginalAndReturnsValue)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "TryCallActive",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    const Result<int> got = h.try_call<int>(7);
    ASSERT_TRUE(got.has_value()) << got.error().message();
    EXPECT_EQ(*got, 7);
}

// A suppressed call<int>(7) and an original result of zero share one value. try_call distinguishes them through its
// error channel.
TEST(HookCall, TryCallFailsClosedWhenInactive)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "TryCallInactive",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(h.call<int>(7), int{});
    const Result<int> got = h.try_call<int>(7);
    ASSERT_FALSE(got.has_value());
    EXPECT_EQ(got.error().code, ErrorCode::InvalidHookState);
}

// try_call<void> carries no value but still reports whether the call dispatched, so a void original can be guarded too.
TEST(HookCall, TryCallVoidReportsDispatchAndFailClosed)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "TryCallVoid",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    const Result<void> active = h.try_call<void, int>(7);
    EXPECT_TRUE(active.has_value()) << (active ? "" : active.error().message());

    ASSERT_TRUE(h.disable().has_value());
    const Result<void> inactive = h.try_call<void, int>(7);
    ASSERT_FALSE(inactive.has_value());
    EXPECT_EQ(inactive.error().code, ErrorCode::InvalidHookState);
}

// The guarded dispatch moves a move-only value into the original. If it passes the local as an lvalue, this test fails
// to compile.
TEST(HookCall, CallMoveOnlyByValueReachesOriginal)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "GuardedMoveOnly",
            .target = addr_of(&consume_owned_int),
        },
        &consume_owned_int_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    // A direct call returns 141. The guarded call reaches the original result, 41.
    OwnedIntFn const volatile direct = &consume_owned_int;
    EXPECT_EQ(direct(std::make_unique<int>(41)), 141);
    EXPECT_EQ(h.call<int>(std::make_unique<int>(41)), 41);
}

// try_call shares the dispatch, so it carries the same forwarding contract.
TEST(HookCall, TryCallMoveOnlyByValueReachesOriginal)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "TryCallMoveOnly",
            .target = addr_of(&consume_owned_int),
        },
        &consume_owned_int_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    const Result<int> got = h.try_call<int>(std::make_unique<int>(41));
    ASSERT_TRUE(got.has_value()) << got.error().message();
    EXPECT_EQ(*got, 41);

    ASSERT_TRUE(h.disable().has_value());
    const Result<int> suppressed = h.try_call<int>(std::make_unique<int>(41));
    ASSERT_FALSE(suppressed.has_value());
    EXPECT_EQ(suppressed.error().code, ErrorCode::InvalidHookState);
}

TEST(HookCall, CallCopyOnlyByValueReachesOriginal)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "GuardedCopyOnly",
            .target = addr_of(&consume_copy_only_int),
        },
        &consume_copy_only_int_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    const CopyOnlyInt value{41};
    CopyOnlyIntFn const volatile direct = &consume_copy_only_int;
    EXPECT_EQ(direct(value), 141);
    EXPECT_EQ(h.call<int>(value), 41);
}

TEST(HookCall, TryCallCopyOnlyByValueReachesOriginal)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "TryCallCopyOnly",
            .target = addr_of(&consume_copy_only_int),
        },
        &consume_copy_only_int_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    const CopyOnlyInt value{41};
    const Result<int> got = h.try_call<int>(value);
    ASSERT_TRUE(got.has_value()) << got.error().message();
    EXPECT_EQ(*got, 41);
}

// A moved-from handle has an empty gate: try_call fails closed just as call() no-ops, but reports it as an error.
TEST(HookCall, TryCallOnMovedFromHandleFailsClosed)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "TryCallMovedFrom",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    Hook moved = std::move(h);

    const Result<int> got = h.try_call<int>(3);
    ASSERT_FALSE(got.has_value());
    EXPECT_EQ(got.error().code, ErrorCode::InvalidHookState);
}
