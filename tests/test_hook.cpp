#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include "internal/hook_publication.hpp"
#include "internal/hook_ledger.hpp"

#include "fixtures/proof_section.hpp"
#include "fixtures/scratch_page.hpp"
#include "test_alloc_probe.hpp"
#include "fixtures/hook_fixture.hpp"
#include "fixtures/log_capture.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace dmk_test::hook_fixture;

// The volatile target result prevents a post-teardown call from becoming a constant-folded substitute for the restored
// entry.
namespace
{
    DMK_PROOF_TARGET int leak_target_mid(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_PROOF_TARGET int leak_target_lifecycle(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_PROOF_TARGET int witness_failure_inline_target(int value)
    {
        const volatile int result = value + 17;
        return result;
    }

    DMK_PROOF_TARGET int witness_failure_mid_target(int a, int b)
    {
        const volatile int result = a - b;
        return result;
    }

    DMK_PROOF_TARGET int publication_proof_target(int value)
    {
        const volatile int result = value + 1;
        return result;
    }

    DMK_PROOF_TARGET int publication_proof_mid_target(int a, int b)
    {
        const volatile int result = a * b;
        return result;
    }

    DMK_PROOF_TARGET int oom_publication_target(int value)
    {
        const volatile int result = value + 3;
        return result;
    }

    int oom_publication_detour(int value)
    {
        return value + 500;
    }

    std::atomic<int> s_mid_detour_calls{0};
} // namespace

// Leak-on-purpose scenarios require dedicated function addresses so their retained patches cannot alias another target.
TEST(HookTargetIsolation, DistinctTargetsDoNotShareAnAddress)
{
    const std::array<std::pair<const char *, std::uintptr_t>, 21> targets{{
        {"echo", reinterpret_cast<std::uintptr_t>(&echo)},
        {"real_hook_target_add", reinterpret_cast<std::uintptr_t>(&real_hook_target_add)},
        {"real_hook_target_mul", reinterpret_cast<std::uintptr_t>(&real_hook_target_mul)},
        {"leak_target_inline", reinterpret_cast<std::uintptr_t>(&leak_target_inline)},
        {"leak_target_disengaged", reinterpret_cast<std::uintptr_t>(&leak_target_disengaged)},
        {"leak_target_mid", reinterpret_cast<std::uintptr_t>(&leak_target_mid)},
        {"leak_target_lifecycle", reinterpret_cast<std::uintptr_t>(&leak_target_lifecycle)},
        {"leak_target_layered", reinterpret_cast<std::uintptr_t>(&leak_target_layered)},
        {"leak_target_ledger_sync", reinterpret_cast<std::uintptr_t>(&leak_target_ledger_sync)},
        {"ledger_commit_failure_target", reinterpret_cast<std::uintptr_t>(&ledger_commit_failure_target)},
        {"witness_failure_inline_target", reinterpret_cast<std::uintptr_t>(&witness_failure_inline_target)},
        {"witness_failure_mid_target", reinterpret_cast<std::uintptr_t>(&witness_failure_mid_target)},
        {"publication_proof_target", reinterpret_cast<std::uintptr_t>(&publication_proof_target)},
        {"publication_proof_mid_target", reinterpret_cast<std::uintptr_t>(&publication_proof_mid_target)},
        {"oom_publication_target", reinterpret_cast<std::uintptr_t>(&oom_publication_target)},
        {"leak_target_retained_id", reinterpret_cast<std::uintptr_t>(&leak_target_retained_id)},
        {"leak_target_retained_newer", reinterpret_cast<std::uintptr_t>(&leak_target_retained_newer)},
        {"leak_target_retained_conflict", reinterpret_cast<std::uintptr_t>(&leak_target_retained_conflict)},
        {"leak_target_release_booked", reinterpret_cast<std::uintptr_t>(&leak_target_release_booked)},
        {"leak_target_release_disabled", reinterpret_cast<std::uintptr_t>(&leak_target_release_disabled)},
        {"leak_target_retained_strict", reinterpret_cast<std::uintptr_t>(&leak_target_retained_strict)},
    }};

    for (std::size_t i = 0; i < targets.size(); ++i)
    {
        for (std::size_t j = i + 1; j < targets.size(); ++j)
        {
            EXPECT_NE(targets[i].second, targets[j].second) << targets[i].first << " and " << targets[j].first
                                                            << " share an address, so a hook on either lands on both";
        }
    }
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
        Result<Hook> r = inline_at(
            InlineRequest{
                .name = "LedgerLive",
                .target = target,
            },
            &real_hook_detour_add
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        EXPECT_TRUE(is_target_hooked(target));
    }
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
            EXPECT_TRUE(ledger.commit_hook(target, second.id));
            (void)ledger.release_hook(target, second.id);
        }
    );

    // A fatal assertion before the join terminates the process. The pending reservation needs a commit, and its cleanup
    // loop needs allow_second_cleanup.
    if (!wait_for_flag(second_started, 100))
    {
        EXPECT_TRUE(ledger.commit_hook(target, first.id));
        allow_second_cleanup.store(true, std::memory_order_release);
        waiter.join();
        (void)ledger.release_hook(target, first.id);
        FAIL() << "waiter thread did not start within the timeout";
    }
    EXPECT_FALSE(wait_for_flag(second_returned, 20));

    ASSERT_TRUE(ledger.commit_hook(target, first.id));
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

// MID create / lifecycle (the MidContext-accessor semantics live in test_mid_hook_context.cpp)

TEST(HookMid, CreateSucceedsDisabled)
{
    auto detour = [](MidContext &) { s_mid_detour_calls.fetch_add(1, std::memory_order_relaxed); };
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidCreate",
            .target = addr_of(&real_hook_target_add),
        },
        detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(h));
    EXPECT_FALSE(h.is_enabled()); // [B-83] governs the disabled install.
    EXPECT_EQ(h.name(), "MidCreate");

    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
}

TEST(HookMid, CreateInvalidTargetAddress)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidBadTarget",
            .target = Address{std::uintptr_t{0}},
        },
        detour
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidTargetAddress);
}

TEST(HookMid, CreateNullDetour)
{
    MidHookFn null_detour = nullptr;
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidNullDetour",
            .target = addr_of(&real_hook_target_add),
        },
        null_detour
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidDetourFunction);
}

TEST(HookMid, CreateEmptyName)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "",
            .target = addr_of(&real_hook_target_add),
        },
        detour
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidArg);
}

TEST(HookMid, EnableDisableToggles)
{
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidToggle",
            .target = addr_of(&real_hook_target_add),
        },
        detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    EXPECT_TRUE(h.is_enabled());
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_FALSE(h.is_enabled());
    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
}

// A mid hook has no callable original.
TEST(HookMid, OriginalIsNullForMidHook)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidNoOriginal",
            .target = addr_of(&real_hook_target_add),
        },
        detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    EXPECT_EQ(h.original<EchoFn>(), nullptr);
}

TEST(HookMid, FailIfAlreadyHookedRefusesSecondMid)
{
    auto detour = [](MidContext &) {};
    Result<Hook> first = mid_at(
        MidRequest{
            .name = "MidDupBase",
            .target = addr_of(&real_hook_target_mul),
        },
        detour
    );
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook base = std::move(*first);

    Result<Hook> second = mid_at(
        MidRequest{
            .name = "MidDupSecond",
            .target = addr_of(&real_hook_target_mul),
            .options = Options{.fail_if_already_hooked = true},
        },
        detour
    );
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::TargetAlreadyHookedByThisKit);
}

// A strict mid install overlaps an existing inline patch. The ledger duplicate check must span hook types.
TEST(HookMid, FailIfAlreadyHookedRefusesOverInline)
{
    Result<Hook> inl = inline_at(
        InlineRequest{
            .name = "MidOverInlineBase",
            .target = addr_of(&real_hook_target_add),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(inl.has_value()) << inl.error().message();
    Hook base = std::move(*inl);

    auto detour = [](MidContext &) {};
    Result<Hook> mid = mid_at(
        MidRequest{
            .name = "MidOverInline",
            .target = addr_of(&real_hook_target_add),
            .options = Options{.fail_if_already_hooked = true},
        },
        detour
    );
    ASSERT_FALSE(mid.has_value());
    EXPECT_EQ(mid.error().code, ErrorCode::TargetAlreadyHookedByThisKit);
}

// A mid hook shares the inline pre-flight, so the breakpoint refusal in HookInlinePrologue.DefaultFailsOnInt3Prologue
// must hold here too.
// Planted on an executable page so the refusal comes from the breakpoint classifier, not the steal-window gate.
TEST(HookMid, DefaultFailsOnInt3Prologue)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0, {0xCC, 0xC3, 0x90, 0x90});
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidInt3Prologue",
            .target = Address{page.addr(0)},
        },
        detour
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// The mid pre-flight shares the inline steal-window gate: a target that is not executable committed memory is refused
// before the backend can decode it.
TEST(HookMid, DefaultRefusesNonExecutableTarget)
{
    alignas(16) static std::uint8_t mid_data_prologue[32] = {0x90, 0x90, 0x90, 0x90, 0x90, 0xC3};
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidDataTarget",
            .target = addr_of(mid_data_prologue),
        },
        detour
    );
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
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidRealCreate",
            .target = addr_of(&real_hook_target_add),
        },
        detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    // The unhooked body returns 5. With rcx := 1000, the resumed body returns 1003.
    EXPECT_EQ(call_unfolded(&real_hook_target_add, 2, 3), 1000 + 3);
}

TEST(HookMid, RealCreateDisabledRestoresOriginal)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidRealDisabled",
            .target = addr_of(&real_hook_target_add),
        },
        detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    EXPECT_EQ(call_unfolded(&real_hook_target_add, 2, 3), 1000 + 3);
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(call_unfolded(&real_hook_target_add, 2, 3), 5); // original body again
}

TEST(HookMid, TeardownRestoresOriginal)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 20);
    {
        auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 10; };
        Result<Hook> r = mid_at(
            MidRequest{
                .name = "MidTeardown",
                .target = addr_of(&real_hook_target_mul),
            },
            detour
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        ASSERT_TRUE(h.enable().has_value());
        EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 10 * 5);
    }
    EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 20); // prologue restored
}

TEST(HookMid, ReleaseLeavesMidInstalled)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    // Dedicated leak target: the released mid hook stays installed for the process lifetime.
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidReleased",
            .target = addr_of(&leak_target_mid),
        },
        detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value());

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
    EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 20);
    {
        auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 10; };
        Result<Hook> r = mid_at(
            MidRequest{
                .name = "MidMovedFrom",
                .target = addr_of(&real_hook_target_mul),
            },
            detour
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook a = std::move(*r);
        ASSERT_TRUE(a.enable().has_value());
        Hook b = std::move(a);
        EXPECT_FALSE(static_cast<bool>(a));
        EXPECT_TRUE(static_cast<bool>(b));
        EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 10 * 5);
    }
    EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 20);
}

// install_all: declarative table with severity + ordering + rollback
namespace
{
    // Real, hookable functions used as install_all scan targets. Their first bytes are scanned by AOB so the deferred
    // OwnedScanRequest resolves to the function entry.
    DMK_PROOF_TARGET int install_target_one(int x)
    {
        volatile int r = x + 1;
        return r;
    }

    DMK_PROOF_TARGET int install_target_two(int x)
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

    /** @brief Supplies the exact AOB literal for the target's first bytes. */
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
            scan::Candidate::direct(std::move(name), scan::Pattern::compile(aob_of(addr, aob_len)).value())
        );
        req.scope = Region{Address{addr}, aob_len + 16};
        return req;
    }

    // An OwnedScanRequest that cannot resolve: a Direct candidate for a byte pattern that is absent from its scope.
    [[nodiscard]] scan::OwnedScanRequest unresolvable_request(std::string name)
    {
        scan::OwnedScanRequest req;
        req.ladder.push_back(
            scan::Candidate::direct(
                std::move(name),
                scan::Pattern::compile("FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF").value()
            )
        );
        req.scope = Region{Address{reinterpret_cast<std::uintptr_t>(&install_target_one)}, 32};
        return req;
    }
} // namespace

TEST(HookInstallAll, TwoMandatoryRowsBothResolve)
{
    const HookSpec table[] = {
        HookSpec::inline_hook(
            "RowOne",
            resolvable_request("RowOnePat", &install_target_one),
            &install_detour_one,
            Severity::Mandatory
        ),
        HookSpec::inline_hook(
            "RowTwo",
            resolvable_request("RowTwoPat", &install_target_two),
            &install_detour_two,
            Severity::Mandatory
        ),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_TRUE(res.has_value()) << res.error().message();
    ASSERT_EQ(res->size(), 2u);

    EXPECT_EQ((*res)[0].name, "RowOne");
    EXPECT_EQ((*res)[0].severity, Severity::Mandatory);
    EXPECT_TRUE((*res)[0].hook.has_value()) << (*res)[0].hook.error().message();
    EXPECT_FALSE((*res)[0].hook->is_enabled());

    EXPECT_EQ((*res)[1].name, "RowTwo");
    EXPECT_TRUE((*res)[1].hook.has_value()) << (*res)[1].hook.error().message();
    EXPECT_FALSE((*res)[1].hook->is_enabled());
    EXPECT_EQ(call_unfolded(&install_target_one, 4), 5);
    EXPECT_EQ(call_unfolded(&install_target_two, 4), 6);

    ASSERT_TRUE((*res)[0].hook->enable().has_value());
    ASSERT_TRUE((*res)[1].hook->enable().has_value());
    EXPECT_EQ(call_unfolded(&install_target_one, 4), 1004);
    EXPECT_EQ(call_unfolded(&install_target_two, 4), 2004);
}

TEST(HookInstallAll, MandatoryMissFailsWholeCall)
{
    const HookSpec table[] = {
        HookSpec::inline_hook(
            "MandHit",
            resolvable_request("MandHitPat", &install_target_one),
            &install_detour_one,
            Severity::Mandatory
        ),
        HookSpec::inline_hook(
            "MandMiss",
            unresolvable_request("MandMissPat"),
            &install_detour_two,
            Severity::Mandatory
        ),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::NoMatch);
    // The failed mandatory row must roll back the earlier install.
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_one)));
}

TEST(HookInstallAll, BestEffortMissStillSucceedsWithMandatoryHit)
{
    const HookSpec table[] = {
        HookSpec::inline_hook("BeMiss", unresolvable_request("BeMissPat"), &install_detour_one, Severity::BestEffort),
        HookSpec::inline_hook(
            "MandHit2",
            resolvable_request("MandHit2Pat", &install_target_two),
            &install_detour_two,
            Severity::Mandatory
        ),
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
    EXPECT_FALSE((*res)[1].hook->is_enabled());
}

// The allocation sweep must preserve the noexcept install_all boundary. Container failure reports OutOfMemory rather
// than a successful empty result.
static_assert(
    noexcept(install_all(std::span<const HookSpec>{})),
    "hook::install_all must be noexcept: it degrades under OOM rather than terminating the host."
);

// A declarative table row carries its own install Options, which install_all applies verbatim. A row that opts into
// fail_if_already_hooked refuses an already-hooked target, while a default-Options row layers on top. The paired
// strict/permissive rows below prove the row's policy reaches the install rather than being overwritten by a container
// default.
TEST(HookInstallAll, PerRowOptionsControlFailIfAlreadyHooked)
{
    // Pre-hook the target so this instance's ledger reports it hooked.
    Result<Hook> pre = inline_at(
        InlineRequest{
            .name = "PerRowPreHook",
            .target = addr_of(&install_target_one),
        },
        &install_detour_one
    );
    ASSERT_TRUE(pre.has_value()) << pre.error().message();
    Hook keep = std::move(*pre);

    // A BestEffort row that opts into fail_if_already_hooked through its per-row Options: it must refuse the
    // already-hooked target rather than layer.
    const HookSpec strict_table[] = {
        HookSpec::inline_hook(
            "StrictRow",
            resolvable_request("StrictRowPat", &install_target_one),
            &install_detour_two,
            Severity::BestEffort,
            Options{
                .fail_if_already_hooked = true,
            }
        ),
    };
    Result<std::vector<InstallOutcome>> strict = install_all(strict_table);
    ASSERT_TRUE(strict.has_value()) << strict.error().message();
    ASSERT_EQ(strict->size(), 1u);
    EXPECT_FALSE((*strict)[0].hook.has_value())
        << "a per-row fail_if_already_hooked must refuse the already-hooked target";

    // Default Options still admit the same target. This control isolates the per-row refusal policy.
    const HookSpec permissive_table[] = {
        HookSpec::inline_hook(
            "PermissiveRow",
            resolvable_request("PermissiveRowPat", &install_target_one),
            &install_detour_two,
            Severity::BestEffort
        ),
    };
    Result<std::vector<InstallOutcome>> permissive = install_all(permissive_table);
    ASSERT_TRUE(permissive.has_value()) << permissive.error().message();
    ASSERT_EQ(permissive->size(), 1u);
    EXPECT_TRUE((*permissive)[0].hook.has_value())
        << "the default-Options row must still layer on top of the already-hooked target";
}

TEST(HookInstallAll, AllocFailureReturnsOutOfMemoryWithoutEscaping)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    const HookSpec table[] = {
        HookSpec::inline_hook(
            "OomRow",
            resolvable_request("OomRowPat", &install_target_one),
            &install_detour_one,
            Severity::Mandatory
        ),
    };

    Result<std::vector<InstallOutcome>> res;
    {
        // Budget zero fails the outcomes reserve before any row starts. The Result must report OutOfMemory.
        dmk_test::AllocFailScope fail(0);
        res = install_all(table);
    }

    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::OutOfMemory);
    // The container failed before the first row, so nothing was installed.
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_one)));
}

// A vector unwind does not guarantee newest-first teardown. Removed events expose the InstallRollback order without a
// fault.
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
        }
    );

    const HookSpec table[] = {
        HookSpec::inline_hook(
            "RollbackOlder",
            resolvable_request("RbOlderPat", &install_target_one),
            &install_detour_one,
            Severity::Mandatory
        ),
        HookSpec::inline_hook(
            "RollbackNewer",
            resolvable_request("RbNewerPat", &install_target_two),
            &install_detour_two,
            Severity::Mandatory
        ),
        HookSpec::inline_hook(
            "RollbackMiss",
            unresolvable_request("RbMissPat"),
            &install_detour_one,
            Severity::Mandatory
        ),
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

// Force the self-reference acquire to fail with a known last-error so each install path's SystemCallFailed carries
// Error::detail = GetLastError(). A genuine acquire_module_ref failure is unreachable in a loaded process, so this
// override (defined in hook.cpp) drives the branch deterministically.
namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    extern HMODULE (*g_hook_module_ref_override)() noexcept;
    extern bool (*g_hook_enable_witness_override)(bool) noexcept;
#endif
} // namespace DetourModKit::detail

namespace
{
    constexpr DWORD INJECTED_ACQUIRE_ERROR = 0x00C0FFEE;

    HMODULE force_module_ref_failure() noexcept
    {
        ::SetLastError(INJECTED_ACQUIRE_ERROR);
        return nullptr;
    }

    bool reject_enable_witness(bool) noexcept
    {
        return false;
    }

    void *s_enable_witness_rollback_page = nullptr;

    bool reject_enable_witness_after_decommit(bool) noexcept
    {
        return s_enable_witness_rollback_page == nullptr ||
               ::VirtualFree(s_enable_witness_rollback_page, dmk_test::ScratchPage::PAGE_SIZE, MEM_DECOMMIT) == FALSE;
    }

    // RAII installer so a failed assertion still clears the override before the next test runs.
    struct HookModuleRefFailureScope
    {
        HookModuleRefFailureScope() noexcept
        {
            DetourModKit::detail::g_hook_module_ref_override = &force_module_ref_failure;
        }
        ~HookModuleRefFailureScope() noexcept { DetourModKit::detail::g_hook_module_ref_override = nullptr; }
        HookModuleRefFailureScope(const HookModuleRefFailureScope &) = delete;
        HookModuleRefFailureScope &operator=(const HookModuleRefFailureScope &) = delete;
    };

    class HookEnableWitnessOverrideScope
    {
    public:
        explicit HookEnableWitnessOverrideScope(bool (*override_fn)(bool) noexcept) noexcept
        {
            DetourModKit::detail::g_hook_enable_witness_override = override_fn;
        }
        ~HookEnableWitnessOverrideScope() noexcept { DetourModKit::detail::g_hook_enable_witness_override = nullptr; }
        HookEnableWitnessOverrideScope(const HookEnableWitnessOverrideScope &) = delete;
        HookEnableWitnessOverrideScope &operator=(const HookEnableWitnessOverrideScope &) = delete;
    };
} // namespace

// Disabled creation leaves no target patch to witness. A rejected enable must restore the target or retain Active if
// rollback fails.
TEST(HookEnableWitness, InlineFailureLeavesHookDisabledAndTargetPristine)
{
    const Address target = addr_of(&witness_failure_inline_target);
    Result<Hook> created = inline_at(
        InlineRequest{
            .name = "InlineWitnessFailure",
            .target = target,
        },
        &echo_detour
    );
    ASSERT_TRUE(created.has_value()) << created.error().message();
    Hook h = std::move(*created);

    {
        const HookEnableWitnessOverrideScope fail_scope(&reject_enable_witness);
        const Result<void> failed = h.enable();
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(failed.error().code, ErrorCode::EnableFailed);
    }

    EXPECT_FALSE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&witness_failure_inline_target, 7), 24);

    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&witness_failure_inline_target, 7), 107);
}

TEST(HookEnableWitness, MidFailureLeavesHookDisabledAndTargetPristine)
{
    const Address target = addr_of(&witness_failure_mid_target);
    const auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 100; };
    Result<Hook> created = mid_at(
        MidRequest{
            .name = "MidWitnessFailure",
            .target = target,
        },
        detour
    );
    ASSERT_TRUE(created.has_value()) << created.error().message();
    Hook h = std::move(*created);

    {
        const HookEnableWitnessOverrideScope fail_scope(&reject_enable_witness);
        const Result<void> failed = h.enable();
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(failed.error().code, ErrorCode::EnableFailed);
    }

    EXPECT_FALSE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&witness_failure_mid_target, 9, 4), 5);

    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&witness_failure_mid_target, 9, 4), 96);
}

TEST(HookEnableWitness, RollbackFailureReportsActiveState)
{
    const diagnostics::Snapshot before = diagnostics::collect();
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf_function(page);

    Result<Hook> installed = try_install_at(page.addr(0), "EnableWitnessRollbackFailure");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    const diagnostics::Snapshot created = diagnostics::collect();
    EXPECT_EQ(created.hooks_active, before.hooks_active);
    EXPECT_EQ(created.hooks_disabled, before.hooks_disabled + 1);

    s_enable_witness_rollback_page = page.base();
    {
        const HookEnableWitnessOverrideScope fail_scope(&reject_enable_witness_after_decommit);
        const Result<void> enabled = hook.enable();
        ASSERT_FALSE(enabled.has_value());
        EXPECT_EQ(enabled.error().code, ErrorCode::DisableFailed);
    }
    s_enable_witness_rollback_page = nullptr;

    EXPECT_TRUE(hook.is_enabled()) << "a failed compensating disable must not be published as Disabled";
    const diagnostics::Snapshot active = diagnostics::collect();
    EXPECT_EQ(active.hooks_active, before.hooks_active + 1);
    EXPECT_EQ(active.hooks_disabled, before.hooks_disabled);
}

// Run the target from another thread after every publication boundary. Each call must reach the original until the
// caller explicitly enables the returned handle.
namespace
{
    std::atomic<int> s_publication_detour_calls{0};

    int publication_proof_detour(int value)
    {
        s_publication_detour_calls.fetch_add(1, std::memory_order_relaxed);
        return value + 1000;
    }

    std::atomic<int> s_publication_mid_detour_calls{0};

    constexpr std::size_t PUBLICATION_STEP_COUNT = 4;
    std::array<bool, PUBLICATION_STEP_COUNT> s_publication_step_fired{};
    std::array<int, PUBLICATION_STEP_COUNT> s_publication_step_observed{};
    std::array<bool, PUBLICATION_STEP_COUNT> s_publication_mid_step_fired{};
    std::array<int, PUBLICATION_STEP_COUNT> s_publication_mid_step_observed{};

    // The target runs on another thread while install pauses. A same-thread call cannot expose the race.
    void observe_target_from_foreign_thread(DetourModKit::detail::HookPublishStep step) noexcept
    {
        const auto index = static_cast<std::size_t>(step);
        if (index >= PUBLICATION_STEP_COUNT)
        {
            ADD_FAILURE() << "unexpected publication step " << index;
            return;
        }
        s_publication_step_fired[index] = true;
        try
        {
            int observed = 0;
            std::thread caller([&observed] { observed = call_unfolded(&publication_proof_target, 5); });
            caller.join();
            s_publication_step_observed[index] = observed;
        }
        catch (...)
        {
            ADD_FAILURE() << "could not run the target at publication step " << index;
        }
    }

    void observe_mid_target_from_foreign_thread(DetourModKit::detail::HookPublishStep step) noexcept
    {
        const auto index = static_cast<std::size_t>(step);
        if (index >= PUBLICATION_STEP_COUNT)
        {
            ADD_FAILURE() << "unexpected mid publication step " << index;
            return;
        }
        s_publication_mid_step_fired[index] = true;
        try
        {
            int observed = 0;
            std::thread caller([&observed] { observed = call_unfolded(&publication_proof_mid_target, 3, 4); });
            caller.join();
            s_publication_mid_step_observed[index] = observed;
        }
        catch (...)
        {
            ADD_FAILURE() << "could not run the mid target at publication step " << index;
        }
    }

    DetourModKit::detail::HookPublishStep s_oom_throw_step{};

    void oom_throwing_probe(DetourModKit::detail::HookPublishStep step)
    {
        if (step == s_oom_throw_step)
        {
            throw std::bad_alloc();
        }
    }

    void oom_publication_mid_detour(MidContext &ctx)
    {
        gpr(ctx, Gpr::Rcx) = 8;
    }
} // namespace

TEST(HookPublicationProof, DisabledUntilCallerPublishesContext)
{
    s_publication_detour_calls.store(0, std::memory_order_relaxed);
    s_publication_step_fired.fill(false);
    s_publication_step_observed.fill(0);

    std::optional<Hook> handle;
    {
        const HookPublishProbeScope probe_scope(&observe_target_from_foreign_thread);
        Result<Hook> created = inline_at(
            InlineRequest{
                .name = "PublicationProof",
                .target = addr_of(&publication_proof_target),
            },
            &publication_proof_detour
        );
        ASSERT_TRUE(created.has_value()) << created.error().message();
        handle.emplace(std::move(*created));
    }

    for (std::size_t i = 0; i < PUBLICATION_STEP_COUNT; ++i)
    {
        EXPECT_TRUE(s_publication_step_fired[i]) << "publication step " << i << " never fired";
        EXPECT_EQ(s_publication_step_observed[i], 6)
            << "the detour was reachable at publication step " << i << ", before the caller held the handle";
    }
    EXPECT_EQ(s_publication_detour_calls.load(std::memory_order_relaxed), 0);

    // The target remains inert after the caller receives the handle because arming is a separate operation.
    EXPECT_FALSE(handle->is_enabled());
    EXPECT_EQ(call_unfolded(&publication_proof_target, 5), 6);
    EXPECT_EQ(s_publication_detour_calls.load(std::memory_order_relaxed), 0);

    // Only the explicit enable commits the patch.
    ASSERT_TRUE(handle->enable().has_value());
    EXPECT_TRUE(handle->is_enabled());
    EXPECT_EQ(call_unfolded(&publication_proof_target, 5), 1005);
    EXPECT_EQ(s_publication_detour_calls.load(std::memory_order_relaxed), 1);
}

// A failure at any publication boundary must leave no active target or partial ledger entry.
TEST(HookPublicationProof, FailureAtEachPublicationStepLeavesNoPartialHook)
{
    const Address target = addr_of(&oom_publication_target);
    ASSERT_FALSE(is_target_hooked(target));

    const DetourModKit::detail::HookPublishStep steps[] = {
        DetourModKit::detail::HookPublishStep::BackendCreated,
        DetourModKit::detail::HookPublishStep::ImplConstructed,
        DetourModKit::detail::HookPublishStep::GatePublished,
        DetourModKit::detail::HookPublishStep::LedgerCommitted,
    };

    for (const auto step : steps)
    {
        Result<Hook> installed = std::unexpected(Error{ErrorCode::UnknownError, "seed"});
        {
            s_oom_throw_step = step;
            const HookPublishProbeScope probe_scope(&oom_throwing_probe);
            installed = inline_at(
                InlineRequest{
                    .name = "OomPublication",
                    .target = target,
                },
                &oom_publication_detour
            );
        }

        ASSERT_FALSE(installed.has_value()) << "step " << static_cast<int>(step) << " did not fail the install";
        EXPECT_EQ(installed.error().code, ErrorCode::OutOfMemory) << "step " << static_cast<int>(step);
        EXPECT_FALSE(is_target_hooked(target)) << "step " << static_cast<int>(step) << " left a partial ledger entry";
        EXPECT_EQ(call_unfolded(&oom_publication_target, 4), 7)
            << "step " << static_cast<int>(step) << " left the target armed or partially patched";
    }

    // The target survived every injected failure and a real install still works end to end.
    Result<Hook> ok = inline_at(
        InlineRequest{
            .name = "OomRecovery",
            .target = target,
        },
        &oom_publication_detour
    );
    ASSERT_TRUE(ok.has_value()) << ok.error().message();
    Hook h = std::move(*ok);
    ASSERT_TRUE(h.enable().has_value());
    EXPECT_EQ(call_unfolded(&oom_publication_target, 4), 504);

    const Address mid_target = addr_of(&publication_proof_mid_target);
    for (const auto step : steps)
    {
        Result<Hook> installed = std::unexpected(Error{ErrorCode::UnknownError, "seed"});
        {
            s_oom_throw_step = step;
            const HookPublishProbeScope probe_scope(&oom_throwing_probe);
            installed = mid_at(
                MidRequest{
                    .name = "OomPublicationMid",
                    .target = mid_target,
                },
                &oom_publication_mid_detour
            );
        }

        ASSERT_FALSE(installed.has_value()) << "mid step " << static_cast<int>(step) << " did not fail the install";
        EXPECT_EQ(installed.error().code, ErrorCode::OutOfMemory) << "mid step " << static_cast<int>(step);
        EXPECT_FALSE(is_target_hooked(mid_target))
            << "mid step " << static_cast<int>(step) << " left a partial ledger entry";
        EXPECT_EQ(call_unfolded(&publication_proof_mid_target, 3, 4), 12)
            << "mid step " << static_cast<int>(step) << " left the target patched";
    }

    Result<Hook> mid_ok = mid_at(
        MidRequest{
            .name = "OomRecoveryMid",
            .target = mid_target,
        },
        &oom_publication_mid_detour
    );
    ASSERT_TRUE(mid_ok.has_value()) << mid_ok.error().message();
    Hook mid_hook = std::move(*mid_ok);
    ASSERT_TRUE(mid_hook.enable().has_value());
    EXPECT_EQ(call_unfolded(&publication_proof_mid_target, 3, 4), 32);
}

TEST(HookPublicationProof, MidHookIsDisabledUntilCallerPublishesContext)
{
    s_publication_mid_detour_calls.store(0, std::memory_order_relaxed);
    s_publication_mid_step_fired.fill(false);
    s_publication_mid_step_observed.fill(0);
    const auto detour = [](MidContext &ctx)
    {
        s_publication_mid_detour_calls.fetch_add(1, std::memory_order_relaxed);
        gpr(ctx, Gpr::Rcx) = 7;
    };

    std::optional<Hook> handle;
    {
        const HookPublishProbeScope probe_scope(&observe_mid_target_from_foreign_thread);
        Result<Hook> created = mid_at(
            MidRequest{
                .name = "PublicationProofMid",
                .target = addr_of(&publication_proof_mid_target),
            },
            detour
        );
        ASSERT_TRUE(created.has_value()) << created.error().message();
        handle.emplace(std::move(*created));
    }

    for (std::size_t i = 0; i < PUBLICATION_STEP_COUNT; ++i)
    {
        EXPECT_TRUE(s_publication_mid_step_fired[i]) << "mid publication step " << i << " never fired";
        EXPECT_EQ(s_publication_mid_step_observed[i], 12)
            << "the mid detour was reachable before the caller held the handle at step " << i;
    }

    EXPECT_FALSE(handle->is_enabled());
    EXPECT_EQ(call_unfolded(&publication_proof_mid_target, 3, 4), 12);
    EXPECT_EQ(s_publication_mid_detour_calls.load(std::memory_order_relaxed), 0);

    ASSERT_TRUE(handle->enable().has_value());
    EXPECT_TRUE(handle->is_enabled());
    EXPECT_EQ(call_unfolded(&publication_proof_mid_target, 3, 4), 28);
    EXPECT_EQ(s_publication_mid_detour_calls.load(std::memory_order_relaxed), 1);
}

TEST(HookModuleRef, InlineAtAcquireFailurePopulatesErrorDetail)
{
    HookModuleRefFailureScope fail_scope;
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "InlineAcquireFail",
            .target = addr_of(&real_hook_target_add),
        },
        &real_hook_detour_add
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::SystemCallFailed);
    EXPECT_EQ(r.error().detail, static_cast<std::uintptr_t>(INJECTED_ACQUIRE_ERROR));
}

TEST(HookModuleRef, MidAtAcquireFailurePopulatesErrorDetail)
{
    auto detour = [](MidContext &) {};
    HookModuleRefFailureScope fail_scope;
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidAcquireFail",
            .target = addr_of(&real_hook_target_mul),
        },
        detour
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::SystemCallFailed);
    EXPECT_EQ(r.error().detail, static_cast<std::uintptr_t>(INJECTED_ACQUIRE_ERROR));
}

TEST(HookModuleRef, VmtForAcquireFailurePopulatesErrorDetail)
{
    auto target = std::make_unique<VmtTestTarget>();
    HookModuleRefFailureScope fail_scope;
    Result<VmtHook> r = vmt_for("VmtAcquireFail", target.get());
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::SystemCallFailed);
    EXPECT_EQ(r.error().detail, static_cast<std::uintptr_t>(INJECTED_ACQUIRE_ERROR));
}

namespace
{
    [[nodiscard]] std::uintptr_t read_vmt_test_vptr(const VmtTestTarget &object) noexcept
    {
        std::uintptr_t value{};
        std::memcpy(&value, std::addressof(object), sizeof(value));
        return value;
    }

    /**
     * @brief Repeats a scenario with one allocation failure at each observed index.
     * @param scenario The callback. A negative budget measures without fault
     *                 injection.
     */
    template <class ScenarioT> void sweep_allocation_failures(ScenarioT &&scenario)
    {
        const long long budget = scenario(-1);
        ASSERT_GT(budget, 0) << "the call under test exposed no allocation index";
        ASSERT_LT(budget, 512) << "the allocation count exceeds the focused diagnostic bound";
        for (long long allow = 0; allow < budget; ++allow)
        {
            (void)scenario(allow);
        }
    }

    /// Arms the sweep budget for each nonnegative index.
    class SweepBudget
    {
    public:
        explicit SweepBudget(long long allow) noexcept
        {
            if (allow >= 0)
            {
                m_armed.emplace(allow);
            }
        }

        SweepBudget(const SweepBudget &) = delete;
        SweepBudget &operator=(const SweepBudget &) = delete;
        SweepBudget(SweepBudget &&) = delete;
        SweepBudget &operator=(SweepBudget &&) = delete;

    private:
        std::optional<dmk_test::AllocFailScope> m_armed;
    };

} // namespace

TEST(HookDiagnosticContainment, RiskyPrologueWarningContainsEveryAllocationFailure)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning, DetourModKit::DEFAULT_TIMESTAMP_FORMAT};
    const HookModuleRefFailureScope fail_module_ref;
    sweep_allocation_failures(
        [](long long allow) -> long long
        {
            dmk_test::ScratchPage page;
            if (!page.ok())
            {
                return 0;
            }
            InlineRequest request{
                .name = "PrologueWarnSweep",
                .target = Address{page.addr(0)},
                .options = Options{.prologue = Prologue::Relocate},
            };
            const long long before = dmk_test::thread_new_calls();
            bool has_value = false;
            {
                const SweepBudget budget{allow};
                const Result<Hook> created = inline_at(std::move(request), reinterpret_cast<void (*)()>(&noop_detour));
                has_value = created.has_value();
            }
            const long long measured = dmk_test::thread_new_calls() - before;
            EXPECT_FALSE(has_value);
            return measured;
        }
    );
    EXPECT_NE(capture.read_all().find("begins with a breakpoint (0xCC/0xCD)"), std::string::npos);
}

TEST(HookDiagnosticContainment, TargetWindowWarningContainsEveryAllocationFailure)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    alignas(16) static std::uint8_t data_prologue[32] = {0x90, 0x90, 0x90, 0x90, 0x90, 0xC3};
    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning, DetourModKit::DEFAULT_TIMESTAMP_FORMAT};
    sweep_allocation_failures(
        [](long long allow) -> long long
        {
            InlineRequest request{
                .name = "TargetWindowWarnSweep",
                .target = addr_of(data_prologue),
            };
            const long long before = dmk_test::thread_new_calls();
            bool has_value = false;
            {
                const SweepBudget budget{allow};
                const Result<Hook> created = inline_at(std::move(request), reinterpret_cast<void (*)()>(&noop_detour));
                has_value = created.has_value();
            }
            const long long measured = dmk_test::thread_new_calls() - before;
            EXPECT_FALSE(has_value);
            return measured;
        }
    );
    EXPECT_NE(capture.read_all().find("refused target"), std::string::npos);
}

TEST(HookDiagnosticContainment, SameKitLayerWarningContainsEveryAllocationFailure)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf_function(page);
    Result<Hook> installed = inline_at(
        InlineRequest{
            .name = "LayerWarnBase",
            .target = Address{page.addr(0)},
        },
        reinterpret_cast<void (*)()>(&noop_detour)
    );
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook base = std::move(*installed);
    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning, DetourModKit::DEFAULT_TIMESTAMP_FORMAT};
    const HookModuleRefFailureScope fail_module_ref;
    sweep_allocation_failures(
        [&page](long long allow) -> long long
        {
            InlineRequest request{
                .name = "LayerWarnSweep",
                .target = Address{page.addr(0)},
            };
            const long long before = dmk_test::thread_new_calls();
            bool has_value = false;
            {
                const SweepBudget budget{allow};
                const Result<Hook> created = inline_at(std::move(request), reinterpret_cast<void (*)()>(&noop_detour));
                has_value = created.has_value();
            }
            const long long measured = dmk_test::thread_new_calls() - before;
            EXPECT_FALSE(has_value);
            return measured;
        }
    );
    EXPECT_NE(capture.read_all().find("layers on a hook this kit already placed"), std::string::npos);
}

TEST(HookDiagnosticContainment, ForeignJumpWarningContainsEveryAllocationFailure)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(kernel32, nullptr);
    const auto foreign_destination = reinterpret_cast<std::uintptr_t>(GetProcAddress(kernel32, "Sleep"));
    ASSERT_NE(foreign_destination, 0u);
    std::vector<std::unique_ptr<dmk_test::ScratchPage>> pages;
    dmk_test::ScratchPage *page = acquire_ledger_free_page(pages);
    ASSERT_NE(page, nullptr);
    page->put(0, {0x48, 0xB8});
    std::memcpy(reinterpret_cast<void *>(page->addr(2)), &foreign_destination, sizeof(foreign_destination));
    page->put(10, {0xFF, 0xE0});
    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning, DetourModKit::DEFAULT_TIMESTAMP_FORMAT};
    const HookModuleRefFailureScope fail_module_ref;
    sweep_allocation_failures(
        [page](long long allow) -> long long
        {
            InlineRequest request{
                .name = "ForeignJumpWarnSweep",
                .target = Address{page->addr(0)},
            };
            const long long before = dmk_test::thread_new_calls();
            bool has_value = false;
            {
                const SweepBudget budget{allow};
                const Result<Hook> created = inline_at(std::move(request), reinterpret_cast<void (*)()>(&noop_detour));
                has_value = created.has_value();
            }
            const long long measured = dmk_test::thread_new_calls() - before;
            EXPECT_FALSE(has_value);
            return measured;
        }
    );
    EXPECT_NE(capture.read_all().find("detects another module's inline hook"), std::string::npos);
}

TEST(HookDiagnosticContainment, VmtForCloneWarningContainsEveryAllocationFailure)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning, DetourModKit::DEFAULT_TIMESTAMP_FORMAT};
    bool saw_injected_failure = false;
    sweep_allocation_failures(
        [&saw_injected_failure](long long allow) -> long long
        {
            namespace diag = DetourModKit::diagnostics;
            const diag::Snapshot population_before = diag::collect();
            const std::size_t hook_pin_index = static_cast<std::size_t>(diag::ModulePinReason::Hook);
            const std::size_t leaks_before = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);
            auto object = std::make_unique<VmtTestTarget>();
            const std::uintptr_t original_vptr = read_vmt_test_vptr(*object);
            Result<VmtHook> base = vmt_for("CloneSweepBase", object.get());
            if (!base.has_value())
            {
                ADD_FAILURE() << base.error().message();
                return 0;
            }
            std::optional<VmtHook> owner;
            owner.emplace(std::move(*base));
            const std::uintptr_t base_vptr = read_vmt_test_vptr(*object);
            EXPECT_NE(base_vptr, original_vptr);
            EXPECT_TRUE(DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(base_vptr));
            const diag::Snapshot with_base = diag::collect();
            EXPECT_EQ(with_base.hooks_total, population_before.hooks_total + 1);
            EXPECT_EQ(with_base.hooks_active, population_before.hooks_active + 1);
            EXPECT_EQ(with_base.module_pins[hook_pin_index], population_before.module_pins[hook_pin_index] + 1);

            // vmt_for takes its name by value. The sweep constructs the string before it arms the budget.
            std::string layered_name{"CloneSweepOfClone"};
            std::optional<VmtHook> layered;
            std::optional<ErrorCode> failure;
            const long long before = dmk_test::thread_new_calls();
            {
                const SweepBudget budget{allow};
                Result<VmtHook> outcome = vmt_for(std::move(layered_name), object.get());
                if (outcome)
                {
                    layered.emplace(std::move(*outcome));
                }
                else
                {
                    failure.emplace(outcome.error().code);
                }
            }
            const long long measured = dmk_test::thread_new_calls() - before;

            EXPECT_NE(layered.has_value(), failure.has_value());
            if (allow < 0)
            {
                EXPECT_TRUE(layered.has_value());
            }
            else if (failure)
            {
                saw_injected_failure = true;
                EXPECT_EQ(*failure, ErrorCode::OutOfMemory);
            }

            if (layered)
            {
                const std::uintptr_t layered_vptr = read_vmt_test_vptr(*object);
                EXPECT_NE(layered_vptr, base_vptr);
                EXPECT_TRUE(DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(layered_vptr));
                const diag::Snapshot with_layer = diag::collect();
                EXPECT_EQ(with_layer.hooks_total, population_before.hooks_total + 2);
                EXPECT_EQ(with_layer.hooks_active, population_before.hooks_active + 2);
                EXPECT_EQ(with_layer.module_pins[hook_pin_index], population_before.module_pins[hook_pin_index] + 2);
                layered.reset();
                EXPECT_EQ(read_vmt_test_vptr(*object), base_vptr);
                EXPECT_FALSE(DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(layered_vptr));
            }
            else
            {
                EXPECT_EQ(read_vmt_test_vptr(*object), base_vptr);
            }

            const diag::Snapshot after_layer = diag::collect();
            EXPECT_EQ(after_layer.hooks_total, population_before.hooks_total + 1);
            EXPECT_EQ(after_layer.hooks_active, population_before.hooks_active + 1);
            EXPECT_EQ(after_layer.module_pins[hook_pin_index], population_before.module_pins[hook_pin_index] + 1);
            EXPECT_TRUE(DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(base_vptr));
            EXPECT_EQ(diag::intentional_leak_count(diag::LeakSubsystem::HookManager), leaks_before);

            owner.reset();
            EXPECT_EQ(read_vmt_test_vptr(*object), original_vptr);
            EXPECT_FALSE(DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(base_vptr));
            const diag::Snapshot after_owner = diag::collect();
            EXPECT_EQ(after_owner.hooks_total, population_before.hooks_total);
            EXPECT_EQ(after_owner.hooks_active, population_before.hooks_active);
            EXPECT_EQ(after_owner.module_pins[hook_pin_index], population_before.module_pins[hook_pin_index]);
            EXPECT_EQ(diag::intentional_leak_count(diag::LeakSubsystem::HookManager), leaks_before);
            return measured;
        }
    );
    EXPECT_TRUE(saw_injected_failure);
    // The sweep proves containment only while it keeps reaching the clone diagnostic.
    EXPECT_NE(capture.read_all().find("hook::vmt_for: VMT hook 'CloneSweepOfClone'"), std::string::npos);
}

TEST(HookDiagnosticContainment, VmtApplyCloneWarningContainsEveryAllocationFailure)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning, DetourModKit::DEFAULT_TIMESTAMP_FORMAT};
    sweep_allocation_failures(
        [](long long allow) -> long long
        {
            auto owner_object = std::make_unique<VmtTestTarget>();
            auto mover_object = std::make_unique<VmtTestTarget>();
            Result<VmtHook> ro = vmt_for("ApplySweepOwner", owner_object.get());
            if (!ro.has_value())
            {
                return 0;
            }
            VmtHook owner = std::move(*ro);
            Result<VmtHook> rm = vmt_for("ApplySweepMover", mover_object.get());
            if (!rm.has_value())
            {
                return 0;
            }
            VmtHook mover = std::move(*rm);

            // The owner object sits on one clone, so the cross-apply selects the clone diagnostic.
            const long long before = dmk_test::thread_new_calls();
            bool applied = false;
            {
                const SweepBudget budget{allow};
                applied = mover.apply_to(owner_object.get()).has_value();
            }
            const long long measured = dmk_test::thread_new_calls() - before;
            if (applied)
            {
                // Remove the cross-apply so one handle restores each object.
                (void)mover.remove_from(owner_object.get());
            }
            return measured;
        }
    );
    // The sweep proves containment only while it keeps reaching the clone diagnostic.
    EXPECT_NE(capture.read_all().find("hook::vmt_apply: VMT hook 'ApplySweepMover'"), std::string::npos);
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
        Result<Hook> r = inline_at(
            InlineRequest{
                .name = "LifecycleHook",
                .target = addr_of(&echo),
            },
            &echo_detour
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        // Created on install (disabled), then the arming enable, then a real disable -> enable transition pair, then
        // Removed when h leaves scope. Each real state change emits exactly once.
        ASSERT_TRUE(h.enable().has_value());
        ASSERT_TRUE(h.disable().has_value());
        ASSERT_TRUE(h.enable().has_value());
    }

    ASSERT_EQ(events.size(), 5u);
    EXPECT_EQ(events[0].transition, diagnostics::HookTransition::Created);
    EXPECT_EQ(events[1].transition, diagnostics::HookTransition::Enabled);
    EXPECT_EQ(events[2].transition, diagnostics::HookTransition::Disabled);
    EXPECT_EQ(events[3].transition, diagnostics::HookTransition::Enabled);
    EXPECT_EQ(events[4].transition, diagnostics::HookTransition::Removed);
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
    Result<Hook> r = mid_at(
        MidRequest{
            .name = "MidLifecycleHook",
            .target = addr_of(&real_hook_target_mul),
        },
        detour
    );
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
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "NoOpLifecycleHook",
            .target = addr_of(&leak_target_lifecycle),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_EQ(events.size(), 1u); // Created only

    // The hook is created disabled, so a redundant disable() is a no-op and emits nothing.
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(events.size(), 1u);

    // Arm it (a real Enabled), then release: release() detaches without a Removed transition path through teardown.
    ASSERT_TRUE(h.enable().has_value());
    ASSERT_EQ(events.size(), 2u);
    EXPECT_EQ(events[1].transition, diagnostics::HookTransition::Enabled);
    h.release();
}
