/**
 * @file hook_fixture.cpp
 * @brief Defines the DMK_PROOF_TARGET hook targets that several hook test files share, once for DetourModKit_tests.
 * @details docs/design/testing.md owns the rule under "A split suite shares one fixture header".
 */

#include "fixtures/hook_fixture.hpp"

namespace dmk_test::hook_fixture
{
    DMK_PROOF_TARGET int echo(int x)
    {
        volatile int r = x;
        return r;
    }

    DMK_PROOF_TARGET int real_hook_target_add(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_PROOF_TARGET int real_hook_target_mul(int a, int b)
    {
        volatile int r = a * b;
        return r;
    }

    // Each release target stays patched for the process lifetime. Separate entries prevent a later case from inheriting
    // that patch.
    DMK_PROOF_TARGET int leak_target_inline(int x)
    {
        volatile int r = x;
        return r;
    }

    DMK_PROOF_TARGET int leak_target_disengaged(int x)
    {
        volatile int r = x;
        return r;
    }

    // Oldest-first teardown retains the older backend. This dedicated target stays patched for the process lifetime and
    // cannot serve another case.
    DMK_PROOF_TARGET int leak_target_layered(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    // This dedicated target stays patched after teardown refusal. No other case can reuse its address.
    DMK_PROOF_TARGET int leak_target_ledger_sync(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    // Dedicated target for the retained-id layering proof. The proof releases its first hook, so the target stays
    // patched for the process lifetime. Other tests must not touch this address.
    DMK_PROOF_TARGET int leak_target_retained_id(int a, int b)
    {
        volatile int r = a + b + 5;
        return r;
    }

    // Dedicated target for the inverse retained-id proof: a pinned NEWER layer over a live older one.
    DMK_PROOF_TARGET int leak_target_retained_newer(int a, int b)
    {
        volatile int r = a + b + 7;
        return r;
    }

    // Dedicated target for the outranked-toggle proof: a pinned NEWER layer over an older one that stays live and
    // keeps trying to write the target's bytes.
    DMK_PROOF_TARGET int leak_target_retained_conflict(int a, int b)
    {
        volatile int r = a + b + 19;
        return r;
    }

    // This release() target stays patched for the process lifetime and cannot serve another case.
    DMK_PROOF_TARGET int leak_target_release_booked(int a, int b)
    {
        volatile int r = a + b + 11;
        return r;
    }

    // This disabled release() target retains its backend without an active patch.
    DMK_PROOF_TARGET int leak_target_release_disabled(int a, int b)
    {
        volatile int r = a + b + 17;
        return r;
    }

    // Dedicated target for the strict-install-after-a-pin proof. Each GoogleTest case runs in its own ctest process,
    // so that case builds its own pin and cannot borrow one from a sibling.
    DMK_PROOF_TARGET int leak_target_retained_strict(int a, int b)
    {
        volatile int r = a + b + 13;
        return r;
    }

    DMK_PROOF_TARGET int ledger_commit_failure_target(int a, int b)
    {
        volatile int r = a + b + 3;
        return r;
    }

} // namespace dmk_test::hook_fixture
