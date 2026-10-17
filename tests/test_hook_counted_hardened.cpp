#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <utility>

#include "DetourModKit/hook.hpp"

#include "fixtures/hook_fixture.hpp"
#include "fixtures/proof_section.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace dmk_test::hook_fixture;

// tests/CMakeLists.txt compiles this file with the stack protector on every function under GCC and Clang. MSVC
// builds it with its default /GS. The counted thunk opts out of both, so its code stays straight-line.

namespace
{
    constexpr std::int64_t WIDE_DELTA = 0x1000;
    constexpr int SCALAR_DELTA = 0x2000;

    /// A 24-byte result returns through a hidden pointer, so the thunk holds an address-taken local for it.
    struct WideResult
    {
        std::int64_t first;
        std::int64_t second;
        std::int64_t third;

        bool operator==(const WideResult &) const = default;
    };

    using WideFn = WideResult (*)(std::int64_t);

    DMK_PROOF_TARGET WideResult wide_target(std::int64_t seed)
    {
        volatile std::int64_t base = seed * 3;
        return WideResult{
            .first = base,
            .second = base + 1,
            .third = base + 2,
        };
    }

    DMK_PROOF_SEEDED_TARGET(scalar_target, 433)

    std::atomic<WideFn> s_wide_original{nullptr};

    DMK_TEST_NOINLINE WideResult wide_detour(std::int64_t seed) noexcept
    {
        WideResult result = s_wide_original.load(std::memory_order_acquire)(seed);
        result.first += WIDE_DELTA;
        return result;
    }

    DMK_TEST_NOINLINE int scalar_detour(int value) noexcept
    {
        return value + SCALAR_DELTA;
    }
} // namespace

// The install decodes each thunk and refuses a branch. A stack protector check is one, so a thunk that carries it
// never installs. Both thunks install here, run, and retire.
TEST(HookCountedHardened, ThunksInstallWithoutAStackProtectorCheck)
{
    const WideResult wide_pristine = dmk_test::call_unfolded(&wide_target, 7);
    const int scalar_pristine = dmk_test::call_unfolded(&scalar_target, 5);
    HookStack stack;

    Result<Hook> wide = inline_at<&wide_detour>(InlineRequest{
        .name = "HardenedWide",
        .target = addr_of(&wide_target),
    });
    ASSERT_TRUE(wide.has_value()) << wide.error().message();
    Hook &wide_hook = stack.push(std::move(*wide));
    s_wide_original.store(wide_hook.original<WideFn>(), std::memory_order_release);
    ASSERT_TRUE(wide_hook.enable().has_value());

    Result<Hook> scalar = inline_at<&scalar_detour>(InlineRequest{
        .name = "HardenedScalar",
        .target = addr_of(&scalar_target),
    });
    ASSERT_TRUE(scalar.has_value()) << scalar.error().message();
    ASSERT_TRUE(stack.push(std::move(*scalar)).enable().has_value());

    const WideResult hooked = dmk_test::call_unfolded(&wide_target, 7);
    EXPECT_EQ(hooked.first, wide_pristine.first + WIDE_DELTA);
    EXPECT_EQ(hooked.second, wide_pristine.second);
    EXPECT_EQ(hooked.third, wide_pristine.third);
    EXPECT_EQ(dmk_test::call_unfolded(&scalar_target, 5), 5 + SCALAR_DELTA) << "the scalar detour did not run";

    const HookRetirement retired = stack.retire(std::chrono::milliseconds{2000});
    EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
    EXPECT_EQ(retired.restored, 2u);
    EXPECT_EQ(retired.vacated + retired.pinned, 0u);
    EXPECT_EQ(dmk_test::call_unfolded(&wide_target, 7), wide_pristine);
    EXPECT_EQ(dmk_test::call_unfolded(&scalar_target, 5), scalar_pristine);
}
