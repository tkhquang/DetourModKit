#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "DetourModKit/abi/staged_reload.h"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/staged_reload.hpp"

#include "platform.hpp"

// A loader and a logic image built from different revisions exchange these values, so each one is frozen.
static_assert(DMK_STAGED_RELOAD_ABI_VERSION == 3u);
static_assert(DMK_STAGED_RELOAD_REFUSED == 0u);
static_assert(DMK_STAGED_RELOAD_OK == 1u);
static_assert(DMK_STAGED_RELOAD_RETAINED == 2u);
static_assert(DMK_STAGED_RELOAD_BUSY == 3u);
static_assert(DMK_STAGED_RELOAD_RESTART_REQUIRED == 4u);

// The shutdown export returns a 32-bit unsigned value, and each macro expands to that type.
static_assert(std::is_same_v<decltype(DMK_STAGED_RELOAD_ABI_VERSION), unsigned int>);
static_assert(std::is_same_v<decltype(DMK_STAGED_RELOAD_REFUSED), unsigned int>);
static_assert(std::is_same_v<decltype(DMK_STAGED_RELOAD_OK), unsigned int>);
static_assert(std::is_same_v<decltype(DMK_STAGED_RELOAD_RETAINED), unsigned int>);
static_assert(std::is_same_v<decltype(DMK_STAGED_RELOAD_BUSY), unsigned int>);
static_assert(std::is_same_v<decltype(DMK_STAGED_RELOAD_RESTART_REQUIRED), unsigned int>);
static_assert(sizeof(unsigned int) == 4);

TEST(StagedReloadAbi, ValuesAndLayoutAreStable)
{
    EXPECT_EQ(DMK_STAGED_RELOAD_ABI_VERSION, 3u);
    EXPECT_EQ(DMK_STAGED_RELOAD_REFUSED, 0u);
    EXPECT_EQ(DMK_STAGED_RELOAD_OK, 1u);
    EXPECT_EQ(DMK_STAGED_RELOAD_RETAINED, 2u);
    EXPECT_EQ(DMK_STAGED_RELOAD_BUSY, 3u);
    EXPECT_EQ(DMK_STAGED_RELOAD_RESTART_REQUIRED, 4u);
}

namespace
{
    namespace diag = DetourModKit::diagnostics;
    namespace hook = DetourModKit::hook;
    namespace staged = DetourModKit::staged_reload;

    constexpr std::uint32_t LOADER_ABI_2 = 2;
    constexpr std::uint32_t LOADER_ABI_3 = DMK_STAGED_RELOAD_ABI_VERSION;

    /// The verdict that an ABI 3 loader and an ABI 2 loader receive for one row.
    struct Expected
    {
        std::uint32_t abi_3;
        std::uint32_t abi_2;
    };

    constexpr Expected UNMAPS{DMK_STAGED_RELOAD_OK, DMK_STAGED_RELOAD_OK};
    constexpr Expected RETAINS{DMK_STAGED_RELOAD_RETAINED, DMK_STAGED_RELOAD_RETAINED};
    constexpr Expected RETRIES{DMK_STAGED_RELOAD_BUSY, DMK_STAGED_RELOAD_REFUSED};
    constexpr Expected RESTARTS{DMK_STAGED_RELOAD_RESTART_REQUIRED, DMK_STAGED_RELOAD_REFUSED};

    // A new bucket or reason must take a row here.
    constexpr std::array<Expected, static_cast<std::size_t>(diag::LeakSubsystem::Count)> LEAK_ROWS{
        RESTARTS, // HookManager
        RETAINS,  // Logger
        RETAINS,  // AsyncLogger
        RETAINS,  // ConfigWatcher
        RETAINS,  // Input
        RETAINS,  // MemoryCache
        RETAINS,  // Worker
        RETAINS,  // Bootstrap
        RETAINS,  // Diagnostics
        UNMAPS,   // HookResidue
    };
    constexpr std::array<Expected, static_cast<std::size_t>(diag::ModulePinReason::Count)> PIN_ROWS{
        RESTARTS, // Hook
        RETAINS,  // Worker
        RETAINS,  // Bootstrap
        RETAINS,  // AsyncLogger
        RETAINS,  // MemoryCache
        RETAINS,  // InputPoller
        RETAINS,  // LifecycleReaper
        RETAINS,  // WndprocKeepalive: reserved, and a self-module pin retains if any code ever books it
        RETAINS,  // XInputKeepalive
        UNMAPS,   // XInputTarget: references the provider module, not this image
        RETAINS,  // MessageHookKeepalive
    };

    void expect_verdict(const hook::HookRetirement &retirement, const staged::Baseline &baseline, Expected expected)
    {
        EXPECT_EQ(staged::verdict(retirement, baseline, LOADER_ABI_3), expected.abi_3);
        EXPECT_EQ(staged::verdict(retirement, baseline, LOADER_ABI_2), expected.abi_2);
    }

    class StagedReloadVerdict : public ::testing::Test
    {
    protected:
        // Each row books real leak events. Clear them, so later suites of this process start from zero.
        void TearDown() override { diag::reset_intentional_leaks(); }
    };
} // namespace

TEST_F(StagedReloadVerdict, TruthTable)
{
    const hook::HookRetirement retired{};
    const hook::HookRetirement busy{.outcome = hook::RetirementOutcome::Busy, .in_flight = 1};
    const hook::HookRetirement refused{
        .outcome = hook::RetirementOutcome::Refused,
        .refusal = DetourModKit::ErrorCode::LayerResidueLimitReached,
    };
    const hook::HookRetirement pinned{.restored = 1, .pinned = 1};

    {
        SCOPED_TRACE("outcomes over a clean baseline");
        const staged::Baseline baseline = staged::capture();
        expect_verdict(retired, baseline, UNMAPS);
        expect_verdict(busy, baseline, RETRIES);
        expect_verdict(refused, baseline, RESTARTS);
        expect_verdict(pinned, baseline, RESTARTS);
        EXPECT_EQ(staged::verdict(busy, baseline, LOADER_ABI_3 + 1), DMK_STAGED_RELOAD_BUSY);
        EXPECT_EQ(staged::verdict(refused, baseline, LOADER_ABI_3 + 1), DMK_STAGED_RELOAD_RESTART_REQUIRED);
    }

    for (std::size_t index = 0; index < LEAK_ROWS.size(); ++index)
    {
        SCOPED_TRACE(::testing::Message() << "leak bucket " << index);
        const staged::Baseline baseline = staged::capture();
        diag::record_intentional_leak(static_cast<diag::LeakSubsystem>(index));
        expect_verdict(retired, baseline, LEAK_ROWS[index]);
        // Busy changed nothing, so it outranks every count.
        expect_verdict(busy, baseline, RETRIES);
        // A count that exists at capture never reaches the verdict.
        expect_verdict(retired, staged::capture(), UNMAPS);
    }

    for (std::size_t index = 0; index < PIN_ROWS.size(); ++index)
    {
        SCOPED_TRACE(::testing::Message() << "module pin reason " << index);
        const auto reason = static_cast<diag::ModulePinReason>(index);
        const staged::Baseline baseline = staged::capture();
        const HMODULE module = DetourModKit::detail::acquire_module_ref(reason);
        ASSERT_NE(module, nullptr);
        expect_verdict(retired, baseline, PIN_ROWS[index]);
        const staged::Baseline held = staged::capture();
        DetourModKit::detail::release_module_ref(module, reason);
        // A count below its baseline adds nothing.
        expect_verdict(retired, held, UNMAPS);
    }
}
