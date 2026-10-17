#include <gtest/gtest.h>

#include <type_traits>

#include "DetourModKit/abi/staged_reload.h"

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
