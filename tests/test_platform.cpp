#include <gtest/gtest.h>

#include "platform.hpp"

using namespace DetourModKit::detail;

TEST(PlatformTest, IsLoaderLockHeld_FalseInNormalContext)
{
    EXPECT_FALSE(is_loader_lock_held());
}

TEST(PlatformTest, PinCurrentModule_SucceedsInNormalContext)
{
    EXPECT_TRUE(pin_current_module());
}

TEST(PlatformTest, PinCurrentModule_IdempotentMultipleCalls)
{
    EXPECT_TRUE(pin_current_module());
    EXPECT_TRUE(pin_current_module());
    EXPECT_TRUE(pin_current_module());
}
