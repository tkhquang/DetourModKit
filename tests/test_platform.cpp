#include <gtest/gtest.h>
#include <cstring>

#include "platform.hpp"
#include "DetourModKit/version.hpp"

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

// --- Version macro tests ---

TEST(VersionTest, MajorMinorPatchAreDefined)
{
    EXPECT_GE(DMK_VERSION_MAJOR, 0);
    EXPECT_GE(DMK_VERSION_MINOR, 0);
    EXPECT_GE(DMK_VERSION_PATCH, 0);
}

TEST(VersionTest, VersionStringIsNonEmpty)
{
    EXPECT_GT(std::strlen(DMK_VERSION_STRING), 0u);
}

TEST(VersionTest, MakeVersionEncoding)
{
    EXPECT_EQ(DMK_MAKE_VERSION(2, 3, 0), 20300);
    EXPECT_EQ(DMK_MAKE_VERSION(1, 0, 0), 10000);
    EXPECT_EQ(DMK_MAKE_VERSION(0, 0, 1), 1);
}

TEST(VersionTest, VersionAtLeast)
{
    EXPECT_TRUE(DMK_VERSION_AT_LEAST(0, 0, 1));
    EXPECT_TRUE(DMK_VERSION_AT_LEAST(DMK_VERSION_MAJOR, DMK_VERSION_MINOR, DMK_VERSION_PATCH));
    EXPECT_FALSE(DMK_VERSION_AT_LEAST(99, 0, 0));
}

TEST(VersionTest, CompositeMatchesComponents)
{
    EXPECT_EQ(DMK_VERSION, DMK_MAKE_VERSION(DMK_VERSION_MAJOR, DMK_VERSION_MINOR, DMK_VERSION_PATCH));
}
