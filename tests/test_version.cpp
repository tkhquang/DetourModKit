#include <gtest/gtest.h>

#include "DetourModKit/version.hpp"

#include <cstring>

namespace
{
    TEST(VersionTest, MacrosMatchProjectVersion)
    {
        EXPECT_EQ(DMK_VERSION_MAJOR, 3);
        EXPECT_EQ(DMK_VERSION_MINOR, 2);
        EXPECT_EQ(DMK_VERSION_PATCH, 2);
    }

    TEST(VersionTest, VersionStringMatchesMacros)
    {
        EXPECT_STREQ(DMK_VERSION_STRING, "3.2.2");
    }

    TEST(VersionTest, AtLeastComparisonsAreCorrect)
    {
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 2, 2));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 2, 1));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 2, 0));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 1, 0));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(2, 0, 0));
        EXPECT_FALSE(DMK_VERSION_AT_LEAST(3, 2, 3));
        EXPECT_FALSE(DMK_VERSION_AT_LEAST(3, 3, 0));
        EXPECT_FALSE(DMK_VERSION_AT_LEAST(4, 0, 0));
    }

    TEST(VersionTest, EncodedVersionMatchesComponents)
    {
        EXPECT_EQ(DMK_VERSION,
                  DMK_MAKE_VERSION(DMK_VERSION_MAJOR,
                                   DMK_VERSION_MINOR,
                                   DMK_VERSION_PATCH));
    }
} // namespace
