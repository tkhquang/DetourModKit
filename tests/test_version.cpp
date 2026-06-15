#include <gtest/gtest.h>

#include "DetourModKit/version.hpp"

#include <cstring>
#include <string>

namespace
{
    TEST(VersionTest, MacrosMatchProjectVersion)
    {
        // The one deliberately literal version assertion: it documents the current release and is the single place a
        // version bump must touch in this file. Every other case below is relational so it tracks the macros
        // automatically. The release workflow separately guards that CMakeLists.txt project(VERSION) matches the tag.
        EXPECT_EQ(DMK_VERSION_MAJOR, 3);
        EXPECT_EQ(DMK_VERSION_MINOR, 8);
        EXPECT_EQ(DMK_VERSION_PATCH, 1);
    }

    TEST(VersionTest, VersionStringMatchesMacros)
    {
        // Build the expected string from the numeric macros instead of pinning a literal, so this stays correct
        // across a version bump: version.hpp.in's contract is that DMK_VERSION_STRING mirrors the MAJOR.MINOR.PATCH
        // triple. Only MacrosMatchProjectVersion above pins the literal, as the one deliberate per-release touch point.
        const std::string expected = std::to_string(DMK_VERSION_MAJOR) + "." + std::to_string(DMK_VERSION_MINOR) + "." +
                                     std::to_string(DMK_VERSION_PATCH);
        EXPECT_EQ(std::string(DMK_VERSION_STRING), expected);
    }

    TEST(VersionTest, AtLeastComparisonsAreCorrect)
    {
        // Historical floors: every shipped predecessor stays satisfied because the version only moves forward, so
        // these pin the comparison logic without needing edits on a bump.
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 6, 1));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 6, 0));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 5, 1));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 5, 0));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 4, 1));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 4, 0));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 3, 0));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 2, 0));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(3, 1, 0));
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(2, 0, 0));

        // Relational invariants derived from the current macros instead of literal future versions: the current
        // version satisfies its own triple, but not the next patch or the next major. These never need editing on a
        // bump.
        EXPECT_TRUE(DMK_VERSION_AT_LEAST(DMK_VERSION_MAJOR, DMK_VERSION_MINOR, DMK_VERSION_PATCH));
        EXPECT_FALSE(DMK_VERSION_AT_LEAST(DMK_VERSION_MAJOR, DMK_VERSION_MINOR, DMK_VERSION_PATCH + 1));
        EXPECT_FALSE(DMK_VERSION_AT_LEAST(DMK_VERSION_MAJOR + 1, 0, 0));
    }

    TEST(VersionTest, EncodedVersionMatchesComponents)
    {
        EXPECT_EQ(DMK_VERSION, DMK_MAKE_VERSION(DMK_VERSION_MAJOR, DMK_VERSION_MINOR, DMK_VERSION_PATCH));
    }
} // namespace
