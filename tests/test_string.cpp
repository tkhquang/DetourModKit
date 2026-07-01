#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "DetourModKit/format.hpp"

using namespace DetourModKit;

TEST(StringTest, TrimLeading)
{
    std::string result = string::trim("  hello");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimTrailing)
{
    std::string result = string::trim("hello  ");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimBoth)
{
    std::string result = string::trim("  hello  ");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimNoSpaces)
{
    std::string result = string::trim("hello");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimEmpty)
{
    std::string result = string::trim("");
    EXPECT_EQ(result, "");
}

TEST(StringTest, TrimOnlySpaces)
{
    std::string result = string::trim("   ");
    EXPECT_EQ(result, "");
}

TEST(StringTest, TrimTabs)
{
    std::string result = string::trim("\thello\t");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimMixedWhitespace)
{
    std::string result = string::trim(" \t hello \t ");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimPreservesInternal)
{
    std::string result = string::trim("  hello world  ");
    EXPECT_EQ(result, "hello world");
}

TEST(StringTest, TrimNewlines)
{
    std::string result = string::trim("\n\rhello\n\r");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimFormFeedAndVerticalTab)
{
    EXPECT_EQ(string::trim("\fhello\f"), "hello");
    EXPECT_EQ(string::trim("\vhello\v"), "hello");
    EXPECT_EQ(string::trim("\f\v\t hello \t\v\f"), "hello");
}

TEST(StringTest, TrimOnlyWhitespaceChars)
{
    EXPECT_EQ(string::trim("\f"), "");
    EXPECT_EQ(string::trim("\v"), "");
    EXPECT_EQ(string::trim("\f\v\t\n\r "), "");
}
