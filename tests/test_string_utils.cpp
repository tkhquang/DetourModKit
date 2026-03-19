// Unit tests for String utilities module
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "DetourModKit/format.hpp"

using namespace DetourModKit;

// Test trim with leading spaces
TEST(StringUtilsTest, TrimLeading)
{
    std::string result = String::trim("  hello");
    EXPECT_EQ(result, "hello");
}

// Test trim with trailing spaces
TEST(StringUtilsTest, TrimTrailing)
{
    std::string result = String::trim("hello  ");
    EXPECT_EQ(result, "hello");
}

// Test trim with both leading and trailing spaces
TEST(StringUtilsTest, TrimBoth)
{
    std::string result = String::trim("  hello  ");
    EXPECT_EQ(result, "hello");
}

// Test trim with no spaces
TEST(StringUtilsTest, TrimNoSpaces)
{
    std::string result = String::trim("hello");
    EXPECT_EQ(result, "hello");
}

// Test trim with empty string
TEST(StringUtilsTest, TrimEmpty)
{
    std::string result = String::trim("");
    EXPECT_EQ(result, "");
}

// Test trim with only spaces
TEST(StringUtilsTest, TrimOnlySpaces)
{
    std::string result = String::trim("   ");
    EXPECT_EQ(result, "");
}

// Test trim with tabs
TEST(StringUtilsTest, TrimTabs)
{
    std::string result = String::trim("\thello\t");
    EXPECT_EQ(result, "hello");
}

// Test trim with mixed whitespace
TEST(StringUtilsTest, TrimMixedWhitespace)
{
    std::string result = String::trim(" \t hello \t ");
    EXPECT_EQ(result, "hello");
}

// Test trim preserves internal spaces
TEST(StringUtilsTest, TrimPreservesInternal)
{
    std::string result = String::trim("  hello world  ");
    EXPECT_EQ(result, "hello world");
}

// Test trim with newlines
TEST(StringUtilsTest, TrimNewlines)
{
    std::string result = String::trim("\n\rhello\n\r");
    EXPECT_EQ(result, "hello");
}
