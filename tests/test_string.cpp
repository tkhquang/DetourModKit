// Unit tests for String utilities module
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "DetourModKit/format.hpp"

using namespace DetourModKit;

// Test trim with leading spaces
TEST(StringTest, TrimLeading)
{
    std::string result = String::trim("  hello");
    EXPECT_EQ(result, "hello");
}

// Test trim with trailing spaces
TEST(StringTest, TrimTrailing)
{
    std::string result = String::trim("hello  ");
    EXPECT_EQ(result, "hello");
}

// Test trim with both leading and trailing spaces
TEST(StringTest, TrimBoth)
{
    std::string result = String::trim("  hello  ");
    EXPECT_EQ(result, "hello");
}

// Test trim with no spaces
TEST(StringTest, TrimNoSpaces)
{
    std::string result = String::trim("hello");
    EXPECT_EQ(result, "hello");
}

// Test trim with empty string
TEST(StringTest, TrimEmpty)
{
    std::string result = String::trim("");
    EXPECT_EQ(result, "");
}

// Test trim with only spaces
TEST(StringTest, TrimOnlySpaces)
{
    std::string result = String::trim("   ");
    EXPECT_EQ(result, "");
}

// Test trim with tabs
TEST(StringTest, TrimTabs)
{
    std::string result = String::trim("\thello\t");
    EXPECT_EQ(result, "hello");
}

// Test trim with mixed whitespace
TEST(StringTest, TrimMixedWhitespace)
{
    std::string result = String::trim(" \t hello \t ");
    EXPECT_EQ(result, "hello");
}

// Test trim preserves internal spaces
TEST(StringTest, TrimPreservesInternal)
{
    std::string result = String::trim("  hello world  ");
    EXPECT_EQ(result, "hello world");
}

// Test trim with newlines
TEST(StringTest, TrimNewlines)
{
    std::string result = String::trim("\n\rhello\n\r");
    EXPECT_EQ(result, "hello");
}
