#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "DetourModKit/format.hpp"

using namespace DetourModKit;

TEST(StringTest, TrimLeading)
{
    std::string result = String::trim("  hello");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimTrailing)
{
    std::string result = String::trim("hello  ");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimBoth)
{
    std::string result = String::trim("  hello  ");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimNoSpaces)
{
    std::string result = String::trim("hello");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimEmpty)
{
    std::string result = String::trim("");
    EXPECT_EQ(result, "");
}

TEST(StringTest, TrimOnlySpaces)
{
    std::string result = String::trim("   ");
    EXPECT_EQ(result, "");
}

TEST(StringTest, TrimTabs)
{
    std::string result = String::trim("\thello\t");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimMixedWhitespace)
{
    std::string result = String::trim(" \t hello \t ");
    EXPECT_EQ(result, "hello");
}

TEST(StringTest, TrimPreservesInternal)
{
    std::string result = String::trim("  hello world  ");
    EXPECT_EQ(result, "hello world");
}

TEST(StringTest, TrimNewlines)
{
    std::string result = String::trim("\n\rhello\n\r");
    EXPECT_EQ(result, "hello");
}
