// Unit tests for String utilities module
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "DetourModKit/string_utils.hpp"

using namespace DetourModKit;

// Test trim
TEST(StringUtilsTest, Trim)
{
    std::string result = String::trim("  hello  ");
    EXPECT_EQ(result, "hello");

    result = String::trim("hello");
    EXPECT_EQ(result, "hello");

    result = String::trim("");
    EXPECT_EQ(result, "");

    result = String::trim("   ");
    EXPECT_EQ(result, "");
}
