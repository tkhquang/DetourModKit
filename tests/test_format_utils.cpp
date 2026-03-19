// Unit tests for Format utilities module
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "DetourModKit/format.hpp"

using namespace DetourModKit;

// Test format_address
TEST(FormatUtilsTest, FormatAddress)
{
    std::string result = Format::format_address(0x12345678);
    EXPECT_EQ(result, "0x0000000012345678");

    result = Format::format_address(0x1000);
    EXPECT_EQ(result, "0x0000000000001000");
}

// Test format_hex
TEST(FormatUtilsTest, FormatHex)
{
    std::string result = Format::format_hex(255);
    EXPECT_EQ(result, "0xFF");

    result = Format::format_hex(255, 4);
    EXPECT_EQ(result, "0x00FF");
}

// Test format_byte
TEST(FormatUtilsTest, FormatByte)
{
    std::byte b = std::byte{0xCC};
    std::string result = Format::format_byte(b);
    EXPECT_EQ(result, "0xCC");
}

// Test format_int_vector
TEST(FormatUtilsTest, FormatIntVector)
{
    std::vector<int> values = {0x72, 0xA0, 0x20};
    std::string result = Format::format_int_vector(values);
    EXPECT_EQ(result, "[0x72, 0xA0, 0x20]");

    // Empty vector
    std::vector<int> empty;
    result = Format::format_int_vector(empty);
    EXPECT_EQ(result, "[]");
}

// Test format_vkcode
TEST(FormatUtilsTest, FormatVkcode)
{
    std::string result = Format::format_vkcode(0x72);
    EXPECT_EQ(result, "0x72");
}

// Test format_vkcode_list
TEST(FormatUtilsTest, FormatVkcodeList)
{
    std::vector<int> keys = {0x41, 0x42, 0x43};
    std::string result = Format::format_vkcode_list(keys);
    EXPECT_EQ(result, "[0x41, 0x42, 0x43]");
}

// Test format_vkcode_list with empty vector
TEST(FormatUtilsTest, FormatVkcodeList_Empty)
{
    std::vector<int> keys;
    std::string result = Format::format_vkcode_list(keys);
    EXPECT_EQ(result, "[]");
}

// Test format_vkcode_list with single element
TEST(FormatUtilsTest, FormatVkcodeList_Single)
{
    std::vector<int> keys = {0x41};
    std::string result = Format::format_vkcode_list(keys);
    EXPECT_EQ(result, "[0x41]");
}

// Test format_address with zero
TEST(FormatUtilsTest, FormatAddress_Zero)
{
    std::string result = Format::format_address(0);
    EXPECT_EQ(result, "0x0000000000000000");
}

// Test format_address with max value
TEST(FormatUtilsTest, FormatAddress_Max)
{
    std::string result = Format::format_address(0xFFFFFFFFFFFFFFFF);
    EXPECT_EQ(result, "0xFFFFFFFFFFFFFFFF");
}

// Test format_hex with zero
TEST(FormatUtilsTest, FormatHex_Zero)
{
    std::string result = Format::format_hex(0);
    EXPECT_EQ(result, "0x0");
}

// Test format_hex with zero width
TEST(FormatUtilsTest, FormatHex_ZeroWidth)
{
    std::string result = Format::format_hex(255, 0);
    EXPECT_EQ(result, "0xFF");
}

// Test format_hex with large width
TEST(FormatUtilsTest, FormatHex_LargeWidth)
{
    std::string result = Format::format_hex(255, 8);
    EXPECT_EQ(result, "0x000000FF");
}

// Test format_byte with zero
TEST(FormatUtilsTest, FormatByte_Zero)
{
    std::byte b = std::byte{0x00};
    std::string result = Format::format_byte(b);
    EXPECT_EQ(result, "0x00");
}

// Test format_byte with max value
TEST(FormatUtilsTest, FormatByte_Max)
{
    std::byte b = std::byte{0xFF};
    std::string result = Format::format_byte(b);
    EXPECT_EQ(result, "0xFF");
}

// Test format_int_vector with large values
TEST(FormatUtilsTest, FormatIntVector_LargeValues)
{
    std::vector<int> values = {static_cast<int>(0x7FFFFFFF), static_cast<int>(0x80000000)};
    std::string result = Format::format_int_vector(values);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("0x"), std::string::npos);
}

// Test format_int_vector with negative values
TEST(FormatUtilsTest, FormatIntVector_Negative)
{
    std::vector<int> values = {-1, -2, -3};
    std::string result = Format::format_int_vector(values);
    EXPECT_FALSE(result.empty());
}

// Test format_vkcode with zero
TEST(FormatUtilsTest, FormatVkcode_Zero)
{
    std::string result = Format::format_vkcode(0);
    // Format may vary, just check it contains 0x
    EXPECT_NE(result.find("0x"), std::string::npos);
}

// Test format_vkcode with large value
TEST(FormatUtilsTest, FormatVkcode_Large)
{
    std::string result = Format::format_vkcode(0xFF);
    EXPECT_EQ(result, "0xFF");
}

// Test String::trim (via format.hpp)
TEST(FormatUtilsTest, StringTrim)
{
    using namespace DetourModKit::String;

    // Test trimming leading spaces
    EXPECT_EQ(trim("  hello"), "hello");

    // Test trimming trailing spaces
    EXPECT_EQ(trim("hello  "), "hello");

    // Test trimming both ends
    EXPECT_EQ(trim("  hello  "), "hello");

    // Test trimming tabs
    EXPECT_EQ(trim("\thello\t"), "hello");

    // Test no trimming needed
    EXPECT_EQ(trim("hello"), "hello");

    // Test empty string
    EXPECT_EQ(trim(""), "");

    // Test only whitespace
    EXPECT_EQ(trim("   "), "");
}
