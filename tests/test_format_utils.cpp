// Unit tests for Format utilities module
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "DetourModKit/format_utils.hpp"

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
