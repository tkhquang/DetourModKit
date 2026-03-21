#include <gtest/gtest.h>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "DetourModKit/format.hpp"

using namespace DetourModKit;

TEST(FormatTest, FormatAddress)
{
    std::string result = Format::format_address(0x12345678);
    EXPECT_EQ(result, "0x0000000012345678");

    result = Format::format_address(0x1000);
    EXPECT_EQ(result, "0x0000000000001000");
}

TEST(FormatTest, FormatHex)
{
    std::string result = Format::format_hex(255);
    EXPECT_EQ(result, "0xFF");

    result = Format::format_hex(255, 4);
    EXPECT_EQ(result, "0x00FF");
}

TEST(FormatTest, FormatByte)
{
    std::byte b = std::byte{0xCC};
    std::string result = Format::format_byte(b);
    EXPECT_EQ(result, "0xCC");
}

TEST(FormatTest, FormatIntVector)
{
    std::vector<int> values = {0x72, 0xA0, 0x20};
    std::string result = Format::format_int_vector(values);
    EXPECT_EQ(result, "[0x72, 0xA0, 0x20]");

    std::vector<int> empty;
    result = Format::format_int_vector(empty);
    EXPECT_EQ(result, "[]");
}

TEST(FormatTest, FormatVkcode)
{
    std::string result = Format::format_vkcode(0x72);
    EXPECT_EQ(result, "0x72");
}

TEST(FormatTest, FormatVkcodeList)
{
    std::vector<int> keys = {0x41, 0x42, 0x43};
    std::string result = Format::format_vkcode_list(keys);
    EXPECT_EQ(result, "[0x41, 0x42, 0x43]");
}

TEST(FormatTest, FormatVkcodeList_Empty)
{
    std::vector<int> keys;
    std::string result = Format::format_vkcode_list(keys);
    EXPECT_EQ(result, "[]");
}

TEST(FormatTest, FormatVkcodeList_Single)
{
    std::vector<int> keys = {0x41};
    std::string result = Format::format_vkcode_list(keys);
    EXPECT_EQ(result, "[0x41]");
}

TEST(FormatTest, FormatAddress_Zero)
{
    std::string result = Format::format_address(0);
    EXPECT_EQ(result, "0x0000000000000000");
}

TEST(FormatTest, FormatAddress_Max)
{
    std::string result = Format::format_address(0xFFFFFFFFFFFFFFFF);
    EXPECT_EQ(result, "0xFFFFFFFFFFFFFFFF");
}

TEST(FormatTest, FormatHex_Zero)
{
    std::string result = Format::format_hex(0);
    EXPECT_EQ(result, "0x0");
}

TEST(FormatTest, FormatHex_ZeroWidth)
{
    std::string result = Format::format_hex(255, 0);
    EXPECT_EQ(result, "0xFF");
}

TEST(FormatTest, FormatHex_LargeWidth)
{
    std::string result = Format::format_hex(255, 8);
    EXPECT_EQ(result, "0x000000FF");
}

TEST(FormatTest, FormatByte_Zero)
{
    std::byte b = std::byte{0x00};
    std::string result = Format::format_byte(b);
    EXPECT_EQ(result, "0x00");
}

TEST(FormatTest, FormatByte_Max)
{
    std::byte b = std::byte{0xFF};
    std::string result = Format::format_byte(b);
    EXPECT_EQ(result, "0xFF");
}

TEST(FormatTest, FormatIntVector_LargeValues)
{
    std::vector<int> values = {static_cast<int>(0x7FFFFFFF), static_cast<int>(0x80000000)};
    std::string result = Format::format_int_vector(values);
    EXPECT_EQ(result, "[0x7FFFFFFF, 0x80000000]");
}

TEST(FormatTest, FormatIntVector_Negative)
{
    std::vector<int> values = {-1, -2, -3};
    std::string result = Format::format_int_vector(values);
    EXPECT_EQ(result, "[0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD]");
}

TEST(FormatTest, FormatVkcode_Zero)
{
    std::string result = Format::format_vkcode(0);
    EXPECT_NE(result.find("0x"), std::string::npos);
}

TEST(FormatTest, FormatVkcode_Large)
{
    std::string result = Format::format_vkcode(0xFF);
    EXPECT_EQ(result, "0xFF");
}

TEST(FormatTest, FormatHex_Negative)
{
    std::string result = Format::format_hex(-1);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("0x"), std::string::npos);
    std::string result2 = Format::format_hex(-256);
    EXPECT_FALSE(result2.empty());
    EXPECT_NE(result2.find("0x"), std::string::npos);
}

TEST(FormatTest, FormatAddress_Width)
{
    std::string result = Format::format_address(0);
    EXPECT_EQ(result.size(), sizeof(uintptr_t) * 2 + 2);
    EXPECT_EQ(result.substr(0, 2), "0x");

    std::string result_max = Format::format_address(UINTPTR_MAX);
    EXPECT_EQ(result_max.size(), sizeof(uintptr_t) * 2 + 2);
}

TEST(FormatTest, FormatHex_PtrdiffPositive)
{
    ptrdiff_t value = 0x1234;
    std::string result = Format::format_hex(value);
    EXPECT_EQ(result, "0x1234");
}

TEST(FormatTest, FormatHex_PtrdiffNegative)
{
    ptrdiff_t value = -0x10;
    std::string result = Format::format_hex(value);
    EXPECT_EQ(result, "-0x10");
}

TEST(FormatTest, FormatHex_PtrdiffZero)
{
    ptrdiff_t value = 0;
    std::string result = Format::format_hex(value);
    EXPECT_EQ(result, "0x0");
}

TEST(FormatTest, FormatHex_PtrdiffMinNoUB)
{
    // This previously caused signed overflow UB via -PTRDIFF_MIN
    ptrdiff_t value = PTRDIFF_MIN;
    std::string result = Format::format_hex(value);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.substr(0, 1), "-");
    EXPECT_NE(result.find("0x"), std::string::npos);
}

TEST(FormatTest, FormatHex_PtrdiffMax)
{
    ptrdiff_t value = PTRDIFF_MAX;
    std::string result = Format::format_hex(value);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.substr(0, 2), "0x");
}

TEST(FormatTest, FormatHex_PtrdiffMinusOne)
{
    ptrdiff_t value = -1;
    std::string result = Format::format_hex(value);
    EXPECT_EQ(result, "-0x1");
}
