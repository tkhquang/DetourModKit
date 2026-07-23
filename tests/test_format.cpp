#include <gtest/gtest.h>
#include <windows.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "DetourModKit/format.hpp"

using namespace DetourModKit;

TEST(FormatTest, FormatAddress)
{
    std::string result = format::format_address(0x12345678);
    EXPECT_EQ(result, "0x0000000012345678");

    result = format::format_address(0x1000);
    EXPECT_EQ(result, "0x0000000000001000");
}

TEST(FormatTest, FormatHex)
{
    std::string result = format::format_hex(255);
    EXPECT_EQ(result, "0xFF");

    result = format::format_hex(255, 4);
    EXPECT_EQ(result, "0x00FF");
}

TEST(FormatTest, FormatByte)
{
    std::byte b = std::byte{0xCC};
    std::string result = format::format_byte(b);
    EXPECT_EQ(result, "0xCC");
}

TEST(FormatTest, FormatIntVector)
{
    std::vector<int> values = {0x72, 0xA0, 0x20};
    std::string result = format::format_int_vector(values);
    EXPECT_EQ(result, "[0x72, 0xA0, 0x20]");

    std::vector<int> empty;
    result = format::format_int_vector(empty);
    EXPECT_EQ(result, "[]");
}

TEST(FormatTest, FormatVkcode)
{
    std::string result = format::format_vkcode(0x72);
    EXPECT_EQ(result, "0x72");
}

TEST(FormatTest, FormatVkcodeList)
{
    std::vector<int> keys = {0x41, 0x42, 0x43};
    std::string result = format::format_vkcode_list(keys);
    EXPECT_EQ(result, "[0x41, 0x42, 0x43]");
}

TEST(FormatTest, FormatVkcodeList_Empty)
{
    std::vector<int> keys;
    std::string result = format::format_vkcode_list(keys);
    EXPECT_EQ(result, "[]");
}

TEST(FormatTest, FormatVkcodeList_Single)
{
    std::vector<int> keys = {0x41};
    std::string result = format::format_vkcode_list(keys);
    EXPECT_EQ(result, "[0x41]");
}

TEST(FormatTest, FormatAddress_Zero)
{
    std::string result = format::format_address(0);
    EXPECT_EQ(result, "0x0000000000000000");
}

TEST(FormatTest, FormatAddress_Max)
{
    std::string result = format::format_address(0xFFFFFFFFFFFFFFFF);
    EXPECT_EQ(result, "0xFFFFFFFFFFFFFFFF");
}

TEST(FormatTest, FormatHex_Zero)
{
    std::string result = format::format_hex(0);
    EXPECT_EQ(result, "0x0");
}

TEST(FormatTest, FormatHex_ZeroWidth)
{
    std::string result = format::format_hex(255, 0);
    EXPECT_EQ(result, "0xFF");
}

TEST(FormatTest, FormatHex_LargeWidth)
{
    std::string result = format::format_hex(255, 8);
    EXPECT_EQ(result, "0x000000FF");
}

TEST(FormatTest, FormatByte_Zero)
{
    std::byte b = std::byte{0x00};
    std::string result = format::format_byte(b);
    EXPECT_EQ(result, "0x00");
}

TEST(FormatTest, FormatByte_Max)
{
    std::byte b = std::byte{0xFF};
    std::string result = format::format_byte(b);
    EXPECT_EQ(result, "0xFF");
}

TEST(FormatTest, FormatIntVector_LargeValues)
{
    std::vector<int> values = {static_cast<int>(0x7FFFFFFF), static_cast<int>(0x80000000)};
    std::string result = format::format_int_vector(values);
    EXPECT_EQ(result, "[0x7FFFFFFF, 0x80000000]");
}

TEST(FormatTest, FormatIntVector_Negative)
{
    std::vector<int> values = {-1, -2, -3};
    std::string result = format::format_int_vector(values);
    EXPECT_EQ(result, "[0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD]");
}

TEST(FormatTest, FormatVkcode_Zero)
{
    std::string result = format::format_vkcode(0);
    EXPECT_NE(result.find("0x"), std::string::npos);
}

TEST(FormatTest, FormatVkcode_Large)
{
    std::string result = format::format_vkcode(0xFF);
    EXPECT_EQ(result, "0xFF");
}

TEST(FormatTest, FormatHex_Negative)
{
    std::string result = format::format_hex(-1);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("0x"), std::string::npos);
    std::string result2 = format::format_hex(-256);
    EXPECT_FALSE(result2.empty());
    EXPECT_NE(result2.find("0x"), std::string::npos);
}

TEST(FormatTest, FormatAddress_Width)
{
    std::string result = format::format_address(0);
    EXPECT_EQ(result.size(), sizeof(uintptr_t) * 2 + 2);
    EXPECT_EQ(result.substr(0, 2), "0x");

    std::string result_max = format::format_address(UINTPTR_MAX);
    EXPECT_EQ(result_max.size(), sizeof(uintptr_t) * 2 + 2);
}

TEST(FormatTest, FormatHex_PtrdiffPositive)
{
    ptrdiff_t value = 0x1234;
    std::string result = format::format_hex(value);
    EXPECT_EQ(result, "0x1234");
}

TEST(FormatTest, FormatHex_PtrdiffNegative)
{
    ptrdiff_t value = -0x10;
    std::string result = format::format_hex(value);
    EXPECT_EQ(result, "-0x10");
}

TEST(FormatTest, FormatHex_PtrdiffZero)
{
    ptrdiff_t value = 0;
    std::string result = format::format_hex(value);
    EXPECT_EQ(result, "0x0");
}

TEST(FormatTest, FormatHex_PtrdiffMinNoUB)
{
    // Negating PTRDIFF_MIN directly is signed-overflow UB; format_hex must take the unsigned-cast negation path.
    ptrdiff_t value = PTRDIFF_MIN;
    std::string result = format::format_hex(value);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.substr(0, 1), "-");
    EXPECT_NE(result.find("0x"), std::string::npos);
}

TEST(FormatTest, FormatHex_PtrdiffMax)
{
    ptrdiff_t value = PTRDIFF_MAX;
    std::string result = format::format_hex(value);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.substr(0, 2), "0x");
}

TEST(FormatTest, FormatHex_PtrdiffMinusOne)
{
    ptrdiff_t value = -1;
    std::string result = format::format_hex(value);
    EXPECT_EQ(result, "-0x1");
}

TEST(FormatTest, FormatHex_UnsignedDisambiguation)
{
    // The constrained std::unsigned_integral overload resolves size_t / unsigned / uint64_t arguments that were
    // previously ambiguous between the int and ptrdiff_t overloads. These calls compiling at all proves the fix.
    EXPECT_EQ(format::format_hex(static_cast<std::size_t>(0xDEADBEEF)), "0xDEADBEEF");
    EXPECT_EQ(format::format_hex(static_cast<unsigned int>(0xABCD)), "0xABCD");
    EXPECT_EQ(format::format_hex(static_cast<std::uint64_t>(0x1122334455667788ULL)), "0x1122334455667788");
}

TEST(FormatTest, FormatHex_UnsignedWidth)
{
    EXPECT_EQ(format::format_hex(static_cast<std::size_t>(0xFF), 4), "0x00FF");
    EXPECT_EQ(format::format_hex(static_cast<unsigned int>(0), 2), "0x00");
}

TEST(FormatTest, FormatHex_UnsignedFullWidthNoNarrowing)
{
    // A value above UINT32_MAX must keep its full width; the signed int overload would have truncated it.
    EXPECT_EQ(format::format_hex(static_cast<std::uint64_t>(0xFFFFFFFFFFFFFFFFULL)), "0xFFFFFFFFFFFFFFFF");
}

TEST(FormatTest, FormatHex_PtrdiffWidthPadsPositive)
{
    // The width binds the ptrdiff_t overload directly now; the pad applies to the hex digits, after "0x".
    ptrdiff_t value = 0xAB;
    EXPECT_EQ(format::format_hex(value, 4), "0x00AB");
}

TEST(FormatTest, FormatHex_PtrdiffWidthPadsNegative)
{
    // The pad count applies to the magnitude's hex digits; the leading '-' and the "0x" prefix sit outside the field.
    ptrdiff_t value = -0x10;
    EXPECT_EQ(format::format_hex(value, 4), "-0x0010");
}

TEST(FormatTest, FormatHex_PtrdiffWidthNoTruncationAboveInt)
{
    // Regression: before the ptrdiff_t overload carried a width parameter, format_hex(ptrdiff, width) bound the int
    // overload and narrowed the 64-bit value to 32 bits. A value whose high half is set must survive intact once a
    // width is supplied, and a width narrower than the natural digit count must leave the value unpadded, never cut.
    ptrdiff_t value = static_cast<ptrdiff_t>(0x1122334455667788LL);
    EXPECT_EQ(format::format_hex(value, 8), "0x1122334455667788");
    EXPECT_EQ(format::format_hex(value), "0x1122334455667788");
}

TEST(FormatTest, FormatHex_PtrdiffWidthNegativeAboveInt)
{
    // A negative pointer difference whose magnitude exceeds 32 bits must keep its full magnitude with a width; the
    // int overload would have widened a truncated 32-bit value to a bogus unsigned representation.
    ptrdiff_t value = -static_cast<ptrdiff_t>(0x0000000100000000LL);
    EXPECT_EQ(format::format_hex(value, 4), "-0x100000000");
}

TEST(FormatTest, SignedLongUsesExactLlp64Bits)
{
    // Negatives use the unsigned 32-bit representation shared by the int and Win32 LONG contracts.
    static_assert(sizeof(long) == 4, "Windows LLP64: long is 32-bit on both supported toolchains");
    EXPECT_EQ(format::format_hex(-1L), "0xFFFFFFFF");
    EXPECT_EQ(format::format_hex(0x10L), "0x10");
    EXPECT_EQ(format::format_hex(-1L, 8), "0xFFFFFFFF");
    EXPECT_EQ(format::format_hex(LONG_MIN), "0x80000000");
    EXPECT_EQ(format::format_hex(0L, 4), "0x0000");
    // HRESULT formatting preserves the complete status-code bit pattern.
    EXPECT_EQ(format::format_hex(E_FAIL), "0x80004005");
}

TEST(FormatCompileTest, Win32SignedIntegerTypedefsResolveUnambiguously)
{
    // Each supported Win32 and language integer type must select one overload on both toolchains.
    const HRESULT hr = E_FAIL;                        // long: exact long overload
    const LONG win_long = -1;                         // long
    const LSTATUS status = ERROR_FILE_NOT_FOUND;      // LONG
    const DWORD dword = 0xDEADBEEFu;                  // unsigned long: unsigned-integral template
    const SIZE_T size = static_cast<SIZE_T>(1) << 40; // unsigned __int64: unsigned-integral template
    const LONG_PTR long_ptr = -0x10;                  // __int64 == ptrdiff_t: signed-magnitude overload
    EXPECT_EQ(format::format_hex(hr), "0x80004005");
    EXPECT_EQ(format::format_hex(win_long), "0xFFFFFFFF");
    EXPECT_EQ(format::format_hex(status), "0x2");
    EXPECT_EQ(format::format_hex(dword), "0xDEADBEEF");
    EXPECT_EQ(format::format_hex(size), "0x10000000000");
    EXPECT_EQ(format::format_hex(long_ptr), "-0x10");

    EXPECT_EQ(format::format_hex(-1), "0xFFFFFFFF");                          // int
    EXPECT_EQ(format::format_hex(0xFFFFFFFFUL), "0xFFFFFFFF");                // unsigned long
    EXPECT_EQ(format::format_hex(static_cast<long long>(-1)), "-0x1");        // long long (== ptrdiff_t on LLP64)
    EXPECT_EQ(format::format_hex(static_cast<std::size_t>(16)), "0x10");      // size_t
    EXPECT_EQ(format::format_hex(static_cast<std::ptrdiff_t>(-16)), "-0x10"); // ptrdiff_t
}
