/**
 * @file test_unchecked_find_pattern_alloc.cpp
 * @brief Pins the per-call allocation count and the 1-based occurrence walk of scan::unchecked::find_pattern.
 * @details Each call copies its Pattern into a heap-backed engine pattern. A change to that setup must update these
 *          pins and the scan.hpp note together.
 */

#include "DetourModKit/scan.hpp"

#include "test_alloc_probe.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

using namespace DetourModKit;

namespace
{
    constexpr std::size_t HAYSTACK_SIZE = std::size_t{1} << 20;
    constexpr std::size_t NEEDLE_STRIDE = 4096;
    constexpr std::size_t NEEDLE_COUNT = HAYSTACK_SIZE / NEEDLE_STRIDE;
    // An interior offset leaves a non-empty suffix after the last needle, so the terminal miss also builds the pattern.
    constexpr std::size_t NEEDLE_OFFSET = 0x7A3;
    constexpr std::size_t PROBED_OCCURRENCE = 100;

    // Twelve distinct literal bytes have no border, so no match can overlap a planted copy. The frequency table scores
    // 0x48 and 0x8B, which moves the compile-time anchor to index 2.
    constexpr scan::Pattern NEEDLE = scan::Pattern::literal("48 8B D1 7E 29 B3 C6 5A 0F 93 E4 1D");

    consteval bool needle_is_distinct_and_literal()
    {
        const std::span<const std::byte> bytes = NEEDLE.bytes();
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            if (NEEDLE.mask()[i] != std::byte{0xFF})
            {
                return false;
            }
            for (std::size_t j = i + 1; j < bytes.size(); ++j)
            {
                if (bytes[i] == bytes[j])
                {
                    return false;
                }
            }
        }
        return true;
    }

    static_assert(NEEDLE.size() == 12);
    static_assert(!NEEDLE.has_jumps());
    static_assert(NEEDLE.offset() == 0);
    static_assert(NEEDLE.anchor_index() == 2);
    static_assert(needle_is_distinct_and_literal());
    static_assert(NEEDLE_OFFSET + 12 < NEEDLE_STRIDE);

    [[nodiscard]] constexpr std::size_t needle_offset(std::size_t index) noexcept
    {
        return index * NEEDLE_STRIDE + NEEDLE_OFFSET;
    }

    [[nodiscard]] std::vector<std::byte> make_planted_haystack()
    {
        std::vector<std::byte> haystack(HAYSTACK_SIZE);
        std::uint64_t state = 0x243F6A8885A308D3ULL;
        for (std::byte &value : haystack)
        {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            value = static_cast<std::byte>(state >> 56);
        }
        for (std::size_t index = 0; index < NEEDLE_COUNT; ++index)
        {
            std::memcpy(haystack.data() + needle_offset(index), NEEDLE.bytes().data(), NEEDLE.size());
        }
        return haystack;
    }

    // An oracle independent of the engine, so a background copy fails the setup instead of the case under test.
    [[nodiscard]] std::size_t count_needles(std::span<const std::byte> haystack) noexcept
    {
        std::size_t count = 0;
        for (std::size_t position = 0; position + NEEDLE.size() <= haystack.size(); ++position)
        {
            if (std::memcmp(haystack.data() + position, NEEDLE.bytes().data(), NEEDLE.size()) == 0)
            {
                ++count;
            }
        }
        return count;
    }

    using FindPatternFunction = decltype(scan::unchecked::find_pattern);
} // namespace

// libstdc++ and the MSVC release STL charge exactly the two engine buffers per call. The MSVC debug STL adds container
// proxies, so every STL pins a constant per-call cost and only a proxy-free STL pins the exact value.
TEST(ScannerUncheckedAllocationTest, CursorWalkFindsEveryNeedleAtAFixedPerCallCost)
{
    const std::vector<std::byte> haystack = make_planted_haystack();
    ASSERT_EQ(count_needles(haystack), NEEDLE_COUNT);

    // The volatile pointer stops an inline expansion of the entry point into the walk.
    FindPatternFunction *volatile find_raw = &scan::unchecked::find_pattern;
    const std::byte *const base = haystack.data();
    const std::byte *const end = base + haystack.size();

    // Preallocated storage keeps every allocation between the counter reads charged to the call under test.
    std::array<const std::byte *, NEEDLE_COUNT> hits{};
    std::array<long long, NEEDLE_COUNT + 1> call_allocations{};
    std::size_t hit_count = 0;
    std::size_t call_count = 0;
    bool rejected_hit = false;
    const std::byte *cursor = base;
    while (call_count < call_allocations.size())
    {
        const Region scope{Address{cursor}, static_cast<std::size_t>(end - cursor)};
        const long long before = dmk_test::thread_new_calls();
        const std::byte *const hit = find_raw(scope, NEEDLE, 1);
        call_allocations[call_count++] = dmk_test::thread_new_calls() - before;
        if (hit == nullptr)
        {
            break;
        }
        if (hit < cursor || hit >= end || hit_count == hits.size())
        {
            rejected_hit = true;
            break;
        }
        hits[hit_count++] = hit;
        cursor = hit + 1;
    }

    EXPECT_FALSE(rejected_hit);
    ASSERT_EQ(hit_count, NEEDLE_COUNT);
    for (std::size_t index = 0; index < NEEDLE_COUNT; ++index)
    {
        EXPECT_EQ(hits[index], base + needle_offset(index)) << "needle " << index;
    }
    ASSERT_EQ(call_count, NEEDLE_COUNT + 1);
    for (std::size_t call = 0; call < call_count; ++call)
    {
        EXPECT_EQ(call_allocations[call], call_allocations[0]) << "call " << call;
    }
    EXPECT_GE(call_allocations[0], 2);
    if (dmk_test::stl_supports_exact_allocation_budgets())
    {
        EXPECT_EQ(call_allocations[0], 2);
    }
}

TEST(ScannerUncheckedAllocationTest, OccurrenceRestartsFromTheRegionBaseAtTheSamePerCallCost)
{
    const std::vector<std::byte> haystack = make_planted_haystack();
    ASSERT_EQ(count_needles(haystack), NEEDLE_COUNT);

    FindPatternFunction *volatile find_raw = &scan::unchecked::find_pattern;
    const std::byte *const base = haystack.data();
    const Region whole{Address{base}, haystack.size()};

    const long long before_probe = dmk_test::thread_new_calls();
    const std::byte *const probed = find_raw(whole, NEEDLE, PROBED_OCCURRENCE);
    const long long probe_allocations = dmk_test::thread_new_calls() - before_probe;

    const long long before_zero = dmk_test::thread_new_calls();
    const std::byte *const zeroth = find_raw(whole, NEEDLE, 0);
    const long long zero_allocations = dmk_test::thread_new_calls() - before_zero;

    EXPECT_EQ(probed, base + (PROBED_OCCURRENCE - 1) * NEEDLE_STRIDE + NEEDLE_OFFSET);
    EXPECT_EQ(find_raw(whole, NEEDLE, 1), base + needle_offset(0));
    EXPECT_EQ(find_raw(whole, NEEDLE, NEEDLE_COUNT), base + needle_offset(NEEDLE_COUNT - 1));
    EXPECT_EQ(find_raw(whole, NEEDLE, NEEDLE_COUNT + 1), nullptr);
    EXPECT_EQ(zeroth, nullptr);
    // Occurrence 0 returns before the setup, so the measurement window itself charges nothing.
    EXPECT_EQ(zero_allocations, 0);
    EXPECT_GE(probe_allocations, 2);
    if (dmk_test::stl_supports_exact_allocation_budgets())
    {
        EXPECT_EQ(probe_allocations, 2);
    }
}

TEST(ScannerUncheckedAllocationTest, BoundedJumpPatternAlsoCopiesItsJumpTable)
{
    constexpr scan::Pattern jumped = scan::Pattern::literal("48 8B D1 [0-2] 29 B3");
    static_assert(jumped.has_jumps());
    const std::vector<std::byte> haystack = make_planted_haystack();

    FindPatternFunction *volatile find_raw = &scan::unchecked::find_pattern;
    const Region whole{Address{haystack.data()}, haystack.size()};

    const long long before = dmk_test::thread_new_calls();
    const std::byte *const hit = find_raw(whole, jumped, 1);
    const long long allocations = dmk_test::thread_new_calls() - before;

    EXPECT_NE(hit, nullptr);
    EXPECT_GE(allocations, 3);
    if (dmk_test::stl_supports_exact_allocation_budgets())
    {
        EXPECT_EQ(allocations, 3);
    }
}
