/**
 * @file test_bench_alloc.cpp
 * @brief Pins the counting-allocator arithmetic in bench_alloc.hpp.
 * @details Includes the header WITHOUT DMK_BENCH_COUNT_ALLOCATIONS, so only the counters are under test
 *          and this executable's global allocator stays untouched.
 */

#include "bench_alloc.hpp"

#include <gtest/gtest.h>

#include <cstdint>

namespace
{
    class BenchAllocCountersTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            m_saved_calls = dmk_alloc::g_alloc_calls.load();
            m_saved_alloc = dmk_alloc::g_alloc_bytes.load();
            m_saved_free = dmk_alloc::g_free_bytes.load();
            m_saved_peak = dmk_alloc::g_peak_live_bytes.load();
        }

        void TearDown() override
        {
            dmk_alloc::g_alloc_calls.store(m_saved_calls);
            dmk_alloc::g_alloc_bytes.store(m_saved_alloc);
            dmk_alloc::g_free_bytes.store(m_saved_free);
            dmk_alloc::g_peak_live_bytes.store(m_saved_peak);
        }

    private:
        std::uint64_t m_saved_calls{0};
        std::uint64_t m_saved_alloc{0};
        std::uint64_t m_saved_free{0};
        std::uint64_t m_saved_peak{0};
    };

    TEST_F(BenchAllocCountersTest, LiveBytesClampsWhenFreesExceedAllocations)
    {
        dmk_alloc::g_alloc_bytes.store(100);
        dmk_alloc::g_free_bytes.store(250);
        EXPECT_EQ(dmk_alloc::live_bytes(), 0u);
    }

    TEST_F(BenchAllocCountersTest, PeakDoesNotWrapAfterForeignFree)
    {
        dmk_alloc::g_alloc_bytes.store(100);
        dmk_alloc::g_free_bytes.store(250);
        dmk_alloc::reset_peak();
        dmk_alloc::note_alloc_bytes(16);
        EXPECT_EQ(dmk_alloc::peak_live_bytes(), 0u);
    }

    TEST_F(BenchAllocCountersTest, PeakTracksNetGrowth)
    {
        dmk_alloc::g_alloc_bytes.store(1000);
        dmk_alloc::g_free_bytes.store(400);
        dmk_alloc::reset_peak();
        EXPECT_EQ(dmk_alloc::peak_live_bytes(), 600u);
        dmk_alloc::note_alloc_bytes(64);
        EXPECT_EQ(dmk_alloc::peak_live_bytes(), 664u);
        EXPECT_EQ(dmk_alloc::live_bytes(), 664u);
    }
} // namespace
