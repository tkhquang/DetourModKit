#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <thread>
#include <vector>

#include "DetourModKit/filesystem.hpp"

using namespace DetourModKit;

TEST(FilesystemTest, GetRuntimeDirectory)
{
    auto dir = Filesystem::get_runtime_directory();

    EXPECT_FALSE(dir.empty());
    EXPECT_TRUE(std::filesystem::exists(dir));
    EXPECT_TRUE(std::filesystem::path(dir).is_absolute());
}

TEST(FilesystemTest, GetRuntimeDirectory_Consistent)
{
    auto dir1 = Filesystem::get_runtime_directory();
    auto dir2 = Filesystem::get_runtime_directory();

    EXPECT_EQ(dir1, dir2);
}

TEST(FilesystemTest, GetRuntimeDirectory_PathFormat)
{
    auto dir = Filesystem::get_runtime_directory();

    EXPECT_FALSE(dir.empty());
    EXPECT_TRUE(std::filesystem::path(dir).is_absolute());
}

TEST(FilesystemTest, GetRuntimeDirectory_ThreadSafety)
{
    const int num_threads = 4;
    std::vector<std::wstring> results(num_threads);
    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&results, i]()
                             { results[i] = Filesystem::get_runtime_directory(); });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    for (int i = 1; i < num_threads; ++i)
    {
        EXPECT_EQ(results[0], results[i]);
    }
}

TEST(FilesystemTest, GetRuntimeDirectory_NoThrow)
{
    EXPECT_NO_THROW(Filesystem::get_runtime_directory());
}

TEST(FilesystemTest, GetRuntimeDirectory_IsDirectory)
{
    auto dir = Filesystem::get_runtime_directory();
    EXPECT_TRUE(std::filesystem::is_directory(dir));
}

TEST(FilesystemTest, GetRuntimeDirectory_NoTrailingSeparator)
{
    auto dir = Filesystem::get_runtime_directory();
    ASSERT_FALSE(dir.empty());
    wchar_t last = dir.back();
    EXPECT_NE(last, L'/');
    EXPECT_NE(last, L'\\');
}

TEST(FilesystemTest, GetRuntimeDirectory_CachedResult)
{
    // Verify that repeated calls return identical values, consistent with
    // the internal caching of the resolved module directory.
    const auto dir1 = Filesystem::get_runtime_directory();
    const auto dir2 = Filesystem::get_runtime_directory();

    EXPECT_EQ(dir1, dir2);

    // Verify caching makes repeated calls effectively free by timing a burst.
    const int iterations = 10000;
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i)
    {
        auto dir = Filesystem::get_runtime_directory();
        (void)dir;
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    // 10000 cached calls should complete well under 1 second.
    EXPECT_LT(elapsed_ms, 1000)
        << "Cached get_runtime_directory should be near-zero cost per call";
}

TEST(FilesystemUtf8, ReturnsNonEmpty)
{
    const std::string utf8 = Filesystem::get_runtime_directory_utf8();
    EXPECT_FALSE(utf8.empty());
}

TEST(FilesystemUtf8, Cached)
{
    const std::string a = Filesystem::get_runtime_directory_utf8();
    const std::string b = Filesystem::get_runtime_directory_utf8();
    EXPECT_EQ(a, b);
}
