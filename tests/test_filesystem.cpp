#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include "DetourModKit/filesystem.hpp"

using namespace DetourModKit;

TEST(FilesystemTest, GetRuntimeDirectory)
{
    auto dir = filesystem::get_runtime_directory();

    EXPECT_FALSE(dir.empty());
    EXPECT_TRUE(std::filesystem::exists(dir));
    EXPECT_TRUE(std::filesystem::path(dir).is_absolute());
}

TEST(FilesystemTest, GetRuntimeDirectory_Consistent)
{
    auto dir1 = filesystem::get_runtime_directory();
    auto dir2 = filesystem::get_runtime_directory();

    EXPECT_EQ(dir1, dir2);
}

TEST(FilesystemTest, GetRuntimeDirectory_PathFormat)
{
    auto dir = filesystem::get_runtime_directory();

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
        threads.emplace_back([&results, i]() { results[i] = filesystem::get_runtime_directory(); });
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
    EXPECT_NO_THROW((void)filesystem::get_runtime_directory());
}

TEST(FilesystemTest, GetRuntimeDirectory_IsDirectory)
{
    auto dir = filesystem::get_runtime_directory();
    EXPECT_TRUE(std::filesystem::is_directory(dir));
}

TEST(FilesystemTest, GetRuntimeDirectory_NoTrailingSeparator)
{
    auto dir = filesystem::get_runtime_directory();
    ASSERT_FALSE(dir.empty());
    wchar_t last = dir.back();
    EXPECT_NE(last, L'/');
    EXPECT_NE(last, L'\\');
}

TEST(FilesystemTest, GetRuntimeDirectory_CachedResult)
{
    // Verify that repeated calls return identical values, consistent with the internal caching of the resolved module
    // directory.
    const auto dir1 = filesystem::get_runtime_directory();
    const auto dir2 = filesystem::get_runtime_directory();

    EXPECT_EQ(dir1, dir2);

    // Verify caching makes repeated calls effectively free by timing a burst.
    const int iterations = 10000;
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i)
    {
        auto dir = filesystem::get_runtime_directory();
        (void)dir;
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    // 10000 cached calls should complete well under 1 second. This bounds wall time only: each call still copies the
    // cached string (see FilesystemContractTest.OwningResultCopyCostIsDocumented for the ownership contract).
    EXPECT_LT(elapsed_ms, 1000) << "Cached resolution should keep repeat calls fast";
}

TEST(FilesystemUtf8, ReturnsNonEmpty)
{
    const std::string utf8 = filesystem::get_runtime_directory_utf8();
    EXPECT_FALSE(utf8.empty());
}

TEST(FilesystemUtf8, Cached)
{
    const std::string a = filesystem::get_runtime_directory_utf8();
    const std::string b = filesystem::get_runtime_directory_utf8();
    EXPECT_EQ(a, b);
}

// The ownership contract is pinned at compile time: by-value string returns cannot alias the cached path, so a caller
// may mutate its copy freely. Cross-call value equality is covered by FilesystemTest.GetRuntimeDirectory_Consistent and
// FilesystemUtf8.Cached; a runtime aliasing probe would be inert against these return types.
TEST(FilesystemContractTest, OwningResultCopyCostIsDocumented)
{
    static_assert(std::is_same_v<decltype(filesystem::get_runtime_directory()), std::wstring>,
                  "get_runtime_directory returns an owning std::wstring, not a reference or view");
    static_assert(std::is_same_v<decltype(filesystem::get_runtime_directory_utf8()), std::string>,
                  "get_runtime_directory_utf8 returns an owning std::string, not a reference or view");
}
