#include <gtest/gtest.h>
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
    std::vector<std::string> results(num_threads);
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
