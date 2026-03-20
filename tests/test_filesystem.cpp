// Unit tests for Filesystem utilities module
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <thread>
#include <vector>

#include "DetourModKit/filesystem.hpp"

using namespace DetourModKit;

// Test fixture for Filesystem tests
class FilesystemTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        test_dir_ = std::filesystem::temp_directory_path() / "test_dmk_fs";
        std::filesystem::create_directory(test_dir_);
    }

    void TearDown() override
    {
        // Clean up test directory
        if (std::filesystem::exists(test_dir_))
        {
            std::filesystem::remove_all(test_dir_);
        }
    }

    std::filesystem::path test_dir_;
};

// Test get_runtime_directory returns a valid directory
TEST_F(FilesystemTest, GetRuntimeDirectory)
{
    auto dir = Filesystem::get_runtime_directory();

    // Should return a non-empty string
    EXPECT_FALSE(dir.empty());

    // On Windows, it should contain a drive letter
    // On success, the directory should exist (though it might be just ".")
}

// Test get_runtime_directory returns consistent results
TEST_F(FilesystemTest, GetRuntimeDirectory_Consistent)
{
    auto dir1 = Filesystem::get_runtime_directory();
    auto dir2 = Filesystem::get_runtime_directory();

    // Multiple calls should return the same result
    EXPECT_EQ(dir1, dir2);
}

// Test get_runtime_directory returns absolute or relative path
TEST_F(FilesystemTest, GetRuntimeDirectory_PathFormat)
{
    auto dir = Filesystem::get_runtime_directory();

    // Should not be empty
    EXPECT_FALSE(dir.empty());

    // Should be a valid path string
    EXPECT_NE(dir.find_first_of("\\/"), std::string::npos);
}

// Test get_runtime_directory with path operations
TEST_F(FilesystemTest, GetRuntimeDirectory_PathOperations)
{
    auto dir = Filesystem::get_runtime_directory();

    // Create a path object from the result
    std::filesystem::path fs_path(dir);

    // Should be able to create a path from it
    EXPECT_FALSE(fs_path.empty());
}

// Test get_runtime_directory returns usable path
TEST_F(FilesystemTest, GetRuntimeDirectory_UsablePath)
{
    auto dir = Filesystem::get_runtime_directory();

    // Should be able to append paths
    std::filesystem::path full_path = std::filesystem::path(dir) / "test_file.txt";

    // Should create a valid path object
    EXPECT_FALSE(full_path.empty());
}

// Test get_runtime_directory thread safety
TEST_F(FilesystemTest, GetRuntimeDirectory_ThreadSafety)
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

    // All threads should get the same result
    for (int i = 1; i < num_threads; ++i)
    {
        EXPECT_EQ(results[0], results[i]);
    }
}

// Test that get_runtime_directory doesn't throw
TEST_F(FilesystemTest, GetRuntimeDirectory_NoThrow)
{
    EXPECT_NO_THROW(Filesystem::get_runtime_directory());
}
