// Unit tests for Filesystem utilities module
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <thread>
#include <vector>

#include "DetourModKit/filesystem.hpp"

using namespace DetourModKit;

// Test fixture for Filesystem tests
class FilesystemUtilsTest : public ::testing::Test
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

// Test getRuntimeDirectory returns a valid directory
TEST_F(FilesystemUtilsTest, GetRuntimeDirectory)
{
    auto dir = Filesystem::getRuntimeDirectory();

    // Should return a non-empty string
    EXPECT_FALSE(dir.empty());

    // On Windows, it should contain a drive letter
    // On success, the directory should exist (though it might be just ".")
}

// Test getRuntimeDirectory returns consistent results
TEST_F(FilesystemUtilsTest, GetRuntimeDirectory_Consistent)
{
    auto dir1 = Filesystem::getRuntimeDirectory();
    auto dir2 = Filesystem::getRuntimeDirectory();

    // Multiple calls should return the same result
    EXPECT_EQ(dir1, dir2);
}

// Test getRuntimeDirectory returns absolute or relative path
TEST_F(FilesystemUtilsTest, GetRuntimeDirectory_PathFormat)
{
    auto dir = Filesystem::getRuntimeDirectory();

    // Should not be empty
    EXPECT_FALSE(dir.empty());

    // Should be a valid path string
    EXPECT_NE(dir.find_first_of("\\/"), std::string::npos);
}

// Test getRuntimeDirectory with path operations
TEST_F(FilesystemUtilsTest, GetRuntimeDirectory_PathOperations)
{
    auto dir = Filesystem::getRuntimeDirectory();

    // Create a path object from the result
    std::filesystem::path fs_path(dir);

    // Should be able to create a path from it
    EXPECT_FALSE(fs_path.empty());
}

// Test getRuntimeDirectory returns usable path
TEST_F(FilesystemUtilsTest, GetRuntimeDirectory_UsablePath)
{
    auto dir = Filesystem::getRuntimeDirectory();

    // Should be able to append paths
    std::filesystem::path full_path = std::filesystem::path(dir) / "test_file.txt";

    // Should create a valid path object
    EXPECT_FALSE(full_path.empty());
}

// Test getRuntimeDirectory thread safety
TEST_F(FilesystemUtilsTest, GetRuntimeDirectory_ThreadSafety)
{
    const int num_threads = 4;
    std::vector<std::string> results(num_threads);
    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&results, i]()
                             { results[i] = Filesystem::getRuntimeDirectory(); });
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

// Test that getRuntimeDirectory doesn't throw
TEST_F(FilesystemUtilsTest, GetRuntimeDirectory_NoThrow)
{
    EXPECT_NO_THROW(Filesystem::getRuntimeDirectory());
}
