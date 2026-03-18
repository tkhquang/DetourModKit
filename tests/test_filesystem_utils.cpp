// Unit tests for Filesystem utilities module
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "DetourModKit/filesystem_utils.hpp"

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
