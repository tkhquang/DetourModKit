// Unit tests for Config module
#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>

#include "DetourModKit/config.hpp"

using namespace DetourModKit;

// Test fixture for Config tests
class ConfigTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        test_ini_file_ = std::filesystem::temp_directory_path() / "test_config.ini";
    }

    void TearDown() override
    {
        if (std::filesystem::exists(test_ini_file_))
        {
            std::filesystem::remove(test_ini_file_);
        }
    }

    std::filesystem::path test_ini_file_;
};

// Test config item registration with callback
TEST_F(ConfigTest, RegisterIntCallback)
{
    int test_value = 0;

    Config::registerIntCallback("TestSection", "TestKey", "test_int", [&test_value](int v)
                                { test_value = v; }, 42);

    // Load the config
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Check the value was loaded (should be default since file doesn't exist)
    EXPECT_EQ(test_value, 42);
}

// Test config item registration with float callback
TEST_F(ConfigTest, RegisterFloatCallback)
{
    float test_value = 0.0f;

    Config::registerFloatCallback("TestSection", "TestKeyFloat", "test_float", [&test_value](float v)
                                  { test_value = v; }, 3.14f);

    // Load the config
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Check the value was loaded (approximate comparison)
    EXPECT_NEAR(test_value, 3.14f, 0.01f);
}

// Test config item registration with bool callback
TEST_F(ConfigTest, RegisterBoolCallback)
{
    bool test_value = false;

    Config::registerBoolCallback("TestSection", "TestKeyBool", "test_bool", [&test_value](bool v)
                                 { test_value = v; }, true);

    // Load the config
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Check the value was loaded
    EXPECT_TRUE(test_value);
}

// Test config item registration with string callback
TEST_F(ConfigTest, RegisterStringCallback)
{
    std::string test_value;

    Config::registerStringCallback("TestSection", "TestKeyString", "test_string", [&test_value](const std::string &v)
                                   { test_value = v; }, "default_value");

    // Load the config
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Check the value was loaded
    EXPECT_EQ(test_value, "default_value");
}

// Test loading config from file with values
TEST_F(ConfigTest, LoadFromFile)
{
    // Create a config file with values
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=100\n";
    ini_file << "TestFloat=2.5\n";
    ini_file << "TestBool=true\n";
    ini_file << "TestString=loaded_value\n";
    ini_file.close();

    int test_int = 0;
    float test_float = 0.0f;
    bool test_bool = false;
    std::string test_string;

    Config::registerIntCallback("TestSection", "TestInt", "test_int", [&test_int](int v)
                                { test_int = v; }, 0);
    Config::registerFloatCallback("TestSection", "TestFloat", "test_float", [&test_float](float v)
                                  { test_float = v; }, 0.0f);
    Config::registerBoolCallback("TestSection", "TestBool", "test_bool", [&test_bool](bool v)
                                 { test_bool = v; }, false);
    Config::registerStringCallback("TestSection", "TestString", "test_string", [&test_string](const std::string &v)
                                   { test_string = v; }, "");

    // Load the config
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Check the values were loaded
    EXPECT_EQ(test_int, 100);
    EXPECT_NEAR(test_float, 2.5f, 0.01f);
    EXPECT_TRUE(test_bool);
    EXPECT_EQ(test_string, "loaded_value");
}

// Test logAll doesn't throw
TEST_F(ConfigTest, LogAll)
{
    Config::registerIntCallback("TestSection", "TestKey", "test_int", [](int) {}, 42);

    EXPECT_NO_THROW(Config::logAll());
}
