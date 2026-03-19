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
        // Clear any previously registered items
        Config::clearRegisteredItems();
    }

    void TearDown() override
    {
        Config::clearRegisteredItems();
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

// Test registerKeyListCallback with default values
TEST_F(ConfigTest, RegisterKeyListCallback_Default)
{
    std::vector<int> test_value;

    Config::registerKeyListCallback("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "0x41, 0x42, 0x43");

    // Load the config
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Check default values were loaded
    EXPECT_EQ(test_value.size(), 3u);
    EXPECT_EQ(test_value[0], 0x41);
    EXPECT_EQ(test_value[1], 0x42);
    EXPECT_EQ(test_value[2], 0x43);
}

// Test registerKeyListCallback loading from file
TEST_F(ConfigTest, RegisterKeyListCallback_FromFile)
{
    // Create a config file with key list
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x10, 0x20, 0x30 ; comment\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::registerKeyListCallback("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "0x00");

    // Load the config
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Check values were loaded
    EXPECT_EQ(test_value.size(), 3u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
    EXPECT_EQ(test_value[2], 0x30);
}

// Test registerKeyListCallback with hex format 0x prefix
TEST_F(ConfigTest, RegisterKeyListCallback_HexFormats)
{
    // Create a config file with various hex formats
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x01, 0X02, 03, 4\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::registerKeyListCallback("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Should parse all hex values
    EXPECT_EQ(test_value.size(), 4u);
    EXPECT_EQ(test_value[0], 0x01);
    EXPECT_EQ(test_value[1], 0x02);
    EXPECT_EQ(test_value[2], 0x03);
    EXPECT_EQ(test_value[3], 0x04);
}

// Test registerKeyListCallback with invalid hex values (should skip them)
TEST_F(ConfigTest, RegisterKeyListCallback_InvalidHex)
{
    // Create a config file with some invalid hex values
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x10, INVALID, 0xGG, 0x20\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::registerKeyListCallback("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Should only have valid hex values
    EXPECT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
}

// Test registerKeyListCallback with empty string
TEST_F(ConfigTest, RegisterKeyListCallback_Empty)
{
    // Create a config file with empty key list
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::registerKeyListCallback("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Both default and INI are empty, so result should be empty
    EXPECT_TRUE(test_value.empty());
}

// Test clearRegisteredItems
TEST_F(ConfigTest, ClearRegisteredItems)
{
    int test_value = 0;

    Config::registerIntCallback("TestSection", "TestKey", "test_int", [&test_value](int v)
                                { test_value = v; }, 42);

    // Load the config
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(test_value, 42);

    // Clear all registered items
    EXPECT_NO_THROW(Config::clearRegisteredItems());

    // Load again - should have no items to process
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // logAll with no items should not throw
    EXPECT_NO_THROW(Config::logAll());
}

// Test clearRegisteredItems with no items
TEST_F(ConfigTest, ClearRegisteredItems_Empty)
{
    // Should not throw when no items are registered
    EXPECT_NO_THROW(Config::clearRegisteredItems());
}

// Test logAll with no items
TEST_F(ConfigTest, LogAll_Empty)
{
    // Should not throw when no items are registered
    EXPECT_NO_THROW(Config::logAll());
}

// Test loading from non-existent file (uses defaults)
TEST_F(ConfigTest, LoadNonExistentFile)
{
    int test_value = 0;
    std::string non_existent_path = (std::filesystem::temp_directory_path() / "non_existent_dir" / "config.ini").string();

    Config::registerIntCallback("TestSection", "TestKey", "test_int", [&test_value](int v)
                                { test_value = v; }, 999);

    // Load should not throw even if file doesn't exist
    EXPECT_NO_THROW(Config::load(non_existent_path));

    // Should have default value
    EXPECT_EQ(test_value, 999);
}

// Test multiple loads (should reload values)
TEST_F(ConfigTest, MultipleLoads)
{
    // Create initial config file
    {
        std::ofstream ini_file(test_ini_file_);
        ini_file << "[TestSection]\n";
        ini_file << "TestInt=100\n";
        ini_file.close();
    }

    int test_value = 0;

    Config::registerIntCallback("TestSection", "TestInt", "test_int", [&test_value](int v)
                                { test_value = v; }, 0);

    // First load
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(test_value, 100);

    // Modify config file
    {
        std::ofstream ini_file(test_ini_file_);
        ini_file << "[TestSection]\n";
        ini_file << "TestInt=200\n";
        ini_file.close();
    }

    // Second load should update the value
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(test_value, 200);
}

// Test multiple different config types together
TEST_F(ConfigTest, MixedConfigTypes)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Section1]\n";
    ini_file << "IntVal=42\n";
    ini_file << "FloatVal=3.14\n";
    ini_file << "[Section2]\n";
    ini_file << "BoolVal=true\n";
    ini_file << "StringVal=hello\n";
    ini_file << "Keys=0x01, 0x02\n";
    ini_file.close();

    int int_val = 0;
    float float_val = 0.0f;
    bool bool_val = false;
    std::string string_val;
    std::vector<int> keys_val;

    Config::registerIntCallback("Section1", "IntVal", "int_val", [&int_val](int v)
                                { int_val = v; }, 0);
    Config::registerFloatCallback("Section1", "FloatVal", "float_val", [&float_val](float v)
                                  { float_val = v; }, 0.0f);
    Config::registerBoolCallback("Section2", "BoolVal", "bool_val", [&bool_val](bool v)
                                 { bool_val = v; }, false);
    Config::registerStringCallback("Section2", "StringVal", "string_val", [&string_val](const std::string &v)
                                   { string_val = v; }, "");
    Config::registerKeyListCallback("Section2", "Keys", "keys_val", [&keys_val](const std::vector<int> &v)
                                    { keys_val = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(int_val, 42);
    EXPECT_NEAR(float_val, 3.14f, 0.01f);
    EXPECT_TRUE(bool_val);
    EXPECT_EQ(string_val, "hello");
    EXPECT_EQ(keys_val.size(), 2u);
}

// Test bool parsing variations
TEST_F(ConfigTest, BoolVariations)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Bool1=true\n";
    ini_file << "Bool2=false\n";
    ini_file << "Bool3=1\n";
    ini_file << "Bool4=0\n";
    ini_file.close();

    bool bool1 = false, bool2 = true, bool3 = false, bool4 = true;

    Config::registerBoolCallback("TestSection", "Bool1", "bool1", [&bool1](bool v)
                                 { bool1 = v; }, false);
    Config::registerBoolCallback("TestSection", "Bool2", "bool2", [&bool2](bool v)
                                 { bool2 = v; }, true);
    Config::registerBoolCallback("TestSection", "Bool3", "bool3", [&bool3](bool v)
                                 { bool3 = v; }, false);
    Config::registerBoolCallback("TestSection", "Bool4", "bool4", [&bool4](bool v)
                                 { bool4 = v; }, true);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_TRUE(bool1);
    EXPECT_FALSE(bool2);
    // Note: SimpleIni may handle 1/0 differently than true/false
}

// Test float with various formats
TEST_F(ConfigTest, FloatFormats)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Float1=3.14159\n";
    ini_file << "Float2=-2.5\n";
    ini_file << "Float3=0.0\n";
    ini_file.close();

    float float1 = 0.0f, float2 = 0.0f, float3 = 1.0f;

    Config::registerFloatCallback("TestSection", "Float1", "float1", [&float1](float v)
                                  { float1 = v; }, 0.0f);
    Config::registerFloatCallback("TestSection", "Float2", "float2", [&float2](float v)
                                  { float2 = v; }, 0.0f);
    Config::registerFloatCallback("TestSection", "Float3", "float3", [&float3](float v)
                                  { float3 = v; }, 1.0f);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_NEAR(float1, 3.14159f, 0.0001f);
    EXPECT_NEAR(float2, -2.5f, 0.01f);
    EXPECT_NEAR(float3, 0.0f, 0.01f);
}

// Test key list with spaces and comments
TEST_F(ConfigTest, KeyListWithCommentsAndSpaces)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=  0x10  ,  0x20  ; this is a comment\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::registerKeyListCallback("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
}

// Test empty default for key list
TEST_F(ConfigTest, KeyListEmptyDefault)
{
    std::vector<int> test_value = {0x99}; // Non-empty to verify it gets cleared

    Config::registerKeyListCallback("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Should have empty vector since default is empty and no INI value
    EXPECT_TRUE(test_value.empty());
}

// Test key list with just 0x prefix (should be skipped)
TEST_F(ConfigTest, KeyListJustPrefix)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x, 0x10\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::registerKeyListCallback("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Should only have the valid 0x10
    EXPECT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0], 0x10);
}

// Test multiple registrations of same callback type
TEST_F(ConfigTest, MultipleCallbacksSameType)
{
    int val1 = 0, val2 = 0;

    Config::registerIntCallback("Section1", "Key1", "val1", [&val1](int v)
                                { val1 = v; }, 10);
    Config::registerIntCallback("Section1", "Key2", "val2", [&val2](int v)
                                { val2 = v; }, 20);

    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Section1]\n";
    ini_file << "Key1=100\n";
    ini_file << "Key2=200\n";
    ini_file.close();

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(val1, 100);
    EXPECT_EQ(val2, 200);
}

// Covers log_current_value for float, bool, string, and vector<int>
TEST_F(ConfigTest, LogAll_AllTypes)
{
    float f_val = 0.0f;
    bool b_val = false;
    std::string s_val;
    std::vector<int> k_val;

    Config::registerFloatCallback("Sec", "F", "f_val", [&f_val](float v)
                                  { f_val = v; }, 1.5f);
    Config::registerBoolCallback("Sec", "B", "b_val", [&b_val](bool v)
                                 { b_val = v; }, true);
    Config::registerStringCallback("Sec", "S", "s_val", [&s_val](const std::string &v)
                                   { s_val = v; }, "hello");
    Config::registerKeyListCallback("Sec", "K", "k_val", [&k_val](const std::vector<int> &v)
                                    { k_val = v; }, "0x41");

    Config::load(test_ini_file_.string());

    // logAll calls log_current_value for each type
    EXPECT_NO_THROW(Config::logAll());

    EXPECT_NEAR(f_val, 1.5f, 0.01f);
    EXPECT_TRUE(b_val);
    EXPECT_EQ(s_val, "hello");
    EXPECT_EQ(k_val.size(), 1u);
}

// Covers inline token comment in keylist load (L191 in config.cpp)
TEST_F(ConfigTest, KeyList_InlineTokenComment)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x10, 0x20 ; inline comment at end of line\n";
    ini_file.close();

    std::vector<int> test_value;
    Config::registerKeyListCallback("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // "0x10, 0x20 ; inline comment" → after strip: "0x10, 0x20 " → 2 valid values
    EXPECT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
}

// Covers empty token (consecutive commas) in keylist load (L196 in config.cpp)
TEST_F(ConfigTest, KeyList_EmptyTokenFromConsecutiveCommas)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x10,,0x20\n";
    ini_file.close();

    std::vector<int> test_value;
    Config::registerKeyListCallback("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Middle empty token is skipped
    EXPECT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
}

// Covers stoul overflow exception in keylist load (L219/222 catch block in config.cpp)
TEST_F(ConfigTest, KeyList_OverflowValue)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    // Value that passes hex char check but overflows stoul
    ini_file << "Keys=FFFFFFFFFFFFFFFFFFFFFFFF, 0x41\n";
    ini_file.close();

    std::vector<int> test_value;
    Config::registerKeyListCallback("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // Overflow value is skipped, valid 0x41 is kept
    EXPECT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0], 0x41);
}

// Covers registerKeyListCallback default value edge cases (L335, L347, L354, L365/368 in config.cpp)
TEST_F(ConfigTest, RegisterKeyList_DefaultEdgeCases)
{
    // Empty token in default string (consecutive commas) → covers L347 continue
    std::vector<int> val1;
    Config::registerKeyListCallback("S", "K1", "k1", [&val1](const std::vector<int> &v)
                                    { val1 = v; }, "0x41,,0x42");
    Config::load(test_ini_file_.string());
    EXPECT_EQ(val1.size(), 2u);

    Config::clearRegisteredItems();

    // Bare "0x" in default → covers L354 empty hex_part continue
    std::vector<int> val2;
    Config::registerKeyListCallback("S", "K2", "k2", [&val2](const std::vector<int> &v)
                                    { val2 = v; }, "0x, 0x42");
    Config::load(test_ini_file_.string());
    EXPECT_EQ(val2.size(), 1u);
    EXPECT_EQ(val2[0], 0x42);

    Config::clearRegisteredItems();

    // Overflow in default → covers L365/368 catch block
    std::vector<int> val3;
    Config::registerKeyListCallback("S", "K3", "k3", [&val3](const std::vector<int> &v)
                                    { val3 = v; }, "FFFFFFFFFFFFFFFFFFFFFFFF, 0x43");
    Config::load(test_ini_file_.string());
    EXPECT_EQ(val3.size(), 1u);
    EXPECT_EQ(val3[0], 0x43);
}
