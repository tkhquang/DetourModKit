#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <thread>
#include <vector>

#include "DetourModKit/config.hpp"

using namespace DetourModKit;

class ConfigTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        test_ini_file_ = std::filesystem::temp_directory_path() / "test_config.ini";
        Config::clear_registered_items();
    }

    void TearDown() override
    {
        Config::clear_registered_items();
        if (std::filesystem::exists(test_ini_file_))
        {
            std::filesystem::remove(test_ini_file_);
        }
    }

    std::filesystem::path test_ini_file_;
};

TEST_F(ConfigTest, RegisterInt)
{
    int test_value = 0;

    Config::register_int("TestSection", "TestKey", "test_int", [&test_value](int v)
                                { test_value = v; }, 42);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(test_value, 42);
}

TEST_F(ConfigTest, RegisterFloat)
{
    float test_value = 0.0f;

    Config::register_float("TestSection", "TestKeyFloat", "test_float", [&test_value](float v)
                                  { test_value = v; }, 3.14f);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_NEAR(test_value, 3.14f, 0.01f);
}

TEST_F(ConfigTest, RegisterBool)
{
    bool test_value = false;

    Config::register_bool("TestSection", "TestKeyBool", "test_bool", [&test_value](bool v)
                                 { test_value = v; }, true);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_TRUE(test_value);
}

TEST_F(ConfigTest, RegisterString)
{
    std::string test_value;

    Config::register_string("TestSection", "TestKeyString", "test_string", [&test_value](const std::string &v)
                                   { test_value = v; }, "default_value");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(test_value, "default_value");
}

TEST_F(ConfigTest, LoadFromFile)
{
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

    Config::register_int("TestSection", "TestInt", "test_int", [&test_int](int v)
                                { test_int = v; }, 0);
    Config::register_float("TestSection", "TestFloat", "test_float", [&test_float](float v)
                                  { test_float = v; }, 0.0f);
    Config::register_bool("TestSection", "TestBool", "test_bool", [&test_bool](bool v)
                                 { test_bool = v; }, false);
    Config::register_string("TestSection", "TestString", "test_string", [&test_string](const std::string &v)
                                   { test_string = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_int, 100);
    EXPECT_NEAR(test_float, 2.5f, 0.01f);
    EXPECT_TRUE(test_bool);
    EXPECT_EQ(test_string, "loaded_value");
}

TEST_F(ConfigTest, LogAll)
{
    Config::register_int("TestSection", "TestKey", "test_int", [](int) {}, 42);

    EXPECT_NO_THROW(Config::log_all());
}

TEST_F(ConfigTest, RegisterKeyList_Default)
{
    std::vector<int> test_value;

    Config::register_key_list("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "0x41, 0x42, 0x43");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 3u);
    EXPECT_EQ(test_value[0], 0x41);
    EXPECT_EQ(test_value[1], 0x42);
    EXPECT_EQ(test_value[2], 0x43);
}

TEST_F(ConfigTest, RegisterKeyList_FromFile)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x10, 0x20, 0x30 ; comment\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::register_key_list("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "0x00");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 3u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
    EXPECT_EQ(test_value[2], 0x30);
}

TEST_F(ConfigTest, RegisterKeyList_HexFormats)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x01, 0X02, 03, 4\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::register_key_list("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 4u);
    EXPECT_EQ(test_value[0], 0x01);
    EXPECT_EQ(test_value[1], 0x02);
    EXPECT_EQ(test_value[2], 0x03);
    EXPECT_EQ(test_value[3], 0x04);
}

TEST_F(ConfigTest, RegisterKeyList_InvalidHex)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x10, INVALID, 0xGG, 0x20\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::register_key_list("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
}

TEST_F(ConfigTest, RegisterKeyList_Empty)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::register_key_list("TestSection", "TestKeys", "test_keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_TRUE(test_value.empty());
}

TEST_F(ConfigTest, ClearRegisteredItems)
{
    int test_value = 0;

    Config::register_int("TestSection", "TestKey", "test_int", [&test_value](int v)
                                { test_value = v; }, 42);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(test_value, 42);

    EXPECT_NO_THROW(Config::clear_registered_items());

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_NO_THROW(Config::log_all());
}

TEST_F(ConfigTest, ClearRegisteredItems_Empty)
{
    EXPECT_NO_THROW(Config::clear_registered_items());
}

TEST_F(ConfigTest, LogAll_Empty)
{
    EXPECT_NO_THROW(Config::log_all());
}

TEST_F(ConfigTest, LoadNonExistentFile)
{
    int test_value = 0;
    std::string non_existent_path = (std::filesystem::temp_directory_path() / "non_existent_dir" / "config.ini").string();

    Config::register_int("TestSection", "TestKey", "test_int", [&test_value](int v)
                                { test_value = v; }, 999);

    EXPECT_NO_THROW(Config::load(non_existent_path));
    EXPECT_EQ(test_value, 999);
}

TEST_F(ConfigTest, MultipleLoads)
{
    {
        std::ofstream ini_file(test_ini_file_);
        ini_file << "[TestSection]\n";
        ini_file << "TestInt=100\n";
        ini_file.close();
    }

    int test_value = 0;

    Config::register_int("TestSection", "TestInt", "test_int", [&test_value](int v)
                                { test_value = v; }, 0);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(test_value, 100);

    {
        std::ofstream ini_file(test_ini_file_);
        ini_file << "[TestSection]\n";
        ini_file << "TestInt=200\n";
        ini_file.close();
    }

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(test_value, 200);
}

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

    Config::register_int("Section1", "IntVal", "int_val", [&int_val](int v)
                                { int_val = v; }, 0);
    Config::register_float("Section1", "FloatVal", "float_val", [&float_val](float v)
                                  { float_val = v; }, 0.0f);
    Config::register_bool("Section2", "BoolVal", "bool_val", [&bool_val](bool v)
                                 { bool_val = v; }, false);
    Config::register_string("Section2", "StringVal", "string_val", [&string_val](const std::string &v)
                                   { string_val = v; }, "");
    Config::register_key_list("Section2", "Keys", "keys_val", [&keys_val](const std::vector<int> &v)
                                    { keys_val = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(int_val, 42);
    EXPECT_NEAR(float_val, 3.14f, 0.01f);
    EXPECT_TRUE(bool_val);
    EXPECT_EQ(string_val, "hello");
    EXPECT_EQ(keys_val.size(), 2u);
}

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

    Config::register_bool("TestSection", "Bool1", "bool1", [&bool1](bool v)
                                 { bool1 = v; }, false);
    Config::register_bool("TestSection", "Bool2", "bool2", [&bool2](bool v)
                                 { bool2 = v; }, true);
    Config::register_bool("TestSection", "Bool3", "bool3", [&bool3](bool v)
                                 { bool3 = v; }, false);
    Config::register_bool("TestSection", "Bool4", "bool4", [&bool4](bool v)
                                 { bool4 = v; }, true);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_TRUE(bool1);
    EXPECT_FALSE(bool2);
    EXPECT_TRUE(bool3);
    EXPECT_FALSE(bool4);
}

TEST_F(ConfigTest, FloatFormats)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Float1=3.14159\n";
    ini_file << "Float2=-2.5\n";
    ini_file << "Float3=0.0\n";
    ini_file.close();

    float float1 = 0.0f, float2 = 0.0f, float3 = 1.0f;

    Config::register_float("TestSection", "Float1", "float1", [&float1](float v)
                                  { float1 = v; }, 0.0f);
    Config::register_float("TestSection", "Float2", "float2", [&float2](float v)
                                  { float2 = v; }, 0.0f);
    Config::register_float("TestSection", "Float3", "float3", [&float3](float v)
                                  { float3 = v; }, 1.0f);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_NEAR(float1, 3.14159f, 0.0001f);
    EXPECT_NEAR(float2, -2.5f, 0.01f);
    EXPECT_NEAR(float3, 0.0f, 0.01f);
}

TEST_F(ConfigTest, KeyListWithCommentsAndSpaces)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=  0x10  ,  0x20  ; this is a comment\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::register_key_list("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
}

TEST_F(ConfigTest, KeyListEmptyDefault)
{
    std::vector<int> test_value = {0x99};

    Config::register_key_list("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_TRUE(test_value.empty());
}

TEST_F(ConfigTest, KeyListJustPrefix)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x, 0x10\n";
    ini_file.close();

    std::vector<int> test_value;

    Config::register_key_list("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0], 0x10);
}

TEST_F(ConfigTest, MultipleRegistrationsSameType)
{
    int val1 = 0, val2 = 0;

    Config::register_int("Section1", "Key1", "val1", [&val1](int v)
                                { val1 = v; }, 10);
    Config::register_int("Section1", "Key2", "val2", [&val2](int v)
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

TEST_F(ConfigTest, LogAll_AllTypes)
{
    float f_val = 0.0f;
    bool b_val = false;
    std::string s_val;
    std::vector<int> k_val;

    Config::register_float("Sec", "F", "f_val", [&f_val](float v)
                                  { f_val = v; }, 1.5f);
    Config::register_bool("Sec", "B", "b_val", [&b_val](bool v)
                                 { b_val = v; }, true);
    Config::register_string("Sec", "S", "s_val", [&s_val](const std::string &v)
                                   { s_val = v; }, "hello");
    Config::register_key_list("Sec", "K", "k_val", [&k_val](const std::vector<int> &v)
                                    { k_val = v; }, "0x41");

    Config::load(test_ini_file_.string());

    EXPECT_NO_THROW(Config::log_all());

    EXPECT_NEAR(f_val, 1.5f, 0.01f);
    EXPECT_TRUE(b_val);
    EXPECT_EQ(s_val, "hello");
    EXPECT_EQ(k_val.size(), 1u);
}

// Tests inline comment stripping in key list values
TEST_F(ConfigTest, KeyList_InlineTokenComment)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x10, 0x20 ; inline comment at end of line\n";
    ini_file.close();

    std::vector<int> test_value;
    Config::register_key_list("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
}

// Tests that consecutive commas produce empty tokens which are skipped
TEST_F(ConfigTest, KeyList_EmptyTokenFromConsecutiveCommas)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x10,,0x20\n";
    ini_file.close();

    std::vector<int> test_value;
    Config::register_key_list("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0], 0x10);
    EXPECT_EQ(test_value[1], 0x20);
}

// Tests that hex values exceeding stoul range are gracefully skipped
TEST_F(ConfigTest, KeyList_OverflowValue)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=FFFFFFFFFFFFFFFFFFFFFFFF, 0x41\n";
    ini_file.close();

    std::vector<int> test_value;
    Config::register_key_list("TestSection", "Keys", "keys", [&test_value](const std::vector<int> &v)
                                    { test_value = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0], 0x41);
}

// Tests that consecutive commas in default string are skipped
TEST_F(ConfigTest, RegisterKeyList_DefaultEmptyToken)
{
    std::vector<int> val;
    Config::register_key_list("S", "K1", "k1", [&val](const std::vector<int> &v)
                                    { val = v; }, "0x41,,0x42");
    Config::load(test_ini_file_.string());
    EXPECT_EQ(val.size(), 2u);
}

// Tests that bare "0x" prefix in default string is skipped
TEST_F(ConfigTest, RegisterKeyList_DefaultBarePrefix)
{
    std::vector<int> val;
    Config::register_key_list("S", "K2", "k2", [&val](const std::vector<int> &v)
                                    { val = v; }, "0x, 0x42");
    Config::load(test_ini_file_.string());
    EXPECT_EQ(val.size(), 1u);
    EXPECT_EQ(val[0], 0x42);
}

// Tests that overflow values in default string are gracefully skipped
TEST_F(ConfigTest, RegisterKeyList_DefaultOverflow)
{
    std::vector<int> val;
    Config::register_key_list("S", "K3", "k3", [&val](const std::vector<int> &v)
                                    { val = v; }, "FFFFFFFFFFFFFFFFFFFFFFFF, 0x43");
    Config::load(test_ini_file_.string());
    EXPECT_EQ(val.size(), 1u);
    EXPECT_EQ(val[0], 0x43);
}

TEST_F(ConfigTest, DuplicateKeyRegistration)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=77\n";
    ini_file.close();

    int first_val = 0;
    int second_val = 0;

    Config::register_int("TestSection", "TestInt", "first", [&first_val](int v)
                                { first_val = v; }, 10);
    Config::register_int("TestSection", "TestInt", "second", [&second_val](int v)
                                { second_val = v; }, 20);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    // The implementation appends each registration independently to the item
    // list. Both callbacks are invoked during load(), so both variables receive
    // the value read from the INI file.
    EXPECT_EQ(first_val, 77);
    EXPECT_EQ(second_val, 77);
}

TEST_F(ConfigTest, WhitespaceAroundValues)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt = 100 \n";
    ini_file << "TestString =  hello  \n";
    ini_file.close();

    int int_val = 0;
    std::string str_val;

    Config::register_int("TestSection", "TestInt", "int_val", [&int_val](int v)
                                { int_val = v; }, 0);
    Config::register_string("TestSection", "TestString", "str_val", [&str_val](const std::string &v)
                                   { str_val = v; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(int_val, 100);
    EXPECT_EQ(str_val, "hello");
}

TEST_F(ConfigTest, NegativeIntValue)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=-50\n";
    ini_file.close();

    int val = 0;

    Config::register_int("TestSection", "TestInt", "val", [&val](int v)
                                { val = v; }, 0);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(val, -50);
}

TEST_F(ConfigTest, MissingSectionInFile)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Other]\n";
    ini_file << "SomeKey=123\n";
    ini_file.close();

    int val = 999;

    Config::register_int("Missing", "TestInt", "val", [&val](int v)
                                { val = v; }, 999);

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(val, 999);
}

TEST_F(ConfigTest, ThreadSafety)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=42\n";
    ini_file.close();

    int val = 0;

    Config::register_int("TestSection", "TestInt", "val", [&val](int v)
                                { val = v; }, 0);

    constexpr int kThreadCount = 8;
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);

    for (int i = 0; i < kThreadCount; ++i)
    {
        threads.emplace_back([this]()
        {
            EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
        });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_EQ(val, 42);
}

TEST_F(ConfigTest, EmptyStringValue)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestString=\n";
    ini_file.close();

    std::string val = "non_empty";

    Config::register_string("TestSection", "TestString", "val", [&val](const std::string &v)
                                   { val = v; }, "non_empty");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_TRUE(val.empty());
}
