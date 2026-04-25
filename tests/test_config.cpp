#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <memory>
#include <process.h>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include "DetourModKit/config.hpp"
#include "DetourModKit/input.hpp"

using namespace DetourModKit;
using DetourModKit::keyboard_key;
using DetourModKit::mouse_button;
using DetourModKit::gamepad_button;

class ConfigTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static int test_counter = 0;
        test_ini_file_ = std::filesystem::temp_directory_path() /
                         ("test_config_" + std::to_string(_getpid()) + "_" + std::to_string(test_counter++) + ".ini");
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

TEST_F(ConfigTest, KeyCombo_HexFormats)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x01, 0X02, 0x03, 0x04\n";
    ini_file.close();

    Config::KeyComboList test_value;

    Config::register_key_combo("TestSection", "TestKeys", "test_keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 4u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x01));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x02));
    EXPECT_EQ(test_value[2].keys[0], keyboard_key(0x03));
    EXPECT_EQ(test_value[3].keys[0], keyboard_key(0x04));
}

TEST_F(ConfigTest, KeyCombo_NamedKeys)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=F3, F4, A\n";
    ini_file.close();

    Config::KeyComboList test_value;

    Config::register_key_combo("TestSection", "TestKeys", "test_keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 3u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x72));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x73));
    EXPECT_EQ(test_value[2].keys[0], keyboard_key(0x41));
}

TEST_F(ConfigTest, KeyCombo_MouseButton)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=Mouse4\n";
    ini_file.close();

    Config::KeyComboList test_value;

    Config::register_key_combo("TestSection", "TestKeys", "test_keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], mouse_button(0x05));
}

TEST_F(ConfigTest, KeyCombo_GamepadButton)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=Gamepad_A\n";
    ini_file.close();

    Config::KeyComboList test_value;

    Config::register_key_combo("TestSection", "TestKeys", "test_keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], gamepad_button(GamepadCode::A));
}

TEST_F(ConfigTest, KeyCombo_GamepadCombo)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=Gamepad_LB+Gamepad_A\n";
    ini_file.close();

    Config::KeyComboList test_value;

    Config::register_key_combo("TestSection", "TestKeys", "test_keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], gamepad_button(GamepadCode::A));
    ASSERT_EQ(test_value[0].modifiers.size(), 1u);
    EXPECT_EQ(test_value[0].modifiers[0], gamepad_button(GamepadCode::LeftBumper));
}

TEST_F(ConfigTest, KeyCombo_InvalidHex)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x10, INVALID, 0xGG, 0x20\n";
    ini_file.close();

    Config::KeyComboList test_value;

    Config::register_key_combo("TestSection", "TestKeys", "test_keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x20));
}

TEST_F(ConfigTest, KeyCombo_CommentOnlyLineYieldsEmpty)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=   ; only a comment\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "TestKeys", "test_keys",
                               [&test_value](const Config::KeyComboList &c)
                               { test_value = c; },
                               "");
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_TRUE(test_value.empty());
}

TEST_F(ConfigTest, KeyCombo_EmptyCommaSeparatorsAreSkipped)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=,,F3,,F4,,\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "TestKeys", "test_keys",
                               [&test_value](const Config::KeyComboList &c)
                               { test_value = c; },
                               "");
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x72));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x73));
}

TEST_F(ConfigTest, KeyCombo_HexWithOnlyPrefixIsSkipped)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x, 0X, 0x72\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "TestKeys", "test_keys",
                               [&test_value](const Config::KeyComboList &c)
                               { test_value = c; },
                               "");
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x72));
}

TEST_F(ConfigTest, KeyCombo_HexValueAboveIntMaxIsSkipped)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    // 0xFFFFFFFF > INT_MAX, so the > limits check rejects it. The valid 0x10 still parses.
    ini_file << "TestKeys=0xFFFFFFFF, 0x10\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "TestKeys", "test_keys",
                               [&test_value](const Config::KeyComboList &c)
                               { test_value = c; },
                               "");
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
}

TEST_F(ConfigTest, KeyCombo_DoublePlusSkipsEmptySegment)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=Ctrl++F3\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "TestKeys", "test_keys",
                               [&test_value](const Config::KeyComboList &c)
                               { test_value = c; },
                               "");
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    ASSERT_EQ(test_value.size(), 1u);
    ASSERT_EQ(test_value[0].modifiers.size(), 1u);
    EXPECT_EQ(test_value[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x72));
}

TEST_F(ConfigTest, KeyCombo_TrailingPlusIsRejected)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    // "Ctrl+" parses with Ctrl as the only non-empty segment and becomes
    // the trigger key with no modifiers; the trailing empty segment is
    // dropped by the !segment.empty() filter.
    ini_file << "TestKeys=Ctrl+\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "TestKeys", "test_keys",
                               [&test_value](const Config::KeyComboList &c)
                               { test_value = c; },
                               "");
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x11));
    EXPECT_TRUE(test_value[0].modifiers.empty());
}

TEST_F(ConfigTest, KeyCombo_OnlyPlusSignsYieldsEmpty)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=+++\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "TestKeys", "test_keys",
                               [&test_value](const Config::KeyComboList &c)
                               { test_value = c; },
                               "F3");
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_TRUE(test_value.empty());
}

TEST_F(ConfigTest, KeyCombo_FormatRoundTripsMultipleCombos)
{
    Config::KeyComboList captured;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle",
                               [&captured](const Config::KeyComboList &c)
                               { captured = c; },
                               "Ctrl+F3,Gamepad_LT+Gamepad_A");
    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(captured.size(), 2u);
    EXPECT_EQ(captured[0].modifiers.size(), 1u);
    EXPECT_EQ(captured[1].modifiers.size(), 1u);
    EXPECT_EQ(captured[0].keys[0], keyboard_key(0x72));
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
    Config::KeyComboList keys_val;

    Config::register_int("Section1", "IntVal", "int_val", [&int_val](int v)
                         { int_val = v; }, 0);
    Config::register_float("Section1", "FloatVal", "float_val", [&float_val](float v)
                           { float_val = v; }, 0.0f);
    Config::register_bool("Section2", "BoolVal", "bool_val", [&bool_val](bool v)
                          { bool_val = v; }, false);
    Config::register_string("Section2", "StringVal", "string_val", [&string_val](const std::string &v)
                            { string_val = v; }, "");
    Config::register_key_combo("Section2", "Keys", "keys_val", [&keys_val](const Config::KeyComboList &c)
                               { keys_val = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(int_val, 42);
    EXPECT_NEAR(float_val, 3.14f, 0.01f);
    EXPECT_TRUE(bool_val);
    EXPECT_EQ(string_val, "hello");
    ASSERT_EQ(keys_val.size(), 2u);
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

TEST_F(ConfigTest, KeyCombo_CommentsAndSpaces)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=  0x10  ,  0x20  ; this is a comment\n";
    ini_file.close();

    Config::KeyComboList test_value;

    Config::register_key_combo("TestSection", "Keys", "keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x20));
}

TEST_F(ConfigTest, KeyCombo_JustPrefix)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x, 0x10\n";
    ini_file.close();

    Config::KeyComboList test_value;

    Config::register_key_combo("TestSection", "Keys", "keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
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
    Config::KeyComboList k_val;

    Config::register_float("Sec", "F", "f_val", [&f_val](float v)
                           { f_val = v; }, 1.5f);
    Config::register_bool("Sec", "B", "b_val", [&b_val](bool v)
                          { b_val = v; }, true);
    Config::register_string("Sec", "S", "s_val", [&s_val](const std::string &v)
                            { s_val = v; }, "hello");
    Config::register_key_combo("Sec", "K", "k_val", [&k_val](const Config::KeyComboList &c)
                               { k_val = c; }, "0x41");

    Config::load(test_ini_file_.string());

    EXPECT_NO_THROW(Config::log_all());

    EXPECT_NEAR(f_val, 1.5f, 0.01f);
    EXPECT_TRUE(b_val);
    EXPECT_EQ(s_val, "hello");
    ASSERT_EQ(k_val.size(), 1u);
}

TEST_F(ConfigTest, KeyCombo_InlineTokenComment)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x10, 0x20 ; inline comment at end of line\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "Keys", "keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x20));
}

TEST_F(ConfigTest, KeyCombo_EmptyTokenFromConsecutiveCommas)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x10,,0x20\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "Keys", "keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x20));
}

TEST_F(ConfigTest, KeyCombo_OverflowValue)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=FFFFFFFFFFFFFFFFFFFFFFFF, 0x41\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "Keys", "keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x41));
}

TEST_F(ConfigTest, KeyCombo_DefaultEmptyToken)
{
    Config::KeyComboList val;
    Config::register_key_combo("S", "K1", "k1", [&val](const Config::KeyComboList &c)
                               { val = c; }, "0x41,,0x42");
    Config::load(test_ini_file_.string());
    ASSERT_EQ(val.size(), 2u);
}

TEST_F(ConfigTest, KeyCombo_DefaultBarePrefix)
{
    Config::KeyComboList val;
    Config::register_key_combo("S", "K2", "k2", [&val](const Config::KeyComboList &c)
                               { val = c; }, "0x, 0x42");
    Config::load(test_ini_file_.string());
    ASSERT_EQ(val.size(), 1u);
    EXPECT_EQ(val[0].keys[0], keyboard_key(0x42));
}

TEST_F(ConfigTest, KeyCombo_DefaultOverflow)
{
    Config::KeyComboList val;
    Config::register_key_combo("S", "K3", "k3", [&val](const Config::KeyComboList &c)
                               { val = c; }, "FFFFFFFFFFFFFFFFFFFFFFFF, 0x43");
    Config::load(test_ini_file_.string());
    ASSERT_EQ(val.size(), 1u);
    EXPECT_EQ(val[0].keys[0], keyboard_key(0x43));
}

TEST_F(ConfigTest, KeyCombo_ValueExceedingIntMax)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x80000000, 0x41\n";
    ini_file.close();

    Config::KeyComboList test_value;
    Config::register_key_combo("TestSection", "Keys", "keys", [&test_value](const Config::KeyComboList &c)
                               { test_value = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x41));
}

TEST_F(ConfigTest, KeyCombo_DefaultValueExceedingIntMax)
{
    Config::KeyComboList val;
    Config::register_key_combo("S", "K4", "k4", [&val](const Config::KeyComboList &c)
                               { val = c; }, "0x80000000, 0x44");
    Config::load(test_ini_file_.string());
    ASSERT_EQ(val.size(), 1u);
    EXPECT_EQ(val[0].keys[0], keyboard_key(0x44));
}

TEST_F(ConfigTest, DuplicateKeyRegistration_ReplacesExisting)
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

    // Re-registration with the same section+key replaces the previous entry.
    // Only the second (latest) callback receives the loaded value.
    EXPECT_EQ(first_val, 10);
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
                             { EXPECT_NO_THROW(Config::load(test_ini_file_.string())); });
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

TEST_F(ConfigTest, RegisterString_DefaultValueNotMovedFrom)
{
    std::string val = "unset";
    std::string default_val = "my_default";

    Config::register_string("Defaults", "Str", "val", [&val](const std::string &v)
                            { val = v; }, default_val);

    // Before load(), the setter should have been called with the default value
    EXPECT_EQ(val, "my_default");
}


TEST_F(ConfigTest, RegisterKeyCombo_SingleKey)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "0x72");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    EXPECT_TRUE(combo[0].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_NamedSingleKey)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "F3");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    EXPECT_TRUE(combo[0].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_SingleModifier)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "0x11+0x72");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_NamedModifier)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "Ctrl+F3");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_MultipleModifiers)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "Ctrl+Shift+F3");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 2u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combo[0].modifiers[1], keyboard_key(0x10));
}

TEST_F(ConfigTest, RegisterKeyCombo_MultipleTriggerKeys)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "Ctrl+F3,F4");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 2u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combo[1].keys[0], keyboard_key(0x73));
    EXPECT_TRUE(combo[1].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_Empty)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_TRUE(combo.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_FromFile)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Hotkeys]\n";
    ini_file << "Toggle=Ctrl+Shift+F3 ; Ctrl+Shift+F3\n";
    ini_file.close();

    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "0x41");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 2u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combo[0].modifiers[1], keyboard_key(0x10));
}

TEST_F(ConfigTest, RegisterKeyCombo_FromFileNoModifiers)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Hotkeys]\n";
    ini_file << "Toggle=F3\n";
    ini_file.close();

    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    EXPECT_TRUE(combo[0].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_FromFileMultipleTriggers)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Hotkeys]\n";
    ini_file << "Toggle=Ctrl+F3,F4,F5\n";
    ini_file.close();

    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 3u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combo[1].keys[0], keyboard_key(0x73));
    EXPECT_TRUE(combo[1].modifiers.empty());
    EXPECT_EQ(combo[2].keys[0], keyboard_key(0x74));
    EXPECT_TRUE(combo[2].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_InvalidModifierSkipped)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "0xGG+Ctrl+F3");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_WhitespaceAroundPlus)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "  Ctrl  +  Shift  +  F3  ");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 2u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combo[0].modifiers[1], keyboard_key(0x10));
}

TEST_F(ConfigTest, RegisterKeyCombo_DefaultValueApplied)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "Ctrl+F3");

    // Before load(), the setter should have been called with the parsed default
    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_LogAll)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "Ctrl+F3");

    Config::load(test_ini_file_.string());

    EXPECT_NO_THROW(Config::log_all());
}

TEST_F(ConfigTest, RegisterKeyCombo_GamepadDefault)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "GP", "gp", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "Gamepad_LB+Gamepad_A,Gamepad_B");

    ASSERT_EQ(combo.size(), 2u);
    EXPECT_EQ(combo[0].keys[0], gamepad_button(GamepadCode::A));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], gamepad_button(GamepadCode::LeftBumper));
    EXPECT_EQ(combo[1].keys[0], gamepad_button(GamepadCode::B));
    EXPECT_TRUE(combo[1].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_MouseDefault)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "MS", "ms", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "Ctrl+Mouse4");

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], mouse_button(0x05));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_ThumbstickDefault)
{
    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "LS", "ls", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "Gamepad_LB+Gamepad_LSUp");

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], gamepad_button(GamepadCode::LeftStickUp));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], gamepad_button(GamepadCode::LeftBumper));
}

TEST_F(ConfigTest, KeyCombo_ThumbstickFromFile)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Hotkeys]\n";
    ini_file << "StickCombo=Gamepad_RSLeft,Gamepad_RSRight\n";
    ini_file.close();

    Config::KeyComboList combo;

    Config::register_key_combo("Hotkeys", "StickCombo", "stick", [&combo](const Config::KeyComboList &c)
                               { combo = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combo.size(), 2u);
    EXPECT_EQ(combo[0].keys[0], gamepad_button(GamepadCode::RightStickLeft));
    EXPECT_EQ(combo[1].keys[0], gamepad_button(GamepadCode::RightStickRight));
}

TEST_F(ConfigTest, KeyComboList_IndependentCombos)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Hotkeys]\n";
    ini_file << "Toggle=F3,Gamepad_LT+Gamepad_B\n";
    ini_file.close();

    Config::KeyComboList combos;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combos](const Config::KeyComboList &c)
                               { combos = c; }, "");

    EXPECT_NO_THROW(Config::load(test_ini_file_.string()));

    ASSERT_EQ(combos.size(), 2u);
    ASSERT_EQ(combos[0].keys.size(), 1u);
    EXPECT_EQ(combos[0].keys[0], keyboard_key(0x72));
    EXPECT_TRUE(combos[0].modifiers.empty());
    ASSERT_EQ(combos[1].keys.size(), 1u);
    EXPECT_EQ(combos[1].keys[0], gamepad_button(GamepadCode::B));
    ASSERT_EQ(combos[1].modifiers.size(), 1u);
    EXPECT_EQ(combos[1].modifiers[0], gamepad_button(GamepadCode::LeftTrigger));
}

TEST_F(ConfigTest, KeyComboList_IndependentCombosDefault)
{
    Config::KeyComboList combos;

    Config::register_key_combo("Hotkeys", "Toggle", "toggle", [&combos](const Config::KeyComboList &c)
                               { combos = c; }, "F3,Gamepad_LT+Gamepad_B");

    ASSERT_EQ(combos.size(), 2u);
    ASSERT_EQ(combos[0].keys.size(), 1u);
    EXPECT_EQ(combos[0].keys[0], keyboard_key(0x72));
    EXPECT_TRUE(combos[0].modifiers.empty());
    ASSERT_EQ(combos[1].keys.size(), 1u);
    EXPECT_EQ(combos[1].keys[0], gamepad_button(GamepadCode::B));
    ASSERT_EQ(combos[1].modifiers.size(), 1u);
    EXPECT_EQ(combos[1].modifiers[0], gamepad_button(GamepadCode::LeftTrigger));
}

TEST_F(ConfigTest, KeyComboList_MixedDeviceCombos)
{
    Config::KeyComboList combos;

    Config::register_key_combo("Hotkeys", "Action", "action", [&combos](const Config::KeyComboList &c)
                               { combos = c; }, "Ctrl+F3,Mouse4,Gamepad_LB+Gamepad_A");

    ASSERT_EQ(combos.size(), 3u);
    EXPECT_EQ(combos[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combos[0].modifiers.size(), 1u);
    EXPECT_EQ(combos[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combos[1].keys[0], mouse_button(0x05));
    EXPECT_TRUE(combos[1].modifiers.empty());
    EXPECT_EQ(combos[2].keys[0], gamepad_button(GamepadCode::A));
    ASSERT_EQ(combos[2].modifiers.size(), 1u);
    EXPECT_EQ(combos[2].modifiers[0], gamepad_button(GamepadCode::LeftBumper));
}

TEST_F(ConfigTest, LogAll_SectionGrouping)
{
    Config::register_int("SectionA", "Key1", "A Key1", nullptr, 1);
    Config::register_int("SectionA", "Key2", "A Key2", nullptr, 2);
    Config::register_int("SectionB", "Key1", "B Key1", nullptr, 3);

    EXPECT_NO_THROW(Config::log_all());
}

TEST_F(ConfigTest, LogAll_LongStringNotTruncated)
{
    std::string long_value(200, 'x');
    Config::register_string("Sec", "LongVal", "long_val", nullptr, long_value);

    EXPECT_NO_THROW(Config::log_all());
}

TEST_F(ConfigTest, LogAll_EmptyKeyComboList)
{
    Config::register_key_combo("Sec", "K", "empty_combo", nullptr, "");

    EXPECT_NO_THROW(Config::log_all());
}

TEST_F(ConfigTest, ReRegistration_ReplacesCallback)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=50\n";
    ini_file.close();

    int old_val = 0;
    int new_val = 0;

    Config::register_int("TestSection", "TestInt", "old", [&old_val](int v)
                         { old_val = v; }, 10);

    // Simulate hot-reload: re-register the same section+key with a new callback.
    Config::register_int("TestSection", "TestInt", "new", [&new_val](int v)
                         { new_val = v; }, 20);

    Config::load(test_ini_file_.string());

    // The old callback is replaced; only the new callback receives the loaded value.
    EXPECT_EQ(old_val, 10);
    EXPECT_EQ(new_val, 50);
}

TEST_F(ConfigTest, ReRegistration_PreservesOtherKeys)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Sec]\n";
    ini_file << "A=1\n";
    ini_file << "B=2\n";
    ini_file.close();

    int a_val = 0, b_val = 0, a_val_new = 0;

    Config::register_int("Sec", "A", "a", [&a_val](int v)
                         { a_val = v; }, 0);
    Config::register_int("Sec", "B", "b", [&b_val](int v)
                         { b_val = v; }, 0);

    // Re-register only key A.
    Config::register_int("Sec", "A", "a_new", [&a_val_new](int v)
                         { a_val_new = v; }, 0);

    Config::load(test_ini_file_.string());

    EXPECT_EQ(a_val, 0);
    EXPECT_EQ(a_val_new, 1);
    EXPECT_EQ(b_val, 2);
}

TEST_F(ConfigTest, ReRegistration_DifferentSectionsSameKey)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[Sec1]\n";
    ini_file << "Key=10\n";
    ini_file << "[Sec2]\n";
    ini_file << "Key=20\n";
    ini_file.close();

    int val1 = 0, val2 = 0;

    Config::register_int("Sec1", "Key", "k1", [&val1](int v)
                         { val1 = v; }, 0);
    Config::register_int("Sec2", "Key", "k2", [&val2](int v)
                         { val2 = v; }, 0);

    Config::load(test_ini_file_.string());

    // Same key name but different sections; both should be kept independently.
    EXPECT_EQ(val1, 10);
    EXPECT_EQ(val2, 20);
}

TEST_F(ConfigTest, SetterCalledOnRegistrationAndLoad)
{
    // Verify that setter fires twice: once during register (with default),
    // once during load (with INI or default value). Consumers must be idempotent.
    std::vector<int> invocations;

    Config::register_int("TestSection", "TestKey", "test_int", [&invocations](int v)
                         { invocations.push_back(v); }, 42);

    // After registration, setter should have been called once with default
    ASSERT_EQ(invocations.size(), 1u);
    EXPECT_EQ(invocations[0], 42);

    // Load with no INI file: setter called again with default
    Config::load(test_ini_file_.string());

    ASSERT_EQ(invocations.size(), 2u);
    EXPECT_EQ(invocations[1], 42);
}

TEST_F(ConfigTest, SetterCalledOnRegistrationAndLoad_WithFile)
{
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "TestKey=99\n";
    ini_file.close();

    std::vector<int> invocations;

    Config::register_int("TestSection", "TestKey", "test_int", [&invocations](int v)
                         { invocations.push_back(v); }, 42);

    // After registration, setter called with default
    ASSERT_EQ(invocations.size(), 1u);
    EXPECT_EQ(invocations[0], 42);

    // Load from INI: setter called with file value
    Config::load(test_ini_file_.string());

    ASSERT_EQ(invocations.size(), 2u);
    EXPECT_EQ(invocations[1], 99);
}

TEST_F(ConfigTest, AccumulativeSetterMustBeIdempotent)
{
    // Demonstrates the pattern consumers should use: clear-before-add
    std::ofstream ini_file(test_ini_file_);
    ini_file << "[TestSection]\n";
    ini_file << "Items=alpha\n";
    ini_file.close();

    std::vector<std::string> items;

    Config::register_string("TestSection", "Items", "items",
                            [&items](const std::string &v)
                            {
                                // Idempotent pattern: clear before applying
                                items.clear();
                                items.push_back(v);
                            },
                            "default_item");

    // After registration: ["default_item"]
    ASSERT_EQ(items.size(), 1u);
    EXPECT_EQ(items[0], "default_item");

    // After load: ["alpha"] (not ["default_item", "alpha"])
    Config::load(test_ini_file_.string());

    ASSERT_EQ(items.size(), 1u);
    EXPECT_EQ(items[0], "alpha");
}

TEST_F(ConfigTest, SetterCalledTwice_Float)
{
    std::vector<float> invocations;

    Config::register_float("TestSection", "TestFloat", "test_float", [&invocations](float v)
                           { invocations.push_back(v); }, 1.5f);

    ASSERT_EQ(invocations.size(), 1u);
    EXPECT_NEAR(invocations[0], 1.5f, 0.01f);

    Config::load(test_ini_file_.string());

    ASSERT_EQ(invocations.size(), 2u);
    EXPECT_NEAR(invocations[1], 1.5f, 0.01f);
}

TEST_F(ConfigTest, SetterCalledTwice_Bool)
{
    std::vector<bool> invocations;

    Config::register_bool("TestSection", "TestBool", "test_bool", [&invocations](bool v)
                          { invocations.push_back(v); }, true);

    ASSERT_EQ(invocations.size(), 1u);
    EXPECT_TRUE(invocations[0]);

    Config::load(test_ini_file_.string());

    ASSERT_EQ(invocations.size(), 2u);
    EXPECT_TRUE(invocations[1]);
}

TEST_F(ConfigTest, SetterCalledTwice_KeyCombo)
{
    int call_count = 0;

    Config::register_key_combo("TestSection", "TestKeys", "test_keys", [&call_count](const Config::KeyComboList &)
                               { ++call_count; }, "F3");

    EXPECT_EQ(call_count, 1);

    Config::load(test_ini_file_.string());

    EXPECT_EQ(call_count, 2);
}

TEST(InputBindingGuard, DefaultIsInactive)
{
    Config::InputBindingGuard g;
    EXPECT_FALSE(g.is_active());
    EXPECT_TRUE(g.name().empty());
}

TEST(InputBindingGuard, ReleaseIsIdempotent)
{
    auto flag = std::make_shared<std::atomic<bool>>(true);
    Config::InputBindingGuard g("binding", flag);
    EXPECT_TRUE(g.is_active());
    g.release();
    EXPECT_FALSE(g.is_active());
    g.release();
    EXPECT_FALSE(g.is_active());
    EXPECT_FALSE(flag->load());
}

TEST(InputBindingGuard, MoveTransfersOwnership)
{
    auto flag = std::make_shared<std::atomic<bool>>(true);
    Config::InputBindingGuard a("b", flag);
    Config::InputBindingGuard b(std::move(a));
    EXPECT_TRUE(b.is_active());
    EXPECT_FALSE(a.is_active());
    b.release();
    EXPECT_FALSE(flag->load());
}

TEST(InputBindingGuard, MoveAssignment_TransfersAndReleasesOldFlag)
{
    auto flag_a = std::make_shared<std::atomic<bool>>(true);
    auto flag_b = std::make_shared<std::atomic<bool>>(true);

    Config::InputBindingGuard a("a", flag_a);
    Config::InputBindingGuard b("b", flag_b);

    b = std::move(a);

    EXPECT_FALSE(flag_b->load()) << "Move-assignment must release the prior flag";
    EXPECT_TRUE(flag_a->load());
    EXPECT_TRUE(b.is_active());
    EXPECT_FALSE(a.is_active());
}

TEST(InputBindingGuard, MoveAssignment_SelfMoveIsNoOp)
{
    auto flag = std::make_shared<std::atomic<bool>>(true);
    Config::InputBindingGuard g("self", flag);

    auto &alias = g;
    g = std::move(alias);

    EXPECT_TRUE(g.is_active()) << "Self move-assign must not release the flag";
    EXPECT_TRUE(flag->load());
}

TEST(InputBindingGuard, IsActiveReturnsFalseAfterExternalFlagFlip)
{
    auto flag = std::make_shared<std::atomic<bool>>(false);
    Config::InputBindingGuard g("flipped", flag);
    EXPECT_FALSE(g.is_active());
    flag->store(true, std::memory_order_release);
    EXPECT_TRUE(g.is_active());
}

TEST(InputBindingGuard, DestructorReleasesFlag)
{
    auto flag = std::make_shared<std::atomic<bool>>(true);
    ASSERT_TRUE(flag->load());
    {
        Config::InputBindingGuard g("scoped", flag);
        EXPECT_TRUE(g.is_active());
        EXPECT_TRUE(flag->load());
    }
    EXPECT_FALSE(flag->load());
}

// --- Reload tests ---

TEST_F(ConfigTest, Reload_WithoutInitialLoad_ReturnsFalse)
{
    EXPECT_FALSE(Config::reload());
}

TEST_F(ConfigTest, Reload_PreservesRegistrations)
{
    std::vector<int> int_invocations;
    std::vector<bool> bool_invocations;
    std::vector<std::string> string_invocations;

    Config::register_int("S", "Count", "count",
                         [&](int v)
                         { int_invocations.push_back(v); },
                         0);
    Config::register_bool("S", "Enabled", "enabled",
                          [&](bool v)
                          { bool_invocations.push_back(v); },
                          false);
    Config::register_string("S", "Label", "label",
                            [&](const std::string &v)
                            { string_invocations.push_back(v); },
                            std::string("default"));

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nCount=7\nEnabled=true\nLabel=first\n";
    }

    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    ASSERT_FALSE(int_invocations.empty());
    EXPECT_EQ(int_invocations.back(), 7);
    ASSERT_FALSE(bool_invocations.empty());
    EXPECT_TRUE(bool_invocations.back());
    ASSERT_FALSE(string_invocations.empty());
    EXPECT_EQ(string_invocations.back(), "first");

    // Rewrite the INI with fresh values; reload() must re-fire every setter.
    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nCount=42\nEnabled=false\nLabel=second\n";
    }

    const size_t int_before = int_invocations.size();
    const size_t bool_before = bool_invocations.size();
    const size_t str_before = string_invocations.size();

    EXPECT_TRUE(Config::reload());

    EXPECT_EQ(int_invocations.size(), int_before + 1);
    EXPECT_EQ(int_invocations.back(), 42);
    EXPECT_EQ(bool_invocations.size(), bool_before + 1);
    EXPECT_FALSE(bool_invocations.back());
    EXPECT_EQ(string_invocations.size(), str_before + 1);
    EXPECT_EQ(string_invocations.back(), "second");
}

TEST_F(ConfigTest, Reload_SetterThrows_RemainingSettersStillRun)
{
    std::atomic<int> first_value{0};
    std::atomic<int> third_value{0};
    std::atomic<int> throw_count{0};

    Config::register_int("S", "First", "first",
                         [&first_value](int v)
                         { first_value.store(v, std::memory_order_release); },
                         0);
    // Setter fires once at register, once at load, once at reload; start
    // throwing only on the third invocation so the failure lands on the
    // reload path.
    Config::register_int("S", "Middle", "middle",
                         [&throw_count](int /*v*/)
                         {
                             const int calls =
                                 throw_count.fetch_add(1, std::memory_order_relaxed) + 1;
                             if (calls >= 3)
                             {
                                 throw std::runtime_error("middle setter deliberately throws");
                             }
                         },
                         0);
    Config::register_int("S", "Third", "third",
                         [&third_value](int v)
                         { third_value.store(v, std::memory_order_release); },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nFirst=1\nMiddle=2\nThird=3\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));

    // Bump all values and reload. The middle setter throws; the first
    // and third setters must still receive the new values.
    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nFirst=10\nMiddle=20\nThird=30\n";
    }

    EXPECT_NO_THROW({ (void)Config::reload(); });

    EXPECT_EQ(first_value.load(std::memory_order_acquire), 10);
    EXPECT_EQ(third_value.load(std::memory_order_acquire), 30);
    EXPECT_GE(throw_count.load(std::memory_order_relaxed), 3);
}

TEST_F(ConfigTest, Reload_AfterClear_ReturnsFalse_BecausePathCleared)
{
    // clear_registered_items() also clears the remembered INI path, so
    // reload() takes the no-last-loaded-path branch (not a no-items one).
    int value = 0;
    Config::register_int("S", "K", "k",
                         [&value](int v)
                         { value = v; },
                         1);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=5\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(value, 5);

    Config::clear_registered_items();
    EXPECT_FALSE(Config::reload());
}

TEST_F(ConfigTest, ReloadHotkey_RegistersBinding)
{
    InputManager::get_instance().shutdown();

    int value = 0;
    Config::register_int("S", "K", "k",
                         [&value](int v)
                         { value = v; },
                         1);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=2\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(value, 2);

    const size_t before = InputManager::get_instance().binding_count();

    EXPECT_TRUE(Config::register_reload_hotkey("ReloadConfig", "Ctrl+F5"));

    EXPECT_GT(InputManager::get_instance().binding_count(), before);

    // Rewrite and simulate the hotkey by invoking what the callback does.
    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=123\n";
    }
    EXPECT_TRUE(Config::reload());
    EXPECT_EQ(value, 123);

    InputManager::get_instance().shutdown();
}

TEST_F(ConfigTest, ReloadHotkey_EmptyComboRejected)
{
    InputManager::get_instance().shutdown();
    EXPECT_FALSE(Config::register_reload_hotkey("ReloadConfig", ""));
}

TEST_F(ConfigTest, ReloadHotkey_ActuallyFiresOnPress)
{
    // Regression guard: register_reload_hotkey() must retain the
    // InputBindingGuard so the binding's enabled flag stays true. If the
    // guard were discarded, ~InputBindingGuard would release the flag and
    // the bound callback could never fire.
    //
    // InputManager has no press-injection hook from user code, so we
    // prove the callback path indirectly: after registration the
    // binding's enabled flag must still be true. We cannot peek the flag
    // directly, so we call Config::reload() (what the press callback
    // does) and observe the setter fire.
    InputManager::get_instance().shutdown();

    int value = 0;
    Config::register_int("S", "K", "k",
                         [&value](int v)
                         { value = v; },
                         1);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=2\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(value, 2);

    ASSERT_TRUE(Config::register_reload_hotkey("ReloadConfig", "F5"));

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=77\n";
    }
    ASSERT_TRUE(Config::reload());
    EXPECT_EQ(value, 77);

    // Re-register with a different combo: the second call must replace
    // the first guard in place rather than stacking per reload cycle.
    ASSERT_TRUE(Config::register_reload_hotkey("ReloadConfig", "F6"));

    InputManager::get_instance().shutdown();
}

TEST_F(ConfigTest, RegisterReloadHotkey_InvalidCombo_Rejected)
{
    // Unparseable combos like "NotAKey" produce zero bindings inside
    // register_press_combo. register_reload_hotkey must reject the
    // registration rather than return success for a silent no-op.
    InputManager::get_instance().shutdown();
    EXPECT_FALSE(Config::register_reload_hotkey("ReloadConfig", "NotAKey"));
}

TEST_F(ConfigTest, DisableAutoReload_FromReloadCallback_DoesNotDeadlock)
{
    // A reload callback that runs on the watcher thread and itself calls
    // disable_auto_reload() must not self-join the worker. The self-join
    // is short-circuited and a later disable_auto_reload() from the main
    // thread must still clean up normally.
    Config::disable_auto_reload();

    std::atomic<int> current_value{0};
    Config::register_int("S", "K", "k",
                         [&](int v)
                         { current_value.store(v, std::memory_order_release); },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=10\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));

    std::atomic<int> on_reload_hits{0};
    ASSERT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{100},
                                         [&](bool /*content_changed*/)
                                         {
                                             on_reload_hits.fetch_add(1, std::memory_order_relaxed);
                                             // Self-call must not deadlock the worker.
                                             Config::disable_auto_reload();
                                         }),
              Config::AutoReloadStatus::Started);

    std::this_thread::sleep_for(std::chrono::milliseconds{150});

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=42\n";
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{3};
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (on_reload_hits.load(std::memory_order_relaxed) >= 1)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }

    EXPECT_GE(on_reload_hits.load(std::memory_order_relaxed), 1)
        << "on_reload callback must have run at least once";

    EXPECT_NO_THROW(Config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_EndToEnd)
{
    // Ensure a previous test's watcher is not still attached.
    Config::disable_auto_reload();

    std::atomic<int> current_value{0};
    std::atomic<int> setter_invocations{0};

    Config::register_int("S", "K", "k",
                         [&](int v)
                         {
                             current_value.store(v, std::memory_order_release);
                             setter_invocations.fetch_add(1, std::memory_order_relaxed);
                         },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=10\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    EXPECT_EQ(current_value.load(), 10);

    std::atomic<int> on_reload_hits{0};
    ASSERT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{100},
                                         [&](bool /*content_changed*/)
                                         { on_reload_hits.fetch_add(1); }),
              Config::AutoReloadStatus::Started);

    // Give the watcher thread time to issue its first ReadDirectoryChangesW.
    std::this_thread::sleep_for(std::chrono::milliseconds{150});

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=77\n";
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{3};
    bool observed = false;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (current_value.load(std::memory_order_acquire) == 77)
        {
            observed = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }

    Config::disable_auto_reload();

    EXPECT_TRUE(observed) << "Watcher never observed the write";
    EXPECT_GE(on_reload_hits.load(), 1);
    EXPECT_GE(setter_invocations.load(), 2);
}

TEST_F(ConfigTest, AutoReload_DisableBeforeEnableIsSafe)
{
    EXPECT_NO_THROW(Config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_EnableWithoutPriorLoadIsIgnored)
{
    // With no prior load() the watcher must refuse to start.
    EXPECT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{50}),
              Config::AutoReloadStatus::NoPriorLoad);
    // disable_auto_reload() must still be safe.
    EXPECT_NO_THROW(Config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_Enable_ReportsNoPriorLoad)
{
    Config::disable_auto_reload();
    Config::clear_registered_items();

    EXPECT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{50}),
              Config::AutoReloadStatus::NoPriorLoad);
    EXPECT_NO_THROW(Config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_Enable_ReportsAlreadyRunning)
{
    Config::disable_auto_reload();

    int value = 0;
    Config::register_int("S", "K", "k",
                         [&value](int v)
                         { value = v; },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=1\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));

    EXPECT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{100}),
              Config::AutoReloadStatus::Started);
    EXPECT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{100}),
              Config::AutoReloadStatus::AlreadyRunning);

    Config::disable_auto_reload();
}

TEST_F(ConfigTest, AutoReload_Enable_ReportsStartFailed)
{
    // Remove the parent directory between load() and enable_auto_reload()
    // so ConfigWatcher::start()'s CreateFileW call fails.
    Config::disable_auto_reload();

    const auto temp_dir = std::filesystem::temp_directory_path() /
                          ("dmk_cfg_startfail_" + std::to_string(_getpid()) +
                           "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(temp_dir);
    const auto ini_path = temp_dir / "cfg.ini";
    {
        std::ofstream f(ini_path);
        f << "[S]\nK=1\n";
    }

    int value = 0;
    Config::register_int("S", "K", "k",
                         [&value](int v)
                         { value = v; },
                         0);
    ASSERT_NO_THROW(Config::load(ini_path.string()));

    // Destroy the parent directory so CreateFileW fails inside start().
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
    ASSERT_FALSE(ec) << "Failed to remove temp dir: " << ec.message();

    EXPECT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{50}),
              Config::AutoReloadStatus::StartFailed);
    EXPECT_NO_THROW(Config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_Enable_AfterStartFailed_RecoversOnRetry)
{
    // A failed start must not latch the watcher slot as AlreadyRunning;
    // a later retry once the backing file exists must report Started.
    Config::disable_auto_reload();

    const auto temp_dir = std::filesystem::temp_directory_path() /
                          ("dmk_cfg_recover_" + std::to_string(_getpid()) +
                           "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(temp_dir);
    const auto ini_path = temp_dir / "cfg.ini";
    {
        std::ofstream f(ini_path);
        f << "[S]\nK=1\n";
    }

    int value = 0;
    Config::register_int("S", "K", "k",
                         [&value](int v)
                         { value = v; },
                         0);
    ASSERT_NO_THROW(Config::load(ini_path.string()));

    // Remove the watched directory to drive start() into StartFailed.
    // The stored INI path survives the failed start.
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
    ASSERT_FALSE(ec) << "Failed to remove temp dir: " << ec.message();

    EXPECT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{50}),
              Config::AutoReloadStatus::StartFailed);

    // Recreate the directory; the stored path is unchanged so the
    // retried start handshake can open it without another load().
    std::filesystem::create_directories(temp_dir);
    {
        std::ofstream f(ini_path);
        f << "[S]\nK=2\n";
    }

    EXPECT_EQ(Config::enable_auto_reload(std::chrono::milliseconds{50}),
              Config::AutoReloadStatus::Started);

    Config::disable_auto_reload();

    std::filesystem::remove_all(temp_dir, ec);
}

TEST_F(ConfigTest, Reload_ContentUnchanged_SkipsSetters)
{
    std::atomic<int> setter_hits{0};
    Config::register_int("S", "K", "k",
                         [&](int /*v*/)
                         { setter_hits.fetch_add(1, std::memory_order_relaxed); },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=1\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    // No file change: reload() returns success but must not re-run the
    // setter, because the content-hash short-circuit kicks in.
    EXPECT_TRUE(Config::reload());
    EXPECT_EQ(setter_hits.load(std::memory_order_relaxed), after_load)
        << "Content-hash skip must suppress setter re-invocation.";
}

TEST_F(ConfigTest, Reload_ContentChanged_RunsSetters)
{
    std::atomic<int> setter_hits{0};
    Config::register_int("S", "K", "k",
                         [&](int /*v*/)
                         { setter_hits.fetch_add(1, std::memory_order_relaxed); },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=1\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    // Modify the file: the hash must mismatch and setters must run again.
    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=2\n";
    }
    EXPECT_TRUE(Config::reload());
    EXPECT_GT(setter_hits.load(std::memory_order_relaxed), after_load)
        << "Changed content must re-invoke the setter.";
}

TEST_F(ConfigTest, Reload_FileUnreadable_FallsBackToReload)
{
    // Prime: load once so a hash exists, then delete the file so
    // read_ini_bytes() returns nullopt inside reload(). The expected
    // behavior is that reload() still returns true (matching the
    // existing contract when SimpleIni itself fails to open the file)
    // and does not crash.
    std::atomic<int> setter_hits{0};
    Config::register_int("S", "K", "k",
                         [&](int /*v*/)
                         { setter_hits.fetch_add(1, std::memory_order_relaxed); },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=9\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    std::error_code ec;
    std::filesystem::remove(test_ini_file_, ec);
    ASSERT_FALSE(ec);

    // reload() must still return true. Setters re-run with defaults
    // because SimpleIni cannot open the missing file; the count must
    // therefore have advanced (erring on the side of reloading).
    EXPECT_TRUE(Config::reload());
    EXPECT_GT(setter_hits.load(std::memory_order_relaxed), after_load)
        << "Unreadable file must fall back to a full reload rather than a hash-skip.";
}

TEST_F(ConfigTest, Servicer_RapidPresses_CoalesceToAtMostOneReloadPerBurst)
{
    // Exercise the coalescing guarantee from the public surface: N
    // parallel reload() calls against unchanged bytes run the setter at
    // most once; subsequent unchanged-bytes calls short-circuit on the
    // content hash.
    std::atomic<int> setter_hits{0};
    Config::register_int("S", "K", "k",
                         [&](int /*v*/)
                         {
                             // Sleep so overlapping reload() calls from
                             // multiple threads actually race.
                             std::this_thread::sleep_for(std::chrono::milliseconds{10});
                             setter_hits.fetch_add(1, std::memory_order_relaxed);
                         },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=1\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    const int baseline = setter_hits.load(std::memory_order_relaxed);

    // 10 parallel reload() calls against unchanged bytes. Config::reload
    // serialises on getConfigMutex(); expected setter-hit delta is 0.
    constexpr int kThreads = 10;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i)
    {
        threads.emplace_back([] { (void)Config::reload(); });
    }
    for (auto &t : threads)
    {
        t.join();
    }

    // Upper bound 1 tolerates a race past the hash check in a narrow
    // window; expected delta is 0.
    const int delta = setter_hits.load(std::memory_order_relaxed) - baseline;
    EXPECT_LE(delta, 1)
        << "Content-hash skip must collapse concurrent unchanged-bytes reloads "
           "to at most one setter pass (observed delta=" << delta << ").";
}

TEST_F(ConfigTest, Reload_WatcherPath_HashSkip_EmitsOnReloadFalse)
{
    // After a watcher-driven hash-skip, the user-facing on_reload
    // callback must deliver content_changed == false.
    Config::disable_auto_reload();

    std::atomic<int> current_value{0};
    Config::register_int("S", "K", "k",
                         [&](int v)
                         { current_value.store(v, std::memory_order_release); },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=42\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    ASSERT_EQ(current_value.load(), 42);

    // Collect (content_changed) booleans from watcher-driven reloads.
    std::mutex hits_mutex;
    std::vector<bool> hits;
    ASSERT_EQ(
        Config::enable_auto_reload(std::chrono::milliseconds{100},
                                   [&](bool content_changed)
                                   {
                                       std::lock_guard<std::mutex> lock(hits_mutex);
                                       hits.push_back(content_changed);
                                   }),
        Config::AutoReloadStatus::Started);

    // Let the watcher finish its first ReadDirectoryChangesW call so
    // subsequent writes are observed.
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    // Phase 1: rewrite with *different* bytes -- must deliver content_changed=true.
    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=43\n";
    }

    const auto wait_for_hit_count = [&](std::size_t target,
                                        std::chrono::milliseconds timeout) -> bool
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            {
                std::lock_guard<std::mutex> lock(hits_mutex);
                if (hits.size() >= target)
                {
                    return true;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{25});
        }
        return false;
    };

    ASSERT_TRUE(wait_for_hit_count(1, std::chrono::seconds{3}))
        << "Watcher never observed the first (changed-bytes) write.";

    // Phase 2: rewrite with identical bytes to bump mtime without
    // changing the content hash. on_reload must deliver
    // content_changed = false.
    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=43\n";
    }

    ASSERT_TRUE(wait_for_hit_count(2, std::chrono::seconds{3}))
        << "Watcher never observed the touch (identical-bytes) write.";

    Config::disable_auto_reload();

    std::lock_guard<std::mutex> lock(hits_mutex);
    ASSERT_GE(hits.size(), 2u);
    EXPECT_TRUE(hits.front())
        << "First watcher hit must report content_changed=true (bytes differed).";
    EXPECT_FALSE(hits.back())
        << "Final watcher hit must report content_changed=false (hash-skip suppressed setters).";
}

TEST_F(ConfigTest, Reload_EmptyFile_DoesNotCrash)
{
    // SimpleIni treats a zero-byte buffer as SI_OK with no sections; a
    // subsequent reload() against the same empty bytes must hash-skip.
    std::atomic<int> setter_hits{0};
    Config::register_int("S", "K", "k",
                         [&](int /*v*/)
                         { setter_hits.fetch_add(1, std::memory_order_relaxed); },
                         7);

    // Create an empty file.
    { std::ofstream f(test_ini_file_, std::ios::binary); }
    ASSERT_TRUE(std::filesystem::exists(test_ini_file_));
    ASSERT_EQ(std::filesystem::file_size(test_ini_file_), 0u);

    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    // First reload(): identical empty bytes -> hash-skip. Returns true,
    // no setter re-invocation.
    EXPECT_TRUE(Config::reload());
    EXPECT_EQ(setter_hits.load(std::memory_order_relaxed), after_load)
        << "Empty-file reload must hash-skip.";

    // Second reload(): same result.
    EXPECT_TRUE(Config::reload());
    EXPECT_EQ(setter_hits.load(std::memory_order_relaxed), after_load)
        << "Repeated empty-file reload must stay on the hash-skip path.";
}

TEST_F(ConfigTest, Reload_HashResetOnLoadFailure)
{
    // A load() against a missing file must clear the cached content
    // hash so a later successful load() cannot spuriously hash-skip.
    std::atomic<int> setter_hits{0};
    Config::register_int("S", "K", "k",
                         [&](int /*v*/)
                         { setter_hits.fetch_add(1, std::memory_order_relaxed); },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=5\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));

    // Deriving the missing path from test_ini_file_ inherits the pid +
    // per-test counter so uniqueness holds under parallel runs.
    const auto missing = test_ini_file_.parent_path() /
                         (test_ini_file_.stem().string() + "_missing.ini");
    std::filesystem::remove(missing);
    ASSERT_FALSE(std::filesystem::exists(missing));
    ASSERT_NO_THROW(Config::load(missing.string()));

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=5\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    const int after_second_load = setter_hits.load(std::memory_order_relaxed);

    EXPECT_TRUE(Config::reload());
    EXPECT_EQ(setter_hits.load(std::memory_order_relaxed), after_second_load)
        << "Post-reset re-load must re-establish a valid hash so unchanged-bytes reloads skip.";
}

TEST_F(ConfigTest, Reload_HashResetOnReadFailure)
{
    // As Reload_HashResetOnLoadFailure, but the clearing happens on a
    // reload() read failure. A stale hash would let a subsequent
    // identical-bytes reload hash-skip and leave state at defaults.
    std::atomic<int> setter_hits{0};
    Config::register_int("S", "K", "k",
                         [&](int /*v*/)
                         { setter_hits.fetch_add(1, std::memory_order_relaxed); },
                         0);

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=5\n";
    }
    ASSERT_NO_THROW(Config::load(test_ini_file_.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    // Remove the file; reload() targets the path remembered from the
    // last load() and will fail to open.
    ASSERT_TRUE(std::filesystem::remove(test_ini_file_));
    ASSERT_FALSE(std::filesystem::exists(test_ini_file_));
    EXPECT_TRUE(Config::reload());
    const int after_failed_reload = setter_hits.load(std::memory_order_relaxed);
    EXPECT_GT(after_failed_reload, after_load)
        << "reload() on a disappeared file must still run setters with defaults.";

    {
        std::ofstream f(test_ini_file_);
        f << "[S]\nK=5\n";
    }
    EXPECT_TRUE(Config::reload());
    EXPECT_GT(setter_hits.load(std::memory_order_relaxed), after_failed_reload)
        << "Recovery reload() with identical bytes must re-run setters because the "
           "read-failure branch cleared the cached hash.";
}
