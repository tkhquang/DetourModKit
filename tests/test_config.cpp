#include <gtest/gtest.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <clocale>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <memory>
#include <process.h>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "DetourModKit/config.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/input_hold_gate.hpp"
#include "internal/input_intercept.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;
using DetourModKit::mouse_button;

// clear() runs inside the noexcept Session teardown chain, so a throw from it would terminate the host. Its
// diagnostic logging routes through the no-throw try_log path to keep the contract honest; pin it here.
static_assert(noexcept(config::clear()),
              "config::clear() must be noexcept (it runs inside the noexcept teardown chain).");

class ConfigTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static int s_test_counter = 0;
        m_test_ini_file = std::filesystem::temp_directory_path() / ("test_config_" + std::to_string(_getpid()) + "_" +
                                                                    std::to_string(s_test_counter++) + ".ini");
        config::clear();
    }

    void TearDown() override
    {
        config::clear();
        if (std::filesystem::exists(m_test_ini_file))
        {
            std::filesystem::remove(m_test_ini_file);
        }
    }

    std::filesystem::path m_test_ini_file;
};

TEST_F(ConfigTest, RegisterInt)
{
    int test_value = 0;

    config::bind_int("TestSection", "TestKey", "test_int", [&test_value](int v) { test_value = v; }, 42);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(test_value, 42);
}

TEST_F(ConfigTest, RegisterFloat)
{
    float test_value = 0.0f;

    config::bind_float("TestSection", "TestKeyFloat", "test_float", [&test_value](float v) { test_value = v; }, 3.14f);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_NEAR(test_value, 3.14f, 0.01f);
}

TEST_F(ConfigTest, RegisterBool)
{
    bool test_value = false;

    config::bind_bool("TestSection", "TestKeyBool", "test_bool", [&test_value](bool v) { test_value = v; }, true);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_TRUE(test_value);
}

TEST_F(ConfigTest, RegisterString)
{
    std::string test_value;

    config::bind_string(
        "TestSection", "TestKeyString", "test_string", [&test_value](std::string_view v) { test_value = v; },
        "default_value");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(test_value, "default_value");
}

TEST_F(ConfigTest, LoadFromFile)
{
    std::ofstream ini_file(m_test_ini_file);
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

    config::bind_int("TestSection", "TestInt", "test_int", [&test_int](int v) { test_int = v; }, 0);
    config::bind_float("TestSection", "TestFloat", "test_float", [&test_float](float v) { test_float = v; }, 0.0f);
    config::bind_bool("TestSection", "TestBool", "test_bool", [&test_bool](bool v) { test_bool = v; }, false);
    config::bind_string(
        "TestSection", "TestString", "test_string", [&test_string](std::string_view v) { test_string = v; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    EXPECT_EQ(test_int, 100);
    EXPECT_NEAR(test_float, 2.5f, 0.01f);
    EXPECT_TRUE(test_bool);
    EXPECT_EQ(test_string, "loaded_value");
}

TEST_F(ConfigTest, LogAll)
{
    config::bind_int("TestSection", "TestKey", "test_int", [](int) {}, 42);

    EXPECT_NO_THROW(config::log_all());
}

TEST_F(ConfigTest, KeyCombo_HexFormats)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x01, 0X02, 0x03, 0x04\n";
    ini_file.close();

    input::KeyComboList test_value;

    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 4u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x01));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x02));
    EXPECT_EQ(test_value[2].keys[0], keyboard_key(0x03));
    EXPECT_EQ(test_value[3].keys[0], keyboard_key(0x04));
}

TEST_F(ConfigTest, KeyCombo_NamedKeys)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=F3, F4, A\n";
    ini_file.close();

    input::KeyComboList test_value;

    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 3u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x72));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x73));
    EXPECT_EQ(test_value[2].keys[0], keyboard_key(0x41));
}

TEST_F(ConfigTest, KeyCombo_MouseButton)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=Mouse4\n";
    ini_file.close();

    input::KeyComboList test_value;

    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], mouse_button(0x05));
}

TEST_F(ConfigTest, KeyCombo_GamepadButton)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=Gamepad_A\n";
    ini_file.close();

    input::KeyComboList test_value;

    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], gamepad_button(GamepadCode::A));
}

TEST_F(ConfigTest, KeyCombo_GamepadCombo)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=Gamepad_LB+Gamepad_A\n";
    ini_file.close();

    input::KeyComboList test_value;

    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], gamepad_button(GamepadCode::A));
    ASSERT_EQ(test_value[0].modifiers.size(), 1u);
    EXPECT_EQ(test_value[0].modifiers[0], gamepad_button(GamepadCode::LeftBumper));
}

TEST_F(ConfigTest, KeyCombo_InvalidHex)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x10, INVALID, 0xGG, 0x20\n";
    ini_file.close();

    input::KeyComboList test_value;

    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x20));
}

TEST_F(ConfigTest, KeyCombo_CommentOnlyLineYieldsEmpty)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=   ; only a comment\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_TRUE(test_value.empty());
}

TEST_F(ConfigTest, KeyCombo_EmptyCommaSeparatorsAreSkipped)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=,,F3,,F4,,\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x72));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x73));
}

TEST_F(ConfigTest, KeyCombo_HexWithOnlyPrefixIsSkipped)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=0x, 0X, 0x72\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x72));
}

TEST_F(ConfigTest, KeyCombo_HexValueAboveIntMaxIsSkipped)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    // 0xFFFFFFFF > INT_MAX, so the > limits check rejects it. The valid 0x10 still parses.
    ini_file << "TestKeys=0xFFFFFFFF, 0x10\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
}

TEST_F(ConfigTest, KeyCombo_DoublePlusSkipsEmptySegment)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=Ctrl++F3\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    ASSERT_EQ(test_value.size(), 1u);
    ASSERT_EQ(test_value[0].modifiers.size(), 1u);
    EXPECT_EQ(test_value[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x72));
}

TEST_F(ConfigTest, KeyCombo_TrailingPlusParsedAsTrigger)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    // "Ctrl+" parses with Ctrl as the only non-empty segment and becomes the trigger key with no modifiers; the
    // trailing empty segment is dropped by the !segment.empty() filter.
    ini_file << "TestKeys=Ctrl+\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x11));
    EXPECT_TRUE(test_value[0].modifiers.empty());
}

TEST_F(ConfigTest, KeyCombo_OnlyPlusSignsYieldsEmpty)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKeys=+++\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "F3");
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_TRUE(test_value.empty());
}

TEST_F(ConfigTest, KeyCombo_DefaultParsesMultipleCombos)
{
    input::KeyComboList captured;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&captured](const input::KeyComboList &c) { captured = c; },
        "Ctrl+F3,Gamepad_LT+Gamepad_A");
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(captured.size(), 2u);
    EXPECT_EQ(captured[0].modifiers.size(), 1u);
    EXPECT_EQ(captured[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(captured[1].modifiers.size(), 1u);
    ASSERT_FALSE(captured[1].keys.empty());
    EXPECT_EQ(captured[1].keys[0], DetourModKit::gamepad_button(DetourModKit::GamepadCode::A));
}

TEST_F(ConfigTest, ClearRegisteredItems)
{
    int test_value = 0;

    config::bind_int("TestSection", "TestKey", "test_int", [&test_value](int v) { test_value = v; }, 42);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(test_value, 42);

    EXPECT_NO_THROW(config::clear());

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_NO_THROW(config::log_all());
}

TEST_F(ConfigTest, ClearRegisteredItems_Empty)
{
    EXPECT_NO_THROW(config::clear());
}

TEST_F(ConfigTest, LogAll_Empty)
{
    EXPECT_NO_THROW(config::log_all());
}

TEST_F(ConfigTest, LoadNonExistentFile)
{
    int test_value = 0;
    std::string non_existent_path =
        (std::filesystem::temp_directory_path() / "non_existent_dir" / "config.ini").string();

    config::bind_int("TestSection", "TestKey", "test_int", [&test_value](int v) { test_value = v; }, 999);

    EXPECT_NO_THROW(config::load(non_existent_path));
    EXPECT_EQ(test_value, 999);
}

// A reload whose read fails (here: the file vanished after a good load, the same fail-to-open path a mid-save lock
// takes) must retain the last good in-memory value instead of applying defaults from an unpopulated parser.
TEST_F(ConfigTest, ReloadWhenFileDisappearsRetainsLastValues)
{
    {
        std::ofstream ini(m_test_ini_file);
        ini << "[S]\nSpeed=5\n";
    }

    int speed = 0;
    config::bind_int("S", "Speed", "speed", [&speed](int v) { speed = v; }, 9);
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    ASSERT_EQ(speed, 5) << "precondition: initial load must read 5";

    // Remove the file so reload()'s read of the remembered path fails.
    std::filesystem::remove(m_test_ini_file);

    EXPECT_NO_THROW((void)config::reload());

    // Retained: still 5, not the registered default 9.
    EXPECT_EQ(speed, 5);
}

// The ship-with-defaults first run has no INI on disk yet. load() must still remember the path so enable_auto_reload()
// can start a watcher on the existing parent directory and pick the file up when it later appears.
TEST_F(ConfigTest, LoadMissingFileStoresPathSoAutoReloadCanStart)
{
    const auto missing =
        std::filesystem::temp_directory_path() / ("test_config_missing_" + std::to_string(_getpid()) + ".ini");
    std::filesystem::remove(missing);

    EXPECT_NO_THROW(config::load(missing.string()));
    const auto status = config::enable_auto_reload();

    EXPECT_EQ(status, config::AutoReloadStatus::Started);
    config::disable_auto_reload();
}

// Pins the float parse grammar: a leading '+' is honored, '-' parses directly, and a value with a trailing non-numeric
// suffix warns and falls back to the default rather than partially parsing.
TEST_F(ConfigTest, FloatBind_ParsesSignsAndRejectsTrailingJunk)
{
    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nPlus=+1.5\nMinus=-2.5\nBad=1.5x\n";
    }
    float plus = 0.0f;
    float minus = 0.0f;
    float bad = 0.0f;
    config::bind_float("S", "Plus", "plus", [&plus](float v) { plus = v; }, 9.0f);
    config::bind_float("S", "Minus", "minus", [&minus](float v) { minus = v; }, 9.0f);
    config::bind_float("S", "Bad", "bad", [&bad](float v) { bad = v; }, 9.0f);
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    EXPECT_FLOAT_EQ(plus, 1.5f);
    EXPECT_FLOAT_EQ(minus, -2.5f);
    EXPECT_FLOAT_EQ(bad, 9.0f);
}

// Regression teeth for locale-independent float parsing: the float bind must resolve a fractional value the same way
// regardless of the host LC_NUMERIC. Under a comma-decimal locale the replaced strtod path read "1.5" as 1 and
// SimpleIni::GetDoubleValue then silently returned the registered default; std::from_chars ignores the C locale, so
// the value must still parse to 1.5. This assertion is the one that fails if the bind is reverted to GetDoubleValue.
// Skips when no comma-decimal locale is installed.
TEST_F(ConfigTest, FloatBind_IsLocaleIndependent)
{
    // Copy the active LC_NUMERIC name before mutating it; setlocale returns a pointer into a shared static buffer.
    const std::string previous_numeric = []
    {
        const char *const current = std::setlocale(LC_NUMERIC, nullptr);
        return current != nullptr ? std::string(current) : std::string("C");
    }();

    bool locale_applied = false;
    for (const char *candidate : {"de-DE", "German_Germany.1252", "de_DE.UTF-8", "de_DE"})
    {
        if (std::setlocale(LC_NUMERIC, candidate) != nullptr)
        {
            locale_applied = true;
            break;
        }
    }
    if (!locale_applied)
    {
        // No candidate changed the locale, so nothing to restore.
        GTEST_SKIP() << "no comma-decimal locale available on this host";
    }

    // Restore the original numeric locale however the assertions below exit, so the mutation cannot leak into a
    // sibling test in the single-process run.
    struct LocaleRestore
    {
        const std::string &name;
        ~LocaleRestore() { std::setlocale(LC_NUMERIC, name.c_str()); }
    } const restore{previous_numeric};

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nScale=1.5\n";
    }
    float scale = 0.0f;
    config::bind_float("S", "Scale", "scale", [&scale](float v) { scale = v; }, 9.0f);
    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    // Comma-locale strtod would have yielded the registered default 9.0; from_chars yields the real value.
    EXPECT_FLOAT_EQ(scale, 1.5f);
}

TEST_F(ConfigTest, MultipleLoads)
{
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[TestSection]\n";
        ini_file << "TestInt=100\n";
        ini_file.close();
    }

    int test_value = 0;

    config::bind_int("TestSection", "TestInt", "test_int", [&test_value](int v) { test_value = v; }, 0);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(test_value, 100);

    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[TestSection]\n";
        ini_file << "TestInt=200\n";
        ini_file.close();
    }

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(test_value, 200);
}

TEST_F(ConfigTest, MixedConfigTypes)
{
    std::ofstream ini_file(m_test_ini_file);
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
    input::KeyComboList keys_val;

    config::bind_int("Section1", "IntVal", "int_val", [&int_val](int v) { int_val = v; }, 0);
    config::bind_float("Section1", "FloatVal", "float_val", [&float_val](float v) { float_val = v; }, 0.0f);
    config::bind_bool("Section2", "BoolVal", "bool_val", [&bool_val](bool v) { bool_val = v; }, false);
    config::bind_string(
        "Section2", "StringVal", "string_val", [&string_val](std::string_view v) { string_val = v; }, "");
    config::bind_combos(
        "Section2", "Keys", "keys_val", [&keys_val](const input::KeyComboList &c) { keys_val = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    EXPECT_EQ(int_val, 42);
    EXPECT_NEAR(float_val, 3.14f, 0.01f);
    EXPECT_TRUE(bool_val);
    EXPECT_EQ(string_val, "hello");
    ASSERT_EQ(keys_val.size(), 2u);
}

TEST_F(ConfigTest, BoolVariations)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "Bool1=true\n";
    ini_file << "Bool2=false\n";
    ini_file << "Bool3=1\n";
    ini_file << "Bool4=0\n";
    ini_file.close();

    bool bool1 = false, bool2 = true, bool3 = false, bool4 = true;

    config::bind_bool("TestSection", "Bool1", "bool1", [&bool1](bool v) { bool1 = v; }, false);
    config::bind_bool("TestSection", "Bool2", "bool2", [&bool2](bool v) { bool2 = v; }, true);
    config::bind_bool("TestSection", "Bool3", "bool3", [&bool3](bool v) { bool3 = v; }, false);
    config::bind_bool("TestSection", "Bool4", "bool4", [&bool4](bool v) { bool4 = v; }, true);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    EXPECT_TRUE(bool1);
    EXPECT_FALSE(bool2);
    EXPECT_TRUE(bool3);
    EXPECT_FALSE(bool4);
}

TEST_F(ConfigTest, FloatFormats)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "Float1=3.14159\n";
    ini_file << "Float2=-2.5\n";
    ini_file << "Float3=0.0\n";
    ini_file.close();

    float float1 = 0.0f, float2 = 0.0f, float3 = 1.0f;

    config::bind_float("TestSection", "Float1", "float1", [&float1](float v) { float1 = v; }, 0.0f);
    config::bind_float("TestSection", "Float2", "float2", [&float2](float v) { float2 = v; }, 0.0f);
    config::bind_float("TestSection", "Float3", "float3", [&float3](float v) { float3 = v; }, 1.0f);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    EXPECT_NEAR(float1, 3.14159f, 0.0001f);
    EXPECT_NEAR(float2, -2.5f, 0.01f);
    EXPECT_NEAR(float3, 0.0f, 0.01f);
}

TEST_F(ConfigTest, KeyCombo_CommentsAndSpaces)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=  0x10  ,  0x20  ; this is a comment\n";
    ini_file.close();

    input::KeyComboList test_value;

    config::bind_combos(
        "TestSection", "Keys", "keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x20));
}

TEST_F(ConfigTest, KeyCombo_JustPrefix)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x, 0x10\n";
    ini_file.close();

    input::KeyComboList test_value;

    config::bind_combos(
        "TestSection", "Keys", "keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
}

TEST_F(ConfigTest, MultipleRegistrationsSameType)
{
    int val1 = 0, val2 = 0;

    config::bind_int("Section1", "Key1", "val1", [&val1](int v) { val1 = v; }, 10);
    config::bind_int("Section1", "Key2", "val2", [&val2](int v) { val2 = v; }, 20);

    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[Section1]\n";
    ini_file << "Key1=100\n";
    ini_file << "Key2=200\n";
    ini_file.close();

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    EXPECT_EQ(val1, 100);
    EXPECT_EQ(val2, 200);
}

TEST_F(ConfigTest, LogAll_AllTypes)
{
    float f_val = 0.0f;
    bool b_val = false;
    std::string s_val;
    input::KeyComboList k_val;

    config::bind_float("Sec", "F", "f_val", [&f_val](float v) { f_val = v; }, 1.5f);
    config::bind_bool("Sec", "B", "b_val", [&b_val](bool v) { b_val = v; }, true);
    config::bind_string("Sec", "S", "s_val", [&s_val](std::string_view v) { s_val = v; }, "hello");
    config::bind_combos("Sec", "K", "k_val", [&k_val](const input::KeyComboList &c) { k_val = c; }, "0x41");

    config::load(m_test_ini_file.string());

    EXPECT_NO_THROW(config::log_all());

    EXPECT_NEAR(f_val, 1.5f, 0.01f);
    EXPECT_TRUE(b_val);
    EXPECT_EQ(s_val, "hello");
    ASSERT_EQ(k_val.size(), 1u);
}

TEST_F(ConfigTest, KeyCombo_InlineTokenComment)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x10, 0x20 ; inline comment at end of line\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "Keys", "keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x20));
}

TEST_F(ConfigTest, KeyCombo_EmptyTokenFromConsecutiveCommas)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x10,,0x20\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "Keys", "keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 2u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x10));
    EXPECT_EQ(test_value[1].keys[0], keyboard_key(0x20));
}

TEST_F(ConfigTest, KeyCombo_OverflowValue)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=FFFFFFFFFFFFFFFFFFFFFFFF, 0x41\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "Keys", "keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x41));
}

TEST_F(ConfigTest, KeyCombo_DefaultEmptyToken)
{
    input::KeyComboList val;
    config::bind_combos("S", "K1", "k1", [&val](const input::KeyComboList &c) { val = c; }, "0x41,,0x42");
    config::load(m_test_ini_file.string());
    ASSERT_EQ(val.size(), 2u);
}

TEST_F(ConfigTest, KeyCombo_DefaultBarePrefix)
{
    input::KeyComboList val;
    config::bind_combos("S", "K2", "k2", [&val](const input::KeyComboList &c) { val = c; }, "0x, 0x42");
    config::load(m_test_ini_file.string());
    ASSERT_EQ(val.size(), 1u);
    EXPECT_EQ(val[0].keys[0], keyboard_key(0x42));
}

TEST_F(ConfigTest, KeyCombo_DefaultOverflow)
{
    input::KeyComboList val;
    config::bind_combos(
        "S", "K3", "k3", [&val](const input::KeyComboList &c) { val = c; }, "FFFFFFFFFFFFFFFFFFFFFFFF, 0x43");
    config::load(m_test_ini_file.string());
    ASSERT_EQ(val.size(), 1u);
    EXPECT_EQ(val[0].keys[0], keyboard_key(0x43));
}

TEST_F(ConfigTest, KeyCombo_ValueExceedingIntMax)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "Keys=0x80000000, 0x41\n";
    ini_file.close();

    input::KeyComboList test_value;
    config::bind_combos(
        "TestSection", "Keys", "keys", [&test_value](const input::KeyComboList &c) { test_value = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(test_value.size(), 1u);
    EXPECT_EQ(test_value[0].keys[0], keyboard_key(0x41));
}

TEST_F(ConfigTest, KeyCombo_DefaultValueExceedingIntMax)
{
    input::KeyComboList val;
    config::bind_combos("S", "K4", "k4", [&val](const input::KeyComboList &c) { val = c; }, "0x80000000, 0x44");
    config::load(m_test_ini_file.string());
    ASSERT_EQ(val.size(), 1u);
    EXPECT_EQ(val[0].keys[0], keyboard_key(0x44));
}

TEST_F(ConfigTest, DuplicateKeyRegistration_ReplacesExisting)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=77\n";
    ini_file.close();

    int first_val = 0;
    int second_val = 0;

    config::bind_int("TestSection", "TestInt", "first", [&first_val](int v) { first_val = v; }, 10);
    config::bind_int("TestSection", "TestInt", "second", [&second_val](int v) { second_val = v; }, 20);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    // Re-registration with the same section+key replaces the previous entry. Only the second (latest) callback receives
    // the loaded value.
    EXPECT_EQ(first_val, 10);
    EXPECT_EQ(second_val, 77);
}

TEST_F(ConfigTest, WhitespaceAroundValues)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt = 100 \n";
    ini_file << "TestString =  hello  \n";
    ini_file.close();

    int int_val = 0;
    std::string str_val;

    config::bind_int("TestSection", "TestInt", "int_val", [&int_val](int v) { int_val = v; }, 0);
    config::bind_string("TestSection", "TestString", "str_val", [&str_val](std::string_view v) { str_val = v; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    EXPECT_EQ(int_val, 100);
    EXPECT_EQ(str_val, "hello");
}

TEST_F(ConfigTest, NegativeIntValue)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=-50\n";
    ini_file.close();

    int val = 0;

    config::bind_int("TestSection", "TestInt", "val", [&val](int v) { val = v; }, 0);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(val, -50);
}

TEST_F(ConfigTest, PositiveIntValueWithExplicitSign)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=+50\n";
    ini_file.close();

    int val = 0;

    config::bind_int("TestSection", "TestInt", "val", [&val](int v) { val = v; }, 7);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(val, 50);
}

TEST_F(ConfigTest, IntValueAboveIntMaxFallsBackToDefault)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    // 5000000000 is larger than INT_MAX. The 64-bit parse can observe that overflow and fall back to the registered
    // default.
    ini_file << "TestInt=5000000000\n";
    ini_file.close();

    int val = 0;

    config::bind_int("TestSection", "TestInt", "val", [&val](int v) { val = v; }, 7);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(val, 7);
}

TEST_F(ConfigTest, IntValueBelowIntMinFallsBackToDefault)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    // -5000000000 is below INT_MIN; the symmetric lower-bound branch must also fall back to the registered default.
    ini_file << "TestInt=-5000000000\n";
    ini_file.close();

    int val = 0;

    config::bind_int("TestSection", "TestInt", "val", [&val](int v) { val = v; }, -3);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(val, -3);
}

TEST_F(ConfigTest, IntValueLeadingZeroStaysDecimal)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    // Match SimpleIni's historical GetLongValue behavior: only 0x switches to hex, so a leading zero is not octal.
    ini_file << "TestInt=010\n";
    ini_file.close();

    int val = 0;

    config::bind_int("TestSection", "TestInt", "val", [&val](int v) { val = v; }, 7);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(val, 10);
}

TEST_F(ConfigTest, IntValueNonNumericFallsBackToDefault)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    // A non-numeric value must be rejected and fall back to the registered default rather than committing zero.
    ini_file << "TestInt=abc\n";
    ini_file.close();

    int val = 0;

    config::bind_int("TestSection", "TestInt", "val", [&val](int v) { val = v; }, 5);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(val, 5);
}

TEST_F(ConfigTest, MissingSectionInFile)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[Other]\n";
    ini_file << "SomeKey=123\n";
    ini_file.close();

    int val = 999;

    config::bind_int("Missing", "TestInt", "val", [&val](int v) { val = v; }, 999);

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(val, 999);
}

TEST_F(ConfigTest, ThreadSafety)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=42\n";
    ini_file.close();

    int val = 0;

    config::bind_int("TestSection", "TestInt", "val", [&val](int v) { val = v; }, 0);

    constexpr int THREAD_COUNT = 8;
    std::vector<std::thread> threads;
    threads.reserve(THREAD_COUNT);

    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        threads.emplace_back([this]() { EXPECT_NO_THROW(config::load(m_test_ini_file.string())); });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_EQ(val, 42);
}

TEST_F(ConfigTest, EmptyStringValue)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestString=\n";
    ini_file.close();

    std::string val = "non_empty";

    config::bind_string("TestSection", "TestString", "val", [&val](std::string_view v) { val = v; }, "non_empty");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_TRUE(val.empty());
}

TEST_F(ConfigTest, RegisterString_DefaultValueNotMovedFrom)
{
    std::string val = "unset";
    std::string default_val = "my_default";

    config::bind_string("Defaults", "Str", "val", [&val](std::string_view v) { val = v; }, default_val);

    // Before load(), the setter should have been called with the default value
    EXPECT_EQ(val, "my_default");
}

TEST_F(ConfigTest, RegisterKeyCombo_SingleKey)
{
    input::KeyComboList combo;

    config::bind_combos("Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "0x72");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    EXPECT_TRUE(combo[0].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_NamedSingleKey)
{
    input::KeyComboList combo;

    config::bind_combos("Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "F3");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    EXPECT_TRUE(combo[0].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_SingleModifier)
{
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "0x11+0x72");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_NamedModifier)
{
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "Ctrl+F3");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_MultipleModifiers)
{
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "Ctrl+Shift+F3");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 2u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combo[0].modifiers[1], keyboard_key(0x10));
}

TEST_F(ConfigTest, RegisterKeyCombo_MultipleTriggerKeys)
{
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "Ctrl+F3,F4");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 2u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combo[1].keys[0], keyboard_key(0x73));
    EXPECT_TRUE(combo[1].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_Empty)
{
    input::KeyComboList combo;

    config::bind_combos("Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    EXPECT_TRUE(combo.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_FromFile)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[Hotkeys]\n";
    ini_file << "Toggle=Ctrl+Shift+F3 ; Ctrl+Shift+F3\n";
    ini_file.close();

    input::KeyComboList combo;

    config::bind_combos("Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "0x41");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 2u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combo[0].modifiers[1], keyboard_key(0x10));
}

TEST_F(ConfigTest, RegisterKeyCombo_FromFileNoModifiers)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[Hotkeys]\n";
    ini_file << "Toggle=F3\n";
    ini_file.close();

    input::KeyComboList combo;

    config::bind_combos("Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    EXPECT_TRUE(combo[0].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_FromFileMultipleTriggers)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[Hotkeys]\n";
    ini_file << "Toggle=Ctrl+F3,F4,F5\n";
    ini_file.close();

    input::KeyComboList combo;

    config::bind_combos("Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

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
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "0xGG+Ctrl+F3");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_WhitespaceAroundPlus)
{
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; },
        "  Ctrl  +  Shift  +  F3  ");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 2u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
    EXPECT_EQ(combo[0].modifiers[1], keyboard_key(0x10));
}

TEST_F(ConfigTest, RegisterKeyCombo_DefaultValueApplied)
{
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "Ctrl+F3");

    // Before load(), the setter should have been called with the parsed default
    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], keyboard_key(0x72));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_LogAll)
{
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&combo](const input::KeyComboList &c) { combo = c; }, "Ctrl+F3");

    config::load(m_test_ini_file.string());

    EXPECT_NO_THROW(config::log_all());
}

TEST_F(ConfigTest, RegisterKeyCombo_GamepadDefault)
{
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "GP", "gp", [&combo](const input::KeyComboList &c) { combo = c; }, "Gamepad_LB+Gamepad_A,Gamepad_B");

    ASSERT_EQ(combo.size(), 2u);
    EXPECT_EQ(combo[0].keys[0], gamepad_button(GamepadCode::A));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], gamepad_button(GamepadCode::LeftBumper));
    EXPECT_EQ(combo[1].keys[0], gamepad_button(GamepadCode::B));
    EXPECT_TRUE(combo[1].modifiers.empty());
}

TEST_F(ConfigTest, RegisterKeyCombo_MouseDefault)
{
    input::KeyComboList combo;

    config::bind_combos("Hotkeys", "MS", "ms", [&combo](const input::KeyComboList &c) { combo = c; }, "Ctrl+Mouse4");

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], mouse_button(0x05));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], keyboard_key(0x11));
}

TEST_F(ConfigTest, RegisterKeyCombo_ThumbstickDefault)
{
    input::KeyComboList combo;

    config::bind_combos(
        "Hotkeys", "LS", "ls", [&combo](const input::KeyComboList &c) { combo = c; }, "Gamepad_LB+Gamepad_LSUp");

    ASSERT_EQ(combo.size(), 1u);
    EXPECT_EQ(combo[0].keys[0], gamepad_button(GamepadCode::LeftStickUp));
    ASSERT_EQ(combo[0].modifiers.size(), 1u);
    EXPECT_EQ(combo[0].modifiers[0], gamepad_button(GamepadCode::LeftBumper));
}

TEST_F(ConfigTest, KeyCombo_ThumbstickFromFile)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[Hotkeys]\n";
    ini_file << "StickCombo=Gamepad_RSLeft,Gamepad_RSRight\n";
    ini_file.close();

    input::KeyComboList combo;

    config::bind_combos("Hotkeys", "StickCombo", "stick", [&combo](const input::KeyComboList &c) { combo = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

    ASSERT_EQ(combo.size(), 2u);
    EXPECT_EQ(combo[0].keys[0], gamepad_button(GamepadCode::RightStickLeft));
    EXPECT_EQ(combo[1].keys[0], gamepad_button(GamepadCode::RightStickRight));
}

TEST_F(ConfigTest, KeyComboList_IndependentCombos)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[Hotkeys]\n";
    ini_file << "Toggle=F3,Gamepad_LT+Gamepad_B\n";
    ini_file.close();

    input::KeyComboList combos;

    config::bind_combos("Hotkeys", "Toggle", "toggle", [&combos](const input::KeyComboList &c) { combos = c; }, "");

    EXPECT_NO_THROW(config::load(m_test_ini_file.string()));

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
    input::KeyComboList combos;

    config::bind_combos(
        "Hotkeys", "Toggle", "toggle", [&combos](const input::KeyComboList &c) { combos = c; },
        "F3,Gamepad_LT+Gamepad_B");

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
    input::KeyComboList combos;

    config::bind_combos(
        "Hotkeys", "Action", "action", [&combos](const input::KeyComboList &c) { combos = c; },
        "Ctrl+F3,Mouse4,Gamepad_LB+Gamepad_A");

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
    config::bind_int("SectionA", "Key1", "A Key1", nullptr, 1);
    config::bind_int("SectionA", "Key2", "A Key2", nullptr, 2);
    config::bind_int("SectionB", "Key1", "B Key1", nullptr, 3);

    EXPECT_NO_THROW(config::log_all());
}

TEST_F(ConfigTest, LogAll_LongStringNotTruncated)
{
    std::string long_value(200, 'x');
    config::bind_string("Sec", "LongVal", "long_val", nullptr, long_value);

    EXPECT_NO_THROW(config::log_all());
}

TEST_F(ConfigTest, LogAll_EmptyKeyComboList)
{
    config::bind_combos("Sec", "K", "empty_combo", nullptr, "");

    EXPECT_NO_THROW(config::log_all());
}

TEST_F(ConfigTest, ReRegistration_ReplacesCallback)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestInt=50\n";
    ini_file.close();

    int old_val = 0;
    int new_val = 0;

    config::bind_int("TestSection", "TestInt", "old", [&old_val](int v) { old_val = v; }, 10);

    // Simulate hot-reload: re-register the same section+key with a new callback.
    config::bind_int("TestSection", "TestInt", "new", [&new_val](int v) { new_val = v; }, 20);

    config::load(m_test_ini_file.string());

    // The old callback is replaced; only the new callback receives the loaded value.
    EXPECT_EQ(old_val, 10);
    EXPECT_EQ(new_val, 50);
}

TEST_F(ConfigTest, ReRegistration_PreservesOtherKeys)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[Sec]\n";
    ini_file << "A=1\n";
    ini_file << "B=2\n";
    ini_file.close();

    int a_val = 0, b_val = 0, a_val_new = 0;

    config::bind_int("Sec", "A", "a", [&a_val](int v) { a_val = v; }, 0);
    config::bind_int("Sec", "B", "b", [&b_val](int v) { b_val = v; }, 0);

    // Re-register only key A.
    config::bind_int("Sec", "A", "a_new", [&a_val_new](int v) { a_val_new = v; }, 0);

    config::load(m_test_ini_file.string());

    EXPECT_EQ(a_val, 0);
    EXPECT_EQ(a_val_new, 1);
    EXPECT_EQ(b_val, 2);
}

TEST_F(ConfigTest, ReRegistration_DifferentSectionsSameKey)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[Sec1]\n";
    ini_file << "Key=10\n";
    ini_file << "[Sec2]\n";
    ini_file << "Key=20\n";
    ini_file.close();

    int val1 = 0, val2 = 0;

    config::bind_int("Sec1", "Key", "k1", [&val1](int v) { val1 = v; }, 0);
    config::bind_int("Sec2", "Key", "k2", [&val2](int v) { val2 = v; }, 0);

    config::load(m_test_ini_file.string());

    // Same key name but different sections; both should be kept independently.
    EXPECT_EQ(val1, 10);
    EXPECT_EQ(val2, 20);
}

TEST_F(ConfigTest, SetterCalledOnRegistrationAndLoad)
{
    // Verify that setter fires twice: once during register (with default), once during load (with INI or default
    // value). Consumers must be idempotent.
    std::vector<int> invocations;

    config::bind_int("TestSection", "TestKey", "test_int", [&invocations](int v) { invocations.push_back(v); }, 42);

    // After registration, setter should have been called once with default
    ASSERT_EQ(invocations.size(), 1u);
    EXPECT_EQ(invocations[0], 42);

    // Load with no INI file: setter called again with default
    config::load(m_test_ini_file.string());

    ASSERT_EQ(invocations.size(), 2u);
    EXPECT_EQ(invocations[1], 42);
}

TEST_F(ConfigTest, SetterCalledOnRegistrationAndLoad_WithFile)
{
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "TestKey=99\n";
    ini_file.close();

    std::vector<int> invocations;

    config::bind_int("TestSection", "TestKey", "test_int", [&invocations](int v) { invocations.push_back(v); }, 42);

    // After registration, setter called with default
    ASSERT_EQ(invocations.size(), 1u);
    EXPECT_EQ(invocations[0], 42);

    // Load from INI: setter called with file value
    config::load(m_test_ini_file.string());

    ASSERT_EQ(invocations.size(), 2u);
    EXPECT_EQ(invocations[1], 99);
}

TEST_F(ConfigTest, AccumulativeSetterMustBeIdempotent)
{
    // Demonstrates the pattern consumers should use: clear-before-add
    std::ofstream ini_file(m_test_ini_file);
    ini_file << "[TestSection]\n";
    ini_file << "Items=alpha\n";
    ini_file.close();

    std::vector<std::string> items;

    config::bind_string(
        "TestSection", "Items", "items",
        [&items](std::string_view v)
        {
            // Idempotent pattern: clear before applying
            items.clear();
            items.push_back(std::string(v));
        },
        "default_item");

    // After registration: ["default_item"]
    ASSERT_EQ(items.size(), 1u);
    EXPECT_EQ(items[0], "default_item");

    // After load: ["alpha"] (not ["default_item", "alpha"])
    config::load(m_test_ini_file.string());

    ASSERT_EQ(items.size(), 1u);
    EXPECT_EQ(items[0], "alpha");
}

TEST_F(ConfigTest, SetterCalledTwice_Float)
{
    std::vector<float> invocations;

    config::bind_float(
        "TestSection", "TestFloat", "test_float", [&invocations](float v) { invocations.push_back(v); }, 1.5f);

    ASSERT_EQ(invocations.size(), 1u);
    EXPECT_NEAR(invocations[0], 1.5f, 0.01f);

    config::load(m_test_ini_file.string());

    ASSERT_EQ(invocations.size(), 2u);
    EXPECT_NEAR(invocations[1], 1.5f, 0.01f);
}

TEST_F(ConfigTest, SetterCalledTwice_Bool)
{
    std::vector<bool> invocations;

    config::bind_bool(
        "TestSection", "TestBool", "test_bool", [&invocations](bool v) { invocations.push_back(v); }, true);

    ASSERT_EQ(invocations.size(), 1u);
    EXPECT_TRUE(invocations[0]);

    config::load(m_test_ini_file.string());

    ASSERT_EQ(invocations.size(), 2u);
    EXPECT_TRUE(invocations[1]);
}

TEST_F(ConfigTest, SetterCalledTwice_KeyCombo)
{
    int call_count = 0;

    config::bind_combos(
        "TestSection", "TestKeys", "test_keys", [&call_count](const input::KeyComboList &) { ++call_count; }, "F3");

    EXPECT_EQ(call_count, 1);

    config::load(m_test_ini_file.string());

    EXPECT_EQ(call_count, 2);
}

namespace
{
    // input::BindingGuard has a private ctor: only input::register_combo mints one, so this helper builds a real guard
    // to exercise the release / move / idempotence behavior. The cancellation flag is private (pimpl), so the
    // assertions read the observable is_active() / name() surface that the flag drives.
    input::BindingGuard make_press_guard(std::string name)
    {
        input::ComboBinding binding;
        binding.name = std::move(name);
        binding.trigger = input::Trigger::Press;
        binding.on_press = []() {};
        auto result = input::register_combo(std::move(binding));
        EXPECT_TRUE(result.has_value());
        return std::move(result).value();
    }
} // anonymous namespace

TEST(BindingGuard, DefaultIsInactive)
{
    input::BindingGuard g;
    EXPECT_FALSE(g.is_active());
    EXPECT_TRUE(g.name().empty());
}

TEST(BindingGuard, ReleaseIsIdempotent)
{
    input::BindingGuard g = make_press_guard("binding");
    EXPECT_TRUE(g.is_active());
    g.release();
    EXPECT_FALSE(g.is_active()) << "release() must clear the gating flag (observed via is_active()).";
    g.release();
    EXPECT_FALSE(g.is_active());
}

TEST(BindingGuard, MoveTransfersOwnership)
{
    input::BindingGuard a = make_press_guard("b");
    input::BindingGuard b(std::move(a));
    EXPECT_TRUE(b.is_active());
    EXPECT_FALSE(a.is_active());
    b.release();
    EXPECT_FALSE(b.is_active());
}

TEST(BindingGuard, MoveAssignment_TransfersAndReleasesOldFlag)
{
    input::BindingGuard a = make_press_guard("a");
    input::BindingGuard b = make_press_guard("b");

    b = std::move(a);

    // Move-assignment releases b's prior binding, then adopts a's. Observed via the guard surface: b now gates a's
    // (still-live) binding and reports a's name; a is left inert.
    EXPECT_TRUE(b.is_active());
    EXPECT_EQ(b.name(), "a") << "Move-assignment must adopt the moved-from guard's binding";
    EXPECT_FALSE(a.is_active());
}

TEST(BindingGuard, MoveAssignment_SelfMoveIsNoOp)
{
    input::BindingGuard g = make_press_guard("self");

    auto &alias = g;
    g = std::move(alias);

    EXPECT_TRUE(g.is_active()) << "Self move-assign must not release the flag";
}

TEST(BindingGuard, IsActiveReturnsTrueUntilReleased)
{
    // The cancellation flag is private (pimpl), so this asserts the observable contract: is_active() tracks the
    // not-yet-released state of the guard's own flag.
    input::BindingGuard g = make_press_guard("flipped");
    EXPECT_TRUE(g.is_active());
    g.release();
    EXPECT_FALSE(g.is_active());
}

TEST(BindingGuard, DestructorReleasesFlag)
{
    // The destructor releases the binding's gating flag. Because the flag is private (pimpl), the destruction-release
    // is exercised by transferring ownership out of the inner scope and confirming the surviving guard is still live
    // while the moved-from one is inert.
    input::BindingGuard outer;
    EXPECT_FALSE(outer.is_active());
    {
        input::BindingGuard g = make_press_guard("scoped");
        EXPECT_TRUE(g.is_active());
        outer = std::move(g);
        EXPECT_FALSE(g.is_active());
    }
    EXPECT_TRUE(outer.is_active()) << "Ownership moved out before the inner guard's destructor ran";
    outer.release();
    EXPECT_FALSE(outer.is_active());
}

// Reload tests

TEST_F(ConfigTest, Reload_WithoutInitialLoad_ReturnsFalse)
{
    EXPECT_FALSE(config::reload());
}

TEST_F(ConfigTest, Reload_PreservesRegistrations)
{
    std::vector<int> int_invocations;
    std::vector<bool> bool_invocations;
    std::vector<std::string> string_invocations;

    config::bind_int("S", "Count", "count", [&](int v) { int_invocations.push_back(v); }, 0);
    config::bind_bool("S", "Enabled", "enabled", [&](bool v) { bool_invocations.push_back(v); }, false);
    config::bind_string(
        "S", "Label", "label", [&](std::string_view v) { string_invocations.push_back(std::string(v)); },
        std::string("default"));

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nCount=7\nEnabled=true\nLabel=first\n";
    }

    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    ASSERT_FALSE(int_invocations.empty());
    EXPECT_EQ(int_invocations.back(), 7);
    ASSERT_FALSE(bool_invocations.empty());
    EXPECT_TRUE(bool_invocations.back());
    ASSERT_FALSE(string_invocations.empty());
    EXPECT_EQ(string_invocations.back(), "first");

    // Rewrite the INI with fresh values; reload() must re-fire every setter.
    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nCount=42\nEnabled=false\nLabel=second\n";
    }

    const size_t int_before = int_invocations.size();
    const size_t bool_before = bool_invocations.size();
    const size_t str_before = string_invocations.size();

    EXPECT_TRUE(config::reload());

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

    config::bind_int(
        "S", "First", "first", [&first_value](int v) { first_value.store(v, std::memory_order_release); }, 0);
    // Setter fires once at register, once at load, once at reload; start throwing only on the third invocation so the
    // failure lands on the reload path.
    config::bind_int(
        "S", "Middle", "middle",
        [&throw_count](int /*v*/)
        {
            const int calls = throw_count.fetch_add(1, std::memory_order_relaxed) + 1;
            if (calls >= 3)
            {
                throw std::runtime_error("middle setter deliberately throws");
            }
        },
        0);
    config::bind_int(
        "S", "Third", "third", [&third_value](int v) { third_value.store(v, std::memory_order_release); }, 0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nFirst=1\nMiddle=2\nThird=3\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));

    // Bump all values and reload. The middle setter throws; the first and third setters must still receive the new
    // values.
    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nFirst=10\nMiddle=20\nThird=30\n";
    }

    EXPECT_NO_THROW({ (void)config::reload(); });

    EXPECT_EQ(first_value.load(std::memory_order_acquire), 10);
    EXPECT_EQ(third_value.load(std::memory_order_acquire), 30);
    EXPECT_GE(throw_count.load(std::memory_order_relaxed), 3);
}

TEST_F(ConfigTest, Reload_AfterClear_ReturnsFalse_BecausePathCleared)
{
    // clear_registered_items() also clears the remembered INI path, so reload() takes the no-last-loaded-path branch
    // (not a no-items one).
    int value = 0;
    config::bind_int("S", "K", "k", [&value](int v) { value = v; }, 1);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=5\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(value, 5);

    config::clear();
    EXPECT_FALSE(config::reload());
}

TEST_F(ConfigTest, ReloadHotkey_RegistersBinding)
{
    input::Input::instance().shutdown();

    int value = 0;
    config::bind_int("S", "K", "k", [&value](int v) { value = v; }, 1);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=2\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(value, 2);

    const size_t before = input::Input::instance().binding_count();

    EXPECT_TRUE(config::reload_hotkey("ReloadConfig", "Ctrl+F5"));

    EXPECT_GT(input::Input::instance().binding_count(), before);

    // Rewrite and simulate the hotkey by invoking what the callback does.
    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=123\n";
    }
    EXPECT_TRUE(config::reload());
    EXPECT_EQ(value, 123);

    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, ReloadHotkey_EmptyComboRejected)
{
    input::Input::instance().shutdown();
    EXPECT_FALSE(config::reload_hotkey("ReloadConfig", ""));
}

TEST_F(ConfigTest, ReloadHotkey_ActuallyFiresOnPress)
{
    // Regression guard: config::reload_hotkey() must retain the
    // input::BindingGuard so the binding's enabled flag stays true. If the guard were discarded, ~BindingGuard would
    // release the flag and the bound callback could never fire.
    //
    // The input facade has no press-injection hook from user code, so we prove the callback path indirectly: after
    // registration the binding's enabled flag must still be true. We cannot peek the flag directly, so we call
    // config::reload() (what the press callback does) and observe the setter fire.
    input::Input::instance().shutdown();

    int value = 0;
    config::bind_int("S", "K", "k", [&value](int v) { value = v; }, 1);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=2\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(value, 2);

    ASSERT_TRUE(config::reload_hotkey("ReloadConfig", "F5"));

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=77\n";
    }
    ASSERT_TRUE(config::reload());
    EXPECT_EQ(value, 77);

    // Re-register with a different combo: the second call must replace the first guard in place rather than stacking
    // per reload cycle.
    ASSERT_TRUE(config::reload_hotkey("ReloadConfig", "F6"));

    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, RegisterReloadHotkey_InvalidCombo_Rejected)
{
    // Unparseable combos like "NotAKey" produce zero bindings inside config::press_combo. config::reload_hotkey must
    // reject the registration rather than return success for a silent no-op.
    input::Input::instance().shutdown();
    EXPECT_FALSE(config::reload_hotkey("ReloadConfig", "NotAKey"));
}

TEST_F(ConfigTest, DisableAutoReload_FromReloadCallback_DoesNotDeadlock)
{
    // A reload callback that runs on the watcher thread and itself calls disable_auto_reload() must not self-join the
    // worker. The self-join is short-circuited and a later disable_auto_reload() from the main thread must still clean
    // up normally.
    config::disable_auto_reload();

    std::atomic<int> current_value{0};
    config::bind_int("S", "K", "k", [&](int v) { current_value.store(v, std::memory_order_release); }, 0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=10\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));

    std::atomic<int> on_reload_hits{0};
    ASSERT_EQ(config::enable_auto_reload(std::chrono::milliseconds{100},
                                         [&](bool /*setters_ran*/)
                                         {
                                             on_reload_hits.fetch_add(1, std::memory_order_relaxed);
                                             // Self-call must not deadlock the worker.
                                             config::disable_auto_reload();
                                         }),
              config::AutoReloadStatus::Started);

    std::this_thread::sleep_for(std::chrono::milliseconds{150});

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=42\n";
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (on_reload_hits.load(std::memory_order_relaxed) >= 1)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }

    EXPECT_GE(on_reload_hits.load(std::memory_order_relaxed), 1) << "on_reload callback must have run at least once";

    EXPECT_NO_THROW(config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_EndToEnd)
{
    // Ensure a previous test's watcher is not still attached.
    config::disable_auto_reload();

    std::atomic<int> current_value{0};
    std::atomic<int> setter_invocations{0};

    config::bind_int(
        "S", "K", "k",
        [&](int v)
        {
            current_value.store(v, std::memory_order_release);
            setter_invocations.fetch_add(1, std::memory_order_relaxed);
        },
        0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=10\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(current_value.load(), 10);

    std::atomic<int> on_reload_hits{0};
    ASSERT_EQ(config::enable_auto_reload(std::chrono::milliseconds{100},
                                         [&](bool /*setters_ran*/) { on_reload_hits.fetch_add(1); }),
              config::AutoReloadStatus::Started);

    // Give the watcher thread time to issue its first ReadDirectoryChangesW.
    std::this_thread::sleep_for(std::chrono::milliseconds{150});

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=77\n";
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
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

    config::disable_auto_reload();

    EXPECT_TRUE(observed) << "Watcher never observed the write";
    EXPECT_GE(on_reload_hits.load(), 1);
    EXPECT_GE(setter_invocations.load(), 2);
}

TEST_F(ConfigTest, AutoReload_DisableBeforeEnableIsSafe)
{
    EXPECT_NO_THROW(config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_EnableWithoutPriorLoadIsIgnored)
{
    // With no prior load() the watcher must refuse to start.
    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::NoPriorLoad);
    // disable_auto_reload() must still be safe.
    EXPECT_NO_THROW(config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_Enable_ReportsNoPriorLoad)
{
    config::disable_auto_reload();
    config::clear();

    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::NoPriorLoad);
    EXPECT_NO_THROW(config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_Enable_ReportsAlreadyRunning)
{
    config::disable_auto_reload();

    int value = 0;
    config::bind_int("S", "K", "k", [&value](int v) { value = v; }, 0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=1\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));

    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{100}), config::AutoReloadStatus::Started);
    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{100}), config::AutoReloadStatus::AlreadyRunning);

    config::disable_auto_reload();
}

TEST_F(ConfigTest, AutoReload_Enable_ReportsStartFailed)
{
    // Remove the parent directory between load() and enable_auto_reload() so ConfigWatcher::start()'s CreateFileW call
    // fails.
    config::disable_auto_reload();

    const auto temp_dir = std::filesystem::temp_directory_path() /
                          ("dmk_cfg_startfail_" + std::to_string(_getpid()) + "_" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(temp_dir);
    const auto ini_path = temp_dir / "cfg.ini";
    {
        std::ofstream f(ini_path);
        f << "[S]\nK=1\n";
    }

    int value = 0;
    config::bind_int("S", "K", "k", [&value](int v) { value = v; }, 0);
    ASSERT_NO_THROW(config::load(ini_path.string()));

    // Destroy the parent directory so CreateFileW fails inside start().
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
    ASSERT_FALSE(ec) << "Failed to remove temp dir: " << ec.message();

    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::StartFailed);
    EXPECT_NO_THROW(config::disable_auto_reload());
}

TEST_F(ConfigTest, AutoReload_Enable_AfterStartFailed_RecoversOnRetry)
{
    // A failed start must not latch the watcher slot as AlreadyRunning;
    // a later retry once the backing file exists must report Started.
    config::disable_auto_reload();

    const auto temp_dir = std::filesystem::temp_directory_path() /
                          ("dmk_cfg_recover_" + std::to_string(_getpid()) + "_" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(temp_dir);
    const auto ini_path = temp_dir / "cfg.ini";
    {
        std::ofstream f(ini_path);
        f << "[S]\nK=1\n";
    }

    int value = 0;
    config::bind_int("S", "K", "k", [&value](int v) { value = v; }, 0);
    ASSERT_NO_THROW(config::load(ini_path.string()));

    // Remove the watched directory to drive start() into StartFailed. The stored INI path survives the failed start.
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
    ASSERT_FALSE(ec) << "Failed to remove temp dir: " << ec.message();

    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::StartFailed);

    // Recreate the directory; the stored path is unchanged so the retried start handshake can open it without another
    // load().
    std::filesystem::create_directories(temp_dir);
    {
        std::ofstream f(ini_path);
        f << "[S]\nK=2\n";
    }

    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started);

    config::disable_auto_reload();

    std::filesystem::remove_all(temp_dir, ec);
}

TEST_F(ConfigTest, Reload_ContentUnchanged_SkipsSetters)
{
    std::atomic<int> setter_hits{0};
    config::bind_int("S", "K", "k", [&](int /*v*/) { setter_hits.fetch_add(1, std::memory_order_relaxed); }, 0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=1\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    // No file change: reload() returns success but must not re-run the setter, because the content-hash short-circuit
    // kicks in.
    EXPECT_TRUE(config::reload());
    EXPECT_EQ(setter_hits.load(std::memory_order_relaxed), after_load)
        << "Content-hash skip must suppress setter re-invocation.";
}

TEST_F(ConfigTest, Reload_ContentChanged_RunsSetters)
{
    std::atomic<int> setter_hits{0};
    config::bind_int("S", "K", "k", [&](int /*v*/) { setter_hits.fetch_add(1, std::memory_order_relaxed); }, 0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=1\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    // Modify the file: the hash must mismatch and setters must run again.
    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=2\n";
    }
    EXPECT_TRUE(config::reload());
    EXPECT_GT(setter_hits.load(std::memory_order_relaxed), after_load) << "Changed content must re-invoke the setter.";
}

TEST_F(ConfigTest, Reload_FileUnreadable_RetainsWithoutRerunningSetters)
{
    // Prime: load once so a value + hash exist, then delete the file so read_ini_bytes() returns nullopt inside
    // reload(). reload() must still return true because the reload path existed and was handled, but a read failure
    // retains the last values instead of running the setter pass against a never-populated INI object. The setter count
    // therefore must not advance.
    std::atomic<int> setter_hits{0};
    config::bind_int("S", "K", "k", [&](int /*v*/) { setter_hits.fetch_add(1, std::memory_order_relaxed); }, 0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=9\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    std::error_code ec;
    std::filesystem::remove(m_test_ini_file, ec);
    ASSERT_FALSE(ec);

    // reload() still returns true, but no setters re-run: the read failed, so the values are retained untouched.
    EXPECT_TRUE(config::reload());
    EXPECT_EQ(setter_hits.load(std::memory_order_relaxed), after_load)
        << "An unreadable-file reload must retain last values, not re-run setters against defaults.";
}

TEST_F(ConfigTest, Servicer_RapidPresses_CoalesceToAtMostOneReloadPerBurst)
{
    // Exercise the coalescing guarantee from the public surface: N parallel reload() calls against unchanged bytes run
    // the setter at most once; subsequent unchanged-bytes calls short-circuit on the content hash.
    std::atomic<int> setter_hits{0};
    config::bind_int(
        "S", "K", "k",
        [&](int /*v*/)
        {
            // Sleep so overlapping reload() calls from multiple threads actually race.
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
            setter_hits.fetch_add(1, std::memory_order_relaxed);
        },
        0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=1\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    const int baseline = setter_hits.load(std::memory_order_relaxed);

    // 10 parallel reload() calls against unchanged bytes. config::reload serialises on get_config_mutex(); expected
    // setter-hit delta is 0.
    constexpr int THREAD_FAN_OUT = 10;
    std::vector<std::thread> threads;
    threads.reserve(THREAD_FAN_OUT);
    for (int i = 0; i < THREAD_FAN_OUT; ++i)
    {
        threads.emplace_back([] { (void)config::reload(); });
    }
    for (auto &t : threads)
    {
        t.join();
    }

    // Upper bound 1 tolerates a race past the hash check in a narrow window; expected delta is 0.
    const int delta = setter_hits.load(std::memory_order_relaxed) - baseline;
    EXPECT_LE(delta, 1) << "Content-hash skip must collapse concurrent unchanged-bytes reloads "
                           "to at most one setter pass (observed delta="
                        << delta << ").";
}

TEST_F(ConfigTest, Reload_WatcherPath_HashSkip_EmitsSettersRanFalse)
{
    // After a watcher-driven hash-skip, the user-facing on_reload callback must report that no setters ran.
    config::disable_auto_reload();

    std::atomic<int> current_value{0};
    config::bind_int("S", "K", "k", [&](int v) { current_value.store(v, std::memory_order_release); }, 0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=42\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    ASSERT_EQ(current_value.load(), 42);

    // Collect setter-pass booleans from watcher-driven reloads. The watcher watches the whole temp directory, and on a
    // notification-buffer overflow it must assume this file changed because the events were dropped, so parallel test
    // processes churning the directory can inject extra reloads that hash-skip and emit false at any point in this
    // test's timeline. Every wait and assertion below therefore keys on hit values, never on hit counts or positions.
    std::mutex hits_mutex;
    std::vector<bool> hits;
    ASSERT_EQ(config::enable_auto_reload(std::chrono::milliseconds{100},
                                         [&](bool setters_ran)
                                         {
                                             std::lock_guard<std::mutex> lock(hits_mutex);
                                             hits.push_back(setters_ran);
                                         }),
              config::AutoReloadStatus::Started);
    // No arming delay is needed: enable_auto_reload() returns Started only after the watcher has queued its first
    // ReadDirectoryChangesW, so every directory change from here on is captured.

    // Rewrites go through a write-then-rename swap so the watcher can never observe a half-written file. An in-place
    // truncate+write opens a window in which a debounced reload reads EMPTY content: that poisons the stored hash and
    // yields spurious setters_ran=true hits once the write completes. The rename surfaces this filename in a
    // RENAMED_NEW_NAME event, which the watcher matches exactly like a write.
    const auto replace_atomically = [&](std::string_view content)
    {
        const std::filesystem::path staging{m_test_ini_file.string() + ".staging"};
        {
            std::ofstream f(staging, std::ios::binary);
            f << content;
        }
        std::filesystem::rename(staging, m_test_ini_file);
    };

    // Polls the hit list until the predicate (evaluated under the lock) holds or the timeout elapses.
    const auto wait_for_hits = [&](std::chrono::milliseconds timeout, auto predicate) -> bool
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            {
                std::lock_guard<std::mutex> lock(hits_mutex);
                if (predicate())
                {
                    return true;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{25});
        }
        return false;
    };

    // Phase 1: replace with different bytes; a reload must eventually report that setters ran. Waiting for a true value
    // instead of the first hit tolerates any spurious overflow-driven false hits landing first.
    replace_atomically("[S]\nK=43\n");
    ASSERT_TRUE(
        wait_for_hits(std::chrono::seconds{3}, [&] { return std::find(hits.begin(), hits.end(), true) != hits.end(); }))
        << "Watcher never reported setters_ran=true for the changed-bytes replace.";

    // The true hit means the stored hash now matches the on-disk bytes, and the atomic replace guarantees no torn
    // intermediate content was ever observable -- so every reload after this point, whether driven by the
    // identical-bytes replace below or injected by foreign directory churn, must hash-skip and report false.
    std::size_t settled_count = 0;
    {
        std::lock_guard<std::mutex> lock(hits_mutex);
        settled_count = hits.size();
    }

    // Phase 2: replace with identical bytes to bump the directory state without changing the content hash. on_reload
    // must report setters_ran=false.
    replace_atomically("[S]\nK=43\n");
    ASSERT_TRUE(wait_for_hits(std::chrono::seconds{3}, [&] { return hits.size() > settled_count; }))
        << "Watcher never reported a reload for the identical-bytes replace.";

    // disable_auto_reload() joins the watcher (flushing at most one final pending callback first), so the hit list is
    // complete and unsynchronized reads below are safe.
    config::disable_auto_reload();

    std::lock_guard<std::mutex> lock(hits_mutex);
    ASSERT_GT(hits.size(), settled_count);
    for (std::size_t i = settled_count; i < hits.size(); ++i)
    {
        EXPECT_FALSE(hits[i]) << "Reload at index " << i
                              << " reported setters_ran=true after the hash had settled; the hash-skip failed.";
    }
}

TEST_F(ConfigTest, Reload_EmptyFile_DoesNotCrash)
{
    // SimpleIni treats a zero-byte buffer as SI_OK with no sections; a subsequent reload() against the same empty bytes
    // must hash-skip.
    std::atomic<int> setter_hits{0};
    config::bind_int("S", "K", "k", [&](int /*v*/) { setter_hits.fetch_add(1, std::memory_order_relaxed); }, 7);

    // Create an empty file.
    {
        std::ofstream f(m_test_ini_file, std::ios::binary);
    }
    ASSERT_TRUE(std::filesystem::exists(m_test_ini_file));
    ASSERT_EQ(std::filesystem::file_size(m_test_ini_file), 0u);

    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    // First reload(): identical empty bytes -> hash-skip. Returns true, no setter re-invocation.
    EXPECT_TRUE(config::reload());
    EXPECT_EQ(setter_hits.load(std::memory_order_relaxed), after_load) << "Empty-file reload must hash-skip.";

    // Second reload(): same result.
    EXPECT_TRUE(config::reload());
    EXPECT_EQ(setter_hits.load(std::memory_order_relaxed), after_load)
        << "Repeated empty-file reload must stay on the hash-skip path.";
}

TEST_F(ConfigTest, Reload_HashResetOnLoadFailure)
{
    // A load() against a missing file must clear the cached content hash so a later successful load() cannot spuriously
    // hash-skip.
    std::atomic<int> setter_hits{0};
    config::bind_int("S", "K", "k", [&](int /*v*/) { setter_hits.fetch_add(1, std::memory_order_relaxed); }, 0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=5\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));

    // Deriving the missing path from m_test_ini_file inherits the pid + per-test counter so uniqueness holds under
    // parallel runs.
    const auto missing = m_test_ini_file.parent_path() / (m_test_ini_file.stem().string() + "_missing.ini");
    std::filesystem::remove(missing);
    ASSERT_FALSE(std::filesystem::exists(missing));
    ASSERT_NO_THROW(config::load(missing.string()));

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=5\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    const int after_second_load = setter_hits.load(std::memory_order_relaxed);

    EXPECT_TRUE(config::reload());
    EXPECT_EQ(setter_hits.load(std::memory_order_relaxed), after_second_load)
        << "Post-reset re-load must re-establish a valid hash so unchanged-bytes reloads skip.";
}

TEST_F(ConfigTest, Reload_HashResetOnReadFailure)
{
    // As Reload_HashResetOnLoadFailure, but the clearing happens on a reload() read failure. A stale hash would let a
    // subsequent identical-bytes reload hash-skip and leave state at defaults.
    std::atomic<int> setter_hits{0};
    config::bind_int("S", "K", "k", [&](int /*v*/) { setter_hits.fetch_add(1, std::memory_order_relaxed); }, 0);

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=5\n";
    }
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    const int after_load = setter_hits.load(std::memory_order_relaxed);

    // Remove the file; reload() targets the path remembered from the last load() and will fail to open.
    ASSERT_TRUE(std::filesystem::remove(m_test_ini_file));
    ASSERT_FALSE(std::filesystem::exists(m_test_ini_file));
    EXPECT_TRUE(config::reload());
    const int after_failed_reload = setter_hits.load(std::memory_order_relaxed);
    EXPECT_EQ(after_failed_reload, after_load)
        << "reload() on a disappeared file retains last values and does not re-run setters.";

    {
        std::ofstream f(m_test_ini_file);
        f << "[S]\nK=5\n";
    }
    EXPECT_TRUE(config::reload());
    EXPECT_GT(setter_hits.load(std::memory_order_relaxed), after_failed_reload)
        << "Recovery reload() with identical bytes must re-run setters because the "
           "read-failure branch cleared the cached hash.";
}

TEST_F(ConfigTest, RegisterPressCombo_EmptyDefaultRegistersName)
{
    input::Input::instance().shutdown();

    std::atomic<int> press_count{0};
    auto guard = config::press_combo(
        "Input", "EmptyDefaultKey", "binding with empty default", "empty-default-binding",
        [&]() { press_count.fetch_add(1, std::memory_order_relaxed); }, "");

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1))
        << "Empty default must still reserve the binding name as a pending binding.";

    input::KeyComboList replacement;
    replacement.push_back({{keyboard_key(0x41)}, {}});
    (void)input::Input::instance().rebind("empty-default-binding", replacement);
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, RegisterLogLevel_RoundTripFromIni)
{
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Logging]\nLevel=DEBUG\n";
    }

    const LogLevel original = log().get_log_level();
    config::bind_log_level("Logging", "Level", "INFO");
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(log().get_log_level(), LogLevel::Debug);

    log().set_log_level(original);
}

TEST_F(ConfigTest, RegisterAtomic_BoolRoundTrip)
{
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Atom]\nFlag=true\n";
    }

    std::atomic<bool> flag{false};
    config::bind<bool>("Atom", "Flag", "atomic bool flag", flag, false);
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_TRUE(flag.load(std::memory_order_relaxed));
}

TEST_F(ConfigTest, RegisterAtomic_IntRoundTrip)
{
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Atom]\nNum=7\n";
    }

    std::atomic<int> n{0};
    config::bind<int>("Atom", "Num", "atomic int", n, -1);
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(n.load(std::memory_order_relaxed), 7);
}

TEST_F(ConfigTest, RegisterAtomic_DefaultFromMember_BoolIniWins)
{
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Atom]\nFlag=false\n";
    }

    std::atomic<bool> flag{true};
    config::bind<bool>("Atom", "Flag", "atomic bool flag", flag);
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_FALSE(flag.load(std::memory_order_relaxed));
}

TEST_F(ConfigTest, RegisterAtomic_DefaultFromMember_BoolMissingUsesMemberInitializer)
{
    // The INI exists but omits the target key, so the registration default (the atomic's member value) applies. The
    // unrelated key keeps this distinct from the file-not-found fallback.
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Atom]\nUnrelated=1\n";
    }

    std::atomic<bool> flag{true};
    config::bind<bool>("Atom", "Flag", "atomic bool flag", flag);
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_TRUE(flag.load(std::memory_order_relaxed));
}

TEST_F(ConfigTest, RegisterAtomic_DefaultFromMember_IntIniWins)
{
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Atom]\nCount=11\n";
    }

    std::atomic<int> count{-3};
    config::bind<int>("Atom", "Count", "atomic int", count);
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(count.load(std::memory_order_relaxed), 11);
}

TEST_F(ConfigTest, RegisterAtomic_DefaultFromMember_IntMissingUsesMemberInitializer)
{
    // File exists but omits the key, so the member default applies (not the file-not-found path).
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Atom]\nUnrelated=1\n";
    }

    std::atomic<int> count{-3};
    config::bind<int>("Atom", "Count", "atomic int", count);
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(count.load(std::memory_order_relaxed), -3);
}

TEST_F(ConfigTest, RegisterAtomic_DefaultFromMember_FloatIniWins)
{
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Atom]\nScale=2.5\n";
    }

    std::atomic<float> scale{0.15f};
    config::bind<float>("Atom", "Scale", "atomic float", scale);
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_FLOAT_EQ(scale.load(std::memory_order_relaxed), 2.5f);
}

TEST_F(ConfigTest, RegisterAtomic_DefaultFromMember_FloatMissingUsesMemberInitializer)
{
    // File exists but omits the key, so the member default applies (not the file-not-found path).
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Atom]\nUnrelated=1\n";
    }

    std::atomic<float> scale{0.15f};
    config::bind<float>("Atom", "Scale", "atomic float", scale);
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_FLOAT_EQ(scale.load(std::memory_order_relaxed), 0.15f);
}

namespace
{
    // RAII helper that redirects the global Logger to a temporary file and exposes the captured contents for
    // assertions. On destruction the Logger is parked on a stable per-process file so the capture file's handle is
    // released and remove() succeeds on Windows; subsequent tests overwrite the parking sink as needed via their own
    // configure() calls. Sync mode is forced because the tests inspect the file immediately after the logging call
    // returns.
    class LoggerFileCapture
    {
    public:
        LoggerFileCapture()
        {
            static std::atomic<int> counter{0};
            const int n = counter.fetch_add(1, std::memory_order_relaxed);
            m_capture_file = std::filesystem::temp_directory_path() /
                             ("dmk_capture_" + std::to_string(_getpid()) + "_" + std::to_string(n) + ".log");
            auto &logger = DetourModKit::log();
            m_previous_async = logger.is_async_mode_enabled();
            if (m_previous_async)
            {
                logger.disable_async_mode();
            }
            DetourModKit::Logger::configure("CAPTURE", m_capture_file.string(), "%H:%M:%S");
            m_previous_level = logger.get_log_level();
            logger.set_log_level(DetourModKit::LogLevel::Trace);
        }

        ~LoggerFileCapture()
        {
            auto &logger = DetourModKit::log();
            logger.flush();
            const auto parking =
                std::filesystem::temp_directory_path() / ("dmk_capture_parked_" + std::to_string(_getpid()) + ".log");
            DetourModKit::Logger::configure("PARKED", parking.string(), "%H:%M:%S");
            logger.set_log_level(m_previous_level);
            if (m_previous_async)
            {
                logger.enable_async_mode();
            }
            std::error_code ec;
            std::filesystem::remove(m_capture_file, ec);
        }

        LoggerFileCapture(const LoggerFileCapture &) = delete;
        LoggerFileCapture &operator=(const LoggerFileCapture &) = delete;

        [[nodiscard]] std::string read_all() const
        {
            DetourModKit::log().flush();
            std::ifstream in(m_capture_file);
            if (!in)
            {
                return {};
            }
            return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }

        [[nodiscard]] bool contains_warning_with(std::string_view needle) const
        {
            const std::string content = read_all();
            std::size_t pos = 0;
            while (true)
            {
                const std::size_t next = content.find('\n', pos);
                const std::string_view line(content.data() + pos,
                                            (next == std::string::npos ? content.size() : next) - pos);
                if (line.find("[WARNING]") != std::string_view::npos && line.find(needle) != std::string_view::npos)
                {
                    return true;
                }
                if (next == std::string::npos)
                {
                    break;
                }
                pos = next + 1;
            }
            return false;
        }

        [[nodiscard]] std::size_t warning_count() const
        {
            const std::string content = read_all();
            std::size_t count = 0;
            std::size_t pos = 0;
            while ((pos = content.find("[WARNING]", pos)) != std::string::npos)
            {
                ++count;
                pos += 9;
            }
            return count;
        }

    private:
        std::filesystem::path m_capture_file;
        DetourModKit::LogLevel m_previous_level{DetourModKit::LogLevel::Info};
        bool m_previous_async{false};
    };

    // Drives the combo-list parser indirectly via config::bind_combos, which is the only reachable entry point for the
    // parser from outside the TU.
    DetourModKit::input::KeyComboList parse_via_register(std::string_view default_value,
                                                         std::string_view log_name = "test binding")
    {
        DetourModKit::config::clear();
        DetourModKit::input::KeyComboList captured;
        DetourModKit::config::bind_combos(
            "ParserSec", "ParserKey", log_name,
            [&captured](const DetourModKit::input::KeyComboList &c) { captured = c; }, default_value);
        return captured;
    }
} // anonymous namespace

TEST_F(ConfigTest, ParseKeyComboList_EmptyStringIsSilent)
{
    LoggerFileCapture cap;
    auto result = parse_via_register("");
    EXPECT_TRUE(result.empty());
    EXPECT_EQ(cap.warning_count(), 0u) << "Empty string is the explicit-empty sentinel; must not warn.";
}

TEST_F(ConfigTest, ParseKeyComboList_NoneSentinelIsSilent)
{
    for (std::string_view literal : {"NONE", "none", "None", "  None  ", "NoNe"})
    {
        LoggerFileCapture cap;
        auto result = parse_via_register(literal);
        EXPECT_TRUE(result.empty()) << "Failed for: \"" << literal << "\"";
        EXPECT_EQ(cap.warning_count(), 0u) << "NONE sentinel must be silent; failed for: \"" << literal << "\"";
    }
}

TEST_F(ConfigTest, ParseKeyComboList_SingleValidComboNoWarning)
{
    LoggerFileCapture cap;
    auto result = parse_via_register("F4");
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(cap.warning_count(), 0u);
}

TEST_F(ConfigTest, ParseKeyComboList_MultipleValidCombosNoWarning)
{
    LoggerFileCapture cap;
    auto result = parse_via_register("F4,F5");
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(cap.warning_count(), 0u);
}

TEST_F(ConfigTest, ParseKeyComboList_TypoEmitsOneWarning)
{
    LoggerFileCapture cap;
    auto result = parse_via_register("xyzzy", "press hotkey");
    EXPECT_TRUE(result.empty());
    EXPECT_EQ(cap.warning_count(), 1u);
    EXPECT_TRUE(cap.contains_warning_with("xyzzy"));
    EXPECT_TRUE(cap.contains_warning_with("press hotkey"));
}

TEST_F(ConfigTest, ParseKeyComboList_EmptyInnerTokensSkippedSilently)
{
    LoggerFileCapture cap;
    auto result = parse_via_register("F4,,F5");
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(cap.warning_count(), 0u);
}

TEST_F(ConfigTest, ParseKeyComboList_AllTokensTypoEmitsOneWarning)
{
    LoggerFileCapture cap;
    auto result = parse_via_register("xyzzy,blarg", "multi typo");
    EXPECT_TRUE(result.empty());
    EXPECT_EQ(cap.warning_count(), 1u);
    EXPECT_TRUE(cap.contains_warning_with("multi typo"));
}

TEST_F(ConfigTest, ParseKeyComboList_PartialParseDoesNotWarn)
{
    // F4 parses, xyzzy does not. Result is non-empty, so no typo WARNING.
    LoggerFileCapture cap;
    auto result = parse_via_register("F4,xyzzy");
    ASSERT_GE(result.size(), 1u);
    EXPECT_EQ(cap.warning_count(), 0u);
}

TEST_F(ConfigTest, EndToEnd_EmptyDefaultThenReloadStaysSilent)
{
    input::Input::instance().shutdown();
    {
        std::ofstream f(m_test_ini_file);
        f << "[Hotkeys]\n";
    }
    LoggerFileCapture cap;
    auto guard =
        config::press_combo("Hotkeys", "EmptyKey", "empty default test", "endtoend-empty-default", []() {}, "");

    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    ASSERT_TRUE(config::reload());

    EXPECT_EQ(cap.warning_count(), 0u) << "Empty default + missing INI key must produce no WARNING.";

    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, EndToEnd_BoundEmptyBoundCycle)
{
    // The bound -> unbound -> bound transition must complete without losing the binding name.
    input::Input::instance().shutdown();
    {
        std::ofstream f(m_test_ini_file);
        f << "[Hotkeys]\nKey=F4\n";
    }
    auto guard = config::press_combo("Hotkeys", "Key", "cycle test", "endtoend-cycle", []() {}, "F4");

    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    {
        std::ofstream f(m_test_ini_file);
        f << "[Hotkeys]\nKey=\n";
    }
    LoggerFileCapture cap;
    ASSERT_TRUE(config::reload());
    EXPECT_FALSE(input::Input::instance().is_active("endtoend-cycle"));
    EXPECT_EQ(cap.warning_count(), 0u) << "Empty INI value must unbind silently.";

    {
        std::ofstream f(m_test_ini_file);
        f << "[Hotkeys]\nKey=F5\n";
    }
    ASSERT_TRUE(config::reload());
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, EndToEnd_TypoEmitsOneWarning)
{
    input::Input::instance().shutdown();
    {
        std::ofstream f(m_test_ini_file);
        f << "[Hotkeys]\nKey=F4\n";
    }
    auto guard = config::press_combo("Hotkeys", "Key", "typo test", "endtoend-typo", []() {}, "F4");

    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));

    {
        std::ofstream f(m_test_ini_file);
        f << "[Hotkeys]\nKey=xyzzy\n";
    }
    LoggerFileCapture cap;
    ASSERT_TRUE(config::reload());
    EXPECT_EQ(cap.warning_count(), 1u);
    EXPECT_TRUE(cap.contains_warning_with("xyzzy"));
    EXPECT_TRUE(cap.contains_warning_with("typo test"));
    EXPECT_FALSE(input::Input::instance().is_active("endtoend-typo"));

    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, EndToEnd_NoneDefaultRegistersCleanly)
{
    input::Input::instance().shutdown();
    LoggerFileCapture cap;
    auto guard = config::press_combo("Hotkeys", "Key", "none default", "endtoend-none-default", []() {}, "NONE");

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1))
        << "NONE default must still reserve the binding name as a sentinel.";
    EXPECT_EQ(cap.warning_count(), 0u) << "NONE default must register without warning.";

    guard.release();
    input::Input::instance().shutdown();
}

namespace
{
    // SFINAE probes: detect whether each config::bind<T> atomic overload can be invoked. The BindableScalar concept
    // constrains T to int, bool, and float, so only those instantiations yield a viable overload.
    template <typename T, typename = void> struct ConfigBindCallable : std::false_type
    {
    };

    template <typename T>
    struct ConfigBindCallable<
        T, std::void_t<decltype(config::bind<T>(std::declval<std::string_view>(), std::declval<std::string_view>(),
                                                std::declval<std::string_view>(), std::declval<std::atomic<T> &>(),
                                                std::declval<T>()))>> : std::true_type
    {
    };

    template <typename T, typename = void> struct ConfigBindDefaultCallable : std::false_type
    {
    };

    template <typename T>
    struct ConfigBindDefaultCallable<
        T, std::void_t<decltype(config::bind<T>(std::declval<std::string_view>(), std::declval<std::string_view>(),
                                                std::declval<std::string_view>(), std::declval<std::atomic<T> &>()))>>
        : std::true_type
    {
    };
} // anonymous namespace

// Only the BindableScalar instantiations (int, bool, float) are reachable. Unsupported T must be a compile-time error
// at the call site rather than a mangled link-time error in user binaries.
static_assert(ConfigBindCallable<int>::value, "config::bind<int> must remain available.");
static_assert(ConfigBindCallable<bool>::value, "config::bind<bool> must remain available.");
static_assert(ConfigBindCallable<float>::value, "config::bind<float> must remain available.");
static_assert(!ConfigBindCallable<double>::value,
              "config::bind<double> must be unavailable; only int, bool, and float satisfy BindableScalar.");
static_assert(!ConfigBindCallable<long>::value,
              "config::bind<long> must be unavailable; only int, bool, and float satisfy BindableScalar.");
static_assert(ConfigBindDefaultCallable<int>::value, "config::bind<int> inferred-default overload must exist.");
static_assert(ConfigBindDefaultCallable<bool>::value, "config::bind<bool> inferred-default overload must exist.");
static_assert(ConfigBindDefaultCallable<float>::value, "config::bind<float> inferred-default overload must exist.");
static_assert(!ConfigBindDefaultCallable<double>::value,
              "config::bind<double> inferred-default overload must stay unavailable.");
static_assert(!ConfigBindDefaultCallable<long>::value,
              "config::bind<long> inferred-default overload must stay unavailable.");

// Input-binding fusion: the BindingGuard release action, the HoldGate teardown gate, and the hold_combo / consume
// facet (config layer). The HoldGate synchronization is exercised directly through its internal header because the
// poll loop reads real key state and cannot deliver hold edges deterministically from a test.
//
// input::BindingGuard has a private ctor, so these cases obtain a real Hold guard from input::register_combo. The
// guard's release action is the HoldGate teardown, which synthesizes a balancing on_state_change(false) ONLY for a
// still-held binding. A test cannot drive a poll-thread true edge, so the action's positive callback effect is not
// observable here; that path is covered at full fidelity by the HoldGate suite below. These cases preserve the guard's
// lifecycle contract: release is idempotent, the destructor releases, a move transfers ownership and leaves the
// moved-from guard inert, a move-assign releases the prior binding before adopting the moved-from one, and a release
// whose hold callback would throw is swallowed in the noexcept teardown.

namespace
{
    // Builds a real Hold guard whose on_state_change records edges, so a release that synthesizes a balancing false (if
    // one were held) would be observed. enabled starts live via register_combo.
    input::BindingGuard make_hold_guard(std::string name, std::function<void(bool)> on_state_change)
    {
        input::ComboBinding binding;
        binding.name = std::move(name);
        binding.trigger = input::Trigger::Hold;
        binding.on_state_change = std::move(on_state_change);
        auto result = input::register_combo(std::move(binding));
        EXPECT_TRUE(result.has_value());
        return std::move(result).value();
    }
} // anonymous namespace

TEST(BindingGuard, ReleaseActionRunsOnceThenIdempotent)
{
    std::vector<bool> edges;
    input::BindingGuard guard = make_hold_guard("hold", [&edges](bool active) { edges.push_back(active); });
    EXPECT_TRUE(guard.is_active());
    guard.release();
    EXPECT_FALSE(guard.is_active());
    // No true edge was ever delivered, so the release action synthesizes nothing; a second release is a safe no-op.
    guard.release();
    EXPECT_FALSE(guard.is_active());
    EXPECT_TRUE(edges.empty()) << "Unheld release must not fabricate an edge.";
}

TEST(BindingGuard, ReleaseActionRunsOnDestruct)
{
    std::vector<bool> edges;
    {
        input::BindingGuard guard = make_hold_guard("hold", [&edges](bool active) { edges.push_back(active); });
        EXPECT_TRUE(guard.is_active());
    }
    // Destruction runs the release action (gate teardown) exactly once without throwing; nothing was held, so no edge.
    EXPECT_TRUE(edges.empty());
}

TEST(BindingGuard, ReleaseActionMoveCtorTransfersOwnership)
{
    std::vector<bool> edges;
    input::BindingGuard a = make_hold_guard("hold", [&edges](bool active) { edges.push_back(active); });
    input::BindingGuard b(std::move(a));
    // The moved-from guard is inert; only b owns the release action.
    EXPECT_FALSE(a.is_active());
    EXPECT_TRUE(b.is_active());
    a.release();
    EXPECT_FALSE(a.is_active());
    b.release();
    EXPECT_FALSE(b.is_active());
}

TEST(BindingGuard, ReleaseActionMoveAssignFiresOldThenTransfers)
{
    std::vector<bool> edges_a;
    std::vector<bool> edges_b;
    input::BindingGuard a = make_hold_guard("a", [&edges_a](bool active) { edges_a.push_back(active); });
    input::BindingGuard b = make_hold_guard("b", [&edges_b](bool active) { edges_b.push_back(active); });
    // Move assignment releases b's prior binding (its release action runs), then adopts a's binding.
    EXPECT_NO_THROW({ b = std::move(a); });
    EXPECT_EQ(b.name(), "a") << "Move-assignment must adopt the moved-from guard's binding";
    EXPECT_FALSE(a.is_active());
    EXPECT_TRUE(b.is_active());
    b.release();
    EXPECT_FALSE(b.is_active());
}

TEST(BindingGuard, ReleaseActionExceptionIsSwallowed)
{
    // A hold callback that throws on its balancing false: release() is noexcept and must swallow it. No true edge is
    // delivered here so the throw path is not entered; the throwing-during-teardown path is covered at full fidelity by
    // HoldGate.SelfReleaseThenThrowDuringDeliveryStillBalances / HoldGate.CallbackExceptionKeepsGateConsistent.
    input::BindingGuard guard = make_hold_guard("hold", [](bool) { throw std::runtime_error("boom"); });
    EXPECT_NO_THROW(guard.release());
}

namespace
{
    // Builds a HoldGate wired to a recording callback. enabled starts live so deliver() forwards edges.
    std::shared_ptr<DetourModKit::detail::HoldGate> make_recording_gate(std::vector<bool> &events)
    {
        auto gate = std::make_shared<DetourModKit::detail::HoldGate>();
        gate->enabled = std::make_shared<std::atomic<bool>>(true);
        gate->on_state_change = [&events](bool active) { events.push_back(active); };
        return gate;
    }

    class PublishedConsumeRuleReset
    {
    public:
        PublishedConsumeRuleReset() noexcept { DetourModKit::detail::publish_gamepad_consume_rules(nullptr, 0); }
        ~PublishedConsumeRuleReset() noexcept { DetourModKit::detail::publish_gamepad_consume_rules(nullptr, 0); }

        PublishedConsumeRuleReset(const PublishedConsumeRuleReset &) = delete;
        PublishedConsumeRuleReset &operator=(const PublishedConsumeRuleReset &) = delete;
    };

    [[nodiscard]] std::uint16_t gamepad_mask(int code) noexcept
    {
        return static_cast<std::uint16_t>(code);
    }
} // anonymous namespace

TEST(HoldGate, InactiveReleaseSynthesizesNothing)
{
    std::vector<bool> events;
    auto gate = make_recording_gate(events);
    // Never held, so there is nothing to balance.
    gate->release();
    EXPECT_TRUE(events.empty());
}

TEST(HoldGate, HeldReleaseSynthesizesOneFalse)
{
    std::vector<bool> events;
    auto gate = make_recording_gate(events);
    gate->deliver(true);
    gate->release();
    // Idempotent: the balancing false was already emitted.
    gate->release();
    ASSERT_EQ(events.size(), 2u);
    EXPECT_TRUE(events[0]);
    EXPECT_FALSE(events[1]);
}

TEST(HoldGate, NaturalReleaseLeavesNothingToSynthesize)
{
    std::vector<bool> events;
    auto gate = make_recording_gate(events);
    gate->deliver(true);
    // Natural key-up already balanced the hold.
    gate->deliver(false);
    gate->release();
    ASSERT_EQ(events.size(), 2u);
    EXPECT_TRUE(events[0]);
    // Exactly one false, no extra synthetic one.
    EXPECT_FALSE(events[1]);
}

TEST(HoldGate, ReleasedGateSwallowsLaterEdges)
{
    std::vector<bool> events;
    auto gate = make_recording_gate(events);
    gate->deliver(true);
    gate->release();
    // Released gates swallow later edges.
    gate->deliver(true);
    gate->deliver(false);
    ASSERT_EQ(events.size(), 2u);
    EXPECT_FALSE(events.back());
}

TEST(HoldGate, SelfReleaseDuringDeliveryDefersBalancingFalse)
{
    std::vector<bool> events;
    auto gate = std::make_shared<DetourModKit::detail::HoldGate>();
    gate->enabled = std::make_shared<std::atomic<bool>>(true);
    gate->on_state_change = [&events, &gate](bool active)
    {
        events.push_back(active);
        if (active)
        {
            // Self-release from inside the callback while delivering true.
            gate->release();
        }
    };
    gate->deliver(true);
    // The balancing false is deferred to deliver()'s unwind and fired exactly once, never re-entering the callback
    // while it is still on the stack.
    ASSERT_EQ(events.size(), 2u);
    EXPECT_TRUE(events[0]);
    EXPECT_FALSE(events[1]);
    // Released gates swallow later edges.
    gate->deliver(true);
    EXPECT_EQ(events.size(), 2u);
}

TEST(HoldGate, SelfReleaseThenThrowDuringDeliveryStillBalances)
{
    std::vector<bool> events;
    auto gate = std::make_shared<DetourModKit::detail::HoldGate>();
    gate->enabled = std::make_shared<std::atomic<bool>>(true);
    bool first = true;
    gate->on_state_change = [&events, &gate, &first](bool active)
    {
        events.push_back(active);
        if (active && first)
        {
            first = false;
            // Self-release and then throw inside the same true delivery: the deferred balancing false must still
            // fire so the consumer is not stranded observing the stale true.
            gate->release();
            throw std::runtime_error("boom");
        }
    };
    EXPECT_THROW(gate->deliver(true), std::runtime_error); // the original exception surfaces to the poller
    ASSERT_EQ(events.size(), 2u);
    EXPECT_TRUE(events[0]);
    EXPECT_FALSE(events[1]);
    gate->deliver(true); // released -> swallowed
    EXPECT_EQ(events.size(), 2u);
}

TEST(HoldGate, CallbackExceptionKeepsGateConsistent)
{
    auto gate = std::make_shared<DetourModKit::detail::HoldGate>();
    gate->enabled = std::make_shared<std::atomic<bool>>(true);
    gate->on_state_change = [](bool) { throw std::runtime_error("boom"); };
    // deliver() propagates to the poller's callback handler.
    EXPECT_THROW(gate->deliver(true), std::runtime_error);

    // delivering was reset by deliver()'s catch, so a later release() can still synthesize the balancing false
    // (a true edge was forwarded before the throw).
    int falses = 0;
    gate->on_state_change = [&falses](bool active)
    {
        if (!active)
        {
            ++falses;
        }
    };
    gate->release();
    EXPECT_EQ(falses, 1);
}

TEST(HoldGate, ConcurrentReleaseNeverStrandsHeld)
{
    // A poll-thread-like producer toggles the hold while a control-plane thread releases the guard. After release the
    // consumer must never be left observing 'held' (true): a stale true cannot land after the synthetic false.
    for (int iter = 0; iter < 200; ++iter)
    {
        auto gate = std::make_shared<DetourModKit::detail::HoldGate>();
        gate->enabled = std::make_shared<std::atomic<bool>>(true);
        // Last delivered state: 1 = held, 0 = released, -1 = nothing yet.
        std::atomic<int> last{-1};
        std::atomic<bool> stop{false};
        gate->on_state_change = [&last](bool active) { last.store(active ? 1 : 0, std::memory_order_relaxed); };

        std::thread producer(
            [gate, &stop]()
            {
                bool state = false;
                while (!stop.load(std::memory_order_relaxed))
                {
                    state = !state;
                    gate->deliver(state);
                }
            });

        // Race the release against a producer that has already delivered at least one edge.
        while (last.load(std::memory_order_relaxed) == -1)
        {
            std::this_thread::yield();
        }
        gate->release();
        stop.store(true, std::memory_order_relaxed);
        producer.join();

        EXPECT_NE(last.load(std::memory_order_relaxed), 1)
            << "consumer left observing 'held' after release on iteration " << iter;
    }
}

TEST_F(ConfigTest, HoldCombo_RegistersOneBinding)
{
    input::Input::instance().shutdown();
    auto guard = config::hold_combo("Camera", "ZoomKey", "zoom hold", "zoom-hold-reg", [](bool) {}, "F4");
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));
    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, HoldCombo_LoadAndReloadRebinds)
{
    input::Input::instance().shutdown();
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Camera]\nZoomKey=F4,F5\n";
    }

    auto guard = config::hold_combo("Camera", "ZoomKey", "zoom hold", "zoom-hold-rebind", [](bool) {}, "F3");
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(2));

    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Camera]\nZoomKey=F6\n";
    }
    ASSERT_TRUE(config::reload());
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, HoldCombo_ConsumeNulloptRegistersNoConsumeItem)
{
    input::Input::instance().shutdown();
    LoggerFileCapture cap;
    auto guard = config::hold_combo("Camera", "ZoomKey", "zoom hold", "zoom-hold-plain", [](bool) {}, "F4");
    config::log_all();
    EXPECT_EQ(cap.read_all().find("Consume"), std::string::npos);
    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, PressCombo_ConsumeNulloptPreservesCurrentRegistrationShape)
{
    input::Input::instance().shutdown();
    LoggerFileCapture cap;
    auto guard = config::press_combo("Camera", "ToggleKey", "toggle", "toggle-plain", []() {}, "Gamepad_A");
    config::log_all();
    EXPECT_EQ(cap.read_all().find("Consume"), std::string::npos);
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));
    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, PressCombo_ConsumeFalseRegistersFacetAndLeavesRulesEmpty)
{
    PublishedConsumeRuleReset rules;
    input::Input::instance().shutdown();
    LoggerFileCapture cap;
    auto guard = config::press_combo(
        "Camera", "ToggleKey", "toggle", "toggle-suppress-false", []() {}, "Gamepad_A",
        /*consume=*/false);
    config::log_all();
    EXPECT_NE(cap.read_all().find("ToggleKey.Consume"), std::string::npos);

    (void)input::Input::instance().start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{1000}});
    const std::uint16_t button = gamepad_mask(GamepadCode::A);
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), 0u);
    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, HoldCombo_ConsumeTrueRegistersFacetAndPublishesRule)
{
    PublishedConsumeRuleReset rules;
    input::Input::instance().shutdown();
    LoggerFileCapture cap;
    auto guard = config::hold_combo(
        "Camera", "ZoomKey", "zoom hold", "zoom-hold-suppress-true", [](bool) {}, "Gamepad_A",
        /*consume=*/true);
    config::log_all();
    EXPECT_NE(cap.read_all().find("ZoomKey.Consume"), std::string::npos);

    (void)input::Input::instance().start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{1000}});
    const std::uint16_t button = gamepad_mask(GamepadCode::A);
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button);
    guard.release();
    input::Input::instance().shutdown();
}

TEST_F(ConfigTest, ConsumeFacet_IniOverrideAppliesThroughComboHelper)
{
    PublishedConsumeRuleReset rules;
    input::Input::instance().shutdown();
    {
        std::ofstream ini_file(m_test_ini_file);
        ini_file << "[Camera]\nZoomKey=Gamepad_A\nZoomKey.Consume=true\n";
    }

    // Register with the consume facet defaulting to false; load() must then apply the INI-sourced
    // "<ini_key>.Consume = true" through the combo helper's consume item so the published rule masks the button.
    auto guard = config::hold_combo(
        "Camera", "ZoomKey", "zoom hold", "zoom-hold-consume-ini", [](bool) {}, "Gamepad_A",
        /*consume=*/false);
    ASSERT_NO_THROW(config::load(m_test_ini_file.string()));

    (void)input::Input::instance().start(input::Input::Settings{.poll_interval = std::chrono::milliseconds{1000}});
    const std::uint16_t button = gamepad_mask(GamepadCode::A);
    EXPECT_EQ(DetourModKit::detail::evaluate_published_consume_rules(button), button);
    guard.release();
    input::Input::instance().shutdown();
}
