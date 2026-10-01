#include <gtest/gtest.h>
#include <clocale>
#include <string>
#include <unordered_set>

#include "DetourModKit/input.hpp"
#include "DetourModKit/config.hpp"

using namespace DetourModKit;
using DetourModKit::gamepad_button;
using DetourModKit::keyboard_key;

// InputSource string conversion

TEST(InputSourceTest, KeyboardToString)
{
    EXPECT_EQ(input_source_to_string(InputSource::Keyboard), "Keyboard");
}

TEST(InputSourceTest, MouseToString)
{
    EXPECT_EQ(input_source_to_string(InputSource::Mouse), "Mouse");
}

TEST(InputSourceTest, GamepadToString)
{
    EXPECT_EQ(input_source_to_string(InputSource::Gamepad), "Gamepad");
}

TEST(InputSourceTest, MouseWheelToString)
{
    EXPECT_EQ(input_source_to_string(InputSource::MouseWheel), "MouseWheel");
}

// InputCode

TEST(InputCodeTest, DefaultConstruction)
{
    InputCode code;
    EXPECT_EQ(code.source, InputSource::Keyboard);
    EXPECT_EQ(code.code, 0);
}

TEST(InputCodeTest, Equality)
{
    EXPECT_EQ(keyboard_key(0x41), keyboard_key(0x41));
    EXPECT_NE(keyboard_key(0x41), keyboard_key(0x42));
    EXPECT_NE(keyboard_key(0x41), mouse_button(0x41));
    EXPECT_NE(keyboard_key(0x41), gamepad_button(0x41));
}

TEST(InputCodeTest, FactoryFunctions)
{
    auto kb = keyboard_key(0x41);
    EXPECT_EQ(kb.source, InputSource::Keyboard);
    EXPECT_EQ(kb.code, 0x41);

    auto mouse = mouse_button(0x05);
    EXPECT_EQ(mouse.source, InputSource::Mouse);
    EXPECT_EQ(mouse.code, 0x05);

    auto gp = gamepad_button(GamepadCode::A);
    EXPECT_EQ(gp.source, InputSource::Gamepad);
    EXPECT_EQ(gp.code, GamepadCode::A);

    auto wheel = mouse_wheel(WheelCode::Up);
    EXPECT_EQ(wheel.source, InputSource::MouseWheel);
    EXPECT_EQ(wheel.code, WheelCode::Up);
}

// Both public spellings of every input-code constant name one value (input_codes.hpp file contract).
TEST(InputCodeTest, UpperSnakeSpellingsNameTheSameValues)
{
    static_assert(GamepadCode::DPAD_UP == GamepadCode::DpadUp);
    static_assert(GamepadCode::DPAD_DOWN == GamepadCode::DpadDown);
    static_assert(GamepadCode::DPAD_LEFT == GamepadCode::DpadLeft);
    static_assert(GamepadCode::DPAD_RIGHT == GamepadCode::DpadRight);
    static_assert(GamepadCode::START == GamepadCode::Start);
    static_assert(GamepadCode::BACK == GamepadCode::Back);
    static_assert(GamepadCode::LEFT_STICK == GamepadCode::LeftStick);
    static_assert(GamepadCode::RIGHT_STICK == GamepadCode::RightStick);
    static_assert(GamepadCode::LEFT_BUMPER == GamepadCode::LeftBumper);
    static_assert(GamepadCode::RIGHT_BUMPER == GamepadCode::RightBumper);
    static_assert(GamepadCode::LEFT_TRIGGER == GamepadCode::LeftTrigger);
    static_assert(GamepadCode::RIGHT_TRIGGER == GamepadCode::RightTrigger);
    static_assert(GamepadCode::LEFT_STICK_UP == GamepadCode::LeftStickUp);
    static_assert(GamepadCode::LEFT_STICK_DOWN == GamepadCode::LeftStickDown);
    static_assert(GamepadCode::LEFT_STICK_LEFT == GamepadCode::LeftStickLeft);
    static_assert(GamepadCode::LEFT_STICK_RIGHT == GamepadCode::LeftStickRight);
    static_assert(GamepadCode::RIGHT_STICK_UP == GamepadCode::RightStickUp);
    static_assert(GamepadCode::RIGHT_STICK_DOWN == GamepadCode::RightStickDown);
    static_assert(GamepadCode::RIGHT_STICK_LEFT == GamepadCode::RightStickLeft);
    static_assert(GamepadCode::RIGHT_STICK_RIGHT == GamepadCode::RightStickRight);
    static_assert(GamepadCode::TRIGGER_THRESHOLD == GamepadCode::TriggerThreshold);
    static_assert(GamepadCode::STICK_THRESHOLD == GamepadCode::StickThreshold);
    static_assert(WheelCode::UP == WheelCode::Up);
    static_assert(WheelCode::DOWN == WheelCode::Down);
    static_assert(WheelCode::LEFT == WheelCode::Left);
    static_assert(WheelCode::RIGHT == WheelCode::Right);

    // A runtime witness so the case reports through ctest rather than only at compile time.
    EXPECT_EQ(gamepad_button(GamepadCode::DPAD_UP), gamepad_button(GamepadCode::DpadUp));
    EXPECT_EQ(mouse_wheel(WheelCode::UP), mouse_wheel(WheelCode::Up));
}

// Mouse-wheel name resolution

TEST(WheelNameTest, ParseWheelNames)
{
    EXPECT_EQ(parse_input_name("WheelUp"), mouse_wheel(WheelCode::Up));
    EXPECT_EQ(parse_input_name("WheelDown"), mouse_wheel(WheelCode::Down));
    EXPECT_EQ(parse_input_name("WheelLeft"), mouse_wheel(WheelCode::Left));
    EXPECT_EQ(parse_input_name("WheelRight"), mouse_wheel(WheelCode::Right));
}

TEST(WheelNameTest, ParseWheelNamesCaseInsensitive)
{
    EXPECT_EQ(parse_input_name("wheelup"), mouse_wheel(WheelCode::Up));
    EXPECT_EQ(parse_input_name("WHEELDOWN"), mouse_wheel(WheelCode::Down));
}

TEST(WheelNameTest, FormatWheelNames)
{
    EXPECT_EQ(format_input_code(mouse_wheel(WheelCode::Up)), "WheelUp");
    EXPECT_EQ(format_input_code(mouse_wheel(WheelCode::Down)), "WheelDown");
    EXPECT_EQ(format_input_code(mouse_wheel(WheelCode::Left)), "WheelLeft");
    EXPECT_EQ(format_input_code(mouse_wheel(WheelCode::Right)), "WheelRight");
}

// Trigger string conversion

TEST(TriggerTest, PressToString)
{
    EXPECT_EQ(input::to_string(input::Trigger::Press), "Press");
}

TEST(TriggerTest, HoldToString)
{
    EXPECT_EQ(input::to_string(input::Trigger::Hold), "Hold");
}

// The Turkish locale can distinguish locale-sensitive case folds from the ASCII table. If that locale is absent, the
// same pairs still pass under C.
TEST(InputCodeNameTest, NameResolutionIsLocaleIndependentAsciiFold)
{
    const char *saved = std::setlocale(LC_ALL, nullptr);
    const std::string saved_copy = saved ? saved : "C";
    (void)(std::setlocale(LC_ALL, "tr-TR") || std::setlocale(LC_ALL, "tr_TR.UTF-8") ||
           std::setlocale(LC_ALL, "Turkish"));

    const auto upper = DetourModKit::parse_input_name("I");
    const auto lower = DetourModKit::parse_input_name("i");
    const auto mixed = DetourModKit::parse_input_name("InSeRt");
    const auto plain = DetourModKit::parse_input_name("insert");

    std::setlocale(LC_ALL, saved_copy.c_str());

    ASSERT_TRUE(upper.has_value());
    ASSERT_TRUE(lower.has_value());
    EXPECT_EQ(upper, lower) << "ASCII 'I'/'i' must fold together regardless of the active C locale";
    ASSERT_TRUE(mixed.has_value());
    ASSERT_TRUE(plain.has_value());
    EXPECT_EQ(mixed, plain);
}

// InputCode: Name Resolution

TEST(InputCodeNameTest, ParseKeyboardNames)
{
    auto ctrl = parse_input_name("Ctrl");
    ASSERT_TRUE(ctrl.has_value());
    EXPECT_EQ(ctrl->source, InputSource::Keyboard);
    EXPECT_EQ(ctrl->code, 0x11);

    auto f3 = parse_input_name("F3");
    ASSERT_TRUE(f3.has_value());
    EXPECT_EQ(f3->source, InputSource::Keyboard);
    EXPECT_EQ(f3->code, 0x72);

    auto a = parse_input_name("A");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->source, InputSource::Keyboard);
    EXPECT_EQ(a->code, 0x41);
}

TEST(InputCodeNameTest, ParseMouseNames)
{
    auto m4 = parse_input_name("Mouse4");
    ASSERT_TRUE(m4.has_value());
    EXPECT_EQ(m4->source, InputSource::Mouse);
    EXPECT_EQ(m4->code, 0x05);

    auto m1 = parse_input_name("Mouse1");
    ASSERT_TRUE(m1.has_value());
    EXPECT_EQ(m1->source, InputSource::Mouse);
    EXPECT_EQ(m1->code, 0x01);
}

TEST(InputCodeNameTest, ParseGamepadNames)
{
    auto ga = parse_input_name("Gamepad_A");
    ASSERT_TRUE(ga.has_value());
    EXPECT_EQ(ga->source, InputSource::Gamepad);
    EXPECT_EQ(ga->code, GamepadCode::A);

    auto lb = parse_input_name("Gamepad_LB");
    ASSERT_TRUE(lb.has_value());
    EXPECT_EQ(lb->source, InputSource::Gamepad);
    EXPECT_EQ(lb->code, GamepadCode::LeftBumper);

    auto lt = parse_input_name("Gamepad_LT");
    ASSERT_TRUE(lt.has_value());
    EXPECT_EQ(lt->source, InputSource::Gamepad);
    EXPECT_EQ(lt->code, GamepadCode::LeftTrigger);
}

TEST(InputCodeNameTest, CaseInsensitive)
{
    auto ctrl = parse_input_name("ctrl");
    ASSERT_TRUE(ctrl.has_value());
    EXPECT_EQ(*ctrl, keyboard_key(0x11));

    auto gpa = parse_input_name("gamepad_a");
    ASSERT_TRUE(gpa.has_value());
    EXPECT_EQ(*gpa, gamepad_button(GamepadCode::A));
}

TEST(InputCodeNameTest, UnknownNameReturnsNullopt)
{
    EXPECT_FALSE(parse_input_name("InvalidKey").has_value());
    EXPECT_FALSE(parse_input_name("").has_value());
    EXPECT_FALSE(parse_input_name("Gamepad_Z").has_value());
}

TEST(InputCodeNameTest, ReverseNameLookup)
{
    EXPECT_EQ(input_code_to_name(keyboard_key(0x11)), "Ctrl");
    EXPECT_EQ(input_code_to_name(mouse_button(0x05)), "Mouse4");
    EXPECT_EQ(input_code_to_name(gamepad_button(GamepadCode::A)), "Gamepad_A");
    EXPECT_TRUE(input_code_to_name(keyboard_key(0xFF)).empty());
}

TEST(InputCodeNameTest, FormatInputCode)
{
    EXPECT_EQ(format_input_code(keyboard_key(0x11)), "Ctrl");
    EXPECT_EQ(format_input_code(keyboard_key(0x72)), "F3");
    EXPECT_EQ(format_input_code(mouse_button(0x05)), "Mouse4");
    EXPECT_EQ(format_input_code(gamepad_button(GamepadCode::A)), "Gamepad_A");
    // Unknown code falls back to hex
    EXPECT_EQ(format_input_code(keyboard_key(0xFF)), "0xFF");
}

// Thumbstick axis codes

TEST(InputCodeNameTest, ParseThumbstickNames)
{
    auto lsu = parse_input_name("Gamepad_LSUp");
    ASSERT_TRUE(lsu.has_value());
    EXPECT_EQ(lsu->source, InputSource::Gamepad);
    EXPECT_EQ(lsu->code, GamepadCode::LeftStickUp);

    auto lsd = parse_input_name("Gamepad_LSDown");
    ASSERT_TRUE(lsd.has_value());
    EXPECT_EQ(lsd->code, GamepadCode::LeftStickDown);

    auto lsl = parse_input_name("Gamepad_LSLeft");
    ASSERT_TRUE(lsl.has_value());
    EXPECT_EQ(lsl->code, GamepadCode::LeftStickLeft);

    auto lsr = parse_input_name("Gamepad_LSRight");
    ASSERT_TRUE(lsr.has_value());
    EXPECT_EQ(lsr->code, GamepadCode::LeftStickRight);

    auto rsu = parse_input_name("Gamepad_RSUp");
    ASSERT_TRUE(rsu.has_value());
    EXPECT_EQ(rsu->code, GamepadCode::RightStickUp);

    auto rsd = parse_input_name("Gamepad_RSDown");
    ASSERT_TRUE(rsd.has_value());
    EXPECT_EQ(rsd->code, GamepadCode::RightStickDown);

    auto rsl = parse_input_name("Gamepad_RSLeft");
    ASSERT_TRUE(rsl.has_value());
    EXPECT_EQ(rsl->code, GamepadCode::RightStickLeft);

    auto rsr = parse_input_name("Gamepad_RSRight");
    ASSERT_TRUE(rsr.has_value());
    EXPECT_EQ(rsr->code, GamepadCode::RightStickRight);
}

TEST(InputCodeNameTest, ThumbstickCaseInsensitive)
{
    auto code = parse_input_name("gamepad_lsup");
    ASSERT_TRUE(code.has_value());
    EXPECT_EQ(*code, gamepad_button(GamepadCode::LeftStickUp));
}

TEST(InputCodeNameTest, ThumbstickReverseNameLookup)
{
    EXPECT_EQ(input_code_to_name(gamepad_button(GamepadCode::LeftStickUp)), "Gamepad_LSUp");
    EXPECT_EQ(input_code_to_name(gamepad_button(GamepadCode::RightStickRight)), "Gamepad_RSRight");
}

TEST(InputCodeNameTest, FormatThumbstickCode)
{
    EXPECT_EQ(format_input_code(gamepad_button(GamepadCode::LeftStickUp)), "Gamepad_LSUp");
    EXPECT_EQ(format_input_code(gamepad_button(GamepadCode::RightStickDown)), "Gamepad_RSDown");
}

TEST(InputStringTest, TriggerToString_IsNoexcept)
{
    static_assert(noexcept(input::to_string(input::Trigger::Press)));
    static_assert(noexcept(input::to_string(input::Trigger::Hold)));
}

TEST(InputStringTest, InputSourceToString_IsNoexcept)
{
    static_assert(noexcept(input_source_to_string(InputSource::Keyboard)));
    static_assert(noexcept(input_source_to_string(InputSource::Gamepad)));
}

// InputCodeHash

TEST(InputCodeHashTest, DifferentCodesProduceDifferentHashes)
{
    InputCodeHash hasher;

    InputCode kb_a = keyboard_key(0x41);
    InputCode kb_b = keyboard_key(0x42);
    InputCode mouse_1 = mouse_button(0x01);
    InputCode gp_a = gamepad_button(GamepadCode::A);

    std::size_t h1 = hasher(kb_a);
    std::size_t h2 = hasher(kb_b);
    std::size_t h3 = hasher(mouse_1);
    std::size_t h4 = hasher(gp_a);

    EXPECT_NE(h1, h2);
    EXPECT_NE(h1, h3);
    EXPECT_NE(h1, h4);
    EXPECT_NE(h2, h3);
    EXPECT_NE(h2, h4);
    EXPECT_NE(h3, h4);
}

TEST(InputCodeHashTest, SameCodeProducesSameHash)
{
    InputCodeHash hasher;

    InputCode a1 = keyboard_key(0x41);
    InputCode a2 = keyboard_key(0x41);

    EXPECT_EQ(hasher(a1), hasher(a2));
}

TEST(InputCodeHashTest, UsableInUnorderedSet)
{
    std::unordered_set<InputCode, InputCodeHash> codes;

    codes.insert(keyboard_key(0x41));
    codes.insert(keyboard_key(0x42));
    codes.insert(mouse_button(0x01));
    codes.insert(gamepad_button(GamepadCode::A));
    codes.insert(keyboard_key(0x41));

    EXPECT_EQ(codes.size(), 4u);
    EXPECT_EQ(codes.count(keyboard_key(0x41)), 1u);
    EXPECT_EQ(codes.count(keyboard_key(0x42)), 1u);
    EXPECT_EQ(codes.count(mouse_button(0x01)), 1u);
    EXPECT_EQ(codes.count(gamepad_button(GamepadCode::A)), 1u);
    EXPECT_NE(codes.find(keyboard_key(0x41)), codes.end());
    EXPECT_EQ(codes.find(keyboard_key(0x99)), codes.end());
}

TEST(InputCodeNameTest, FormatInputCode_UnknownMouseCode_EmitsSourceTaggedHex)
{
    // The device tag preserves an off-table non-keyboard source. Bare hexadecimal text parses as Keyboard.
    InputCode unknown_mouse = mouse_button(0xFE);
    EXPECT_EQ(format_input_code(unknown_mouse), "Mouse:0xFE");
}

TEST(InputCodeNameTest, FormatInputCode_UnknownKeyboardCode_StaysBareHex)
{
    // Keyboard off-table codes keep the bare-hex form for backward compatibility with existing configs.
    EXPECT_EQ(format_input_code(keyboard_key(0xFF)), "0xFF");
}

TEST(InputCodeNameTest, SourceTaggedHexRoundTrip)
{
    // The tagged off-table code preserves Mouse, Gamepad, or Wheel across format and parse.
    for (const InputCode code : {mouse_button(0xFE), gamepad_button(0x0800), mouse_wheel(0x09)})
    {
        const std::string formatted = format_input_code(code);
        const auto parsed = parse_input_name(formatted);
        ASSERT_TRUE(parsed.has_value()) << "failed to round-trip " << formatted;
        EXPECT_EQ(*parsed, code) << "round-trip mismatch for " << formatted;
    }
}

TEST(InputCodeNameTest, KeyboardBareHexRoundTripsThroughConfigParser)
{
    // Bare keyboard hexadecimal text returns nullopt from parse_input_name. The config combo fallback restores
    // Keyboard, so that separate path needs its own round-trip proof.
    const InputCode original = keyboard_key(0xFF);
    const std::string formatted = format_input_code(original);
    ASSERT_EQ(formatted, "0xFF");
    EXPECT_FALSE(parse_input_name(formatted).has_value()) << "parse_input_name must not reconstruct a bare hex token";

    // bind_combos parses its default immediately. The setter observes that result without an INI file.
    input::KeyComboList captured;
    bool fired = false;
    config::bind_combos(
        "RoundTrip",
        "Key",
        "Round Trip Key",
        [&](const input::KeyComboList &combos)
        {
            captured = combos;
            fired = true;
        },
        formatted
    );
    config::clear(); // drop the registration so its setter does not fire against later config tests

    ASSERT_TRUE(fired);
    ASSERT_EQ(captured.size(), 1u);
    ASSERT_EQ(captured[0].keys.size(), 1u);
    EXPECT_EQ(captured[0].keys[0], original) << "config combo parser must recover the bare-hex keyboard code";
}

TEST(InputCodeNameTest, ParseSourceTaggedHexFormats)
{
    EXPECT_EQ(parse_input_name("Mouse:0xFE"), mouse_button(0xFE));
    EXPECT_EQ(parse_input_name("Gamepad:0x800"), gamepad_button(0x800));
    EXPECT_EQ(parse_input_name("MouseWheel:0x9"), mouse_wheel(0x9));
    // Tag and value are case-insensitive in the tag, and the 0x prefix is optional.
    EXPECT_EQ(parse_input_name("mouse:FE"), mouse_button(0xFE));
    // An unknown tag or a non-hex value fails closed.
    EXPECT_FALSE(parse_input_name("Bogus:0x10").has_value());
    EXPECT_FALSE(parse_input_name("Mouse:0xZZ").has_value());
    EXPECT_FALSE(parse_input_name("Mouse:").has_value());
}

TEST(InputCodeNameTest, ParseWindowsAndOemPunctuationNames)
{
    EXPECT_EQ(parse_input_name("LWin"), keyboard_key(0x5B));
    EXPECT_EQ(parse_input_name("RWin"), keyboard_key(0x5C));
    EXPECT_EQ(parse_input_name("Apps"), keyboard_key(0x5D));
    EXPECT_EQ(parse_input_name("Menu"), keyboard_key(0x5D));
    EXPECT_EQ(parse_input_name("Semicolon"), keyboard_key(0xBA));
    EXPECT_EQ(parse_input_name("Equals"), keyboard_key(0xBB));
    EXPECT_EQ(parse_input_name("Comma"), keyboard_key(0xBC));
    EXPECT_EQ(parse_input_name("Minus"), keyboard_key(0xBD));
    EXPECT_EQ(parse_input_name("Period"), keyboard_key(0xBE));
    EXPECT_EQ(parse_input_name("Slash"), keyboard_key(0xBF));
    EXPECT_EQ(parse_input_name("LBracket"), keyboard_key(0xDB));
    EXPECT_EQ(parse_input_name("Backslash"), keyboard_key(0xDC));
    EXPECT_EQ(parse_input_name("RBracket"), keyboard_key(0xDD));
    EXPECT_EQ(parse_input_name("Apostrophe"), keyboard_key(0xDE));
}

TEST(InputCodeNameTest, ParseGraveConsoleKeyAndAliases)
{
    // Every grave-key alias resolves to VK_OEM_3.
    EXPECT_EQ(parse_input_name("Grave"), keyboard_key(0xC0));
    EXPECT_EQ(parse_input_name("Backtick"), keyboard_key(0xC0));
    EXPECT_EQ(parse_input_name("Tilde"), keyboard_key(0xC0));
    EXPECT_EQ(parse_input_name("grave"), keyboard_key(0xC0)); // case-insensitive
}

TEST(InputCodeNameTest, AddedNamesReverseLookupPicksCanonical)
{
    // Aliases parse but the reverse lookup yields the canonical (first-listed) name.
    EXPECT_EQ(input_code_to_name(keyboard_key(0xC0)), "Grave");
    EXPECT_EQ(input_code_to_name(keyboard_key(0x5D)), "Apps");
    EXPECT_EQ(input_code_to_name(keyboard_key(0xDE)), "Apostrophe");
    EXPECT_EQ(input_code_to_name(keyboard_key(0x5B)), "LWin");
}

TEST(InputSourceTest, UnknownSourceToString)
{
    auto unknown = static_cast<InputSource>(999);
    EXPECT_EQ(input_source_to_string(unknown), "Unknown");
}

TEST(TriggerTest, UnknownTriggerToString)
{
    auto unknown = static_cast<input::Trigger>(999);
    EXPECT_EQ(input::to_string(unknown), "Unknown");
}
