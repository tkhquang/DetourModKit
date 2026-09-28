#ifndef DETOURMODKIT_INPUT_CODES_HPP
#define DETOURMODKIT_INPUT_CODES_HPP

/**
 * @file input_codes.hpp
 * @brief Tagged input codes for keyboard, mouse, mouse-wheel, and gamepad inputs, with named-key resolution.
 * @details Each PascalCase constant in GamepadCode and WheelCode also has an UPPER_SNAKE_CASE spelling with the same
 *          value. Both spellings are public API.
 */

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace DetourModKit
{
    /** @brief Identifies the device type for an input code. */
    enum class InputSource : std::uint8_t
    {
        Keyboard,
        Mouse,
        Gamepad,
        MouseWheel
    };

    /** @brief Returns the enumerator name of @p source, or "Unknown" for a value outside the enum. */
    [[nodiscard]] constexpr std::string_view input_source_to_string(InputSource source) noexcept
    {
        switch (source)
        {
        case InputSource::Keyboard:
            return "Keyboard";
        case InputSource::Mouse:
            return "Mouse";
        case InputSource::Gamepad:
            return "Gamepad";
        case InputSource::MouseWheel:
            return "MouseWheel";
        }
        return "Unknown";
    }

    /**
     * @brief A tagged input identifier: a device source and a button or key code.
     * @details A Keyboard or Mouse code is a Windows virtual-key code, usable with GetAsyncKeyState. A Gamepad code is
     *          an XInput button bitmask or a synthetic GamepadCode identifier. A MouseWheel code is a WheelCode
     *          direction. It fires at most one momentary pulse per whole notch of queue-delivered wheel input and
     *          never acts as a held modifier. `input::Input::WheelBackend` documents the capture scope.
     */
    struct InputCode
    {
        InputSource source = InputSource::Keyboard;
        int code = 0;

        constexpr bool operator==(const InputCode &) const noexcept = default;
    };

    /** @brief Hash functor for InputCode keys in unordered containers. */
    struct InputCodeHash
    {
        std::size_t operator()(const InputCode &ic) const noexcept
        {
            return std::hash<int>{}(ic.code) ^ (std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(ic.source)) << 16);
        }
    };

    /** @brief Creates a Keyboard InputCode from a Windows virtual-key code, for example 0x41 for 'A'. */
    [[nodiscard]] constexpr InputCode keyboard_key(int vk) noexcept
    {
        return {InputSource::Keyboard, vk};
    }

    /** @brief Creates a Mouse InputCode from a Windows virtual-key code, for example 0x01 for VK_LBUTTON. */
    [[nodiscard]] constexpr InputCode mouse_button(int vk) noexcept
    {
        return {InputSource::Mouse, vk};
    }

    /** @brief Creates a Gamepad InputCode from an XInput button mask or a synthetic GamepadCode identifier. */
    [[nodiscard]] constexpr InputCode gamepad_button(int code) noexcept
    {
        return {InputSource::Gamepad, code};
    }

    /** @brief Creates a MouseWheel InputCode from a WheelCode direction. */
    [[nodiscard]] constexpr InputCode mouse_wheel(int code) noexcept
    {
        return {InputSource::MouseWheel, code};
    }

    /** @brief Button codes equal XINPUT_GAMEPAD_* bitmasks. Trigger and stick-direction codes are synthetic. */
    namespace GamepadCode
    {
        inline constexpr int DpadUp = 0x0001;
        inline constexpr int DpadDown = 0x0002;
        inline constexpr int DpadLeft = 0x0004;
        inline constexpr int DpadRight = 0x0008;
        inline constexpr int Start = 0x0010;
        inline constexpr int Back = 0x0020;
        inline constexpr int LeftStick = 0x0040;
        inline constexpr int RightStick = 0x0080;
        inline constexpr int LeftBumper = 0x0100;
        inline constexpr int RightBumper = 0x0200;
        inline constexpr int A = 0x1000;
        inline constexpr int B = 0x2000;
        inline constexpr int X = 0x4000;
        inline constexpr int Y = 0x8000;

        /// Synthetic codes for analog triggers treated as digital inputs.
        inline constexpr int LeftTrigger = 0x10000;
        inline constexpr int RightTrigger = 0x10001;

        /** @brief Synthetic thumbstick codes. Each fires when its axis exceeds the stick deadzone threshold. */
        inline constexpr int LeftStickUp = 0x10002;
        inline constexpr int LeftStickDown = 0x10003;
        inline constexpr int LeftStickLeft = 0x10004;
        inline constexpr int LeftStickRight = 0x10005;
        inline constexpr int RightStickUp = 0x10006;
        inline constexpr int RightStickDown = 0x10007;
        inline constexpr int RightStickLeft = 0x10008;
        inline constexpr int RightStickRight = 0x10009;

        /// Default of `input::Input::Settings::trigger_threshold` (0 to 255 range). A trigger fires above the setting.
        inline constexpr int TriggerThreshold = 30;

        /** @brief Default stick deadzone threshold (0 to 32767 range), equal to XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE. */
        inline constexpr int StickThreshold = 7849;

        // A, B, X, and Y are identical in both spellings.
        inline constexpr int DPAD_UP = DpadUp;
        inline constexpr int DPAD_DOWN = DpadDown;
        inline constexpr int DPAD_LEFT = DpadLeft;
        inline constexpr int DPAD_RIGHT = DpadRight;
        inline constexpr int START = Start;
        inline constexpr int BACK = Back;
        inline constexpr int LEFT_STICK = LeftStick;
        inline constexpr int RIGHT_STICK = RightStick;
        inline constexpr int LEFT_BUMPER = LeftBumper;
        inline constexpr int RIGHT_BUMPER = RightBumper;
        inline constexpr int LEFT_TRIGGER = LeftTrigger;
        inline constexpr int RIGHT_TRIGGER = RightTrigger;
        inline constexpr int LEFT_STICK_UP = LeftStickUp;
        inline constexpr int LEFT_STICK_DOWN = LeftStickDown;
        inline constexpr int LEFT_STICK_LEFT = LeftStickLeft;
        inline constexpr int LEFT_STICK_RIGHT = LeftStickRight;
        inline constexpr int RIGHT_STICK_UP = RightStickUp;
        inline constexpr int RIGHT_STICK_DOWN = RightStickDown;
        inline constexpr int RIGHT_STICK_LEFT = RightStickLeft;
        inline constexpr int RIGHT_STICK_RIGHT = RightStickRight;
        inline constexpr int TRIGGER_THRESHOLD = TriggerThreshold;
        inline constexpr int STICK_THRESHOLD = StickThreshold;
    } // namespace GamepadCode

    /**
     * @brief Mouse-wheel direction identifiers for InputSource::MouseWheel codes.
     * @details Values are 1-based and dense, so `code - WheelCode::Up` is a zero-based direction index. Up and Down
     *          are the vertical wheel. Left and Right are the horizontal (tilt) wheel.
     */
    namespace WheelCode
    {
        inline constexpr int Up = 1;
        inline constexpr int Down = 2;
        inline constexpr int Left = 3;
        inline constexpr int Right = 4;

        inline constexpr int UP = Up;
        inline constexpr int DOWN = Down;
        inline constexpr int LEFT = Left;
        inline constexpr int RIGHT = Right;
    } // namespace WheelCode

    /**
     * @brief Resolves a human-readable input name to an InputCode, case-insensitively.
     * @details Recognized name formats:
     *          - Keyboard: "A" through "Z", "0" through "9", "F1" through "F24", "Ctrl", "Shift", "Alt", "Space",
     *            "Enter", "Escape", "Tab", "Backspace", "LWin", "RWin", "Apps", and others.
     *          - OEM punctuation: "Grave"/"Backtick"/"Tilde", "Semicolon", "Comma", "Period", "Slash", and others.
     *          - Mouse: "Mouse1" (left) through "Mouse5" (XButton2).
     *          - Mouse wheel: "WheelUp", "WheelDown", "WheelLeft", "WheelRight".
     *          - Gamepad: "Gamepad_A", "Gamepad_B", "Gamepad_LB", "Gamepad_LT", and others.
     *          - Source-tagged hex: "Mouse:0xFE", "Gamepad:0x800", "MouseWheel:0x9", "Keyboard:0xFF".
     * @return The resolved code, or std::nullopt for an unrecognized name or a bare hex token such as "0xFF".
     */
    [[nodiscard]] std::optional<InputCode> parse_input_name(std::string_view name);

    /** @brief Returns the canonical name of @p code, or an empty view if the name table has no entry for it. */
    [[nodiscard]] std::string_view input_code_to_name(const InputCode &code);

    /**
     * @brief Formats an InputCode as a human-readable string.
     * @details Returns the canonical name if the name table has one. An off-table Keyboard code formats as bare hex
     *          ("0xFF"). Any other off-table code formats as source-tagged hex ("Mouse:0xFE"). parse_input_name reads
     *          the tagged form back, and config::bind_combos reads bare hex back as a Keyboard code.
     */
    [[nodiscard]] std::string format_input_code(const InputCode &code);

} // namespace DetourModKit

#endif // DETOURMODKIT_INPUT_CODES_HPP
