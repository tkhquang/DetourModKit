#ifndef DETOURMODKIT_INPUT_CODES_HPP
#define DETOURMODKIT_INPUT_CODES_HPP

/**
 * @file input_codes.hpp
 * @brief Unified input code types for keyboard, mouse, and gamepad inputs.
 * @details Provides a tagged InputCode type that identifies both the device source
 *          and button/key code, along with named key resolution for human-readable
 *          configuration strings. Gamepad codes correspond to XInput button masks.
 */

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace DetourModKit
{
    /**
     * @enum InputSource
     * @brief Identifies the device type for an input code.
     */
    enum class InputSource : uint8_t
    {
        Keyboard,
        Mouse,
        Gamepad
    };

    /**
     * @brief Converts an InputSource enum to its string representation.
     * @param source The InputSource enum value.
     * @return std::string_view String representation of the source.
     */
    constexpr std::string_view input_source_to_string(InputSource source) noexcept
    {
        switch (source)
        {
        case InputSource::Keyboard:
            return "Keyboard";
        case InputSource::Mouse:
            return "Mouse";
        case InputSource::Gamepad:
            return "Gamepad";
        }
        return "Unknown";
    }

    /**
     * @struct InputCode
     * @brief A tagged input identifier combining a device source and a button/key code.
     * @details For Keyboard and Mouse sources, the code is a Windows Virtual Key code
     *          (usable with GetAsyncKeyState). For Gamepad, the code is an XInput
     *          button bitmask or a synthetic trigger identifier (see GamepadCode).
     */
    struct InputCode
    {
        InputSource source = InputSource::Keyboard;
        int code = 0;

        constexpr bool operator==(const InputCode &) const noexcept = default;
    };

    /**
     * @brief Hash functor for InputCode, enabling use in unordered containers.
     */
    struct InputCodeHash
    {
        std::size_t operator()(const InputCode &ic) const noexcept
        {
            return std::hash<int>{}(ic.code) ^
                   (std::hash<uint8_t>{}(static_cast<uint8_t>(ic.source)) << 16);
        }
    };

    /**
     * @brief Creates a keyboard InputCode from a Windows Virtual Key code.
     * @param vk The VK code (e.g., 0x41 for 'A').
     * @return InputCode Tagged as Keyboard.
     */
    constexpr InputCode keyboard_key(int vk) noexcept { return {InputSource::Keyboard, vk}; }

    /**
     * @brief Creates a mouse InputCode from a Windows Virtual Key code.
     * @param vk The VK code (e.g., 0x01 for VK_LBUTTON).
     * @return InputCode Tagged as Mouse.
     */
    constexpr InputCode mouse_button(int vk) noexcept { return {InputSource::Mouse, vk}; }

    /**
     * @brief Creates a gamepad InputCode from an XInput button code.
     * @param code The XInput button mask or synthetic trigger code (see GamepadCode).
     * @return InputCode Tagged as Gamepad.
     */
    constexpr InputCode gamepad_button(int code) noexcept { return {InputSource::Gamepad, code}; }

    /**
     * @namespace GamepadCode
     * @brief XInput-compatible gamepad button codes and synthetic analog identifiers.
     * @details Digital button codes match XInput XINPUT_GAMEPAD_* bitmask values.
     *          LeftTrigger/RightTrigger and thumbstick direction codes are synthetic
     *          identifiers for analog inputs treated as digital with configurable
     *          deadzone thresholds.
     */
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

        /// Synthetic codes for thumbstick axes treated as digital inputs.
        /// Each direction fires when the axis exceeds the stick deadzone threshold.
        inline constexpr int LeftStickUp = 0x10002;
        inline constexpr int LeftStickDown = 0x10003;
        inline constexpr int LeftStickLeft = 0x10004;
        inline constexpr int LeftStickRight = 0x10005;
        inline constexpr int RightStickUp = 0x10006;
        inline constexpr int RightStickDown = 0x10007;
        inline constexpr int RightStickLeft = 0x10008;
        inline constexpr int RightStickRight = 0x10009;

        /// Default analog trigger threshold (0-255 range, values above are "pressed").
        inline constexpr int TriggerThreshold = 30;

        /// Default thumbstick deadzone threshold (0-32767 range).
        /// Matches XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE (7849).
        inline constexpr int StickThreshold = 7849;
    } // namespace GamepadCode

    /**
     * @brief Attempts to resolve a human-readable name to an InputCode.
     * @details Performs case-insensitive matching against a built-in table of known
     *          key, mouse button, and gamepad button names.
     *
     *          Recognized name formats:
     *          - Keyboard: "A"-"Z", "0"-"9", "F1"-"F24", "Ctrl", "Shift", "Alt",
     *            "Space", "Enter", "Escape", "Tab", "Backspace", etc.
     *          - Mouse: "Mouse1" (left) through "Mouse5" (XButton2)
     *          - Gamepad: "Gamepad_A", "Gamepad_B", "Gamepad_LB", "Gamepad_LT", etc.
     *
     * @param name The input name to resolve.
     * @return std::optional<InputCode> The resolved code, or std::nullopt if unrecognized.
     */
    [[nodiscard]] std::optional<InputCode> parse_input_name(std::string_view name);

    /**
     * @brief Returns a human-readable name for an InputCode, if one exists.
     * @param code The input code to look up.
     * @return std::string_view The canonical name, or an empty view if not in the table.
     */
    std::string_view input_code_to_name(const InputCode &code);

    /**
     * @brief Formats an InputCode as a human-readable string.
     * @details Returns the canonical name if the code is in the lookup table,
     *          otherwise falls back to a hexadecimal representation (e.g., "0x72").
     * @param code The input code to format.
     * @return std::string Formatted string.
     */
    std::string format_input_code(const InputCode &code);

} // namespace DetourModKit

#endif // DETOURMODKIT_INPUT_CODES_HPP
