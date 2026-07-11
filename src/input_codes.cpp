/**
 * @file input_codes.cpp
 * @brief Implementation of named input code resolution and formatting.
 *
 * Provides the name lookup table and resolution functions for converting between human-readable input names (e.g.,
 * "Ctrl", "Mouse4", "Gamepad_A") and their corresponding InputCode values.
 */

#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/format.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <unordered_map>

namespace DetourModKit
{
    namespace
    {
        struct NameEntry
        {
            const char *name = nullptr;
            InputCode code;
        };

        // clang-format off
        constexpr NameEntry NAME_TABLE[] = {
            // Keyboard: Modifiers
            {"Ctrl",        {InputSource::Keyboard, 0x11}},
            {"LCtrl",       {InputSource::Keyboard, 0xA2}},
            {"RCtrl",       {InputSource::Keyboard, 0xA3}},
            {"Shift",       {InputSource::Keyboard, 0x10}},
            {"LShift",      {InputSource::Keyboard, 0xA0}},
            {"RShift",      {InputSource::Keyboard, 0xA1}},
            {"Alt",         {InputSource::Keyboard, 0x12}},
            {"LAlt",        {InputSource::Keyboard, 0xA4}},
            {"RAlt",        {InputSource::Keyboard, 0xA5}},

            // Keyboard: Function keys
            {"F1",          {InputSource::Keyboard, 0x70}},
            {"F2",          {InputSource::Keyboard, 0x71}},
            {"F3",          {InputSource::Keyboard, 0x72}},
            {"F4",          {InputSource::Keyboard, 0x73}},
            {"F5",          {InputSource::Keyboard, 0x74}},
            {"F6",          {InputSource::Keyboard, 0x75}},
            {"F7",          {InputSource::Keyboard, 0x76}},
            {"F8",          {InputSource::Keyboard, 0x77}},
            {"F9",          {InputSource::Keyboard, 0x78}},
            {"F10",         {InputSource::Keyboard, 0x79}},
            {"F11",         {InputSource::Keyboard, 0x7A}},
            {"F12",         {InputSource::Keyboard, 0x7B}},
            {"F13",         {InputSource::Keyboard, 0x7C}},
            {"F14",         {InputSource::Keyboard, 0x7D}},
            {"F15",         {InputSource::Keyboard, 0x7E}},
            {"F16",         {InputSource::Keyboard, 0x7F}},
            {"F17",         {InputSource::Keyboard, 0x80}},
            {"F18",         {InputSource::Keyboard, 0x81}},
            {"F19",         {InputSource::Keyboard, 0x82}},
            {"F20",         {InputSource::Keyboard, 0x83}},
            {"F21",         {InputSource::Keyboard, 0x84}},
            {"F22",         {InputSource::Keyboard, 0x85}},
            {"F23",         {InputSource::Keyboard, 0x86}},
            {"F24",         {InputSource::Keyboard, 0x87}},

            // Keyboard: Letters
            {"A",           {InputSource::Keyboard, 0x41}},
            {"B",           {InputSource::Keyboard, 0x42}},
            {"C",           {InputSource::Keyboard, 0x43}},
            {"D",           {InputSource::Keyboard, 0x44}},
            {"E",           {InputSource::Keyboard, 0x45}},
            {"F",           {InputSource::Keyboard, 0x46}},
            {"G",           {InputSource::Keyboard, 0x47}},
            {"H",           {InputSource::Keyboard, 0x48}},
            {"I",           {InputSource::Keyboard, 0x49}},
            {"J",           {InputSource::Keyboard, 0x4A}},
            {"K",           {InputSource::Keyboard, 0x4B}},
            {"L",           {InputSource::Keyboard, 0x4C}},
            {"M",           {InputSource::Keyboard, 0x4D}},
            {"N",           {InputSource::Keyboard, 0x4E}},
            {"O",           {InputSource::Keyboard, 0x4F}},
            {"P",           {InputSource::Keyboard, 0x50}},
            {"Q",           {InputSource::Keyboard, 0x51}},
            {"R",           {InputSource::Keyboard, 0x52}},
            {"S",           {InputSource::Keyboard, 0x53}},
            {"T",           {InputSource::Keyboard, 0x54}},
            {"U",           {InputSource::Keyboard, 0x55}},
            {"V",           {InputSource::Keyboard, 0x56}},
            {"W",           {InputSource::Keyboard, 0x57}},
            {"X",           {InputSource::Keyboard, 0x58}},
            {"Y",           {InputSource::Keyboard, 0x59}},
            {"Z",           {InputSource::Keyboard, 0x5A}},

            // Keyboard: Digits
            {"0",           {InputSource::Keyboard, 0x30}},
            {"1",           {InputSource::Keyboard, 0x31}},
            {"2",           {InputSource::Keyboard, 0x32}},
            {"3",           {InputSource::Keyboard, 0x33}},
            {"4",           {InputSource::Keyboard, 0x34}},
            {"5",           {InputSource::Keyboard, 0x35}},
            {"6",           {InputSource::Keyboard, 0x36}},
            {"7",           {InputSource::Keyboard, 0x37}},
            {"8",           {InputSource::Keyboard, 0x38}},
            {"9",           {InputSource::Keyboard, 0x39}},

            // Keyboard: Navigation
            {"Up",          {InputSource::Keyboard, 0x26}},
            {"Down",        {InputSource::Keyboard, 0x28}},
            {"Left",        {InputSource::Keyboard, 0x25}},
            {"Right",       {InputSource::Keyboard, 0x27}},
            {"Home",        {InputSource::Keyboard, 0x24}},
            {"End",         {InputSource::Keyboard, 0x23}},
            {"PageUp",      {InputSource::Keyboard, 0x21}},
            {"PageDown",    {InputSource::Keyboard, 0x22}},
            {"Insert",      {InputSource::Keyboard, 0x2D}},
            {"Delete",      {InputSource::Keyboard, 0x2E}},

            // Keyboard: Common keys
            {"Space",       {InputSource::Keyboard, 0x20}},
            {"Enter",       {InputSource::Keyboard, 0x0D}},
            {"Escape",      {InputSource::Keyboard, 0x1B}},
            {"Tab",         {InputSource::Keyboard, 0x09}},
            {"Backspace",   {InputSource::Keyboard, 0x08}},
            {"CapsLock",    {InputSource::Keyboard, 0x14}},
            {"NumLock",     {InputSource::Keyboard, 0x90}},
            {"ScrollLock",  {InputSource::Keyboard, 0x91}},
            {"PrintScreen", {InputSource::Keyboard, 0x2C}},
            {"Pause",       {InputSource::Keyboard, 0x13}},

            // Keyboard: Windows / application keys
            {"LWin",        {InputSource::Keyboard, 0x5B}},
            {"RWin",        {InputSource::Keyboard, 0x5C}},
            {"Apps",        {InputSource::Keyboard, 0x5D}},
            {"Menu",        {InputSource::Keyboard, 0x5D}}, // alias for the application/context-menu key

            // Keyboard: OEM punctuation (US layout)
            // The canonical name is listed first so the reverse lookup picks it; trailing aliases still parse. Grave
            // (VK_OEM_3) is the backtick/tilde key many games use to open the console.
            {"Semicolon",   {InputSource::Keyboard, 0xBA}},
            {"Equals",      {InputSource::Keyboard, 0xBB}},
            {"Comma",       {InputSource::Keyboard, 0xBC}},
            {"Minus",       {InputSource::Keyboard, 0xBD}},
            {"Period",      {InputSource::Keyboard, 0xBE}},
            {"Slash",       {InputSource::Keyboard, 0xBF}},
            {"Grave",       {InputSource::Keyboard, 0xC0}},
            {"Backtick",    {InputSource::Keyboard, 0xC0}}, // alias for Grave
            {"Tilde",       {InputSource::Keyboard, 0xC0}}, // alias for Grave
            {"LBracket",    {InputSource::Keyboard, 0xDB}},
            {"Backslash",   {InputSource::Keyboard, 0xDC}},
            {"RBracket",    {InputSource::Keyboard, 0xDD}},
            {"Apostrophe",  {InputSource::Keyboard, 0xDE}},
            {"Quote",       {InputSource::Keyboard, 0xDE}}, // alias for Apostrophe

            // Keyboard: Numpad
            {"Numpad0",         {InputSource::Keyboard, 0x60}},
            {"Numpad1",         {InputSource::Keyboard, 0x61}},
            {"Numpad2",         {InputSource::Keyboard, 0x62}},
            {"Numpad3",         {InputSource::Keyboard, 0x63}},
            {"Numpad4",         {InputSource::Keyboard, 0x64}},
            {"Numpad5",         {InputSource::Keyboard, 0x65}},
            {"Numpad6",         {InputSource::Keyboard, 0x66}},
            {"Numpad7",         {InputSource::Keyboard, 0x67}},
            {"Numpad8",         {InputSource::Keyboard, 0x68}},
            {"Numpad9",         {InputSource::Keyboard, 0x69}},
            {"NumpadAdd",       {InputSource::Keyboard, 0x6B}},
            {"NumpadSubtract",  {InputSource::Keyboard, 0x6D}},
            {"NumpadMultiply",  {InputSource::Keyboard, 0x6A}},
            {"NumpadDivide",    {InputSource::Keyboard, 0x6F}},
            {"NumpadDecimal",   {InputSource::Keyboard, 0x6E}},

            // Mouse buttons
            {"Mouse1",     {InputSource::Mouse, 0x01}},
            {"Mouse2",     {InputSource::Mouse, 0x02}},
            {"Mouse3",     {InputSource::Mouse, 0x04}},
            {"Mouse4",     {InputSource::Mouse, 0x05}},
            {"Mouse5",     {InputSource::Mouse, 0x06}},

            // Mouse wheel (event-only; captured via the input layer's WndProc hook)
            {"WheelUp",    {InputSource::MouseWheel, WheelCode::Up}},
            {"WheelDown",  {InputSource::MouseWheel, WheelCode::Down}},
            {"WheelLeft",  {InputSource::MouseWheel, WheelCode::Left}},
            {"WheelRight", {InputSource::MouseWheel, WheelCode::Right}},

            // Gamepad buttons
            {"Gamepad_A",          {InputSource::Gamepad, GamepadCode::A}},
            {"Gamepad_B",          {InputSource::Gamepad, GamepadCode::B}},
            {"Gamepad_X",          {InputSource::Gamepad, GamepadCode::X}},
            {"Gamepad_Y",          {InputSource::Gamepad, GamepadCode::Y}},
            {"Gamepad_LB",         {InputSource::Gamepad, GamepadCode::LeftBumper}},
            {"Gamepad_RB",         {InputSource::Gamepad, GamepadCode::RightBumper}},
            {"Gamepad_LT",         {InputSource::Gamepad, GamepadCode::LeftTrigger}},
            {"Gamepad_RT",         {InputSource::Gamepad, GamepadCode::RightTrigger}},
            {"Gamepad_Start",      {InputSource::Gamepad, GamepadCode::Start}},
            {"Gamepad_Back",       {InputSource::Gamepad, GamepadCode::Back}},
            {"Gamepad_LS",         {InputSource::Gamepad, GamepadCode::LeftStick}},
            {"Gamepad_RS",         {InputSource::Gamepad, GamepadCode::RightStick}},
            {"Gamepad_DpadUp",     {InputSource::Gamepad, GamepadCode::DpadUp}},
            {"Gamepad_DpadDown",   {InputSource::Gamepad, GamepadCode::DpadDown}},
            {"Gamepad_DpadLeft",   {InputSource::Gamepad, GamepadCode::DpadLeft}},
            {"Gamepad_DpadRight",  {InputSource::Gamepad, GamepadCode::DpadRight}},

            // Gamepad thumbstick axes (digital)
            {"Gamepad_LSUp",       {InputSource::Gamepad, GamepadCode::LeftStickUp}},
            {"Gamepad_LSDown",     {InputSource::Gamepad, GamepadCode::LeftStickDown}},
            {"Gamepad_LSLeft",     {InputSource::Gamepad, GamepadCode::LeftStickLeft}},
            {"Gamepad_LSRight",    {InputSource::Gamepad, GamepadCode::LeftStickRight}},
            {"Gamepad_RSUp",       {InputSource::Gamepad, GamepadCode::RightStickUp}},
            {"Gamepad_RSDown",     {InputSource::Gamepad, GamepadCode::RightStickDown}},
            {"Gamepad_RSLeft",     {InputSource::Gamepad, GamepadCode::RightStickLeft}},
            {"Gamepad_RSRight",    {InputSource::Gamepad, GamepadCode::RightStickRight}},
        };
        // clang-format on

        constexpr size_t NAME_TABLE_SIZE = sizeof(NAME_TABLE) / sizeof(NAME_TABLE[0]);

        int icompare(std::string_view a, std::string_view b) noexcept
        {
            // Branch-free ASCII case fold. The input-name and source tables are pure ASCII, so a locale-sensitive
            // std::tolower is both unnecessary and a portability hazard on this resolution path: under a non-invariant
            // CRT locale it could fold identifiers differently (the ASCII 'I'/'i' pair is the classic Turkish example),
            // making name resolution locale-dependent. Folding only 'A'-'Z' inline keeps the comparison deterministic
            // across every locale and allocation-free.
            const auto ascii_lower = [](char c) noexcept -> unsigned char
            {
                const auto u = static_cast<unsigned char>(c);
                return (u >= 'A' && u <= 'Z') ? static_cast<unsigned char>(u + ('a' - 'A')) : u;
            };
            const size_t len = std::min(a.size(), b.size());
            for (size_t i = 0; i < len; ++i)
            {
                const int ca = ascii_lower(a[i]);
                const int cb = ascii_lower(b[i]);
                if (ca != cb)
                {
                    return ca - cb;
                }
            }
            if (a.size() < b.size())
            {
                return -1;
            }
            if (a.size() > b.size())
            {
                return 1;
            }
            return 0;
        }

        /**
         * @brief Parses a source-tagged hex token such as "Mouse:0xFE" into an InputCode.
         * @details The inverse of format_input_code's off-table form for non-keyboard sources. The source tag matches
         *          input_source_to_string ("Keyboard", "Mouse", "Gamepad", "MouseWheel"), case-insensitively, and the
         *          value parses as hex with or without a 0x prefix.
         * @param source_token The device-source tag (text before the ':').
         * @param hex_token The hex value (text after the ':'), with or without a 0x/0X prefix.
         * @return The resolved InputCode, or std::nullopt if the tag is unknown or the value is not a valid
         *         non-negative hex int.
         */
        std::optional<InputCode> parse_source_tagged_hex(std::string_view source_token,
                                                         std::string_view hex_token) noexcept
        {
            InputSource source = InputSource::Keyboard;
            if (icompare(source_token, "Keyboard") == 0)
            {
                source = InputSource::Keyboard;
            }
            else if (icompare(source_token, "Mouse") == 0)
            {
                source = InputSource::Mouse;
            }
            else if (icompare(source_token, "Gamepad") == 0)
            {
                source = InputSource::Gamepad;
            }
            else if (icompare(source_token, "MouseWheel") == 0)
            {
                source = InputSource::MouseWheel;
            }
            else
            {
                return std::nullopt;
            }

            // Strip an optional 0x / 0X prefix; std::from_chars(base 16) does not accept one.
            if (hex_token.size() >= 2 && hex_token[0] == '0' && (hex_token[1] == 'x' || hex_token[1] == 'X'))
            {
                hex_token.remove_prefix(2);
            }
            if (hex_token.empty())
            {
                return std::nullopt;
            }

            unsigned long value = 0;
            const char *const first = hex_token.data();
            const char *const last = hex_token.data() + hex_token.size();
            const auto [ptr, ec] = std::from_chars(first, last, value, 16);
            if (ec != std::errc{} || ptr != last)
            {
                return std::nullopt;
            }
            if (value > static_cast<unsigned long>(std::numeric_limits<int>::max()))
            {
                return std::nullopt;
            }
            return InputCode{source, static_cast<int>(value)};
        }

        struct SortedNameIndex
        {
            size_t indices[NAME_TABLE_SIZE]{};
            size_t count = NAME_TABLE_SIZE;

            SortedNameIndex()
            {
                for (size_t i = 0; i < NAME_TABLE_SIZE; ++i)
                {
                    indices[i] = i;
                }
                std::sort(indices, indices + count,
                          [](size_t a, size_t b) { return icompare(NAME_TABLE[a].name, NAME_TABLE[b].name) < 0; });
            }
        };

        const SortedNameIndex &get_sorted_index()
        {
            static const SortedNameIndex instance;
            return instance;
        }

        struct CodeNameMap
        {
            std::unordered_map<InputCode, std::string_view, InputCodeHash> map;

            CodeNameMap()
            {
                map.reserve(NAME_TABLE_SIZE);
                for (size_t i = 0; i < NAME_TABLE_SIZE; ++i)
                {
                    map.emplace(NAME_TABLE[i].code, NAME_TABLE[i].name);
                }
            }
        };

        const CodeNameMap &get_code_name_map()
        {
            static const CodeNameMap instance;
            return instance;
        }
    } // anonymous namespace

    std::optional<InputCode> parse_input_name(std::string_view name)
    {
        // A source-tagged hex token ("Mouse:0xFE", "Gamepad:0x800") is the inverse of format_input_code's off-table
        // form: it carries the device source so a non-keyboard code survives a config round-trip. No table name
        // contains ':', so a token with one is only ever a tag; a malformed tag falls through to the table search
        // (which cannot match it) and yields nullopt.
        if (const size_t colon = name.find(':'); colon != std::string_view::npos)
        {
            if (const auto tagged = parse_source_tagged_hex(name.substr(0, colon), name.substr(colon + 1)))
            {
                return tagged;
            }
        }

        const auto &idx = get_sorted_index();
        size_t lo = 0;
        size_t hi = idx.count;
        while (lo < hi)
        {
            const size_t mid = lo + (hi - lo) / 2;
            const int cmp = icompare(NAME_TABLE[idx.indices[mid]].name, name);
            if (cmp < 0)
            {
                lo = mid + 1;
            }
            else if (cmp > 0)
            {
                hi = mid;
            }
            else
            {
                return NAME_TABLE[idx.indices[mid]].code;
            }
        }
        return std::nullopt;
    }

    std::string_view input_code_to_name(const InputCode &code)
    {
        const auto &map = get_code_name_map().map;
        const auto it = map.find(code);
        if (it != map.end())
        {
            return it->second;
        }
        return {};
    }

    std::string format_input_code(const InputCode &code)
    {
        const auto name = input_code_to_name(code);
        if (!name.empty())
        {
            return std::string(name);
        }
        // Off-table fallback. A Keyboard code emits bare hex ("0xNN"), which round-trips through the config
        // keyboard hex fallback and preserves the existing serialized form. Any other source is tagged with its
        // device name ("Mouse:0xNN") so the source is not lost: an untagged hex always parses back as Keyboard,
        // which would silently turn an off-table Mouse/Gamepad code into a keyboard key on a config round-trip.
        if (code.source == InputSource::Keyboard)
        {
            return format::format_hex(code.code, 2);
        }
        return std::string(input_source_to_string(code.source)) + ':' + format::format_hex(code.code, 2);
    }

} // namespace DetourModKit
