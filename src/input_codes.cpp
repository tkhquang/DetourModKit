/**
 * @file input_codes.cpp
 * @brief Implementation of named input code resolution and formatting.
 *
 * Provides the name lookup table and resolution functions for converting between
 * human-readable input names (e.g., "Ctrl", "Mouse4", "Gamepad_A") and their
 * corresponding InputCode values.
 */

#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/format.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace DetourModKit
{
    namespace
    {
        struct NameEntry
        {
            const char *name;
            InputCode code;
        };

        // clang-format off
        constexpr NameEntry name_table[] = {
            // --- Keyboard: Modifiers ---
            {"Ctrl",        {InputSource::Keyboard, 0x11}},
            {"LCtrl",       {InputSource::Keyboard, 0xA2}},
            {"RCtrl",       {InputSource::Keyboard, 0xA3}},
            {"Shift",       {InputSource::Keyboard, 0x10}},
            {"LShift",      {InputSource::Keyboard, 0xA0}},
            {"RShift",      {InputSource::Keyboard, 0xA1}},
            {"Alt",         {InputSource::Keyboard, 0x12}},
            {"LAlt",        {InputSource::Keyboard, 0xA4}},
            {"RAlt",        {InputSource::Keyboard, 0xA5}},

            // --- Keyboard: Function keys ---
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

            // --- Keyboard: Letters ---
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

            // --- Keyboard: Digits ---
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

            // --- Keyboard: Navigation ---
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

            // --- Keyboard: Common keys ---
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

            // --- Keyboard: Numpad ---
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

            // --- Mouse buttons ---
            {"Mouse1",     {InputSource::Mouse, 0x01}},
            {"Mouse2",     {InputSource::Mouse, 0x02}},
            {"Mouse3",     {InputSource::Mouse, 0x04}},
            {"Mouse4",     {InputSource::Mouse, 0x05}},
            {"Mouse5",     {InputSource::Mouse, 0x06}},

            // --- Gamepad buttons ---
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
        };
        // clang-format on

        constexpr size_t name_table_size = sizeof(name_table) / sizeof(name_table[0]);

        int icompare(std::string_view a, std::string_view b) noexcept
        {
            const size_t len = std::min(a.size(), b.size());
            for (size_t i = 0; i < len; ++i)
            {
                const int ca = std::tolower(static_cast<unsigned char>(a[i]));
                const int cb = std::tolower(static_cast<unsigned char>(b[i]));
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

        struct SortedNameIndex
        {
            size_t indices[name_table_size]{};
            size_t count = name_table_size;

            SortedNameIndex()
            {
                for (size_t i = 0; i < name_table_size; ++i)
                {
                    indices[i] = i;
                }
                std::sort(indices, indices + count, [](size_t a, size_t b)
                          { return icompare(name_table[a].name, name_table[b].name) < 0; });
            }
        };

        const SortedNameIndex &get_sorted_index()
        {
            static const SortedNameIndex instance;
            return instance;
        }
        struct InputCodeHash
        {
            size_t operator()(const InputCode &c) const noexcept
            {
                return std::hash<int>{}(c.code) ^ (std::hash<uint8_t>{}(static_cast<uint8_t>(c.source)) << 16);
            }
        };

        struct CodeNameMap
        {
            std::unordered_map<InputCode, std::string_view, InputCodeHash> map;

            CodeNameMap()
            {
                map.reserve(name_table_size);
                for (size_t i = 0; i < name_table_size; ++i)
                {
                    map.emplace(name_table[i].code, name_table[i].name);
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
        const auto &idx = get_sorted_index();
        size_t lo = 0;
        size_t hi = idx.count;
        while (lo < hi)
        {
            const size_t mid = lo + (hi - lo) / 2;
            const int cmp = icompare(name_table[idx.indices[mid]].name, name);
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
                return name_table[idx.indices[mid]].code;
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
        auto name = input_code_to_name(code);
        if (!name.empty())
        {
            return std::string(name);
        }
        return Format::format_hex(code.code, 2);
    }

} // namespace DetourModKit
