/**
 * @file xinput_local_ex_proxy_dll.cpp
 * @brief Synthetic XInput proxy whose primary and ordinal-100 exports both live in the module.
 * @details The ordinal-100 function is the positive control for the forwarding guard and the compatible target of the
 *          forwarding fixture.
 */

#include <windows.h>
#include <xinput.h>

#include <array>
#include <atomic>

namespace
{
    std::atomic<bool> s_success_enabled{false};
    std::atomic<WORD> s_buttons{
        XINPUT_GAMEPAD_LEFT_SHOULDER | XINPUT_GAMEPAD_DPAD_UP | XINPUT_GAMEPAD_A | XINPUT_GAMEPAD_B
    };
    std::array<std::atomic<DWORD>, XUSER_MAX_COUNT> s_primary_packets{};
    std::array<std::atomic<DWORD>, XUSER_MAX_COUNT> s_ex_packets{};

    DWORD sample_success(DWORD user_index, XINPUT_STATE *state, bool ex) noexcept
    {
        if (state == nullptr)
            return ERROR_BAD_ARGUMENTS;
        if (user_index >= XUSER_MAX_COUNT)
            return ERROR_DEVICE_NOT_CONNECTED;

        auto &packets = ex ? s_ex_packets : s_primary_packets;
        *state = XINPUT_STATE{};
        state->dwPacketNumber = (ex ? 0x6000u : 0x4000u) + user_index * 0x100u +
                                packets[user_index].fetch_add(1, std::memory_order_relaxed);
        state->Gamepad.wButtons = s_buttons.load(std::memory_order_relaxed);
        state->Gamepad.bLeftTrigger = static_cast<BYTE>(27u + user_index);
        state->Gamepad.bRightTrigger = static_cast<BYTE>(193u - user_index);
        state->Gamepad.sThumbLX = static_cast<SHORT>(-12345 + static_cast<int>(user_index));
        state->Gamepad.sThumbLY = static_cast<SHORT>(23456 - static_cast<int>(user_index));
        state->Gamepad.sThumbRX = static_cast<SHORT>(-23456 + static_cast<int>(user_index));
        state->Gamepad.sThumbRY = static_cast<SHORT>(12345 - static_cast<int>(user_index));
        return ERROR_SUCCESS;
    }
} // namespace

/** @brief Selects successful controller states before the host starts its callers. */
extern "C" void WINAPI dmk_xinput_set_success_state(BOOL enabled) noexcept
{
    for (auto &packets : s_primary_packets)
        packets.store(0, std::memory_order_relaxed);
    for (auto &packets : s_ex_packets)
        packets.store(0, std::memory_order_relaxed);
    s_success_enabled.store(enabled != FALSE, std::memory_order_release);
}

/** @brief Changes digital buttons without a provider byte change. */
extern "C" void WINAPI dmk_xinput_set_buttons(WORD buttons) noexcept
{
    s_buttons.store(buttons, std::memory_order_relaxed);
}

extern "C" DWORD WINAPI XInputGetState(DWORD user_index, XINPUT_STATE *state) noexcept
{
    if (s_success_enabled.load(std::memory_order_acquire))
        return sample_success(user_index, state, false);
    if (state != nullptr)
    {
        *state = XINPUT_STATE{};
        state->dwPacketNumber = user_index;
    }
    return ERROR_DEVICE_NOT_CONNECTED;
}

// The distinct result prevents identical-code folding with XInputGetState.
extern "C" DWORD WINAPI XInputGetStateExLocal(DWORD user_index, XINPUT_STATE *state) noexcept
{
    if (s_success_enabled.load(std::memory_order_acquire))
        return sample_success(user_index, state, true);
    if (state != nullptr)
    {
        *state = XINPUT_STATE{};
        state->dwPacketNumber = user_index + 1u;
    }
    return ERROR_DEVICE_NOT_CONNECTED;
}
