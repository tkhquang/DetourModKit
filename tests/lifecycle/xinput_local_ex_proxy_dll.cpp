/**
 * @file xinput_local_ex_proxy_dll.cpp
 * @brief Synthetic XInput proxy whose primary and ordinal-100 exports both live in the module.
 * @details The ordinal-100 function is the positive control for the forwarding guard and the compatible target of the
 *          forwarding fixture.
 */

#include <windows.h>
#include <xinput.h>

extern "C" DWORD WINAPI XInputGetState(DWORD user_index, XINPUT_STATE *state) noexcept
{
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
    if (state != nullptr)
    {
        *state = XINPUT_STATE{};
        state->dwPacketNumber = user_index + 1u;
    }
    return ERROR_DEVICE_NOT_CONNECTED;
}
