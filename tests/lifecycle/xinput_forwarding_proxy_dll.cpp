/**
 * @file xinput_forwarding_proxy_dll.cpp
 * @brief Synthetic XInput proxy whose ordinal-100 export forwards to another fixture DLL.
 * @details XInputGetState remains local and hookable. The paired .def forwards ordinal 100 to a compatible function in
 *          the local-export fixture, making GetProcAddress return an address outside this module.
 */

#include <windows.h>
#include <xinput.h>

// The .def owns the export table. Touching both parameters keeps a hookable prologue in optimized builds.
extern "C" DWORD WINAPI XInputGetState(DWORD user_index, XINPUT_STATE *state) noexcept
{
    if (state != nullptr)
    {
        *state = XINPUT_STATE{};
        state->dwPacketNumber = user_index;
    }
    return ERROR_DEVICE_NOT_CONNECTED;
}
