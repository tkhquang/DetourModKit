/**
 * @file routed_bypass_provider.cpp
 * @brief Supplies an isolated module page for the XInput continuation proof.
 */

#include <cstdint>

extern "C"
{
    __declspec(dllexport) alignas(4096) std::uint8_t XInputGetState[4096]{};
}
