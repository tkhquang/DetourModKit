// Exercise enough compiled surface to require the DetourModKit archive, its private static dependency chain, and the
// WheelHost archive.
#include <DetourModKit.hpp>
#include <DetourModKit/abi/wheel_host.h>

#include <cstdint>
#include <cstdio>

int main()
{
    static_assert(DMK_VERSION_AT_LEAST(0, 0, 0));
    static_assert(DetourModKit::Address{}.raw() == 0, "Address{} must be the null address.");

#if defined(NDEBUG)
    const char *const built_configuration = "Release";
#else
    const char *const built_configuration = "Debug";
#endif
    std::printf("dmk_dual_config_consumer built %s\n", built_configuration);

    if (auto session = DetourModKit::Session::start(DetourModKit::ModInfo{}); !session.has_value())
    {
        return 1;
    }
    if (!DetourModKit::shutdown_and_wait())
    {
        return 2;
    }
    if (DetourModKit::hook::is_target_hooked(DetourModKit::Address{}))
    {
        return 3;
    }
    // A rejected ABI version reaches the WheelHost archive and starts no host.
    WheelHostTable table{};
    if (wheel_host_start(0, DMK_WHEELHOST_ABI_VERSION + 1U, static_cast<std::uint32_t>(sizeof(table)), &table) !=
        DMK_WHEELHOST_ERR_ABI)
    {
        return 4;
    }
    return 0;
}
