#include <DetourModKit.hpp>

int main()
{
    static_assert(DMK_VERSION_AT_LEAST(0, 0, 0));

    auto &hook_manager = DetourModKit::HookManager::get_instance();
    if (hook_manager.is_target_already_hooked(0))
    {
        return 1;
    }

    DMK_Shutdown();
    return 0;
}
