#include <DetourModKit.hpp>

// The umbrella header above does not pull in these public headers. Include them directly so the installed package's
// non-umbrella-reachable headers are also compile-checked against the consumer toolchain by this smoke test.
#include <DetourModKit/srw_shared_mutex.hpp>
#include <DetourModKit/win_file_stream.hpp>

int main()
{
    static_assert(DMK_VERSION_AT_LEAST(0, 0, 0));

    if (DetourModKit::hook::is_target_hooked(DetourModKit::Address{0}))
    {
        return 1;
    }

    DMK_Shutdown();
    return 0;
}
