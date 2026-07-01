#include <DetourModKit/dmk.hpp>

/*
 * dmk.hpp is the umbrella + process-lifecycle surface, but it does not pull in these two demote-candidate headers.
 * Include them directly so the installed package's non-umbrella-reachable headers are also compile-checked against the
 * consumer toolchain by this smoke test.
 */
#include <DetourModKit/srw_shared_mutex.hpp>
#include <DetourModKit/win_file_stream.hpp>

int main()
{
    static_assert(DMK_VERSION_AT_LEAST(0, 0, 0));

    if (DetourModKit::hook::is_target_hooked(DetourModKit::Address{0}))
    {
        return 1;
    }

    // Exercise the v4 lifecycle surface end to end: start a Session for the current process (no gate, no
    // single-instance guard), then let it destruct to run the ordered teardown. This links the whole Session +
    // subsystem-teardown path.
    if (auto session = DetourModKit::Session::start(DetourModKit::ModInfo{}); !session.has_value())
    {
        return 2;
    }
    // ~Session ran the ordered teardown when `session` left the if-statement scope.
    return 0;
}
