// Proves the process-lifecycle surface is usable from its own header alone: a consumer that only needs
// Session / bootstrap / ModInfo can include DetourModKit/session.hpp without pulling in the whole umbrella. This
// translation unit deliberately includes NOTHING else from DetourModKit, so a missing include in session.hpp would
// fail this compile -- that compile is the real assertion; the runtime body below just anchors a gtest case.
#include "DetourModKit/session.hpp"

#include <gtest/gtest.h>

#include <type_traits>
#include <utility>

namespace
{
    using DetourModKit::ModInfo;
    using DetourModKit::Session;

    // Session is move-only: its teardown and single-instance guard cannot be copied (the session.hpp contract).
    static_assert(std::is_move_constructible_v<Session>);
    static_assert(std::is_move_assignable_v<Session>);
    static_assert(!std::is_copy_constructible_v<Session>);
    static_assert(!std::is_copy_assignable_v<Session>);

    // The synchronous factory returns a Result<Session>; the Result vocabulary is reachable from this header alone.
    static_assert(std::is_same_v<decltype(Session::start(std::declval<const ModInfo &>())),
                                 DetourModKit::Result<Session>>);
} // namespace

TEST(SessionHeader, ProcessLifecycleSurfaceIsUsableFromItsOwnHeader)
{
    // ModInfo is an aggregate of borrowed views; building one from literals must compile against session.hpp alone.
    ModInfo info{};
    info.name = "StandaloneHeaderProbe";
    info.log_file = "probe.log";
    EXPECT_EQ(info.name, "StandaloneHeaderProbe");
    EXPECT_TRUE(info.game_process_name.empty());

    // The free lifecycle entry points are all named by this header: module_handle() is reachable and callable without
    // the umbrella (its value depends on prior bootstrap() calls in the shared test process, so it is not asserted).
    static_assert(std::is_same_v<decltype(DetourModKit::module_handle()), DetourModKit::ModuleHandle>);
}
