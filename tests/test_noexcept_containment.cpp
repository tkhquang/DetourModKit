/**
 * @file test_noexcept_containment.cpp
 * @brief Pins the standard-lock exception facts from AGENTS.md.
 *
 * Live standard locks and waits need no local wrapper. Static assertions pin the cited type and boundary contracts.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/memory.hpp"

#include "internal/config_diagnostics.hpp"
#include "internal/config_watch_control.hpp"
#include "internal/input_poller.hpp"
#include "internal/srw_shared_mutex.hpp"

#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

namespace
{
    using DetourModKit::detail::SrwSharedMutex;

    // SrwSharedMutex wraps SRWLOCK, which reports no failure. Its unique and shared lock operations cannot throw.
    static_assert(noexcept(std::declval<SrwSharedMutex &>().lock()), "SrwSharedMutex::lock must not throw");
    static_assert(noexcept(std::declval<SrwSharedMutex &>().unlock()), "SrwSharedMutex::unlock must not throw");
    static_assert(
        noexcept(std::declval<SrwSharedMutex &>().lock_shared()),
        "SrwSharedMutex::lock_shared must not throw"
    );
    static_assert(
        noexcept(std::declval<SrwSharedMutex &>().unlock_shared()),
        "SrwSharedMutex::unlock_shared must not throw"
    );

    // Each watcher detach commits through a no-throw move. An unsafe move makes the exception false.
    static_assert(
        std::is_nothrow_move_assignable_v<std::vector<DetourModKit::input::BindingGuard>>,
        "the hotkey guard list must use a no-throw move"
    );
    static_assert(
        std::is_nothrow_move_assignable_v<std::function<void(bool)>>,
        "the persisted reload callback must use a no-throw move"
    );
    static_assert(
        std::is_nothrow_move_assignable_v<std::shared_ptr<void>>,
        "the type-erased servicer owner must use a no-throw move"
    );
    static_assert(
        std::is_nothrow_move_constructible_v<DetourModKit::config::detail::WatchHotkeyControl>,
        "detach_hotkey_control must use a no-throw return move"
    );
    static_assert(
        std::is_nothrow_move_assignable_v<DetourModKit::config::detail::DeferredDiagnostics>,
        "the startup diagnostic channel must use a no-throw move"
    );

    // A lost noexcept specifier puts the site back under the containment rule.
    static_assert(noexcept(DetourModKit::config::detail::on_reload_servicer_thread()));
    static_assert(noexcept(DetourModKit::config::detail::detach_hotkey_control()));
    static_assert(noexcept(DetourModKit::memory::clear_cache()));
    static_assert(noexcept(std::declval<const DetourModKit::detail::InputPoller &>().binding_count()));
    static_assert(noexcept(std::declval<const DetourModKit::detail::InputPoller &>().acquire_binding_token("")));
    static_assert(noexcept(std::declval<DetourModKit::detail::InputPoller &>().set_consume("", true)));
} // namespace

TEST(NoexceptContainmentProof, CitedSynchronizationBoundariesStayNoexcept)
{
    // Static assertions carry the proof. These calls preserve link coverage for two fixture-free boundaries.
    EXPECT_NO_THROW(DetourModKit::memory::clear_cache());
    EXPECT_FALSE(DetourModKit::config::detail::on_reload_servicer_thread());
}
