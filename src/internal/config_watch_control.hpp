#ifndef DETOURMODKIT_INTERNAL_CONFIG_WATCH_CONTROL_HPP
#define DETOURMODKIT_INTERNAL_CONFIG_WATCH_CONTROL_HPP

/**
 * @file internal/config_watch_control.hpp
 * @brief Watcher control-plane vocabulary owned by config_watch.cpp.
 * @details The watcher slot, the reload servicer, the persisted user callback, the disable generation, and the
 *          reload-hotkey guards live behind one control mutex in config_watch.cpp. load()'s re-point, clear()'s
 *          disposal, and the unload drain reach that state through this seam. The servicer type stays private, so the
 *          moved-out owner is type-erased.
 */

#include "internal/config_watcher.hpp"

#include "DetourModKit/input.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

namespace DetourModKit::config::detail
{
    /**
     * @struct WatchRepoint
     * @brief A stale watcher detached for load()'s re-point, plus the restart facts captured under the control mutex.
     * @details The caller joins @ref stale outside every config mutex, then restarts through
     *          @ref restart_watcher_after_repoint with the captured debounce and disable generation.
     */
    struct WatchRepoint
    {
        std::unique_ptr<DetourModKit::detail::ConfigWatcher> stale;
        std::chrono::milliseconds debounce{};
        std::uint64_t generation_at_move{0};
        bool repoint{false};
    };

    /**
     * @brief Detaches the live watcher when load() switched the config file out from under it.
     * @details Path comparison is the watcher's ordinal case-insensitive match. On the watcher's own worker thread the
     *          re-point is refused with an error log, because inline watcher destruction self-joins the worker.
     */
    [[nodiscard]] WatchRepoint detach_watcher_if_repointed(std::string_view loaded_resolved_path);

    /**
     * @brief Restarts the auto-reload watcher after load()'s stale-watcher join.
     * @details Re-snapshots the remembered INI path and re-starts under the control mutex. A disable-generation bump
     *          since the move-out means a disable raced into the join window: it is honored and auto-reload stays off.
     */
    void restart_watcher_after_repoint(std::chrono::milliseconds debounce, std::uint64_t generation_at_move);

    /// Reports whether the current thread is the reload servicer's worker thread.
    [[nodiscard]] bool on_reload_servicer_thread() noexcept;

    /**
     * @struct WatchHotkeyControl
     * @brief The reload-hotkey guards and the type-erased servicer owner moved out for disposal outside the mutex.
     */
    struct WatchHotkeyControl
    {
        std::vector<input::BindingGuard> guards;
        std::shared_ptr<void> servicer;
    };

    /// Moves the hotkey guards and servicer out under the control mutex. The caller disposes after unlock.
    [[nodiscard]] WatchHotkeyControl detach_hotkey_control() noexcept;

    /// Disposes reload-hotkey guards and runs the disposal probe once when any guard exists.
    void dispose_reload_hotkey_guards(std::vector<input::BindingGuard> &guards) noexcept;

    /// Outcome of the drain's non-blocking stop request against the watcher control plane.
    enum class WatchStopPoke
    {
        /// Another thread owns the control mutex. The disabled lifecycle latch already blocks consumer entry.
        LockBusy,
        /// The caller is the watcher or servicer worker thread and cannot drain itself.
        SelfDelivery,
        /// Stop was requested on every live worker.
        Requested
    };

    /// Requests watcher and servicer stop without joining, under a non-blocking control-mutex attempt.
    [[nodiscard]] WatchStopPoke request_watch_stops_for_drain() noexcept;

    /**
     * @struct WatchTeardown
     * @brief Watcher control-plane ownership moved out by a completed drain detach.
     */
    struct WatchTeardown
    {
        std::unique_ptr<DetourModKit::detail::ConfigWatcher> watcher;
        std::shared_ptr<void> servicer;
        std::function<void(bool)> callback;
        std::vector<input::BindingGuard> guards;
    };

    /// Outcome of one drain-poll iteration over the watcher control plane.
    enum class WatchDrainState
    {
        /// The control mutex was busy this iteration.
        LockBusy,
        /// The caller is the watcher or servicer worker thread.
        SelfDelivery,
        /// A worker body or reload pass is still live.
        Draining,
        /// Every worker exited and reloads quiesced. Ownership moved into the out parameter.
        Detached
    };

    /**
     * @brief One drain-poll step: re-requests stops, then detaches the control plane once every body exited.
     * @param reloads_quiesced Caller predicate for "no background reload pass is in flight", evaluated under the held
     *        control mutex in the same iteration as the worker-exit check.
     * @param out Receives detached ownership on @ref WatchDrainState::Detached. It stays untouched otherwise. The
     *        disable generation advances with the detach.
     */
    [[nodiscard]] WatchDrainState try_detach_watch_control(bool (*reloads_quiesced)() noexcept,
                                                           WatchTeardown &out) noexcept;
} // namespace DetourModKit::config::detail

#endif // DETOURMODKIT_INTERNAL_CONFIG_WATCH_CONTROL_HPP
