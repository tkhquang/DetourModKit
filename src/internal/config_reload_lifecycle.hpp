#ifndef DETOURMODKIT_INTERNAL_CONFIG_RELOAD_LIFECYCLE_HPP
#define DETOURMODKIT_INTERNAL_CONFIG_RELOAD_LIFECYCLE_HPP

/**
 * @file internal/config_reload_lifecycle.hpp
 * @brief Reload-pass and lifecycle-gate vocabulary owned by src/internal/config_reload.cpp.
 * @details The data-plane pass (config.cpp) and the watcher control plane (config_watch.cpp) reach the pass lock and
 *          the background-reload lifecycle gate through this seam. The state itself lives in one TU.
 */

#include <cstdint>
#include <mutex>

namespace DetourModKit::config::detail
{
    /**
     * @class ReloadApplyLock
     * @brief Guards a reload pass and fails fast on same-thread re-entry.
     * @details Serializes an entire load()/reload() pass: read, content-hash decision, and deferred-setter
     *          application. Setters run after the config mutex is released, so this separate lock prevents stale pass
     *          reorder. Acquire this lock FIRST, then the config mutex. Lock order against the watcher control mutex
     *          (config_watch.cpp): a pass-lock holder can take the watcher mutex (load()'s re-point does), but a
     *          watcher-mutex holder must not acquire this lock. The drain predicate reads only the atomic in-flight
     *          count under the watcher mutex. A refused same-thread re-entry stays disengaged, which lets the caller
     *          report failure without a wait.
     */
    class ReloadApplyLock
    {
    public:
        ReloadApplyLock();
        ~ReloadApplyLock() noexcept;

        ReloadApplyLock(const ReloadApplyLock &) = delete;
        ReloadApplyLock &operator=(const ReloadApplyLock &) = delete;

        /// Reports true for an acquired pass lock and false for a refused same-thread re-entry.
        [[nodiscard]] bool engaged() const noexcept { return m_engaged; }

        /// Releases the pass lock before load() performs a stale-watcher join. The operation is idempotent.
        void unlock() noexcept;

    private:
        std::unique_lock<std::mutex> m_lock;
        bool m_engaged{false};
    };

    /// Reports whether the current thread owns the reload pass lock (it runs inside a bound setter).
    [[nodiscard]] bool reload_apply_lock_held_by_current_thread() noexcept;

    /**
     * @class BackgroundReloadGuard
     * @brief Controls entry to a background reload pass from a watcher callback or hotkey servicer.
     * @details The captured lifecycle epoch must match an enabled lifecycle state before and after admission.
     *          Otherwise, the pass stops before it can call consumer code. While engaged, it holds the in-flight
     *          count for the whole pass. The check, increment, and recheck pair with the drain latch store and count
     *          load. A pass that unload misses also fails to engage.
     */
    class BackgroundReloadGuard
    {
    public:
        explicit BackgroundReloadGuard(std::uint64_t expected_epoch) noexcept;
        ~BackgroundReloadGuard() noexcept;

        BackgroundReloadGuard(const BackgroundReloadGuard &) = delete;
        BackgroundReloadGuard &operator=(const BackgroundReloadGuard &) = delete;

        /// Returns true when reloads are armed for this lifecycle and this pass can run consumer code.
        [[nodiscard]] bool engaged() const noexcept { return m_engaged; }

        /// Reports whether an admitted pass still belongs to its enabled lifecycle.
        [[nodiscard]] bool current() const noexcept;

    private:
        [[nodiscard]] bool lifecycle_current() const noexcept;

        std::uint64_t m_expected_epoch{0};
        bool m_engaged{false};
    };

    /// Returns the current reload lifecycle epoch with the unload latch masked off.
    [[nodiscard]] std::uint64_t current_reload_lifecycle_epoch() noexcept;

    /// Reports whether the background-reload unload latch is set.
    [[nodiscard]] bool background_reloads_disabled() noexcept;
} // namespace DetourModKit::config::detail

#endif // DETOURMODKIT_INTERNAL_CONFIG_RELOAD_LIFECYCLE_HPP
