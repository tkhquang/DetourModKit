#ifndef DETOURMODKIT_INTERNAL_CONFIG_WATCHER_HPP
#define DETOURMODKIT_INTERNAL_CONFIG_WATCHER_HPP

/**
 * @file config_watcher.hpp
 * @brief Internal filesystem watcher engine that triggers a callback when an INI file changes.
 * @details This is the private engine that backs config::enable_auto_reload / disable_auto_reload. It is reached only
 *          through the config module's pimpl orchestration, carries the Win32 ReadDirectoryChangesW pump, and is never
 *          installed. The config surface owns the watcher's lifetime; consumers do not see this type.
 */

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

namespace DetourModKit::detail
{
    /**
     * @class ConfigWatcher
     * @brief Background watcher for a single INI config file.
     * @details Owns a StoppableWorker that opens the INI file's parent directory via ReadDirectoryChangesW and fires @p
     *          on_reload when the target file is modified. Consecutive change events within the debounce window
     *          collapse to a single callback so editor save-flurries (Notepad++ / VSCode atomic save, rename-swap-save,
     *          last-write-time tick) do not cause redundant reloads.
     *
     *          Detected change kinds:
     *            - FILE_NOTIFY_CHANGE_LAST_WRITE  (plain save in place)
     *            - FILE_NOTIFY_CHANGE_SIZE        (truncation or growth)
     *            - FILE_NOTIFY_CHANGE_FILE_NAME   (rename-swap-save pattern,
     *              where the editor writes to a sibling temp and renames it over the target)
     *
     *          Filename matching is case-insensitive (Windows filesystem convention). The watcher does not recurse into
     *          subdirectories.
     *
     *          Non-copyable, non-movable. The watcher owns a worker thread and a directory handle; neither would
     *          survive a duplicated or moved owner.
     *
     * @warning The @p on_reload callback is invoked on the watcher's background thread. Callers must handle their own
     *          synchronization if the callback touches shared state. Exceptions escaping the callback are caught by the
     *          underlying StoppableWorker and logged as errors; the watcher continues running.
     */
    class ConfigWatcher
    {
    public:
        /**
         * @brief Constructs a watcher for @p ini_path.
         * @param ini_path Absolute or relative path to the INI file to monitor. The parent directory is opened for
         *                 change notifications; the file itself does not need to exist at construction time.
         * @param debounce Quiet-window length. A callback fires only after @p debounce has elapsed since the last
         *                 matching change event.
         * @param on_reload Callback invoked on the watcher thread when a debounced change is observed. May be empty to
         *                  construct an inert watcher.
         */
        explicit ConfigWatcher(std::string_view ini_path,
                               std::chrono::milliseconds debounce = std::chrono::milliseconds{250},
                               std::function<void()> on_reload = {});

        ~ConfigWatcher() noexcept;

        ConfigWatcher(const ConfigWatcher &) = delete;
        ConfigWatcher &operator=(const ConfigWatcher &) = delete;
        ConfigWatcher(ConfigWatcher &&) = delete;
        ConfigWatcher &operator=(ConfigWatcher &&) = delete;

        /**
         * @brief Starts the background watcher thread.
         * @details Idempotent. If the watcher is already running, the call is a no-op and returns true. The worker
         *          opens the parent directory and issues the first overlapped
         *          ReadDirectoryChangesW before signalling the main thread, so a true return means I/O is in flight.
         * @return true if the worker is (or already was) running. Returns false when the directory handle could not be
         *         opened, when the startup handshake timed out after
         *         5 seconds (e.g. a hostile hook on CreateFileW), or when the worker lambda threw before signalling --
         *         in all three cases an error has already been logged and the watcher remains stopped.
         */
        [[nodiscard]] bool start();

        /**
         * @brief Stops the background watcher thread.
         * @details Idempotent. Safe to call before start() or multiple times. Blocks until the worker exits, unless the
         *          current thread holds the Windows loader lock, in which case the worker is detached (see
         *          StoppableWorker::shutdown()). Returns promptly (~100 ms bound) regardless.
         * @note A change that arrived within the debounce window but had not yet fired triggers one final @p on_reload
         *       callback during this stop, so stop() does not guarantee that no further callback runs. Callers that
         *       must observe no callback after stopping should latch their own flag.
         */
        void stop() noexcept;

        /**
         * @brief Returns true while the watcher thread is still alive.
         */
        [[nodiscard]] bool is_running() const noexcept;

        /**
         * @brief Returns the INI file path this watcher is monitoring.
         */
        [[nodiscard]] const std::string &ini_path() const noexcept;

        /**
         * @brief Returns the configured debounce duration.
         */
        [[nodiscard]] std::chrono::milliseconds debounce() const noexcept;

        /**
         * @brief Returns true if @p id names the background worker thread.
         * @details Lets a stop request detect a setter-induced self-call (a reload callback that, running on the worker
         *          thread, tries to tear the watcher down) and avoid joining the worker from the worker itself, which
         *          would otherwise raise
         *          std::system_error(resource_deadlock_would_occur). The worker publishes its id when its thread
         *          starts (before the first overlapped read is issued) and clears it on exit, so this returns false
         *          before the worker thread has started and after the worker has exited (including after stop() has
         *          joined it); a later OS-recycled thread id therefore cannot alias a dead worker and suppress a real
         *          stop.
         * @param id The thread id to compare against.
         * @return true only while the worker is running and @p id equals its thread id; the default (no-thread) id
         *         never matches.
         */
        [[nodiscard]] bool is_worker_thread(std::thread::id id) const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_CONFIG_WATCHER_HPP
