#ifndef DETOURMODKIT_CONFIG_WATCHER_HPP
#define DETOURMODKIT_CONFIG_WATCHER_HPP

/**
 * @file config_watcher.hpp
 * @brief Filesystem watcher that triggers a callback when an INI file changes.
 */

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

namespace DetourModKit
{
    /**
     * @class ConfigWatcher
     * @brief Background watcher for a single INI config file.
     * @details Owns a StoppableWorker that opens the INI file's parent
     *          directory via ReadDirectoryChangesW and fires @p on_reload
     *          when the target file is modified. Consecutive change events
     *          within the debounce window collapse to a single callback so
     *          editor save-flurries (Notepad++ / VSCode atomic save,
     *          rename-swap-save, last-write-time tick) do not cause
     *          redundant reloads.
     *
     *          Detected change kinds:
     *            - FILE_NOTIFY_CHANGE_LAST_WRITE  (plain save in place)
     *            - FILE_NOTIFY_CHANGE_SIZE        (truncation or growth)
     *            - FILE_NOTIFY_CHANGE_FILE_NAME   (rename-swap-save pattern,
     *              where the editor writes to a sibling temp and renames it
     *              over the target)
     *
     *          Filename matching is case-insensitive (Windows filesystem
     *          convention). The watcher does not recurse into
     *          subdirectories.
     *
     *          Non-copyable, non-movable. The watcher owns a worker
     *          thread and a directory handle; neither would survive a
     *          duplicated or moved owner.
     *
     * @warning The @p on_reload callback is invoked on the watcher's
     *          background thread. Callers must handle their own
     *          synchronization if the callback touches shared state.
     *          Exceptions escaping the callback are caught by the
     *          underlying StoppableWorker and logged as errors; the
     *          watcher continues running.
     */
    class ConfigWatcher
    {
    public:
        /**
         * @brief Constructs a watcher for @p ini_path.
         * @param ini_path Absolute or relative path to the INI file to
         *                 monitor. The parent directory is opened for
         *                 change notifications; the file itself does not
         *                 need to exist at construction time.
         * @param debounce Quiet-window length. A callback fires only
         *                 after @p debounce has elapsed since the last
         *                 matching change event.
         * @param on_reload Callback invoked on the watcher thread when
         *                  a debounced change is observed. May be empty
         *                  to construct an inert watcher.
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
         * @details Idempotent. If the watcher is already running, the
         *          call is a no-op and returns true. The worker opens
         *          the parent directory and issues the first overlapped
         *          ReadDirectoryChangesW before signalling the main
         *          thread, so a true return means I/O is in flight.
         * @return true if the worker is (or already was) running.
         *         Returns false when the directory handle could not be
         *         opened, when the startup handshake timed out after
         *         5 seconds (e.g. a hostile hook on CreateFileW), or
         *         when the worker lambda threw before signalling -- in
         *         all three cases an error has already been logged and
         *         the watcher remains stopped.
         */
        [[nodiscard]] bool start();

        /**
         * @brief Stops the background watcher thread.
         * @details Idempotent. Safe to call before start() or multiple
         *          times. Blocks until the worker exits, unless the
         *          current thread holds the Windows loader lock, in
         *          which case the worker is detached (see
         *          StoppableWorker::shutdown()). Returns promptly
         *          (~100 ms bound) regardless.
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
         * @details Lets callers (in particular Config::disable_auto_reload)
         *          detect setter-induced self-calls and avoid joining the
         *          worker from the worker itself, which would otherwise
         *          raise std::system_error(resource_deadlock_would_occur).
         *          Returns false before start() has posted the first
         *          overlapped read and after stop() has joined the worker.
         * @param id The thread id to compare against.
         * @return true if @p id equals the worker's thread id.
         */
        [[nodiscard]] bool is_worker_thread(std::thread::id id) const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };
} // namespace DetourModKit

#endif // DETOURMODKIT_CONFIG_WATCHER_HPP
