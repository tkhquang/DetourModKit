/**
 * @file config_watch.cpp
 * @brief This TU owns the watcher control plane: the auto-reload watcher slot, the reload-hotkey servicer, and the
 *        persisted reload callback.
 *
 * The data-plane pass lives in config.cpp and the reload lifecycle gate in src/internal/config_reload.cpp. The other
 * planes reach this state through internal/config_watch_control.hpp.
 */

#include "DetourModKit/config.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/detail/worker.hpp"

#include "internal/config_pass.hpp"
#include "internal/config_reload_lifecycle.hpp"
#include "internal/config_watch_control.hpp"
#include "internal/config_watcher.hpp"
#include "internal/lifecycle_context.hpp"
#include "internal/lifecycle_reaper.hpp"
#include "internal/worker_start_log.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    // Test-only override for the loader-lock probe inside ~ReloadServicer's teardown gate.
    // It replaces only the veto result.
    // The explicit loader context remains the sole authorization.
    // One fixture thread sets and clears this plain function pointer.
    bool (*g_config_reload_loader_lock_override)() noexcept = nullptr;

    // ~ReloadServicer sets this flag on the off-thread reaper branch. A proof can observe self-retirement.
    std::atomic<bool> g_servicer_reaped_on_worker{false};

    // Parks the reload worker while it owns Channel::mutex. A subprocess can drive process-exit teardown after
    // Windows terminates the mutex owner.
    std::atomic<std::atomic<bool> *> g_config_reload_worker_mutex_gate_probe{nullptr};
    std::atomic<bool> g_config_reload_worker_mutex_waiting_probe{false};

    // Parks the reload worker after its last mutex use and before exit-guard publication. A test can keep the body
    // live but unexited across teardown.
    std::atomic<std::atomic<bool> *> g_config_reload_worker_exit_gate_probe{nullptr};

    // Fired immediately before config disposes of an internally retained reload-hotkey BindingGuard.
    void (*g_config_reload_hotkey_guard_disposal_probe)() noexcept = nullptr;
#endif
} // namespace DetourModKit::detail

namespace DetourModKit
{
    namespace config
    {
        namespace
        {
            // A separate mutex keeps watcher start/stop apart from registration traffic. It also serializes the reload
            // servicer and reload-hotkey guard vector.
            std::mutex &get_watcher_mutex()
            {
                static std::mutex s_mtx;
                return s_mtx;
            }

            std::unique_ptr<DetourModKit::detail::ConfigWatcher> &get_config_watcher()
            {
                static std::unique_ptr<DetourModKit::detail::ConfigWatcher> s_watcher;
                return s_watcher;
            }

            // Stores a copy of the user on_reload callback. ConfigWatcher swallows it with no getter, so only this
            // copy lets load()'s re-point reconstruct an equivalent watcher. get_watcher_mutex() guards it.
            std::function<void(bool)> &get_reload_user_callback() noexcept
            {
                static std::function<void(bool)> s_callback;
                return s_callback;
            }

            // This counter advances on each real disable_auto_reload() teardown. load() captures it before a stale-
            // watcher join and checks it before restart. A changed value prevents watcher resurrection after a
            // concurrent disable. An empty callback slot still represents a valid enabled state. get_watcher_mutex()
            // guards the counter.
            [[nodiscard]] std::uint64_t &get_watcher_disable_generation() noexcept
            {
                static std::uint64_t s_generation = 0;
                return s_generation;
            }

            // Compares two resolved INI paths without case sensitivity. Separators and normalization already match.
            // An ordinal ASCII fold is correct for case-insensitive Windows paths. A locale fold is
            // deliberately avoided, per the watcher's ordinal filename match.
            [[nodiscard]] bool resolved_paths_equivalent(std::string_view a, std::string_view b) noexcept
            {
                if (a.size() != b.size())
                {
                    return false;
                }
                const auto ascii_lower = [](char c) noexcept -> unsigned char
                {
                    const auto u = static_cast<unsigned char>(c);
                    return (u >= 'A' && u <= 'Z') ? static_cast<unsigned char>(u + ('a' - 'A')) : u;
                };
                for (size_t i = 0; i < a.size(); ++i)
                {
                    if (ascii_lower(a[i]) != ascii_lower(b[i]))
                    {
                        return false;
                    }
                }
                return true;
            }

            // Keeps reload-hotkey BindingGuards alive for the process lifetime. ~BindingGuard disables the binding,
            // so a dropped returned guard makes the hotkey a silent no-op forever. Guarded by
            // get_watcher_mutex().
            std::vector<input::BindingGuard> &get_reload_hotkey_guards() noexcept
            {
                static std::vector<input::BindingGuard> s_guards;
                return s_guards;
            }

            void run_reload_hotkey_guard_disposal_probe() noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (const auto probe = DetourModKit::detail::g_config_reload_hotkey_guard_disposal_probe)
                {
                    probe();
                }
#endif
            }

            // ~ReloadServicer uses this to choose join versus detach-and-leak. This matches the ConfigWatcher
            // destructor's watcher_must_not_block().
            bool reload_servicer_must_not_block() noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                return !DetourModKit::detail::blocking_teardown_permitted(
                    DetourModKit::detail::g_config_reload_loader_lock_override
                );
#else
                return !DetourModKit::detail::blocking_teardown_permitted();
#endif
            }

            /**
             * @class ReloadServicer
             * @brief Owns a background thread that coalesces reload-hotkey presses and invokes reload() off the input
             *        poll thread at most once per press batch.
             * @details All state the worker touches lives in a heap-owned @ref Channel.
             *          It is separate from the servicer shell. The loader-lock teardown branch can detach the worker
             *          and leak the Channel under the ConfigWatcher discipline. It starts on the first reload_hotkey
             *          call.
             *          A std::shared_ptr prevents a press callback concurrent with shutdown from access to a freed
             *          servicer.
             *          The worker contains exceptions from reload(), so the service remains alive.
             */
            class ReloadServicer
            {
                // Channel stores every field that the worker reads. The worker member appears last, so ~Channel
                // destroys it first and joins before the mutex or condition variable dies.
                struct Channel
                {
                    std::mutex mutex;
                    std::condition_variable cv;
                    std::atomic<bool> reload_requested{false};
                    std::atomic<bool> shutdown{false};
                    std::atomic<bool> worker_exited{false};
                    // service_loop publishes this value on entry and clears it on exit. ~ReloadServicer can then detect
                    // a self-join. config::clear() from a reload setter runs on this worker thread.
                    std::atomic<std::thread::id> worker_tid{};
                    // Lifecycle epoch captured at construction so superseded servicers cannot enter consumer code.
                    std::uint64_t birth_epoch{0};
                    std::unique_ptr<DetourModKit::StoppableWorker> worker;
                };

            public:
                /**
                 * @brief Starts the reload service and records its canonical worker start line.
                 * @param diags Receives the worker start line for later emission.
                 */
                explicit ReloadServicer(detail::DeferredDiagnostics &diags) : m_channel(std::make_unique<Channel>())
                {
                    // Launch the worker against the heap-owned Channel, NOT `this`. The loader-lock teardown branch
                    // leaks the Channel, so the body must use storage that outlives the shell.
                    m_channel->birth_epoch = detail::current_reload_lifecycle_epoch();
                    Channel *channel = m_channel.get();
                    const DetourModKit::detail::WorkerStartLogDeferral start_log_deferral{
                        &diags,
                        &detail::defer_worker_start_diagnostic,
                    };
                    m_channel->worker = std::make_unique<DetourModKit::StoppableWorker>(
                        "ConfigReloadServicer",
                        [channel](std::stop_token st) { service_loop(*channel, std::move(st)); }
                    );
                }

                ~ReloadServicer() noexcept
                {
                    if (!m_channel)
                    {
                        return;
                    }
                    if (reload_servicer_must_not_block())
                    {
                        // The worker can own the Channel mutex when process-exit teardown begins, so publish only the
                        // lock-free shutdown hint and detach without callback invocation. The wake is best-effort by
                        // construction. A servicer parked in cv.wait can stay parked for process lifetime.
                        // This does not strand resources because this branch retains the Channel and module reference.
                        m_channel->shutdown.store(true, std::memory_order_release);
                        m_channel->cv.notify_all();
                        if (m_channel->worker)
                        {
                            m_channel->worker->shutdown();
                        }

                        // The detached service_loop can still read the Channel, so retain it for process lifetime.
                        (void)m_channel.release();
                        DetourModKit::diagnostics::record_intentional_leak(
                            DetourModKit::diagnostics::LeakSubsystem::Worker
                        );
                        return;
                    }

                    // Synchronous teardown is authorized. Serialize the shutdown predicate with the CV wait so the
                    // notification cannot land in its lost-wakeup window.
                    {
                        std::lock_guard<std::mutex> lock(m_channel->mutex);
                        m_channel->shutdown.store(true, std::memory_order_release);
                    }
                    m_channel->cv.notify_all();

                    const bool on_worker =
                        m_channel->worker_tid.load(std::memory_order_acquire) == std::this_thread::get_id();

                    if (on_worker)
                    {
                        // Self-shutdown off the loader lock cannot join this worker from itself because
                        // std::system_error results. Inline Channel destruction frees storage that service_loop uses.
                        // Hand the Channel to the off-thread reaper. It joins the worker, then destroys the Channel.
                        // No permanent leak remains.
#if defined(DMK_ENABLE_TEST_SEAMS)
                        DetourModKit::detail::g_servicer_reaped_on_worker.store(true, std::memory_order_release);
#endif
                        DetourModKit::detail::reap_owner(std::move(m_channel));
                        return;
                    }

                    // Off the loader lock and off the worker thread. shutdown() rechecks the teardown veto, so a join
                    // path can finish as a detach. Observe the body's exit publication, not another TOCTOU-prone veto
                    // check. Retain the Channel while the body remains active, as ~ConfigWatcher does. A leak is the
                    // safe direction.
                    if (m_channel->worker)
                    {
                        m_channel->worker->shutdown();
                    }
                    if (!m_channel->worker_exited.load(std::memory_order_acquire))
                    {
                        (void)m_channel.release();
                        DetourModKit::diagnostics::record_intentional_leak(
                            DetourModKit::diagnostics::LeakSubsystem::Worker
                        );
                        return;
                    }
                    m_channel.reset();
                }

                ReloadServicer(const ReloadServicer &) = delete;
                ReloadServicer &operator=(const ReloadServicer &) = delete;
                ReloadServicer(ReloadServicer &&) = delete;
                ReloadServicer &operator=(ReloadServicer &&) = delete;

                /// Requests a reload without exceptions or allocations. The press callback must not throw.
                void request_reload() noexcept
                {
                    // Mutate the predicate under the channel mutex to close the waiter-side lost-wakeup window.
                    {
                        std::lock_guard<std::mutex> lock(m_channel->mutex);
                        m_channel->reload_requested.store(true, std::memory_order_release);
                    }
                    m_channel->cv.notify_one();
                }

                /// Requests worker stop without a join or callback-storage destruction.
                void request_stop() noexcept
                {
                    if (!m_channel)
                    {
                        return;
                    }
                    {
                        std::lock_guard<std::mutex> lock(m_channel->mutex);
                        m_channel->shutdown.store(true, std::memory_order_release);
                    }
                    m_channel->cv.notify_all();
                    if (m_channel->worker)
                    {
                        m_channel->worker->request_stop();
                    }
                }

                /// Returns true after worker body exit.
                [[nodiscard]] bool has_exited() const noexcept
                {
                    return m_channel != nullptr && m_channel->worker_exited.load(std::memory_order_acquire);
                }

                /**
                 * @brief Reports whether @p id is the servicer worker thread's id.
                 * @details Any teardown that can join this worker must query this first and skip. Otherwise it
                 *          self-joins or deadlocks. The default id never matches, so a reset slot cannot alias a live
                 *          query.
                 */
                [[nodiscard]] bool is_worker_thread(std::thread::id id) const noexcept
                {
                    if (!m_channel)
                    {
                        return false;
                    }
                    const std::thread::id worker = m_channel->worker_tid.load(std::memory_order_acquire);
                    return worker != std::thread::id{} && worker == id;
                }

            private:
                static void service_loop(Channel &channel, std::stop_token st) noexcept
                {
                    class ExitGuard
                    {
                    public:
                        explicit ExitGuard(Channel &owned_channel) noexcept : m_channel(owned_channel) {}
                        ~ExitGuard() noexcept
                        {
                            m_channel.worker_tid.store(std::thread::id{}, std::memory_order_release);
                            m_channel.worker_exited.store(true, std::memory_order_release);
                        }

                        ExitGuard(const ExitGuard &) = delete;
                        ExitGuard &operator=(const ExitGuard &) = delete;

                    private:
                        Channel &m_channel;
                    };

                    const ExitGuard exit_guard{channel};
                    DetourModKit::Logger &logger = DetourModKit::log();

                    // Publish our thread id for ~ReloadServicer's self-join detection. Clear it on exit so a later
                    // OS-recycled id cannot alias a dead worker.
                    channel.worker_tid.store(std::this_thread::get_id(), std::memory_order_release);

                    // Wake the CV on a stop request so the blocked wait exits promptly.
                    std::stop_callback stop_cb(
                        st,
                        [&channel]() -> void
                        {
                            {
                                std::lock_guard<std::mutex> lock(channel.mutex);
                                channel.shutdown.store(true, std::memory_order_release);
                            }
                            channel.cv.notify_all();
                        }
                    );

                    while (!st.stop_requested() && !channel.shutdown.load(std::memory_order_acquire))
                    {
                        {
                            std::unique_lock<std::mutex> lock(channel.mutex);
#if defined(DMK_ENABLE_TEST_SEAMS)
                            if (auto *gate = DetourModKit::detail::g_config_reload_worker_mutex_gate_probe.load(
                                    std::memory_order_acquire
                                ))
                            {
                                DetourModKit::detail::g_config_reload_worker_mutex_waiting_probe.store(
                                    true,
                                    std::memory_order_release
                                );
                                while (gate->load(std::memory_order_acquire))
                                {
                                    std::this_thread::yield();
                                }
                                DetourModKit::detail::g_config_reload_worker_mutex_waiting_probe.store(
                                    false,
                                    std::memory_order_release
                                );
                            }
#endif
                            channel.cv.wait(
                                lock,
                                [&]() noexcept
                                {
                                    return st.stop_requested() || channel.shutdown.load(std::memory_order_acquire) ||
                                           channel.reload_requested.load(std::memory_order_acquire);
                                }
                            );
                        }

                        if (st.stop_requested() || channel.shutdown.load(std::memory_order_acquire))
                        {
                            break;
                        }

                        // Coalesce: a burst of presses during the reload collapses into at most one follow-up pass.
                        while (channel.reload_requested.exchange(false, std::memory_order_acq_rel))
                        {
                            // Gate on the unload latch and this servicer's lifecycle epoch. Do not run setters into a
                            // Logic DLL under unload or a re-armed registry that belongs to a newer one.
                            detail::BackgroundReloadGuard reload_guard{channel.birth_epoch};
                            if (!reload_guard.engaged())
                            {
                                break;
                            }
                            try
                            {
                                bool setters_ran = false;
                                (void)detail::reload_impl(setters_ran, &reload_guard);
                            }
                            catch (const std::exception &e)
                            {
                                (void)logger
                                    .try_log(LogLevel::Error, "Config: reload servicer caught exception: {}", e.what());
                            }
                            catch (...)
                            {
                                (
                                    void
                                )logger.try_log(LogLevel::Error, "Config: reload servicer caught unknown exception.");
                            }
                        }
                    }

#if defined(DMK_ENABLE_TEST_SEAMS)
                    // Holds the body between its last channel.mutex use and the exit guard below. A concurrent teardown
                    // observes a worker that is provably live and lacks an exit publication.
                    if (auto *gate = DetourModKit::detail::g_config_reload_worker_exit_gate_probe.load(
                            std::memory_order_acquire
                        ))
                    {
                        while (gate->load(std::memory_order_acquire))
                        {
                            std::this_thread::yield();
                        }
                    }
#endif
                }

                std::unique_ptr<Channel> m_channel;
            };

            // A shared_ptr lets a press callback keep its own strong reference when clear() resets the slot.
            std::shared_ptr<ReloadServicer> &get_reload_servicer() noexcept
            {
                static std::shared_ptr<ReloadServicer> s_servicer;
                return s_servicer;
            }

            // start_watcher_locked creates an auto-reload watcher on a resolved path, then connects the persisted user
            // callback. The caller must hold get_watcher_mutex(). enable_auto_reload() and load()'s re-point use this
            // single construction site, so the presence guard and construction are atomic.
            [[nodiscard]] AutoReloadStatus start_watcher_locked(
                const std::string &resolved_path,
                std::chrono::milliseconds debounce,
                detail::DeferredDiagnostics &diags,
                DetourModKit::detail::ConfigWatcher::StartGate &start_gate,
                std::unique_ptr<DetourModKit::detail::ConfigWatcher> &failed_watcher
            )
            {
                auto &watcher = get_config_watcher();
                if (detail::background_reloads_disabled())
                {
                    return AutoReloadStatus::StartFailed;
                }
                // Guard on existence, not is_running(). A second caller otherwise can overwrite the unique_ptr before
                // the worker publishes its active state.
                if (watcher)
                {
                    detail::defer_diagnostic(
                        diags,
                        LogLevel::Warning,
                        "Config: Auto-reload watcher start skipped because a watcher is already present; "
                        "call disable_auto_reload() first."
                    );
                    return AutoReloadStatus::AlreadyRunning;
                }

                // Copy the persisted user callback into the reload lambda. The persisted slot must survive. A later
                // load()-driven re-point can then reconstruct an equivalent watcher.
                watcher = std::make_unique<DetourModKit::detail::ConfigWatcher>(
                    resolved_path,
                    debounce,
                    [user_cb = get_reload_user_callback(), birth_epoch = detail::current_reload_lifecycle_epoch()]()
                    {
                        // Gate the whole pass on the unload latch and this watcher's lifecycle epoch. The guard holds
                        // the in-flight count across BOTH the setter pass and the user callback.
                        detail::BackgroundReloadGuard reload_guard{birth_epoch};
                        if (!reload_guard.engaged())
                        {
                            return;
                        }
                        // Reload first so the user callback observes the refreshed values. setters_ran lets it
                        // distinguish a real reload from a skipped setter pass.
                        bool setters_ran = false;
                        (void)detail::reload_impl(setters_ran, &reload_guard);
                        // Re-check the latch. An unload can set it during the pass.
                        if (user_cb && reload_guard.current())
                        {
                            user_cb(setters_ran);
                        }
                    }
                );

                bool started = false;
                try
                {
                    started = watcher->start(diags, start_gate);
                }
                catch (...)
                {
                    failed_watcher = std::move(watcher);
                    get_reload_user_callback() = nullptr;
                    throw;
                }
                if (!started)
                {
                    failed_watcher = std::move(watcher);
                    // Drop the persisted callback with the failed watcher so it cannot pin Logic DLL references.
                    get_reload_user_callback() = nullptr;
                    try
                    {
                        detail::defer_diagnostic(
                            diags,
                            LogLevel::Error,
                            "Config: Auto-reload watcher failed to start for {}",
                            resolved_path
                        );
                    }
                    catch (...)
                    {
                        DetourModKit::detail::LoggerDropAccess::record(log());
                    }
                    return AutoReloadStatus::StartFailed;
                }
                return AutoReloadStatus::Started;
            }
        } // anonymous namespace

        namespace detail
        {
            void dispose_reload_hotkey_guards(std::vector<input::BindingGuard> &guards) noexcept
            {
                if (guards.empty())
                {
                    return;
                }
                run_reload_hotkey_guard_disposal_probe();
                guards.clear();
            }

            WatchRepoint detach_watcher_if_repointed(std::string_view loaded_resolved_path)
            {
                WatchRepoint result;
                DeferredDiagnostics diags = open_deferred_diagnostics();
                {
                    std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                    auto &watcher = get_config_watcher();
                    if (watcher)
                    {
                        if (!resolved_paths_equivalent(watcher->ini_path(), loaded_resolved_path))
                        {
                            if (watcher->is_worker_thread(std::this_thread::get_id()))
                            {
                                // Inline watcher destruction self-joins the worker. Report and skip the re-point under
                                // disable_auto_reload()'s self-join rule.
                                defer_diagnostic(
                                    diags,
                                    LogLevel::Error,
                                    "Config: load() switched the config file on the watcher thread; not "
                                    "re-pointing auto-reload to avoid a self-join. Re-point from another "
                                    "thread via disable_auto_reload()/enable_auto_reload()."
                                );
                            }
                            else
                            {
                                // Move the stale watcher out and preserve the persisted user callback for restart.
                                // Snapshot the disable generation under this lock for the lost-disable window check.
                                result.debounce = watcher->debounce();
                                result.generation_at_move = get_watcher_disable_generation();
                                result.stale = std::move(watcher);
                                result.repoint = true;
                            }
                        }
                    }
                }
                emit_deferred_diagnostics(diags);
                return result;
            }

            void restart_watcher_after_repoint(std::chrono::milliseconds debounce, std::uint64_t generation_at_move)
            {
                // Re-snapshot the latest remembered path and re-start under get_watcher_mutex(). A disable
                // generation bump since the move-out means a disable raced into the join window: honor it and
                // leave auto-reload OFF. The re-check and construction are one atomic step under the held lock.
                const std::string repoint_filename = snapshot_last_loaded_ini_path();
                DeferredDiagnostics diags = open_deferred_diagnostics();
                DetourModKit::detail::ConfigWatcher::StartGate start_gate;
                std::unique_ptr<DetourModKit::detail::ConfigWatcher> failed_watcher;
                try
                {
                    {
                        std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                        if (!repoint_filename.empty() && get_watcher_disable_generation() == generation_at_move)
                        {
                            const std::filesystem::path repoint_path = get_ini_file_path(repoint_filename, diags);
                            (
                                void
                            )start_watcher_locked(repoint_path.string(), debounce, diags, start_gate, failed_watcher);
                        }
                    }
                    emit_deferred_diagnostics(diags);
                }
                catch (...)
                {
                    DetourModKit::detail::ConfigWatcher::release_start_gate(start_gate);
                    failed_watcher.reset();
                    throw;
                }
                DetourModKit::detail::ConfigWatcher::release_start_gate(start_gate);
                failed_watcher.reset();
            }

            bool on_reload_servicer_thread() noexcept
            {
                std::lock_guard<std::mutex> lock(get_watcher_mutex());
                const std::shared_ptr<ReloadServicer> &servicer = get_reload_servicer();
                return servicer && servicer->is_worker_thread(std::this_thread::get_id());
            }

            WatchHotkeyControl detach_hotkey_control() noexcept
            {
                WatchHotkeyControl control;
                std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                control.guards = std::move(get_reload_hotkey_guards());
                control.servicer = std::move(get_reload_servicer());
                return control;
            }

            // Shared stop poke for both drain verbs. The caller holds get_watcher_mutex(). Returns false when the
            // caller is the watcher or servicer worker thread, without requesting any stop.
            [[nodiscard]] bool poke_stops_locked() noexcept
            {
                const auto &watcher = get_config_watcher();
                const auto &servicer = get_reload_servicer();
                if ((watcher && watcher->is_worker_thread(std::this_thread::get_id())) ||
                    (servicer && servicer->is_worker_thread(std::this_thread::get_id())))
                {
                    return false;
                }

                if (watcher)
                {
                    watcher->request_stop();
                }
                if (servicer)
                {
                    servicer->request_stop();
                }
                return true;
            }

            WatchStopPoke request_watch_stops_for_drain() noexcept
            {
                std::unique_lock<std::mutex> lock(get_watcher_mutex(), std::try_to_lock);
                if (!lock.owns_lock())
                {
                    return WatchStopPoke::LockBusy;
                }
                return poke_stops_locked() ? WatchStopPoke::Requested : WatchStopPoke::SelfDelivery;
            }

            WatchDrainState try_detach_watch_control(bool (*reloads_quiesced)() noexcept, WatchTeardown &out) noexcept
            {
                std::unique_lock<std::mutex> lock(get_watcher_mutex(), std::try_to_lock);
                if (!lock.owns_lock())
                {
                    return WatchDrainState::LockBusy;
                }
                if (!poke_stops_locked())
                {
                    return WatchDrainState::SelfDelivery;
                }
                const auto &watcher = get_config_watcher();
                const auto &servicer = get_reload_servicer();
                const bool workers_exited =
                    (!watcher || watcher->has_exited()) && (!servicer || servicer->has_exited());
                if (workers_exited && reloads_quiesced())
                {
                    out.watcher = std::move(get_config_watcher());
                    out.servicer = std::move(get_reload_servicer());
                    // std::function move assignment has no standard noexcept guarantee. Stage through the noexcept
                    // move constructor, then commit with the noexcept member swap.
                    std::function<void(bool)> detached_callback(std::move(get_reload_user_callback()));
                    out.callback.swap(detached_callback);
                    out.guards = std::move(get_reload_hotkey_guards());
                    ++get_watcher_disable_generation();
                    return WatchDrainState::Detached;
                }
                return WatchDrainState::Draining;
            }
        } // namespace detail

        AutoReloadStatus enable_auto_reload(std::chrono::milliseconds debounce, std::function<void(bool)> on_reload)
        {
            const std::string ini_filename = detail::snapshot_last_loaded_ini_path();

            Logger &logger = log();

            if (ini_filename.empty())
            {
                logger.warning("Config: enable_auto_reload() called before load(); watcher not started.");
                return AutoReloadStatus::NoPriorLoad;
            }

            // The path resolution runs before the watcher mutex, so it reaches the same absolute path load() uses.
            detail::DeferredDiagnostics diags = detail::open_deferred_diagnostics();
            std::filesystem::path ini_path = detail::get_ini_file_path(ini_filename, diags);
            std::string resolved_path = ini_path.string();
            DetourModKit::detail::ConfigWatcher::StartGate start_gate;
            std::unique_ptr<DetourModKit::detail::ConfigWatcher> failed_watcher;

            // Hold get_watcher_mutex() across publish-callback-then-start: a bounded start() stall is preferable to
            // a use-after-free if disable_auto_reload() destroyed the watcher mid-start().
            AutoReloadStatus status{AutoReloadStatus::StartFailed};
            try
            {
                status = [&]() -> AutoReloadStatus
                {
                    std::lock_guard<std::mutex> wlock(get_watcher_mutex());

                    if (detail::background_reloads_disabled())
                    {
                        return AutoReloadStatus::StartFailed;
                    }

                    // On a duplicate enable attempt, preserve the live watcher's callback. A new callback publication
                    // before this check makes a later re-point switch callbacks silently.
                    if (get_config_watcher())
                    {
                        detail::defer_diagnostic(
                            diags,
                            LogLevel::Warning,
                            "Config: enable_auto_reload() called while a watcher is already present; "
                            "call disable_auto_reload() first."
                        );
                        return AutoReloadStatus::AlreadyRunning;
                    }

                    // Persist a copy of the user callback for load()'s re-point, published under the watcher mutex
                    // before the construction helper reads it.
                    get_reload_user_callback() = std::move(on_reload);

                    return start_watcher_locked(resolved_path, debounce, diags, start_gate, failed_watcher);
                }();

                if (status == AutoReloadStatus::Started)
                {
                    try
                    {
                        detail::defer_diagnostic(
                            diags,
                            LogLevel::Info,
                            "Config: Auto-reload enabled for {} (debounce {} ms)",
                            resolved_path,
                            static_cast<long long>(debounce.count())
                        );
                    }
                    catch (...)
                    {
                        DetourModKit::detail::LoggerDropAccess::record(log());
                    }
                }
                detail::emit_deferred_diagnostics(diags);
            }
            catch (...)
            {
                DetourModKit::detail::ConfigWatcher::release_start_gate(start_gate);
                failed_watcher.reset();
                throw;
            }
            DetourModKit::detail::ConfigWatcher::release_start_gate(start_gate);
            failed_watcher.reset();
            return status;
        }

        void disable_auto_reload() noexcept
        {
            // A watcher join from a bound setter blocks on its final flush, which re-enters reload_impl and waits for
            // the pass lock this thread holds. Refuse to avoid deadlock.
            if (detail::reload_apply_lock_held_by_current_thread())
            {
                (void)log().try_log(
                    LogLevel::Error,
                    "Config: disable_auto_reload() called from a bound setter; ignoring to avoid "
                    "joining a watcher that may be waiting for the active reload pass."
                );
                return;
            }

            std::unique_ptr<DetourModKit::detail::ConfigWatcher> to_drop;
            bool self_join_refused = false;
            {
                std::lock_guard<std::mutex> wlock(get_watcher_mutex());
                auto &watcher = get_config_watcher();
                // Inline unique_ptr destruction on the watcher thread forces the worker to join itself. Report after
                // the unlock and return. To cancel inside a reload, release the binding guard or flip a caller-owned
                // flag.
                if (watcher && watcher->is_worker_thread(std::this_thread::get_id()))
                {
                    self_join_refused = true;
                }
                else
                {
                    to_drop = std::move(watcher);
                    // Drop the persisted re-point callback with its watcher so it cannot pin Logic DLL references.
                    get_reload_user_callback() = nullptr;
                    // Signal a load() re-point in its lost-disable window so it does not resurrect the watcher.
                    ++get_watcher_disable_generation();
                }
            }
            if (self_join_refused)
            {
                (void)log().try_log(
                    LogLevel::Error,
                    "Config: disable_auto_reload() called from the watcher thread; ignoring to avoid self-join "
                    "deadlock. Call from a different thread or disable the hotkey binding instead."
                );
                return;
            }
            // ~ConfigWatcher joins its worker outside our mutex.
        }

        bool reload_hotkey(std::string_view ini_key, std::string_view default_combo)
        {
            // An empty or opt-out default leaves the hotkey inert. Return false to expose that state.
            if (default_combo.empty())
            {
                log().warning(
                    "Config: reload_hotkey('{}', '<empty>') rejected; provide a non-empty default combo.",
                    std::string(ini_key)
                );
                return false;
            }

            // Pre-parse the default. The parser defers its own typo WARNING, and a NONE opt-out still returns false.
            detail::DeferredDiagnostics diags = detail::open_deferred_diagnostics();
            const input::KeyComboList parsed =
                detail::parse_key_combo_list(std::string(default_combo), diags, "Config reload hotkey");
            detail::emit_deferred_diagnostics(diags);
            if (parsed.empty())
            {
                return false;
            }

            // The INI key supplies a stable binding name, so repeat registrations update in place.
            std::string binding_name = "config_reload:" + std::string(ini_key);

            // Lazily spin up the reload servicer on the first hotkey registration, under get_watcher_mutex().
            std::shared_ptr<ReloadServicer> servicer;
            bool servicer_created = false;
            {
                std::lock_guard<std::mutex> lock(get_watcher_mutex());
                if (detail::background_reloads_disabled())
                {
                    return false;
                }
                auto &slot = get_reload_servicer();
                if (!slot)
                {
                    slot = std::make_shared<ReloadServicer>(diags);
                    servicer_created = true;
                }
                servicer = slot;
            }

            if (servicer_created)
            {
                detail::emit_deferred_diagnostics(diags);
            }

            input::BindingGuard guard = press_combo(
                "Input",
                ini_key,
                "Config reload hotkey",
                binding_name,
                [servicer]() noexcept
                {
                    // Press callbacks run on the poll thread and must return promptly. Defer the reload to the
                    // servicer thread. The shared_ptr capture keeps the servicer alive.
                    if (servicer)
                    {
                        servicer->request_reload();
                    }
                },
                default_combo,
                std::nullopt
            );
            input::BindingGuard replaced_guard;
            bool replaced_existing = false;

            // Store the guard under the watcher mutex so its destructor does not disable the binding. Replace any
            // prior guard for the same INI key. Release the replaced guard outside the mutex. A release under this
            // mutex can wait on an unload drain whose callable disposal joins a worker that needs the same mutex.
            {
                std::lock_guard<std::mutex> lock(get_watcher_mutex());
                if (detail::background_reloads_disabled())
                {
                    return false;
                }
                auto &guards = get_reload_hotkey_guards();
                for (auto it = guards.begin(); it != guards.end(); ++it)
                {
                    if (it->name() == binding_name)
                    {
                        replaced_guard = std::move(*it);
                        replaced_existing = true;
                        guards.erase(it);
                        break;
                    }
                }
                guards.emplace_back(std::move(guard));
            }
            if (replaced_existing)
            {
                run_reload_hotkey_guard_disposal_probe();
                replaced_guard.release();
            }

            return true;
        }
    } // namespace config

#if defined(DMK_ENABLE_TEST_SEAMS)
    namespace detail
    {
        // Requests one servicer-thread reload without synthetic key input. Returns false if no servicer exists.
        bool request_servicer_reload_for_test() noexcept
        {
            std::shared_ptr<config::ReloadServicer> servicer;
            {
                std::lock_guard<std::mutex> lock(config::get_watcher_mutex());
                servicer = config::get_reload_servicer();
            }
            if (!servicer)
            {
                return false;
            }
            servicer->request_reload();
            return true;
        }

        void lock_config_watcher_mutex_for_test() noexcept
        {
            std::lock_guard<std::mutex> lock(config::get_watcher_mutex());
        }

        // Reports whether the watcher control mutex is free right now. A record producer cannot pass this probe under
        // the same non-recursive mutex.
        bool config_watcher_mutex_free_for_test() noexcept
        {
            std::unique_lock<std::mutex> probe(config::get_watcher_mutex(), std::try_to_lock);
            return probe.owns_lock();
        }
    } // namespace detail
#endif
} // namespace DetourModKit
