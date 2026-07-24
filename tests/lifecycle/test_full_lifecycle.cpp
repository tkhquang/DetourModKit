/**
 * @file test_full_lifecycle.cpp
 * @brief Long-lived host driving every process-global subsystem across repeated bootstrap generations.
 * @details Four scenarios, each its own process because their terminal states are mutually exclusive and none can be
 *          undone inside a shared test process:
 *
 *          - "cycles": repeated bootstrap -> use every process-global subsystem -> synchronous drain. Proves each
 *            generation retires cleanly enough for the next to start, which a single start/stop pair cannot.
 *          - "concurrent": two control threads drain the same generation. Exactly one owns the drain and the other is
 *            told so, rather than one returning before the session is actually down.
 *          - "misuse": invokes the bare-FreeLibrary detach entry while the worker is live. It must abandon and pin
 *            instead of waiting, and a later drain must refuse rather than pretend.
 *          - "exit": process exit with a live session, verifying the CRT teardown path (static destruction plus the
 *            memory-cache atexit handler) neither hangs nor faults with subsystem threads still running.
 *
 *          Built as a standalone executable (no test framework); the process exit code is the oracle. A hang is caught
 *          by the CTest TIMEOUT rather than by an assertion, which is the point of isolating these.
 */

#include "DetourModKit/config.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/profiler.hpp"
#include "DetourModKit/session.hpp"

#include "internal/lifecycle_context.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <process.h>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace
{
    using namespace std::chrono_literals;

    constexpr int CYCLE_COUNT = 6;
    constexpr auto READY_TIMEOUT = 20s;

#if defined(_MSC_VER)
#define DMK_PROOF_NOINLINE __declspec(noinline)
#else
#define DMK_PROOF_NOINLINE __attribute__((noinline))
#endif

    DMK_PROOF_NOINLINE int lifecycle_target(int x)
    {
        volatile int result = x;
        return result;
    }

    int lifecycle_detour(int x)
    {
        return x + 41;
    }

    /// Calls through a volatile indirection so the optimizer cannot fold the call past the patched entry.
    int call_unfolded(int (*function)(int), int value)
    {
        int (*const volatile indirect)(int) = function;
        return indirect(value);
    }

    /// Owns a unique scenario INI and removes it when normally destroyed.
    class ScratchIni
    {
    public:
        explicit ScratchIni(std::string tag)
            : m_path(
                  std::filesystem::temp_directory_path() /
                  ("dmk_full_lifecycle_" + tag + "_" + std::to_string(static_cast<unsigned long>(_getpid())) + ".ini"))
        {
        }

        ~ScratchIni() noexcept
        {
            std::error_code error;
            std::filesystem::remove(m_path, error);
        }

        ScratchIni(const ScratchIni &) = delete;
        ScratchIni &operator=(const ScratchIni &) = delete;
        ScratchIni(ScratchIni &&) = delete;
        ScratchIni &operator=(ScratchIni &&) = delete;

        [[nodiscard]] bool write(int value) const
        {
            std::ofstream ini(m_path);
            ini << "[Full]\nValue=" << value << "\n";
            return static_cast<bool>(ini);
        }

        [[nodiscard]] std::string string() const { return m_path.string(); }

    private:
        std::filesystem::path m_path;
    };

    /**
     * @brief One-shot gate the control thread waits on instead of sleeping for a fixed interval.
     * @note Every gate is owned by a shared_ptr the worker callback captures by value, so it outlives each
     *       wait()/signal() pair regardless of which side returns first.
     */
    class ReadyGate
    {
    public:
        void signal() noexcept
        {
            std::lock_guard lock(m_mutex);
            m_signalled = true;
            m_cv.notify_all();
        }

        [[nodiscard]] bool wait(std::chrono::milliseconds timeout)
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [this] { return m_signalled; });
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_signalled{false};
    };

    [[nodiscard]] bool fail(const char *scenario, const char *what)
    {
        std::fprintf(stderr, "FAIL[%s]: %s\n", scenario, what);
        return false;
    }

    // Bound by every generation's config registry. It must outlive each load()/reload() (the setter captures it by
    // reference and the auto-reload watcher can fire it at any time), so it cannot be a local of the worker frame that
    // registers it: the registry outlives that frame until the ordered teardown clears it.
    std::atomic<int> s_bound_value{0};

    /**
     * @brief Drives every process-global subsystem the Session owns, from the bootstrap worker.
     * @details Each subsystem is left with live state that the ordered teardown then has to retire: a configured async
     *          logger, a bound config key whose auto-reload watcher has already driven one observed reload, an input
     *          binding held by the session scope, an initialized memory cache, and a recorded profiler sample. The
     *          inline hook is installed, fired, and RAII-dropped in place instead, because hook lifetime is
     *          caller-owned rather than session-owned and each generation must start with a clean target. A cycle that
     *          exercised nothing would prove only that bootstrap and drain can run back to back.
     */
    bool use_every_subsystem(const char *scenario, DetourModKit::Session &session, const ScratchIni &ini, int cycle)
    {
        using namespace DetourModKit;

        session.log().info("full-lifecycle: cycle {} starting", cycle);

        s_bound_value.store(-1, std::memory_order_relaxed);
        config::Ini config_file = session.ini();
        config_file.bind<int>("Full", "Value", "value", s_bound_value, -1);
        config_file.load(ini.string());
        if (s_bound_value.load(std::memory_order_relaxed) != cycle)
        {
            return fail(scenario, "bound config setter did not observe this cycle's INI value");
        }
        if (config_file.enable_auto_reload(10ms) != config::AutoReloadStatus::Started)
        {
            return fail(scenario, "auto-reload watcher did not start for this generation");
        }

        // Drive an actual reload, not just a started watcher. Rewriting the watched file makes the watcher thread and
        // the reload servicer re-run the bound setter, which is the state the ordered teardown then has to retire; a
        // Started status alone is satisfied by a watcher that never observes a change.
        const int reloaded = cycle + 100;
        if (!ini.write(reloaded))
        {
            return fail(scenario, "could not rewrite the scenario INI to drive a reload");
        }
        const auto reload_deadline = std::chrono::steady_clock::now() + READY_TIMEOUT;
        while (s_bound_value.load(std::memory_order_relaxed) != reloaded)
        {
            if (std::chrono::steady_clock::now() >= reload_deadline)
            {
                return fail(scenario, "the auto-reload watcher never re-applied the bound setter");
            }
            std::this_thread::sleep_for(1ms);
        }

        Result<input::BindingGuard> binding = input::register_combo(
            input::ComboBinding{.name = "full_lifecycle_binding", .trigger = input::Trigger::Press, .on_press = [] {}});
        if (!binding)
        {
            return fail(scenario, "input binding registration failed");
        }
        session.scope().add(std::move(*binding));

        if (!memory::init_cache())
        {
            return fail(scenario, "memory cache init failed");
        }
        // is_readable is the predicate the cache actually backs, so a repeated query must move the cache counters.
        // memory::read deliberately bypasses the cache on its guarded hot path and would prove nothing here.
        const memory::MemoryStats before_queries = memory::get_memory_stats();
        const Region probe{Address{reinterpret_cast<std::uintptr_t>(&s_bound_value)}, sizeof(s_bound_value)};
        if (!memory::is_readable(probe) || !memory::is_readable(probe))
        {
            return fail(scenario, "this module's own static storage did not read back as readable");
        }
        const memory::MemoryStats after_queries = memory::get_memory_stats();
        if (after_queries.hits + after_queries.misses <= before_queries.hits + before_queries.misses)
        {
            return fail(scenario, "the protection cache recorded no query, so this generation's cache is not live");
        }

        const std::uint64_t samples_before = Profiler::get_instance().total_samples_recorded();
        {
            ScopedProfile sample("full_lifecycle_cycle");
        }
        // The counter is process-global and monotonic, so only the delta is meaningful past the first generation.
        if (Profiler::get_instance().total_samples_recorded() <= samples_before)
        {
            return fail(scenario, "profiler recorded no sample for this generation");
        }

        const Address hook_target{reinterpret_cast<std::uintptr_t>(&lifecycle_target)};
        {
            Result<hook::Hook> installed = hook::inline_at(
                hook::InlineRequest{.name = "full_lifecycle_hook", .target = hook_target}, &lifecycle_detour);
            if (!installed)
            {
                return fail(scenario, "inline hook install failed");
            }
            if (!installed->enable())
            {
                return fail(scenario, "inline hook enable failed");
            }
            if (call_unfolded(&lifecycle_target, cycle) != cycle + 41)
            {
                return fail(scenario, "the armed detour did not run");
            }
            // The Hook handle drops at the end of this scope: RAII unhook, so the next generation starts clean.
        }
        if (hook::is_target_hooked(hook_target))
        {
            return fail(scenario, "dropping the Hook handle left the target hooked");
        }

        return true;
    }

    int run_cycles()
    {
        using namespace DetourModKit;

        const auto ini = std::make_shared<ScratchIni>("cycles");
        const std::weak_ptr<ScratchIni> ini_observer = ini;
        const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Bootstrap);

        for (int cycle = 0; cycle < CYCLE_COUNT; ++cycle)
        {
            if (!ini->write(cycle))
            {
                (void)fail("cycles", "could not write the scenario INI");
                return 2;
            }

            const auto ready = std::make_shared<ReadyGate>();
            const auto subsystems_ok = std::make_shared<std::atomic<bool>>(false);
            auto on_ready = [subsystems_ok, ini_observer, ready, cycle](Session &session) -> Result<void>
            {
                const std::shared_ptr<ScratchIni> active_ini = ini_observer.lock();
                const bool ok = active_ini != nullptr && use_every_subsystem("cycles", session, *active_ini, cycle);
                subsystems_ok->store(ok, std::memory_order_release);
                ready->signal();
                return ok ? Result<void>{} : std::unexpected(Error{ErrorCode::Unknown, "cycles"});
            };
            Result<void> started =
                bootstrap(ModInfo{.name = "FULL_LIFECYCLE", .log_file = "full_lifecycle.log"}, std::move(on_ready));
            if (!started)
            {
                std::fprintf(stderr, "FAIL[cycles]: cycle %d: bootstrap failed: %s\n", cycle,
                             started.error().message().c_str());
                return 1;
            }
            if (!ready->wait(READY_TIMEOUT))
            {
                std::fprintf(stderr, "FAIL[cycles]: cycle %d: on_ready never completed\n", cycle);
                return 1;
            }
            if (!subsystems_ok->load(std::memory_order_acquire))
            {
                return 1; // use_every_subsystem already printed the specific failure.
            }
            if (module_handle() == nullptr)
            {
                std::fprintf(stderr, "FAIL[cycles]: cycle %d: module identity was cleared while the session ran\n",
                             cycle);
                return 1;
            }

            Result<void> drained = shutdown_and_wait();
            if (!drained)
            {
                std::fprintf(stderr, "FAIL[cycles]: cycle %d: drain failed: %s\n", cycle,
                             drained.error().message().c_str());
                return 1;
            }
            if (module_handle() != nullptr)
            {
                std::fprintf(stderr, "FAIL[cycles]: cycle %d: drain left the module identity published\n", cycle);
                return 1;
            }
        }

        // A drained generation abandons nothing. This is what distinguishes a real rundown from the misuse path, which
        // is allowed to retain and does record a leak.
        if (diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Bootstrap) != leaks_before)
        {
            (void)fail("cycles", "a clean drain recorded an intentional leak");
            return 1;
        }

        std::fprintf(stderr, "OK: %d full start/use/stop generations drained cleanly\n", CYCLE_COUNT);
        return 0;
    }

    int run_concurrent()
    {
        using namespace DetourModKit;

        const auto ready = std::make_shared<ReadyGate>();
        const auto release_worker = std::make_shared<ReadyGate>();
        Result<void> started = bootstrap(ModInfo{.name = "FULL_LIFECYCLE_CC", .log_file = "full_lifecycle_cc.log"},
                                         [ready, release_worker](Session &) -> Result<void>
                                         {
                                             ready->signal();
                                             // Hold the worker inside on_ready so both control threads are certainly
                                             // in shutdown_and_wait before either can complete.
                                             (void)release_worker->wait(READY_TIMEOUT);
                                             return {};
                                         });
        if (!started)
        {
            (void)fail("concurrent", "bootstrap failed");
            return 1;
        }
        if (!ready->wait(READY_TIMEOUT))
        {
            (void)fail("concurrent", "on_ready never started");
            return 1;
        }

        std::atomic<int> successes{0};
        std::atomic<int> in_progress{0};
        std::atomic<int> other{0};
        std::vector<std::thread> drainers;
        for (int i = 0; i < 2; ++i)
        {
            drainers.emplace_back(
                [&successes, &in_progress, &other]() -> void
                {
                    Result<void> outcome = shutdown_and_wait();
                    if (outcome)
                    {
                        successes.fetch_add(1, std::memory_order_relaxed);
                    }
                    else if (outcome.error().code == ErrorCode::SessionShutdownInProgress)
                    {
                        in_progress.fetch_add(1, std::memory_order_relaxed);
                    }
                    else
                    {
                        other.fetch_add(1, std::memory_order_relaxed);
                    }
                });
        }

        // Wait for the loser rather than sleeping. The winner cannot return until the worker exits, and the worker
        // cannot exit until release_worker is signalled, so the FIRST drainer to record an outcome is necessarily the
        // one that was refused. Observing it proves both threads are past the claim before the worker is released; a
        // fixed sleep would let a late-scheduled second thread arrive after the first drain had already completed and
        // then legitimately succeed, failing the run for a scheduling reason.
        const auto arrival_deadline = std::chrono::steady_clock::now() + READY_TIMEOUT;
        bool arrival_timed_out{false};
        while (successes.load(std::memory_order_relaxed) + in_progress.load(std::memory_order_relaxed) +
                   other.load(std::memory_order_relaxed) ==
               0)
        {
            if (std::chrono::steady_clock::now() >= arrival_deadline)
            {
                (void)fail("concurrent", "neither drain resolved, so no thread was refused");
                arrival_timed_out = true;
                break;
            }
            std::this_thread::yield();
        }
        release_worker->signal();
        for (auto &drainer : drainers)
        {
            drainer.join();
        }

        if (arrival_timed_out)
        {
            return 1;
        }

        if (other.load(std::memory_order_relaxed) != 0)
        {
            (void)fail("concurrent", "a drain reported neither success nor SessionShutdownInProgress");
            return 1;
        }
        if (successes.load(std::memory_order_relaxed) != 1 || in_progress.load(std::memory_order_relaxed) != 1)
        {
            std::fprintf(stderr,
                         "FAIL[concurrent]: exactly one drain must own the rundown and one must be refused "
                         "(successes=%d, in_progress=%d)\n",
                         successes.load(std::memory_order_relaxed), in_progress.load(std::memory_order_relaxed));
            return 1;
        }
        if (module_handle() != nullptr)
        {
            (void)fail("concurrent", "the winning drain left the module identity published");
            return 1;
        }

        std::fprintf(stderr, "OK: concurrent drains resolved to one owner and one refusal\n");
        return 0;
    }

    int run_misuse()
    {
        using namespace DetourModKit;

        const auto ready = std::make_shared<ReadyGate>();
        auto retained_capture = std::make_shared<int>(42);
        const std::weak_ptr<int> retained_observer = retained_capture;

        // Bring every subsystem up before the errant FreeLibrary, so the poll thread, the auto-reload watcher and its
        // servicer, the cache cleanup thread, and the async writer all exist when the worker runs its teardown. Without
        // them the leak deltas asserted below could not move and the scenario would prove only that the state word
        // reached Stopped.
        const auto ini = std::make_shared<ScratchIni>("misuse");
        const std::weak_ptr<ScratchIni> ini_observer = ini;
        if (!ini->write(0))
        {
            (void)fail("misuse", "could not write the scenario INI");
            return 2;
        }

        const auto subsystems_ok = std::make_shared<std::atomic<bool>>(false);
        Result<void> started =
            bootstrap(ModInfo{.name = "FULL_LIFECYCLE_MU", .log_file = "full_lifecycle_mu.log"},
                      [ready, retained_capture, ini_observer, subsystems_ok](Session &session) -> Result<void>
                      {
                          (void)retained_capture;
                          const std::shared_ptr<ScratchIni> active_ini = ini_observer.lock();
                          const bool ok =
                              active_ini != nullptr && use_every_subsystem("misuse", session, *active_ini, 0);
                          subsystems_ok->store(ok, std::memory_order_release);
                          ready->signal();
                          return ok ? Result<void>{} : std::unexpected(Error{ErrorCode::Unknown, "misuse"});
                      });
        if (!started)
        {
            (void)fail("misuse", "bootstrap failed");
            return 1;
        }
        if (!ready->wait(READY_TIMEOUT))
        {
            (void)fail("misuse", "on_ready never completed");
            return 1;
        }
        if (!subsystems_ok->load(std::memory_order_acquire))
        {
            return 1; // use_every_subsystem already printed the specific failure.
        }
        retained_capture.reset();

        const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Bootstrap);
        // Snapshot the leaves the worker's own teardown owns. The detach thread abandons the BOOTSTRAP state, but the
        // worker is a separate thread in no loader callback, so its ~Session must still JOIN every subsystem rather
        // than detach it. Reaching Stopped alone cannot tell those apart: Session::release() publishes Stopped whether
        // the teardown joined everything or abandoned everything.
        const std::size_t input_leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Input);
        const std::size_t worker_leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Worker);
        const std::size_t writer_leaks_before =
            diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::AsyncLogger);
        const std::size_t watcher_leaks_before =
            diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::ConfigWatcher);
        const std::size_t cache_leaks_before =
            diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::MemoryCache);

        // Model the bare-FreeLibrary DLL_PROCESS_DETACH entry while the worker is still live. It must return promptly:
        // this call is the one that would deadlock the loader if it waited or joined. A regression that waits here is
        // caught by the CTest timeout, not by an assertion.
        const auto detach_started = std::chrono::steady_clock::now();
        bootstrap_detach(nullptr);
        const auto detach_elapsed = std::chrono::steady_clock::now() - detach_started;
        if (detach_elapsed > 2s)
        {
            (void)fail("misuse", "the detach notification blocked instead of abandoning");
            return 1;
        }

        if (diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Bootstrap) <= leaks_before)
        {
            (void)fail("misuse", "abandoning the bootstrap state recorded no intentional leak");
            return 1;
        }
        if (module_handle() != nullptr)
        {
            (void)fail("misuse", "detach left the module identity published");
            return 1;
        }
        if (detail::lifecycle().loader_context() != detail::LoaderContext::LoaderDetach)
        {
            (void)fail("misuse", "detach did not publish the LoaderDetach context");
            return 1;
        }
        if (detail::blocking_teardown_permitted())
        {
            (void)fail("misuse", "the detach context still authorizes blocking teardown");
            return 1;
        }

        // The state was claimed by detach, so a drain can no longer promise one: it must say so rather than return a
        // success the caller would read as "safe to unmap now".
        Result<void> refused = shutdown_and_wait();
        if (refused)
        {
            (void)fail("misuse", "a drain after detach claimed success");
            return 1;
        }
        if (refused.error().code != ErrorCode::SessionShutdownUnavailable)
        {
            std::fprintf(stderr, "FAIL[misuse]: expected SessionShutdownUnavailable, got %s\n",
                         refused.error().message().c_str());
            return 1;
        }

        // The refusal is only half the contract. Abandoning does not orphan the session: the pinned worker still runs
        // its own ordered teardown to completion, which is why the pin exists. Stopped only says the teardown FINISHED
        // (the leak deltas below say what it did), but waiting for it is what a real host provides for free -- it keeps
        // running after the errant FreeLibrary. Returning from main() the instant the refusal lands would instead race
        // CRT teardown against a worker still inside ~Session.
        const auto stop_deadline = std::chrono::steady_clock::now() + READY_TIMEOUT;
        while (detail::lifecycle().state() != detail::LifecycleState::Stopped)
        {
            if (std::chrono::steady_clock::now() >= stop_deadline)
            {
                (void)fail("misuse", "the abandoned worker never finished its own ordered teardown");
                return 1;
            }
            std::this_thread::sleep_for(1ms);
        }
        if (retained_observer.expired())
        {
            (void)fail("misuse", "loader detach destroyed the retained on_ready capture");
            return 1;
        }

        // The teardown that just completed must have JOINED. A leaf that detached instead books an intentional leak,
        // so any increment here means the DllMain thread's published phase revoked the worker's authorization and the
        // module now carries a stranded poll thread, watcher, or writer for the rest of the process.
        if (diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Input) != input_leaks_before ||
            diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Worker) != worker_leaks_before ||
            diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::AsyncLogger) != writer_leaks_before ||
            diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::ConfigWatcher) != watcher_leaks_before ||
            diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::MemoryCache) != cache_leaks_before)
        {
            (void)fail("misuse", "the pinned worker abandoned its subsystems instead of joining them");
            return 1;
        }

        std::fprintf(stderr,
                     "OK: bare-FreeLibrary misuse abandoned, pinned, refused a later drain, and self-drained\n");
        return 0;
    }

    int run_exit()
    {
        using namespace DetourModKit;

        const auto ready = std::make_shared<ReadyGate>();
        const auto ini = std::make_shared<ScratchIni>("exit");
        const std::weak_ptr<ScratchIni> ini_observer = ini;
        if (!ini->write(0))
        {
            (void)fail("exit", "could not write the scenario INI");
            return 2;
        }

        const auto subsystems_ok = std::make_shared<std::atomic<bool>>(false);
        Result<void> started =
            bootstrap(ModInfo{.name = "FULL_LIFECYCLE_EX", .log_file = "full_lifecycle_ex.log"},
                      [ini_observer, ready, subsystems_ok](Session &session) -> Result<void>
                      {
                          const std::shared_ptr<ScratchIni> active_ini = ini_observer.lock();
                          const bool ok = active_ini != nullptr && use_every_subsystem("exit", session, *active_ini, 0);
                          subsystems_ok->store(ok, std::memory_order_release);
                          ready->signal();
                          return ok ? Result<void>{} : std::unexpected(Error{ErrorCode::Unknown, "exit"});
                      });
        if (!started)
        {
            (void)fail("exit", "bootstrap failed");
            return 1;
        }
        if (!ready->wait(READY_TIMEOUT))
        {
            (void)fail("exit", "on_ready never completed");
            return 1;
        }
        // on_ready's own failure Result is only logged by the worker, so the host has to observe it: without this the
        // scenario would reach its exit-code oracle having brought nothing up, and report PASS.
        if (!subsystems_ok->load(std::memory_order_acquire))
        {
            return 1; // use_every_subsystem already printed the specific failure.
        }

        // Deliberately no drain. Returning from main runs the CRT teardown with the worker, the poll thread, the
        // config watcher, the cache cleanup thread, and the async writer all still live. The oracle is that the
        // process reaches exit code 0 instead of hanging in a static destructor or faulting on retired state.
        std::fprintf(stderr, "OK: reached process exit with every subsystem live\n");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    const char *const scenario = argc > 1 ? argv[1] : "";
    if (std::strcmp(scenario, "cycles") == 0)
    {
        return run_cycles();
    }
    if (std::strcmp(scenario, "concurrent") == 0)
    {
        return run_concurrent();
    }
    if (std::strcmp(scenario, "misuse") == 0)
    {
        return run_misuse();
    }
    if (std::strcmp(scenario, "exit") == 0)
    {
        return run_exit();
    }

    std::fprintf(stderr, "usage: %s cycles|concurrent|misuse|exit\n", argc > 0 ? argv[0] : "test_full_lifecycle");
    return 2;
}
