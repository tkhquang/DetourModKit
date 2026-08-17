/**
 * @file session_detach_terminal.cpp
 * @brief Proves that a DllMain detach after a completed synchronous drain revokes blocking authorization and leaves
 *        the bootstrap slot terminally refused.
 * @details bootstrap_detach(nullptr) publishes LoaderContext::LoaderDetach and moves the process-wide bootstrap slot
 *          to Detached. Nothing reverses that slot, so every later bootstrap in the process correctly reports
 *          SessionShutdownUnavailable and no case can follow this one in a shared test process. Built as a standalone
 *          executable; the process exit code is the oracle.
 *
 *          This host owns the test binary's replacement of the global allocation operators (through
 *          tests/test_alloc_probe.cpp), so the terminal refusal can be proved to allocate nothing.
 */

#include "DetourModKit/session.hpp"

#include "internal/lifecycle_context.hpp"
#include "platform.hpp"

#include "test_alloc_probe.hpp"

#include <windows.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <memory>
#include <mutex>

#if defined(_MSC_VER)
#include <crtdbg.h>
#include <cstdlib>
#endif

namespace
{
    using namespace std::chrono_literals;

    constexpr auto READY_TIMEOUT = 20s;

    bool force_loader_lock_held() noexcept
    {
        return true;
    }

    bool force_loader_lock_free() noexcept
    {
        return false;
    }

    /// Restores both the forced probe verdict and the loader context, so a failing branch leaks neither.
    class ForcedLoaderProbe
    {
    public:
        explicit ForcedLoaderProbe(bool (*probe)() noexcept) noexcept
            : m_saved_context(DetourModKit::detail::lifecycle().loader_context())
        {
            DetourModKit::detail::g_loader_lock_override = probe;
        }
        ForcedLoaderProbe(const ForcedLoaderProbe &) = delete;
        ForcedLoaderProbe &operator=(const ForcedLoaderProbe &) = delete;
        ForcedLoaderProbe(ForcedLoaderProbe &&) = delete;
        ForcedLoaderProbe &operator=(ForcedLoaderProbe &&) = delete;
        ~ForcedLoaderProbe() noexcept
        {
            DetourModKit::detail::g_loader_lock_override = nullptr;
            DetourModKit::detail::lifecycle().set_loader_context(m_saved_context);
        }

    private:
        DetourModKit::detail::LoaderContext m_saved_context;
    };

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

    [[nodiscard]] bool fail(const char *what)
    {
        std::fprintf(stderr, "FAIL[detach-terminal]: %s\n", what);
        return false;
    }

    DetourModKit::Result<void> attach_entry_noop(DetourModKit::Session &)
    {
        return {};
    }
} // namespace

int main()
{
    using namespace DetourModKit;

#if defined(_MSC_VER)
    // A raw proof runs headless: nothing dismisses a modal CRT dialog. Route asserts and errors to stderr and make
    // abort() exit with a status, so a failure is a fast diagnostic exit rather than a hang.
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
    ::SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
#endif

    // Built before the budget is armed. Constructing it inside the armed scope would charge the caller's own
    // argument setup to the refusal and throw out of a noexcept frame.
    const ModInfo terminal_attach_info{.name = "SESS_DETACH_TERMINAL_RELOAD"};

    const auto ready = std::make_shared<ReadyGate>();
    Result<void> started = bootstrap(ModInfo{.name = "SESS_DETACH_TERMINAL", .log_file = "sess_detach_terminal.log"},
                                     [ready](Session &) -> Result<void>
                                     {
                                         ready->signal();
                                         return {};
                                     });
    if (!started)
    {
        (void)fail("bootstrap failed");
        return 1;
    }
    if (!ready->wait(READY_TIMEOUT))
    {
        (void)fail("on_ready never completed");
        return 1;
    }

    Result<void> drained = shutdown_and_wait();
    if (!drained)
    {
        (void)fail("the synchronous drain failed");
        return 1;
    }
    if (detail::lifecycle().loader_context() != detail::LoaderContext::Normal)
    {
        (void)fail("the completed drain left a phase published");
        return 1;
    }

    detail::LoaderContext detach_context = detail::LoaderContext::Normal;
    bool blocking_permitted = true;
    {
        ForcedLoaderProbe probe{&force_loader_lock_free};
        bootstrap_detach(nullptr);
        detach_context = detail::lifecycle().loader_context();
        blocking_permitted = detail::blocking_teardown_permitted();
    }
    if (detach_context != detail::LoaderContext::LoaderDetach)
    {
        (void)fail("detach did not publish the LoaderDetach context");
        return 1;
    }
    if (blocking_permitted)
    {
        (void)fail("detach did not revoke the earlier drain authorization when no bootstrap handles remained");
        return 1;
    }

    // The probe above restored the saved context, so the refusal below can only come from the terminal bootstrap
    // slot. The armed allocation budget makes any allocation on this path a thrown bad_alloc out of a noexcept
    // frame, which terminates the process rather than reporting a pass.
    Result<void> terminal_attach;
    {
        ForcedLoaderProbe probe{&force_loader_lock_held};
        dmk_test::AllocFailScope no_alloc{0};
        terminal_attach = bootstrap_attach(terminal_attach_info, &attach_entry_noop);
    }
    if (terminal_attach)
    {
        (void)fail("an attach on the detached slot claimed success");
        return 1;
    }
    if (terminal_attach.error().code != ErrorCode::SessionShutdownUnavailable)
    {
        std::fprintf(stderr, "FAIL[detach-terminal]: expected SessionShutdownUnavailable, got %s\n",
                     terminal_attach.error().message().c_str());
        return 1;
    }

    std::fprintf(stderr, "OK: detach after a drain revoked blocking authorization and refused a later attach\n");
    return 0;
}
