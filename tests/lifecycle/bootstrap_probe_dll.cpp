/**
 * @file bootstrap_probe_dll.cpp
 * @brief Hosts the T-BOOTSTRAP lifecycle probe.
 *
 *          The bootstrap path takes a counted reference on this module before it creates the worker.
 *          A consequence the proofs rely on: because the worker holds that reference, a bare FreeLibrary does NOT drive
 *          the module reference count to zero, so DLL_PROCESS_DETACH does not fire on it: the module simply stays
 *          mapped. DETACH fires only after the worker has been drained and released its reference, either through the
 *          exported synchronous drain forwarder or through the worker's own shutdown request, or at process
 *          termination.
 *
 *          This is a separate build artifact (a DLL, not a test translation unit), so it lives outside the in-tree test
 *          glob and is compiled and driven by scripts/run_lifecycle_proofs.sh against the prebuilt library archive.
 */

#include "DetourModKit.hpp"

#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <iterator>
#include <new>
#include <type_traits>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    extern std::atomic<std::atomic<bool> *> g_config_reload_worker_mutex_gate_probe;
    extern std::atomic<bool> g_config_reload_worker_mutex_waiting_probe;
#endif
} // namespace DetourModKit::detail

namespace
{
    std::atomic<bool> s_worker_ready{false};
    std::atomic<bool> s_track_attach_allocations{false};
    std::atomic<DWORD> s_attach_thread_id{0};
    std::atomic<std::uint64_t> s_attach_allocations{0};
    std::atomic<bool> s_track_selftest_allocations{false};
    std::atomic<DWORD> s_selftest_thread_id{0};
    std::atomic<std::uint64_t> s_selftest_allocations{0};
    std::atomic<bool> s_attach_succeeded{false};
#if defined(DMK_ENABLE_TEST_SEAMS)
    std::atomic<bool> s_reload_mutex_gate{true};
#endif

    void make_worker_release_event_name(wchar_t (&name)[96]) noexcept
    {
        (void)std::swprintf(name, std::size(name), L"Local\\DMK_Bootstrap_SelfDrain_%lu", GetCurrentProcessId());
    }

    void make_reload_mutex_exit_event_name(wchar_t (&name)[96]) noexcept
    {
        (void)std::swprintf(name, std::size(name), L"Local\\DMK_ReloadMutex_ProcessExit_%lu", GetCurrentProcessId());
    }

    [[nodiscard]] bool prepare_reload_mutex_exit_probe()
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        wchar_t event_name[96]{};
        make_reload_mutex_exit_event_name(event_name);
        const HANDLE requested = OpenEventW(SYNCHRONIZE, FALSE, event_name);
        if (requested == nullptr)
        {
            return true;
        }
        CloseHandle(requested);

        s_reload_mutex_gate.store(true, std::memory_order_release);
        DetourModKit::detail::g_config_reload_worker_mutex_waiting_probe.store(false, std::memory_order_release);
        DetourModKit::detail::g_config_reload_worker_mutex_gate_probe.store(
            &s_reload_mutex_gate,
            std::memory_order_release
        );
        if (!DetourModKit::config::reload_hotkey("ReloadMutexExit", "F5"))
        {
            return false;
        }

        constexpr ULONGLONG WAIT_BUDGET_MS = 3000;
        const ULONGLONG deadline = GetTickCount64() + WAIT_BUDGET_MS;
        while (!DetourModKit::detail::g_config_reload_worker_mutex_waiting_probe.load(std::memory_order_acquire) &&
               GetTickCount64() < deadline)
        {
            Sleep(1);
        }
        return DetourModKit::detail::g_config_reload_worker_mutex_waiting_probe.load(std::memory_order_acquire);
#else
        return true;
#endif
    }

    /**
     * @brief Runs probe setup from the hosted worker.
     * @return An empty Result on success, or the reload-mutex setup failure.
     */
    DetourModKit::Result<void> probe_on_ready(DetourModKit::Session &)
    {
        // The mapped and bare hosts create this event before they load the DLL.
        wchar_t event_name[96]{};
        make_worker_release_event_name(event_name);
        const HANDLE self_shutdown = OpenEventW(SYNCHRONIZE, FALSE, event_name);

        if (!prepare_reload_mutex_exit_probe())
        {
            if (self_shutdown != nullptr)
            {
                CloseHandle(self_shutdown);
            }
            return std::unexpected(
                DetourModKit::Error{DetourModKit::ErrorCode::Unknown, "reload mutex process-exit setup"}
            );
        }
        s_worker_ready.store(true, std::memory_order_release);
        if (self_shutdown != nullptr)
        {
            (void)WaitForSingleObject(self_shutdown, INFINITE);
            CloseHandle(self_shutdown);
            DetourModKit::request_shutdown();
        }
        return {};
    }

    static_assert(
        std::is_trivially_copyable_v<DetourModKit::BootstrapReadyFn> &&
        std::is_trivially_destructible_v<DetourModKit::BootstrapReadyFn>
    );

    /// Models consumer cleanup that must be unrepresentable in the DllMain descriptor.
    struct DestructibleReadyCallback
    {
        ~DestructibleReadyCallback() noexcept {}

        DetourModKit::Result<void> operator()(DetourModKit::Session &) const { return {}; }
    };

    static_assert(!std::is_trivially_destructible_v<DestructibleReadyCallback>);
    static_assert(!std::is_convertible_v<DestructibleReadyCallback, DetourModKit::BootstrapReadyFn>);
} // namespace

void *operator new(std::size_t size)
{
    if (s_track_attach_allocations.load(std::memory_order_relaxed) &&
        GetCurrentThreadId() == s_attach_thread_id.load(std::memory_order_relaxed))
    {
        s_attach_allocations.fetch_add(1, std::memory_order_relaxed);
    }
    if (s_track_selftest_allocations.load(std::memory_order_relaxed) &&
        GetCurrentThreadId() == s_selftest_thread_id.load(std::memory_order_relaxed))
    {
        s_selftest_allocations.fetch_add(1, std::memory_order_relaxed);
    }
    if (void *memory = std::malloc(size != 0 ? size : 1))
    {
        return memory;
    }
    throw std::bad_alloc{};
}

void *operator new[](std::size_t size)
{
    return ::operator new(size);
}

void operator delete(void *memory) noexcept
{
    std::free(memory);
}

void operator delete[](void *memory) noexcept
{
    std::free(memory);
}

void operator delete(void *memory, std::size_t) noexcept
{
    std::free(memory);
}

void operator delete[](void *memory, std::size_t) noexcept
{
    std::free(memory);
}

/**
 * @brief Provides an address in this DLL's executable image for the host's mapped-state query.
 */
extern "C" __declspec(dllexport) void dmk_probe_marker() noexcept {}

/**
 * @brief Reports whether the bootstrap worker reached the consumer callback.
 * @return TRUE after the callback publishes readiness; otherwise FALSE.
 */
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_probe_worker_ready() noexcept
{
    return s_worker_ready.load(std::memory_order_acquire) ? TRUE : FALSE;
}

/**
 * @brief Returns the number of plain heap allocations made by the attach thread inside bootstrap_attach().
 * @return The measured allocation count.
 */
extern "C" __declspec(dllexport) std::uint64_t WINAPI dmk_probe_attach_allocations() noexcept
{
    return s_attach_allocations.load(std::memory_order_acquire);
}

/**
 * @brief Runs an off-loader-lock allocation round trip through this module's operator new replacement.
 * @details The positive control for @ref dmk_probe_attach_allocations. A zero attach count only proves the leaf rule
 *          if this replacement is the operator new the module actually binds. The host calls this export after
 *          LoadLibrary returns, so the positive control itself never allocates from DllMain.
 * @return The measured self-test allocation count, which must be non-zero.
 */
extern "C" __declspec(dllexport) std::uint64_t WINAPI dmk_probe_selftest_allocations() noexcept
{
    s_selftest_allocations.store(0, std::memory_order_relaxed);
    s_selftest_thread_id.store(GetCurrentThreadId(), std::memory_order_relaxed);
    s_track_selftest_allocations.store(true, std::memory_order_release);
    try
    {
        // Volatile call targets prevent allocation elision and preserve the matched operator pair.
        void *(*volatile allocate)(std::size_t) = static_cast<void *(*)(std::size_t)>(&::operator new);
        void (*volatile deallocate)(void *) noexcept = static_cast<void (*)(void *) noexcept>(&::operator delete);
        void *const witness = allocate(sizeof(void *));
        deallocate(witness);
    }
    catch (...)
    {
        s_track_selftest_allocations.store(false, std::memory_order_release);
        s_selftest_thread_id.store(0, std::memory_order_relaxed);
        return 0;
    }
    s_track_selftest_allocations.store(false, std::memory_order_release);
    s_selftest_thread_id.store(0, std::memory_order_relaxed);
    return s_selftest_allocations.load(std::memory_order_acquire);
}

/**
 * @brief Reports whether bootstrap_attach() accepted and published the lifecycle worker.
 * @return TRUE on success; otherwise FALSE.
 */
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_probe_attach_succeeded() noexcept
{
    return s_attach_succeeded.load(std::memory_order_acquire) ? TRUE : FALSE;
}

/**
 * @brief Reports whether the reload worker owns its channel mutex at the process-exit parking seam.
 * @return TRUE only after the worker publishes that it is parked inside the critical section.
 */
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_probe_reload_mutex_owned() noexcept
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    const bool owned = DetourModKit::detail::g_config_reload_worker_mutex_waiting_probe.load(std::memory_order_acquire);
    return owned ? TRUE : FALSE;
#else
    return FALSE;
#endif
}

/**
 * @brief Drains the bootstrap worker and releases its counted module reference.
 * @return TRUE on success; otherwise FALSE.
 */
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_probe_shutdown_and_wait() noexcept
{
    return DetourModKit::shutdown_and_wait().has_value() ? TRUE : FALSE;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Empty process and mutex settings keep the attach phase focused on publishing the worker. Logger setup and
        // consumer initialization run on that worker after this entry point returns.
        s_worker_ready.store(false, std::memory_order_release);

        // Form ModInfo before the probe because its MSVC debug string can allocate a proxy.
        DetourModKit::ModInfo info{};
        info.name = "DMKBootstrapProbe";
        info.log_file = "dmk_bootstrap_probe.log";

        // Arm allocation tracking before conversion of the function pointer.
        s_attach_allocations.store(0, std::memory_order_relaxed);
        s_attach_thread_id.store(GetCurrentThreadId(), std::memory_order_relaxed);
        s_track_attach_allocations.store(true, std::memory_order_release);
        const DetourModKit::Result<void> attached = DetourModKit::bootstrap_attach(info, &probe_on_ready);
        s_track_attach_allocations.store(false, std::memory_order_release);
        s_attach_thread_id.store(0, std::memory_order_relaxed);
        s_attach_succeeded.store(attached.has_value(), std::memory_order_release);
        break;
    }
    case DLL_PROCESS_DETACH:
        // Forward exactly as a real mod's DllMain would. Because the worker holds its own module reference, a bare
        // FreeLibrary does not fire this DETACH; it fires only after the worker has been drained and released that
        // reference (the clean-unload path) or at process termination (reserved != nullptr).
        DetourModKit::bootstrap_detach(reserved);
        break;
    default:
        break;
    }
    return TRUE;
}
