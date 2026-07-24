/**
 * @file bootstrap_probe_dll.cpp
 * @brief Minimal mod-shaped DLL used by the bootstrap-worker module-reference proofs.
 *
 * @details It reproduces the exact runtime shape DetourModKit's async bootstrap path is built for: a DLL whose DllMain
 *          forwards DLL_PROCESS_ATTACH into bootstrap() (which stages a Session and spawns the lifecycle worker) and
 *          forwards DLL_PROCESS_DETACH into bootstrap_detach(). The bootstrap path takes a counted reference on this
 *          module before creating the worker, so its code cannot be unmapped before the worker runs or while it runs.
 *
 *          A consequence the proofs rely on: because the worker holds that reference, a bare FreeLibrary does NOT drive
 *          the module reference count to zero, so DLL_PROCESS_DETACH does not fire on it -- the module simply stays
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
#include <functional>
#include <iterator>
#include <new>
#include <utility>

namespace
{
    std::atomic<bool> s_worker_ready{false};
    std::atomic<bool> s_track_attach_allocations{false};
    std::atomic<DWORD> s_attach_thread_id{0};
    std::atomic<std::uint64_t> s_attach_allocations{0};
    std::atomic<std::uint64_t> s_selftest_allocations{0};
    std::atomic<bool> s_attach_succeeded{false};

    void make_worker_release_event_name(wchar_t (&name)[96]) noexcept
    {
        (void)std::swprintf(name, std::size(name), L"Local\\DMK_Bootstrap_SelfDrain_%lu", GetCurrentProcessId());
    }

    void make_capture_destroyed_event_name(wchar_t (&name)[96]) noexcept
    {
        (void)std::swprintf(name, std::size(name), L"Local\\DMK_Bootstrap_CaptureDestroyed_%lu", GetCurrentProcessId());
    }

    class RetainedCapture
    {
    public:
        RetainedCapture() noexcept = default;
        ~RetainedCapture() noexcept
        {
            if (m_destroyed_event != nullptr)
            {
                (void)SetEvent(m_destroyed_event);
                CloseHandle(m_destroyed_event);
            }
        }

        RetainedCapture(const RetainedCapture &) = delete;
        RetainedCapture &operator=(const RetainedCapture &) = delete;
        RetainedCapture(RetainedCapture &&other) noexcept : m_destroyed_event(other.m_destroyed_event)
        {
            other.m_destroyed_event = nullptr;
        }
        RetainedCapture &operator=(RetainedCapture &&) = delete;

        /**
         * @brief Opens the host's capture-destroyed witness event so ~RetainedCapture can signal it.
         * @return true if the event was opened, so the caller can refuse to report readiness without a live witness.
         */
        [[nodiscard]] bool arm() noexcept
        {
            wchar_t event_name[96]{};
            make_capture_destroyed_event_name(event_name);
            m_destroyed_event = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name);
            return m_destroyed_event != nullptr;
        }

    private:
        HANDLE m_destroyed_event{nullptr};
    };
} // namespace

void *operator new(std::size_t size)
{
    if (s_track_attach_allocations.load(std::memory_order_relaxed) &&
        GetCurrentThreadId() == s_attach_thread_id.load(std::memory_order_relaxed))
    {
        s_attach_allocations.fetch_add(1, std::memory_order_relaxed);
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
 * @brief Returns the number of plain heap allocations made by the attach thread inside bootstrap().
 * @return The measured allocation count.
 */
extern "C" __declspec(dllexport) std::uint64_t WINAPI dmk_probe_attach_allocations() noexcept
{
    return s_attach_allocations.load(std::memory_order_acquire);
}

/**
 * @brief Returns the allocation count observed for this module's own deliberate round trip through the replacement.
 * @details The positive control for @ref dmk_probe_attach_allocations. A zero attach count only proves the leaf rule
 *          if the replacement below is the operator new this module actually binds; a zero here instead means the
 *          replacement never interposed and the attach measurement is vacuous.
 * @return The measured self-test allocation count, which must be non-zero.
 */
extern "C" __declspec(dllexport) std::uint64_t WINAPI dmk_probe_selftest_allocations() noexcept
{
    return s_selftest_allocations.load(std::memory_order_acquire);
}

/**
 * @brief Reports whether bootstrap() accepted and published the lifecycle worker.
 * @return TRUE on success; otherwise FALSE.
 */
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_probe_attach_succeeded() noexcept
{
    return s_attach_succeeded.load(std::memory_order_acquire) ? TRUE : FALSE;
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
        DetourModKit::ModInfo info{};
        info.name = "DMKBootstrapProbe";
        info.log_file = "dmk_bootstrap_probe.log";
        std::move_only_function<DetourModKit::Result<void>(DetourModKit::Session &)> on_ready{
            [retained_capture = RetainedCapture{}](DetourModKit::Session &) mutable -> DetourModKit::Result<void>
            {
                const bool capture_armed = retained_capture.arm();
                // The bare-FreeLibrary scenario creates this named event before loading the DLL. Waiting here keeps
                // the worker inside consumer code until the host has dropped its own module reference; signalling then
                // lets the worker request shutdown without the host calling back through an already-freed handle.
                wchar_t event_name[96]{};
                make_worker_release_event_name(event_name);
                const HANDLE self_shutdown = OpenEventW(SYNCHRONIZE, FALSE, event_name);
                if (self_shutdown != nullptr && !capture_armed)
                {
                    // Only the bare scenario creates the release event, and only its oracle reads the capture witness.
                    // An unarmed witness can never signal, so that scenario would pass having proved nothing. Withhold
                    // readiness instead: the host fails on its readiness timeout rather than on a silent tautology.
                    CloseHandle(self_shutdown);
                    return {};
                }
                s_worker_ready.store(true, std::memory_order_release);
                if (self_shutdown != nullptr)
                {
                    (void)WaitForSingleObject(self_shutdown, INFINITE);
                    CloseHandle(self_shutdown);
                    DetourModKit::request_shutdown();
                }
                return {};
            }};
        s_attach_allocations.store(0, std::memory_order_relaxed);
        s_attach_thread_id.store(GetCurrentThreadId(), std::memory_order_relaxed);
        s_track_attach_allocations.store(true, std::memory_order_release);

        // Positive control, taken on the attach thread with tracking already armed. Called as ::operator new rather
        // than written as a new-expression so the compiler may not elide it, then folded away before the measurement
        // that follows. Without it a build whose module-local replacement never interposed would report zero attach
        // allocations and pass having measured nothing.
        void *const witness = ::operator new(sizeof(void *));
        ::operator delete(witness);
        s_selftest_allocations.store(s_attach_allocations.load(std::memory_order_relaxed), std::memory_order_release);
        s_attach_allocations.store(0, std::memory_order_relaxed);

        const DetourModKit::Result<void> attached = DetourModKit::bootstrap(info, std::move(on_ready));
        s_track_attach_allocations.store(false, std::memory_order_release);
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
