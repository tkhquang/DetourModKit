/**
 * @file mod_loader.cpp
 * @brief Reference dev loader for the staged-generation reload pattern.
 */

#include "protocol.h"

#include <windows.h>

#include <process.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace
{
    using InitFn = std::uint32_t(DMK_WHEELHOST_CALL *)(const StagedReloadInitRequest *) noexcept;
    using ShutdownFn = std::uint32_t(DMK_WHEELHOST_CALL *)() noexcept;
    using RevisionFn = const char *(DMK_WHEELHOST_CALL *)() noexcept;

    /// Uses F10 as the reload hotkey.
    constexpr int RELOAD_VK = VK_F10;

    /// Caps retained generations before the loader requests a restart.
    constexpr std::size_t MAX_RETAINED_GENERATIONS = 32;
    constexpr std::uintmax_t MAX_RETAINED_BYTES = 128ull * 1024 * 1024;

    constexpr std::size_t MODULE_PATH_INITIAL_CHARS = 512;
    constexpr std::size_t MODULE_PATH_MAX_CHARS = 32'768;
    constexpr DWORD CONTROL_POLL_MS = 50;
    constexpr DWORD UNMAP_POLL_MS = 10;
    constexpr DWORD UNMAP_TIMEOUT_MS = 2000;
    constexpr SHORT KEY_DOWN_MASK = static_cast<SHORT>(0x8000);
    constexpr std::uint64_t LEASE_PROBE_OWNER = UINT64_C(0x444d4b50524f4245);

    /// The build supplies DMK_EXAMPLE_MOD_NAME. One name derives the logic-DLL names, the sweep filter, and the log.
    constexpr std::wstring_view MOD_NAME = L"" DMK_EXAMPLE_MOD_NAME;

    /// Stores one loaded staged copy and its exports.
    struct Generation
    {
        std::filesystem::path path;
        HMODULE module = nullptr;
        InitFn init = nullptr;
        ShutdownFn shutdown = nullptr;
        RevisionFn revision = nullptr;
        const void *unmap_address = nullptr;
        std::uint64_t generation_id = 0;
        std::uintmax_t image_bytes = 0;
    };

    HMODULE s_loader_module = nullptr;
    WheelHostTable s_wheel_host{};
    // Host identity captured once at start. The request carries this copy, so the logic-side identity check compares
    // against the start-time value instead of re-reading the same table field it validates.
    std::uint64_t s_host_identity = 0;
    std::optional<Generation> s_current;
    unsigned s_generation_counter = 0;
    std::size_t s_retained_count = 0;
    std::uintmax_t s_retained_bytes = 0;
    bool s_restart_required = false;

    static_assert(std::is_nothrow_move_constructible_v<Generation>);

    [[nodiscard]] std::optional<std::filesystem::path> loader_directory()
    {
        std::wstring buffer(MODULE_PATH_INITIAL_CHARS, L'\0');
        for (;;)
        {
            const DWORD capacity = static_cast<DWORD>(buffer.size());
            const DWORD length = ::GetModuleFileNameW(s_loader_module, buffer.data(), capacity);
            if (length == 0)
            {
                return std::nullopt;
            }
            if (length < capacity)
            {
                buffer.resize(length);
                return std::filesystem::path{buffer}.parent_path();
            }
            if (buffer.size() >= MODULE_PATH_MAX_CHARS)
            {
                return std::nullopt;
            }
            const std::size_t next_size = buffer.size() * 2;
            buffer.resize(next_size > MODULE_PATH_MAX_CHARS ? MODULE_PATH_MAX_CHARS : next_size);
        }
    }

    /// Appends one line to the loader-owned log, which survives every generation.
    void append_log(std::string_view line) noexcept
    {
        try
        {
            const std::optional<std::filesystem::path> directory = loader_directory();
            if (!directory.has_value())
            {
                return;
            }
            std::ofstream file(*directory / std::format(L"{}.loader.log", MOD_NAME), std::ios::app);
            SYSTEMTIME now = {};
            ::GetLocalTime(&now);
            file << std::format("[{:04}-{:02}-{:02} {:02}:{:02}:{:02}] {}\n", now.wYear, now.wMonth, now.wDay,
                                now.wHour, now.wMinute, now.wSecond, line);
        }
        catch (...)
        {
            // The log is best-effort and cannot terminate the loader.
        }
    }

    template <typename... Args> void append_formatted_log(std::format_string<Args...> text, Args &&...args) noexcept
    {
        try
        {
            append_log(std::format(text, std::forward<Args>(args)...));
        }
        catch (...)
        {
        }
    }

    void remove_staged_file(const std::filesystem::path &path) noexcept
    {
        try
        {
            std::error_code error;
            [[maybe_unused]] const bool removed = std::filesystem::remove(path, error);
        }
        catch (...)
        {
        }
    }

    /// Deletes staged copies from earlier sessions. A copy that still backs a mapped image stays locked and survives.
    void remove_stale_staged_files() noexcept
    {
        try
        {
            const std::optional<std::filesystem::path> directory = loader_directory();
            if (!directory.has_value())
            {
                return;
            }
            const std::wstring staged_prefix = std::format(L"{}.gen", MOD_NAME);
            std::size_t removed = 0;
            std::error_code error;
            for (const std::filesystem::directory_entry &entry : std::filesystem::directory_iterator(*directory, error))
            {
                const std::wstring name = entry.path().filename().wstring();
                if (name.starts_with(staged_prefix) && name.ends_with(L".logic.dll"))
                {
                    std::error_code remove_error;
                    if (std::filesystem::remove(entry.path(), remove_error))
                    {
                        ++removed;
                    }
                }
            }
            if (removed > 0)
            {
                append_formatted_log("Removed {} stale staged copies.", removed);
            }
        }
        catch (...)
        {
        }
    }

    void record_retained_generation(const Generation &generation) noexcept
    {
        if (s_retained_count < (std::numeric_limits<std::size_t>::max)())
        {
            ++s_retained_count;
        }
        if (generation.image_bytes > (std::numeric_limits<std::uintmax_t>::max)() - s_retained_bytes)
        {
            s_retained_bytes = (std::numeric_limits<std::uintmax_t>::max)();
        }
        else
        {
            s_retained_bytes += generation.image_bytes;
        }
        append_formatted_log("Generation retained ({} images, {} bytes total).", s_retained_count, s_retained_bytes);
    }

    /**
     * @brief Waits until no loaded module owns an old generation address.
     * @return true only when the
     * address becomes unmapped before the deadline.
     */
    [[nodiscard]] bool wait_for_unmap(const void *address) noexcept
    {
        if (address == nullptr)
        {
            // No probe address means no unmap proof. Report the image as still mapped.
            return false;
        }
        for (DWORD waited = 0; waited < UNMAP_TIMEOUT_MS; waited += UNMAP_POLL_MS)
        {
            HMODULE owner = nullptr;
            if (::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                     reinterpret_cast<LPCWSTR>(address), &owner) == 0)
            {
                return true;
            }
            ::Sleep(UNMAP_POLL_MS);
        }
        return false;
    }

    /**
     * @brief Opens and closes a probe lease after logic shutdown.
     * @return true only when the generation
     * left no host lease open.
     */
    [[nodiscard]] bool host_lease_is_closed(std::uint64_t generation_id) noexcept
    {
        WheelHostLease probe = 0;
        const int32_t open_status =
            s_wheel_host.open_lease(s_wheel_host.host_context, LEASE_PROBE_OWNER, generation_id, &probe);
        if (open_status != DMK_WHEELHOST_OK)
        {
            append_formatted_log("The generation left its wheel-host lease open: {}.", open_status);
            return false;
        }
        const int32_t close_status =
            s_wheel_host.close_lease(s_wheel_host.host_context, probe, LEASE_PROBE_OWNER, generation_id);
        if (close_status != DMK_WHEELHOST_OK)
        {
            // A failed probe close leaves the host lease state unknown, exactly like a failed unmap.
            s_restart_required = true;
            append_formatted_log("The loader failed to close its wheel-host probe lease: {}.", close_status);
            return false;
        }
        return true;
    }

    /**
     * @brief Drops one loader reference and records a surviving image.
     * @return true only when the staged image no longer maps.
     */
    [[nodiscard]] bool release_generation(Generation &generation) noexcept
    {
        if (generation.module == nullptr)
        {
            return true;
        }
        if (!host_lease_is_closed(generation.generation_id))
        {
            return false;
        }
        const HMODULE module = generation.module;
        if (::FreeLibrary(module) == 0)
        {
            append_formatted_log("FreeLibrary failed: {}.", ::GetLastError());
            return false;
        }
        generation.module = nullptr;
        if (!wait_for_unmap(generation.unmap_address))
        {
            record_retained_generation(generation);
            return false;
        }
        remove_staged_file(generation.path);
        return true;
    }

    /**
     * @brief Copies the build output to a unique staged name (guide step 6).
     * @details A direct load locks the build output. A reused name can return a pinned predecessor as a stale image.
     */
    [[nodiscard]] bool stage_copy(Generation &generation)
    {
        const std::optional<std::filesystem::path> directory = loader_directory();
        if (!directory.has_value())
        {
            return false;
        }
        const std::filesystem::path source = *directory / std::format(L"{}.logic.dll", MOD_NAME);
        ++s_generation_counter;
        generation.generation_id = s_generation_counter;
        generation.path = *directory / std::format(L"{}.gen{:04}.logic.dll", MOD_NAME, s_generation_counter);
        std::error_code error;
        std::filesystem::copy_file(source, generation.path, std::filesystem::copy_options::overwrite_existing, error);
        if (error)
        {
            remove_staged_file(generation.path);
            append_formatted_log("The stage copy failed: {}.", error.message());
            return false;
        }
        generation.image_bytes = std::filesystem::file_size(generation.path, error);
        if (error)
        {
            const std::error_code size_error = error;
            remove_staged_file(generation.path);
            append_formatted_log("The staged image size query failed: {}.", size_error.message());
            return false;
        }
        return true;
    }

    template <class Fn> [[nodiscard]] Fn resolve(HMODULE module, const char *symbol) noexcept
    {
        return reinterpret_cast<Fn>(reinterpret_cast<void *>(::GetProcAddress(module, symbol)));
    }

    /// Stages, loads, resolves, and initializes one generation (guide steps 6 to 8).
    [[nodiscard]] bool load_generation()
    {
        Generation generation;
        if (!stage_copy(generation))
        {
            return false;
        }
        generation.module = ::LoadLibraryW(generation.path.c_str());
        if (generation.module == nullptr)
        {
            const DWORD error = ::GetLastError();
            remove_staged_file(generation.path);
            append_formatted_log("LoadLibrary failed: {}.", error);
            return false;
        }
        generation.init = resolve<InitFn>(generation.module, "Init");
        generation.shutdown = resolve<ShutdownFn>(generation.module, "Shutdown");
        generation.revision = resolve<RevisionFn>(generation.module, "Revision");
        generation.unmap_address = reinterpret_cast<const void *>(generation.init);
        if (generation.init == nullptr || generation.shutdown == nullptr || generation.revision == nullptr)
        {
            const bool unmapped = release_generation(generation);
            append_log(unmapped ? "The export resolution failed. The staged image unloaded."
                                : "The export resolution failed. The staged image remains mapped.");
            return false;
        }
        const StagedReloadInitRequest request{.struct_size =
                                                     static_cast<std::uint32_t>(sizeof(StagedReloadInitRequest)),
                                                 .abi_version = DMK_STAGED_RELOAD_ABI_VERSION,
                                                 .generation_id = generation.generation_id,
                                                 .expected_host_identity = s_host_identity,
                                                 .wheel_host = &s_wheel_host};
        if (generation.init(&request) != DMK_STAGED_RELOAD_OK)
        {
            const bool unmapped = release_generation(generation);
            append_log(unmapped ? "Init failed. The staged image unloaded."
                                : "Init failed. The staged image remains mapped.");
            return false;
        }
        s_current.emplace(std::move(generation));
        const char *revision = s_current->revision();
        append_formatted_log("Generation {} is live. Revision: {}.", s_generation_counter,
                             revision != nullptr ? std::string_view{revision} : std::string_view{"unknown"});
        return true;
    }

    /**
     * @brief Unloads the current generation (guide steps 2 to 5).
     * @return false on a Shutdown refusal. The DLL stays mapped and the loader retries on the next press.
     */
    [[nodiscard]] bool unload_current() noexcept
    {
        if (!s_current.has_value())
        {
            return true;
        }
        if (s_current->shutdown() != DMK_STAGED_RELOAD_OK)
        {
            append_log("Shutdown refused the unload. The generation stays mapped.");
            return false;
        }
        if (!release_generation(*s_current))
        {
            s_restart_required = true;
            append_log("The old logic image did not unmap. Restart the game before another reload.");
            return false;
        }
        s_current.reset();
        return true;
    }

    /**
     * @brief Refuses the reload once worst-case retention would breach the budget, backing the guide's restart rule.
     * @details The check runs before the unload and counts the current image as retained. A refusal keeps the current
     *          generation live.
     */
    [[nodiscard]] bool budget_allows_reload() noexcept
    {
        const std::uintmax_t current_bytes = s_current.has_value() ? s_current->image_bytes : 0;
        const bool count_would_exceed = s_retained_count >= MAX_RETAINED_GENERATIONS;
        const bool bytes_would_exceed =
            s_retained_bytes > MAX_RETAINED_BYTES || current_bytes > MAX_RETAINED_BYTES - s_retained_bytes;
        if (count_would_exceed || bytes_would_exceed)
        {
            s_restart_required = true;
            append_log("The retained-generation budget is full. Restart the game before another reload.");
            return false;
        }
        return true;
    }

    void reload_once()
    {
        // This control thread is the only reload caller, so it cannot re-enter this function.
        if (s_restart_required || !budget_allows_reload())
        {
            return;
        }
        if (!unload_current())
        {
            return;
        }
        if (!load_generation())
        {
            append_log("The reload failed. No generation is live until the next press.");
        }
    }

    /**
     * @brief Accepts the hotkey only while this process owns the foreground window.
     * @details GetAsyncKeyState reads global key state, so an unguarded press in an editor window can trigger a
     *          game reload.
     */
    [[nodiscard]] bool foreground_belongs_to_this_process() noexcept
    {
        const HWND foreground = ::GetForegroundWindow();
        if (foreground == nullptr)
        {
            return false;
        }
        DWORD process_id = 0;
        ::GetWindowThreadProcessId(foreground, &process_id);
        return process_id == ::GetCurrentProcessId();
    }

    unsigned __stdcall control_thread(void *) noexcept
    {
        try
        {
            append_log("The loader started.");
            remove_stale_staged_files();
            // ABI v2 starts unmounted in target-wait state. The logic-side poller resolves the game UI thread and
            // drives the host retarget through the C table, so the loader needs no window wait of its own.
            const int32_t host_status = wheel_host_start(
                0, DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(s_wheel_host)), &s_wheel_host);
            if (host_status != DMK_WHEELHOST_OK)
            {
                append_formatted_log("The resident wheel host failed to start: {}.", host_status);
                return 0;
            }
            s_host_identity = s_wheel_host.host_identity;
            if (!load_generation())
            {
                append_log("The initial load failed.");
            }
            bool was_down = false;
            for (;;) // The loader lives for the game session. Process exit ends this thread.
            {
                ::Sleep(CONTROL_POLL_MS);
                const bool down = (::GetAsyncKeyState(RELOAD_VK) & KEY_DOWN_MASK) != 0;
                if (down && !was_down && foreground_belongs_to_this_process())
                {
                    reload_once();
                }
                was_down = down;
            }
        }
        catch (...)
        {
            // An exception cannot cross the CRT thread boundary into the host process.
            return 0;
        }
    }
} // namespace

/// Starts the control thread on attach. The loader never unloads, so detach has no work.
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) noexcept
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        s_loader_module = module;
        ::DisableThreadLibraryCalls(module);
        const std::uintptr_t thread = _beginthreadex(nullptr, 0, &control_thread, nullptr, 0, nullptr);
        if (thread == 0)
        {
            return FALSE;
        }
        ::CloseHandle(reinterpret_cast<HANDLE>(thread));
    }
    return TRUE;
}
