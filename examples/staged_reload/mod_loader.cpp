/**
 * @file mod_loader.cpp
 * @brief Reference dev loader for the staged-generation reload pattern.
 */

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
    using InitFn = bool (*)() noexcept;
    using ShutdownFn = bool (*)() noexcept;
    using RevisionFn = const char *(*)() noexcept;

    /// Uses F10 as the reload hotkey.
    constexpr int RELOAD_VK = VK_F10;

    /// Caps retained generations before the loader requests a restart.
    constexpr std::size_t MAX_RETAINED_GENERATIONS = 32;
    constexpr std::uintmax_t MAX_RETAINED_BYTES = 128ull * 1024 * 1024;

    constexpr std::size_t MODULE_PATH_INITIAL_CHARS = 512;
    constexpr std::size_t MODULE_PATH_MAX_CHARS = 32'768;
    constexpr DWORD CONTROL_POLL_MS = 50;
    constexpr SHORT KEY_DOWN_MASK = static_cast<SHORT>(0x8000);

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
        std::uintmax_t image_bytes = 0;
    };

    HMODULE s_loader_module = nullptr;
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
     * @brief Drops one loader reference and records a surviving image.
     * @return true only when the staged image no longer maps.
     */
    [[nodiscard]] bool release_generation(Generation &generation) noexcept
    {
        const HMODULE module = std::exchange(generation.module, nullptr);
        if (module == nullptr)
        {
            return true;
        }
        const BOOL released = ::FreeLibrary(module);
        const DWORD release_error = released != 0 ? ERROR_SUCCESS : ::GetLastError();
        HMODULE survivor = nullptr;
        const BOOL still_mapped =
            ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 reinterpret_cast<LPCWSTR>(module), &survivor);
        if (released == 0 || still_mapped != 0)
        {
            record_retained_generation(generation);
            if (released == 0)
            {
                append_formatted_log("FreeLibrary failed: {}.", release_error);
            }
            return false;
        }
        remove_staged_file(generation.path);
        return true;
    }

    /**
     * @brief Copies the build output to a unique staged name (guide step 4).
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

    /// Stages, loads, resolves, and initializes one generation (guide steps 4 to 6).
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
        if (generation.init == nullptr || generation.shutdown == nullptr || generation.revision == nullptr)
        {
            const bool unmapped = release_generation(generation);
            append_log(unmapped ? "The export resolution failed. The staged image unloaded."
                                : "The export resolution failed. The staged image remains mapped.");
            return false;
        }
        if (!generation.init())
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
     * @brief Unloads the current generation (guide steps 2 and 3).
     * @return false on a Shutdown refusal. The DLL stays mapped and the loader retries on the next press.
     */
    [[nodiscard]] bool unload_current() noexcept
    {
        if (!s_current.has_value())
        {
            return true;
        }
        if (!s_current->shutdown())
        {
            append_log("Shutdown refused the unload. The generation stays mapped.");
            return false;
        }
        (void)release_generation(*s_current);
        s_current.reset();
        return true;
    }

    /**
     * @brief Refuses the reload once worst-case retention would breach the budget (guide step 7).
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
