#include "DetourModKit/bootstrap.hpp"

#include "DetourModKit/logger.hpp"
#include "DetourModKit/async_logger.hpp"

#include <DetourModKit.hpp>

#include <atomic>
#include <cstring>

namespace DetourModKit::Bootstrap
{
    namespace
    {
        HANDLE g_shutdown_event = nullptr;
        HANDLE g_worker_thread = nullptr;
        HANDLE g_instance_mutex = nullptr;
        HMODULE g_module = nullptr;
        std::atomic<bool> g_detach_called{false};

        std::function<bool()> g_init_fn;
        std::function<void()> g_shutdown_fn;

        bool is_target_process(std::string_view expected) noexcept
        {
            if (expected.empty())
            {
                return true;
            }

            char exe_path[MAX_PATH]{};
            const DWORD len = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
            if (len == 0 || len >= MAX_PATH)
            {
                return false;
            }

            const char *exe_name = std::strrchr(exe_path, '\\');
            exe_name = exe_name ? exe_name + 1 : exe_path;

            std::string expected_copy(expected);
            return _stricmp(exe_name, expected_copy.c_str()) == 0;
        }

        bool acquire_instance_mutex(std::string_view prefix) noexcept
        {
            if (prefix.empty())
            {
                return true;
            }

            wchar_t mutex_name[128]{};
            std::wstring wprefix;
            wprefix.reserve(prefix.size());
            for (char c : prefix)
            {
                wprefix.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
            }

            const int n = wsprintfW(mutex_name, L"%s%lu", wprefix.c_str(), GetCurrentProcessId());
            if (n <= 0)
            {
                return false;
            }

            HANDLE h = CreateMutexW(nullptr, FALSE, mutex_name);
            if (!h)
            {
                return false;
            }
            if (GetLastError() == ERROR_ALREADY_EXISTS)
            {
                CloseHandle(h);
                return false;
            }

            g_instance_mutex = h;
            return true;
        }

        DWORD WINAPI lifecycle_thread(LPVOID) noexcept
        {
            Logger &logger = Logger::get_instance();

            bool init_ok = false;
            if (g_init_fn)
            {
                try
                {
                    init_ok = g_init_fn();
                }
                catch (const std::exception &e)
                {
                    logger.error("Bootstrap: init_fn threw: {}", e.what());
                }
                catch (...)
                {
                    logger.error("Bootstrap: init_fn threw unknown exception.");
                }
            }
            else
            {
                init_ok = true;
            }

            if (!init_ok)
            {
                logger.error("Bootstrap: init_fn returned failure; worker idling until detach.");
            }

            if (g_shutdown_event)
            {
                WaitForSingleObject(g_shutdown_event, INFINITE);
            }

            if (g_shutdown_fn)
            {
                try
                {
                    g_shutdown_fn();
                }
                catch (const std::exception &e)
                {
                    logger.error("Bootstrap: shutdown_fn threw: {}", e.what());
                }
                catch (...)
                {
                    logger.error("Bootstrap: shutdown_fn threw unknown exception.");
                }
            }

            DMK_Shutdown();
            return 0;
        }
    } // anonymous namespace

    namespace
    {
        void release_instance_mutex_locked() noexcept
        {
            if (g_instance_mutex)
            {
                CloseHandle(g_instance_mutex);
                g_instance_mutex = nullptr;
            }
        }

        // Shared teardown path for early-attach failures. Ensures singletons
        // initialized by Logger::configure / user init_fn are torn down before
        // on_dll_attach returns FALSE, so a subsequent DLL load starts clean.
        void unwind_early_attach_failure() noexcept
        {
            if (g_shutdown_event)
            {
                CloseHandle(g_shutdown_event);
                g_shutdown_event = nullptr;
            }
            release_instance_mutex_locked();
            g_init_fn = nullptr;
            g_shutdown_fn = nullptr;
            g_module = nullptr;
            try
            {
                DMK_Shutdown();
            }
            catch (...)
            {
            }
        }
    } // anonymous namespace

    [[nodiscard]] BOOL on_dll_attach(HMODULE hMod,
                                     const ModInfo &info,
                                     std::function<bool()> init_fn,
                                     std::function<void()> shutdown_fn)
    {
        if (g_shutdown_event || g_worker_thread)
        {
            return FALSE;
        }

        g_module = hMod;
        if (hMod)
        {
            DisableThreadLibraryCalls(hMod);
        }

        if (!is_target_process(info.game_process_name))
        {
            g_module = nullptr;
            return FALSE;
        }

        if (!acquire_instance_mutex(info.instance_mutex_prefix))
        {
            g_module = nullptr;
            return FALSE;
        }

        Logger::configure(info.prefix, info.log_file);
        Logger::get_instance().enable_async_mode(info.async_cfg);

        g_init_fn = std::move(init_fn);
        g_shutdown_fn = std::move(shutdown_fn);

        g_shutdown_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_shutdown_event)
        {
            unwind_early_attach_failure();
            return FALSE;
        }

        g_worker_thread = CreateThread(nullptr, 0, lifecycle_thread, nullptr, 0, nullptr);
        if (!g_worker_thread)
        {
            unwind_early_attach_failure();
            return FALSE;
        }

        return TRUE;
    }

    void request_shutdown() noexcept
    {
        if (g_shutdown_event)
        {
            SetEvent(g_shutdown_event);
        }
    }

    void on_dll_detach(BOOL is_process_exit) noexcept
    {
        bool expected = false;
        if (!g_detach_called.compare_exchange_strong(expected, true,
                                                     std::memory_order_acq_rel))
        {
            return;
        }

        // On process exit Windows has already terminated every other thread in
        // the process before calling DllMain with DLL_PROCESS_DETACH. Waiting
        // on g_worker_thread would block forever because the worker was
        // abruptly killed mid-WaitForSingleObject. Skip the wait and run the
        // explicit shutdown path directly.
        if (is_process_exit)
        {
            if (g_shutdown_fn)
            {
                try
                {
                    g_shutdown_fn();
                }
                catch (const std::exception &e)
                {
                    try
                    {
                        Logger::get_instance().error(
                            "Bootstrap: shutdown_fn threw: {}", e.what());
                    }
                    catch (...)
                    {
                    }
                }
                catch (...)
                {
                    try
                    {
                        Logger::get_instance().error(
                            "Bootstrap: shutdown_fn threw unknown exception.");
                    }
                    catch (...)
                    {
                    }
                }
            }
            try
            {
                DMK_Shutdown();
            }
            catch (const std::exception &e)
            {
                try
                {
                    Logger::get_instance().error(
                        "Bootstrap: DMK_Shutdown threw: {}", e.what());
                }
                catch (...)
                {
                }
            }
            catch (...)
            {
                try
                {
                    Logger::get_instance().error(
                        "Bootstrap: DMK_Shutdown threw unknown exception.");
                }
                catch (...)
                {
                }
            }
        }
        else if (g_shutdown_event)
        {
            // Dynamic unload under loader lock. Signal the worker but do NOT
            // wait here: blocking under loader lock deadlocks any peer DllMain
            // that touches Win32 APIs. The contract (see bootstrap.hpp) is
            // that callers who need a clean unload call request_shutdown()
            // before FreeLibrary and give the worker time to drain.
            SetEvent(g_shutdown_event);
        }

        if (g_shutdown_event)
        {
            CloseHandle(g_shutdown_event);
            g_shutdown_event = nullptr;
        }

        if (g_worker_thread)
        {
            CloseHandle(g_worker_thread);
            g_worker_thread = nullptr;
        }

        release_instance_mutex_locked();
        g_module = nullptr;
    }

    HMODULE module_handle() noexcept
    {
        return g_module;
    }
} // namespace DetourModKit::Bootstrap
