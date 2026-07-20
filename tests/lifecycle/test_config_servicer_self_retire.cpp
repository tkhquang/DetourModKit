/**
 * @file test_config_servicer_self_retire.cpp
 * @brief Proves reload-servicer self-retirement through the off-thread reaper.
 * @details A setter running on the servicer thread clears config and destroys that servicer. The isolated process
 *          turns a self-join regression into a bounded test failure instead of wedging the shared unit-test process.
 */

#include "DetourModKit/config.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/input.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <process.h>
#include <string>
#include <thread>
#include <utility>

namespace DetourModKit::detail
{
    // Test-only driver: asks the reload servicer to run one reload on its own worker thread, as a hotkey press would.
    bool request_servicer_reload_for_test() noexcept;

    // Set by ~ReloadServicer when it hands its Channel to the off-thread reaper.
    extern std::atomic<bool> g_servicer_reaped_on_worker;
} // namespace DetourModKit::detail

int main()
{
    using namespace DetourModKit;
    using namespace std::chrono_literals;

    const std::filesystem::path ini_path =
        std::filesystem::temp_directory_path() /
        ("dmk_config_servicer_self_retire_" + std::to_string(static_cast<unsigned long>(_getpid())) + ".ini");
    class FileCleanup
    {
    public:
        explicit FileCleanup(std::filesystem::path path) : m_path(std::move(path)) {}

        ~FileCleanup()
        {
            std::error_code error;
            std::filesystem::remove(m_path, error);
        }

        FileCleanup(const FileCleanup &) = delete;
        FileCleanup &operator=(const FileCleanup &) = delete;

    private:
        std::filesystem::path m_path;
    } const file_cleanup{ini_path};

    {
        std::ofstream ini(ini_path);
        ini << "[S]\nV=1\n";
        if (!ini)
        {
            std::fprintf(stderr, "FAIL: could not create probe INI\n");
            return 1;
        }
    }

    std::atomic<bool> armed{false};
    std::atomic<bool> setter_ran{false};
    std::atomic<bool> cleared{false};

    if (!config::reload_hotkey("ReloadKey", "Ctrl+F5"))
    {
        std::fprintf(stderr, "FAIL: reload_hotkey did not register\n");
        config::clear();
        return 1;
    }

    config::bind_int(
        "S", "V", "v",
        [&](int)
        {
            if (!armed.load(std::memory_order_acquire))
            {
                return;
            }
            setter_ran.store(true, std::memory_order_release);
            config::clear();
            cleared.store(true, std::memory_order_release);
        },
        0);

    config::load(ini_path.string());

    // reload_hotkey's press callback captures a strong reference to the servicer, and that capture outlives the
    // BindingGuard (release only gates delivery). Drop the staged binding so config::clear()'s guard teardown leaves
    // DMK's own slot holding the last reference: only then is the final drop -- and therefore ~ReloadServicer -- on
    // the servicer worker thread, which is the path under test.
    input::Input::instance().clear_bindings(false);

    {
        std::ofstream ini(ini_path);
        ini << "[S]\nV=2\n";
        if (!ini)
        {
            std::fprintf(stderr, "FAIL: could not update probe INI\n");
            config::clear();
            return 1;
        }
    }

    const std::size_t leaks_before = DetourModKit::diagnostics::intentional_leak_count(
        DetourModKit::diagnostics::LeakSubsystem::Worker);
    armed.store(true, std::memory_order_release);
    if (!DetourModKit::detail::request_servicer_reload_for_test())
    {
        std::fprintf(stderr, "FAIL: no servicer to drive\n");
        config::clear();
        return 1;
    }

    const auto deadline = std::chrono::steady_clock::now() + 15s;
    while (!cleared.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(5ms);
    }

    if (!setter_ran.load(std::memory_order_acquire))
    {
        std::fprintf(stderr, "FAIL: reload setter never ran on the servicer thread\n");
        config::clear();
        return 1;
    }
    if (!cleared.load(std::memory_order_acquire))
    {
        std::fprintf(stderr, "FAIL: clear() from the servicer thread did not complete (self-join hang?)\n");
        config::clear();
        return 1;
    }
    if (!DetourModKit::detail::g_servicer_reaped_on_worker.load(std::memory_order_acquire))
    {
        std::fprintf(stderr, "FAIL: ~ReloadServicer did not run on its own worker thread; reaper path not exercised\n");
        config::clear();
        return 1;
    }
    if (DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::Worker) !=
        leaks_before)
    {
        std::fprintf(stderr, "FAIL: servicer retirement fell back to an intentional leak\n");
        config::clear();
        return 1;
    }

    config::clear();
    std::fprintf(stderr, "OK: servicer self-retired through the off-thread reaper\n");
    return 0;
}
