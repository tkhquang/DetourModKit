/**
 * @file staged_example_reload.cpp
 * @brief Verifies fresh generations through the checked-in loader and logic.
 */

// NOLINTNEXTLINE(bugprone-suspicious-include): Exercise the reference implementation.
#include "../../examples/staged_reload/mod_loader.cpp"

#include <safetyhook/inline_hook.hpp>

#include <xinput.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <exception>
#include <iterator>
#include <vector>

extern "C" void DMK_WHEELHOST_CALL
wheel_host_test_snapshot(std::uint32_t *, std::uint32_t *, std::uint32_t *, std::uint64_t *) noexcept;

namespace
{
    using StateFn = DWORD(WINAPI *)(DWORD, XINPUT_STATE *);
    using SnapshotFn = void(DMK_WHEELHOST_CALL *)(std::uint64_t *) noexcept;
    using FaultFn = void(DMK_WHEELHOST_CALL *)(std::uint32_t) noexcept;
    using WorkerControlFn = std::uint32_t(DMK_WHEELHOST_CALL *)() noexcept;
    std::atomic<StateFn> s_rival_original{nullptr};

    DWORD WINAPI rival_state(DWORD user, XINPUT_STATE *state) noexcept
    {
        const StateFn original = s_rival_original.load(std::memory_order_acquire);
        return original != nullptr ? original(user, state) : ERROR_INVALID_FUNCTION;
    }

    [[nodiscard]] std::array<std::uint64_t, 19> snapshot(HMODULE module)
    {
        std::array<std::uint64_t, 19> out{};
        resolve<SnapshotFn>(module, "example_proof_snapshot")(out.data());
        return out;
    }

    [[nodiscard]] bool write_build(const std::filesystem::path &fixture, unsigned revision)
    {
        std::ifstream input(fixture, std::ios::binary);
        std::vector<char> bytes{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
        constexpr std::string_view marker = "DMKEXAMPLEFRESHTAG:";
        const auto position = std::search(bytes.begin(), bytes.end(), marker.begin(), marker.end());
        if (position == bytes.end())
        {
            return false;
        }
        const std::string tag = std::format("{:016}", revision);
        std::copy(tag.begin(), tag.end(), position + static_cast<std::ptrdiff_t>(marker.size()));
        const auto directory = loader_directory();
        if (!directory.has_value())
            return false;
        std::ofstream output(*directory / L"StagedExampleProof.logic.dll", std::ios::binary | std::ios::trunc);
        output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        return output.good();
    }

    [[nodiscard]] bool write_ini(bool consume)
    {
        const auto directory = loader_directory();
        if (!directory.has_value())
            return false;
        std::ofstream output(*directory / L"StagedExampleProof.ini", std::ios::trunc);
        output << "[Input]\nDemoCombo=WheelUp,Gamepad_DpadUp\nDemoCombo.Consume=" << (consume ? "true" : "false")
               << "\n";
        return output.good();
    }

    [[nodiscard]] bool wait_for_mask(StateFn primary, StateFn extended, bool masked)
    {
        for (unsigned i = 0; i < 5000; ++i)
        {
            MSG message{};
            while (::PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
            {
                ::TranslateMessage(&message);
                ::DispatchMessageW(&message);
            }
            XINPUT_STATE first{}, second{}, other{};
            if (primary(0, &first) == ERROR_SUCCESS && extended(0, &second) == ERROR_SUCCESS &&
                primary(1, &other) == ERROR_SUCCESS && first.Gamepad.sThumbLX == -12345 &&
                first.Gamepad.bRightTrigger == 193 && other.Gamepad.wButtons == XINPUT_GAMEPAD_DPAD_UP &&
                first.Gamepad.wButtons == (masked ? 0 : XINPUT_GAMEPAD_DPAD_UP) &&
                second.Gamepad.wButtons == first.Gamepad.wButtons)
            {
                return true;
            }
            ::Sleep(1);
        }
        return false;
    }

    [[nodiscard]] int fail(const char *message)
    {
        std::fprintf(stderr, "%s\n", message);
        return 1;
    }

    /** @brief Releases the fixture worker on every proof exit. */
    class WorkerReleaseGuard
    {
    public:
        /** @brief Adopts the fixture cleanup export. */
        explicit WorkerReleaseGuard(WorkerControlFn cleanup) noexcept : m_finish(cleanup) {}
        /** @brief Releases a worker after an early proof failure. */
        ~WorkerReleaseGuard() noexcept
        {
            if (!finish())
                std::fputs("The parked worker cleanup did not witness thread exit.\n", stderr);
        }
        WorkerReleaseGuard(const WorkerReleaseGuard &) = delete;
        WorkerReleaseGuard &operator=(const WorkerReleaseGuard &) = delete;
        WorkerReleaseGuard(WorkerReleaseGuard &&) = delete;
        WorkerReleaseGuard &operator=(WorkerReleaseGuard &&) = delete;

        /** @brief Returns true after the native worker thread exits. */
        [[nodiscard]] bool finish() noexcept
        {
            if (m_finish == nullptr)
                return true;
            if (m_finish() == 0)
                return false;
            m_finish = nullptr;
            return true;
        }

    private:
        WorkerControlFn m_finish;
    };

    int run_worker_refusal(HMODULE module, bool rollback)
    {
        const auto park_worker = resolve<WorkerControlFn>(module, "example_proof_park_worker");
        const auto release_worker = resolve<WorkerControlFn>(module, "example_proof_release_worker");
        const auto roll_back_worker =
            resolve<void(DMK_WHEELHOST_CALL *)() noexcept>(module, "example_proof_roll_back_worker");
        if (park_worker == nullptr || release_worker == nullptr || roll_back_worker == nullptr)
            return fail("The worker proof exports are absent.");
        WorkerReleaseGuard release{release_worker};
        if (park_worker() != 1)
            return fail("The worker did not park before its final hook call.");
        const auto before = snapshot(module);
        if (before[2] != 1 || before[5] != 1 || before[6] != 1 || before[12] != 1 || before[13] != 1 ||
            before[14] != 1 || before[15] != 0 || before[16] != 0)
            return fail("The parked worker did not retain its live hook dependencies.");
        const auto dependencies_intact = [module]() -> bool
        {
            const auto state = snapshot(module);
            return s_current && s_current->module == module && s_generation_counter == 1 && s_retained_count == 0 &&
                   !s_restart_required && state[0] == 1 && state[2] == 1 && state[5] == 1 && state[6] == 1 &&
                   state[7] == 0 && state[12] == 1 && state[13] == 1 && state[16] == 0 && state[17] == 1;
        };
        if (rollback)
        {
            roll_back_worker();
            if (!dependencies_intact() || snapshot(module)[15] != 0)
                return fail("Rollback retired dependencies before the worker exited.");
            roll_back_worker();
            if (!dependencies_intact() || snapshot(module)[15] != 0)
                return fail("Repeated rollback bypassed the failed worker join.");
        }
        reload_once();
        if (!dependencies_intact() || snapshot(module)[15] != 0)
            return fail("A failed worker join retired dependencies or accepted a successor.");
        reload_once();
        if (!dependencies_intact() || snapshot(module)[15] != 0)
            return fail("A reload retry bypassed the failed worker join.");
        if (!release.finish())
            return fail("The released worker did not exit before its deadline.");
        const auto exited = snapshot(module);
        if (exited[15] != 1 || exited[18] != 115 || exited[8] != before[8] + 1)
            return fail("The released worker lost its original hook path.");
        reload_once();
        if (!dependencies_intact())
            return fail("Worker exit cleared the permanent teardown refusal.");
        std::puts("The failed worker join preserves dependencies and refuses every successor.");
        return 0;
    }

    [[nodiscard]] std::filesystem::path fresh_proof_directory()
    {
        const auto root = std::filesystem::current_path();
        for (unsigned nonce = 1; nonce <= 1024; ++nonce)
        {
            const auto candidate = root / std::format("staged_example.p{}_n{}", _getpid(), nonce);
            if (std::filesystem::create_directory(candidate))
                return candidate;
        }
        return {};
    }

    int run(const std::filesystem::path &fixture, std::string_view scenario)
    {
        const auto directory = fresh_proof_directory();
        if (directory.empty())
            return fail("The sample proof has no fresh directory.");
        const auto anchor_path = directory / std::format("anchor.p{}_n1.dll", _getpid());
        std::filesystem::copy_file(fixture, anchor_path);
        s_loader_module = ::LoadLibraryW(anchor_path.c_str());
        if (s_loader_module == nullptr)
            return fail("The directory anchor did not load.");
        const HMODULE provider = ::LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (provider == nullptr)
            return fail("The required controller provider did not load.");
        resolve<void(WINAPI *)(BOOL)>(provider, "dmk_xinput_set_success_state")(TRUE);
        resolve<void(WINAPI *)(WORD)>(provider, "dmk_xinput_set_buttons")(XINPUT_GAMEPAD_DPAD_UP);
        const auto primary = resolve<StateFn>(provider, "XInputGetState");
        const auto extended = resolve<StateFn>(provider, MAKEINTRESOURCEA(100));
        if (primary == nullptr || extended == nullptr)
            return fail("The paired provider exports are absent.");
        const HWND window = ::CreateWindowExW(
            0,
            L"STATIC",
            L"DMK sample proof",
            WS_OVERLAPPEDWINDOW,
            0,
            0,
            200,
            150,
            nullptr,
            nullptr,
            ::GetModuleHandleW(nullptr),
            nullptr
        );
        if (window == nullptr)
            return fail("The required wheel window is absent.");
        ::ShowWindow(window, SW_SHOWNA);
        if (wheel_host_start(
                ::GetCurrentThreadId(),
                DMK_WHEELHOST_ABI_VERSION,
                static_cast<std::uint32_t>(sizeof(s_wheel_host)),
                &s_wheel_host
            ) != DMK_WHEELHOST_OK)
            return fail("The resident wheel host did not start.");
        s_host_identity = s_wheel_host.host_identity;
        const bool worker_failure = scenario == "worker-join-failure" || scenario == "worker-rollback-failure";
        if (!write_ini(scenario != "leak" && scenario != "drain-retry" && !worker_failure))
            return fail("The INI write failed.");
        if (scenario != "missing-export" && !write_build(fixture, 1))
            return fail("The first fresh build write failed.");
        if (scenario == "failed-init")
        {
            ::SetEnvironmentVariableW(L"DMK_EXAMPLE_PROOF_FAIL_INIT", L"1");
            if (load_generation() || s_current.has_value() || s_restart_required || s_retained_count != 0)
                return fail("A failed Init did not roll back and unmap cleanly.");
            ::SetEnvironmentVariableW(L"DMK_EXAMPLE_PROOF_FAIL_INIT", nullptr);
        }
        if (scenario == "missing-export")
        {
            std::filesystem::copy_file("dmk_xinput_proxy_local.dll", directory / L"StagedExampleProof.logic.dll");
            if (load_generation() || !s_restart_required || s_retained_count != 1 ||
                s_retained_loader_refs[0] == nullptr)
                return fail("An unresolved Shutdown did not preserve the failed image and require restart.");
            return 0;
        }
        if (!load_generation() || !s_current || std::string_view{s_current->revision()} != "0000000000000001")
            return fail("The first generation did not start from fresh bytes.");
        std::uint32_t mounted_hooks = 0, thread_handles = 0, active_leases = 0;
        std::uint64_t mount_generation = 0;
        wheel_host_test_snapshot(&mounted_hooks, &thread_handles, &active_leases, &mount_generation);
        if (mounted_hooks != 1 || active_leases != 1 || mount_generation == 0)
            return fail("The generation did not own a lease on the mounted wheel host.");
        const HMODULE first_module = s_current->module;
        const auto first_path = s_current->path;
        if (worker_failure)
            return run_worker_refusal(first_module, scenario == "worker-rollback-failure");
        if (scenario == "drain-retry")
        {
            using ParkFn = std::uint32_t(DMK_WHEELHOST_CALL *)() noexcept;
            using ReleaseFn = void(DMK_WHEELHOST_CALL *)() noexcept;
            const auto park_callback = resolve<ParkFn>(first_module, "example_proof_park_callback");
            const auto release_callback = resolve<ReleaseFn>(first_module, "example_proof_release_callback");
            if (park_callback == nullptr || release_callback == nullptr || park_callback() != 1)
                return fail("The callback park did not register.");
            resolve<void(WINAPI *)(WORD)>(provider, "dmk_xinput_set_buttons")(XINPUT_GAMEPAD_DPAD_DOWN);
            const ULONGLONG park_deadline = ::GetTickCount64() + 5000;
            while (snapshot(first_module)[9] == 0 || snapshot(first_module)[8] == 0)
            {
                if (::GetTickCount64() >= park_deadline)
                {
                    release_callback();
                    return fail("The input callback and heartbeat did not both execute.");
                }
                ::Sleep(1);
            }
            const ULONGLONG started = ::GetTickCount64();
            reload_once();
            const ULONGLONG elapsed = ::GetTickCount64() - started;
            const auto refused = snapshot(first_module);
            release_callback();
            if (!s_current || s_current->module != first_module || s_generation_counter != 1 || s_retained_count != 0 ||
                s_restart_required || refused[2] != 1 || refused[6] != 0 || refused[7] != 0 || refused[10] != 0 ||
                refused[11] != 0 || elapsed >= 5000)
                return fail("A parked callback escaped refusal or the heartbeat remained live.");
            std::printf(
                "Refused drain: hook pins=%llu, worker pins=%llu, hook calls=%llu, elapsed=%llu ms.\n",
                static_cast<unsigned long long>(refused[5]),
                static_cast<unsigned long long>(refused[6]),
                static_cast<unsigned long long>(refused[8]),
                static_cast<unsigned long long>(elapsed)
            );
            const std::uint32_t verdict = s_current->shutdown();
            const auto retired = snapshot(first_module);
            if (verdict != DMK_STAGED_RELOAD_OK || retired[2] != 0 || retired[4] != 0 || retired[8] != refused[8] ||
                retired[10] != 1 || retired[11] != 0)
                return fail("The retry failed to retire callbacks, hooks, and worker ownership.");
            const void *const old_address = s_current->unmap_address;
            if (!unload_current() || s_current || s_retained_count != 0 || !wait_for_unmap(old_address))
                return fail("The retired generation did not unmap after the successful retry.");
            if (!write_build(fixture, 2) || !load_generation() || !s_current ||
                std::string_view{s_current->revision()} != "0000000000000002" || snapshot(s_current->module)[0] != 1)
                return fail("The successor did not initialize from fresh bytes.");
            if (!unload_current() || wheel_host_stop() != DMK_WHEELHOST_OK)
                return fail("The drain proof did not retire its successor.");
            ::DestroyWindow(window);
            std::puts("Retry: callbacks retired, hook calls unchanged, image unmapped, fresh successor accepted.");
            return 0;
        }
        if (scenario == "refused")
        {
            resolve<FaultFn>(first_module, "example_proof_fault")(2);
            reload_once();
            if (!s_current || s_current->module != first_module || s_generation_counter != 1 ||
                snapshot(first_module)[0] != 1 || s_retained_count != 0)
                return fail("Unsafe teardown did not stop the successor or repeated Init.");
            return 0;
        }
        if (scenario == "budget")
        {
            s_retained_count = MAX_RETAINED_GENERATIONS - 1;
            reload_once();
            if (!s_restart_required || !s_current || snapshot(first_module)[2] != 1 || s_generation_counter != 1)
                return fail("The count budget did not stop before teardown.");
            s_restart_required = false;
            s_retained_count = 0;
            s_retained_bytes = MAX_RETAINED_BYTES;
            reload_once();
            if (!s_restart_required || !s_current || snapshot(first_module)[2] != 1 || s_generation_counter != 1)
                return fail("The byte budget did not stop before teardown.");
            s_restart_required = false;
            s_retained_bytes = 0;
            if (!unload_current() || wheel_host_stop() != DMK_WHEELHOST_OK)
                return fail("The budget proof did not retire its live fixture before process exit.");
            ::DestroyWindow(window);
            return 0;
        }
        std::optional<safetyhook::InlineHook> rival;
        if (scenario == "retained")
        {
            if (!wait_for_mask(primary, extended, true))
                return fail("INI Consume did not suppress both controller exports.");
            for (unsigned i = 0; snapshot(first_module)[1] == 0 && i < 5000; ++i)
                ::Sleep(1);
            if (snapshot(first_module)[1] == 0)
                return fail("Raw controller input did not trigger the generation callback.");
            auto created = safetyhook::InlineHook::create(primary, &rival_state, safetyhook::InlineHook::StartDisabled);
            if (!created)
                return fail("The newer XInput layer did not install.");
            rival.emplace(std::move(*created));
            s_rival_original.store(rival->original<StateFn>(), std::memory_order_release);
            if (!rival->enable())
                return fail("The newer XInput layer did not enable.");
        }
        else if (scenario == "leak")
        {
            resolve<FaultFn>(first_module, "example_proof_fault")(1);
        }
        if (!write_build(fixture, 2))
            return fail("The second fresh build write failed.");
        reload_once();
        if (!s_current || s_current->path == first_path || s_restart_required ||
            std::string_view{s_current->revision()} != "0000000000000002")
            return fail("The successor did not execute the new build bytes.");
        if (scenario == "retained" || scenario == "leak")
        {
            if (s_current->module == first_module || s_retained_count != 1 ||
                s_retained_loader_refs[0] != first_module || s_retained_bytes == 0)
                return fail("The retired image lost its loader reference or budget charge.");
            const auto old = snapshot(first_module);
            if (old[0] != 1 || old[2] != 0 || (scenario == "retained" ? old[3] != 1 : old[4] != 0))
                return fail("Retirement left old feature state or invalid pin ownership.");
            if (!wait_for_mask(primary, extended, scenario == "retained"))
                return fail("Controller behavior did not survive the fresh successor.");
            if (snapshot(first_module)[1] != old[1] || snapshot(s_current->module)[0] != 1)
                return fail("The old image received feature callbacks or another Init.");
        }
        if (scenario == "retained")
        {
            const auto old_presses = snapshot(first_module)[1];
            for (unsigned revision = 3; revision <= 4; ++revision)
            {
                const bool consume = revision == 4;
                const auto prior_path = s_current->path;
                if (!write_ini(consume) || !write_build(fixture, revision))
                    return fail("The INI transition or fresh build write failed.");
                reload_once();
                if (!s_current || s_restart_required || s_current->path == prior_path ||
                    std::string_view{s_current->revision()} != std::format("{:016}", revision) ||
                    !wait_for_mask(primary, extended, consume) || snapshot(first_module)[1] != old_presses ||
                    snapshot(s_current->module)[0] != 1)
                    return fail("An INI Consume transition blocked fresh code or revived an old generation.");
            }
        }
        if (!unload_current() || !wait_for_mask(primary, extended, false))
            return fail("Final retirement did not restore raw controller input.");
        if (rival && !rival->disable())
            return fail("The foreign layer did not return ownership after retirement.");
        if (wheel_host_stop() != DMK_WHEELHOST_OK)
            return fail("The wheel host did not stop after every lease closed.");
        ::DestroyWindow(window);
        return 0;
    }

    int run_directory_collision(const std::filesystem::path &fixture)
    {
        const auto directory = fresh_proof_directory();
        if (directory.empty())
            return fail("The directory collision control has no fresh directory.");
        const auto anchor = directory / std::format("anchor.p{}_n1.dll", _getpid());
        {
            std::ofstream output(anchor, std::ios::binary);
            output << "prior generation";
            if (!output.good())
                return fail("The directory collision control did not write its anchor.");
        }
        const int result = run(fixture, "retained");
        if (result != 0)
            return result;
        std::ifstream input(anchor, std::ios::binary);
        const std::string bytes{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
        if (bytes != "prior generation")
            return fail("The fresh proof changed an existing directory anchor.");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 3)
        return fail("A fixture path and scenario are required.");
    const std::string_view scenario{argv[2]};
    if (scenario != "retained" && scenario != "leak" && scenario != "refused" && scenario != "budget" &&
        scenario != "failed-init" && scenario != "missing-export" && scenario != "directory-collision" &&
        scenario != "drain-retry" && scenario != "worker-join-failure" && scenario != "worker-rollback-failure")
        return fail("Unknown sample proof scenario.");
    try
    {
        if (scenario == "directory-collision")
            return run_directory_collision(std::filesystem::absolute(argv[1]));
        return run(std::filesystem::absolute(argv[1]), scenario);
    }
    catch (const std::exception &error)
    {
        std::fprintf(stderr, "The sample proof raised an exception: %s\n", error.what());
        return 1;
    }
    catch (...)
    {
        return fail("The sample proof raised an exception.");
    }
}
