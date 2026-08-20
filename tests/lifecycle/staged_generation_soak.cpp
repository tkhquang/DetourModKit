/**
 * @file staged_generation_soak.cpp
 * @brief Proves staged-generation reload behavior in isolated processes.
 * @details Each scenario maps byte-unique copies of the consumer DLL. The host verifies clean teardown and retained
 *          chain safety. CTest supplies a process timeout and removes staged copies after exit.
 */

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/input_codes.hpp"

#include "internal/input_intercept.hpp"

#include "staged_generation_protocol.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <process.h>
#include <windows.h>

namespace
{
    using namespace std::chrono_literals;

    constexpr int SKIP_EXIT_CODE = 77;
    constexpr int SETUP_FAILURE = 2;
    constexpr int SOAK_CYCLES = 4;

    constexpr DWORD UNLOAD_POLL_BUDGET_MS = 3000;
    constexpr DWORD UNLOAD_POLL_STEP_MS = 10;
    constexpr auto PARK_BUDGET = 10s;
    constexpr WORD XINPUT_GET_STATE_EX_ORDINAL = 100;
    constexpr DWORD XINPUT_PROBE_INDEX = 2;
    constexpr std::size_t ENTRY_SNAPSHOT_BYTES = 16;
    constexpr int RIVAL_FALLBACK_RESULT = -0x6EED;

    constexpr const wchar_t *TEST_WINDOW_CLASS = L"DMKStagedGenTestWindow";

    using TargetFn = int (*)(int, int);
    using XInputGetStateFn = DWORD(WINAPI *)(DWORD, XINPUT_STATE *);
    using EntryBytes = std::array<std::uint8_t, ENTRY_SNAPSHOT_BYTES>;

    struct ModuleDeleter
    {
        void operator()(HMODULE module) const noexcept
        {
            if (module != nullptr)
            {
                ::FreeLibrary(module);
            }
        }
    };

    using UniqueModule = std::unique_ptr<std::remove_pointer_t<HMODULE>, ModuleDeleter>;

    std::atomic<TargetFn> s_hook_rival_original{nullptr};
    std::atomic<std::uint64_t> s_hook_rival_calls{0};
    std::atomic<XInputGetStateFn> s_xinput_rival_original{nullptr};
    std::atomic<std::uint64_t> s_xinput_rival_calls{0};

    int hook_rival_detour(int base, int modifier)
    {
        s_hook_rival_calls.fetch_add(1, std::memory_order_relaxed);
        const TargetFn original = s_hook_rival_original.load(std::memory_order_acquire);
        return original != nullptr ? original(base, modifier) : RIVAL_FALLBACK_RESULT;
    }

    DWORD WINAPI xinput_rival_detour(DWORD user_index, XINPUT_STATE *state) noexcept
    {
        s_xinput_rival_calls.fetch_add(1, std::memory_order_relaxed);
        const XInputGetStateFn original = s_xinput_rival_original.load(std::memory_order_acquire);
        return original != nullptr ? original(user_index, state) : ERROR_DEVICE_NOT_CONNECTED;
    }

    [[nodiscard]] int fail(const char *scenario, const char *what) noexcept
    {
        std::fprintf(stderr, "FAIL[%s]: %s\n", scenario, what);
        return 1;
    }

    void ensure_window_class_registered() noexcept
    {
        static const bool registered = []
        {
            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.lpfnWndProc = DefWindowProcW;
            wc.hInstance = GetModuleHandleW(nullptr);
            wc.lpszClassName = TEST_WINDOW_CLASS;
            return RegisterClassExW(&wc) != 0;
        }();
        (void)registered;
    }

    /// Creates a visible ownerless top-level window or returns nullptr on a headless host.
    [[nodiscard]] HWND make_test_window() noexcept
    {
        ensure_window_class_registered();
        const HWND window =
            CreateWindowExW(0, TEST_WINDOW_CLASS, L"DMK Staged Gen", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                            200, 150, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (window != nullptr)
        {
            ShowWindow(window, SW_SHOWNA);
        }
        return window;
    }

    [[nodiscard]] UniqueModule load_module(const char *name) noexcept
    {
        return UniqueModule{::LoadLibraryA(name)};
    }

    [[nodiscard]] std::string make_log_name(std::string_view stem)
    {
        static std::atomic<unsigned> s_counter{0};
        const unsigned nonce = s_counter.fetch_add(1, std::memory_order_relaxed);
        return std::string{stem} + ".p" + std::to_string(static_cast<unsigned long>(_getpid())) + "_n" +
               std::to_string(nonce) + ".log";
    }

    [[nodiscard]] EntryBytes read_entry_bytes(const void *entry) noexcept
    {
        EntryBytes bytes{};
        std::memcpy(bytes.data(), entry, bytes.size());
        return bytes;
    }

    [[nodiscard]] bool proxy_result_matches(XInputGetStateFn get_state) noexcept
    {
        XINPUT_STATE state{};
        state.dwPacketNumber = 0xFFFFFFFFu;
        const DWORD result = get_state(XINPUT_PROBE_INDEX, &state);
        return result == ERROR_DEVICE_NOT_CONNECTED && state.dwPacketNumber == XINPUT_PROBE_INDEX;
    }

    [[nodiscard]] bool module_owns(const void *address) noexcept
    {
        HMODULE owner = nullptr;
        const BOOL ok =
            ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 reinterpret_cast<LPCWSTR>(address), &owner);
        return ok != FALSE && owner != nullptr;
    }

    [[nodiscard]] bool wait_for_unmap(const void *marker) noexcept
    {
        DWORD waited = 0;
        while (module_owns(marker) && waited < UNLOAD_POLL_BUDGET_MS)
        {
            ::Sleep(UNLOAD_POLL_STEP_MS);
            waited += UNLOAD_POLL_STEP_MS;
        }
        return !module_owns(marker);
    }

    /**
     * @struct Generation
     * @brief One loaded staged copy and every export the scenarios drive.
     */
    struct Generation
    {
        std::filesystem::path path;
        HMODULE module = nullptr;
        const void *marker = nullptr;
        staged_gen::InitFn init = nullptr;
        staged_gen::ShutdownFn shutdown = nullptr;
        staged_gen::TagFn tag = nullptr;
        staged_gen::StatusFn status = nullptr;
        staged_gen::ArmParkFn arm_park = nullptr;
        staged_gen::ReleaseParkFn release_park = nullptr;
        staged_gen::WaitParkedFn wait_parked = nullptr;

        [[nodiscard]] staged_gen::Status read_status() const noexcept
        {
            staged_gen::Status snapshot{};
            status(&snapshot);
            return snapshot;
        }
    };

    template <class Fn> [[nodiscard]] Fn resolve(HMODULE module, const char *symbol) noexcept
    {
        return reinterpret_cast<Fn>(reinterpret_cast<void *>(::GetProcAddress(module, symbol)));
    }

    /// Copies the source image to a per-process unique name and rewrites the tag bytes to @p tag_value.
    [[nodiscard]] bool stage_copy(const std::string &tag_value, std::filesystem::path &staged)
    {
        static std::atomic<unsigned> s_counter{0};
        std::error_code error;
        const std::filesystem::path source = std::filesystem::current_path(error) / staged_gen::SOURCE_MODULE_NAME;
        if (error)
        {
            return false;
        }
        const unsigned nonce = s_counter.fetch_add(1, std::memory_order_relaxed);
        staged = source.parent_path() / ("staged_generation.p" + std::to_string(static_cast<unsigned long>(_getpid())) +
                                         "_g" + std::to_string(nonce) + ".dll");
        std::filesystem::copy_file(source, staged, std::filesystem::copy_options::overwrite_existing, error);
        if (error)
        {
            return false;
        }

        std::fstream file(staged, std::ios::in | std::ios::out | std::ios::binary);
        if (!file)
        {
            return false;
        }
        std::vector<char> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        const std::string_view needle{staged_gen::TAG_MARKER};
        const auto found = std::string_view{bytes.data(), bytes.size()}.find(needle);
        if (found == std::string_view::npos)
        {
            return false;
        }
        const std::size_t tag_at = found + needle.size();
        if (tag_at + staged_gen::TAG_LENGTH > bytes.size())
        {
            return false;
        }
        for (std::size_t i = 0; i < staged_gen::TAG_LENGTH; ++i)
        {
            bytes[tag_at + i] = i < tag_value.size() ? tag_value[i] : '0';
        }
        file.seekp(static_cast<std::streamoff>(tag_at), std::ios::beg);
        file.write(bytes.data() + tag_at, static_cast<std::streamsize>(staged_gen::TAG_LENGTH));
        return static_cast<bool>(file);
    }

    [[nodiscard]] bool load_generation(const std::string &tag_value, Generation &generation)
    {
        if (!stage_copy(tag_value, generation.path))
        {
            return false;
        }
        generation.module = ::LoadLibraryW(generation.path.c_str());
        if (generation.module == nullptr)
        {
            return false;
        }
        generation.marker =
            reinterpret_cast<const void *>(::GetProcAddress(generation.module, staged_gen::MARKER_SYMBOL));
        generation.init = resolve<staged_gen::InitFn>(generation.module, staged_gen::INIT_SYMBOL);
        generation.shutdown = resolve<staged_gen::ShutdownFn>(generation.module, staged_gen::SHUTDOWN_SYMBOL);
        generation.tag = resolve<staged_gen::TagFn>(generation.module, staged_gen::TAG_SYMBOL);
        generation.status = resolve<staged_gen::StatusFn>(generation.module, staged_gen::STATUS_SYMBOL);
        generation.arm_park = resolve<staged_gen::ArmParkFn>(generation.module, staged_gen::ARM_PARK_SYMBOL);
        generation.release_park =
            resolve<staged_gen::ReleaseParkFn>(generation.module, staged_gen::RELEASE_PARK_SYMBOL);
        generation.wait_parked = resolve<staged_gen::WaitParkedFn>(generation.module, staged_gen::WAIT_PARKED_SYMBOL);
        return generation.marker != nullptr && generation.init != nullptr && generation.shutdown != nullptr &&
               generation.tag != nullptr && generation.status != nullptr && generation.arm_park != nullptr &&
               generation.release_park != nullptr && generation.wait_parked != nullptr;
    }

    [[nodiscard]] bool unload_generation(Generation &generation) noexcept
    {
        if (generation.module == nullptr)
        {
            return true;
        }
        if (::FreeLibrary(generation.module) == 0)
        {
            return false;
        }
        generation.module = nullptr;
        return true;
    }

    void remove_unmapped_staged_file_best_effort(const Generation &generation) noexcept
    {
        std::error_code error;
        (void)std::filesystem::remove(generation.path, error);
    }

    int run_soak()
    {
        UniqueModule proxy = load_module(staged_gen::XINPUT_PROXY_MODULE_NAME);
        if (!proxy)
        {
            return fail("soak", "failed to load the required XInput proxy");
        }
        const auto *const primary_entry =
            reinterpret_cast<const void *>(::GetProcAddress(proxy.get(), "XInputGetState"));
        const auto *const extended_entry = reinterpret_cast<const void *>(
            ::GetProcAddress(proxy.get(), MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        const auto get_state = reinterpret_cast<XInputGetStateFn>(const_cast<void *>(primary_entry));
        if (primary_entry == nullptr || extended_entry == nullptr || primary_entry == extended_entry ||
            get_state == nullptr)
        {
            return fail("soak", "the XInput proxy did not expose two distinct state entries");
        }
        if (!proxy_result_matches(get_state))
        {
            return fail("soak", "the XInput proxy did not return its synthetic state result");
        }
        const EntryBytes primary_baseline = read_entry_bytes(primary_entry);
        const EntryBytes extended_baseline = read_entry_bytes(extended_entry);

        const HWND window = make_test_window();
        if (window == nullptr)
        {
            std::fprintf(stderr, "SKIP: staged soak needs a window station\n");
            return SKIP_EXIT_CODE;
        }

        for (int cycle = 0; cycle < SOAK_CYCLES; ++cycle)
        {
            const std::string tag = "GEN" + std::to_string(cycle * 7 + 3);
            Generation generation;
            if (!load_generation(tag, generation))
            {
                return fail("soak", "failed to stage and load a generation");
            }

            staged_gen::InitOptions options{};
            options.wheel_window = window;
            options.enable_wheel = 1;
            options.enable_consume_gamepad = 1;
            const std::string log_name = make_log_name("staged_gen_soak");
            options.log_file = log_name.c_str();
            if (generation.init(&options) == 0)
            {
                return fail("soak", "the generation's Init did not bring every subsystem up");
            }

            // The loaded tag rejects a stale pinned predecessor.
            if (std::strncmp(generation.tag(), tag.c_str(), tag.size()) != 0)
            {
                return fail("soak", "the loaded generation did not run the freshly staged bytes");
            }

            const staged_gen::Status live = generation.read_status();
            if (live.wndproc_installed == 0 || live.xinput_installed == 0)
            {
                return fail("soak", "an interception layer was not live before teardown");
            }

            if (generation.shutdown() == 0)
            {
                return fail("soak", "a clean generation's Shutdown did not accept the reload");
            }

            const staged_gen::Status after = generation.read_status();
            if (after.wndproc_installed != 0 || after.xinput_installed != 0)
            {
                return fail("soak", "the interception layer stayed installed after teardown");
            }
            if (after.wheel_pins != 1)
            {
                return fail("soak", "the generation did not hold exactly its own permanent wheel keepalive");
            }
            if (after.xinput_self_pins != 0 || after.xinput_target_pins != 0 || after.hook_manager_leaks != 0)
            {
                return fail("soak", "a clean generation retained an interception chain");
            }
            if (read_entry_bytes(primary_entry) != primary_baseline ||
                read_entry_bytes(extended_entry) != extended_baseline)
            {
                return fail("soak", "clean teardown did not restore both persistent XInput entries");
            }
            if (!proxy_result_matches(get_state))
            {
                return fail("soak", "the persistent XInput provider was not callable after teardown");
            }

            if (!unload_generation(generation))
            {
                return fail("soak", "FreeLibrary rejected the clean generation loader reference");
            }
            if (!module_owns(generation.marker))
            {
                return fail("soak", "a wheel generation unmapped despite its permanent keepalive");
            }
            const staged_gen::Status retained = generation.read_status();
            if (retained.init_calls != 1)
            {
                return fail("soak", "the retained generation's own state was not readable after unload");
            }
        }

        std::fprintf(stderr, "OK: %d staged generations restored one persistent XInput provider exactly\n",
                     SOAK_CYCLES);
        return 0;
    }

    int run_wheel_resubclass()
    {
        const HWND window = make_test_window();
        if (window == nullptr)
        {
            std::fprintf(stderr, "SKIP: wheel re-subclass needs a window station\n");
            return SKIP_EXIT_CODE;
        }

        const LONG_PTR original_proc = GetWindowLongPtrW(window, GWLP_WNDPROC);

        Generation first;
        if (!load_generation("WHEELA", first))
        {
            return fail("wheel-resubclass", "failed to stage generation A");
        }
        staged_gen::InitOptions options{};
        options.wheel_window = window;
        options.enable_wheel = 1;
        const std::string first_log_name = make_log_name("staged_gen_wheel_a");
        options.log_file = first_log_name.c_str();
        if (first.init(&options) == 0)
        {
            return fail("wheel-resubclass", "generation A did not install its wheel subclass");
        }
        const LONG_PTR first_subclassed_proc = GetWindowLongPtrW(window, GWLP_WNDPROC);
        if (first_subclassed_proc == original_proc)
        {
            return fail("wheel-resubclass", "generation A did not change the window procedure");
        }
        if (first.read_status().wheel_pins != 1)
        {
            return fail("wheel-resubclass", "generation A did not book its own wheel keepalive");
        }

        // Topmost teardown restores the window procedure so the next generation subclasses a clean window.
        if (first.shutdown() == 0)
        {
            return fail("wheel-resubclass", "generation A's Shutdown did not accept the reload");
        }
        if (GetWindowLongPtrW(window, GWLP_WNDPROC) != original_proc)
        {
            return fail("wheel-resubclass", "topmost teardown did not restore the original window procedure");
        }
        // The keepalive is permanent: it survives A's own teardown and pins A's module past FreeLibrary.
        if (first.read_status().wheel_pins != 1)
        {
            return fail("wheel-resubclass", "generation A's teardown released the permanent wheel keepalive");
        }
        if (!unload_generation(first))
        {
            return fail("wheel-resubclass", "FreeLibrary rejected generation A's loader reference");
        }
        if (!module_owns(first.marker))
        {
            return fail("wheel-resubclass", "generation A unmapped despite its permanent keepalive");
        }

        Generation second;
        if (!load_generation("WHEELB", second))
        {
            return fail("wheel-resubclass", "failed to stage generation B");
        }
        const std::string second_log_name = make_log_name("staged_gen_wheel_b");
        options.log_file = second_log_name.c_str();
        if (second.init(&options) == 0)
        {
            return fail("wheel-resubclass", "generation B did not subclass the restored window");
        }
        const LONG_PTR second_subclassed_proc = GetWindowLongPtrW(window, GWLP_WNDPROC);
        if (second_subclassed_proc == original_proc || second_subclassed_proc == first_subclassed_proc)
        {
            return fail("wheel-resubclass", "generation B did not install its distinct fresh subclass");
        }
        if (second.read_status().wheel_pins != 1)
        {
            return fail("wheel-resubclass", "generation B did not book its own per-generation keepalive");
        }
        if (second.shutdown() == 0)
        {
            return fail("wheel-resubclass", "generation B's Shutdown did not accept the reload");
        }
        if (GetWindowLongPtrW(window, GWLP_WNDPROC) != original_proc)
        {
            return fail("wheel-resubclass", "generation B did not restore the original window procedure");
        }
        if (second.read_status().wheel_pins != 1)
        {
            return fail("wheel-resubclass", "generation B's teardown released its permanent wheel keepalive");
        }
        if (!unload_generation(second))
        {
            return fail("wheel-resubclass", "FreeLibrary rejected generation B's loader reference");
        }
        if (!module_owns(second.marker))
        {
            return fail("wheel-resubclass", "generation B unmapped despite its permanent keepalive");
        }

        std::fprintf(stderr, "OK: each generation subclassed fresh, restored topmost, and pinned per-generation\n");
        return 0;
    }

    // This in-process control checks the host archive's clear_bindings and poller shutdown paths.
    int run_uninstall_call_site()
    {
        using namespace DetourModKit;
        namespace diag = diagnostics;

        const HWND window = make_test_window();
        if (window == nullptr)
        {
            std::fprintf(stderr, "SKIP: uninstall call-site proof needs a window station\n");
            return SKIP_EXIT_CODE;
        }
        detail::set_wndproc_window_override_for_test(window);

        Result<input::BindingGuard> wheel = input::register_combo(
            input::ComboBinding{.name = "callsite.wheel",
                                .trigger = input::Trigger::Press,
                                .combos = {{.keys = {mouse_wheel(WheelCode::Up)}, .modifiers = {}}},
                                .consume = true,
                                .on_press = [] {}});
        if (!wheel)
        {
            detail::set_wndproc_window_override_for_test(nullptr);
            return fail("uninstall-call-site", "wheel binding registration failed");
        }
        input::BindingGuard guard = std::move(*wheel);

        if (!input::Input::instance().start(input::Input::Settings{.poll_interval = 2ms, .require_focus = false}))
        {
            detail::set_wndproc_window_override_for_test(nullptr);
            return fail("uninstall-call-site", "input engine did not start");
        }

        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (!detail::wndproc_installed() && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(1ms);
        }
        if (!detail::wndproc_installed())
        {
            input::Input::instance().shutdown();
            detail::set_wndproc_window_override_for_test(nullptr);
            return fail("uninstall-call-site", "the wheel subclass never installed");
        }
        const std::size_t wheel_pin_installed = diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive);

        // Binding removal must leave interception installed. Only poller shutdown owns uninstall().
        guard.release();
        input::Input::instance().clear_bindings();
        std::this_thread::sleep_for(50ms);
        if (!detail::wndproc_installed())
        {
            input::Input::instance().shutdown();
            detail::set_wndproc_window_override_for_test(nullptr);
            return fail("uninstall-call-site", "binding removal tore the interception layer down");
        }
        if (diag::module_pin_count(diag::ModulePinReason::WndprocKeepalive) != wheel_pin_installed)
        {
            input::Input::instance().shutdown();
            detail::set_wndproc_window_override_for_test(nullptr);
            return fail("uninstall-call-site", "binding removal disturbed the wheel keepalive");
        }

        // Poller shutdown restores the window procedure.
        input::Input::instance().shutdown();
        if (detail::wndproc_installed())
        {
            detail::set_wndproc_window_override_for_test(nullptr);
            return fail("uninstall-call-site", "the poll-thread stop path did not uninstall the layer");
        }
        detail::set_wndproc_window_override_for_test(nullptr);

        std::fprintf(stderr, "OK: clear_bindings left the layer up. Only the poll-thread stop path uninstalled it\n");
        return 0;
    }

    int run_parked_and_retry(bool release_before_retry)
    {
        const char *const scenario = release_before_retry ? "drain-retry" : "parked-callback";

        Generation generation;
        if (!load_generation("PARKGEN", generation))
        {
            return fail(scenario, "failed to stage the parked-callback generation");
        }
        staged_gen::InitOptions options{};
        options.enable_probe_binding = 1;
        options.drain_timeout_ms = 300;
        const std::string log_name = make_log_name("staged_gen_parked");
        options.log_file = log_name.c_str();
        if (generation.init(&options) == 0)
        {
            return fail(scenario, "the parked-callback generation did not start");
        }

        generation.arm_park();
        if (generation.wait_parked(static_cast<std::uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(PARK_BUDGET).count())) == 0)
        {
            return fail(scenario, "the binding callback never parked inside DetourModKit");
        }

        // A callback parked inside DetourModKit makes the drain refuse, so Shutdown returns the reload refusal.
        if (generation.shutdown() != 0)
        {
            generation.release_park();
            return fail(scenario, "Shutdown accepted the reload while a callback was parked");
        }

        generation.release_park();
        bool accepted = false;
        const auto deadline = std::chrono::steady_clock::now() + PARK_BUDGET;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (generation.shutdown() != 0)
            {
                accepted = true;
                break;
            }
            std::this_thread::sleep_for(5ms);
        }
        if (!accepted)
        {
            return fail(scenario, "the retried Shutdown never accepted after the release");
        }
        const void *const marker = generation.marker;
        if (!unload_generation(generation))
        {
            return fail(scenario, "FreeLibrary rejected the drained generation loader reference");
        }
        if (!wait_for_unmap(marker))
        {
            return fail(scenario, "the drained generation stayed mapped after its loader reference dropped");
        }
        remove_unmapped_staged_file_best_effort(generation);

        std::fprintf(stderr, release_before_retry ? "OK: the refused reload succeeded after callback release\n"
                                                  : "OK: a parked callback refused reload and then drained safely\n");
        return 0;
    }

    int run_partial_init()
    {
        UniqueModule target_module = load_module(staged_gen::HOOK_TARGET_MODULE_NAME);
        if (!target_module)
        {
            return fail("partial-init", "failed to load the required hook target fixture");
        }
        const TargetFn target = resolve<TargetFn>(target_module.get(), staged_gen::HOOK_TARGET_SYMBOL);
        if (target == nullptr)
        {
            return fail("partial-init", "the hook target fixture did not export the required symbol");
        }
        constexpr int base = 19;
        constexpr int modifier = 6;
        constexpr int original_result = base + modifier;
        if (target(base, modifier) != original_result)
        {
            return fail("partial-init", "the hook target fixture did not return its baseline result");
        }

        Generation failed_generation;
        if (!load_generation("PARTIAL", failed_generation))
        {
            return fail("partial-init", "failed to stage the partial-init generation");
        }
        staged_gen::InitOptions options{};
        options.fail_stage = static_cast<int>(staged_gen::FailStage::AfterHook);
        const std::string failed_log_name = make_log_name("staged_gen_partial");
        options.log_file = failed_log_name.c_str();
        if (failed_generation.init(&options) != 0)
        {
            return fail("partial-init", "Init reported success despite a forced mid-sequence failure");
        }
        const staged_gen::Status failed_status = failed_generation.read_status();
        if (failed_status.init_calls != 1 || failed_status.hook_calls != 1 || failed_status.hook_manager_leaks != 0)
        {
            return fail("partial-init", "the forced failure did not exercise one clean hook rollback");
        }
        if (target(base, modifier) != original_result ||
            failed_generation.read_status().hook_calls != failed_status.hook_calls)
        {
            return fail("partial-init", "the failed Init left its target hook reachable");
        }

        const void *const failed_marker = failed_generation.marker;
        if (!unload_generation(failed_generation))
        {
            return fail("partial-init", "FreeLibrary rejected the failed generation loader reference");
        }
        if (!wait_for_unmap(failed_marker))
        {
            return fail("partial-init", "a failed generation stayed mapped, so Init did not roll back");
        }
        remove_unmapped_staged_file_best_effort(failed_generation);

        Generation retained_generation;
        if (!load_generation("HOOKREFUSE", retained_generation))
        {
            return fail("partial-init", "failed to stage the HookManager refusal generation");
        }
        options = {};
        const std::string retained_log_name = make_log_name("staged_gen_hook_refusal");
        options.log_file = retained_log_name.c_str();
        if (retained_generation.init(&options) == 0)
        {
            return fail("partial-init", "the HookManager refusal generation did not start");
        }

        const staged_gen::Status before_generation_call = retained_generation.read_status();
        const int chained_result = target(base, modifier);
        const staged_gen::Status after_generation_call = retained_generation.read_status();
        if (chained_result == original_result ||
            after_generation_call.hook_calls != before_generation_call.hook_calls + 1)
        {
            return fail("partial-init", "the generation's base hook did not establish the refusal premise");
        }

        DetourModKit::hook::InlineRequest request{.name = "staged_gen_host_newer_hook",
                                                  .target =
                                                      DetourModKit::Address{reinterpret_cast<std::uintptr_t>(target)},
                                                  .options = {.prologue = DetourModKit::hook::Prologue::Relocate}};
        auto installed = DetourModKit::hook::inline_at(std::move(request), &hook_rival_detour);
        if (!installed)
        {
            return fail("partial-init", "the host failed to create the newer hook layer");
        }
        {
            DetourModKit::hook::Hook newer = std::move(*installed);
            s_hook_rival_original.store(newer.original<TargetFn>(), std::memory_order_release);
            s_hook_rival_calls.store(0, std::memory_order_relaxed);
            if (!newer.enable())
            {
                s_hook_rival_original.store(nullptr, std::memory_order_release);
                return fail("partial-init", "the host failed to arm the newer hook layer");
            }

            const std::uint64_t hook_calls_before_layered_call = retained_generation.read_status().hook_calls;
            if (target(base, modifier) != chained_result || s_hook_rival_calls.load(std::memory_order_relaxed) != 1 ||
                retained_generation.read_status().hook_calls != hook_calls_before_layered_call + 1)
            {
                s_hook_rival_original.store(nullptr, std::memory_order_release);
                return fail("partial-init", "the newer host hook did not forward through the generation");
            }

            const std::uint64_t leaks_before = retained_generation.read_status().hook_manager_leaks;
            if (retained_generation.shutdown() != 0)
            {
                s_hook_rival_original.store(nullptr, std::memory_order_release);
                return fail("partial-init", "Shutdown accepted unload below the newer host hook");
            }
            const staged_gen::Status refused = retained_generation.read_status();
            if (refused.hook_manager_leaks == 0 || refused.hook_manager_leaks <= leaks_before)
            {
                s_hook_rival_original.store(nullptr, std::memory_order_release);
                return fail("partial-init", "the refused HookManager teardown did not book its retained layer");
            }

            const std::uint64_t hook_calls_before_refused_call = refused.hook_calls;
            if (target(base, modifier) != chained_result || s_hook_rival_calls.load(std::memory_order_relaxed) != 2 ||
                retained_generation.read_status().hook_calls != hook_calls_before_refused_call + 1)
            {
                s_hook_rival_original.store(nullptr, std::memory_order_release);
                return fail("partial-init", "the refused generation did not remain callable through the newer hook");
            }
        }
        s_hook_rival_original.store(nullptr, std::memory_order_release);

        target_module.reset();
        if (!module_owns(reinterpret_cast<const void *>(target)))
        {
            return fail("partial-init", "the refused generation did not retain the hook target module");
        }
        if (!module_owns(retained_generation.marker))
        {
            return fail("partial-init", "the generation loader reference did not remain mapped");
        }
        const std::uint64_t hook_calls_before_hand_back = retained_generation.read_status().hook_calls;
        if (target(base, modifier) != chained_result ||
            retained_generation.read_status().hook_calls != hook_calls_before_hand_back + 1)
        {
            return fail("partial-init", "the retained generation did not survive newer-hook hand-back");
        }

        std::fprintf(stderr, "OK: partial Init rolled back and HookManager refusal retained a callable generation\n");
        return 0;
    }

    int run_foreign_xinput()
    {
        UniqueModule proxy = load_module(staged_gen::XINPUT_PROXY_MODULE_NAME);
        if (!proxy)
        {
            return fail("foreign-xinput", "failed to load the required XInput proxy");
        }
        auto *const target = reinterpret_cast<void *>(::GetProcAddress(proxy.get(), "XInputGetState"));
        auto *const extended_target =
            reinterpret_cast<void *>(::GetProcAddress(proxy.get(), MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        const auto get_state = reinterpret_cast<XInputGetStateFn>(target);
        if (target == nullptr || extended_target == nullptr || target == extended_target || get_state == nullptr)
        {
            return fail("foreign-xinput", "the XInput proxy did not expose two distinct state entries");
        }
        if (!proxy_result_matches(get_state))
        {
            return fail("foreign-xinput", "the XInput proxy did not return its synthetic state result");
        }

        Generation generation;
        if (!load_generation("FOREIGN", generation))
        {
            return fail("foreign-xinput", "failed to stage the foreign-xinput generation");
        }
        staged_gen::InitOptions options{};
        options.enable_consume_gamepad = 1;
        const std::string log_name = make_log_name("staged_gen_foreign");
        options.log_file = log_name.c_str();
        if (generation.init(&options) == 0)
        {
            return fail("foreign-xinput", "the generation did not establish XInput coverage");
        }
        if (generation.read_status().xinput_installed == 0)
        {
            return fail("foreign-xinput", "the generation did not publish live XInput coverage");
        }

        DetourModKit::hook::InlineRequest request{.name = "staged_gen_host_xinput_rival",
                                                  .target =
                                                      DetourModKit::Address{reinterpret_cast<std::uintptr_t>(target)},
                                                  .options = {.prologue = DetourModKit::hook::Prologue::Relocate}};
        auto installed = DetourModKit::hook::inline_at(std::move(request), &xinput_rival_detour);
        if (!installed)
        {
            return fail("foreign-xinput", "the host failed to create the newer XInput layer");
        }
        {
            DetourModKit::hook::Hook newer = std::move(*installed);
            s_xinput_rival_original.store(newer.original<XInputGetStateFn>(), std::memory_order_release);
            s_xinput_rival_calls.store(0, std::memory_order_relaxed);
            if (!newer.enable())
            {
                s_xinput_rival_original.store(nullptr, std::memory_order_release);
                return fail("foreign-xinput", "the host failed to arm the newer XInput layer");
            }
            if (!proxy_result_matches(get_state) || s_xinput_rival_calls.load(std::memory_order_relaxed) != 1)
            {
                s_xinput_rival_original.store(nullptr, std::memory_order_release);
                return fail("foreign-xinput", "the newer XInput layer did not forward through the generation");
            }

            if (generation.shutdown() == 0)
            {
                s_xinput_rival_original.store(nullptr, std::memory_order_release);
                return fail("foreign-xinput", "Shutdown refused the inert retained XInput pair");
            }
            const staged_gen::Status after = generation.read_status();
            if (after.xinput_installed != 0 || after.xinput_self_pins != 1 || after.xinput_target_pins != 1 ||
                after.hook_manager_leaks != 0)
            {
                s_xinput_rival_original.store(nullptr, std::memory_order_release);
                return fail("foreign-xinput", "teardown did not retain exactly the inert local XInput pair");
            }
            if (!proxy_result_matches(get_state) || s_xinput_rival_calls.load(std::memory_order_relaxed) != 2)
            {
                s_xinput_rival_original.store(nullptr, std::memory_order_release);
                return fail("foreign-xinput", "the revoked generation did not forward through the newer layer");
            }

            if (!unload_generation(generation))
            {
                s_xinput_rival_original.store(nullptr, std::memory_order_release);
                return fail("foreign-xinput", "FreeLibrary rejected the retained generation loader reference");
            }
            if (!module_owns(generation.marker))
            {
                s_xinput_rival_original.store(nullptr, std::memory_order_release);
                return fail("foreign-xinput", "the XInput self-pin did not keep the generation mapped");
            }
            if (!proxy_result_matches(get_state) || s_xinput_rival_calls.load(std::memory_order_relaxed) != 3)
            {
                s_xinput_rival_original.store(nullptr, std::memory_order_release);
                return fail("foreign-xinput", "the retained generation did not forward after FreeLibrary");
            }

            if (!newer.disable())
            {
                s_xinput_rival_original.store(nullptr, std::memory_order_release);
                return fail("foreign-xinput", "the host failed to return ownership to the retained generation");
            }
            s_xinput_rival_original.store(nullptr, std::memory_order_release);
            if (!proxy_result_matches(get_state) || s_xinput_rival_calls.load(std::memory_order_relaxed) != 3)
            {
                return fail("foreign-xinput", "the retained generation did not survive newer-layer hand-back");
            }
        }
        s_xinput_rival_original.store(nullptr, std::memory_order_release);

        std::fprintf(stderr, "OK: the retained XInput route survived revocation, FreeLibrary, and hand-back\n");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    const std::string scenario = argc > 1 ? argv[1] : "";
    if (scenario == "soak")
    {
        return run_soak();
    }
    if (scenario == "wheel-resubclass")
    {
        return run_wheel_resubclass();
    }
    if (scenario == "uninstall-call-site")
    {
        return run_uninstall_call_site();
    }
    if (scenario == "parked-callback")
    {
        return run_parked_and_retry(false);
    }
    if (scenario == "drain-retry")
    {
        return run_parked_and_retry(true);
    }
    if (scenario == "partial-init")
    {
        return run_partial_init();
    }
    if (scenario == "foreign-xinput")
    {
        return run_foreign_xinput();
    }

    std::fprintf(stderr,
                 "usage: %s soak|wheel-resubclass|uninstall-call-site|parked-callback|drain-retry|"
                 "partial-init|foreign-xinput\n",
                 argc > 0 ? argv[0] : "staged_generation_soak");
    return SETUP_FAILURE;
}
