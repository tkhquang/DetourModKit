// Fresh-process proofs for the XInput interception lifetime. Retention branches latch a process-lifetime permanent
// detour and the OOM branches replace global allocation, so no mode may share a process with another. Exit status is
// the oracle.

#include "internal/input_intercept.hpp"
#include "internal/input_poller.hpp"

#include "DetourModKit/hook.hpp"
#include "DetourModKit/input_codes.hpp"
#include "DetourModKit/logger.hpp"

#include <safetyhook.hpp>

#include <windows.h>
#include <Xinput.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <initializer_list>
#include <limits>
#include <new>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_MSC_VER)
#define DMK_LIFECYCLE_NOINLINE __declspec(noinline)
#else
#define DMK_LIFECYCLE_NOINLINE [[gnu::noinline]]
#endif

#if defined(_MSC_VER)
#include <crtdbg.h>
#endif

namespace
{
    // Thread id whose plain (non-aligned) operator new must throw, or 0 when disarmed. Armed only around uninstall() on
    // that thread so unrelated worker allocations do not weaken the caller-thread teardown contract.
    std::atomic<DWORD> s_poison_thread_id{0};
    std::atomic<DetourModKit::detail::XInputGetStateFn> s_newer_original{nullptr};
    std::atomic<int> s_newer_calls{0};
} // namespace

void *operator new(std::size_t size)
{
    if (s_poison_thread_id.load(std::memory_order_acquire) == GetCurrentThreadId())
    {
        throw std::bad_alloc{};
    }
    if (void *allocation = std::malloc(size != 0 ? size : 1))
    {
        return allocation;
    }
    throw std::bad_alloc{};
}

void *operator new[](std::size_t size)
{
    return ::operator new(size);
}

void operator delete(void *p) noexcept
{
    std::free(p);
}

void operator delete[](void *p) noexcept
{
    std::free(p);
}

void operator delete(void *p, std::size_t) noexcept
{
    std::free(p);
}

void operator delete[](void *p, std::size_t) noexcept
{
    std::free(p);
}

namespace
{
    using DetourModKit::detail::adopt_owner_for_test;
    using DetourModKit::detail::apply_xinput_suppress_for_test;
    using DetourModKit::detail::arm_xinput_process_exit_oracle_for_test;
    using DetourModKit::detail::expire_xinput_recovery_delay_for_test;
    using DetourModKit::detail::install_xinput;
    using DetourModKit::detail::publish_gamepad_suppress;
    using DetourModKit::detail::set_xinput_arm_seam;
    using DetourModKit::detail::set_xinput_backend_toggle_exception_for_test;
    using DetourModKit::detail::set_xinput_clean_release_seam;
    using DetourModKit::detail::set_xinput_create_seam;
    using DetourModKit::detail::set_xinput_detour_body_seam;
    using DetourModKit::detail::set_xinput_module_override_for_test;
    using DetourModKit::detail::set_xinput_route_entry_hold_for_test;
    using DetourModKit::detail::uninstall;
    using DetourModKit::detail::xinput_backend_toggle_exception_catches_for_test;
    using DetourModKit::detail::xinput_installed;
    using DetourModKit::detail::xinput_module_refs_held;
    using DetourModKit::detail::xinput_pair_coverage_for_test;
    using DetourModKit::detail::xinput_pair_degraded_for_test;
    using DetourModKit::detail::xinput_recovery_attempts_for_test;
    using DetourModKit::detail::xinput_trampoline;

    using XInputGetStateFn = DWORD(WINAPI *)(DWORD, XINPUT_STATE *);

    constexpr const wchar_t *XINPUT_NAMES[] = {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"};
    constexpr WORD XINPUT_GET_STATE_EX_ORDINAL = 100;

    // Reported to ctest through SKIP_RETURN_CODE. Exit status is this proof's only oracle, so a host with no XInput
    // runtime must not exit 0 and be counted as a pass that asserted nothing.
    constexpr int SKIP_EXIT_CODE = 77;

    // The parked caller signals arrival here and waits for release, so the drain has a genuinely in-flight detour.
    std::atomic<bool> s_parked{false};
    std::atomic<bool> s_release{false};
    std::atomic<bool> s_body_entered{false};

    DWORD WINAPI newer_xinput_detour(DWORD user_index, XINPUT_STATE *state) noexcept
    {
        s_newer_calls.fetch_add(1, std::memory_order_relaxed);
        const XInputGetStateFn original = s_newer_original.load(std::memory_order_acquire);
        return original != nullptr ? original(user_index, state) : ERROR_DEVICE_NOT_CONNECTED;
    }

    void park_in_detour() noexcept
    {
        s_parked.store(true, std::memory_order_release);
        while (!s_release.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

    void note_detour_body() noexcept
    {
        s_body_entered.store(true, std::memory_order_release);
    }

    void poison_clean_release() noexcept
    {
        s_poison_thread_id.store(GetCurrentThreadId(), std::memory_order_release);
    }

    void poison_hook_creation() noexcept
    {
        s_poison_thread_id.store(GetCurrentThreadId(), std::memory_order_release);
    }

    // Stands in for a third-party writer that restores the exact pre-DMK prologue while DMK's patch is live. Wider
    // than any steal window, so the restored span always covers the whole patch; the bytes past it are rewritten with
    // the values they already hold.
    constexpr std::size_t ARM_RACE_SPAN = 32;
    std::uint8_t *s_arm_race_target{nullptr};
    std::array<std::uint8_t, ARM_RACE_SPAN> s_arm_race_original{};
    std::atomic<int> s_arm_race_runs{0};
    std::atomic<bool> s_ex_arm_pass_through_probe_enabled{false};
    std::atomic<bool> s_ex_arm_call_requested{false};
    std::atomic<bool> s_ex_arm_route_reached{false};

    [[nodiscard]] bool overwrite_prologue_span(std::uint8_t *target, const std::uint8_t *bytes) noexcept
    {
        DWORD previous_protect = 0;
        if (VirtualProtect(target, ARM_RACE_SPAN, PAGE_EXECUTE_READWRITE, &previous_protect) == 0)
        {
            return false;
        }
        std::memcpy(target, bytes, ARM_RACE_SPAN);
        DWORD restored_protect = 0;
        (void)VirtualProtect(target, ARM_RACE_SPAN, previous_protect, &restored_protect);
        return true;
    }

    void restore_original_prologue_in_arm_window() noexcept
    {
        // Only the first armed hook is inverted: a second inversion would say nothing the first has not already
        // proven, and the counter is also what shows the seam reached its window at all.
        if (s_arm_race_target == nullptr || s_arm_race_runs.fetch_add(1, std::memory_order_relaxed) != 0)
        {
            return;
        }
        (void)overwrite_prologue_span(s_arm_race_target, s_arm_race_original.data());
    }

    // Inverts the ordinal-100 transaction instead of the primary one. install_xinput arms the primary first, so the
    // second window this seam sees is the Ex arm; leaving the primary armed is what makes the retained pair
    // asymmetric.
    void restore_ex_prologue_in_arm_window() noexcept
    {
        if (s_arm_race_target == nullptr || s_arm_race_runs.fetch_add(1, std::memory_order_relaxed) != 1)
        {
            return;
        }
        if (s_ex_arm_pass_through_probe_enabled.exchange(false, std::memory_order_acq_rel))
        {
            s_ex_arm_call_requested.store(true, std::memory_order_release);
            const std::uint64_t deadline_ms = GetTickCount64() + 5000;
            while (!DetourModKit::detail::xinput_route_entry_reached_for_test() && GetTickCount64() < deadline_ms)
            {
                std::this_thread::yield();
            }
            s_ex_arm_route_reached.store(DetourModKit::detail::xinput_route_entry_reached_for_test(),
                                         std::memory_order_release);
        }
        (void)overwrite_prologue_span(s_arm_race_target, s_arm_race_original.data());
    }

    // The primary target and its pre-DMK bytes, for the cases whose competing writer takes the PRIMARY export rather
    // than its ordinal-100 partner. Kept separate from the s_arm_race_* pair so one seam can invert one member's arm
    // window while the other member is the one that loses its prologue.
    std::uint8_t *s_primary_race_target{nullptr};
    std::array<std::uint8_t, ARM_RACE_SPAN> s_primary_race_original{};
    std::atomic<bool> s_installed_during_arm{true};
    std::atomic<WORD> s_masked_during_arm{0};

    // Restores the PRIMARY prologue inside the ordinal-100 arm window. install_xinput arms the primary first, so the
    // second window this seam sees is the Ex arm: the transaction therefore reaches its publication decision with the
    // Ex member armed and the primary silently handed back to whoever restored it.
    void restore_primary_prologue_in_ex_arm_window() noexcept
    {
        if (s_primary_race_target == nullptr || s_arm_race_runs.fetch_add(1, std::memory_order_relaxed) != 1)
        {
            return;
        }
        (void)overwrite_prologue_span(s_primary_race_target, s_primary_race_original.data());
    }

    // Samples the layer from inside a backend arm window. Recovery has to clear complete coverage and fail open BEFORE
    // it touches the backend, and this is the only point at which "before" is observable from outside.
    void sample_layer_state_in_arm_window() noexcept
    {
        s_installed_during_arm.store(xinput_installed(), std::memory_order_release);
        XINPUT_STATE probe{};
        probe.Gamepad.wButtons = XINPUT_GAMEPAD_A;
        apply_xinput_suppress_for_test(&probe, 0);
        s_masked_during_arm.store(probe.Gamepad.wButtons, std::memory_order_release);
    }

    // A third-party writer taking ownership of an export DMK stopped patching. The case never calls through this
    // span; it only has to differ from both the original bytes and any patch DMK emitted, so the window witnesses
    // Foreign.
    constexpr std::array<std::uint8_t, ARM_RACE_SPAN> FOREIGN_PROLOGUE_PATCH{
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};

    [[nodiscard]] const wchar_t *find_loadable_xinput() noexcept
    {
        for (const wchar_t *name : XINPUT_NAMES)
        {
            const HMODULE module = LoadLibraryW(name);
            if (module != nullptr)
            {
                FreeLibrary(module);
                return name;
            }
        }
        return nullptr;
    }

    [[nodiscard]] bool legal_xinput_result(DWORD result) noexcept
    {
        return result == ERROR_SUCCESS || result == ERROR_DEVICE_NOT_CONNECTED;
    }

    [[nodiscard]] bool layer_masks_bound_index() noexcept;

    int run_pre_body_route_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 110;
        }
        set_xinput_module_override_for_test(xinput);
        auto *const get_state_target = reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, "XInputGetState"));
        const auto get_state = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(get_state_target));
        if (get_state_target == nullptr)
        {
            std::fprintf(stderr, "FAIL: same-module proxy exports no XInputGetState\n");
            return 120;
        }
        std::array<std::uint8_t, ARM_RACE_SPAN> primary_original{};
        std::memcpy(primary_original.data(), get_state_target, ARM_RACE_SPAN);
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: could not arm the proxy XInput detour\n");
            return 111;
        }
        if (*reinterpret_cast<const std::uint8_t *>(reinterpret_cast<const void *>(get_state)) != 0xE9)
        {
            std::fprintf(stderr, "FAIL: routed proof requires the target E9 entry form\n");
            return 119;
        }

        s_body_entered.store(false, std::memory_order_relaxed);
        set_xinput_detour_body_seam(&note_detour_body);
        set_xinput_route_entry_hold_for_test(true);
        DWORD call_result = ERROR_GEN_FAILURE;
        DWORD call_packet = 0xFFFFFFFFu;
        std::thread caller(
            [&]() noexcept
            {
                XINPUT_STATE state{};
                state.dwPacketNumber = 0xFFFFFFFFu;
                call_result = get_state(7, &state);
                call_packet = state.dwPacketNumber;
            });

        const ULONGLONG deadline = GetTickCount64() + 5000;
        while (!DetourModKit::detail::xinput_route_entry_reached_for_test() && GetTickCount64() < deadline)
        {
            std::this_thread::yield();
        }
        if (!DetourModKit::detail::xinput_route_entry_reached_for_test())
        {
            set_xinput_route_entry_hold_for_test(false);
            caller.join();
            std::fprintf(stderr, "FAIL: caller never reached the stable pre-body route park\n");
            return 112;
        }
        if (s_body_entered.load(std::memory_order_acquire))
        {
            set_xinput_route_entry_hold_for_test(false);
            caller.join();
            std::fprintf(stderr, "FAIL: pre-body route park ran after the C++ detour body\n");
            return 113;
        }

        // Hand the primary prologue back while the caller is parked past admission, then refuse the compensating
        // re-arm before it writes. Teardown must retain the published original pointer even though byte reconciliation
        // has made this hook inactive: the admitted caller has not reached the detour's pointer load yet.
        if (!overwrite_prologue_span(get_state_target, primary_original.data()))
        {
            set_xinput_route_entry_hold_for_test(false);
            caller.join();
            std::fprintf(stderr, "FAIL: could not restore the primary prologue before degraded teardown\n");
            return 121;
        }
        set_xinput_backend_toggle_exception_for_test(reinterpret_cast<void *>(get_state_target), false);
        const bool republished = install_xinput(0);
        set_xinput_backend_toggle_exception_for_test(nullptr, false);
        if (republished || xinput_installed() || !xinput_pair_degraded_for_test())
        {
            set_xinput_route_entry_hold_for_test(false);
            caller.join();
            std::fprintf(stderr, "FAIL: refused recovery did not leave the restored primary degraded and fail-open\n");
            return 122;
        }

        uninstall();
        if (xinput_installed() || !DetourModKit::detail::xinput_permanent_primary_retained() ||
            DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            set_xinput_route_entry_hold_for_test(false);
            caller.join();
            std::fprintf(stderr, "FAIL: pre-body timeout did not retain the executable chain and keepalives\n");
            return 114;
        }

        set_xinput_route_entry_hold_for_test(false);
        caller.join();
        set_xinput_detour_body_seam(nullptr);
        if (!s_body_entered.load(std::memory_order_acquire) || call_result != ERROR_DEVICE_NOT_CONNECTED ||
            call_packet != 7)
        {
            std::fprintf(stderr,
                         "FAIL: retained degraded caller did not resume through the proxy (result %lu packet %lu)\n",
                         static_cast<unsigned long>(call_result), static_cast<unsigned long>(call_packet));
            return 115;
        }

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    int run_process_exit_storage_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 197;
        }
        set_xinput_module_override_for_test(xinput);
        auto *const get_state_target = reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, "XInputGetState"));
        if (get_state_target == nullptr)
        {
            std::fprintf(stderr, "FAIL: the same-module XInput proxy has no primary export\n");
            return 198;
        }
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: could not install the active XInput pair for the process-exit proof\n");
            return 198;
        }
        const auto coverage = xinput_pair_coverage_for_test();
        if (!coverage.primary || !coverage.ex || !xinput_installed() || xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: process-exit premise primary=%d ex=%d installed=%d refs=%d\n",
                         coverage.primary ? 1 : 0, coverage.ex ? 1 : 0, xinput_installed() ? 1 : 0,
                         xinput_module_refs_held());
            return 199;
        }

        // B-100 process-exit oracle.
        arm_xinput_process_exit_oracle_for_test(get_state_target);
        std::puts("ACTIVE_XINPUT_PAIR_REMAINS_IN_PROCESS_LIFETIME_STORAGE_AT_EXIT");
        return 0;
    }

    int run_clean_release_oom_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 116;
        }
        set_xinput_module_override_for_test(xinput);
        const auto get_state =
            reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState")));
        if (get_state == nullptr || !install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: could not arm the proxy XInput detour\n");
            return 117;
        }

        (void)DetourModKit::log();
        set_xinput_clean_release_seam(&poison_clean_release);
        uninstall();
        s_poison_thread_id.store(0, std::memory_order_release);
        set_xinput_clean_release_seam(nullptr);

        XINPUT_STATE state{};
        const DWORD call_result = get_state(0, &state);
        if (xinput_installed() || DetourModKit::detail::xinput_permanent_primary_retained() ||
            DetourModKit::detail::xinput_module_refs_held() != 0 || !legal_xinput_result(call_result))
        {
            std::fprintf(stderr, "FAIL: allocation-free clean release did not leave a pristine callable target\n");
            return 118;
        }

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    // A game thread parked inside a detour body makes the bounded quiesce expire. Teardown must then keep the hook
    // objects and their trampolines mapped, using only resources install_xinput() secured in advance -- proven by
    // failing every plain allocation across the call.
    int run_timeout_case()
    {
        const wchar_t *const name = find_loadable_xinput();
        if (name == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }
        const HMODULE xinput = LoadLibraryW(name);
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }

        const auto get_state =
            reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState")));
        if (get_state == nullptr)
        {
            std::fprintf(stderr, "FAIL: XInputGetState is not exported\n");
            return 2;
        }
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: install_xinput could not arm the detour\n");
            return 3;
        }
        if (DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: the detour went live without the keepalives a stalled teardown needs\n");
            return 13;
        }

        set_xinput_detour_body_seam(&park_in_detour);
        std::thread parked(
            [get_state]() noexcept
            {
                XINPUT_STATE state{};
                (void)get_state(0, &state);
            });
        while (!s_parked.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        // The parked caller is the only one that may take the seam; later entrants must run through freely so the
        // republished trampoline can be exercised below.
        set_xinput_detour_body_seam(nullptr);

        // Keep the process-default logger's one-time setup outside the allocation-poison window so this proof isolates
        // uninstall's retain path.
        (void)DetourModKit::log();

        // Poison only this thread's plain allocations across uninstall(): the retain-on-timeout path retains the hooks,
        // trampolines, and keepalives using resources secured at install time, so it takes no plain heap allocation of
        // its own. Allocations on unrelated threads stay outside this caller-thread contract.
        s_poison_thread_id.store(GetCurrentThreadId(), std::memory_order_release);
        uninstall();
        s_poison_thread_id.store(0, std::memory_order_release);

        // Release and join before any verdict below: the parked caller only ever waits on s_release, so returning
        // while it is still joinable would destroy a running std::thread and terminate the process, replacing every
        // diagnostic exit code after this point with an abort.
        s_release.store(true, std::memory_order_release);
        parked.join();

        if (xinput_installed())
        {
            std::fprintf(stderr, "FAIL: a timed-out teardown left interception logically armed\n");
            return 4;
        }
        if (DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: the permanent detour did not retain both keepalives\n");
            return 10;
        }

        // The retained detour code and the patched prologue stay mapped and callable: the call must return one of
        // XInput's legal statuses rather than fault through freed trampoline memory.
        XINPUT_STATE state{};
        const DWORD result = get_state(0, &state);
        if (result != ERROR_SUCCESS && result != ERROR_DEVICE_NOT_CONNECTED)
        {
            std::fprintf(stderr, "FAIL: the retained detour returned an illegal status (result %lu)\n",
                         static_cast<unsigned long>(result));
            return 5;
        }

        // A later install re-arms logical interception over the permanent detour instead of layering a second hook.
        // Its success is also what proves the trampoline was republished: the permanent-detour branch reports ready
        // only when the saved original is non-null, so a detour left faking a disconnect forever fails here.
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: a permanent detour could not be logically re-armed\n");
            return 6;
        }
        uninstall();
        if (DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: logical disarm released a permanent detour keepalive\n");
            return 14;
        }

        FreeLibrary(xinput);
        return 0;
    }

    // Balance proof: every install takes exactly the pair of keepalives a non-draining teardown would need, and a
    // drained teardown releases exactly that pair. Repeated rounds catch an acquire that accumulates.
    int run_reference_balance_case()
    {
        const wchar_t *const name = find_loadable_xinput();
        if (name == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }
        const HMODULE xinput = LoadLibraryW(name);
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }

        if (DetourModKit::detail::xinput_module_refs_held() != 0)
        {
            std::fprintf(stderr, "FAIL: keepalives were held before the first install\n");
            return 7;
        }

        constexpr int rounds = 4;
        for (int round = 0; round < rounds; ++round)
        {
            if (!install_xinput(0))
            {
                std::fprintf(stderr, "FAIL: install_xinput could not arm the detour\n");
                return 8;
            }
            if (DetourModKit::detail::xinput_module_refs_held() != 2)
            {
                std::fprintf(stderr, "FAIL: round %d published a detour without both keepalives\n", round);
                return 9;
            }
            uninstall();
            if (xinput_installed())
            {
                std::fprintf(stderr, "FAIL: a drained teardown left interception armed\n");
                return 11;
            }
            if (DetourModKit::detail::xinput_module_refs_held() != 0)
            {
                std::fprintf(stderr, "FAIL: round %d left a keepalive outstanding after a drained teardown\n", round);
                return 12;
            }
        }

        FreeLibrary(xinput);
        return 0;
    }

    // Poison after the isolated route allocator exists, so the first failing allocation is inside InlineHook::create.
    // Narrowing create_disabled_xinput_hook's catch then terminates this case and no other.
    int run_first_install_oom_create_case()
    {
        const wchar_t *const name = find_loadable_xinput();
        if (name == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }
        const HMODULE xinput = LoadLibraryW(name);
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "SKIP: the resolved XInput runtime could not be loaded\n");
            return SKIP_EXIT_CODE;
        }
        const auto get_state =
            reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState")));
        if (get_state == nullptr)
        {
            std::fprintf(stderr, "FAIL: XInputGetState is not exported\n");
            return 83;
        }

        set_xinput_create_seam(&poison_hook_creation);
        const bool installed = install_xinput(0);
        set_xinput_create_seam(nullptr);
        s_poison_thread_id.store(0, std::memory_order_release);
        if (installed || xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 0)
        {
            std::fprintf(stderr, "FAIL: a poisoned hook construction did not fail the install closed\n");
            return 84;
        }

        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)))
        {
            std::fprintf(stderr, "FAIL: a poisoned hook construction left the target uncallable\n");
            return 85;
        }
        if (!install_xinput(0) || DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: XInput interception did not recover after a poisoned hook construction\n");
            return 86;
        }
        uninstall();
        if (DetourModKit::detail::xinput_module_refs_held() != 0)
        {
            std::fprintf(stderr, "FAIL: the recovered install did not balance its keepalives\n");
            return 87;
        }

        FreeLibrary(xinput);
        return 0;
    }

    int run_first_install_oom_case()
    {
        const wchar_t *const name = find_loadable_xinput();
        if (name == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }
        const HMODULE xinput = LoadLibraryW(name);
        if (xinput == nullptr)
        {
            return SKIP_EXIT_CODE;
        }
        const auto get_state =
            reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState")));
        if (get_state == nullptr)
        {
            std::fprintf(stderr, "FAIL: XInputGetState is not exported\n");
            return 20;
        }

        s_poison_thread_id.store(GetCurrentThreadId(), std::memory_order_release);
        const bool installed = install_xinput(0);
        s_poison_thread_id.store(0, std::memory_order_release);
        if (installed || xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 0)
        {
            std::fprintf(stderr, "FAIL: first-install OOM did not leave XInput interception cleanly disabled\n");
            return 21;
        }

        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)))
        {
            std::fprintf(stderr, "FAIL: first-install OOM left the target uncallable\n");
            return 22;
        }
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: XInput interception did not recover after first-install OOM\n");
            return 23;
        }
        uninstall();
        if (DetourModKit::detail::xinput_module_refs_held() != 0)
        {
            std::fprintf(stderr, "FAIL: recovered first install did not balance its keepalives\n");
            return 24;
        }

        FreeLibrary(xinput);
        return 0;
    }

    int run_enable_exception_case(bool after_mutation)
    {
        const wchar_t *const name = find_loadable_xinput();
        if (name == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }
        const HMODULE xinput = LoadLibraryW(name);
        if (xinput == nullptr)
        {
            return SKIP_EXIT_CODE;
        }
        auto *const target = reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState"));
        const auto get_state = reinterpret_cast<XInputGetStateFn>(target);
        if (target == nullptr)
        {
            std::fprintf(stderr, "FAIL: XInputGetState is not exported\n");
            return 30;
        }

        const auto retention_before = safetyhook::route_retention_stats();
        set_xinput_backend_toggle_exception_for_test(target, after_mutation);
        const bool installed = install_xinput(0);
        set_xinput_backend_toggle_exception_for_test(nullptr, false);
        const auto retention_after = safetyhook::route_retention_stats();
        if (xinput_backend_toggle_exception_catches_for_test() != 1)
        {
            std::fprintf(stderr, "FAIL: raw enable exception did not reach the containment boundary\n");
            return 31;
        }

        if (!after_mutation)
        {
            if (retention_after.logical_reserved != retention_before.logical_reserved ||
                retention_after.committed_reserved != retention_before.committed_reserved ||
                retention_after.logical_charged != retention_before.logical_charged ||
                retention_after.committed_charged != retention_before.committed_charged)
            {
                std::fprintf(stderr, "FAIL: a pre-mutation enable exception changed retention accounting\n");
                return 37;
            }
            if (installed || xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 0)
            {
                std::fprintf(stderr, "FAIL: pre-mutation enable exception did not fail cleanly\n");
                return 32;
            }
            if (!install_xinput(0))
            {
                std::fprintf(stderr, "FAIL: pre-mutation enable exception left the hook unretryable\n");
                return 33;
            }
        }
        else if (!installed || !xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: committed enable exception was not reconciled as a live hook\n");
            return 34;
        }
        else if (retention_after.logical_reserved != retention_before.logical_reserved ||
                 retention_after.committed_reserved != retention_before.committed_reserved)
        {
            std::fprintf(stderr, "FAIL: committed enable exception left a route reservation outstanding\n");
            return 38;
        }
        else if (retention_after.logical_charged <= retention_before.logical_charged ||
                 retention_after.committed_charged <= retention_before.committed_charged)
        {
            std::fprintf(stderr, "FAIL: committed enable exception did not charge the published route\n");
            return 39;
        }

        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)))
        {
            std::fprintf(stderr, "FAIL: reconciled enable path left XInputGetState uncallable\n");
            return 35;
        }
        uninstall();
        if (DetourModKit::detail::xinput_module_refs_held() != 0)
        {
            std::fprintf(stderr, "FAIL: reconciled enable path did not balance its keepalives\n");
            return 36;
        }

        FreeLibrary(xinput);
        return 0;
    }

    // A committed prologue patch publishes the trampoline to every thread that enters the detour. When another writer
    // restores the original bytes before the post-toggle witness read, the transaction is judged unreachable even
    // though a game thread can already be inside that trampoline. Install must therefore hand the storage and both
    // keepalives to permanent ownership rather than release module lifetime while an admitted frame may still run,
    // and must refuse to layer a second hook over the prologue afterwards.
    int run_arm_inversion_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 49;
        }
        set_xinput_module_override_for_test(xinput);
        auto *const target = reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, "XInputGetState"));
        auto *const ex_target =
            reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        if (target == nullptr || ex_target == nullptr || target == ex_target)
        {
            std::fprintf(stderr, "FAIL: same-module proxy does not expose a distinct XInput pair\n");
            return 50;
        }
        const auto get_state = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(target));
        const auto get_state_ex = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(ex_target));
        std::array<std::uint8_t, ARM_RACE_SPAN> ex_original{};
        std::memcpy(ex_original.data(), ex_target, ARM_RACE_SPAN);

        std::memcpy(s_arm_race_original.data(), target, ARM_RACE_SPAN);
        s_arm_race_target = target;
        set_xinput_arm_seam(&restore_original_prologue_in_arm_window);
        const bool installed = install_xinput(0);
        set_xinput_arm_seam(nullptr);

        if (s_arm_race_runs.load(std::memory_order_relaxed) == 0)
        {
            std::fprintf(stderr, "FAIL: the competing writer never reached the arm window\n");
            return 51;
        }
        if (installed || xinput_installed())
        {
            std::fprintf(stderr, "FAIL: an inverted arm transaction reported a live installation\n");
            return 52;
        }
        // Load-bearing pair. The keepalive count proves the install chose retention over its ordinary failure exit,
        // and the storage check proves the hook itself moved there instead of running the destructor that returns the
        // published trampoline range to the backend allocator's freelist.
        if (DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: an inverted arm transaction released the keepalives its detour body needs\n");
            return 53;
        }
        if (!DetourModKit::detail::xinput_permanent_primary_retained())
        {
            std::fprintf(stderr, "FAIL: an inverted arm transaction freed storage a live detour body can still hold\n");
            return 58;
        }
        if (std::memcmp(target, s_arm_race_original.data(), ARM_RACE_SPAN) != 0)
        {
            std::fprintf(stderr, "FAIL: an inverted arm transaction left a patch on the target prologue\n");
            return 54;
        }
        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)))
        {
            std::fprintf(stderr, "FAIL: an inverted arm transaction left XInputGetState uncallable\n");
            return 55;
        }
        // Retained storage is never layered over, but it is still recoverable. The writer that inverted the arm has
        // handed the prologue back, so a later install must re-arm the SAME retained hook -- its own witness gate is
        // what authorizes the write -- rather than either giving the export up permanently or creating a second hook
        // whose original would capture this one's jump. A fresh hook would take its own keepalives and its own storage,
        // so the unchanged pair of those is what separates recovery from layering.
        if (!install_xinput(0) || !xinput_installed())
        {
            std::fprintf(stderr, "FAIL: retained storage whose export came back could not be re-armed\n");
            return 56;
        }
        if (DetourModKit::detail::xinput_module_refs_held() != 2 ||
            !DetourModKit::detail::xinput_permanent_primary_retained())
        {
            std::fprintf(stderr, "FAIL: a later install layered a second hook over retained storage\n");
            return 59;
        }
        const DetourModKit::detail::XInputPairCoverage recovered = xinput_pair_coverage_for_test();
        if (!recovered.primary || !recovered.ex || DetourModKit::detail::xinput_trampoline() == nullptr ||
            DetourModKit::detail::xinput_ex_trampoline() == nullptr ||
            std::memcmp(target, s_arm_race_original.data(), ARM_RACE_SPAN) == 0 ||
            std::memcmp(ex_target, ex_original.data(), ARM_RACE_SPAN) == 0)
        {
            std::fprintf(stderr,
                         "FAIL: retained recovery did not patch and publish both existing pair members (%d, %d)\n",
                         static_cast<int>(recovered.primary), static_cast<int>(recovered.ex));
            return 60;
        }
        XINPUT_STATE primary_state{};
        XINPUT_STATE ex_state{};
        if (!legal_xinput_result(get_state(0, &primary_state)) || !legal_xinput_result(get_state_ex(0, &ex_state)))
        {
            std::fprintf(stderr, "FAIL: the recovered retained pair is not callable through both exports\n");
            return 61;
        }
        uninstall();
        if (DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: teardown released a keepalive the retained storage still needs\n");
            return 57;
        }

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    int run_disable_exception_case(bool after_mutation)
    {
        const wchar_t *const name = find_loadable_xinput();
        if (name == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }
        const HMODULE xinput = LoadLibraryW(name);
        if (xinput == nullptr)
        {
            return SKIP_EXIT_CODE;
        }
        auto *const target = reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState"));
        const auto get_state = reinterpret_cast<XInputGetStateFn>(target);
        if (target == nullptr)
        {
            std::fprintf(stderr, "FAIL: XInputGetState is not exported\n");
            return 40;
        }
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: install_xinput could not arm the detour\n");
            return 41;
        }

        set_xinput_backend_toggle_exception_for_test(target, after_mutation);
        uninstall();
        set_xinput_backend_toggle_exception_for_test(nullptr, false);
        if (xinput_backend_toggle_exception_catches_for_test() != 1)
        {
            std::fprintf(stderr, "FAIL: raw disable exception did not reach the containment boundary\n");
            return 42;
        }
        if (xinput_installed())
        {
            std::fprintf(stderr, "FAIL: disable exception left interception logically armed\n");
            return 43;
        }

        const int expected_refs = after_mutation ? 0 : 2;
        if (DetourModKit::detail::xinput_module_refs_held() != expected_refs)
        {
            std::fprintf(stderr, "FAIL: disable exception reconciled the wrong keepalive state\n");
            return 44;
        }
        if (!after_mutation && (!install_xinput(0) || DetourModKit::detail::xinput_trampoline() == nullptr))
        {
            std::fprintf(stderr, "FAIL: retained primary trampoline could not be logically rearmed\n");
            return 45;
        }
        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)))
        {
            std::fprintf(stderr, "FAIL: reconciled disable path left XInputGetState uncallable\n");
            return 46;
        }
        if (!after_mutation)
            uninstall();

        FreeLibrary(xinput);
        return 0;
    }

    // The asymmetric direction the pre-restore classification cannot cover: the ordinal-100 restore commits and the
    // primary restore then refuses. Retaining at that point publishes a primary-only chain, and the ordinal-100 entry
    // point that was masked before this teardown is gone for the life of the process, because a later install accepts
    // the retained primary without ever reaching Ex creation. Compensation puts the Ex member back before retention,
    // so the pair is preserved as a unit and a supported teardown/reinstall cycle keeps both entry points.
    int run_primary_disable_exception_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 110;
        }
        set_xinput_module_override_for_test(xinput);
        auto *const get_state_target = reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState"));
        auto *const get_state_ex_target =
            reinterpret_cast<void *>(GetProcAddress(xinput, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        const auto get_state = reinterpret_cast<XInputGetStateFn>(get_state_target);
        const auto get_state_ex = reinterpret_cast<XInputGetStateFn>(get_state_ex_target);
        if (get_state_target == nullptr || get_state_ex_target == nullptr || get_state_ex_target == get_state_target)
        {
            std::fprintf(stderr, "FAIL: same-module proxy does not expose distinct primary and ordinal-100 targets\n");
            return 111;
        }
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: install_xinput could not arm the primary and Ex detours\n");
            return 112;
        }
        // Without an armed Ex hook the loss this case measures could not be observed.
        if (DetourModKit::detail::xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: the ordinal-100 detour was not armed, so the pair rule is unobservable\n");
            return 113;
        }

        set_xinput_backend_toggle_exception_for_test(get_state_target, false);
        uninstall();
        set_xinput_backend_toggle_exception_for_test(nullptr, false);
        // Exactly one: the Ex restore and the compensating Ex re-arm both run against the other target.
        if (xinput_backend_toggle_exception_catches_for_test() != 1)
        {
            std::fprintf(stderr, "FAIL: the primary disable exception did not reach the containment boundary\n");
            return 114;
        }
        if (xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: a refused primary restore did not retain the raw hook pair\n");
            return 115;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: retention dropped the ordinal-100 entry point the pair covered on entry\n");
            return 116;
        }

        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)) || !legal_xinput_result(get_state_ex(0, &state)))
        {
            std::fprintf(stderr, "FAIL: the compensated pair's forwarding chains are not both callable\n");
            return 117;
        }
        if (!install_xinput(0) || !xinput_installed() || DetourModKit::detail::xinput_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: the retained primary could not be logically rearmed\n");
            return 118;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: a later install settled for primary-only coverage\n");
            return 119;
        }
        uninstall();

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    // Compensation is the first line and can itself be beaten: a writer that restores the ordinal-100 prologue inside
    // the re-arm window leaves the retained pair asymmetric anyway. The retained Ex hook still owns its trampoline, so
    // the next install has to recover that member rather than accept the primary alone and latch the loss.
    int run_pair_compensation_inverted_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 120;
        }
        set_xinput_module_override_for_test(xinput);
        auto *const get_state_target = reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, "XInputGetState"));
        auto *const get_state_ex_target =
            reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        if (get_state_target == nullptr || get_state_ex_target == nullptr || get_state_ex_target == get_state_target)
        {
            std::fprintf(stderr, "FAIL: same-module proxy does not expose distinct primary and ordinal-100 targets\n");
            return 121;
        }

        std::memcpy(s_arm_race_original.data(), get_state_ex_target, ARM_RACE_SPAN);
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: install_xinput could not arm the primary and Ex detours\n");
            return 122;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: the ordinal-100 detour was not armed, so the pair rule is unobservable\n");
            return 123;
        }
        const XInputGetStateFn initial_ex_trampoline = DetourModKit::detail::xinput_ex_trampoline();
        std::array<std::uint8_t, ARM_RACE_SPAN> armed_ex_prologue{};
        std::memcpy(armed_ex_prologue.data(), get_state_ex_target, ARM_RACE_SPAN);

        s_arm_race_target = get_state_ex_target;
        s_arm_race_runs.store(0, std::memory_order_relaxed);
        set_xinput_arm_seam(&restore_original_prologue_in_arm_window);
        set_xinput_backend_toggle_exception_for_test(get_state_target, false);
        uninstall();
        set_xinput_backend_toggle_exception_for_test(nullptr, false);
        set_xinput_arm_seam(nullptr);
        s_arm_race_target = nullptr;

        if (s_arm_race_runs.load(std::memory_order_relaxed) != 1)
        {
            std::fprintf(stderr, "FAIL: the competing writer never reached the compensating re-arm window\n");
            return 124;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() != nullptr)
        {
            std::fprintf(stderr, "FAIL: an inverted compensation still published an ordinal-100 chain\n");
            return 125;
        }
        if (xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: a refused primary restore did not retain the raw hook pair\n");
            return 126;
        }
        if (!adopt_owner_for_test(DetourModKit::detail::STANDALONE_INTERCEPT_OWNER) ||
            !publish_gamepad_suppress(XINPUT_GAMEPAD_A, DetourModKit::detail::STANDALONE_INTERCEPT_OWNER))
        {
            std::fprintf(stderr, "FAIL: could not model the WndProc-owned shared layer\n");
            return 127;
        }

        set_xinput_backend_toggle_exception_for_test(get_state_ex_target, false);
        const bool failed_recovery_installed = install_xinput(0);
        set_xinput_backend_toggle_exception_for_test(nullptr, false);
        if (failed_recovery_installed || xinput_installed())
        {
            std::fprintf(stderr, "FAIL: a refused ordinal-100 recovery published primary-only coverage\n");
            return 128;
        }
        if (xinput_backend_toggle_exception_catches_for_test() != 1)
        {
            std::fprintf(stderr, "FAIL: the ordinal-100 recovery exception missed the containment boundary\n");
            return 129;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() != nullptr ||
            DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: a refused ordinal-100 recovery did not preserve the retained pair\n");
            return 130;
        }
        XINPUT_STATE logically_disarmed_state{};
        logically_disarmed_state.Gamepad.wButtons = XINPUT_GAMEPAD_A;
        apply_xinput_suppress_for_test(&logically_disarmed_state, 0);
        if (logically_disarmed_state.Gamepad.wButtons != XINPUT_GAMEPAD_A)
        {
            std::fprintf(stderr, "FAIL: the retained primary masked while ordinal-100 recovery was pending\n");
            return 131;
        }

        // The poll loop asks for recovery every cycle. The deadline gate must absorb that burst without running one
        // further backend transaction: that is the whole difference between capped-delay recovery and a per-frame
        // protection change plus code write on an export that is not coming back this instant.
        const std::size_t attempts_after_refusal = xinput_recovery_attempts_for_test();
        for (int cycle = 0; cycle < 64; ++cycle)
        {
            if (install_xinput(0))
            {
                std::fprintf(stderr, "FAIL: a gated retry published coverage without a recovery transaction\n");
                return 137;
            }
        }
        if (xinput_recovery_attempts_for_test() != attempts_after_refusal)
        {
            std::fprintf(stderr, "FAIL: the recovery deadline let a burst of retries reach the backend\n");
            return 138;
        }
        if (!xinput_pair_degraded_for_test() || xinput_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: a retained pair awaiting ordinal-100 recovery is not an owned degraded pair "
                                 "the poller can still read raw state through\n");
            return 139;
        }

        (void)expire_xinput_recovery_delay_for_test();
        if (!install_xinput(0) || !xinput_installed())
        {
            std::fprintf(stderr, "FAIL: the retained pair could not recover after a transient re-arm failure\n");
            return 132;
        }
        if (xinput_recovery_attempts_for_test() != attempts_after_refusal + 1)
        {
            std::fprintf(stderr, "FAIL: the recovering install did not run exactly one backend transaction\n");
            return 140;
        }
        if (xinput_pair_degraded_for_test())
        {
            std::fprintf(stderr, "FAIL: a recovered pair is still marked degraded\n");
            return 141;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() != initial_ex_trampoline ||
            std::memcmp(get_state_ex_target, armed_ex_prologue.data(), ARM_RACE_SPAN) != 0)
        {
            std::fprintf(stderr, "FAIL: a later install did not restore the retained ordinal-100 entry route\n");
            return 133;
        }
        // Republish the mask here rather than leaning on the deadline the pre-recovery publication set: two backend
        // transactions, each of which suspends every other thread, run between them, and this assertion is about the
        // recovered pair rather than about how long a reactive mask stays live.
        if (!publish_gamepad_suppress(XINPUT_GAMEPAD_A, DetourModKit::detail::STANDALONE_INTERCEPT_OWNER))
        {
            std::fprintf(stderr, "FAIL: could not refresh the suppression mask over the recovered pair\n");
            return 136;
        }
        XINPUT_STATE logically_armed_state{};
        logically_armed_state.Gamepad.wButtons = XINPUT_GAMEPAD_A;
        apply_xinput_suppress_for_test(&logically_armed_state, 0);
        if (logically_armed_state.Gamepad.wButtons != 0)
        {
            std::fprintf(stderr, "FAIL: the recovered pair did not reactivate primary suppression\n");
            return 134;
        }
        XINPUT_STATE state{};
        const auto get_state_ex = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(get_state_ex_target));
        if (!legal_xinput_result(get_state_ex(0, &state)))
        {
            std::fprintf(stderr, "FAIL: the recovered ordinal-100 chain is not callable\n");
            return 135;
        }
        uninstall();

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    int run_ex_disable_exception_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 60;
        }
        set_xinput_module_override_for_test(xinput);
        auto *const get_state_target = reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState"));
        auto *const get_state_ex_target =
            reinterpret_cast<void *>(GetProcAddress(xinput, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        const auto get_state = reinterpret_cast<XInputGetStateFn>(get_state_target);
        const auto get_state_ex = reinterpret_cast<XInputGetStateFn>(get_state_ex_target);
        if (get_state_target == nullptr || get_state_ex_target == nullptr || get_state_ex_target == get_state_target)
        {
            std::fprintf(stderr, "FAIL: same-module proxy does not expose distinct primary and ordinal-100 targets\n");
            return 61;
        }
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: install_xinput could not arm the primary and Ex detours\n");
            return 62;
        }

        set_xinput_backend_toggle_exception_for_test(get_state_ex_target, false);
        uninstall();
        set_xinput_backend_toggle_exception_for_test(nullptr, false);
        if (xinput_backend_toggle_exception_catches_for_test() != 1)
        {
            std::fprintf(stderr, "FAIL: raw Ex disable exception did not reach the containment boundary\n");
            return 63;
        }
        if (xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: Ex restore refusal did not retain the raw hook pair\n");
            return 64;
        }

        XINPUT_STATE state{};
        if (DetourModKit::detail::xinput_ex_trampoline() == nullptr || !legal_xinput_result(get_state(0, &state)) ||
            !legal_xinput_result(get_state_ex(0, &state)))
        {
            std::fprintf(stderr, "FAIL: retained primary/Ex forwarding chain is not callable\n");
            return 65;
        }
        if (!install_xinput(0) || !xinput_installed() || DetourModKit::detail::xinput_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: optional Ex restore refusal made the retained primary unrearmable\n");
            return 66;
        }
        uninstall();

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    int run_newer_layer_case()
    {
        const wchar_t *const name = find_loadable_xinput();
        if (name == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }
        const HMODULE xinput = LoadLibraryW(name);
        if (xinput == nullptr)
        {
            return SKIP_EXIT_CODE;
        }
        auto *const target = reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState"));
        const auto get_state = reinterpret_cast<XInputGetStateFn>(target);
        if (target == nullptr)
        {
            std::fprintf(stderr, "FAIL: XInputGetState is not exported\n");
            return 50;
        }
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: install_xinput could not arm the base detour\n");
            return 51;
        }

        DetourModKit::hook::InlineRequest request{.name = "XInputNewerLayer",
                                                  .target =
                                                      DetourModKit::Address{reinterpret_cast<std::uintptr_t>(target)},
                                                  .options = {.prologue = DetourModKit::hook::Prologue::Relocate}};
        auto layered = DetourModKit::hook::inline_at(std::move(request), &newer_xinput_detour);
        if (!layered)
        {
            std::fprintf(stderr, "FAIL: could not create the newer XInput layer\n");
            return 52;
        }
        DetourModKit::hook::Hook newer = std::move(*layered);
        s_newer_original.store(newer.original<XInputGetStateFn>(), std::memory_order_release);
        const auto enabled = newer.enable();
        if (!enabled)
        {
            std::fprintf(stderr, "FAIL: could not arm the newer XInput layer\n");
            return 53;
        }

        if (!publish_gamepad_suppress(XINPUT_GAMEPAD_A, DetourModKit::detail::STANDALONE_INTERCEPT_OWNER) ||
            !layer_masks_bound_index())
        {
            std::fprintf(stderr, "FAIL: the complete base layer did not establish the suppression premise\n");
            return 60;
        }
        const XInputGetStateFn retained_trampoline = xinput_trampoline();
        const bool maintained = install_xinput(0);
        const DetourModKit::detail::XInputPairCoverage degraded = xinput_pair_coverage_for_test();
        if (maintained || xinput_installed() || !xinput_pair_degraded_for_test() || degraded.primary ||
            layer_masks_bound_index())
        {
            std::fprintf(stderr, "FAIL: a foreign primary patch was accepted as exact complete coverage (primary=%d)\n",
                         static_cast<int>(degraded.primary));
            return 61;
        }

        s_newer_calls.store(0, std::memory_order_relaxed);
        uninstall();
        if (xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: layered teardown did not retain the raw trampoline chain\n");
            return 54;
        }

        XINPUT_STATE state{};
        const DWORD target_result = get_state(0, &state);
        if (s_newer_calls.load(std::memory_order_relaxed) != 1 || !legal_xinput_result(target_result))
        {
            std::fprintf(stderr, "FAIL: raw teardown overwrote the newer XInput patch\n");
            return 56;
        }
        const auto original_result = newer.try_call<DWORD, DWORD, XINPUT_STATE *>(0, &state);
        if (!original_result || !legal_xinput_result(*original_result))
        {
            std::fprintf(stderr, "FAIL: the newer XInput layer's saved original chain is not callable\n");
            return 57;
        }

        const auto disabled = newer.disable();
        if (!disabled)
        {
            std::fprintf(stderr, "FAIL: could not remove the newer XInput layer after the proof\n");
            return 58;
        }
        if (!install_xinput(0) || !xinput_installed() || xinput_trampoline() != retained_trampoline)
        {
            std::fprintf(stderr, "FAIL: retained storage did not recover through the existing hook after hand-back\n");
            return 55;
        }
        uninstall();
        s_newer_original.store(nullptr, std::memory_order_release);
        FreeLibrary(xinput);
        return 0;
    }

    // A newer layer over the primary alone must not let the optional Ex prologue be restored on its own. Teardown
    // classifies both windows before it mutates either, so a primary already owned by a newer layer at that read
    // retains the Ex hook, its trampoline, and the pair's keepalives. The primary-refuses-after-Ex-committed direction
    // is the same guarantee reached by compensation instead of by classification; run_primary_disable_exception_case
    // owns it. The same-module proxy is used because it guarantees a distinct ordinal-100 target in the pinned module
    // on every host.
    int run_newer_layer_ex_pair_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 70;
        }
        set_xinput_module_override_for_test(xinput);
        auto *const get_state_target = reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState"));
        auto *const get_state_ex_target =
            reinterpret_cast<void *>(GetProcAddress(xinput, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        const auto get_state = reinterpret_cast<XInputGetStateFn>(get_state_target);
        const auto get_state_ex = reinterpret_cast<XInputGetStateFn>(get_state_ex_target);
        if (get_state_target == nullptr || get_state_ex_target == nullptr || get_state_ex_target == get_state_target)
        {
            std::fprintf(stderr, "FAIL: same-module proxy does not expose distinct primary and ordinal-100 targets\n");
            return 71;
        }
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: install_xinput could not arm the primary and Ex detours\n");
            return 72;
        }
        // Without an armed Ex hook the retention assertion below could not distinguish a preserved pair from a pair
        // that never existed.
        if (DetourModKit::detail::xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: the ordinal-100 detour was not armed, so the pair rule is unobservable\n");
            return 73;
        }

        DetourModKit::hook::InlineRequest request{
            .name = "XInputNewerLayerExPair",
            .target = DetourModKit::Address{reinterpret_cast<std::uintptr_t>(get_state_target)},
            .options = {.prologue = DetourModKit::hook::Prologue::Relocate}};
        auto layered = DetourModKit::hook::inline_at(std::move(request), &newer_xinput_detour);
        if (!layered)
        {
            std::fprintf(stderr, "FAIL: could not create the newer primary layer\n");
            return 74;
        }
        DetourModKit::hook::Hook newer = std::move(*layered);
        s_newer_original.store(newer.original<XInputGetStateFn>(), std::memory_order_release);
        if (!newer.enable())
        {
            std::fprintf(stderr, "FAIL: could not arm the newer primary layer\n");
            return 75;
        }

        if (!publish_gamepad_suppress(XINPUT_GAMEPAD_A, DetourModKit::detail::STANDALONE_INTERCEPT_OWNER) ||
            !layer_masks_bound_index())
        {
            std::fprintf(stderr, "FAIL: the complete local pair did not establish the suppression premise\n");
            return 80;
        }
        const XInputGetStateFn retained_trampoline = xinput_trampoline();
        const bool maintained = install_xinput(0);
        const DetourModKit::detail::XInputPairCoverage degraded = xinput_pair_coverage_for_test();
        if (maintained || xinput_installed() || !xinput_pair_degraded_for_test() || degraded.primary || !degraded.ex ||
            layer_masks_bound_index())
        {
            std::fprintf(stderr, "FAIL: the foreign primary was accepted as exact local-pair coverage (%d, %d)\n",
                         static_cast<int>(degraded.primary), static_cast<int>(degraded.ex));
            return 81;
        }

        uninstall();
        if (xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: a foreign primary window did not retain the raw hook pair\n");
            return 76;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: the Ex hook was restored on its own while the primary stayed patched\n");
            return 78;
        }

        XINPUT_STATE state{};
        s_newer_calls.store(0, std::memory_order_relaxed);
        if (!legal_xinput_result(get_state_ex(0, &state)) || !legal_xinput_result(get_state(0, &state)) ||
            s_newer_calls.load(std::memory_order_relaxed) != 1)
        {
            std::fprintf(stderr, "FAIL: the retained pair's forwarding chains are not both callable\n");
            return 79;
        }

        if (!newer.disable())
        {
            std::fprintf(stderr, "FAIL: could not hand the retained primary back after the local-pair proof\n");
            return 82;
        }
        if (!install_xinput(0) || !xinput_installed() || xinput_trampoline() != retained_trampoline)
        {
            std::fprintf(stderr, "FAIL: the retained local pair did not recover through its existing primary hook\n");
            return 83;
        }
        const DetourModKit::detail::XInputPairCoverage recovered = xinput_pair_coverage_for_test();
        if (!recovered.primary || !recovered.ex)
        {
            std::fprintf(stderr, "FAIL: the retained local pair republished without both exact patches\n");
            return 84;
        }
        uninstall();
        s_newer_original.store(nullptr, std::memory_order_release);
        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    // An inverted arm leaves its hook retained but inactive: it holds a recorded target it no longer patches. Whoever
    // owns that address next is not DMK's business, so teardown must not read those bytes and must not let them veto
    // the healthy member of the pair. The ordinal-100 arm is the one inverted here, so the primary stays armed and is
    // the member a wrong verdict would strand.
    int run_ex_arm_inversion_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 90;
        }
        set_xinput_module_override_for_test(xinput);
        auto *const get_state_target = reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, "XInputGetState"));
        auto *const get_state_ex_target =
            reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        if (get_state_target == nullptr || get_state_ex_target == nullptr || get_state_ex_target == get_state_target)
        {
            std::fprintf(stderr, "FAIL: same-module proxy does not expose distinct primary and ordinal-100 targets\n");
            return 91;
        }
        const auto get_state = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(get_state_target));
        const auto get_state_ex = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(get_state_ex_target));

        std::array<std::uint8_t, ARM_RACE_SPAN> primary_original{};
        std::array<std::uint8_t, ARM_RACE_SPAN> ex_original{};
        std::memcpy(primary_original.data(), get_state_target, ARM_RACE_SPAN);
        std::memcpy(ex_original.data(), get_state_ex_target, ARM_RACE_SPAN);

        std::memcpy(s_arm_race_original.data(), ex_original.data(), ARM_RACE_SPAN);
        s_arm_race_target = get_state_ex_target;
        s_arm_race_runs.store(0, std::memory_order_relaxed);
        s_ex_arm_call_requested.store(false, std::memory_order_relaxed);
        s_ex_arm_route_reached.store(false, std::memory_order_relaxed);
        s_ex_arm_pass_through_probe_enabled.store(true, std::memory_order_release);
        set_xinput_route_entry_hold_for_test(true);
        std::atomic<DWORD> admitted_result{ERROR_INVALID_FUNCTION};
        std::atomic<DWORD> admitted_packet{0xFFFFFFFFu};
        std::thread admitted_caller(
            [get_state_ex, &admitted_result, &admitted_packet]() noexcept
            {
                while (!s_ex_arm_call_requested.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                XINPUT_STATE state{};
                state.dwPacketNumber = 0xFFFFFFFFu;
                admitted_result.store(get_state_ex(7, &state), std::memory_order_release);
                admitted_packet.store(state.dwPacketNumber, std::memory_order_release);
            });
        set_xinput_arm_seam(&restore_ex_prologue_in_arm_window);
        const bool installed = install_xinput(0);
        set_xinput_arm_seam(nullptr);
        s_arm_race_target = nullptr;

        // The caller remains parked while a later retry is refused before mutation. That retry must not clear the
        // chain published by the earlier committed arm: the admitted frame has not reached its original-pointer load
        // yet, even though the current attempt itself admitted nobody.
        const bool retry_foreign_patch_written =
            overwrite_prologue_span(get_state_ex_target, FOREIGN_PROLOGUE_PATCH.data());
        const bool uncommitted_retry_installed = retry_foreign_patch_written && install_xinput(0);
        const bool retry_original_restored = overwrite_prologue_span(get_state_ex_target, ex_original.data());

        s_ex_arm_call_requested.store(true, std::memory_order_release);
        set_xinput_route_entry_hold_for_test(false);
        admitted_caller.join();

        if (!retry_foreign_patch_written)
        {
            std::fprintf(stderr, "FAIL: could not take the ordinal-100 target before the refused retry\n");
            return 147;
        }
        if (uncommitted_retry_installed || xinput_installed())
        {
            std::fprintf(stderr, "FAIL: a retry against a foreign ordinal-100 target reported complete coverage\n");
            return 148;
        }
        if (!retry_original_restored)
        {
            std::fprintf(stderr, "FAIL: could not restore the ordinal-100 target after the refused retry\n");
            return 149;
        }

        if (installed || xinput_installed())
        {
            std::fprintf(stderr, "FAIL: an unarmed distinct ordinal-100 export was reported as complete coverage\n");
            return 92;
        }
        if (s_arm_race_runs.load(std::memory_order_relaxed) < 2)
        {
            std::fprintf(stderr, "FAIL: the competing writer never reached the ordinal-100 arm window\n");
            return 93;
        }
        if (!s_ex_arm_route_reached.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL: no ordinal-100 caller was admitted before the arm became unreachable\n");
            return 145;
        }
        if (admitted_result.load(std::memory_order_acquire) != ERROR_DEVICE_NOT_CONNECTED ||
            admitted_packet.load(std::memory_order_acquire) != 8)
        {
            std::fprintf(stderr, "FAIL: an admitted ordinal-100 caller did not pass through after degradation\n");
            return 146;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: an admitted ordinal-100 route lost its forwarding chain\n");
            return 94;
        }
        if (!xinput_pair_degraded_for_test())
        {
            std::fprintf(stderr, "FAIL: an incomplete pair was not recorded as degraded coverage\n");
            return 102;
        }
        // The owning poll loop still has to read raw controller state, and it must get there through the primary
        // trampoline rather than by calling the export it has itself patched.
        if (xinput_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: a degraded pair hid the primary trampoline from its own owner\n");
            return 103;
        }
        // Fail open on both entries. Nothing may be masked while coverage is incomplete: the game would otherwise
        // lose a button on the entry point DMK covers and keep it on the one it does not.
        if (!publish_gamepad_suppress(XINPUT_GAMEPAD_A, DetourModKit::detail::STANDALONE_INTERCEPT_OWNER))
        {
            std::fprintf(stderr, "FAIL: could not publish a suppression mask over the degraded pair\n");
            return 104;
        }
        XINPUT_STATE degraded_state{};
        degraded_state.Gamepad.wButtons = XINPUT_GAMEPAD_A;
        apply_xinput_suppress_for_test(&degraded_state, 0);
        if (degraded_state.Gamepad.wButtons != XINPUT_GAMEPAD_A)
        {
            std::fprintf(stderr, "FAIL: a degraded pair masked the state the game reads\n");
            return 105;
        }
        // Recovery is deadline-gated. Re-arm the competing writer so every re-arm keeps losing the export, then let
        // the poll loop's per-cycle retries run: they must not turn into per-cycle backend transactions.
        s_arm_race_target = get_state_ex_target;
        set_xinput_arm_seam(&restore_ex_prologue_in_arm_window);
        const std::size_t attempts_before_burst = xinput_recovery_attempts_for_test();
        bool burst_published = false;
        for (int cycle = 0; cycle < 64; ++cycle)
        {
            // The seam inverts the second arm window it sees, so rewind the counter to make every recovery attempt
            // in this burst lose the export again.
            s_arm_race_runs.store(1, std::memory_order_relaxed);
            burst_published = burst_published || install_xinput(0);
        }
        const std::size_t attempts_after_burst = xinput_recovery_attempts_for_test();

        if (burst_published || xinput_installed())
        {
            std::fprintf(stderr, "FAIL: a retry published coverage while the ordinal-100 export was still taken\n");
            return 106;
        }
        if (attempts_after_burst <= attempts_before_burst)
        {
            std::fprintf(stderr, "FAIL: fresh evidence did not let the first retry reach the backend\n");
            return 107;
        }
        if (attempts_after_burst > attempts_before_burst + 2)
        {
            std::fprintf(stderr, "FAIL: the recovery deadline let a burst of retries reach the backend\n");
            return 108;
        }

        // Drive the exponential backoff through its ceiling without waiting. Every failed transaction must leave a
        // delay at or below the declared 2,000 ms cap; checking each step catches a one-step overshoot that a final
        // value alone would miss after the following attempt clamps it again.
        constexpr std::uint64_t recovery_max_delay_ms = 2000;
        for (int attempt = 0; attempt < 8; ++attempt)
        {
            const std::uint64_t delay_ms = expire_xinput_recovery_delay_for_test();
            if (delay_ms > recovery_max_delay_ms)
            {
                std::fprintf(stderr, "FAIL: the XInput recovery delay exceeded its 2,000 ms cap (%llu ms)\n",
                             static_cast<unsigned long long>(delay_ms));
                return 142;
            }
            s_arm_race_runs.store(1, std::memory_order_relaxed);
            if (install_xinput(0))
            {
                std::fprintf(stderr, "FAIL: a forced backoff attempt unexpectedly completed XInput coverage\n");
                return 143;
            }
        }
        const std::uint64_t capped_delay_ms = expire_xinput_recovery_delay_for_test();
        if (capped_delay_ms != recovery_max_delay_ms)
        {
            std::fprintf(stderr, "FAIL: the XInput recovery delay did not settle at its 2,000 ms cap (%llu ms)\n",
                         static_cast<unsigned long long>(capped_delay_ms));
            return 144;
        }
        set_xinput_arm_seam(nullptr);
        s_arm_race_target = nullptr;

        // The export DMK stopped owning now belongs to another writer. The inactive hook still names it as its
        // target, and that is exactly the byte read teardown must not perform.
        if (!overwrite_prologue_span(get_state_ex_target, FOREIGN_PROLOGUE_PATCH.data()))
        {
            std::fprintf(stderr, "FAIL: could not install the foreign patch over the ordinal-100 export\n");
            return 95;
        }

        uninstall();

        if (DetourModKit::detail::xinput_permanent_primary_retained())
        {
            std::fprintf(stderr, "FAIL: a foreign writer at an unowned export stranded the healthy primary hook\n");
            return 96;
        }
        if (DetourModKit::detail::xinput_module_refs_held() != 0)
        {
            std::fprintf(stderr, "FAIL: a drained teardown did not balance the install-time keepalives\n");
            return 97;
        }
        if (std::memcmp(get_state_target, primary_original.data(), ARM_RACE_SPAN) != 0)
        {
            std::fprintf(stderr, "FAIL: teardown left a patch on the primary prologue\n");
            return 98;
        }
        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)))
        {
            std::fprintf(stderr, "FAIL: teardown left XInputGetState uncallable\n");
            return 99;
        }

        // Hand the export back before re-arming: a permanent latch, not the foreign bytes, is what this re-install
        // has to disprove.
        if (!overwrite_prologue_span(get_state_ex_target, ex_original.data()))
        {
            std::fprintf(stderr, "FAIL: could not hand the ordinal-100 export back\n");
            return 100;
        }
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: teardown latched permanent retention instead of releasing the pair\n");
            return 101;
        }
        uninstall();

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    // Loads the same-module proxy and resolves its two distinct entry points. Returns nullptr and prints the reason
    // when it cannot.
    //
    // A failure here is FAIL, never SKIP_EXIT_CODE. `dmk_xinput_proxy_local.dll` is the `xinput_forwarding_proxy_local`
    // CMake target built next to this host, not a host-supplied XInput runtime, so its absence means a broken build
    // rather than an unavailable subject. Every proxy-backed mode in this file reports it the same way; only the modes
    // that resolve a real runtime through find_loadable_xinput() may skip.
    [[nodiscard]] HMODULE load_distinct_pair_proxy(std::uint8_t **primary_target, std::uint8_t **ex_target) noexcept
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return nullptr;
        }
        *primary_target = reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, "XInputGetState"));
        *ex_target =
            reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        if (*primary_target == nullptr || *ex_target == nullptr || *primary_target == *ex_target)
        {
            std::fprintf(stderr, "FAIL: same-module proxy does not expose distinct primary and ordinal-100 targets\n");
            FreeLibrary(xinput);
            return nullptr;
        }
        set_xinput_module_override_for_test(xinput);
        return xinput;
    }

    // Reports whether the layer is masking the state a game reads on the bound index.
    [[nodiscard]] bool layer_masks_bound_index() noexcept
    {
        XINPUT_STATE probe{};
        probe.Gamepad.wButtons = XINPUT_GAMEPAD_A;
        apply_xinput_suppress_for_test(&probe, 0);
        return probe.Gamepad.wButtons != XINPUT_GAMEPAD_A;
    }

    // A competing writer that restores the PRIMARY prologue while the ordinal-100 member is being armed. Publication
    // used to be the unconditional tail of a successful Ex arm, so the pair reported complete coverage while the very
    // export it exists to mask bypassed the layer entirely. The final pair witness has to see the loss and degrade.
    int run_fresh_primary_loss_case()
    {
        std::uint8_t *primary_target = nullptr;
        std::uint8_t *ex_target = nullptr;
        const HMODULE xinput = load_distinct_pair_proxy(&primary_target, &ex_target);
        if (xinput == nullptr)
        {
            return 150;
        }
        const auto get_state = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(primary_target));

        std::array<std::uint8_t, ARM_RACE_SPAN> primary_original{};
        std::memcpy(primary_original.data(), primary_target, ARM_RACE_SPAN);
        std::memcpy(s_primary_race_original.data(), primary_original.data(), ARM_RACE_SPAN);
        s_primary_race_target = primary_target;
        s_arm_race_runs.store(0, std::memory_order_relaxed);

        set_xinput_arm_seam(&restore_primary_prologue_in_ex_arm_window);
        const bool installed = install_xinput(0);
        set_xinput_arm_seam(nullptr);
        s_primary_race_target = nullptr;

        if (s_arm_race_runs.load(std::memory_order_relaxed) < 2)
        {
            std::fprintf(stderr, "FAIL: the competing writer never reached the ordinal-100 arm window\n");
            return 151;
        }
        if (installed || xinput_installed())
        {
            std::fprintf(stderr, "FAIL: a primary restored during the ordinal-100 arm was published as complete "
                                 "coverage\n");
            return 152;
        }
        const DetourModKit::detail::XInputPairCoverage degraded = xinput_pair_coverage_for_test();
        if (degraded.primary || !degraded.ex)
        {
            std::fprintf(stderr, "FAIL: the degraded pair named the wrong missing member (primary=%d ex=%d)\n",
                         static_cast<int>(degraded.primary), static_cast<int>(degraded.ex));
            return 153;
        }
        if (!xinput_pair_degraded_for_test())
        {
            std::fprintf(stderr, "FAIL: an incomplete pair was not recorded as degraded coverage\n");
            return 154;
        }
        if (!publish_gamepad_suppress(XINPUT_GAMEPAD_A, DetourModKit::detail::STANDALONE_INTERCEPT_OWNER))
        {
            std::fprintf(stderr, "FAIL: could not publish a suppression mask over the degraded pair\n");
            return 155;
        }
        if (layer_masks_bound_index())
        {
            std::fprintf(stderr, "FAIL: a pair whose primary bypasses still masked the state the game reads\n");
            return 156;
        }
        // Both chains stay published: a caller admitted through either route before the loss still has to forward.
        if (xinput_trampoline() == nullptr || DetourModKit::detail::xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr,
                         "FAIL: a degraded pair dropped a forwarding chain an admitted caller can still need\n");
            return 157;
        }

        // The writer is gone, so the very next maintenance cycle must re-arm the primary through its own hook and
        // publish only after the final witness proves both members.
        const XInputGetStateFn degraded_trampoline = xinput_trampoline();
        if (!install_xinput(0) || !xinput_installed())
        {
            std::fprintf(stderr, "FAIL: recovery did not re-arm the lost primary member\n");
            return 158;
        }
        const DetourModKit::detail::XInputPairCoverage recovered = xinput_pair_coverage_for_test();
        if (!recovered.primary || !recovered.ex)
        {
            std::fprintf(stderr, "FAIL: coverage was published without both members patched\n");
            return 159;
        }
        if (xinput_trampoline() != degraded_trampoline)
        {
            std::fprintf(stderr, "FAIL: recovery layered a new primary hook instead of re-arming the existing one\n");
            return 160;
        }

        uninstall();
        if (std::memcmp(primary_target, primary_original.data(), ARM_RACE_SPAN) != 0)
        {
            std::fprintf(stderr, "FAIL: teardown left a patch on the primary prologue\n");
            return 161;
        }
        if (DetourModKit::detail::xinput_module_refs_held() != 0)
        {
            std::fprintf(stderr, "FAIL: a drained teardown did not balance the install-time keepalives\n");
            return 162;
        }
        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)))
        {
            std::fprintf(stderr, "FAIL: teardown left XInputGetState uncallable\n");
            return 163;
        }

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    // Ordinary maintenance of an already published pair. A competing writer that hands the primary export back AFTER
    // publication used to be invisible forever: the poll loop skipped the install call while the published flag was
    // set, so the layer kept masking one entry point while the other bypassed it.
    int run_installed_primary_loss_case()
    {
        std::uint8_t *primary_target = nullptr;
        std::uint8_t *ex_target = nullptr;
        const HMODULE xinput = load_distinct_pair_proxy(&primary_target, &ex_target);
        if (xinput == nullptr)
        {
            return 170;
        }
        const auto get_state = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(primary_target));

        std::array<std::uint8_t, ARM_RACE_SPAN> primary_original{};
        std::memcpy(primary_original.data(), primary_target, ARM_RACE_SPAN);

        if (!install_xinput(0) || !xinput_installed())
        {
            std::fprintf(stderr, "FAIL: install_xinput could not publish complete coverage\n");
            return 171;
        }
        if (!publish_gamepad_suppress(XINPUT_GAMEPAD_A, DetourModKit::detail::STANDALONE_INTERCEPT_OWNER))
        {
            std::fprintf(stderr, "FAIL: could not publish a suppression mask over the complete pair\n");
            return 172;
        }
        if (!layer_masks_bound_index())
        {
            std::fprintf(stderr, "FAIL: a complete pair did not mask, so the fail-open check below proves nothing\n");
            return 173;
        }
        const XInputGetStateFn published_trampoline = xinput_trampoline();

        // The competing writer restores the primary export out from under a published pair.
        if (!overwrite_prologue_span(primary_target, primary_original.data()))
        {
            std::fprintf(stderr, "FAIL: could not hand the primary export back to a competing writer\n");
            return 174;
        }

        s_installed_during_arm.store(true, std::memory_order_release);
        s_masked_during_arm.store(0, std::memory_order_release);
        const std::size_t attempts_before = xinput_recovery_attempts_for_test();
        set_xinput_arm_seam(&sample_layer_state_in_arm_window);
        const bool republished = install_xinput(0);
        set_xinput_arm_seam(nullptr);

        if (xinput_recovery_attempts_for_test() <= attempts_before)
        {
            std::fprintf(stderr, "FAIL: maintenance did not detect the lost primary at all\n");
            return 175;
        }
        if (s_installed_during_arm.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL: recovery reached the backend with complete coverage still published\n");
            return 176;
        }
        if (s_masked_during_arm.load(std::memory_order_acquire) != XINPUT_GAMEPAD_A)
        {
            std::fprintf(stderr, "FAIL: the layer was still masking while a member bypassed it\n");
            return 177;
        }
        if (!republished || !xinput_installed())
        {
            std::fprintf(stderr, "FAIL: maintenance did not recover and republish the pair\n");
            return 178;
        }
        const DetourModKit::detail::XInputPairCoverage recovered = xinput_pair_coverage_for_test();
        if (!recovered.primary || !recovered.ex)
        {
            std::fprintf(stderr, "FAIL: coverage was republished without both members patched\n");
            return 179;
        }
        if (xinput_trampoline() != published_trampoline)
        {
            std::fprintf(stderr, "FAIL: recovery layered a new primary hook instead of re-arming the existing one\n");
            return 180;
        }
        if (DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: recovery took a second set of keepalives\n");
            return 181;
        }

        uninstall();
        if (std::memcmp(primary_target, primary_original.data(), ARM_RACE_SPAN) != 0)
        {
            std::fprintf(stderr, "FAIL: teardown left a patch on the primary prologue\n");
            return 182;
        }
        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)))
        {
            std::fprintf(stderr, "FAIL: teardown left XInputGetState uncallable\n");
            return 183;
        }

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    // The retained-storage direction of the same loss. A refused primary restore makes the pair permanent with both
    // members still forwarding; a writer then takes the primary export. Recovery has to re-arm the RETAINED primary
    // hook, not settle for the ordinal-100 survivor and not layer a fresh hook over process-lifetime storage.
    int run_permanent_primary_loss_case()
    {
        std::uint8_t *primary_target = nullptr;
        std::uint8_t *ex_target = nullptr;
        const HMODULE xinput = load_distinct_pair_proxy(&primary_target, &ex_target);
        if (xinput == nullptr)
        {
            return 190;
        }
        const auto get_state = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(primary_target));
        const auto get_state_ex = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(ex_target));

        std::array<std::uint8_t, ARM_RACE_SPAN> primary_original{};
        std::memcpy(primary_original.data(), primary_target, ARM_RACE_SPAN);

        if (!install_xinput(0) || DetourModKit::detail::xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: install_xinput could not arm the primary and Ex detours\n");
            return 191;
        }

        // A refused primary restore retains the whole pair rather than dropping an entry point it covered on entry.
        set_xinput_backend_toggle_exception_for_test(reinterpret_cast<void *>(primary_target), false);
        uninstall();
        set_xinput_backend_toggle_exception_for_test(nullptr, false);
        if (!DetourModKit::detail::xinput_permanent_primary_retained() ||
            DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: a refused primary restore did not retain the raw hook pair\n");
            return 192;
        }

        std::array<std::uint8_t, ARM_RACE_SPAN> retained_primary_patch{};
        std::memcpy(retained_primary_patch.data(), primary_target, ARM_RACE_SPAN);
        if (std::memcmp(retained_primary_patch.data(), primary_original.data(), ARM_RACE_SPAN) == 0)
        {
            std::fprintf(stderr, "FAIL: the retained primary was not left patched, so no loss can be staged\n");
            return 193;
        }
        if (!overwrite_prologue_span(primary_target, primary_original.data()))
        {
            std::fprintf(stderr, "FAIL: could not hand the retained primary export back\n");
            return 194;
        }

        const std::size_t attempts_before = xinput_recovery_attempts_for_test();
        if (!install_xinput(0) || !xinput_installed())
        {
            std::fprintf(stderr, "FAIL: the retained pair did not recover its lost primary member\n");
            return 195;
        }
        if (xinput_recovery_attempts_for_test() <= attempts_before)
        {
            std::fprintf(stderr, "FAIL: the retained primary was republished without a recovery transaction\n");
            return 196;
        }
        const DetourModKit::detail::XInputPairCoverage recovered = xinput_pair_coverage_for_test();
        if (!recovered.primary || !recovered.ex)
        {
            std::fprintf(stderr, "FAIL: retained coverage was published without both members patched\n");
            return 197;
        }
        if (!DetourModKit::detail::xinput_permanent_primary_retained() ||
            DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: recovery replaced the retained storage instead of re-arming it\n");
            return 198;
        }
        // The recovered prologue is the one the retained hook already emitted; a second hook layered over it would
        // encode a different jump and would have captured DMK's own patch as its original.
        if (std::memcmp(primary_target, retained_primary_patch.data(), ARM_RACE_SPAN) != 0)
        {
            std::fprintf(stderr, "FAIL: recovery wrote a different patch than the retained hook owns\n");
            return 199;
        }

        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)) || !legal_xinput_result(get_state_ex(0, &state)))
        {
            std::fprintf(stderr, "FAIL: the recovered pair's forwarding chains are not both callable\n");
            return 200;
        }
        uninstall();

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return 0;
    }

    // Bounded wait for a transition only the poll thread can make. The regression this serves is the ABSENCE of an
    // action, so the deadline is what turns it into a reported failure instead of a hang inside the ctest timeout.
    template <typename Predicate> [[nodiscard]] bool wait_for_poll_thread(Predicate predicate) noexcept
    {
        const ULONGLONG deadline = GetTickCount64() + 5000;
        while (!predicate() && GetTickCount64() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        }
        return predicate();
    }

    // The production caller of the maintenance transaction. Every case above drives install_xinput() directly, so a
    // poll loop that skipped the call whenever its own published flag was set would leave all of them green while a
    // post-publication loss stayed permanently invisible in the shipped library. This case owns that decision: a real
    // poll thread publishes the pair, a competing writer hands the primary export back, and the loop has to witness
    // the loss and re-arm that member through the hook it already owns, with no further help from the case.
    int run_poller_maintenance_case()
    {
        std::uint8_t *primary_target = nullptr;
        std::uint8_t *ex_target = nullptr;
        const HMODULE xinput = load_distinct_pair_proxy(&primary_target, &ex_target);
        if (xinput == nullptr)
        {
            return 210;
        }

        std::array<std::uint8_t, ARM_RACE_SPAN> primary_original{};
        std::memcpy(primary_original.data(), primary_target, ARM_RACE_SPAN);

        DetourModKit::detail::InputBinding binding;
        binding.name = "poller_consume_pad";
        binding.keys = {DetourModKit::gamepad_button(DetourModKit::GamepadCode::A)};
        binding.trigger = DetourModKit::input::Trigger::Press;
        binding.consume = true;
        binding.on_press = [] {};
        std::vector<DetourModKit::detail::InputBinding> bindings;
        bindings.push_back(std::move(binding));

        int status = 0;
        std::array<std::uint8_t, ARM_RACE_SPAN> published_patch{};
        {
            DetourModKit::detail::InputPoller poller(std::move(bindings), std::chrono::milliseconds{2},
                                                     /*require_focus=*/false);
            poller.start();
            if (!wait_for_poll_thread([] { return xinput_installed(); }))
            {
                std::fprintf(stderr, "FAIL: the poll loop never published complete XInput coverage\n");
                status = 211;
            }

            const XInputGetStateFn published_trampoline = status == 0 ? xinput_trampoline() : nullptr;
            if (status == 0)
            {
                std::memcpy(published_patch.data(), primary_target, ARM_RACE_SPAN);
                if (std::memcmp(published_patch.data(), primary_original.data(), ARM_RACE_SPAN) == 0)
                {
                    std::fprintf(stderr, "FAIL: a published pair left the primary prologue unpatched\n");
                    status = 212;
                }
            }
            if (status == 0 && !overwrite_prologue_span(primary_target, primary_original.data()))
            {
                std::fprintf(stderr, "FAIL: could not hand the published primary export back\n");
                status = 213;
            }
            // The exact patch the published hook owns has to come back. A second hook layered over the handed-back
            // prologue would encode a different jump, so byte equality is also what separates recovery from layering.
            const auto primary_repatched = [&]
            { return std::memcmp(primary_target, published_patch.data(), ARM_RACE_SPAN) == 0; };
            if (status == 0 && !wait_for_poll_thread(primary_repatched))
            {
                std::fprintf(stderr, "FAIL: the poll loop never re-armed a primary lost after publication\n");
                status = 214;
            }
            if (status == 0 &&
                !wait_for_poll_thread([] { return xinput_installed() && xinput_pair_coverage_for_test().primary; }))
            {
                std::fprintf(stderr, "FAIL: the recovered pair was not republished as complete coverage\n");
                status = 215;
            }
            if (status == 0 && xinput_trampoline() != published_trampoline)
            {
                std::fprintf(stderr, "FAIL: the poll loop layered a new primary hook instead of re-arming its own\n");
                status = 216;
            }
            poller.shutdown();
        }

        if (status == 0 && (xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 0 ||
                            std::memcmp(primary_target, primary_original.data(), ARM_RACE_SPAN) != 0))
        {
            std::fprintf(stderr, "FAIL: the poll thread's own teardown did not restore and release the pair\n");
            status = 217;
        }

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
        return status;
    }

    // Routed-wrapper unwind proofs.
    //
    // A routed inline hook reaches its destination through generated code that establishes a real call frame: the
    // gateway admits the caller, the wrapper allocates shadow space and CALLs the destination, and the exit thunk
    // releases mid-hook entrants. Windows x64 has no frame pointer to fall back on, so a frame with no registered
    // RUNTIME_FUNCTION is unwound as a leaf -- the unwinder reads a return address out of the middle of the shadow
    // space and walks into nonsense. These cases hold the generated addresses and assert the platform's own answer.

    DMK_LIFECYCLE_NOINLINE int routed_unwind_target(int a, int b)
    {
        volatile int result = a + b;
        return result;
    }

    std::atomic<int> s_routed_detour_calls{0};
    // Frames observed inside the gateway allocation while unwinding out of the detour.
    std::atomic<int> s_wrapper_frames_seen{0};
    std::atomic<int> s_wrapper_lookup_failures{0};
    std::atomic<bool> s_reached_driver_frame{false};
    std::atomic<std::uintptr_t> s_gateway_base{0};
    std::atomic<std::uintptr_t> s_gateway_limit{0};
    std::atomic<std::uintptr_t> s_driver_low{0};
    std::atomic<std::uintptr_t> s_driver_high{0};

    // Walks out of the calling frame using the platform unwinder alone. Every generated frame in the chain has to be
    // described by registered data or this walk desynchronizes, which is exactly the failure being ruled out.
    void walk_and_classify_frames() noexcept
    {
        CONTEXT ctx{};
        RtlCaptureContext(&ctx);

        const auto base = s_gateway_base.load(std::memory_order_acquire);
        const auto limit = s_gateway_limit.load(std::memory_order_acquire);
        const auto driver_low = s_driver_low.load(std::memory_order_acquire);
        const auto driver_high = s_driver_high.load(std::memory_order_acquire);

        for (int depth = 0; depth < 24; ++depth)
        {
            DWORD64 image_base = 0;
            PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(ctx.Rip, &image_base, nullptr);
            const auto rip = static_cast<std::uintptr_t>(ctx.Rip);
            if (rip >= base && rip < limit)
            {
                s_wrapper_frames_seen.fetch_add(1, std::memory_order_relaxed);
                if (entry == nullptr || static_cast<std::uintptr_t>(image_base) != base)
                {
                    s_wrapper_lookup_failures.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
            }
            if (rip >= driver_low && rip < driver_high)
            {
                s_reached_driver_frame.store(true, std::memory_order_release);
                return;
            }
            if (entry == nullptr)
            {
                // A genuine leaf: the return address is on top of the stack. Generated frames must never take this
                // branch, which is why an unregistered wrapper is recorded as a lookup failure above instead.
                if (ctx.Rsp == 0)
                {
                    return;
                }
                ctx.Rip = *reinterpret_cast<DWORD64 *>(ctx.Rsp);
                ctx.Rsp += sizeof(DWORD64);
                continue;
            }
            PVOID handler_data = nullptr;
            DWORD64 establisher = 0;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx.Rip, entry, &ctx, &handler_data, &establisher, nullptr);
            if (ctx.Rip == 0)
            {
                return;
            }
        }
    }

    int routed_unwind_detour(int a, int b)
    {
        s_routed_detour_calls.fetch_add(1, std::memory_order_relaxed);
        walk_and_classify_frames();
        return a + b;
    }

    int routed_throwing_detour(int a, int b)
    {
        s_routed_detour_calls.fetch_add(1, std::memory_order_relaxed);
        if (a + b >= 0)
        {
            throw std::runtime_error("thrown through the routed wrapper frame");
        }
        return 0;
    }

    // Every call to the hooked target goes through this volatile pointer. A direct call to a locally visible function
    // whose body provably cannot throw lets the compiler drop the exception region around the call site, and the hook
    // is exactly what makes that inference false: the code that actually runs is the detour, not this body.
    using RoutedTargetFn = int (*)(int, int);
    volatile RoutedTargetFn s_routed_target_indirect = &routed_unwind_target;

    [[nodiscard]] int call_routed_target(int a, int b)
    {
        return s_routed_target_indirect(a, b);
    }

    // Creates one routed hook over the local target. The caller owns enabling it.
    [[nodiscard]] std::expected<safetyhook::InlineHook, safetyhook::InlineHook::Error> make_routed_hook(void *detour)
    {
        return safetyhook::InlineHook::create(
            safetyhook::Allocator::global(), reinterpret_cast<void *>(&routed_unwind_target), detour,
            static_cast<safetyhook::InlineHook::Flags>(safetyhook::InlineHook::StartDisabled |
                                                       safetyhook::InlineHook::RoutedExternal));
    }

    [[nodiscard]] bool virtually_unwind_flag_region(std::uint8_t *region, std::size_t region_size,
                                                    std::size_t expected_restores, bool returns) noexcept
    {
        if (region[0] != 0x53 || region[1] != 0x9C)
        {
            return false;
        }

        std::array<std::uint8_t *, 2> restores{};
        std::size_t restore_count = 0;
        for (std::size_t i = 2; i + 2 < region_size; ++i)
        {
            if (region[i] != 0x9D || region[i + 1] != 0x5B)
            {
                continue;
            }
            if (restore_count >= restores.size())
            {
                return false;
            }
            // The jump tail is two bytes wider than the return tail, so each branch checks its own read against
            // region_size. A single loop guard sized for the shorter tail would let the wider check read one byte
            // past the region it was handed.
            if (returns)
            {
                if (region[i + 2] != 0xC3)
                {
                    return false;
                }
            }
            else if (i + 3 >= region_size || region[i + 2] != 0xFF || region[i + 3] != 0x25)
            {
                return false;
            }
            restores[restore_count++] = region + i;
        }
        if (restore_count != expected_restores)
        {
            return false;
        }

        const auto unwind = [](CONTEXT &context) noexcept
        {
            DWORD64 image_base = 0;
            PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(context.Rip, &image_base, nullptr);
            if (entry == nullptr)
            {
                return false;
            }
            PVOID handler_data = nullptr;
            DWORD64 establisher = 0;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, context.Rip, entry, &context, &handler_data, &establisher,
                             nullptr);
            return true;
        };

        constexpr DWORD64 saved_rbx = 0x1122'3344'5566'7788ULL;
        constexpr DWORD64 saved_flags = 0x202;
        const DWORD64 caller = reinterpret_cast<DWORD64>(&routed_unwind_target);

        // At offset one only push rbx has executed. This catches a wrong CodeOffset that applies pushfq's allocation
        // too early, while the byte check above couples the synthetic stack to the emitted prologue itself.
        alignas(16) std::array<DWORD64, 3> partial_stack{saved_rbx, caller, 0};
        CONTEXT partial{};
        partial.Rip = reinterpret_cast<DWORD64>(region + 1);
        partial.Rsp = reinterpret_cast<DWORD64>(partial_stack.data());
        if (!unwind(partial) || partial.Rbx != saved_rbx || partial.Rip != caller ||
            partial.Rsp != reinterpret_cast<DWORD64>(partial_stack.data() + 2))
        {
            return false;
        }

        for (std::uint8_t *const restore : restores)
        {
            if (restore == nullptr)
            {
                continue;
            }
            alignas(16) std::array<DWORD64, 4> stack{saved_flags, saved_rbx, caller, 0};

            // A body instruction and popfq both precede the described restores, so ordinary unwind codes must recover
            // the saved nonvolatile register and caller stack from either control PC.
            for (std::uint8_t *const control_pc : {region + 2, restore})
            {
                CONTEXT context{};
                context.Rip = reinterpret_cast<DWORD64>(control_pc);
                context.Rsp = reinterpret_cast<DWORD64>(stack.data());
                if (!unwind(context) || context.Rbx != saved_rbx || context.Rip != caller ||
                    context.Rsp != reinterpret_cast<DWORD64>(stack.data() + 3))
                {
                    return false;
                }
            }

            // At pop rbx and at the terminal jump/ret, the platform must recognize the epilogue rather than replaying
            // both prologue codes against an already-restored stack. A padding instruction in this tail fails here.
            CONTEXT at_pop{};
            at_pop.Rip = reinterpret_cast<DWORD64>(restore + 1);
            at_pop.Rsp = reinterpret_cast<DWORD64>(stack.data() + 1);
            if (!unwind(at_pop) || at_pop.Rbx != saved_rbx || at_pop.Rip != caller ||
                at_pop.Rsp != reinterpret_cast<DWORD64>(stack.data() + 3))
            {
                return false;
            }

            CONTEXT at_terminal{};
            at_terminal.Rip = reinterpret_cast<DWORD64>(restore + 2);
            at_terminal.Rsp = reinterpret_cast<DWORD64>(stack.data() + 2);
            at_terminal.Rbx = saved_rbx;
            if (!unwind(at_terminal) || at_terminal.Rbx != saved_rbx || at_terminal.Rip != caller ||
                at_terminal.Rsp != reinterpret_cast<DWORD64>(stack.data() + 3))
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool virtually_unwind_wrapper_region(std::uint8_t *wrapper, std::size_t region_size) noexcept
    {
        constexpr std::array<std::uint8_t, 4> prologue{0x48, 0x83, 0xEC, 0x28};
        constexpr std::array<std::uint8_t, 5> epilogue{0x48, 0x83, 0xC4, 0x28, 0xC3};
        if (std::memcmp(wrapper, prologue.data(), prologue.size()) != 0)
        {
            return false;
        }
        std::uint8_t *tail = nullptr;
        for (std::size_t i = prologue.size(); i + epilogue.size() <= region_size; ++i)
        {
            if (std::memcmp(wrapper + i, epilogue.data(), epilogue.size()) != 0)
            {
                continue;
            }
            if (tail != nullptr)
            {
                return false;
            }
            tail = wrapper + i;
        }
        if (tail == nullptr)
        {
            return false;
        }

        const auto unwind = [](CONTEXT &context) noexcept
        {
            DWORD64 image_base = 0;
            PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(context.Rip, &image_base, nullptr);
            if (entry == nullptr)
            {
                return false;
            }
            PVOID handler_data = nullptr;
            DWORD64 establisher = 0;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, context.Rip, entry, &context, &handler_data, &establisher,
                             nullptr);
            return true;
        };

        const DWORD64 caller = reinterpret_cast<DWORD64>(&routed_unwind_target);
        alignas(16) std::array<DWORD64, 7> stack{0, 0, 0, 0, 0, caller, 0};
        for (std::uint8_t *const control_pc : {wrapper + prologue.size(), tail})
        {
            CONTEXT context{};
            context.Rip = reinterpret_cast<DWORD64>(control_pc);
            context.Rsp = reinterpret_cast<DWORD64>(stack.data());
            if (!unwind(context) || context.Rip != caller || context.Rsp != reinterpret_cast<DWORD64>(stack.data() + 6))
            {
                return false;
            }
        }

        CONTEXT at_return{};
        at_return.Rip = reinterpret_cast<DWORD64>(tail + epilogue.size() - 1);
        at_return.Rsp = reinterpret_cast<DWORD64>(stack.data() + 5);
        return unwind(at_return) && at_return.Rip == caller &&
               at_return.Rsp == reinterpret_cast<DWORD64>(stack.data() + 6);
    }

    int run_wrapper_unwind_case()
    {
        auto created = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
        if (!created)
        {
            std::fprintf(stderr, "FAIL: the routed hook could not be created\n");
            return 110;
        }
        safetyhook::InlineHook hook = std::move(*created);

        auto *const gateway = hook.route_region_for_test(0);
        auto *const wrapper = hook.route_region_for_test(1);
        auto *const exit_thunk = hook.route_region_for_test(2);
        if (gateway == nullptr || wrapper == nullptr || exit_thunk == nullptr ||
            hook.route_unwind_table_for_test() == nullptr)
        {
            std::fprintf(stderr, "FAIL: the routed hook published no generated regions or no unwind records\n");
            return 111;
        }

        // Every generated region resolves through the platform's dynamic table, against the gateway allocation as its
        // base. This is the structural half: it holds whether or not a thread is currently inside them.
        for (int index = 0; index < 3; ++index)
        {
            DWORD64 image_base = 0;
            auto *const region = hook.route_region_for_test(index);
            if (RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(region), &image_base, nullptr) == nullptr ||
                image_base != reinterpret_cast<DWORD64>(gateway))
            {
                std::fprintf(stderr, "FAIL: generated region %d has no registered unwind record\n", index);
                return 112;
            }
        }
        const bool gateway_unwinds = virtually_unwind_flag_region(gateway, 160, 2, false);
        const bool wrapper_unwinds = virtually_unwind_wrapper_region(wrapper, 64);
        const bool exit_unwinds = virtually_unwind_flag_region(exit_thunk, 64, 1, true);
        if (!gateway_unwinds || !wrapper_unwinds || !exit_unwinds)
        {
            std::fprintf(stderr, "FAIL: generated unwind records failed gateway=%d wrapper=%d exit=%d\n",
                         gateway_unwinds, wrapper_unwinds, exit_unwinds);
            return 118;
        }

        s_gateway_base.store(reinterpret_cast<std::uintptr_t>(gateway), std::memory_order_release);
        s_gateway_limit.store(reinterpret_cast<std::uintptr_t>(gateway) + 512, std::memory_order_release);
        s_driver_low.store(reinterpret_cast<std::uintptr_t>(&run_wrapper_unwind_case), std::memory_order_release);
        s_driver_high.store(reinterpret_cast<std::uintptr_t>(&run_wrapper_unwind_case) + 4096,
                            std::memory_order_release);

        if (auto enabled = hook.enable(); !enabled)
        {
            std::fprintf(stderr, "FAIL: the routed hook could not be enabled\n");
            return 113;
        }

        const int observed = call_routed_target(3, 4);
        if (observed != 7 || s_routed_detour_calls.load(std::memory_order_relaxed) != 1)
        {
            std::fprintf(stderr, "FAIL: the routed hook did not dispatch through its wrapper\n");
            return 114;
        }
        if (s_wrapper_frames_seen.load(std::memory_order_relaxed) == 0)
        {
            std::fprintf(stderr, "FAIL: the unwind never passed through the generated wrapper frame\n");
            return 115;
        }
        if (s_wrapper_lookup_failures.load(std::memory_order_relaxed) != 0)
        {
            std::fprintf(stderr, "FAIL: a generated frame in the live chain had no registered unwind record\n");
            return 116;
        }
        if (!s_reached_driver_frame.load(std::memory_order_acquire))
        {
            std::fprintf(stderr, "FAIL: the unwind did not reach the hooked call's own caller\n");
            return 117;
        }

        std::puts("ROUTED_WRAPPER_IS_UNWINDABLE");
        return 0;
    }

    int run_wrapper_native_exception_case()
    {
        auto created = make_routed_hook(reinterpret_cast<void *>(&routed_throwing_detour));
        if (!created)
        {
            std::fprintf(stderr, "FAIL: the routed hook could not be created\n");
            return 120;
        }
        safetyhook::InlineHook hook = std::move(*created);
        s_gateway_base.store(reinterpret_cast<std::uintptr_t>(hook.route_region_for_test(0)),
                             std::memory_order_release);
        s_gateway_limit.store(s_gateway_base.load(std::memory_order_acquire) + 512, std::memory_order_release);
        s_driver_low.store(reinterpret_cast<std::uintptr_t>(&run_wrapper_native_exception_case),
                           std::memory_order_release);
        s_driver_high.store(s_driver_low.load(std::memory_order_acquire) + 4096, std::memory_order_release);
        if (auto enabled = hook.enable(); !enabled)
        {
            std::fprintf(stderr, "FAIL: the routed hook could not be enabled\n");
            return 121;
        }

        // The throw has to cross the generated wrapper frame to reach this handler. With the frame undescribed the
        // unwinder does not arrive here at all, so reaching the catch is the whole assertion.
        bool caught = false;
        try
        {
            (void)call_routed_target(1, 2);
        }
        catch (const std::runtime_error &)
        {
            caught = true;
        }
        if (!caught || s_routed_detour_calls.load(std::memory_order_relaxed) != 1)
        {
            std::fprintf(stderr, "FAIL: the exception did not propagate through the routed wrapper\n");
            return 122;
        }

        // The route counter is decremented after the destination returns, and an exception never returns, so the
        // entrant stays counted. Teardown must retain rather than reclaim; asserting it here keeps that honest.
        if (hook.route_entries() == 0)
        {
            std::fprintf(stderr, "FAIL: an unwound entrant was accounted as having left the route\n");
            return 123;
        }

        std::puts("ROUTED_WRAPPER_PROPAGATES_NATIVE_EXCEPTIONS");
        return 0;
    }

    int run_unwind_registration_refused_case()
    {
        const auto before = safetyhook::route_retention_stats();
        safetyhook::g_unwind_registration_failure.store(true, std::memory_order_release);
        auto created = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
        safetyhook::g_unwind_registration_failure.store(false, std::memory_order_release);

        if (created)
        {
            std::fprintf(stderr, "FAIL: a refused unwind registration still produced a routed hook\n");
            return 130;
        }
        if (created.error().type != safetyhook::InlineHook::Error::FAILED_TO_REGISTER_UNWIND)
        {
            std::fprintf(stderr, "FAIL: the refusal was not attributed to unwind registration\n");
            return 131;
        }
        // Nothing may be left reserved or charged by a creation that rolled back.
        const auto after = safetyhook::route_retention_stats();
        if (after.logical_reserved != before.logical_reserved || after.logical_charged != before.logical_charged ||
            after.committed_reserved != before.committed_reserved ||
            after.committed_charged != before.committed_charged)
        {
            std::fprintf(stderr, "FAIL: the rolled-back creation left retention accounting behind\n");
            return 132;
        }
        // The target must be untouched: the refusal happens before anything patches a prologue.
        if (call_routed_target(2, 5) != 7 || s_routed_detour_calls.load(std::memory_order_relaxed) != 0)
        {
            std::fprintf(stderr, "FAIL: a refused routed hook still altered its target\n");
            return 133;
        }

        // A subsequent creation with the seam disarmed must succeed, or the refusal proves nothing about the branch.
        {
            auto recovered = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
            if (!recovered)
            {
                std::fprintf(stderr, "FAIL: routed creation did not recover after the refusal\n");
                return 134;
            }
            for (int index = 0; index < 3; ++index)
            {
                DWORD64 image_base = 0;
                if (RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(recovered->route_region_for_test(index)),
                                           &image_base, nullptr) == nullptr)
                {
                    std::fprintf(stderr, "FAIL: recovered route %d was not registered before destruction\n", index);
                    return 135;
                }
            }
            // Never enabled: destruction must withdraw all three records before their shared storage is reusable.
            std::array<std::uintptr_t, 3> regions{};
            for (int index = 0; index < 3; ++index)
            {
                regions[static_cast<std::size_t>(index)] =
                    reinterpret_cast<std::uintptr_t>(recovered->route_region_for_test(index));
            }
            recovered = std::unexpected{safetyhook::InlineHook::Error::not_enough_space(nullptr)};
            for (const std::uintptr_t region : regions)
            {
                DWORD64 image_base = 0;
                if (RtlLookupFunctionEntry(static_cast<DWORD64>(region), &image_base, nullptr) != nullptr)
                {
                    std::fprintf(stderr, "FAIL: never-published route metadata remained registered after destroy\n");
                    return 136;
                }
            }
        }

        std::puts("REFUSED_UNWIND_REGISTRATION_ROLLS_BACK");
        return 0;
    }

    int run_route_metadata_retained_case()
    {
        std::uintptr_t wrapper = 0;
        std::uintptr_t gateway = 0;
        std::uintptr_t exit_thunk = 0;
        {
            auto created = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
            if (!created)
            {
                std::fprintf(stderr, "FAIL: the routed hook could not be created\n");
                return 140;
            }
            safetyhook::InlineHook hook = std::move(*created);
            gateway = reinterpret_cast<std::uintptr_t>(hook.route_region_for_test(0));
            wrapper = reinterpret_cast<std::uintptr_t>(hook.route_region_for_test(1));
            exit_thunk = reinterpret_cast<std::uintptr_t>(hook.route_region_for_test(2));
            if (auto enabled = hook.enable(); !enabled)
            {
                std::fprintf(stderr, "FAIL: the routed hook could not be enabled\n");
                return 141;
            }
            (void)call_routed_target(1, 1);
            // Destroyed here. Publication already happened, so the code and its records are process-lifetime storage.
        }

        DWORD64 image_base = 0;
        if (RtlLookupFunctionEntry(static_cast<DWORD64>(wrapper), &image_base, nullptr) == nullptr ||
            image_base != static_cast<DWORD64>(gateway))
        {
            std::fprintf(stderr, "FAIL: the retained wrapper lost its unwind record when its handle was destroyed\n");
            return 142;
        }
        // A thread parked before the gateway's first instruction after the handle is gone still has to find records,
        // so a published route must never hand its metadata back.
        if (RtlLookupFunctionEntry(static_cast<DWORD64>(gateway), &image_base, nullptr) == nullptr)
        {
            std::fprintf(stderr, "FAIL: the retained gateway lost its unwind record\n");
            return 143;
        }
        if (RtlLookupFunctionEntry(static_cast<DWORD64>(exit_thunk), &image_base, nullptr) == nullptr)
        {
            std::fprintf(stderr, "FAIL: the retained exit thunk lost its unwind record\n");
            return 144;
        }

        std::puts("PUBLISHED_ROUTE_METADATA_IS_RETAINED");
        return 0;
    }

    int run_route_capacity_refusal_case()
    {
        const auto before = safetyhook::route_retention_stats();
        // Below one worst-case chain, so the very first reservation cannot fit. The refusal has to happen while the
        // hook is still uncreated: after publication the chain is permanent and refusing is no longer an option.
        safetyhook::set_route_retention_capacity(before.logical_charged + before.logical_reserved,
                                                 before.committed_capacity);
        safetyhook::g_unwind_unregistration_failure.store(true, std::memory_order_release);
        auto refused = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
        const bool unregistration_was_not_reached =
            safetyhook::g_unwind_unregistration_failure.exchange(false, std::memory_order_acq_rel);
        safetyhook::set_route_retention_capacity(before.logical_capacity, before.committed_capacity);

        if (refused)
        {
            std::fprintf(stderr, "FAIL: a zero-headroom ceiling still admitted a routed chain\n");
            return 150;
        }
        if (refused.error().type != safetyhook::InlineHook::Error::ROUTE_RETENTION_EXHAUSTED)
        {
            std::fprintf(stderr, "FAIL: the refusal was not attributed to the retention ceiling\n");
            return 151;
        }
        if (!unregistration_was_not_reached)
        {
            std::fprintf(stderr, "FAIL: capacity refusal registered metadata before it owned a reservation\n");
            return 163;
        }
        if (call_routed_target(4, 4) != 8 || s_routed_detour_calls.load(std::memory_order_relaxed) != 0)
        {
            std::fprintf(stderr, "FAIL: a ceiling refusal still altered its target\n");
            return 152;
        }
        const auto refused_stats = safetyhook::route_retention_stats();
        if (refused_stats.refusals <= before.refusals)
        {
            std::fprintf(stderr, "FAIL: the ceiling refusal was not accounted\n");
            return 153;
        }
        if (refused_stats.logical_reserved != before.logical_reserved ||
            refused_stats.committed_reserved != before.committed_reserved)
        {
            std::fprintf(stderr, "FAIL: a refused reservation stayed outstanding\n");
            return 154;
        }

        safetyhook::set_route_retention_capacity(before.logical_capacity,
                                                 before.committed_charged + before.committed_reserved);
        auto committed_refused = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
        safetyhook::set_route_retention_capacity(before.logical_capacity, before.committed_capacity);
        if (committed_refused ||
            committed_refused.error().type != safetyhook::InlineHook::Error::ROUTE_RETENTION_EXHAUSTED)
        {
            std::fprintf(stderr, "FAIL: a committed-only zero-headroom ceiling admitted a routed chain\n");
            return 164;
        }
        const auto committed_refused_stats = safetyhook::route_retention_stats();
        if (committed_refused_stats.logical_reserved != before.logical_reserved ||
            committed_refused_stats.committed_reserved != before.committed_reserved ||
            committed_refused_stats.logical_charged != before.logical_charged ||
            committed_refused_stats.committed_charged != before.committed_charged)
        {
            std::fprintf(stderr, "FAIL: committed-capacity refusal changed retention totals\n");
            return 165;
        }

        // With headroom restored, creation succeeds, publication charges the chain, and the high-water rises with it.
        auto created = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
        if (!created)
        {
            std::fprintf(stderr, "FAIL: routed creation did not recover once the ceiling was restored\n");
            return 155;
        }
        safetyhook::InlineHook hook = std::move(*created);
        const auto reserved = safetyhook::route_retention_stats();
        if (reserved.logical_reserved <= before.logical_reserved ||
            reserved.committed_reserved <= before.committed_reserved)
        {
            std::fprintf(stderr, "FAIL: creation did not reserve its retained chain\n");
            return 156;
        }
        if (reserved.logical_charged != before.logical_charged ||
            reserved.committed_charged != before.committed_charged)
        {
            std::fprintf(stderr, "FAIL: an unpublished chain was charged as permanent\n");
            return 157;
        }
        if (auto enabled = hook.enable(); !enabled)
        {
            std::fprintf(stderr, "FAIL: the routed hook could not be enabled\n");
            return 158;
        }
        const auto charged = safetyhook::route_retention_stats();
        if (charged.logical_charged <= before.logical_charged || charged.committed_charged <= before.committed_charged)
        {
            std::fprintf(stderr, "FAIL: publication did not charge the retained chain\n");
            return 159;
        }
        if (charged.logical_reserved != before.logical_reserved ||
            charged.committed_reserved != before.committed_reserved)
        {
            std::fprintf(stderr, "FAIL: the reservation was not converted into a permanent charge\n");
            return 160;
        }
        if (charged.logical_high_water < charged.logical_charged ||
            charged.committed_high_water < charged.committed_charged)
        {
            std::fprintf(stderr, "FAIL: the high-water figures do not cover the charged totals\n");
            return 161;
        }
        // Committed counts complete allocator blocks, so it must be at least the logical figure it covers.
        if (charged.committed_charged < charged.logical_charged)
        {
            std::fprintf(stderr, "FAIL: committed bytes fell below the logical bytes they contain\n");
            return 162;
        }

        std::puts("ROUTE_CAPACITY_REFUSES_BEFORE_PUBLICATION");
        return 0;
    }

    int run_xinput_pair_capacity_case()
    {
        const wchar_t *const name = find_loadable_xinput();
        if (name == nullptr)
        {
            std::fprintf(stderr, "SKIP: no XInput runtime available on this host\n");
            return SKIP_EXIT_CODE;
        }
        const HMODULE xinput = LoadLibraryW(name);
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "SKIP: the resolved XInput runtime could not be loaded\n");
            return SKIP_EXIT_CODE;
        }
        const auto get_state =
            reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState")));
        const auto get_state_ex = reinterpret_cast<XInputGetStateFn>(
            reinterpret_cast<void *>(GetProcAddress(xinput, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL))));
        if (get_state == nullptr)
        {
            std::fprintf(stderr, "FAIL: XInputGetState is not exported\n");
            return 170;
        }

        const auto before = safetyhook::route_retention_stats();
        // Room for exactly one worst-case chain. A per-hook reservation would admit the primary and then refuse its Ex
        // partner, which is the primary-only coverage the pair transaction exists to prevent.
        const auto one_chain = safetyhook::route_chain_worst_case().logical;
        safetyhook::set_route_retention_capacity(before.logical_charged + before.logical_reserved + one_chain,
                                                 before.committed_capacity);
        const bool installed = install_xinput(0);
        safetyhook::set_route_retention_capacity(before.logical_capacity, before.committed_capacity);

        if (installed || xinput_installed())
        {
            std::fprintf(stderr, "FAIL: a ceiling that cannot hold the pair still installed XInput interception\n");
            return 171;
        }
        const auto refused_stats = safetyhook::route_retention_stats();
        if (refused_stats.logical_reserved != before.logical_reserved ||
            refused_stats.logical_charged != before.logical_charged ||
            refused_stats.committed_reserved != before.committed_reserved ||
            refused_stats.committed_charged != before.committed_charged)
        {
            std::fprintf(stderr, "FAIL: the refused pair changed route retention totals\n");
            return 172;
        }
        // Fail open on BOTH entries: a refused install must leave the game's own polling untouched.
        XINPUT_STATE state{};
        if (!legal_xinput_result(get_state(0, &state)))
        {
            std::fprintf(stderr, "FAIL: a refused pair left the primary entry uncallable\n");
            return 173;
        }
        if (get_state_ex != nullptr && !legal_xinput_result(get_state_ex(0, &state)))
        {
            std::fprintf(stderr, "FAIL: a refused pair left the Ex entry uncallable\n");
            return 174;
        }

        // With the ordinary ceiling back, the same install succeeds, so the refusal is about capacity and not about a
        // host without a usable XInput runtime.
        if (!install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: the install did not recover once the ceiling was restored\n");
            return 175;
        }
        uninstall();

        FreeLibrary(xinput);
        std::puts("XINPUT_PAIR_RESERVES_ATOMICALLY");
        return 0;
    }

    int run_unwind_unregistration_refused_case()
    {
        const auto before = safetyhook::route_retention_stats();
        std::array<std::uintptr_t, 3> regions{};
        std::uintptr_t gateway = 0;
        std::size_t gateway_bytes = 0;
        {
            auto created = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
            if (!created)
            {
                std::fprintf(stderr, "FAIL: could not create the unregistration-refusal route\n");
                return 145;
            }
            gateway = reinterpret_cast<std::uintptr_t>(created->route_region_for_test(0));
            // The retained logical cost of a non-MID route is exactly gateway plus trampoline, so the remainder is the
            // gateway request. Checked rather than assumed: an unsigned wrap here would ask for a colossal block and
            // turn the reuse probe below into a vacuous pass.
            const auto retained_logical = created->route_retention_for_test().logical;
            if (retained_logical < created->trampoline().size())
            {
                std::fprintf(stderr, "FAIL: retained logical cost does not cover the trampoline it includes\n");
                return 149;
            }
            gateway_bytes = retained_logical - created->trampoline().size();
            for (int index = 0; index < 3; ++index)
            {
                regions[static_cast<std::size_t>(index)] =
                    reinterpret_cast<std::uintptr_t>(created->route_region_for_test(index));
            }
            safetyhook::g_unwind_unregistration_failure.store(true, std::memory_order_release);
        }
        safetyhook::g_unwind_unregistration_failure.store(false, std::memory_order_release);

        for (const std::uintptr_t region : regions)
        {
            DWORD64 image_base = 0;
            if (RtlLookupFunctionEntry(static_cast<DWORD64>(region), &image_base, nullptr) == nullptr ||
                image_base != static_cast<DWORD64>(gateway))
            {
                std::fprintf(stderr, "FAIL: refused unregistration did not retain every registered region\n");
                return 146;
            }
        }
        const auto after = safetyhook::route_retention_stats();
        if (after.logical_reserved != before.logical_reserved ||
            after.committed_reserved != before.committed_reserved || after.logical_charged <= before.logical_charged ||
            after.committed_charged <= before.committed_charged)
        {
            std::fprintf(stderr, "FAIL: refused unregistration did not charge its permanently retained arena\n");
            return 147;
        }

        // Control for the probe below. A refused exact-address request only means "retained" if the same size is
        // otherwise satisfiable; without this, an allocator that could not serve the request for any reason would make
        // the retention assertion pass vacuously.
        const auto control = safetyhook::Allocator::global()->allocate(gateway_bytes);
        if (!control)
        {
            std::fprintf(stderr, "FAIL: the allocator could not serve the reuse-probe size at all\n");
            return 150;
        }

        // max_distance 0 admits only the retained address itself, so a refusal here is the assertion: the arena did not
        // hand the registered gateway back for reuse.
        auto reused = safetyhook::Allocator::global()->allocate_near({reinterpret_cast<std::uint8_t *>(gateway)},
                                                                     gateway_bytes, 0);
        if (reused && reused->address() == gateway)
        {
            std::fprintf(stderr, "FAIL: refused unregistration returned the registered gateway to allocator reuse\n");
            return 148;
        }

        std::puts("REFUSED_UNWIND_UNREGISTRATION_RETAINS_STORAGE");
        return 0;
    }

    void routed_mid_detour(safetyhook::Context &) noexcept {}

    int run_route_capacity_overflow_case()
    {
        const auto before = safetyhook::route_retention_stats();
        const auto worst = safetyhook::route_chain_worst_case();
        const std::size_t logical_overflow_count = std::numeric_limits<std::size_t>::max() / worst.logical + 1;
        safetyhook::RouteRetentionCredit logical_credit =
            safetyhook::RouteRetentionCredit::acquire(logical_overflow_count);
        if (logical_credit)
        {
            std::fprintf(stderr, "FAIL: a logical-overflow route-credit request produced a valid reservation\n");
            return 180;
        }
        const auto after_logical = safetyhook::route_retention_stats();
        const std::size_t committed_overflow_count = std::numeric_limits<std::size_t>::max() / worst.committed + 1;
        safetyhook::RouteRetentionCredit committed_credit =
            safetyhook::RouteRetentionCredit::acquire(committed_overflow_count);
        if (committed_credit)
        {
            std::fprintf(stderr, "FAIL: a committed-overflow route-credit request produced a valid reservation\n");
            return 186;
        }
        const auto after = safetyhook::route_retention_stats();
        if (after.logical_reserved != before.logical_reserved ||
            after.committed_reserved != before.committed_reserved || after.logical_charged != before.logical_charged ||
            after.committed_charged != before.committed_charged)
        {
            std::fprintf(stderr, "FAIL: an overflowing route-credit request corrupted the accounting totals\n");
            return 181;
        }
        if (after_logical.refusals <= before.refusals || after.refusals <= after_logical.refusals)
        {
            std::fprintf(stderr, "FAIL: the overflowing route-credit refusal was not counted\n");
            return 182;
        }

        std::puts("ROUTE_CREDIT_OVERFLOW_REFUSES_CLEANLY");
        return 0;
    }

    int run_route_restore_failure_accounting_case()
    {
        const auto before = safetyhook::route_retention_stats();
        auto created = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
        if (!created)
        {
            std::fprintf(stderr, "FAIL: could not create the restore-failure accounting route\n");
            return 183;
        }
        safetyhook::InlineHook hook = std::move(*created);
        const auto actual = hook.route_retention_for_test();
        safetyhook::g_trap_restore_failure_override.store(reinterpret_cast<std::uint8_t *>(&routed_unwind_target),
                                                          std::memory_order_release);
        const auto enabled = hook.enable();
        safetyhook::g_trap_restore_failure_override.store(nullptr, std::memory_order_release);
        if (enabled || !hook.enabled() || enabled.error().type != safetyhook::InlineHook::Error::FAILED_TO_UNPROTECT)
        {
            std::fprintf(stderr, "FAIL: restore failure did not report a committed enabled route\n");
            return 184;
        }
        const auto after = safetyhook::route_retention_stats();
        if (after.logical_reserved != before.logical_reserved ||
            after.committed_reserved != before.committed_reserved ||
            after.logical_charged - before.logical_charged != actual.logical ||
            after.committed_charged - before.committed_charged != actual.committed)
        {
            std::fprintf(stderr, "FAIL: restore-error return did not charge its published route\n");
            return 185;
        }

        std::puts("ROUTE_RESTORE_FAILURE_CHARGES_PUBLICATION");
        return 0;
    }

    int run_route_allocator_reclamation_case()
    {
        const auto allocator = safetyhook::Allocator::create();
        auto allocation = allocator->allocate(128);
        if (!allocation)
        {
            std::fprintf(stderr, "FAIL: could not allocate the reclamation control block\n");
            return 187;
        }
        const auto address = allocation->address();
        MEMORY_BASIC_INFORMATION before{};
        if (VirtualQuery(reinterpret_cast<void *>(address), &before, sizeof(before)) == 0 || before.State != MEM_COMMIT)
        {
            std::fprintf(stderr, "FAIL: reclamation control was not committed virtual memory\n");
            return 188;
        }
        allocation->free();

        MEMORY_BASIC_INFORMATION after{};
        if (VirtualQuery(reinterpret_cast<void *>(address), &after, sizeof(after)) == 0 || after.State != MEM_FREE)
        {
            std::fprintf(stderr, "FAIL: a wholly free allocator block remained mapped\n");
            return 189;
        }

        std::puts("ROUTE_ALLOCATOR_RECLAIMS_WHOLE_BLOCK");
        return 0;
    }

    int run_mid_route_accounting_case()
    {
        const auto before = safetyhook::route_retention_stats();
        safetyhook::RouteRetentionCost inline_cost{};
        {
            auto created = make_routed_hook(reinterpret_cast<void *>(&routed_unwind_detour));
            if (!created)
            {
                std::fprintf(stderr, "FAIL: could not create the inline accounting control\n");
                return 190;
            }
            inline_cost = created->route_retention_for_test();
        }
        const auto after_inline = safetyhook::route_retention_stats();
        if (after_inline.logical_reserved != before.logical_reserved ||
            after_inline.committed_reserved != before.committed_reserved)
        {
            std::fprintf(stderr, "FAIL: the unpublished inline control did not release its complete slot\n");
            return 191;
        }

        SYSTEM_INFO system_info{};
        GetSystemInfo(&system_info);
        const auto caller_allocator = safetyhook::Allocator::create();
        auto pollution = caller_allocator->allocate(static_cast<std::size_t>(system_info.dwAllocationGranularity) + 2);
        if (!pollution || pollution->backing_size() <= system_info.dwAllocationGranularity)
        {
            std::fprintf(stderr, "FAIL: could not prepare the oversized caller allocator block\n");
            return 196;
        }
        auto created = safetyhook::MidHook::create(caller_allocator, reinterpret_cast<void *>(&routed_unwind_target),
                                                   &routed_mid_detour, safetyhook::MidHook::StartDisabled);
        if (!created)
        {
            std::fprintf(stderr, "FAIL: could not create the MID accounting route\n");
            return 192;
        }
        safetyhook::MidHook hook = std::move(*created);
        const auto mid_cost = hook.route_retention_for_test();
        if (mid_cost.logical != inline_cost.logical + 404 ||
            mid_cost.committed != inline_cost.committed + system_info.dwAllocationGranularity ||
            mid_cost.committed > static_cast<std::size_t>(system_info.dwAllocationGranularity) * 3)
        {
            std::fprintf(stderr, "FAIL: the complete MID cost does not include its generated stub/backing block\n");
            return 193;
        }
        if (auto enabled = hook.enable(); !enabled)
        {
            std::fprintf(stderr, "FAIL: the MID accounting route could not publish\n");
            return 194;
        }
        const auto charged = safetyhook::route_retention_stats();
        if (charged.logical_reserved != before.logical_reserved ||
            charged.committed_reserved != before.committed_reserved ||
            charged.logical_charged - before.logical_charged != mid_cost.logical ||
            charged.committed_charged - before.committed_charged != mid_cost.committed)
        {
            std::fprintf(stderr, "FAIL: MID publication did not convert its complete actual chain into a charge\n");
            return 195;
        }

        std::puts("MID_ROUTE_ACCOUNTING_INCLUDES_GENERATED_STUB");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: xinput_detour_rundown <timeout|pre-body-route|process-exit-storage|"
                             "clean-release-oom|reference-balance|"
                             "first-install-oom|first-install-oom-create|enable-before|enable-after|disable-before|"
                             "disable-after|disable-ex-before|disable-primary-before|pair-compensation-inverted|"
                             "newer-layer|newer-layer-ex|arm-inversion|ex-arm-inversion|wrapper-unwind|"
                             "wrapper-native-exception|unwind-registration-refused|unwind-unregistration-refused|"
                             "route-metadata-retained|route-capacity-refusal|route-capacity-overflow|"
                             "route-restore-failure|route-allocator-reclamation|"
                             "mid-route-accounting|xinput-pair-capacity|fresh-primary-loss|"
                             "installed-primary-loss|permanent-primary-loss|poller-maintains-pair>\n");
        return 1;
    }

#if defined(_MSC_VER)
    // A raw proof runs headless: nothing dismisses a modal CRT dialog. Route asserts/errors to stderr and make abort()
    // exit with a status instead of blocking on a message box, so a failure is a fast diagnostic exit, not a hang.
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
#endif

    const std::string_view selected_case{argv[1]};
    if (selected_case == "wrapper-unwind")
        return run_wrapper_unwind_case();
    if (selected_case == "wrapper-native-exception")
        return run_wrapper_native_exception_case();
    if (selected_case == "unwind-registration-refused")
        return run_unwind_registration_refused_case();
    if (selected_case == "unwind-unregistration-refused")
        return run_unwind_unregistration_refused_case();
    if (selected_case == "route-metadata-retained")
        return run_route_metadata_retained_case();
    if (selected_case == "route-capacity-refusal")
        return run_route_capacity_refusal_case();
    if (selected_case == "xinput-pair-capacity")
        return run_xinput_pair_capacity_case();
    if (selected_case == "route-capacity-overflow")
        return run_route_capacity_overflow_case();
    if (selected_case == "route-restore-failure")
        return run_route_restore_failure_accounting_case();
    if (selected_case == "route-allocator-reclamation")
        return run_route_allocator_reclamation_case();
    if (selected_case == "mid-route-accounting")
        return run_mid_route_accounting_case();
#if defined(_MSC_VER) && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL != 0
    // MSVC debug iterators allocate hidden vector proxies inside the raw backend's default construction. The release
    // STL lane proves first-install OOM containment without that unrelated noexcept allocation.
    if (selected_case == "first-install-oom" || selected_case == "first-install-oom-create" ||
        selected_case == "clean-release-oom")
        return SKIP_EXIT_CODE;
#endif
    if (selected_case == "timeout")
        return run_timeout_case();
    if (selected_case == "pre-body-route")
        return run_pre_body_route_case();
    if (selected_case == "process-exit-storage")
        return run_process_exit_storage_case();
    if (selected_case == "clean-release-oom")
        return run_clean_release_oom_case();
    if (selected_case == "reference-balance")
        return run_reference_balance_case();
    if (selected_case == "first-install-oom")
        return run_first_install_oom_case();
    if (selected_case == "first-install-oom-create")
        return run_first_install_oom_create_case();
    if (selected_case == "arm-inversion")
        return run_arm_inversion_case();
    if (selected_case == "enable-before")
        return run_enable_exception_case(false);
    if (selected_case == "enable-after")
        return run_enable_exception_case(true);
    if (selected_case == "disable-before")
        return run_disable_exception_case(false);
    if (selected_case == "disable-after")
        return run_disable_exception_case(true);
    if (selected_case == "disable-ex-before")
        return run_ex_disable_exception_case();
    if (selected_case == "disable-primary-before")
        return run_primary_disable_exception_case();
    if (selected_case == "pair-compensation-inverted")
        return run_pair_compensation_inverted_case();
    if (selected_case == "newer-layer")
        return run_newer_layer_case();
    if (selected_case == "newer-layer-ex")
        return run_newer_layer_ex_pair_case();
    if (selected_case == "ex-arm-inversion")
        return run_ex_arm_inversion_case();
    if (selected_case == "fresh-primary-loss")
        return run_fresh_primary_loss_case();
    if (selected_case == "installed-primary-loss")
        return run_installed_primary_loss_case();
    if (selected_case == "permanent-primary-loss")
        return run_permanent_primary_loss_case();
    if (selected_case == "poller-maintains-pair")
        return run_poller_maintenance_case();

    std::fprintf(stderr, "unknown xinput rundown case\n");
    return 1;
}
