// Fresh-process proofs for the XInput interception lifetime. Retention branches latch a process-lifetime permanent
// detour and the OOM branches replace global allocation, so no mode may share a process with another. Exit status is
// the oracle.

#include "internal/input_intercept.hpp"

#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"

#include <windows.h>
#include <Xinput.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string_view>
#include <thread>

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
    using DetourModKit::detail::install_xinput;
    using DetourModKit::detail::publish_gamepad_suppress;
    using DetourModKit::detail::set_xinput_arm_seam;
    using DetourModKit::detail::set_xinput_backend_toggle_exception_for_test;
    using DetourModKit::detail::set_xinput_clean_release_seam;
    using DetourModKit::detail::set_xinput_detour_body_seam;
    using DetourModKit::detail::set_xinput_module_override_for_test;
    using DetourModKit::detail::set_xinput_route_entry_hold_for_test;
    using DetourModKit::detail::uninstall;
    using DetourModKit::detail::xinput_backend_toggle_exception_catches_for_test;
    using DetourModKit::detail::xinput_installed;

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

    // Stands in for a third-party writer that restores the exact pre-DMK prologue while DMK's patch is live. Wider
    // than any steal window, so the restored span always covers the whole patch; the bytes past it are rewritten with
    // the values they already hold.
    constexpr std::size_t ARM_RACE_SPAN = 32;
    std::uint8_t *s_arm_race_target{nullptr};
    std::array<std::uint8_t, ARM_RACE_SPAN> s_arm_race_original{};
    std::atomic<int> s_arm_race_runs{0};

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
        (void)overwrite_prologue_span(s_arm_race_target, s_arm_race_original.data());
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

    int run_pre_body_route_case()
    {
        const HMODULE xinput = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (xinput == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the same-module XInput proxy (error %lu)\n", GetLastError());
            return 110;
        }
        set_xinput_module_override_for_test(xinput);
        const auto get_state =
            reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(GetProcAddress(xinput, "XInputGetState")));
        if (get_state == nullptr || !install_xinput(0))
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
        std::thread caller(
            [&]() noexcept
            {
                XINPUT_STATE state{};
                call_result = get_state(0, &state);
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
        if (!s_body_entered.load(std::memory_order_acquire) || !legal_xinput_result(call_result))
        {
            std::fprintf(stderr, "FAIL: retained pre-body caller did not resume safely (result %lu)\n",
                         static_cast<unsigned long>(call_result));
            return 115;
        }

        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(xinput);
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

    // The unpinned first install acquires the backend allocator before it constructs a hook, so poisoning allocation
    // across the whole call proves only the allocator third of the containment. Keeping one live managed hook on an
    // unrelated target holds the process-global allocator alive, so its acquisition no longer allocates and the first
    // poisoned allocation lands inside InlineHook::create instead. Narrowing create_xinput_hook's catch then
    // terminates this case and no other.
    int run_first_install_oom_create_case()
    {
        const HMODULE pin_module = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (pin_module == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the allocator-pinning proxy (error %lu)\n", GetLastError());
            return 80;
        }
        auto *const pin_target = reinterpret_cast<void *>(GetProcAddress(pin_module, "XInputGetState"));
        if (pin_target == nullptr)
        {
            std::fprintf(stderr, "FAIL: the allocator-pinning proxy does not export XInputGetState\n");
            return 81;
        }
        DetourModKit::hook::InlineRequest pin_request{
            .name = "XInputAllocatorPin",
            .target = DetourModKit::Address{reinterpret_cast<std::uintptr_t>(pin_target)},
            .options = {.prologue = DetourModKit::hook::Prologue::Relocate}};
        auto pin = DetourModKit::hook::inline_at(std::move(pin_request), &newer_xinput_detour);
        if (!pin)
        {
            std::fprintf(stderr, "FAIL: could not create the allocator-pinning hook\n");
            return 82;
        }
        DetourModKit::hook::Hook allocator_pin = std::move(*pin);

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

        s_poison_thread_id.store(GetCurrentThreadId(), std::memory_order_release);
        const bool installed = install_xinput(0);
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

        set_xinput_backend_toggle_exception_for_test(target, after_mutation);
        const bool installed = install_xinput(0);
        set_xinput_backend_toggle_exception_for_test(nullptr, false);
        if (xinput_backend_toggle_exception_catches_for_test() != 1)
        {
            std::fprintf(stderr, "FAIL: raw enable exception did not reach the containment boundary\n");
            return 31;
        }

        if (!after_mutation)
        {
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
        auto *const target = reinterpret_cast<std::uint8_t *>(GetProcAddress(xinput, "XInputGetState"));
        if (target == nullptr)
        {
            std::fprintf(stderr, "FAIL: XInputGetState is not exported\n");
            return 50;
        }
        const auto get_state = reinterpret_cast<XInputGetStateFn>(reinterpret_cast<void *>(target));

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
        // Retained storage is never layered over, and a later teardown neither restores nor frees what it no longer
        // owns: the disarmed primary entry is unreachable, so re-arming it would be a claim the bytes cannot support.
        if (install_xinput(0))
        {
            std::fprintf(stderr, "FAIL: a later install layered a second hook over retained storage\n");
            return 56;
        }
        // Both installs above failed, so neither published an owner and an unowned uninstall() would return before the
        // permanent-detour branch, leaving the keepalive check below asserting against a no-op. Claim the idle layer so
        // the disarm path this case is about actually runs. The state is reachable in production too: the WndProc half
        // publishes the owner independently of a refused XInput install.
        if (!adopt_owner_for_test(DetourModKit::detail::STANDALONE_INTERCEPT_OWNER))
        {
            std::fprintf(stderr, "FAIL: the interception layer was still owned after two refused installs\n");
            return 59;
        }
        uninstall();
        if (DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: teardown released a keepalive the retained storage still needs\n");
            return 57;
        }

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

        if (!install_xinput(0) || !xinput_installed())
        {
            std::fprintf(stderr, "FAIL: the retained pair could not recover after a transient re-arm failure\n");
            return 132;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() != initial_ex_trampoline ||
            std::memcmp(get_state_ex_target, armed_ex_prologue.data(), ARM_RACE_SPAN) != 0)
        {
            std::fprintf(stderr, "FAIL: a later install did not restore the retained ordinal-100 entry route\n");
            return 133;
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

        s_newer_calls.store(0, std::memory_order_relaxed);
        uninstall();
        if (xinput_installed() || DetourModKit::detail::xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: layered teardown did not retain the raw trampoline chain\n");
            return 54;
        }
        if (!install_xinput(0) || DetourModKit::detail::xinput_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: retained newer-layer chain could not be logically rearmed\n");
            return 55;
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

        (void)newer.disable();
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

        std::array<std::uint8_t, ARM_RACE_SPAN> primary_original{};
        std::array<std::uint8_t, ARM_RACE_SPAN> ex_original{};
        std::memcpy(primary_original.data(), get_state_target, ARM_RACE_SPAN);
        std::memcpy(ex_original.data(), get_state_ex_target, ARM_RACE_SPAN);

        std::memcpy(s_arm_race_original.data(), ex_original.data(), ARM_RACE_SPAN);
        s_arm_race_target = get_state_ex_target;
        s_arm_race_runs.store(0, std::memory_order_relaxed);
        set_xinput_arm_seam(&restore_ex_prologue_in_arm_window);
        const bool installed = install_xinput(0);
        set_xinput_arm_seam(nullptr);
        s_arm_race_target = nullptr;

        if (!installed)
        {
            std::fprintf(stderr, "FAIL: an inverted ordinal-100 arm must not fail the primary install\n");
            return 92;
        }
        if (s_arm_race_runs.load(std::memory_order_relaxed) < 2)
        {
            std::fprintf(stderr, "FAIL: the competing writer never reached the ordinal-100 arm window\n");
            return 93;
        }
        if (DetourModKit::detail::xinput_ex_trampoline() != nullptr)
        {
            std::fprintf(stderr, "FAIL: an inverted ordinal-100 arm still published a forwarding chain\n");
            return 94;
        }

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
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: xinput_detour_rundown <timeout|pre-body-route|clean-release-oom|reference-balance|"
                             "first-install-oom|enable-before|"
                             "enable-after|disable-before|disable-after|disable-ex-before|disable-primary-before|"
                             "pair-compensation-inverted|newer-layer|"
                             "newer-layer-ex|first-install-oom-create|arm-inversion|ex-arm-inversion>\n");
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

    std::fprintf(stderr, "unknown xinput rundown case\n");
    return 1;
}
