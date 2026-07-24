// Fresh-process proofs for the XInput interception lifetime. The timeout branch latches a process-lifetime permanent
// detour, so it cannot share a process with the ordinary install/uninstall cases. Exit status is the oracle.

#include "internal/input_intercept.hpp"

#include <windows.h>
#include <Xinput.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string_view>
#include <thread>

namespace
{
    // When set, every plain (non-aligned) operator new throws. Armed only around uninstall() so the retain-on-timeout
    // path is proven to need no plain heap allocation.
    std::atomic<bool> g_poison{false};
} // namespace

void *operator new(std::size_t size)
{
    if (g_poison.load(std::memory_order_acquire))
    {
        throw std::bad_alloc{};
    }
    if (void *p = std::malloc(size != 0 ? size : 1))
    {
        return p;
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
    using DetourModKit::detail::install_xinput;
    using DetourModKit::detail::set_xinput_detour_body_seam;
    using DetourModKit::detail::uninstall;
    using DetourModKit::detail::xinput_installed;

    using XInputGetStateFn = DWORD(WINAPI *)(DWORD, XINPUT_STATE *);

    constexpr const wchar_t *XINPUT_NAMES[] = {L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll"};

    // Reported to ctest through SKIP_RETURN_CODE. Exit status is this proof's only oracle, so a host with no XInput
    // runtime must not exit 0 and be counted as a pass that asserted nothing.
    constexpr int SKIP_EXIT_CODE = 77;

    // The parked caller signals arrival here and waits for release, so the drain has a genuinely in-flight detour.
    std::atomic<bool> g_parked{false};
    std::atomic<bool> g_release{false};

    void park_in_detour() noexcept
    {
        g_parked.store(true, std::memory_order_release);
        while (!g_release.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

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
        while (!g_parked.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        // The parked caller is the only one that may take the seam; later entrants must run through freely so the
        // republished trampoline can be exercised below.
        set_xinput_detour_body_seam(nullptr);

        g_poison.store(true, std::memory_order_release);
        uninstall();
        g_poison.store(false, std::memory_order_release);

        // Release and join before any verdict below: the parked caller only ever waits on g_release, so returning
        // while it is still joinable would destroy a running std::thread and terminate the process, replacing every
        // diagnostic exit code after this point with an abort.
        g_release.store(true, std::memory_order_release);
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

        constexpr int ROUNDS = 4;
        for (int round = 0; round < ROUNDS; ++round)
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
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: xinput_detour_rundown <timeout|reference-balance>\n");
        return 1;
    }

    const std::string_view selected_case{argv[1]};
    if (selected_case == "timeout")
        return run_timeout_case();
    if (selected_case == "reference-balance")
        return run_reference_balance_case();

    std::fprintf(stderr, "unknown xinput rundown case\n");
    return 1;
}
