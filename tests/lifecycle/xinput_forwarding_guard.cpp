/**
 * @file xinput_forwarding_guard.cpp
 * @brief Raw proof that install_xinput()'s ordinal-100 guard skips a forwarded XInputGetStateEx and hooks a local one.
 * @details Runs against one proxy that forwards ordinal 100 to a compatible function in another DLL and one that
 *          exports the function locally. The former must skip the Ex hook; the latter is the positive install control.
 */

#include "internal/input_intercept.hpp"

#include <windows.h>
#include <xinput.h>

#include <cstdio>
#include <cstring>

using DetourModKit::detail::install_xinput;
using DetourModKit::detail::next_intercept_owner;
using DetourModKit::detail::set_xinput_module_override_for_test;
using DetourModKit::detail::uninstall;
using DetourModKit::detail::xinput_ex_trampoline;
using DetourModKit::detail::xinput_installed;
using DetourModKit::detail::xinput_module_refs_held;
using DetourModKit::detail::xinput_trampoline;

namespace
{
    /// Returns the module owning @p address without changing its reference count.
    HMODULE module_owning(const void *address) noexcept
    {
        HMODULE module = nullptr;
        constexpr DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
        if (GetModuleHandleExW(flags, reinterpret_cast<LPCWSTR>(address), &module) == FALSE)
        {
            return nullptr;
        }
        return module;
    }

    void clear_override_and_free(HMODULE proxy) noexcept
    {
        set_xinput_module_override_for_test(nullptr);
        FreeLibrary(proxy);
    }

    int run_forwarded_case()
    {
        const HMODULE proxy = LoadLibraryW(L"dmk_xinput_proxy_fwd.dll");
        if (proxy == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load forwarding proxy (error %lu)\n", GetLastError());
            return 2;
        }
        set_xinput_module_override_for_test(proxy);

        auto *const get_state = reinterpret_cast<void *>(GetProcAddress(proxy, "XInputGetState"));
        auto *const get_state_ex = reinterpret_cast<void *>(GetProcAddress(proxy, MAKEINTRESOURCEA(100)));
        int rc = 0;
        if (get_state == nullptr)
        {
            std::fprintf(stderr, "FAIL: proxy exports no XInputGetState\n");
            rc = 3;
        }
        else if (get_state_ex == nullptr)
        {
            std::fprintf(stderr, "FAIL: proxy ordinal 100 did not resolve\n");
            rc = 4;
        }
        const HMODULE get_state_ex_module = get_state_ex != nullptr ? module_owning(get_state_ex) : nullptr;
        if (rc == 0 && get_state_ex_module == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not identify the module owning ordinal 100\n");
            rc = 14;
        }
        else if (rc == 0 && get_state_ex_module == proxy)
        {
            std::fprintf(stderr, "FAIL: ordinal 100 resolved inside the proxy, not forwarded out\n");
            rc = 5;
        }
        if (rc != 0)
        {
            clear_override_and_free(proxy);
            return rc;
        }

        const std::uint64_t owner = next_intercept_owner();
        if (!install_xinput(0, owner))
        {
            std::fprintf(stderr, "FAIL: install_xinput refused against the proxy\n");
            clear_override_and_free(proxy);
            return 6;
        }
        if (!xinput_installed())
        {
            std::fprintf(stderr, "FAIL: primary hook not installed\n");
            rc = 7;
        }
        else if (xinput_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: primary trampoline is null\n");
            rc = 8;
        }
        else if (xinput_ex_trampoline() != nullptr)
        {
            std::fprintf(stderr, "FAIL: Ex hook installed for a forwarded ordinal (guard skip branch not taken)\n");
            rc = 9;
        }
        else if (xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: expected 2 keepalives, got %d\n", xinput_module_refs_held());
            rc = 10;
        }

        uninstall(owner);
        if (rc == 0 && (xinput_installed() || xinput_module_refs_held() != 0))
        {
            std::fprintf(stderr, "FAIL: teardown left state (installed=%d refs=%d)\n",
                         static_cast<int>(xinput_installed()), xinput_module_refs_held());
            rc = 11;
        }
        clear_override_and_free(proxy);
        return rc;
    }

    int run_same_module_case()
    {
        const HMODULE proxy = LoadLibraryW(L"dmk_xinput_proxy_local.dll");
        if (proxy == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load same-module proxy (error %lu)\n", GetLastError());
            return 2;
        }
        set_xinput_module_override_for_test(proxy);

        auto *const get_state = reinterpret_cast<void *>(GetProcAddress(proxy, "XInputGetState"));
        auto *const get_state_ex = reinterpret_cast<void *>(GetProcAddress(proxy, MAKEINTRESOURCEA(100)));
        int rc = 0;
        if (get_state == nullptr)
        {
            std::fprintf(stderr, "FAIL: proxy exports no XInputGetState\n");
            rc = 3;
        }
        else if (get_state_ex == nullptr)
        {
            std::fprintf(stderr, "FAIL: proxy ordinal 100 did not resolve\n");
            rc = 4;
        }
        else if (module_owning(get_state_ex) != proxy)
        {
            std::fprintf(stderr, "FAIL: ordinal 100 is not in the proxy module\n");
            rc = 5;
        }
        else if (get_state_ex == get_state)
        {
            std::fprintf(stderr, "FAIL: ordinal 100 aliases XInputGetState (guard would skip on address equality)\n");
            rc = 12;
        }
        if (rc != 0)
        {
            clear_override_and_free(proxy);
            return rc;
        }

        const std::uint64_t owner = next_intercept_owner();
        if (!install_xinput(0, owner))
        {
            std::fprintf(stderr, "FAIL: install_xinput refused against the proxy\n");
            clear_override_and_free(proxy);
            return 6;
        }
        if (!xinput_installed())
        {
            std::fprintf(stderr, "FAIL: primary hook not installed\n");
            rc = 7;
        }
        else if (xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: Ex hook NOT installed for a same-module ordinal 100 (positive control)\n");
            rc = 13;
        }
        else if (xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: expected 2 keepalives, got %d\n", xinput_module_refs_held());
            rc = 10;
        }

        uninstall(owner);
        if (rc == 0 && (xinput_installed() || xinput_ex_trampoline() != nullptr || xinput_module_refs_held() != 0))
        {
            std::fprintf(stderr, "FAIL: teardown left state\n");
            rc = 11;
        }
        clear_override_and_free(proxy);
        return rc;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: %s <forwarded|same-module>\n", argv[0]);
        return 1;
    }
    if (std::strcmp(argv[1], "forwarded") == 0)
    {
        return run_forwarded_case();
    }
    if (std::strcmp(argv[1], "same-module") == 0)
    {
        return run_same_module_case();
    }
    std::fprintf(stderr, "unknown case: %s\n", argv[1]);
    return 1;
}
