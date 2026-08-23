/**
 * @file xinput_forwarding_guard.cpp
 * @brief Raw proof of which ordinal-100 XInputGetStateEx targets belong to the XInput coverage pair.
 * @details Four checked-in export shapes, one per branch: ordinal 100 local to the patched module, forwarded into
 *          another module, absent, and aliased onto XInputGetState. The first two are distinct members and must be
 *          hooked (the forwarded case also proves the extra target-module keepalive). The last two are the only
 *          exemptions: there is no second entry point to mask, so coverage is complete with the primary hook alone.
 */

#include "internal/input_intercept.hpp"

#include <windows.h>
#include <xinput.h>

#include <cstdio>
#include <cstring>

using DetourModKit::detail::apply_xinput_suppress_for_test;
using DetourModKit::detail::install_xinput;
using DetourModKit::detail::next_intercept_owner;
using DetourModKit::detail::publish_gamepad_suppress;
using DetourModKit::detail::set_xinput_module_override_for_test;
using DetourModKit::detail::uninstall;
using DetourModKit::detail::xinput_ex_trampoline;
using DetourModKit::detail::xinput_installed;
using DetourModKit::detail::xinput_module_refs_held;
using DetourModKit::detail::xinput_trampoline;

namespace
{
    using XInputGetStateFn = DWORD(WINAPI *)(DWORD, XINPUT_STATE *);

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
        else if (xinput_ex_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: Ex hook was not installed for a forwarded ordinal\n");
            rc = 9;
        }
        else if (xinput_module_refs_held() != 3)
        {
            std::fprintf(stderr, "FAIL: expected 3 keepalives, got %d\n", xinput_module_refs_held());
            rc = 10;
        }
        else
        {
            XINPUT_STATE state{};
            state.dwPacketNumber = 0xFFFFFFFFu;
            const DWORD result = reinterpret_cast<XInputGetStateFn>(get_state_ex)(4, &state);
            if (result != ERROR_DEVICE_NOT_CONNECTED || state.dwPacketNumber != 5)
            {
                std::fprintf(stderr, "FAIL: forwarded Ex route did not pass through to its resolved target\n");
                rc = 15;
            }
        }

        uninstall(owner);
        if (rc == 0 && (xinput_installed() || xinput_module_refs_held() != 0))
        {
            std::fprintf(
                stderr,
                "FAIL: teardown left state (installed=%d refs=%d)\n",
                static_cast<int>(xinput_installed()),
                xinput_module_refs_held()
            );
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

    /**
     * @brief Shared body for the two ordinal-100 exemptions: an absent export and one aliased onto XInputGetState.
     * @details Neither shape offers a second entry point to mask, so the primary hook alone is complete coverage and
     *          the install must publish suppression rather than settle into a degraded pair that retries forever. The
     *          alias half also pins why the exemption exists: one prologue carries one chain, and a second inline hook
     *          over those same bytes would capture the first hook's jump as its original.
     */
    int run_exempt_ordinal_case(const wchar_t *proxy_name, bool expect_alias)
    {
        const HMODULE proxy = LoadLibraryW(proxy_name);
        if (proxy == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load the exempt-ordinal fixture (error %lu)\n", GetLastError());
            return 20;
        }
        set_xinput_module_override_for_test(proxy);

        auto *const get_state = reinterpret_cast<void *>(GetProcAddress(proxy, "XInputGetState"));
        auto *const get_state_ex = reinterpret_cast<void *>(GetProcAddress(proxy, MAKEINTRESOURCEA(100)));
        int rc = 0;
        if (get_state == nullptr)
        {
            std::fprintf(stderr, "FAIL: fixture exports no XInputGetState\n");
            rc = 21;
        }
        else if (expect_alias && get_state_ex != get_state)
        {
            std::fprintf(stderr, "FAIL: fixture ordinal 100 is not an alias of XInputGetState\n");
            rc = 22;
        }
        else if (!expect_alias && get_state_ex != nullptr)
        {
            std::fprintf(stderr, "FAIL: fixture ordinal 100 resolved on the absent-Ex shape\n");
            rc = 23;
        }
        if (rc != 0)
        {
            clear_override_and_free(proxy);
            return rc;
        }

        const std::uint64_t owner = next_intercept_owner();
        if (!install_xinput(0, owner))
        {
            std::fprintf(stderr, "FAIL: an exempt ordinal-100 shape did not install complete coverage\n");
            clear_override_and_free(proxy);
            return 24;
        }
        if (!xinput_installed())
        {
            std::fprintf(stderr, "FAIL: coverage over an exempt ordinal 100 was not published\n");
            rc = 25;
        }
        else if (xinput_trampoline() == nullptr)
        {
            std::fprintf(stderr, "FAIL: primary trampoline is null\n");
            rc = 26;
        }
        else if (xinput_ex_trampoline() != nullptr)
        {
            std::fprintf(stderr, "FAIL: an exempt ordinal 100 built a second forwarding chain\n");
            rc = 27;
        }
        else if (xinput_module_refs_held() != 2)
        {
            std::fprintf(stderr, "FAIL: expected 2 keepalives, got %d\n", xinput_module_refs_held());
            rc = 28;
        }
        else if (!publish_gamepad_suppress(XINPUT_GAMEPAD_A, owner))
        {
            std::fprintf(stderr, "FAIL: could not publish a suppression mask over complete coverage\n");
            rc = 29;
        }
        else
        {
            // Complete coverage means the mask is live, not that a flag reads true.
            XINPUT_STATE masked{};
            masked.Gamepad.wButtons = XINPUT_GAMEPAD_A | XINPUT_GAMEPAD_B;
            apply_xinput_suppress_for_test(&masked, 0);
            if (masked.Gamepad.wButtons != XINPUT_GAMEPAD_B)
            {
                std::fprintf(stderr, "FAIL: complete coverage did not mask the bound controller\n");
                rc = 30;
            }
        }

        if (rc == 0)
        {
            XINPUT_STATE routed{};
            routed.dwPacketNumber = 0xFFFFFFFFu;
            const DWORD result = reinterpret_cast<XInputGetStateFn>(get_state)(6, &routed);
            if (result != ERROR_DEVICE_NOT_CONNECTED || routed.dwPacketNumber != 6)
            {
                std::fprintf(stderr, "FAIL: the single patched prologue did not forward exactly once\n");
                rc = 31;
            }
        }

        uninstall(owner);
        if (rc == 0 && (xinput_installed() || xinput_trampoline() != nullptr || xinput_module_refs_held() != 0))
        {
            std::fprintf(
                stderr,
                "FAIL: teardown left state (installed=%d refs=%d)\n",
                static_cast<int>(xinput_installed()),
                xinput_module_refs_held()
            );
            rc = 32;
        }
        clear_override_and_free(proxy);
        return rc;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: %s <forwarded|same-module|absent-ex|alias-ex>\n", argv[0]);
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
    if (std::strcmp(argv[1], "absent-ex") == 0)
    {
        return run_exempt_ordinal_case(L"dmk_xinput_proxy_noex.dll", false);
    }
    if (std::strcmp(argv[1], "alias-ex") == 0)
    {
        return run_exempt_ordinal_case(L"dmk_xinput_proxy_alias.dll", true);
    }
    std::fprintf(stderr, "unknown case: %s\n", argv[1]);
    return 1;
}
