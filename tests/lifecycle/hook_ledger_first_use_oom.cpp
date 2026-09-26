// Fresh-process proofs for the hook ledger accessor. The OOM arms require a first-use allocation failure to publish the
// inert ledger, so every ledger operation fails closed for the process without termination. A target then reads as
// hooked and an install reports OutOfMemory. The success arm requires a live ledger. Exit status is the oracle.
//
// The constructor arm grants the target map its storage and refuses the map constructor's own allocation, which the
// MSVC STL performs for an empty unordered_map. On an STL whose constructor allocates nothing the ledger comes up live,
// and the arm reports the skip code.

#include "DetourModKit/address.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"

#include "first_use_oom_poison.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <utility>

namespace
{
    constexpr std::string_view OOM_CASE{"oom"};
    constexpr std::string_view CONSTRUCTOR_OOM_CASE{"constructor-oom"};
    constexpr std::string_view SUCCESS_CASE{"success"};

    int fail(const char *what)
    {
        std::fprintf(stderr, "FAIL: %s\n", what);
        return 2;
    }

    // A hookable leaf on a private page: mov eax, 1; ret.
    class LeafPage
    {
    public:
        LeafPage() noexcept
        {
            m_base = ::VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (m_base != nullptr)
            {
                static constexpr unsigned char LEAF[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
                std::memset(m_base, 0xCC, 0x1000);
                std::memcpy(m_base, LEAF, sizeof(LEAF));
                ::FlushInstructionCache(::GetCurrentProcess(), m_base, 0x1000);
            }
        }

        ~LeafPage() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        LeafPage(const LeafPage &) = delete;
        LeafPage &operator=(const LeafPage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] DetourModKit::Address address() const noexcept { return DetourModKit::Address{m_base}; }

    private:
        void *m_base{nullptr};
    };

    int leaf_detour()
    {
        return 2;
    }

    DetourModKit::Result<DetourModKit::hook::Hook> install(const LeafPage &page)
    {
        return DetourModKit::hook::inline_at(
            DetourModKit::hook::InlineRequest{
                .name = "FirstUseLedger",
                .target = page.address(),
            },
            &leaf_detour
        );
    }

    int run_oom_case(long long allow)
    {
        LeafPage page;
        if (!page.ok())
        {
            return fail("VirtualAlloc of the leaf page");
        }

        dmk_first_use::arm(allow);
        const bool poisoned_hooked = DetourModKit::hook::is_target_hooked(page.address());
        dmk_first_use::disarm();
        if (!poisoned_hooked)
        {
            if (allow > 0)
            {
                // The ledger came up live: this STL's map constructor allocated nothing, so the arm has no subject.
                std::fprintf(stderr, "SKIP: the unordered_map constructor allocates nothing on this STL\n");
                return dmk_first_use::SKIP_RETURN_CODE;
            }
            return fail("the inert ledger reported a fresh target as unhooked");
        }
        if (!DetourModKit::hook::is_target_hooked(page.address()))
        {
            return fail("the inert ledger did not latch past the poisoned window");
        }

        DetourModKit::Result<DetourModKit::hook::Hook> installed = install(page);
        if (installed.has_value())
        {
            return fail("the inert ledger admitted an install");
        }
        if (installed.error().code != DetourModKit::ErrorCode::OutOfMemory)
        {
            std::fprintf(stderr, "FAIL: unexpected install code %s\n", installed.error().message().c_str());
            return 3;
        }
        return 0;
    }

    int run_success_case()
    {
        LeafPage page;
        if (!page.ok())
        {
            return fail("VirtualAlloc of the leaf page");
        }
        if (DetourModKit::hook::is_target_hooked(page.address()))
        {
            return fail("a live ledger reported a fresh target as hooked");
        }
        DetourModKit::Result<DetourModKit::hook::Hook> installed = install(page);
        if (!installed.has_value())
        {
            std::fprintf(stderr, "FAIL: install on a live ledger: %s\n", installed.error().message().c_str());
            return 4;
        }
        if (!DetourModKit::hook::is_target_hooked(page.address()))
        {
            return fail("a live ledger did not record the install");
        }
        {
            const DetourModKit::hook::Hook destroyed = std::move(*installed);
        }
        if (DetourModKit::hook::is_target_hooked(page.address()))
        {
            return fail("a live ledger did not release the destroyed hook");
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: hook_ledger_first_use_oom <oom|constructor-oom|success>\n");
        return 1;
    }

    const std::string_view selected_case{argv[1]};
    if (selected_case == SUCCESS_CASE)
    {
        return run_success_case();
    }
    if (dmk_first_use::debug_stl_proxies())
    {
        // The release-STL lane proves this contract on MSVC.
        return dmk_first_use::SKIP_RETURN_CODE;
    }
    if (selected_case == OOM_CASE)
    {
        return run_oom_case(0);
    }
    if (selected_case == CONSTRUCTOR_OOM_CASE)
    {
        return run_oom_case(1);
    }

    std::fprintf(stderr, "unknown hook ledger first-use case\n");
    return 1;
}
