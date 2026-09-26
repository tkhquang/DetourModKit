// Fresh-process proofs for the backend allocator hold. The OOM arms require a first-use allocation failure inside the
// backend to latch an empty hold. Every install then reports AllocatorNotAvailable for the process without termination.
// The success arm requires a live allocator. Exit status is the oracle.
//
// The backend allocates its allocator object and then its shared control block. The oom arm refuses the first, the
// constructor arm refuses the second. Both throws must stay inside the noexcept accessor.

#include "DetourModKit/address.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"

#include "internal/hook_backend.hpp"

#include "first_use_oom_poison.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

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
                .name = "FirstUseAllocator",
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
        const bool poisoned_hold = static_cast<bool>(DetourModKit::hook::backend_allocator());
        dmk_first_use::disarm();
        if (poisoned_hold)
        {
            return fail("first use published an allocator although its allocation was refused");
        }
        if (DetourModKit::hook::backend_allocator())
        {
            return fail("the empty hold did not latch past the poisoned window");
        }

        for (int attempt = 0; attempt < 2; ++attempt)
        {
            DetourModKit::Result<DetourModKit::hook::Hook> installed = install(page);
            if (installed.has_value())
            {
                return fail("an install succeeded without a backend allocator");
            }
            if (installed.error().code != DetourModKit::ErrorCode::AllocatorNotAvailable)
            {
                std::fprintf(stderr, "FAIL: unexpected install code %s\n", installed.error().message().c_str());
                return 3;
            }
        }
        if (DetourModKit::hook::is_target_hooked(page.address()))
        {
            return fail("a refused install left a ledger record");
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
        if (!DetourModKit::hook::backend_allocator())
        {
            return fail("first use published no allocator");
        }
        DetourModKit::Result<DetourModKit::hook::Hook> installed = install(page);
        if (!installed.has_value())
        {
            std::fprintf(stderr, "FAIL: install with a live allocator: %s\n", installed.error().message().c_str());
            return 4;
        }
        if (!installed->enable().has_value() || !installed->disable().has_value())
        {
            return fail("toggle through the live allocator");
        }
        {
            const DetourModKit::hook::Hook destroyed = std::move(*installed);
        }
        if (DetourModKit::hook::is_target_hooked(page.address()))
        {
            return fail("a destroyed hook stayed recorded");
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: backend_allocator_first_use_oom <oom|constructor-oom|success>\n");
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

    std::fprintf(stderr, "unknown backend allocator first-use case\n");
    return 1;
}
