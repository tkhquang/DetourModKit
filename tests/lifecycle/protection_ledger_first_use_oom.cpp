// Fresh-process proofs for the page-protection ledger accessor. The OOM arms require a first-use allocation failure
// to latch a null ledger, so every protection transaction fails closed for the process without termination. The
// success arm requires a live ledger. Exit status is the oracle.
//
// The constructor arm grants the ledger object its storage and refuses the constructor's own allocation, which the
// MSVC STL performs for an empty unordered_map. On an STL whose constructor allocates nothing the ledger comes up live,
// and the arm reports the skip code.

#include "DetourModKit/address.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"

#include "first_use_oom_poison.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>

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

    // An execute-read page: the guarded fast path of patch_code faults, so the patch takes the protection-changing
    // route through the ledger.
    class CodePage
    {
    public:
        CodePage() noexcept { m_base = ::VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ); }

        ~CodePage() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        CodePage(const CodePage &) = delete;
        CodePage &operator=(const CodePage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] DetourModKit::Address address() const noexcept { return DetourModKit::Address{m_base}; }
        [[nodiscard]] std::uint8_t first_byte() const noexcept { return *static_cast<const std::uint8_t *>(m_base); }

        [[nodiscard]] DWORD protection() const noexcept
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(m_base, &mbi, sizeof(mbi)) != sizeof(mbi))
            {
                return 0;
            }
            return mbi.Protect;
        }

    private:
        void *m_base{nullptr};
    };

    // The guarded engine installs on first use, so warm it before the poison is armed.
    bool warm_guarded_engine()
    {
        int probe = 7;
        const DetourModKit::Result<int> read = DetourModKit::memory::read<int>(DetourModKit::Address{&probe});
        return read.has_value() && *read == 7;
    }

    DetourModKit::Result<void> patch_one_byte(const CodePage &page)
    {
        const std::array<std::byte, 1> ret{std::byte{0xC3}};
        return DetourModKit::memory::patch_code(page.address(), ret);
    }

    int expect_refused_closed(const DetourModKit::Result<void> &patch, const CodePage &page, const char *stage)
    {
        if (patch.has_value())
        {
            std::fprintf(stderr, "FAIL: %s: the patch succeeded without a ledger\n", stage);
            return 2;
        }
        if (patch.error().code != DetourModKit::ErrorCode::ProtectionChangeFailed)
        {
            std::fprintf(stderr, "FAIL: %s: unexpected code %s\n", stage, patch.error().message().c_str());
            return 3;
        }
        if (patch.error().extra != ERROR_NOT_ENOUGH_MEMORY)
        {
            std::fprintf(
                stderr,
                "FAIL: %s: the refusal did not name the ledger (extra=%u)\n",
                stage,
                patch.error().extra
            );
            return 4;
        }
        if (page.first_byte() != 0)
        {
            std::fprintf(stderr, "FAIL: %s: a refused patch changed the target\n", stage);
            return 5;
        }
        if (page.protection() != PAGE_EXECUTE_READ)
        {
            std::fprintf(stderr, "FAIL: %s: a refused patch left the page at 0x%lx\n", stage, page.protection());
            return 6;
        }
        return 0;
    }

    int run_oom_case(long long allow)
    {
        CodePage page;
        if (!page.ok())
        {
            return fail("VirtualAlloc of the code page");
        }
        if (!warm_guarded_engine())
        {
            return fail("guarded read warm-up");
        }

        dmk_first_use::arm(allow);
        const DetourModKit::Result<void> first = patch_one_byte(page);
        dmk_first_use::disarm();
        if (const int code = expect_refused_closed(first, page, "poisoned first use"); code != 0)
        {
            return code;
        }

        const DetourModKit::Result<void> second = patch_one_byte(page);
        if (allow > 0 && second.has_value())
        {
            // The ledger came up live: this STL's map constructor allocated nothing, so the arm has no subject.
            std::fprintf(stderr, "SKIP: the unordered_map constructor allocates nothing on this STL\n");
            return dmk_first_use::SKIP_RETURN_CODE;
        }
        return expect_refused_closed(second, page, "latched second use");
    }

    int run_success_case()
    {
        CodePage page;
        if (!page.ok())
        {
            return fail("VirtualAlloc of the code page");
        }
        const DetourModKit::Result<void> patch = patch_one_byte(page);
        if (!patch.has_value())
        {
            std::fprintf(stderr, "FAIL: first use did not record protection: %s\n", patch.error().message().c_str());
            return 7;
        }
        if (page.first_byte() != 0xC3)
        {
            return fail("the patch did not land");
        }
        if (page.protection() != PAGE_EXECUTE_READ)
        {
            return fail("the patch did not restore the original protection");
        }
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: protection_ledger_first_use_oom <oom|constructor-oom|success>\n");
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

    std::fprintf(stderr, "unknown protection ledger first-use case\n");
    return 1;
}
