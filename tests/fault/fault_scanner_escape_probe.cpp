// Exact-span containment proof for the two scanner fault guards. The outside modes raise one access violation at an
// address the declared span does not cover and require escape. The narrow-window inside mode reprotects an address only
// after the production gate accepted its window, then requires that fault to be contained.
//
// The guards exist to absorb a concurrent decommit or reprotect of the bytes the sweep is reading. A fault anywhere
// else is a different event (an unrelated defect inside the same frame), and swallowing it would convert a crash
// the host must see into a silently skipped region. That distinction is invisible from outside the guard: both a
// screened and an unscreened filter return "the sweep was incomplete", so the only way to observe it is to raise the
// fault from inside the guarded frame and watch where it goes. The DMK_ENABLE_TEST_SEAMS-gated
// internal/scan_fault_seam.hpp slot is that injection point.
//
// This needs its own process, and its own exit-status oracle, for two reasons: an escaping access violation is not
// survivable inside a shared GoogleTest process, and the verdict is WHICH frame claimed the exception, which no
// in-process assertion can observe. The mechanism differs by toolchain and so does the oracle. On MSVC the escaping
// exception unwinds to this host's own __except, whose filter accepts only the exact injected address. On MinGW there
// is no frame-based SEH: DMK's vectored handler declines an address outside its armed range, nothing else claims the
// fault, and the top-level filter this host installs is what proves it got all the way out.

#include "DetourModKit/scan.hpp"

#include "internal/scan_fault_seam.hpp"

#include "fault_injection.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

using namespace DetourModKit;

namespace
{
    // The fault reached this host: the guard screened the faulting address and declined it.
    constexpr int EXIT_ESCAPED = 0;
    // The guard claimed a fault outside its declared span. This is the defect the proof exists to catch.
    constexpr int EXIT_SWALLOWED = 1;
    // A fixture could not be built, so the run asserted nothing about the guard.
    constexpr int EXIT_SETUP_FAILED = 2;
    // Unknown or missing scenario token.
    constexpr int EXIT_USAGE = 3;

    constexpr DWORD ACCESS_VIOLATION_CODE = 0xC0000005ul;

    // Published before the scan so the escape oracle can require the exact injected address rather than accepting any
    // access violation, which a genuine defect elsewhere in the sweep would also produce.
    std::uintptr_t s_expected_fault_address = 0;
    int s_escaped_exit_code = EXIT_ESCAPED;
    std::atomic<bool> s_reprotect_succeeded{false};
    DWORD s_previous_protection = 0;

    struct RegionScanContext
    {
        std::uintptr_t scope_base;
        std::size_t scope_size;
    };

    struct XrefScanContext
    {
        std::uintptr_t scope_base;
        std::size_t scope_size;
        const char *literal;
    };

    // Page-gated region sweep. Pages::Executable keeps the scope authoritative without an exclusion span, and the
    // pattern is irrelevant: the seam fires as the guarded body starts, before any match can be reported.
    void region_scan_body(void *raw) noexcept
    {
        const auto *const ctx = static_cast<const RegionScanContext *>(raw);
        (void)scan::scan(
            scan::Pattern::literal("DE AD C0 DE"),
            Region{Address{ctx->scope_base}, ctx->scope_size},
            1,
            scan::Pages::Executable
        );
    }

    // String-xref phase 2. Phase 1 must locate the planted literal first, so the narrow window sweep (the guarded
    // body carrying the second seam) is reached only on the success path.
    void xref_scan_body(void *raw) noexcept
    {
        const auto *const ctx = static_cast<const XrefScanContext *>(raw);
        try
        {
            const scan::StringRefQuery query{
                .text = std::string_view{ctx->literal},
            };
            (void)scan::find_string_xref(query, Region{Address{ctx->scope_base}, ctx->scope_size});
        }
        catch (...)
        {
            // find_string_xref may allocate. An allocation failure is a setup problem, not a verdict; the caller's
            // EXIT_SWALLOWED result then reports that no fault escaped, which is the honest outcome for a scan that
            // never completed its sweep.
        }
    }

    // Called from the narrow body after collect_executable_windows accepted the page. Reprotecting any earlier would
    // prevent phase 1 from finding the literal and would never reach the filter under proof.
    void reprotect_window_address(std::uintptr_t address) noexcept
    {
        DWORD previous = 0;
        const bool changed = ::VirtualProtect(reinterpret_cast<void *>(address), 1, PAGE_NOACCESS, &previous) != FALSE;
        if (changed)
        {
            s_previous_protection = previous;
        }
        s_reprotect_succeeded.store(changed, std::memory_order_release);
    }

#if defined(_MSC_VER)
    // Accept only the injected address. An access violation anywhere else did not come from the seam, so it continues
    // the search and terminates this host, which fails the proof rather than passing it for the wrong reason.
    long escape_filter(::_EXCEPTION_POINTERS *info) noexcept
    {
        const ::EXCEPTION_RECORD *const record = info->ExceptionRecord;
        if (record->ExceptionCode != ACCESS_VIOLATION_CODE || record->NumberParameters < 2)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (static_cast<std::uintptr_t>(record->ExceptionInformation[1]) != s_expected_fault_address)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        return EXCEPTION_EXECUTE_HANDLER;
    }

    // Only POD locals here: MSVC rejects a __try in a function that needs object unwinding.
    int run_and_classify(void (*body)(void *) noexcept, void *ctx) noexcept
    {
        __try
        {
            body(ctx);
            return EXIT_SWALLOWED;
        }
        __except (escape_filter(GetExceptionInformation()))
        {
            return EXIT_ESCAPED;
        }
    }
#else
    // MinGW has no frame-based SEH, so the escape is observed at the top-level filter instead. Terminating from inside
    // it is what makes the exit status deterministic; returning would hand the fault to WER and produce a crash status
    // that cannot be distinguished from an unrelated one.
    long __stdcall escaped_unhandled_filter(::_EXCEPTION_POINTERS *info) noexcept
    {
        const ::EXCEPTION_RECORD *const record = info->ExceptionRecord;
        if (record->ExceptionCode == ACCESS_VIOLATION_CODE && record->NumberParameters >= 2 &&
            static_cast<std::uintptr_t>(record->ExceptionInformation[1]) == s_expected_fault_address)
        {
            ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(s_escaped_exit_code));
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    int run_and_classify(void (*body)(void *) noexcept, void *ctx) noexcept
    {
        ::SetUnhandledExceptionFilter(&escaped_unhandled_filter);
        body(ctx);
        return EXIT_SWALLOWED;
    }
#endif

    // A still-armed slot means the guarded body never ran, so no fault was injected and "nothing escaped" describes
    // the fixture rather than the guard. That must not read as either verdict.
    int reconcile(int outcome, const std::atomic<std::uintptr_t> &slot, const char *what) noexcept
    {
        if (outcome == EXIT_SWALLOWED && slot.load(std::memory_order_acquire) != 0)
        {
            std::fprintf(stderr, "the %s never reached its guarded body; nothing was injected\n", what);
            return EXIT_SETUP_FAILED;
        }
        return outcome;
    }

    int reconcile_contained(int outcome, std::uintptr_t address) noexcept
    {
        const bool prepared = s_reprotect_succeeded.load(std::memory_order_acquire);
        bool restored = false;
        if (prepared)
        {
            DWORD ignored = 0;
            restored = ::VirtualProtect(reinterpret_cast<void *>(address), 1, s_previous_protection, &ignored) != FALSE;
        }

        if (detail::g_scan_window_fault_for_test.load(std::memory_order_acquire) != 0 ||
            detail::g_scan_window_fault_preparation_for_test.load(std::memory_order_acquire) != nullptr || !prepared ||
            !restored)
        {
            std::fprintf(stderr, "the narrow-window in-span fixture did not arm, fire, and restore cleanly\n");
            return EXIT_SETUP_FAILED;
        }
        if (outcome == EXIT_ESCAPED)
        {
            std::fprintf(stderr, "the narrow-window guard did not contain its in-span fault\n");
            return EXIT_SWALLOWED;
        }
        return EXIT_ESCAPED;
    }

    int run_region_scenario()
    {
        dmk_test::ExecutablePage image;
        if (!image.ok())
        {
            return EXIT_SETUP_FAILED;
        }
        constexpr std::array<std::byte, 4> needle{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xC0}, std::byte{0xDE}};
        image.write(0x40, needle.data(), needle.size());

        // Leaked on purpose (see NoAccessPage): a released VA can be recycled, and a fault expected at a recycled
        // address would land on live memory and turn this proof green having asserted nothing.
        dmk_test::NoAccessPage outside;
        if (!outside.ok())
        {
            return EXIT_SETUP_FAILED;
        }

        s_expected_fault_address = outside.addr();
        detail::g_scan_region_fault_for_test.store(outside.addr(), std::memory_order_release);

        RegionScanContext ctx{image.addr(), dmk_test::PAGE_BYTES};
        const int outcome = run_and_classify(&region_scan_body, &ctx);
        return reconcile(outcome, detail::g_scan_region_fault_for_test, "region sweep");
    }

    int run_xref_scenario()
    {
        dmk_test::ExecutablePage image;
        if (!image.ok())
        {
            return EXIT_SETUP_FAILED;
        }
        // The literal lives in the image, and the query's own copy lives in this host's read-only data outside the
        // scope, so phase 1 finds exactly one occurrence and phase 2 runs.
        constexpr const char *literal = "DmkScannerEscapeProbeAnchor";
        constexpr std::size_t literal_offset = 0x200;
        image.write(literal_offset, literal, std::strlen(literal) + 1);
        image.plant_rip_lea(0x20, literal_offset);

        dmk_test::NoAccessPage outside;
        if (!outside.ok())
        {
            return EXIT_SETUP_FAILED;
        }

        s_expected_fault_address = outside.addr();
        detail::g_scan_window_fault_for_test.store(outside.addr(), std::memory_order_release);

        XrefScanContext ctx{image.addr(), dmk_test::PAGE_BYTES, literal};
        const int outcome = run_and_classify(&xref_scan_body, &ctx);
        return reconcile(outcome, detail::g_scan_window_fault_for_test, "narrow window sweep");
    }

    int run_xref_in_span_scenario()
    {
        dmk_test::ExecutablePage image;
        if (!image.ok())
        {
            return EXIT_SETUP_FAILED;
        }
        constexpr const char *literal = "DmkScannerContainedProbeAnchor";
        constexpr std::size_t literal_offset = 0x200;
        image.write(literal_offset, literal, std::strlen(literal) + 1);
        image.plant_rip_lea(0x20, literal_offset);

        const std::uintptr_t fault_address = image.addr() + 0x100;
        s_expected_fault_address = fault_address;
        s_escaped_exit_code = EXIT_SWALLOWED;
        s_reprotect_succeeded.store(false, std::memory_order_release);
        detail::g_scan_window_fault_preparation_for_test.store(&reprotect_window_address, std::memory_order_release);
        detail::g_scan_window_fault_for_test.store(fault_address, std::memory_order_release);

        XrefScanContext ctx{image.addr(), dmk_test::PAGE_BYTES, literal};
        const int outcome = run_and_classify(&xref_scan_body, &ctx);
        return reconcile_contained(outcome, fault_address);
    }
} // namespace

int main(int argc, char **argv)
{
    const std::string_view scenario = (argc > 1) ? std::string_view{argv[1]} : std::string_view{};
    if (scenario == "region")
    {
        return run_region_scenario();
    }
    if (scenario == "xref")
    {
        return run_xref_scenario();
    }
    if (scenario == "xref-in-span")
    {
        return run_xref_in_span_scenario();
    }
    std::fprintf(stderr, "usage: fault_scanner_escape_probe <region|xref|xref-in-span>\n");
    return EXIT_USAGE;
}
