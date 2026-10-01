#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/memory.hpp"

#include "internal/hook_fault_boundary.hpp"
#include "internal/hook_publication.hpp"
#include "internal/hook_ledger.hpp"

#include "fixtures/proof_section.hpp"
#include "fixtures/scratch_page.hpp"
#include "test_alloc_probe.hpp"
#include "fixtures/hook_fixture.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace dmk_test::hook_fixture;

// The hostile targets exercise both MinGW VEH and MSVC SEH containment through typed errors.
namespace
{
    // The target starts on a committed executable page and crosses into an adjacent uncommitted page.
    class SplitExecutableRegion
    {
    public:
        SplitExecutableRegion() noexcept
        {
            m_base = VirtualAlloc(nullptr, REGION_SIZE, MEM_RESERVE, PAGE_NOACCESS);
            if (m_base == nullptr)
            {
                return;
            }
            if (VirtualAlloc(m_base, dmk_test::ScratchPage::PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE) == nullptr)
            {
                (void)VirtualFree(m_base, 0, MEM_RELEASE);
                m_base = nullptr;
                return;
            }
            std::memset(m_base, 0x90, dmk_test::ScratchPage::PAGE_SIZE);
        }

        ~SplitExecutableRegion() noexcept
        {
            if (m_base != nullptr)
            {
                (void)VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        SplitExecutableRegion(const SplitExecutableRegion &) = delete;
        SplitExecutableRegion &operator=(const SplitExecutableRegion &) = delete;
        SplitExecutableRegion(SplitExecutableRegion &&) = delete;
        SplitExecutableRegion &operator=(SplitExecutableRegion &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        [[nodiscard]] std::uintptr_t committed_end() const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base) + dmk_test::ScratchPage::PAGE_SIZE;
        }

    private:
        static constexpr std::size_t REGION_SIZE = dmk_test::ScratchPage::PAGE_SIZE * 2;

        void *m_base{nullptr};
    };

    // One allocation guarantees adjacency. Separate ScratchPages do not guarantee a valid instruction across the
    // boundary.
    class AdjacentExecutablePages
    {
    public:
        AdjacentExecutablePages() noexcept
        {
            m_base = VirtualAlloc(nullptr, REGION_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (m_base != nullptr)
            {
                std::memset(m_base, 0xCC, REGION_SIZE);
            }
        }

        ~AdjacentExecutablePages() noexcept
        {
            if (m_base != nullptr)
            {
                (void)VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        AdjacentExecutablePages(const AdjacentExecutablePages &) = delete;
        AdjacentExecutablePages &operator=(const AdjacentExecutablePages &) = delete;
        AdjacentExecutablePages(AdjacentExecutablePages &&) = delete;
        AdjacentExecutablePages &operator=(AdjacentExecutablePages &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        /// The first byte of the second page: an instruction planted before it and long enough spans the boundary.
        [[nodiscard]] std::uintptr_t boundary() const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base) + dmk_test::ScratchPage::PAGE_SIZE;
        }

        void put(std::uintptr_t address, std::initializer_list<std::uint8_t> bytes) noexcept
        {
            auto *destination = reinterpret_cast<std::uint8_t *>(address);
            std::size_t i = 0;
            for (const std::uint8_t b : bytes)
            {
                destination[i++] = b;
            }
        }

    private:
        static constexpr std::size_t REGION_SIZE = dmk_test::ScratchPage::PAGE_SIZE * 2;

        void *m_base{nullptr};
    };

    class RuntimeFunctionRegistration
    {
    public:
        RuntimeFunctionRegistration(std::uintptr_t image_base, DWORD begin, DWORD end) noexcept
        {
            m_record.BeginAddress = begin;
            m_record.EndAddress = end;
            m_record.UnwindData = 0;
            m_registered = RtlAddFunctionTable(&m_record, 1, image_base) != FALSE;
        }

        ~RuntimeFunctionRegistration() noexcept
        {
            if (m_registered)
            {
                (void)RtlDeleteFunctionTable(&m_record);
            }
        }

        RuntimeFunctionRegistration(const RuntimeFunctionRegistration &) = delete;
        RuntimeFunctionRegistration &operator=(const RuntimeFunctionRegistration &) = delete;
        RuntimeFunctionRegistration(RuntimeFunctionRegistration &&) = delete;
        RuntimeFunctionRegistration &operator=(RuntimeFunctionRegistration &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_registered; }

    private:
        RUNTIME_FUNCTION m_record{};
        bool m_registered{false};
    };
} // namespace

// An address in reserved-but-uncommitted memory is not executable committed memory.
TEST(InlineHookFaultProof, ReservedTargetReturnsTypedFailure)
{
    void *reserved = VirtualAlloc(nullptr, 0x1000, MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(reserved, nullptr);
    Result<Hook> r = try_install_at(reinterpret_cast<std::uintptr_t>(reserved), "ReservedTarget");
    EXPECT_FALSE(r.has_value()) << "a reserved (uncommitted) target must not be hooked";
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
    VirtualFree(reserved, 0, MEM_RELEASE);
}

// A freed (unmapped) address has no region at all.
TEST(InlineHookFaultProof, UnmappedTargetReturnsTypedFailure)
{
    void *page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page, nullptr);
    const auto address = reinterpret_cast<std::uintptr_t>(page);
    ASSERT_NE(VirtualFree(page, 0, MEM_RELEASE), 0);

    Result<Hook> r = try_install_at(address, "UnmappedTarget");
    EXPECT_FALSE(r.has_value()) << "an unmapped target must not be hooked";
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// PAGE_NOACCESS is committed but neither readable nor executable.
TEST(InlineHookFaultProof, PageNoAccessReturnsTypedFailure)
{
    void *page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(page, nullptr);
    Result<Hook> r = try_install_at(reinterpret_cast<std::uintptr_t>(page), "NoAccessTarget");
    EXPECT_FALSE(r.has_value()) << "a PAGE_NOACCESS target must not be hooked";
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
    VirtualFree(page, 0, MEM_RELEASE);
}

// The readable data page distinguishes execute permission from readability.
TEST(InlineHookFaultProof, CommittedNonExecutableReturnsTypedFailure)
{
    void *page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);
    std::memset(page, 0x90, 0x1000);
    Result<Hook> r = try_install_at(reinterpret_cast<std::uintptr_t>(page), "NonExecutableTarget");
    EXPECT_FALSE(r.has_value()) << "a committed non-executable target must not be hooked";
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
    VirtualFree(page, 0, MEM_RELEASE);
}

// PAGE_GUARD reports execute permission but faults on access. The guarded probe must detect that fault before backend
// use.
TEST(InlineHookFaultProof, PageGuardReturnsTypedFailure)
{
    void *page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page, nullptr);
    std::memset(page, 0x90, 0x1000);
    DWORD old = 0;
    ASSERT_NE(VirtualProtect(page, 0x1000, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old), 0);

    Result<Hook> r = try_install_at(reinterpret_cast<std::uintptr_t>(page), "GuardPageTarget");
    ASSERT_FALSE(r.has_value()) << "a PAGE_GUARD target must not be hooked";
    // The protection check sees PAGE_GUARD before any byte access. This preserves the host fence on a refused target.
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
    VirtualFree(page, 0, MEM_RELEASE);
}

// A target whose required patch crosses into an uncommitted page must be refused before backend decode.
TEST(InlineHookFaultProof, FinalBytePageSplitReturnsTypedFailure)
{
    SplitExecutableRegion region;
    ASSERT_TRUE(region.ok());

    Result<Hook> r = try_install_at(region.committed_end() - 4, "PageSplitTarget");
    EXPECT_FALSE(r.has_value()) << "a target whose decode window crosses into uncommitted memory must not be hooked";
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// Both executable pages stay valid. The mov eax, imm32 spans the boundary, so this control separates ordinary
// cross-page relocation from an unreadable window.
TEST(InlineHookFaultProof, InstructionStraddlingTwoValidPagesIsHooked)
{
    AdjacentExecutablePages region;
    ASSERT_TRUE(region.ok());

    constexpr std::size_t mov_eax_imm32_length = 5;
    const std::uintptr_t entry = region.boundary() - 3;
    region.put(
        entry,
        {0xB8,
         static_cast<std::uint8_t>(LEADING_CALL_CALLEE_VALUE & 0xFF),
         static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 8) & 0xFF),
         static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 16) & 0xFF),
         static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 24) & 0xFF),
         0xC3}
    );
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(entry), 16);

    // The instruction must begin on the first page and end on the second. The premise assertion prevents a vacuous
    // boundary control.
    ASSERT_LT(entry, region.boundary());
    ASSERT_GT(entry + mov_eax_imm32_length, region.boundary());

    auto target = reinterpret_cast<int (*)()>(entry);
    ASSERT_EQ(target(), LEADING_CALL_CALLEE_VALUE) << "control: the straddling function runs before any hook";

    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "StraddlingInstruction",
            .target = Address{entry},
        },
        reinterpret_cast<void (*)()>(&leading_call_detour)
    );
    ASSERT_TRUE(r.has_value()) << "an instruction spanning two valid pages must not be refused: "
                               << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    EXPECT_EQ(target(), LEADING_CALL_DETOUR_VALUE);

    // The stolen instruction crossed the boundary intact: the trampoline still yields the original value.
    auto original = h.original<int (*)()>();
    ASSERT_NE(original, nullptr);
    EXPECT_EQ(original(), LEADING_CALL_CALLEE_VALUE);
}

// The full backend window passes the gate, and a window four bytes shorter fails. Installation can fail later if
// trampoline allocation fails.
TEST(InlineHookFaultProof, WindowBoundaryMatchesBackendSteal)
{
    SplitExecutableRegion region;
    ASSERT_TRUE(region.ok());
    const std::uintptr_t committed_end = region.committed_end();

    constexpr std::size_t window = DetourModKit::detail::BACKEND_MAX_STEAL_WINDOW;

    // Exactly the window fits: whatever happens next is the backend's decision, not a window refusal.
    Result<Hook> fits = try_install_at(committed_end - window, "WindowFits");
    if (!fits.has_value())
    {
        EXPECT_NE(fits.error().code, ErrorCode::TargetPrologueUnsafe)
            << "a target with a full steal window of committed executable bytes must not be refused by the gate";
    }

    // One byte short of the window: the gate must refuse.
    Result<Hook> shy = try_install_at(committed_end - window + 1, "WindowShort");
    ASSERT_FALSE(shy.has_value()) << "a target whose window runs past committed memory must be refused";
    EXPECT_EQ(shy.error().code, ErrorCode::TargetPrologueUnsafe);
}

// The registered function bound is authoritative. It must fit the larger patch form because backend selection occurs
// after validation.
TEST(InlineHookFaultProof, ReliableFunctionBoundOverrunReturnsTypedFailure)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0, {0x90, 0x90, 0x90, 0x90, 0xC3});

    // The near jump fits, but the fallback patch exceeds the bound by one byte.
    constexpr DWORD too_short = static_cast<DWORD>(DetourModKit::detail::BACKEND_FALLBACK_MIN_PATCH - 1);
    {
        RuntimeFunctionRegistration registration{page.addr(), 0, too_short};
        ASSERT_TRUE(registration.ok());

        const DetourModKit::detail::TargetWindowResult verdict =
            DetourModKit::detail::validate_backend_steal_window(page.addr());
        ASSERT_EQ(verdict.verdict, DetourModKit::detail::TargetWindowVerdict::BoundOverrun)
            << "a function too short for the fallback patch must be refused, not left to the form the backend picks";
        EXPECT_EQ(verdict.detail, page.addr(too_short));

        Result<Hook> r = try_install_at(page.addr(), "FunctionBoundOverrun");
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
    }

    // Exactly the fallback form's patch: long enough for either form, so the bound must not refuse it.
    {
        RuntimeFunctionRegistration registration{
            page.addr(),
            0,
            static_cast<DWORD>(DetourModKit::detail::BACKEND_FALLBACK_MIN_PATCH)
        };
        ASSERT_TRUE(registration.ok());

        const DetourModKit::detail::TargetWindowResult verdict =
            DetourModKit::detail::validate_backend_steal_window(page.addr());
        EXPECT_NE(verdict.verdict, DetourModKit::detail::TargetWindowVerdict::BoundOverrun)
            << "a function long enough for either patch form must not be refused on its bound";
    }
}

// The leaf target has no .pdata. This control separates absent metadata from an unsafe authoritative bound.
TEST(InlineHookFaultProof, LeafCodeWithoutPdataIsNotRejected)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf_function(page);

    Result<Hook> r = try_install_at(page.addr(0), "LeafNoPdata");
    ASSERT_TRUE(r.has_value()) << "code without unwind metadata must not be refused: " << r.error().message();
    EXPECT_TRUE(static_cast<bool>(*r));
}

// The unrelated PAGE_NOACCESS read still reports its own failure after hook installation. The hook gate cannot install
// a catch-all handler.
TEST(InlineHookFaultProof, UnrelatedFaultIsNotSwallowedByTheHookGate)
{
    void *unrelated = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(unrelated, nullptr);

    const Address probe{reinterpret_cast<std::uintptr_t>(unrelated)};
    const Result<std::uint64_t> read = memory::read<std::uint64_t>(probe);
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, ErrorCode::ReadFaulted);

    // A normal install still succeeds afterwards: the guard is scoped, not sticky.
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "AfterUnrelatedFault",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    EXPECT_TRUE(r.has_value()) << "an unrelated contained fault must not disturb later hook installs";
    VirtualFree(unrelated, 0, MEM_RELEASE);
}

// The recycled address now belongs to a different allocation. A trap from the old patch transaction must not consume
// its fault.
TEST(InlineHookFaultProof, UnrelatedFaultAtRecycledHookedPageSurfaces)
{
    void *base = nullptr;
    {
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf_function(page);
        base = page.base();

        // The hook ends before page release. Its prologue restore and trap retirement therefore occur while the page
        // stays mapped.
        Result<Hook> installed = try_install_at(page.addr(0), "RecycledTrapPage");
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
    }

    const auto release_page = [](void *page) noexcept
    {
        if (page != nullptr)
        {
            (void)VirtualFree(page, 0, MEM_RELEASE);
        }
    };
    void *const recycled =
        VirtualAlloc(base, dmk_test::ScratchPage::PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    const std::unique_ptr<void, decltype(release_page)> recycled_guard{recycled, release_page};
    ASSERT_EQ(recycled_guard.get(), base) << "the proof requires exact virtual-address reuse";

    const Result<std::uint8_t> read =
        memory::read<std::uint8_t>(Address{reinterpret_cast<std::uintptr_t>(recycled_guard.get())});
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, ErrorCode::ReadFaulted);
}

// A backend enable() that cannot reach its target must not publish Active. Decommitting the target (rather than
// releasing it) keeps the address reserved, so the fixture still owns the range and no other allocation can claim it.
TEST(InlineHookFaultProof, EnableFailureIsReported)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf_function(page);

    Result<Hook> installed = try_install_at(page.addr(0), "EnableFailure");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_TRUE(hook.enable().has_value());
    ASSERT_TRUE(hook.disable().has_value());

    ASSERT_NE(VirtualFree(page.base(), dmk_test::ScratchPage::PAGE_SIZE, MEM_DECOMMIT), 0);
    const Result<void> enabled = hook.enable();
    ASSERT_FALSE(enabled.has_value());
    EXPECT_EQ(enabled.error().code, ErrorCode::EnableFailed);
    EXPECT_FALSE(hook.is_enabled());
}

// The mirror of EnableFailureIsReported: a disable() whose restore cannot land keeps reporting the hook as enabled
// rather than claiming a disarm that never happened.
TEST(InlineHookFaultProof, DisableFailureIsReported)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf_function(page);

    Result<Hook> installed = try_install_at(page.addr(0), "DisableFailure");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_TRUE(hook.enable().has_value());

    ASSERT_NE(VirtualFree(page.base(), dmk_test::ScratchPage::PAGE_SIZE, MEM_DECOMMIT), 0);
    const Result<void> disabled = hook.disable();
    ASSERT_FALSE(disabled.has_value());
    EXPECT_EQ(disabled.error().code, ErrorCode::DisableFailed);
    EXPECT_TRUE(hook.is_enabled());
}

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    extern bool (*g_hook_teardown_restore_override)();

    extern void (*g_vmt_before_capture_probe)() noexcept;
    extern void (*g_vmt_before_backend_clone_probe)() noexcept;
    extern void (*g_vmt_before_publish_probe)(void *) noexcept;
#endif
} // namespace DetourModKit::detail

namespace
{
    /** @brief Models a reported backend disable failure that leaves the target patched. */
    bool reject_teardown_restore()
    {
        return false;
    }

    /// Models a backend synchronization failure before disable can alter the target.
    bool throw_teardown_restore_failure()
    {
        throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur));
    }

    class HookTeardownRestoreOverrideScope
    {
    public:
        explicit HookTeardownRestoreOverrideScope(bool (*override_fn)()) noexcept
        {
            DetourModKit::detail::g_hook_teardown_restore_override = override_fn;
        }
        ~HookTeardownRestoreOverrideScope() noexcept
        {
            DetourModKit::detail::g_hook_teardown_restore_override = nullptr;
        }
        HookTeardownRestoreOverrideScope(const HookTeardownRestoreOverrideScope &) = delete;
        HookTeardownRestoreOverrideScope &operator=(const HookTeardownRestoreOverrideScope &) = delete;
        HookTeardownRestoreOverrideScope(HookTeardownRestoreOverrideScope &&) = delete;
        HookTeardownRestoreOverrideScope &operator=(HookTeardownRestoreOverrideScope &&) = delete;
    };

#if defined(DMK_ENABLE_TEST_SEAMS)
    constexpr std::size_t VMT_PUBLISH_RACE_PAGE_BYTES = 0x1000;
#if defined(_MSC_VER)
    constexpr std::size_t TEST_VMT_HEADER_WORDS = 1;
#else
    constexpr std::size_t TEST_VMT_HEADER_WORDS = 2;
#endif
    // A vptr no pre-flight in this suite can have captured, so a publish that writes despite it is detectable.
    constexpr std::uintptr_t VMT_PUBLISH_DISPLACED_VPTR = 0xD15D1CED;

    // The seam invalidates the captured object word before publication. Each state isolates a fault, compare-exchange
    // mismatch, or protection refusal.
    enum class VmtPublishRace
    {
        Unmap,
        Displace,
        ReadOnly
    };

    void *s_vmt_publish_race_object = nullptr;
    VmtPublishRace s_vmt_publish_race = VmtPublishRace::Unmap;

    void invalidate_vmt_object_before_publish(void *object) noexcept
    {
        if (object != s_vmt_publish_race_object)
        {
            return;
        }
        switch (s_vmt_publish_race)
        {
        case VmtPublishRace::Unmap:
            (void)::VirtualFree(object, 0, MEM_RELEASE);
            return;
        case VmtPublishRace::Displace:
            // The word stays readable and writable but names a different vptr. Publication must preserve the original
            // that the object actually held.
            *static_cast<std::uintptr_t *>(object) = VMT_PUBLISH_DISPLACED_VPTR;
            return;
        case VmtPublishRace::ReadOnly:
        {
            DWORD previous = 0;
            (void)::VirtualProtect(object, VMT_PUBLISH_RACE_PAGE_BYTES, PAGE_READONLY, &previous);
            return;
        }
        }
    }

    void **s_vmt_capture_shrink_slot = nullptr;

    void shrink_vmt_before_capture() noexcept
    {
        if (s_vmt_capture_shrink_slot != nullptr)
        {
            // A non-executable word ends the run the backend clones, so the captured table is shorter than the one
            // the pre-count walked.
            *s_vmt_capture_shrink_slot = nullptr;
        }
    }

    // Shrinks the live vtable in the window between vmt_for's pre-count and its guarded capture.
    class VmtCaptureShrinkScope
    {
    public:
        explicit VmtCaptureShrinkScope(void **slot) noexcept
        {
            s_vmt_capture_shrink_slot = slot;
            DetourModKit::detail::g_vmt_before_capture_probe = &shrink_vmt_before_capture;
        }

        ~VmtCaptureShrinkScope() noexcept
        {
            DetourModKit::detail::g_vmt_before_capture_probe = nullptr;
            s_vmt_capture_shrink_slot = nullptr;
        }

        VmtCaptureShrinkScope(const VmtCaptureShrinkScope &) = delete;
        VmtCaptureShrinkScope &operator=(const VmtCaptureShrinkScope &) = delete;
    };

    void *s_vmt_backend_count_race_page = nullptr;
    DWORD s_vmt_backend_count_previous_protection = 0;
    bool s_vmt_backend_count_probe_succeeded = false;

    void remove_execute_before_backend_clone() noexcept
    {
        DWORD previous = 0;
        s_vmt_backend_count_probe_succeeded =
            s_vmt_backend_count_race_page != nullptr &&
            ::VirtualProtect(s_vmt_backend_count_race_page, VMT_PUBLISH_RACE_PAGE_BYTES, PAGE_READWRITE, &previous) !=
                FALSE;
        if (s_vmt_backend_count_probe_succeeded)
        {
            s_vmt_backend_count_previous_protection = previous;
        }
    }

    // Makes one captured slot non-executable only while SafetyHook sizes the detached clone.
    class VmtBackendCountRaceScope
    {
    public:
        explicit VmtBackendCountRaceScope(void *page) noexcept
        {
            s_vmt_backend_count_race_page = page;
            s_vmt_backend_count_previous_protection = 0;
            s_vmt_backend_count_probe_succeeded = false;
            DetourModKit::detail::g_vmt_before_backend_clone_probe = &remove_execute_before_backend_clone;
        }

        ~VmtBackendCountRaceScope() noexcept
        {
            DetourModKit::detail::g_vmt_before_backend_clone_probe = nullptr;
            if (s_vmt_backend_count_probe_succeeded)
            {
                DWORD ignored = 0;
                (void)::VirtualProtect(
                    s_vmt_backend_count_race_page,
                    VMT_PUBLISH_RACE_PAGE_BYTES,
                    s_vmt_backend_count_previous_protection,
                    &ignored
                );
            }
            s_vmt_backend_count_race_page = nullptr;
        }

        [[nodiscard]] bool succeeded() const noexcept { return s_vmt_backend_count_probe_succeeded; }

        VmtBackendCountRaceScope(const VmtBackendCountRaceScope &) = delete;
        VmtBackendCountRaceScope &operator=(const VmtBackendCountRaceScope &) = delete;
    };

    class VmtPublishRaceScope
    {
    public:
        VmtPublishRaceScope(void *object, VmtPublishRace race) noexcept
        {
            s_vmt_publish_race_object = object;
            s_vmt_publish_race = race;
            DetourModKit::detail::g_vmt_before_publish_probe = &invalidate_vmt_object_before_publish;
        }

        ~VmtPublishRaceScope() noexcept
        {
            DetourModKit::detail::g_vmt_before_publish_probe = nullptr;
            s_vmt_publish_race_object = nullptr;
        }

        VmtPublishRaceScope(const VmtPublishRaceScope &) = delete;
        VmtPublishRaceScope &operator=(const VmtPublishRaceScope &) = delete;
    };
#endif
} // namespace

namespace
{
    // Each target stays patched for the process lifetime and needs a unique entry. Distinct detour bodies prevent MSVC
    // /OPT:ICF folding.
    DMK_PROOF_TARGET int teardown_pin_target(int x)
    {
        volatile int r = x;
        return r;
    }

    int teardown_pin_detour(int x)
    {
        return x + 4000;
    }

    DMK_PROOF_TARGET int teardown_throw_target(int x)
    {
        volatile int r = x;
        return r;
    }

    int teardown_throw_detour(int x)
    {
        return x + 5000;
    }
} // namespace

// An unwitnessed restore leaves a live jump into the backend. Both pre-mutation failure modes must pin its trampoline
// and retain its ledger record.
TEST(HookTeardownFaultProof, ReportedDisableFailurePinsBackendAndBooksLeak)
{
    namespace diag = DetourModKit::diagnostics;

    const Address target = addr_of(&teardown_pin_target);
    ASSERT_FALSE(is_target_hooked(target));
    ASSERT_EQ(call_unfolded(&teardown_pin_target, 5), 5);

    const std::size_t leaks_before = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);

    {
        // The override precedes the hook, so it remains live through the hook destructor.
        const HookTeardownRestoreOverrideScope pin_scope(&reject_teardown_restore);

        Result<Hook> created = inline_at(
            InlineRequest{
                .name = "TeardownPin",
                .target = target,
            },
            &teardown_pin_detour
        );
        ASSERT_TRUE(created.has_value()) << created.error().message();
        Hook hook = std::move(*created);
        ASSERT_TRUE(hook.enable().has_value());
        ASSERT_EQ(call_unfolded(&teardown_pin_target, 5), 4005) << "the detour must be live before teardown";
    }

    EXPECT_EQ(diag::intentional_leak_count(diag::LeakSubsystem::HookManager), leaks_before + 1)
        << "an unrestorable teardown must book exactly one intentional leak";
    // The retained detour result distinguishes a pinned backend from the pristine target.
    EXPECT_EQ(call_unfolded(&teardown_pin_target, 5), 4005)
        << "the pinned backend must keep dispatching through its still-mapped trampoline";
    EXPECT_TRUE(is_target_hooked(target))
        << "a pinned-backend teardown must keep reporting the target hooked, not advertise it clean";
}

// The seam throws before mutation and leaves OwnedPatch. The noexcept destructor must contain the exception and pin
// that backend.
TEST(HookTeardownFaultProof, SyncExceptionDuringTeardownIsContainedAndPins)
{
    namespace diag = DetourModKit::diagnostics;

    const Address target = addr_of(&teardown_throw_target);
    ASSERT_FALSE(is_target_hooked(target));
    ASSERT_EQ(call_unfolded(&teardown_throw_target, 5), 5);

    const std::size_t leaks_before = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);

    {
        const HookTeardownRestoreOverrideScope pin_scope(&throw_teardown_restore_failure);

        Result<Hook> created = inline_at(
            InlineRequest{
                .name = "TeardownThrow",
                .target = target,
            },
            &teardown_throw_detour
        );
        ASSERT_TRUE(created.has_value()) << created.error().message();
        Hook hook = std::move(*created);
        ASSERT_TRUE(hook.enable().has_value());
        ASSERT_EQ(call_unfolded(&teardown_throw_target, 5), 5005) << "the detour must be live before teardown";
        // An escaping destructor exception terminates the process before any later assertion.
    }

    EXPECT_EQ(diag::intentional_leak_count(diag::LeakSubsystem::HookManager), leaks_before + 1)
        << "a contained synchronization failure must still book exactly one intentional leak";
    EXPECT_EQ(call_unfolded(&teardown_throw_target, 5), 5005)
        << "the pinned backend must keep dispatching through its still-mapped trampoline";
    EXPECT_TRUE(is_target_hooked(target))
        << "a pinned-backend teardown must keep reporting the target hooked, not advertise it clean";
}

// VMT object-word fault boundary. DMK validates the object word, snapshots the table through guarded reads, and
// publishes through a guarded atomic compare-exchange. Every invalid state must fail before a backend clone is exposed.
namespace
{
    /** @brief Sets the x86-64 base page size for separate hostile object words. */
    constexpr std::size_t OBJECT_WORD_PAGE_BYTES = 0x1000;

    // NoAccess, Reserved and Guarded fault a read, so the guarded capture refuses them. ReadOnly is the odd one out:
    // it reads cleanly, so the explicit writability check must refuse it before the guarded publication attempt.
    enum class ObjectWordState
    {
        NoAccess,
        ReadOnly,
        Reserved,
        Guarded
    };

    [[nodiscard]] std::string_view object_word_state_name(ObjectWordState state) noexcept
    {
        switch (state)
        {
        case ObjectWordState::NoAccess:
            return "PAGE_NOACCESS object word";
        case ObjectWordState::ReadOnly:
            return "PAGE_READONLY object word";
        case ObjectWordState::Reserved:
            return "MEM_RESERVE uncommitted object word";
        case ObjectWordState::Guarded:
            return "PAGE_GUARD object word";
        }
        return "unknown object word";
    }

    /**
     * @brief Creates a page whose object word has the specified protection.
     * @param state The hostile protection for the object word.
     * @param planted_vptr A real vtable pointer that isolates page protection from slot-walk refusal.
     * @return The object word, or nullptr if allocation or protection setup fails.
     * @note The page remains allocated for the process lifetime. fixtures/fault_injection.hpp owns the address-reuse
     * rule.
     */
    [[nodiscard]] void *make_hostile_object_word(ObjectWordState state, std::uintptr_t planted_vptr) noexcept
    {
        if (state == ObjectWordState::Reserved)
        {
            // Reserved but never committed: no page frame backs the word, so any access to it faults.
            return ::VirtualAlloc(nullptr, OBJECT_WORD_PAGE_BYTES, MEM_RESERVE, PAGE_READWRITE);
        }
        if (state == ObjectWordState::NoAccess)
        {
            return ::VirtualAlloc(nullptr, OBJECT_WORD_PAGE_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
        }
        void *page = ::VirtualAlloc(nullptr, OBJECT_WORD_PAGE_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (page == nullptr)
        {
            return nullptr;
        }
        *static_cast<std::uintptr_t *>(page) = planted_vptr;
        const DWORD protection =
            (state == ObjectWordState::ReadOnly) ? PAGE_READONLY : static_cast<DWORD>(PAGE_READWRITE | PAGE_GUARD);
        DWORD previous = 0;
        if (::VirtualProtect(page, OBJECT_WORD_PAGE_BYTES, protection, &previous) == FALSE)
        {
            return nullptr;
        }
        return page;
    }

    // Names the policy and state in assertion failures.
    [[nodiscard]] std::string describe_word_case(ObjectWordState state, const VmtOptions &options)
    {
        return std::string(object_word_state_name(state)) +
               ", fail_if_already_hooked=" + (options.fail_if_already_hooked ? "true" : "false") +
               ", fail_on_non_function_pointer=" + (options.fail_on_non_function_pointer ? "true" : "false");
    }
} // namespace

// Both publication entry points must refuse each hostile object word under every VmtOptions set. The exact error
// distinguishes that boundary from another refusal.
TEST(VmtHookFaultProof, ApplyInvalidObjectAlwaysReturnsTypedFailure)
{
    auto donor = std::make_unique<VmtTestTarget>();
    const std::uintptr_t genuine_vptr = *reinterpret_cast<std::uintptr_t *>(donor.get());

    // apply_to needs a live handle, so seed one on an ordinary writable object. Declared after the object it clones so
    // reverse-order destruction restores the vptr while the object is still alive.
    auto seed_object = std::make_unique<VmtTestTarget>();
    Result<VmtHook> seeded = vmt_for("FaultProofSeed", seed_object.get());
    ASSERT_TRUE(seeded.has_value()) << seeded.error().message();
    VmtHook vh = std::move(*seeded);

    const std::array<VmtOptions, 4> policies{
        VmtOptions{},
        VmtOptions{
            .fail_if_already_hooked = true,
        },
        VmtOptions{
            .fail_on_non_function_pointer = true,
        },
        VmtOptions{
            .fail_if_already_hooked = true,
            .fail_on_non_function_pointer = true,
        },
    };
    const std::array<ObjectWordState, 4> states{
        ObjectWordState::NoAccess,
        ObjectWordState::ReadOnly,
        ObjectWordState::Reserved,
        ObjectWordState::Guarded
    };

    for (const ObjectWordState state : states)
    {
        for (const VmtOptions &options : policies)
        {
            const std::string context = describe_word_case(state, options);

            // Each object uses a fresh page. A consumed PAGE_GUARD must re-arm before failure so a later case cannot
            // inherit a disarmed fence.
            void *const create_object = make_hostile_object_word(state, genuine_vptr);
            ASSERT_NE(create_object, nullptr) << context;
            const Result<VmtHook> created = vmt_for("FaultProofCreate", create_object, options);
            ASSERT_FALSE(created.has_value()) << context;
            EXPECT_EQ(created.error().code, ErrorCode::InvalidObject) << context;

            void *const apply_object = make_hostile_object_word(state, genuine_vptr);
            ASSERT_NE(apply_object, nullptr) << context;
            const Result<void> applied = vh.apply_to(apply_object, options);
            ASSERT_FALSE(applied.has_value()) << context;
            EXPECT_EQ(applied.error().code, ErrorCode::InvalidObject) << context;
        }
    }

    // No hostile-object binding can survive a refused apply. Such a binding faults during handle teardown.
    EXPECT_TRUE(static_cast<bool>(vh));
    EXPECT_TRUE(vh.remove_from(seed_object.get()).has_value());
}

TEST(VmtHookFaultProof, UnalignedObjectWordIsRefusedWithoutMutation)
{
    auto donor = std::make_unique<VmtTestTarget>();
    const std::uintptr_t genuine_vptr = *reinterpret_cast<std::uintptr_t *>(donor.get());
    alignas(std::uintptr_t) std::array<std::byte, sizeof(std::uintptr_t) + 1> storage{};
    void *const object = storage.data() + 1;
    ASSERT_NE(reinterpret_cast<std::uintptr_t>(object) % alignof(std::uintptr_t), 0u);
    std::memcpy(object, &genuine_vptr, sizeof(genuine_vptr));

    const Result<VmtHook> created = vmt_for("UnalignedWordCreate", object);
    ASSERT_FALSE(created.has_value());
    EXPECT_EQ(created.error().code, ErrorCode::InvalidObject);

    auto seed_object = std::make_unique<VmtTestTarget>();
    Result<VmtHook> seeded = vmt_for("UnalignedWordApplySeed", seed_object.get());
    ASSERT_TRUE(seeded.has_value()) << seeded.error().message();
    VmtHook vh = std::move(*seeded);
    const Result<void> applied = vh.apply_to(object);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code, ErrorCode::InvalidObject);

    std::uintptr_t observed = 0;
    std::memcpy(&observed, object, sizeof(observed));
    EXPECT_EQ(observed, genuine_vptr);
}

// The PAGE_READONLY word passes capture and slot checks. Only the explicit publication writability check can refuse it.
TEST(VmtHookFaultProof, CreateRefusesReadOnlyObjectWord)
{
    auto donor = std::make_unique<VmtTestTarget>();
    const std::uintptr_t genuine_vptr = *reinterpret_cast<std::uintptr_t *>(donor.get());

    void *const object = make_hostile_object_word(ObjectWordState::ReadOnly, genuine_vptr);
    ASSERT_NE(object, nullptr);

    const Result<VmtHook> created = vmt_for("ReadOnlyWordCreate", object);
    ASSERT_FALSE(created.has_value());
    EXPECT_EQ(created.error().code, ErrorCode::InvalidObject);
    EXPECT_EQ(*static_cast<std::uintptr_t *>(object), genuine_vptr) << "a refused create must publish nothing";
}

TEST(VmtHookFaultProof, ApplyRefusesReadOnlyObjectWord)
{
    auto donor = std::make_unique<VmtTestTarget>();
    const std::uintptr_t genuine_vptr = *reinterpret_cast<std::uintptr_t *>(donor.get());

    auto seed_object = std::make_unique<VmtTestTarget>();
    Result<VmtHook> seeded = vmt_for("ReadOnlyWordApplySeed", seed_object.get());
    ASSERT_TRUE(seeded.has_value()) << seeded.error().message();
    VmtHook vh = std::move(*seeded);

    void *const object = make_hostile_object_word(ObjectWordState::ReadOnly, genuine_vptr);
    ASSERT_NE(object, nullptr);

    const Result<void> applied = vh.apply_to(object);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code, ErrorCode::InvalidObject);
    EXPECT_EQ(*static_cast<std::uintptr_t *>(object), genuine_vptr) << "a refused apply must publish nothing";
}

// A writable object applies and restores. The retained seed detour distinguishes a harmless hostile-object refusal from
// handle damage.
TEST(VmtHookFaultProof, WritableObjectAppliesAndRefusalLeavesSeedUsable)
{
    auto donor = std::make_unique<VmtTestTarget>();
    const std::uintptr_t genuine_vptr = *reinterpret_cast<std::uintptr_t *>(donor.get());

    auto seed_object = std::make_unique<VmtTestTarget>();
    auto peer_object = std::make_unique<VmtTestTarget>();
    const std::uintptr_t peer_vptr_original = *reinterpret_cast<std::uintptr_t *>(peer_object.get());

    Result<VmtHook> seeded = vmt_for("GateControlSeed", seed_object.get());
    ASSERT_TRUE(seeded.has_value()) << seeded.error().message();
    VmtHook vh = std::move(*seeded);
    MethodVmtScope scope(vh);
    ASSERT_TRUE(vh.hook_method<VmtComputeFn>(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());

    // The detour result distinguishes the correct ABI slot from the unhooked compute method.
    EXPECT_EQ(dispatch_compute(seed_object.get(), 2, 3), 1005);

    // Control: a plain writable object applies, dispatches through the clone, and restores.
    ASSERT_TRUE(vh.apply_to(peer_object.get()).has_value());
    EXPECT_EQ(dispatch_compute(peer_object.get(), 4, 5), 1009);

    void *const hostile = make_hostile_object_word(ObjectWordState::ReadOnly, genuine_vptr);
    ASSERT_NE(hostile, nullptr);
    const Result<void> refused = vh.apply_to(hostile);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().code, ErrorCode::InvalidObject);

    // The refusal changed nothing: both live objects still dispatch through the clone's hooked slot.
    EXPECT_EQ(dispatch_compute(seed_object.get(), 2, 3), 1005);
    EXPECT_EQ(dispatch_compute(peer_object.get(), 4, 5), 1009);

    ASSERT_TRUE(vh.remove_from(peer_object.get()).has_value());
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(peer_object.get()), peer_vptr_original);
    EXPECT_EQ(dispatch_compute(peer_object.get(), 4, 5), 9);
}

// The table shrinks between the pre-count and snapshot. The clone bounds must follow the snapshot because backend
// writes lack slot checks.
#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(VmtHookFaultProof, CaptureRaceBoundsMethodCountToTheClonedTable)
{
    // Two leading words contain the MinGW RTTI prefix. The trailing null bounds the pre-count.
    struct ShrinkVTable
    {
        void *rtti[2];
        void *methods[4];
    };
    ShrinkVTable vtable{};
    vtable.methods[0] = slot_bodies().at(SlotBodyPage::RET);
    vtable.methods[1] = slot_bodies().at(SlotBodyPage::RET);
    vtable.methods[2] = slot_bodies().at(SlotBodyPage::RET);
    vtable.methods[3] = nullptr;
    void *vptr = &vtable.methods[0];

    // The probe shrinks the callable run from three slots to one between the count and the capture.
    Result<VmtHook> created = [&]()
    {
        VmtCaptureShrinkScope scope(&vtable.methods[1]);
        return vmt_for("CaptureRaceShrink", &vptr);
    }();
    ASSERT_TRUE(created.has_value()) << created.error().message();
    VmtHook vh = std::move(*created);

    // Only slot 0 exists in the clone. The pre-count alone cannot authorize slot 1.
    EXPECT_TRUE(vh.hook_method(0, &vmt_detour_compute).has_value());
    const Result<void> past_clone = vh.hook_method(1, &vmt_detour_compute);
    ASSERT_FALSE(past_clone.has_value());
    EXPECT_EQ(past_clone.error().code, ErrorCode::InvalidArg);
}

// The seam removes execute permission after capture. The clone must still contain both captured slots and preserve
// method 1.
TEST(VmtHookFaultProof, ExecuteProtectionRaceCannotShrinkBackendAllocation)
{
    dmk_test::ScratchPage first_method;
    dmk_test::ScratchPage second_method;
    ASSERT_TRUE(first_method.ok());
    ASSERT_TRUE(second_method.ok());
    first_method.put(0, {0xC3});
    second_method.put(0, {0xC3});

    struct RaceVTable
    {
        void *rtti[2];
        void *methods[3];
    };
    RaceVTable raced_table{};
    raced_table.methods[0] = first_method.base();
    raced_table.methods[1] = second_method.base();
    raced_table.methods[2] = nullptr;
    void *raced_vptr = &raced_table.methods[0];

    Result<VmtHook> raced = [&]() -> Result<VmtHook>
    {
        VmtBackendCountRaceScope scope(second_method.base());
        Result<VmtHook> result = vmt_for("BackendCountRace", &raced_vptr);
        EXPECT_TRUE(scope.succeeded());
        return result;
    }();
    ASSERT_TRUE(raced.has_value()) << raced.error().message();
    VmtHook raced_hook = std::move(*raced);
    const std::uintptr_t raced_clone_base = reinterpret_cast<std::uintptr_t>(raced_vptr);

    RaceVTable neighbour_table{};
    neighbour_table.methods[0] = first_method.base();
    neighbour_table.methods[1] = nullptr;
    void *neighbour_vptr = &neighbour_table.methods[0];
    Result<VmtHook> neighbour = vmt_for("BackendCountRaceNeighbour", &neighbour_vptr);
    ASSERT_TRUE(neighbour.has_value()) << neighbour.error().message();
    VmtHook neighbour_hook = std::move(*neighbour);

    // The backend uses first-fit allocation with two-byte alignment. A one-slot clone places the neighbor at method 1.
    const std::uintptr_t header_bytes = TEST_VMT_HEADER_WORDS * sizeof(std::uintptr_t);
    const std::uintptr_t neighbour_allocation_base = reinterpret_cast<std::uintptr_t>(neighbour_vptr) - header_bytes;
    ASSERT_EQ(neighbour_allocation_base, raced_clone_base + (2 * sizeof(std::uintptr_t)));

    ASSERT_TRUE(raced_hook.hook_method(1, &vmt_detour_compute).has_value());
    EXPECT_EQ(raced_hook.original<VmtComputeFn>(1), reinterpret_cast<VmtComputeFn>(second_method.addr()));
}
#endif

// The method-map node allocates before the backend stores the slot. An allocation failure therefore never sits over a
// live detour, and original() resolves from the instant the slot changes. The reader watches the clone slot and
// original() together. A slot that holds the detour while original() is null is a live detour with no resolvable
// original. Repeated refusals make that window observable when it exists.
TEST(VmtHookFaultProof, MethodMapNodeAllocatesBeforeSlotStore)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    struct NodeVTable
    {
        void *rtti[2];
        void *methods[3];
    };
    NodeVTable table{};
    table.methods[0] = slot_bodies().at(SlotBodyPage::RET);
    table.methods[1] = slot_bodies().at(SlotBodyPage::RET);
    table.methods[2] = nullptr;
    void *vptr = &table.methods[0];

    Result<VmtHook> created = vmt_for("MethodMapNode", &vptr);
    ASSERT_TRUE(created.has_value()) << created.error().message();
    VmtHook hook = std::move(*created);
    void *const genuine = slot_bodies().at(SlotBodyPage::RET);
    void *const detour = reinterpret_cast<void *>(&vmt_detour_compute);
    void **const clone_slots = static_cast<void **>(vptr);
    ASSERT_EQ(clone_slots[0], genuine);

    std::atomic<bool> saw_unresolvable_detour{false};
    std::atomic<bool> saw_detour_original{false};
    std::jthread reader(
        [&](const std::stop_token &token)
        {
            while (!token.stop_requested())
            {
                void *const slot = clone_slots[0];
                void *const original = reinterpret_cast<void *>(hook.original<VmtComputeFn>(0));
                if (slot == detour && original == nullptr)
                {
                    saw_unresolvable_detour.store(true, std::memory_order_release);
                }
                if (original == detour)
                {
                    saw_detour_original.store(true, std::memory_order_release);
                }
            }
        }
    );

    for (int attempt = 0; attempt < 200; ++attempt)
    {
        Result<void> refused;
        {
            // The assertions allocate their failure text, so they run after the allocation scope ends.
            const dmk_test::AllocFailScope fail_allocations{0};
            refused = hook.hook_method(0, &vmt_detour_compute);
        }
        ASSERT_FALSE(refused.has_value());
        EXPECT_EQ(refused.error().code, ErrorCode::OutOfMemory);
    }
    EXPECT_EQ(clone_slots[0], genuine);
    EXPECT_EQ(hook.original<VmtComputeFn>(0), nullptr);

    ASSERT_TRUE(hook.hook_method(0, &vmt_detour_compute).has_value());
    EXPECT_EQ(clone_slots[0], detour);
    EXPECT_EQ(reinterpret_cast<void *>(hook.original<VmtComputeFn>(0)), genuine);
    reader.request_stop();
    reader.join();
    EXPECT_FALSE(saw_unresolvable_detour.load(std::memory_order_acquire));
    EXPECT_FALSE(saw_detour_original.load(std::memory_order_acquire));

    ASSERT_TRUE(hook.remove_method(0).has_value());
    EXPECT_EQ(clone_slots[0], genuine);
    EXPECT_EQ(hook.original<VmtComputeFn>(0), nullptr);
}

// The seam changes the captured object word before publication. InvalidObject must preserve the newer vptr and leave no
// failed-object binding or ledger entry.
//
// The surviving seed proves gate usability. A later create reuses the failed allocator slot and detects a stale clone
// record.
//
// The seam isolates comparison before publication. Atomicity rests on InterlockedCompareExchange64 in
// guarded_compare_exchange_word because no seam can interrupt that instruction.
#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(VmtHookFaultProof, PublicationRaceReturnsTypedFailureWithoutResidue)
{
    auto donor = std::make_unique<VmtTestTarget>();
    const std::uintptr_t genuine_vptr = *reinterpret_cast<std::uintptr_t *>(donor.get());
    auto seed_object = std::make_unique<VmtTestTarget>();
    Result<VmtHook> seeded = vmt_for("PublicationRaceSeed", seed_object.get());
    ASSERT_TRUE(seeded.has_value()) << seeded.error().message();
    VmtHook vh = std::move(*seeded);

    const std::array<VmtPublishRace, 3> races{
        VmtPublishRace::Unmap,
        VmtPublishRace::Displace,
        VmtPublishRace::ReadOnly
    };
    for (const VmtPublishRace race : races)
    {
        void *const create_object =
            ::VirtualAlloc(nullptr, VMT_PUBLISH_RACE_PAGE_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ASSERT_NE(create_object, nullptr);
        *static_cast<std::uintptr_t *>(create_object) = genuine_vptr;
        {
            VmtPublishRaceScope scope(create_object, race);
            const Result<VmtHook> created = vmt_for("PublicationRaceCreate", create_object);
            ASSERT_FALSE(created.has_value());
            EXPECT_EQ(created.error().code, ErrorCode::InvalidObject);
        }
        if (race == VmtPublishRace::Displace)
        {
            // The refused publish must preserve the concurrent writer's object word.
            EXPECT_EQ(*static_cast<std::uintptr_t *>(create_object), VMT_PUBLISH_DISPLACED_VPTR);
        }
        if (race != VmtPublishRace::Unmap)
        {
            EXPECT_NE(::VirtualFree(create_object, 0, MEM_RELEASE), 0);
        }

        void *const apply_object =
            ::VirtualAlloc(nullptr, VMT_PUBLISH_RACE_PAGE_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ASSERT_NE(apply_object, nullptr);
        *static_cast<std::uintptr_t *>(apply_object) = genuine_vptr;
        {
            VmtPublishRaceScope scope(apply_object, race);
            const Result<void> applied = vh.apply_to(apply_object);
            ASSERT_FALSE(applied.has_value());
            EXPECT_EQ(applied.error().code, ErrorCode::InvalidObject);
        }
        if (race == VmtPublishRace::Displace)
        {
            EXPECT_EQ(*static_cast<std::uintptr_t *>(apply_object), VMT_PUBLISH_DISPLACED_VPTR);
        }
        if (race != VmtPublishRace::Unmap)
        {
            EXPECT_NE(::VirtualFree(apply_object, 0, MEM_RELEASE), 0);
        }
    }

    std::uintptr_t control_clone_base = 0;
    {
        auto control_object = std::make_unique<VmtTestTarget>();
        Result<VmtHook> control = vmt_for("PublicationRaceLedgerControl", control_object.get());
        ASSERT_TRUE(control.has_value()) << control.error().message();
        VmtHook control_hook = std::move(*control);
        control_clone_base = *reinterpret_cast<std::uintptr_t *>(control_object.get());
    }
    EXPECT_FALSE(DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(control_clone_base));

    auto peer = std::make_unique<VmtTestTarget>();
    const std::uintptr_t peer_original = *reinterpret_cast<std::uintptr_t *>(peer.get());
    ASSERT_TRUE(vh.apply_to(peer.get()).has_value());
    ASSERT_TRUE(vh.remove_from(peer.get()).has_value());
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(peer.get()), peer_original);
}
#endif

// The lock seam injects an acquisition failure that the live Windows mutex does not produce. Each noexcept boundary
// must preserve reachable backend state.
//
// Condition-variable wait specifies "Throws: Nothing". A failed re-lock terminates, so this seam cannot model that
// path.
namespace
{
    std::size_t s_ledger_lock_probe_calls = 0;
    std::size_t s_ledger_lock_failure_call = 0;

    void throw_at_ledger_lock_boundary()
    {
        ++s_ledger_lock_probe_calls;
        if (s_ledger_lock_failure_call == 0 || s_ledger_lock_probe_calls == s_ledger_lock_failure_call)
        {
            throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur));
        }
    }

    /// The last publication step an install reached, or nullopt when it failed before the first one.
    std::optional<DetourModKit::detail::HookPublishStep> s_last_publish_step;

    void record_publish_step(DetourModKit::detail::HookPublishStep step)
    {
        s_last_publish_step = step;
    }

    /// Installs a throwing ledger-lock probe for its scope.
    class LedgerLockFailureScope
    {
    public:
        explicit LedgerLockFailureScope(std::size_t failure_call = 0) noexcept
        {
            s_ledger_lock_probe_calls = 0;
            s_ledger_lock_failure_call = failure_call;
            DetourModKit::detail::g_hook_ledger_lock_probe = &throw_at_ledger_lock_boundary;
        }
        ~LedgerLockFailureScope() noexcept
        {
            DetourModKit::detail::g_hook_ledger_lock_probe = nullptr;
            s_ledger_lock_probe_calls = 0;
            s_ledger_lock_failure_call = 0;
        }
        LedgerLockFailureScope(const LedgerLockFailureScope &) = delete;
        LedgerLockFailureScope &operator=(const LedgerLockFailureScope &) = delete;
        LedgerLockFailureScope(LedgerLockFailureScope &&) = delete;
        LedgerLockFailureScope &operator=(LedgerLockFailureScope &&) = delete;
    };
} // namespace

TEST(HookLedgerFaultProof, SyncFailureRetainsReachableState)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();

    // An unknown ledger must not report a clean target or clone. A strict install cannot overwrite an invisible layer.
    {
        const LedgerLockFailureScope fail;
        EXPECT_TRUE(ledger.is_target_hooked(reinterpret_cast<std::uintptr_t>(&leak_target_ledger_sync)));
        EXPECT_TRUE(ledger.is_vmt_clone_base(0x1000));
        EXPECT_EQ(
            ledger.try_reserve_hook(0x2000, false).status,
            DetourModKit::detail::HookLedger::ReserveStatus::OutOfMemory
        );
        EXPECT_FALSE(ledger.try_record_vmt(0x3000).has_value());
        // A write slot that cannot be claimed reports a positive newer-count, so its caller refuses or leaks.
        EXPECT_GT(ledger.acquire_target_slot(0x2000, 1), 0u);
        EXPECT_GT(ledger.release_hook(0x2000, 1), 0u);
        EXPECT_FALSE(ledger.commit_hook(0x2000, 1));
        // Neither best-effort boundary can terminate the process.
        ledger.release_target_slot(0x2000, 1);
        ledger.release_vmt(1);
    }
    // A null probe restores real behaviour: the failures above left no residue.
    EXPECT_FALSE(ledger.is_target_hooked(reinterpret_cast<std::uintptr_t>(&leak_target_ledger_sync)));

    {
        // GatePublished proves that the failure reaches commit_hook after backend, Impl, and gate creation. A
        // reservation failure returns the same error before those objects exist.
        s_last_publish_step.reset();
        const HookPublishProbeScope steps{&record_publish_step};
        const LedgerLockFailureScope fail_commit{2};
        Result<Hook> failed = inline_at(
            InlineRequest{
                .name = "LedgerCommitFailure",
                .target = addr_of(&ledger_commit_failure_target),
            },
            &real_hook_detour_add
        );
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(failed.error().code, ErrorCode::OutOfMemory);
        ASSERT_TRUE(s_last_publish_step.has_value()) << "install failed before creating a backend, so commit_hook was "
                                                        "never reached and this proves nothing about it";
        EXPECT_EQ(*s_last_publish_step, DetourModKit::detail::HookPublishStep::GatePublished)
            << "the injected failure did not land on commit_hook";
    }
    EXPECT_FALSE(is_target_hooked(addr_of(&ledger_commit_failure_target)));
    EXPECT_EQ(call_unfolded(&ledger_commit_failure_target, 20, 22), 45);

    Result<Hook> created = inline_at(
        InlineRequest{
            .name = "LedgerSync",
            .target = addr_of(&leak_target_ledger_sync),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(created.has_value()) << created.error().message();
    Hook hook = std::move(*created);
    ASSERT_TRUE(hook.enable().has_value());
    ASSERT_EQ(call_unfolded(&leak_target_ledger_sync, 20, 22), real_hook_detour_add(20, 22));

    {
        // A failed slot claim leaves the armed hook enabled and callable.
        const LedgerLockFailureScope fail;
        const Result<void> refused = hook.disable();
        ASSERT_FALSE(refused.has_value());
        EXPECT_EQ(refused.error().code, ErrorCode::LayerConflict);
    }
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(call_unfolded(&leak_target_ledger_sync, 20, 22), real_hook_detour_add(20, 22));

    const std::size_t leaks_before = diagnostics::total_intentional_leaks();
    {
        // Failed teardown retains the backend, patch, and installation module reference. Its leak counter records that
        // retention.
        const LedgerLockFailureScope fail;
        Hook doomed = std::move(hook);
    }
    EXPECT_GT(diagnostics::total_intentional_leaks(), leaks_before);
    // Retained means reachable: the detour still dispatches through the deliberately leaked trampoline.
    EXPECT_EQ(call_unfolded(&leak_target_ledger_sync, 20, 22), real_hook_detour_add(20, 22));
}

// A real lock failure is permanent, so a later reserver must refuse its own acquisition before any wait. Sentinel
// removal without that mutex creates a data race.
TEST(HookLedgerFaultProof, AbandonedSlotCannotParkALaterReserver)
{
    using DetourModKit::detail::HookLedger;
    auto &ledger = HookLedger::instance();
    constexpr std::uintptr_t target = 0xB0BA8000;

    const auto first = ledger.try_reserve_hook(target, /*refuse_if_hooked=*/false);
    ASSERT_EQ(first.status, HookLedger::ReserveStatus::Reserved);
    ASSERT_TRUE(ledger.commit_hook(target, first.id));
    // The slot is held: first.id now sits at the front of the pending queue and gates every later reserver.
    ASSERT_EQ(ledger.acquire_target_slot(target, first.id), 0u);

    // Shared with the probe thread by value so an unexpected park cannot dangle these across the scope exit.
    const auto returned = std::make_shared<std::atomic<bool>>(false);
    const auto status = std::make_shared<std::atomic<int>>(-1);
    {
        // The lock is broken from here on, for every caller, which is the only way a real std::mutex can fail.
        const LedgerLockFailureScope fail;
        ledger.release_target_slot(target, first.id); // cannot retake the lock: the sentinel stays at the front

        std::thread later(
            [&ledger, returned, status]
            {
                status->store(
                    static_cast<int>(ledger.try_reserve_hook(target, /*refuse_if_hooked=*/false).status),
                    std::memory_order_relaxed
                );
                returned->store(true, std::memory_order_release);
            }
        );

        bool completed = false;
        for (int i = 0; i < 2000 && !completed; ++i)
        {
            completed = returned->load(std::memory_order_acquire);
            if (!completed)
            {
                Sleep(1);
            }
        }
        EXPECT_TRUE(completed) << "a later same-target reserve parked behind the abandoned slot sentinel";
        if (completed)
        {
            later.join();
            EXPECT_EQ(
                static_cast<HookLedger::ReserveStatus>(status->load(std::memory_order_relaxed)),
                HookLedger::ReserveStatus::OutOfMemory
            );
        }
        else
        {
            // The shared state outlives the detached thread. A join cannot drain a thread that remains parked.
            later.detach();
        }
    }

    // Drain the synthetic target so it cannot alias a later assertion.
    (void)ledger.release_hook(target, first.id);
    EXPECT_FALSE(ledger.is_target_hooked(target));
}
