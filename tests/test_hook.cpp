#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include "internal/hook_fault_boundary.hpp"
#include "internal/hook_ledger.hpp"

#include "fixtures/scratch_page.hpp"
#include "test_alloc_probe.hpp"

using namespace DetourModKit;
// The SafetyHook backend is confined to the library: a detour names only these DMK-owned hook types, exactly as a
// shipping consumer would. There is no HookManager, no registry, no HookError/HookStatus/HookType enums.
using namespace DetourModKit::hook;

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

// Real, hookable functions used as inline/mid hook targets. DMK_TEST_NOINLINE plus a volatile result forces a real call
// to the patched entry, so a post-teardown call observes the restored prologue rather than a constant-folded value.
namespace
{
    DMK_TEST_NOINLINE int echo(int x)
    {
        volatile int r = x;
        return r;
    }

    DMK_TEST_NOINLINE int real_hook_target_add(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_TEST_NOINLINE int real_hook_target_mul(int a, int b)
    {
        volatile int r = a * b;
        return r;
    }

    // Dedicated targets for the release()/leak tests. release() intentionally leaks an installed detour for the process
    // lifetime, so a leaked hook must never land on a target a later test expects to be clean. Each leak test uses its
    // own function here, touched by no other test.
    DMK_TEST_NOINLINE int leak_target_inline(int x)
    {
        volatile int r = x;
        return r;
    }

    DMK_TEST_NOINLINE int leak_target_disengaged(int x)
    {
        volatile int r = x;
        return r;
    }

    DMK_TEST_NOINLINE int leak_target_mid(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_TEST_NOINLINE int leak_target_lifecycle(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    // Dedicated target for the layered oldest-first teardown test. Destroying the older of two layered hooks first
    // leaks the older backend for the process lifetime (the leak-on-inversion containment), so this target must be
    // touched by no other test.
    DMK_TEST_NOINLINE int leak_target_layered(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_TEST_NOINLINE int witness_failure_inline_target(int value)
    {
        const volatile int result = value + 17;
        return result;
    }

    DMK_TEST_NOINLINE int witness_failure_mid_target(int a, int b)
    {
        const volatile int result = a - b;
        return result;
    }

    std::atomic<int> s_real_detour_calls{0};

    DMK_TEST_NOINLINE int real_hook_detour_add(int a, int b)
    {
        s_real_detour_calls.fetch_add(1, std::memory_order_relaxed);
        return a + b + 1000;
    }

    using EchoFn = int (*)(int);

    // Detour for echo: returns x + 100 so a hooked echo(7) == 107 while the trampoline still yields the original 7.
    int echo_detour(int x)
    {
        return x + 100;
    }

    std::atomic<int> s_mid_detour_calls{0};

    // Builds an Address from a free function pointer via the uintptr form (a function pointer does not implicitly
    // convert to void*).
    template <class Fn> [[nodiscard]] Address addr_of(Fn *fn) noexcept
    {
        return Address{reinterpret_cast<std::uintptr_t>(fn)};
    }

    // A volatile indirection forces the call to reach the patched entry even when the optimizer can see the callee.
    template <class Fn, class... Args> auto call_unfolded(Fn *fn, Args... args)
    {
        Fn *const volatile indirect = fn;
        return indirect(args...);
    }
} // namespace

// INLINE create + validation

TEST(HookInline, CreateSuccessAutoEnabled)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "InlineCreate", .target = addr_of(&real_hook_target_add)},
                               &real_hook_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();

    Hook h = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(h));
    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(h.name(), "InlineCreate");
}

TEST(HookInline, CreateInvalidTargetAddress)
{
    Result<Hook> r =
        inline_at(InlineRequest{.name = "BadTarget", .target = Address{std::uintptr_t{0}}}, &real_hook_detour_add);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidTargetAddress);
}

TEST(HookInline, CreateNullDetour)
{
    EchoFn null_detour = nullptr;
    Result<Hook> r =
        inline_at(InlineRequest{.name = "NullDetour", .target = addr_of(&real_hook_target_add)}, null_detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidDetourFunction);
}

TEST(HookInline, CreateEmptyName)
{
    Result<Hook> r =
        inline_at(InlineRequest{.name = "", .target = addr_of(&real_hook_target_add)}, &real_hook_detour_add);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidArg);
}

// Leak-on-purpose scenarios require dedicated function addresses so their retained patches cannot alias another target.
TEST(HookTargetIsolation, DistinctTargetsDoNotShareAnAddress)
{
    const std::array<std::pair<const char *, std::uintptr_t>, 10> targets{{
        {"echo", reinterpret_cast<std::uintptr_t>(&echo)},
        {"real_hook_target_add", reinterpret_cast<std::uintptr_t>(&real_hook_target_add)},
        {"real_hook_target_mul", reinterpret_cast<std::uintptr_t>(&real_hook_target_mul)},
        {"leak_target_inline", reinterpret_cast<std::uintptr_t>(&leak_target_inline)},
        {"leak_target_disengaged", reinterpret_cast<std::uintptr_t>(&leak_target_disengaged)},
        {"leak_target_mid", reinterpret_cast<std::uintptr_t>(&leak_target_mid)},
        {"leak_target_lifecycle", reinterpret_cast<std::uintptr_t>(&leak_target_lifecycle)},
        {"leak_target_layered", reinterpret_cast<std::uintptr_t>(&leak_target_layered)},
        {"witness_failure_inline_target", reinterpret_cast<std::uintptr_t>(&witness_failure_inline_target)},
        {"witness_failure_mid_target", reinterpret_cast<std::uintptr_t>(&witness_failure_mid_target)},
    }};

    for (std::size_t i = 0; i < targets.size(); ++i)
    {
        for (std::size_t j = i + 1; j < targets.size(); ++j)
        {
            EXPECT_NE(targets[i].second, targets[j].second) << targets[i].first << " and " << targets[j].first
                                                            << " share an address, so a hook on either lands on both";
        }
    }
}

// INLINE typed trampoline + enable/disable

TEST(HookInline, TypedTrampolineCallsOriginal)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "Trampoline", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    // The detour is active: echo(7) routes through echo_detour -> 107.
    EXPECT_EQ(call_unfolded(&echo, 7), 107);

    // The typed trampoline reaches the original body, so it yields the unmodified 7.
    auto *orig = h.original<EchoFn>();
    ASSERT_NE(orig, nullptr);
    EXPECT_EQ(orig(7), 7);
}

TEST(HookInline, EnableDisableTogglesDetour)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "Toggle", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&echo, 7), 107);

    ASSERT_TRUE(h.disable().has_value());
    EXPECT_FALSE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&echo, 7), 7); // original body restored while disabled

    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(call_unfolded(&echo, 7), 107);
}

TEST(HookInline, EnableDisableAreIdempotent)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "Idempotent", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    ASSERT_TRUE(h.enable().has_value()); // already enabled
    EXPECT_TRUE(h.is_enabled());
    ASSERT_TRUE(h.disable().has_value());
    ASSERT_TRUE(h.disable().has_value()); // already disabled
    EXPECT_FALSE(h.is_enabled());
}

// A moved-from inline handle is a mid-hook-style nullptr for original<Fn>() too, but the primary inert guarantee is in
// the RAII teardown test below. Here we pin that the typed trampoline is non-null only for a live inline hook.
TEST(HookInline, OriginalNullForDisengagedHandle)
{
    // Uses a dedicated leak target: release() leaves the detour installed for the process lifetime.
    Result<Hook> r =
        inline_at(InlineRequest{.name = "Disengaged", .target = addr_of(&leak_target_disengaged)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    h.release(); // detach: handle becomes disengaged
    EXPECT_FALSE(static_cast<bool>(h));
    EXPECT_EQ(h.original<EchoFn>(), nullptr);
}

// INLINE prologue policy
namespace
{
    // Synthetic prologue targets live on a committed executable page, not in a static array: the pre-flight's steal
    // window requires the bytes the backend decodes to be executable committed memory, so a prologue planted in
    // read-only or read-write data is refused for that reason before its first byte is ever classified. A static buffer
    // would make every test below pass for the wrong reason.
    void noop_detour() noexcept {}

    // Plants a prologue at the start of a fresh executable page and returns the install result.
    Result<Hook> install_on_planted_prologue(dmk_test::ScratchPage &page, const char *name,
                                             std::initializer_list<std::uint8_t> prologue, Options options = {})
    {
        page.put(0, prologue);
        return inline_at(InlineRequest{.name = name, .target = Address{page.addr(0)}, .options = options},
                         reinterpret_cast<void (*)()>(&noop_detour));
    }

    // A function whose first instruction is a rel32 call is assembled on an executable page:
    //
    //   +0x000  E8 <rel32 to +0x100>   call callee
    //   +0x005  C3                     ret            (returns the callee's EAX)
    //   +0x100  B8 <imm32> C3          mov eax, MAGIC; ret
    //
    // The callee lives on the SAME page as the target so the backend's trampoline, which it allocates near the target,
    // is necessarily within rel32 reach of the callee's absolute address. Splitting them across a VirtualAlloc page and
    // the test image would make relocation reach depend on where the OS happened to place the page.
    constexpr std::size_t LEADING_CALL_CALLEE_OFFSET = 0x100;
    constexpr int LEADING_CALL_CALLEE_VALUE = 0x00C0FFEE;
    constexpr int LEADING_CALL_DETOUR_VALUE = 0x00BADA55;

    void plant_leading_call_fixture(dmk_test::ScratchPage &page) noexcept
    {
        const std::int32_t disp =
            static_cast<std::int32_t>(LEADING_CALL_CALLEE_OFFSET) - 5; // rel32 is relative to the next instruction
        page.put(0, {0xE8, static_cast<std::uint8_t>(disp & 0xFF), static_cast<std::uint8_t>((disp >> 8) & 0xFF),
                     static_cast<std::uint8_t>((disp >> 16) & 0xFF), static_cast<std::uint8_t>((disp >> 24) & 0xFF),
                     0xC3});
        page.put(LEADING_CALL_CALLEE_OFFSET,
                 {0xB8, static_cast<std::uint8_t>(LEADING_CALL_CALLEE_VALUE & 0xFF),
                  static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 8) & 0xFF),
                  static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 16) & 0xFF),
                  static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 24) & 0xFF), 0xC3});
        FlushInstructionCache(GetCurrentProcess(), page.base(), dmk_test::ScratchPage::PAGE_SIZE);
    }

    int leading_call_detour() noexcept
    {
        return LEADING_CALL_DETOUR_VALUE;
    }
} // namespace

// A leading 0xCC (int3) prologue is already a breakpoint -- a foreign hook's stub, a patched byte, or padding -- not a
// real function body. The default Fail policy must refuse. Planted on an executable page so the refusal is proven to
// come from the breakpoint classifier and not from the steal-window gate ahead of it.
TEST(HookInlinePrologue, DefaultFailsOnInt3Prologue)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    Result<Hook> r = install_on_planted_prologue(page, "Int3Prologue", {0xCC, 0xC3, 0x90, 0x90});
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// A leading 0xCD (int n) prologue is the two-byte breakpoint form; classifying on the first byte alone is sufficient.
TEST(HookInlinePrologue, DefaultFailsOnIntNPrologue)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    Result<Hook> r = install_on_planted_prologue(page, "IntNPrologue", {0xCD, 0x03, 0xC3, 0x90});
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// The default policy must never refuse a normal real-function target: a normal prologue installs with no false
// TargetPrologueUnsafe.
TEST(HookInlinePrologue, DefaultInstallsOnNormalTarget)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "NormalPrologue", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << "Default policy must not refuse a normal function prologue: " << r.error().message();
    EXPECT_TRUE(static_cast<bool>(*r));
}

// A leading rel32 call is relocatable: the backend rewrites its displacement against the trampoline, so both the
// patched entry and trampoline must preserve their respective behavior under the default policy.
TEST(HookInlinePrologue, LeadingRel32CallUsesBackendCapability)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leading_call_fixture(page);

    auto target = reinterpret_cast<int (*)()>(page.addr(0));

    // Control: unhooked, the leading call reaches the callee and the target returns its value.
    ASSERT_EQ(target(), LEADING_CALL_CALLEE_VALUE);

    Result<Hook> r = inline_at(InlineRequest{.name = "LeadingRel32Call", .target = Address{page.addr(0)}},
                               reinterpret_cast<void (*)()>(&leading_call_detour));
    ASSERT_TRUE(r.has_value()) << "A backend-relocatable leading E8 rel32 call must not be refused by DMK under the "
                                  "default policy: "
                               << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(static_cast<bool>(h));

    // The detour runs instead of the target, proving the patch is live rather than merely reported.
    EXPECT_EQ(target(), LEADING_CALL_DETOUR_VALUE);

    // The relocated prologue still dispatches its call to the same callee.
    auto original = h.original<int (*)()>();
    ASSERT_NE(original, nullptr);
    EXPECT_EQ(original(), LEADING_CALL_CALLEE_VALUE)
        << "The relocated leading call must still dispatch to its original callee.";

    // Restoring must put the original prologue back and re-expose the callee's value.
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(target(), LEADING_CALL_CALLEE_VALUE);
}

// A target whose bytes are not executable committed memory is refused under EVERY policy: Prologue::Relocate opts in to
// relocating a risky prologue shape, not to letting the backend decode non-code.
TEST(HookInlinePrologue, RelocatePolicyStillRefusesNonExecutableTarget)
{
    alignas(16) static std::uint8_t data_prologue[32] = {0x90, 0x90, 0x90, 0x90, 0x90, 0xC3};
    Result<Hook> r = inline_at(InlineRequest{.name = "RelocateData",
                                             .target = addr_of(data_prologue),
                                             .options = Options{.prologue = Prologue::Relocate}},
                               reinterpret_cast<void (*)()>(&noop_detour));
    ASSERT_FALSE(r.has_value()) << "Prologue::Relocate must not authorize a non-executable target.";
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// Each case hands inline_at a target the backend would decode straight into an access violation, and asserts DMK
// returns a typed Error instead. These in-process tests exercise both the MinGW VEH and MSVC SEH implementations.
namespace
{
    // Reserves two adjacent pages and commits only the first as executable, so the target's window runs off the end of
    // committed memory partway through. The uncommitted tail is the fault the backend would have taken.
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

    // Two adjacent committed executable pages, so a planted instruction can genuinely span the boundary between them
    // while every byte the pre-flight window covers remains valid. Two separate ScratchPages would not do: nothing
    // makes them adjacent.
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

    Result<Hook> try_install_at(std::uintptr_t target, const char *name)
    {
        return inline_at(InlineRequest{.name = name, .target = Address{target}},
                         reinterpret_cast<void (*)()>(&noop_detour));
    }

    /// Plants `mov eax, 1; ret` at @p page offset 0: a complete leaf function, long enough for either patch form.
    void plant_leaf_function(dmk_test::ScratchPage &page) noexcept
    {
        page.put(0, {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3});
        FlushInstructionCache(GetCurrentProcess(), page.base(), dmk_test::ScratchPage::PAGE_SIZE);
    }
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

// Committed and readable, but not executable: the backend would decode a data page as instructions.
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

// PAGE_GUARD is the case a protection-bit check alone cannot catch: the region reports execute access, and the fault
// only appears when the bytes are touched. The gate touches them under the guard, so this must fail closed rather than
// arm a trap the backend would spring.
TEST(InlineHookFaultProof, PageGuardReturnsTypedFailure)
{
    void *page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page, nullptr);
    std::memset(page, 0x90, 0x1000);
    DWORD old = 0;
    ASSERT_NE(VirtualProtect(page, 0x1000, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old), 0);

    Result<Hook> r = try_install_at(reinterpret_cast<std::uintptr_t>(page), "GuardPageTarget");
    ASSERT_FALSE(r.has_value()) << "a PAGE_GUARD target must not be hooked";
    // Refused on the protection verdict, not by tripping the guard: the executable-range gate reads PAGE_GUARD out of
    // the region's protection and rejects before the window is touched. That ordering matters -- touching a guard page
    // consumes the host's fence, and a pre-flight must not have that side effect on a target it goes on to refuse.
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

// An instruction that spans a page boundary is ordinary code when both pages are valid, so the window gate must admit
// it rather than refuse on the boundary alone. This is the false-refusal control for the page-crossing cases above:
// those prove a window running into an INVALID page is refused, and this proves the crossing itself is not the reason.
// The prologue's `mov eax, imm32` starts three bytes before the boundary and ends one byte after it, so the backend
// steals and relocates an instruction that no single page contains.
TEST(InlineHookFaultProof, InstructionStraddlingTwoValidPagesIsHooked)
{
    AdjacentExecutablePages region;
    ASSERT_TRUE(region.ok());

    constexpr std::size_t mov_eax_imm32_length = 5;
    const std::uintptr_t entry = region.boundary() - 3;
    region.put(entry, {0xB8, static_cast<std::uint8_t>(LEADING_CALL_CALLEE_VALUE & 0xFF),
                       static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 8) & 0xFF),
                       static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 16) & 0xFF),
                       static_cast<std::uint8_t>((LEADING_CALL_CALLEE_VALUE >> 24) & 0xFF), 0xC3});
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(entry), 16);

    // Assert the straddle rather than assume it: the instruction must begin on the first page and end on the second,
    // or this proves nothing about page-crossing code.
    ASSERT_LT(entry, region.boundary());
    ASSERT_GT(entry + mov_eax_imm32_length, region.boundary());

    auto target = reinterpret_cast<int (*)()>(entry);
    ASSERT_EQ(target(), LEADING_CALL_CALLEE_VALUE) << "control: the straddling function runs before any hook";

    Result<Hook> r = inline_at(InlineRequest{.name = "StraddlingInstruction", .target = Address{entry}},
                               reinterpret_cast<void (*)()>(&leading_call_detour));
    ASSERT_TRUE(r.has_value()) << "an instruction spanning two valid pages must not be refused: "
                               << r.error().message();
    Hook h = std::move(*r);

    EXPECT_EQ(target(), LEADING_CALL_DETOUR_VALUE);

    // The stolen instruction crossed the boundary intact: the trampoline still yields the original value.
    auto original = h.original<int (*)()>();
    ASSERT_NE(original, nullptr);
    EXPECT_EQ(original(), LEADING_CALL_CALLEE_VALUE);
}

// The window bound is a mirrored backend constant, so it is pinned by a test: a target with the full window of
// executable committed bytes behind it is NOT refused by the gate, while one four bytes short of it is. Asserts the
// gate's verdict rather than overall install success, because a fully-readable target may still legitimately fail
// inside the backend (for example when its trampoline cannot be allocated).
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

// A directly registered function bound is authoritative: even executable bytes cannot be patched past its end. The
// bound must accommodate the LARGER of the backend's two patch forms, because which form runs is decided inside the
// backend after this validation. A function only the near jump could hook is refused rather than risk the indirect
// fallback writing past its end, so the boundary is pinned on both sides here.
TEST(InlineHookFaultProof, ReliableFunctionBoundOverrunReturnsTypedFailure)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0, {0x90, 0x90, 0x90, 0x90, 0xC3});

    // One byte short of the fallback form's patch: refused, even though the near jump alone would have fitted.
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
        RuntimeFunctionRegistration registration{page.addr(), 0,
                                                 static_cast<DWORD>(DetourModKit::detail::BACKEND_FALLBACK_MIN_PATCH)};
        ASSERT_TRUE(registration.ok());

        const DetourModKit::detail::TargetWindowResult verdict =
            DetourModKit::detail::validate_backend_steal_window(page.addr());
        EXPECT_NE(verdict.verdict, DetourModKit::detail::TargetWindowVerdict::BoundOverrun)
            << "a function long enough for either patch form must not be refused on its bound";
    }
}

// Code with no unwind metadata (a JIT buffer, or a leaf function) must NOT be rejected: absence of .pdata is not
// evidence of an unsafe target. This is the load-bearing non-rejection control for the unwind-bound check.
TEST(InlineHookFaultProof, LeafCodeWithoutPdataIsNotRejected)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf_function(page);

    Result<Hook> r = try_install_at(page.addr(0), "LeafNoPdata");
    ASSERT_TRUE(r.has_value()) << "code without unwind metadata must not be refused: " << r.error().message();
    EXPECT_TRUE(static_cast<bool>(*r));
}

// The range-aware filter must not swallow a DMK fault outside the declared span. A guarded read of an unrelated
// no-access page still reports its own failure while hook installs continue to work, proving the hook gate's guard did
// not install a process-wide catch-all.
TEST(InlineHookFaultProof, UnrelatedFaultIsNotSwallowedByTheHookGate)
{
    void *unrelated = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(unrelated, nullptr);

    const Address probe{reinterpret_cast<std::uintptr_t>(unrelated)};
    const Result<std::uint64_t> read = memory::read<std::uint64_t>(probe);
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, ErrorCode::ReadFaulted);

    // A normal install still succeeds afterwards: the guard is scoped, not sticky.
    Result<Hook> r = inline_at(InlineRequest{.name = "AfterUnrelatedFault", .target = addr_of(&echo)}, &echo_detour);
    EXPECT_TRUE(r.has_value()) << "an unrelated contained fault must not disturb later hook installs";
    VirtualFree(unrelated, 0, MEM_RELEASE);
}

// A page this process inline-hooked and then released must not poison its own address: the backend's execution trap is
// scoped to one patch transaction, so once the hook is torn down a later fault at a recycled address belongs to whoever
// owns it now and must surface as a typed failure rather than retry against a stale trap.
TEST(InlineHookFaultProof, UnrelatedFaultAtRecycledHookedPageSurfaces)
{
    void *base = nullptr;
    {
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf_function(page);
        base = page.base();

        // The hook is destroyed before the page: the prologue is restored and the trap retired while the page is still
        // mapped, which is the state a released page is required to be in.
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

    ASSERT_NE(VirtualFree(page.base(), dmk_test::ScratchPage::PAGE_SIZE, MEM_DECOMMIT), 0);
    const Result<void> disabled = hook.disable();
    ASSERT_FALSE(disabled.has_value());
    EXPECT_EQ(disabled.error().code, ErrorCode::DisableFailed);
    EXPECT_TRUE(hook.is_enabled());
}

// INLINE duplicate detection (Options::fail_if_already_hooked + is_target_hooked)

TEST(HookInline, FailIfAlreadyHookedRefusesSecondHook)
{
    Result<Hook> first =
        inline_at(InlineRequest{.name = "DupBase", .target = addr_of(&real_hook_target_add)}, &real_hook_detour_add);
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook base = std::move(*first);

    Result<Hook> second = inline_at(InlineRequest{.name = "DupSecond",
                                                  .target = addr_of(&real_hook_target_add),
                                                  .options = Options{.fail_if_already_hooked = true}},
                                    &real_hook_detour_add);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::TargetAlreadyHookedInProcess);
}

TEST(HookInline, DefaultModeLayersSecondHook)
{
    Result<Hook> first =
        inline_at(InlineRequest{.name = "LayerBase", .target = addr_of(&real_hook_target_mul)}, &real_hook_detour_add);
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook base = std::move(*first);

    // Default mode (fail_if_already_hooked = false): the second hook simply layers on top.
    Result<Hook> second = inline_at(InlineRequest{.name = "LayerSecond", .target = addr_of(&real_hook_target_mul)},
                                    &real_hook_detour_add);
    ASSERT_TRUE(second.has_value()) << second.error().message();
    Hook layer = std::move(*second);
    // Teardown is newest-first by natural reverse-order destruction: layer (declared last) is destroyed before base.
}

// A foreign inline hook can redirect a prologue with a `mov rax, imm64; jmp rax` absolute-jump trampoline
// (48 B8 <imm64> FF E0) when its detour is beyond rel32 reach and it does not use the FF 25 RIP-relative form. The
// pre-flight foreign-JMP heuristic must decode that shape and, under fail_if_already_hooked, refuse.
TEST(HookInline, FailIfAlreadyHookedDetectsAbsJumpTrampoline)
{
    // Destination in a different module (kernel32) so the redirect classifies as HookedByOtherModule (foreign).
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(kernel32, nullptr);
    const auto foreign_destination = reinterpret_cast<std::uintptr_t>(GetProcAddress(kernel32, "Sleep"));
    ASSERT_NE(foreign_destination, 0u);

    // Plant 48 B8 <foreign_destination> FF E0 on an executable page. It must be real executable memory: the pre-flight
    // proves the target is code the backend could decode before it asks whether something else has already hooked it,
    // and a real foreign-hooked function is always executable. Nothing installs here (the heuristic refuses first), so
    // the page carries no backend trap and is safe to free.
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0, {0x48, 0xB8}); // mov rax, imm64
    std::memcpy(reinterpret_cast<void *>(page.addr(2)), &foreign_destination, sizeof(foreign_destination));
    page.put(10, {0xFF, 0xE0}); // jmp rax

    Result<Hook> r = inline_at(InlineRequest{.name = "AbsJumpForeign",
                                             .target = Address{page.addr(0)},
                                             .options = Options{.fail_if_already_hooked = true}},
                               &echo_detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetAlreadyHookedInProcess);
}

// is_target_hooked(Address)

TEST(HookLedger, IsTargetHookedFalseForZero)
{
    EXPECT_FALSE(is_target_hooked(Address{std::uintptr_t{0}}));
}

TEST(HookLedger, IsTargetHookedTrueWhileLiveFalseAfterDrop)
{
    const Address target = addr_of(&real_hook_target_mul);
    EXPECT_FALSE(is_target_hooked(target));
    {
        Result<Hook> r = inline_at(InlineRequest{.name = "LedgerLive", .target = target}, &real_hook_detour_add);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        EXPECT_TRUE(is_target_hooked(target));
    }
    // The hook handle dropped, restoring the prologue and clearing the ledger entry.
    EXPECT_FALSE(is_target_hooked(target));
}

TEST(HookLedger, SameTargetReservationsWaitForCommit)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();
    static int target_marker = 0;
    const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(&target_marker);

    const DetourModKit::detail::HookLedger::Reservation first = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(first.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ASSERT_NE(first.id, 0u);

    std::atomic<bool> second_started{false};
    std::atomic<bool> second_returned{false};
    std::atomic<bool> allow_second_cleanup{false};
    std::uint64_t second_id = 0;

    auto wait_for_flag = [](const std::atomic<bool> &flag, int attempts) -> bool
    {
        for (int i = 0; i < attempts; ++i)
        {
            if (flag.load(std::memory_order_acquire))
            {
                return true;
            }
            Sleep(1);
        }
        return flag.load(std::memory_order_acquire);
    };

    std::thread waiter(
        [&]
        {
            second_started.store(true, std::memory_order_release);
            const DetourModKit::detail::HookLedger::Reservation second = ledger.try_reserve_hook(target, false);
            EXPECT_EQ(second.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
            EXPECT_TRUE(second.preexisting);
            second_id = second.id;
            second_returned.store(true, std::memory_order_release);
            while (!allow_second_cleanup.load(std::memory_order_acquire))
            {
                Sleep(1);
            }
            ledger.commit_hook(target, second.id);
            (void)ledger.release_hook(target, second.id);
        });

    // Wait for the waiter to enter try_reserve_hook. If it does not start in time, tear it down safely before
    // failing: an early return here would destroy a still-joinable std::thread and call std::terminate. Committing
    // first unblocks the waiter's pending reservation so the join cannot hang, and allow_second_cleanup releases its
    // post-reservation cleanup loop.
    if (!wait_for_flag(second_started, 100))
    {
        ledger.commit_hook(target, first.id);
        allow_second_cleanup.store(true, std::memory_order_release);
        waiter.join();
        (void)ledger.release_hook(target, first.id);
        FAIL() << "waiter thread did not start within the timeout";
    }
    EXPECT_FALSE(wait_for_flag(second_returned, 20));

    ledger.commit_hook(target, first.id);
    const bool second_completed = wait_for_flag(second_returned, 1000);
    EXPECT_TRUE(second_completed);
    EXPECT_NE(second_id, 0u);
    if (second_completed)
    {
        EXPECT_EQ(ledger.release_hook(target, first.id), 1u);
    }
    else
    {
        (void)ledger.release_hook(target, first.id);
    }

    allow_second_cleanup.store(true, std::memory_order_release);
    waiter.join();
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// Hook::call<Ret>(args): the guarded trampoline call, with the by-value-ABI lvalue case

TEST(HookCall, GuardedCallReachesOriginalThroughTrampoline)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "GuardedCall", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    // The detour is active so a direct echo(7) is 107; the guarded call routes through the trampoline to the
    // original 7.
    EXPECT_EQ(call_unfolded(&echo, 7), 107);
    EXPECT_EQ(h.call<int>(7), 7);
}

// CRITICAL by-value-ABI case: passing an lvalue int must still go BY VALUE. A forwarding-reference call() would deduce
// a reference type and reconstruct a reference-parameter function pointer, passing a hidden pointer where the by-value
// trampoline expects the scalar -- silent, value-category-dependent ABI UB. By value, an lvalue argument round-trips.
TEST(HookCall, GuardedCallPassesLvalueByValue)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "GuardedLvalue", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    int lv = 7;
    EXPECT_EQ(h.call<int>(lv), 7) << "lvalue int must be passed by value through the trampoline";
}

// After disable(), call() observes an inactive hook and returns a value-initialized Ret (0 for int).
TEST(HookCall, GuardedCallReturnsValueInitWhenInactive)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "GuardedInactive", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(h.call<int>(7), int{});
}

// operator=(Hook&&) is the second teardown entry point the shared call gate must cover: adopting the source's hook
// transfers its gate atomically, tears down the overwritten hook (restoring its old target), and leaves the moved-into
// handle's guarded call() dispatching through the SOURCE's trampoline while the moved-from source is inert.
TEST(HookCall, MoveAssignTransfersGuardedCallAndTearsDownOld)
{
    Result<Hook> first = inline_at(InlineRequest{.name = "MoveAssignOld", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook dest = std::move(*first);
    EXPECT_EQ(call_unfolded(&echo, 7), 107); // echo hooked by dest

    Result<Hook> second = inline_at(InlineRequest{.name = "MoveAssignNew", .target = addr_of(&real_hook_target_add)},
                                    &real_hook_detour_add);
    ASSERT_TRUE(second.has_value()) << second.error().message();
    Hook src = std::move(*second);

    // Move-assign src over dest: dest's old echo hook is torn down (echo restored) and dest adopts src's hook + gate.
    dest = std::move(src);
    // dest's overwritten echo hook was restored by the discard teardown
    EXPECT_EQ(call_unfolded(&echo, 7), 7);
    EXPECT_FALSE(static_cast<bool>(src)); // src is moved-from / inert
    EXPECT_EQ(src.call<int>(3), int{});   // a guarded call on the moved-from handle is a defined no-op (empty gate)

    ASSERT_TRUE(static_cast<bool>(dest));
    EXPECT_EQ(call_unfolded(&real_hook_target_add, 2, 3), 2 + 3 + 1000); // dest's adopted detour is active
    EXPECT_EQ(dest.call<int>(2, 3), 5); // guarded call reaches the original through the trampoline
}

// try_call is the fail-closed-distinguishing sibling of call: it returns Result<Ret> so a suppressed call surfaces as
// an error rather than a value-initialized Ret a caller cannot tell apart from a genuine one.
TEST(HookCall, TryCallReachesOriginalAndReturnsValue)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "TryCallActive", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    const Result<int> got = h.try_call<int>(7);
    ASSERT_TRUE(got.has_value()) << got.error().message();
    EXPECT_EQ(*got, 7);
}

// The ambiguity call() cannot resolve: after disable() call<int>(7) returns int{} (0), which a real original returning
// 0 would also produce. try_call keeps the suppression in the error channel so the two cases are distinguishable.
TEST(HookCall, TryCallFailsClosedWhenInactive)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "TryCallInactive", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(h.call<int>(7), int{});
    const Result<int> got = h.try_call<int>(7);
    ASSERT_FALSE(got.has_value());
    EXPECT_EQ(got.error().code, ErrorCode::InvalidHookState);
}

// try_call<void> carries no value but still reports whether the call dispatched, so a void original can be guarded too.
TEST(HookCall, TryCallVoidReportsDispatchAndFailClosed)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "TryCallVoid", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    const Result<void> active = h.try_call<void, int>(7);
    EXPECT_TRUE(active.has_value()) << (active ? "" : active.error().message());

    ASSERT_TRUE(h.disable().has_value());
    const Result<void> inactive = h.try_call<void, int>(7);
    ASSERT_FALSE(inactive.has_value());
    EXPECT_EQ(inactive.error().code, ErrorCode::InvalidHookState);
}

// A moved-from handle has an empty gate: try_call fails closed just as call() no-ops, but reports it as an error.
TEST(HookCall, TryCallOnMovedFromHandleFailsClosed)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "TryCallMovedFrom", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    Hook moved = std::move(h);

    const Result<int> got = h.try_call<int>(3);
    ASSERT_FALSE(got.has_value());
    EXPECT_EQ(got.error().code, ErrorCode::InvalidHookState);
}

// release(): detach but stay installed for the process lifetime

TEST(HookRelease, ReleaseLeavesHookInstalledAndFiring)
{
    // Dedicated leak target: this detour stays installed for the process lifetime, so no other test may share it.
    const Address target = addr_of(&leak_target_inline);
    EXPECT_EQ(call_unfolded(&leak_target_inline, 7), 7); // sanity: clean before the hook
    Result<Hook> r = inline_at(InlineRequest{.name = "Released", .target = target}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    h.release();
    EXPECT_FALSE(static_cast<bool>(h));    // handle disengaged
    EXPECT_TRUE(is_target_hooked(target)); // still installed (leaked intentionally; that is the contract)
    EXPECT_EQ(call_unfolded(&leak_target_inline, 7), 107); // the detour still fires
    // No restore: leak_target_inline stays hooked for the process lifetime. Intentional leak.
}

// RAII teardown + moved-from inertness

TEST(HookTeardown, DestructorRestoresPrologue)
{
    EXPECT_EQ(call_unfolded(&echo, 7), 7); // sanity: unhooked
    {
        Result<Hook> r = inline_at(InlineRequest{.name = "TeardownRestore", .target = addr_of(&echo)}, &echo_detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        EXPECT_EQ(call_unfolded(&echo, 7), 107); // hooked
    }
    EXPECT_EQ(call_unfolded(&echo, 7), 7); // prologue restored on scope exit
}

TEST(HookTeardown, MovedFromHandleIsInert)
{
    EXPECT_EQ(call_unfolded(&echo, 7), 7);
    {
        Result<Hook> r = inline_at(InlineRequest{.name = "MovedFrom", .target = addr_of(&echo)}, &echo_detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook a = std::move(*r);
        Hook b = std::move(a);
        // Only b owns the live hook now; a is inert and must not double-unhook or crash.
        EXPECT_FALSE(static_cast<bool>(a));
        EXPECT_TRUE(static_cast<bool>(b));
        // call() through a disengaged handle must be a defined no-op returning the inactive default, not a null
        // dereference of the moved-out Impl (the guarded twin of original<Fn>(), which is already inert here).
        EXPECT_EQ(a.call<int>(7), int{});
        EXPECT_EQ(call_unfolded(&echo, 7), 107);
    } // only b unhooks; a's destructor is a no-op
    EXPECT_EQ(call_unfolded(&echo, 7), 7);
}

// MID create / lifecycle (the MidContext-accessor semantics live in test_mid_hook_context.cpp)

TEST(HookMid, CreateSuccessAutoEnabled)
{
    auto detour = [](MidContext &) { s_mid_detour_calls.fetch_add(1, std::memory_order_relaxed); };
    Result<Hook> r = mid_at(MidRequest{.name = "MidCreate", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(h));
    EXPECT_TRUE(h.is_enabled());
    EXPECT_EQ(h.name(), "MidCreate");
}

TEST(HookMid, CreateInvalidTargetAddress)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidBadTarget", .target = Address{std::uintptr_t{0}}}, detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidTargetAddress);
}

TEST(HookMid, CreateNullDetour)
{
    MidHookFn null_detour = nullptr;
    Result<Hook> r = mid_at(MidRequest{.name = "MidNullDetour", .target = addr_of(&real_hook_target_add)}, null_detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidDetourFunction);
}

TEST(HookMid, CreateEmptyName)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidArg);
}

TEST(HookMid, EnableDisableToggles)
{
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(MidRequest{.name = "MidToggle", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    EXPECT_TRUE(h.is_enabled());
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_FALSE(h.is_enabled());
    ASSERT_TRUE(h.enable().has_value());
    EXPECT_TRUE(h.is_enabled());
}

// A mid hook has no callable original; original<Fn>() is nullptr for it.
TEST(HookMid, OriginalIsNullForMidHook)
{
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidNoOriginal", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    EXPECT_EQ(h.original<EchoFn>(), nullptr);
}

TEST(HookMid, FailIfAlreadyHookedRefusesSecondMid)
{
    auto detour = [](MidContext &) {};
    Result<Hook> first = mid_at(MidRequest{.name = "MidDupBase", .target = addr_of(&real_hook_target_mul)}, detour);
    ASSERT_TRUE(first.has_value()) << first.error().message();
    Hook base = std::move(*first);

    Result<Hook> second = mid_at(MidRequest{.name = "MidDupSecond",
                                            .target = addr_of(&real_hook_target_mul),
                                            .options = Options{.fail_if_already_hooked = true}},
                                 detour);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::TargetAlreadyHookedInProcess);
}

// Cross-type duplicate detection: a mid hook over an existing inline hook on the same target is refused under strict
// mode (the ledger check is type-agnostic, overlapping the same prologue bytes).
TEST(HookMid, FailIfAlreadyHookedRefusesOverInline)
{
    Result<Hook> inl = inline_at(InlineRequest{.name = "MidOverInlineBase", .target = addr_of(&real_hook_target_add)},
                                 &real_hook_detour_add);
    ASSERT_TRUE(inl.has_value()) << inl.error().message();
    Hook base = std::move(*inl);

    auto detour = [](MidContext &) {};
    Result<Hook> mid = mid_at(MidRequest{.name = "MidOverInline",
                                         .target = addr_of(&real_hook_target_add),
                                         .options = Options{.fail_if_already_hooked = true}},
                              detour);
    ASSERT_FALSE(mid.has_value());
    EXPECT_EQ(mid.error().code, ErrorCode::TargetAlreadyHookedInProcess);
}

// A mid hook patches the same prologue through the same pre-flight, so the breakpoint refusal must hold there too.
// Planted on an executable page so the refusal comes from the breakpoint classifier, not the steal-window gate.
TEST(HookMid, DefaultFailsOnInt3Prologue)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0, {0xCC, 0xC3, 0x90, 0x90});
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidInt3Prologue", .target = Address{page.addr(0)}}, detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

// The mid pre-flight shares the inline steal-window gate: a target that is not executable committed memory is refused
// before the backend can decode it.
TEST(HookMid, DefaultRefusesNonExecutableTarget)
{
    alignas(16) static std::uint8_t mid_data_prologue[32] = {0x90, 0x90, 0x90, 0x90, 0x90, 0xC3};
    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidDataTarget", .target = addr_of(mid_data_prologue)}, detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TargetPrologueUnsafe);
}

TEST(HookMid, RealCreateModifiesArgViaRcx)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    // A mid hook installed at the entry overwrites rcx (the first integer arg) before the body homes it.
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(MidRequest{.name = "MidRealCreate", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    // unhooked add(2, 3) == 5; with rcx := 1000 the resumed body computes 1000 + 3.
    EXPECT_EQ(call_unfolded(&real_hook_target_add, 2, 3), 1000 + 3);
}

TEST(HookMid, RealCreateDisabledRestoresOriginal)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(MidRequest{.name = "MidRealDisabled", .target = addr_of(&real_hook_target_add)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    EXPECT_EQ(call_unfolded(&real_hook_target_add, 2, 3), 1000 + 3);
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(call_unfolded(&real_hook_target_add, 2, 3), 5); // original body again
}

TEST(HookMid, TeardownRestoresOriginal)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 20);
    {
        auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 10; };
        Result<Hook> r = mid_at(MidRequest{.name = "MidTeardown", .target = addr_of(&real_hook_target_mul)}, detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 10 * 5);
    }
    EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 20); // prologue restored
}

TEST(HookMid, ReleaseLeavesMidInstalled)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    // Dedicated leak target: the released mid hook stays installed for the process lifetime.
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; };
    Result<Hook> r = mid_at(MidRequest{.name = "MidReleased", .target = addr_of(&leak_target_mid)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    h.release();
    EXPECT_FALSE(static_cast<bool>(h));
    EXPECT_TRUE(is_target_hooked(addr_of(&leak_target_mid)));
    EXPECT_EQ(leak_target_mid(2, 3), 1000 + 3); // still fires
}

TEST(HookMid, MovedFromMidHandleIsInert)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 20);
    {
        auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 10; };
        Result<Hook> r = mid_at(MidRequest{.name = "MidMovedFrom", .target = addr_of(&real_hook_target_mul)}, detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook a = std::move(*r);
        Hook b = std::move(a);
        EXPECT_FALSE(static_cast<bool>(a));
        EXPECT_TRUE(static_cast<bool>(b));
        EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 10 * 5);
    }
    EXPECT_EQ(call_unfolded(&real_hook_target_mul, 4, 5), 20);
}

// install_all: declarative table with severity + ordering + rollback
namespace
{
    // Real, hookable functions used as install_all scan targets. Their first bytes are scanned by AOB so the deferred
    // OwnedScanRequest resolves to the function entry. DMK_TEST_NOINLINE keeps them out of line so they have a real
    // prologue to hook.
    DMK_TEST_NOINLINE int install_target_one(int x)
    {
        volatile int r = x + 1;
        return r;
    }

    DMK_TEST_NOINLINE int install_target_two(int x)
    {
        volatile int r = x + 2;
        return r;
    }

    int install_detour_one(int x)
    {
        return x + 1000;
    }
    int install_detour_two(int x)
    {
        return x + 2000;
    }

    // Builds an AOB string from the first @p count bytes at @p addr, so a Direct candidate over a Region covering that
    // address resolves uniquely to the function entry.
    [[nodiscard]] std::string aob_of(std::uintptr_t addr, std::size_t count)
    {
        const auto *bytes = reinterpret_cast<const unsigned char *>(addr);
        std::string aob;
        for (std::size_t i = 0; i < count; ++i)
        {
            if (i > 0)
            {
                aob += ' ';
            }
            char hex[4];
            std::snprintf(hex, sizeof(hex), "%02X", bytes[i]);
            aob += hex;
        }
        return aob;
    }

    // An OwnedScanRequest whose Direct candidate resolves uniquely to @p fn's entry, scoped to @p fn's own body. The
    // function pointer is reinterpret_cast to an integer address since a function pointer does not convert to void*.
    [[nodiscard]] scan::OwnedScanRequest resolvable_request(std::string name, EchoFn fn, std::size_t aob_len = 16)
    {
        const auto addr = reinterpret_cast<std::uintptr_t>(fn);
        scan::OwnedScanRequest req;
        req.ladder.push_back(
            scan::Candidate::direct(std::move(name), scan::Pattern::compile(aob_of(addr, aob_len)).value()));
        req.scope = Region{Address{addr}, aob_len + 16};
        return req;
    }

    // An OwnedScanRequest that cannot resolve: a Direct candidate for a byte pattern that is absent from its scope.
    [[nodiscard]] scan::OwnedScanRequest unresolvable_request(std::string name)
    {
        scan::OwnedScanRequest req;
        req.ladder.push_back(scan::Candidate::direct(
            std::move(name), scan::Pattern::compile("FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF").value()));
        req.scope = Region{Address{reinterpret_cast<std::uintptr_t>(&install_target_one)}, 32};
        return req;
    }
} // namespace

TEST(HookInstallAll, TwoMandatoryRowsBothResolve)
{
    const HookSpec table[] = {
        HookSpec::inline_hook("RowOne", resolvable_request("RowOnePat", &install_target_one), &install_detour_one,
                              Severity::Mandatory),
        HookSpec::inline_hook("RowTwo", resolvable_request("RowTwoPat", &install_target_two), &install_detour_two,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_TRUE(res.has_value()) << res.error().message();
    ASSERT_EQ(res->size(), 2u);

    EXPECT_EQ((*res)[0].name, "RowOne");
    EXPECT_EQ((*res)[0].severity, Severity::Mandatory);
    EXPECT_TRUE((*res)[0].hook.has_value()) << (*res)[0].hook.error().message();

    EXPECT_EQ((*res)[1].name, "RowTwo");
    EXPECT_TRUE((*res)[1].hook.has_value()) << (*res)[1].hook.error().message();
}

TEST(HookInstallAll, MandatoryMissFailsWholeCall)
{
    const HookSpec table[] = {
        HookSpec::inline_hook("MandHit", resolvable_request("MandHitPat", &install_target_one), &install_detour_one,
                              Severity::Mandatory),
        HookSpec::inline_hook("MandMiss", unresolvable_request("MandMissPat"), &install_detour_two,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::NoMatch);
    // The prior Mandatory row that landed is rolled back; nothing stays installed.
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_one)));
}

TEST(HookInstallAll, BestEffortMissStillSucceedsWithMandatoryHit)
{
    const HookSpec table[] = {
        HookSpec::inline_hook("BeMiss", unresolvable_request("BeMissPat"), &install_detour_one, Severity::BestEffort),
        HookSpec::inline_hook("MandHit2", resolvable_request("MandHit2Pat", &install_target_two), &install_detour_two,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_TRUE(res.has_value()) << res.error().message();
    ASSERT_EQ(res->size(), 2u);

    // The best-effort row missed: its outcome carries an Error but the call still succeeded.
    EXPECT_EQ((*res)[0].name, "BeMiss");
    EXPECT_EQ((*res)[0].severity, Severity::BestEffort);
    EXPECT_FALSE((*res)[0].hook.has_value());
    EXPECT_EQ((*res)[0].hook.error().code, ErrorCode::NoMatch);

    // The mandatory row landed.
    EXPECT_EQ((*res)[1].name, "MandHit2");
    EXPECT_TRUE((*res)[1].hook.has_value()) << (*res)[1].hook.error().message();
}

// install_all shares the never-terminate contract with scan::resolve_batch: it is noexcept and, under true
// out-of-memory, reports the failure in its own result shape rather than terminating the host. Its shape is a
// single Result<vector<InstallOutcome>>, so a container-allocation failure surfaces as unexpected(Error{OutOfMemory}),
// not an empty vector. Pin the noexcept property at compile time so a signature change cannot silently drop it.
static_assert(noexcept(install_all(std::span<const HookSpec>{})),
              "hook::install_all must be noexcept: it degrades under OOM rather than terminating the host.");

// A declarative table row carries its own install Options, which install_all applies verbatim. A row that opts into
// fail_if_already_hooked refuses an already-hooked target, while a default-Options row layers on top -- the paired
// strict/permissive rows below prove the row's policy reaches the install rather than being overwritten by a container
// default.
TEST(HookInstallAll, PerRowOptionsControlFailIfAlreadyHooked)
{
    // Pre-hook the target so the process-wide ledger reports it hooked.
    Result<Hook> pre =
        inline_at(InlineRequest{.name = "PerRowPreHook", .target = addr_of(&install_target_one)}, &install_detour_one);
    ASSERT_TRUE(pre.has_value()) << pre.error().message();
    Hook keep = std::move(*pre);

    // A BestEffort row that opts into fail_if_already_hooked through its per-row Options: it must refuse the
    // already-hooked target rather than layer.
    const HookSpec strict_table[] = {
        HookSpec::inline_hook("StrictRow", resolvable_request("StrictRowPat", &install_target_one), &install_detour_two,
                              Severity::BestEffort, Options{.fail_if_already_hooked = true}),
    };
    Result<std::vector<InstallOutcome>> strict = install_all(strict_table);
    ASSERT_TRUE(strict.has_value()) << strict.error().message();
    ASSERT_EQ(strict->size(), 1u);
    EXPECT_FALSE((*strict)[0].hook.has_value())
        << "a per-row fail_if_already_hooked must refuse the already-hooked target";

    // Control: the same row with the default Options layers on top and succeeds, so the refusal above is attributable
    // to the per-row policy, not to the target being unhookable.
    const HookSpec permissive_table[] = {
        HookSpec::inline_hook("PermissiveRow", resolvable_request("PermissiveRowPat", &install_target_one),
                              &install_detour_two, Severity::BestEffort),
    };
    Result<std::vector<InstallOutcome>> permissive = install_all(permissive_table);
    ASSERT_TRUE(permissive.has_value()) << permissive.error().message();
    ASSERT_EQ(permissive->size(), 1u);
    EXPECT_TRUE((*permissive)[0].hook.has_value())
        << "the default-Options row must still layer on top of the already-hooked target";
}

TEST(HookInstallAll, AllocFailureReturnsOutOfMemoryWithoutEscaping)
{
    const HookSpec table[] = {
        HookSpec::inline_hook("OomRow", resolvable_request("OomRowPat", &install_target_one), &install_detour_one,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res;
    {
        // Budget 0: the first allocation (the outcomes container reserve) fails before any row is attempted, so
        // install_all catches the bad_alloc at its noexcept boundary and reports Error{OutOfMemory}.
        dmk_test::AllocFailScope fail(0);
        res = install_all(table);
    }

    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::OutOfMemory);
    // The container failed before the first row, so nothing was installed.
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_one)));
}

// On a mandatory miss, install_all rolls the already-installed rows back newest-first. A std::vector<InstallOutcome>
// unwind does not provide that teardown contract; install_all's InstallRollback guard pops back-to-front instead. The
// Removed lifecycle events make the teardown order observable without forcing a faulting repro.
TEST(HookInstallAll, MandatoryMissRollsBackNewestFirst)
{
    std::vector<std::string> removed;
    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&removed](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.transition == diagnostics::HookTransition::Removed)
            {
                removed.emplace_back(e.name);
            }
        });

    const HookSpec table[] = {
        HookSpec::inline_hook("RollbackOlder", resolvable_request("RbOlderPat", &install_target_one),
                              &install_detour_one, Severity::Mandatory),
        HookSpec::inline_hook("RollbackNewer", resolvable_request("RbNewerPat", &install_target_two),
                              &install_detour_two, Severity::Mandatory),
        HookSpec::inline_hook("RollbackMiss", unresolvable_request("RbMissPat"), &install_detour_one,
                              Severity::Mandatory),
    };

    Result<std::vector<InstallOutcome>> res = install_all(table);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::NoMatch);

    // Both installed rows rolled back cleanly...
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_one)));
    EXPECT_FALSE(is_target_hooked(addr_of(&install_target_two)));
    // ...and newest-first: RollbackNewer (installed second) was torn down before RollbackOlder.
    ASSERT_EQ(removed.size(), 2u);
    EXPECT_EQ(removed[0], "RollbackNewer");
    EXPECT_EQ(removed[1], "RollbackOlder");
}

// VMT object hooking (RAII VmtHook)

class VmtTestInterface
{
public:
    virtual ~VmtTestInterface() = default;
    virtual int compute(int a, int b) = 0;
    virtual int transform(int x) = 0;
};

class VmtTestTarget : public VmtTestInterface
{
public:
    int compute(int a, int b) override { return a + b; }
    int transform(int x) override { return x * 2; }
};

// VMT method-hook test fixtures. The per-method surface installs a detour straight into a cloned vtable slot, so a
// detour models the virtual method's real ABI: the object arrives as the leading integer argument (`this` in rcx under
// the Win64 ABI) with no calling-convention decoration, because x64 has a single convention. The detour reaches the
// original through the handle's typed original<Fn>(index) snapshot, so nothing here names the SafetyHook backend.
//
// The vtable index counts virtual functions only and excludes the ABI header, but the leading destructor slots are
// counted: the Itanium ABI (GCC/MinGW) emits two destructor entries (complete + deleting) ahead of the first declared
// method, while MSVC emits one, so compute/transform sit one slot higher under Itanium.
#if defined(_MSC_VER)
static constexpr std::size_t VMT_COMPUTE_INDEX = 1;
static constexpr std::size_t VMT_TRANSFORM_INDEX = 2;
#else
static constexpr std::size_t VMT_COMPUTE_INDEX = 2;
static constexpr std::size_t VMT_TRANSFORM_INDEX = 3;
#endif

using VmtComputeFn = int (*)(void *self, int a, int b);
using VmtTransformFn = int (*)(void *self, int x);

// The detours reach the original virtual method through the handle, so the fixtures publish the live VmtHook* the way
// the inline-hook detours publish their Hook*. A null handle means "unhooked", so the detour falls back to a plain
// marker rather than dereferencing a stale pointer.
static VmtHook *s_method_vmt = nullptr;

class MethodVmtScope
{
public:
    explicit MethodVmtScope(VmtHook &hook) noexcept;

    ~MethodVmtScope() noexcept;

    MethodVmtScope(const MethodVmtScope &) = delete;
    MethodVmtScope &operator=(const MethodVmtScope &) = delete;
    MethodVmtScope(MethodVmtScope &&) = delete;
    MethodVmtScope &operator=(MethodVmtScope &&) = delete;

private:
    VmtHook *m_previous;
};

MethodVmtScope::MethodVmtScope(VmtHook &hook) noexcept : m_previous(s_method_vmt)
{
    s_method_vmt = &hook;
}

MethodVmtScope::~MethodVmtScope() noexcept
{
    s_method_vmt = m_previous;
}

// Hooked compute: original(this, a, b) + 1000.
int vmt_detour_compute(void *self, int a, int b)
{
    if (s_method_vmt == nullptr)
    {
        return -1;
    }
    const VmtComputeFn original = s_method_vmt->original<VmtComputeFn>(VMT_COMPUTE_INDEX);
    if (original == nullptr)
    {
        return -1;
    }
    return original(self, a, b) + 1000;
}

// Hooked transform: original(this, x) + 500, used to prove two independent slots hook without cross-talk.
int vmt_detour_transform(void *self, int x)
{
    if (s_method_vmt == nullptr)
    {
        return -1;
    }
    const VmtTransformFn original = s_method_vmt->original<VmtTransformFn>(VMT_TRANSFORM_INDEX);
    if (original == nullptr)
    {
        return -1;
    }
    return original(self, x) + 500;
}

// Dispatch the hook-sensitive checks through the VmtTestInterface base at a DMK_TEST_NOINLINE boundary. A VMT hook
// only takes effect through the object's (swapped) vtable, so a call the optimizer can devirtualize to the concrete
// VmtTestTarget would bypass the clone and silently stop testing the hook. Passing a base-class pointer into a
// noinline function that only sees VmtTestInterface forces the real runtime vtable dispatch, exactly as a game
// engine's polymorphic call would, on both the debug and any optimized test build.
DMK_TEST_NOINLINE int dispatch_compute(VmtTestInterface *object, int a, int b)
{
    return object->compute(a, b);
}

DMK_TEST_NOINLINE int dispatch_transform(VmtTestInterface *object, int x)
{
    return object->transform(x);
}

TEST(HookVmt, CreateSuccess)
{
    auto target = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("TestVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(vh));
    EXPECT_EQ(vh.name(), "TestVmt");
}

TEST(HookVmt, CreateNullObject)
{
    Result<VmtHook> r = vmt_for("NullVmt", nullptr);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
}

// A corrupted or forged vptr can point at an arbitrarily long run of executable-looking qwords. count_vmt_method_slots
// hard-caps the slot walk (mirroring the bounded RTTI walkers) so it cannot spin unbounded, failing closed on the
// malformed seed object -- which vmt_for surfaces as InvalidObject. Filling well past the internal cap with an
// executable address makes every slot read as callable, so the walk terminates only at the cap.
TEST(HookVmt, SlotWalkHardCapRejectsMalformedVtable)
{
    constexpr std::size_t OVER_CAP = 5000; // exceeds the internal MAX_VMT_SLOTS (4096)
    static std::vector<std::uintptr_t> fake_vtable(OVER_CAP, reinterpret_cast<std::uintptr_t>(&echo));
    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(fake_vtable.data())};

    Result<VmtHook> r = vmt_for("MalformedVtable", &object);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
}

// The VMT pre-flight (count_vmt_method_slots) proves only the forward slots are mapped, but a clone must also carry the
// ABI RTTI header prefix immediately below the vptr, so vmt_for captures [vptr - VMT_HEADER*8, vptr) too. An object
// whose header prefix straddles an unmapped page must fail closed rather than fault the host inside that capture. This
// builds exactly that geometry: two contiguous committed pages with the fake vtable at the base of the readable second
// page, so the forward slots read fine while vptr - N*8 lands in the first page after it is flipped to PAGE_NOACCESS.
// The expected result is a guarded-read failure surfaced as InvalidObject.
TEST(HookVmt, PreflightGuardsHeaderPrefixBelowVptr)
{
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;

    // Two contiguous pages, intentionally leaked: the no-access page must never be released so a recycled VA cannot let
    // a later unrelated read succeed and flake the test (the fault-fixture leak-on-purpose discipline).
    auto *region =
        static_cast<std::uint8_t *>(::VirtualAlloc(nullptr, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(region, nullptr);

    // Fake vtable at the base of the SECOND page: slot 0 executable so the forward walk counts it, slot 1
    // non-executable as the walk's terminator. vptr is the second-page base, so vptr - 8 / vptr - 16 fall in the first
    // page, which becomes unreadable below.
    auto *vtable = reinterpret_cast<std::uintptr_t *>(region + page);
    vtable[0] = reinterpret_cast<std::uintptr_t>(&echo); // executable slot
    vtable[1] = 0;                                       // non-executable terminator

    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(vtable)};

    DWORD old_protect = 0;
    ASSERT_NE(::VirtualProtect(region, page, PAGE_NOACCESS, &old_protect), 0);

    Result<VmtHook> r = vmt_for("HeaderPrefixOnUnmappedPage", &object);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
    // region is deliberately not freed (see the leak note above): the no-access page stays reserved for process life.
}

// Force the self-reference acquire to fail with a known last-error so each install path's SystemCallFailed carries
// Error::detail = GetLastError(). A genuine acquire_module_ref failure is unreachable in a loaded process, so this
// override (defined in hook.cpp) drives the branch deterministically.
namespace DetourModKit::detail
{
    extern HMODULE (*g_hook_module_ref_override)() noexcept;
#if defined(DMK_ENABLE_TEST_SEAMS)
    extern bool (*g_hook_create_witness_override)(bool) noexcept;
    extern void (*g_vmt_before_capture_probe)() noexcept;
    extern void (*g_vmt_before_backend_clone_probe)() noexcept;
    extern void (*g_vmt_before_publish_probe)(void *) noexcept;
    extern void (*g_vmt_teardown_warning_probe)() noexcept;
#endif
} // namespace DetourModKit::detail

namespace
{
    constexpr DWORD INJECTED_ACQUIRE_ERROR = 0x00C0FFEE;

    HMODULE force_module_ref_failure() noexcept
    {
        ::SetLastError(INJECTED_ACQUIRE_ERROR);
        return nullptr;
    }

    bool reject_create_witness(bool) noexcept
    {
        return false;
    }

    // RAII installer so a failed assertion still clears the override before the next test runs.
    struct HookModuleRefFailureScope
    {
        HookModuleRefFailureScope() noexcept
        {
            DetourModKit::detail::g_hook_module_ref_override = &force_module_ref_failure;
        }
        ~HookModuleRefFailureScope() noexcept { DetourModKit::detail::g_hook_module_ref_override = nullptr; }
        HookModuleRefFailureScope(const HookModuleRefFailureScope &) = delete;
        HookModuleRefFailureScope &operator=(const HookModuleRefFailureScope &) = delete;
    };

    class HookCreateWitnessFailureScope
    {
    public:
        HookCreateWitnessFailureScope() noexcept
        {
            DetourModKit::detail::g_hook_create_witness_override = &reject_create_witness;
        }
        ~HookCreateWitnessFailureScope() noexcept { DetourModKit::detail::g_hook_create_witness_override = nullptr; }
        HookCreateWitnessFailureScope(const HookCreateWitnessFailureScope &) = delete;
        HookCreateWitnessFailureScope &operator=(const HookCreateWitnessFailureScope &) = delete;
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

    // How the object word is invalidated after the test seam compares it with the captured vptr and before the atomic
    // publication attempt. Each drives a distinct refusal: fault containment, compare-exchange mismatch, or a
    // protection fault. A separate read followed by a store would overwrite Displace and fail the assertions below.
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
            // The word stays readable and writable, but no longer holds the vptr the caller captured. Publishing
            // anyway would record an original the object never had and strand it on a freed clone at teardown.
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
                (void)::VirtualProtect(s_vmt_backend_count_race_page, VMT_PUBLISH_RACE_PAGE_BYTES,
                                       s_vmt_backend_count_previous_protection, &ignored);
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

    std::atomic<bool> s_vmt_warning_probe_entered{false};
    std::atomic<bool> s_vmt_warning_inner_done{false};
    std::atomic<bool> s_vmt_warning_inner_done_in_window{false};

    void wait_for_vmt_warning_inner_operation() noexcept
    {
        s_vmt_warning_probe_entered.store(true, std::memory_order_release);
        for (int i = 0; i < 500 && !s_vmt_warning_inner_done.load(std::memory_order_acquire); ++i)
        {
            Sleep(1);
        }
        s_vmt_warning_inner_done_in_window.store(s_vmt_warning_inner_done.load(std::memory_order_acquire),
                                                 std::memory_order_release);
    }

    class VmtTeardownWarningProbeScope
    {
    public:
        VmtTeardownWarningProbeScope() noexcept
        {
            s_vmt_warning_probe_entered.store(false, std::memory_order_relaxed);
            s_vmt_warning_inner_done.store(false, std::memory_order_relaxed);
            s_vmt_warning_inner_done_in_window.store(false, std::memory_order_relaxed);
            DetourModKit::detail::g_vmt_teardown_warning_probe = &wait_for_vmt_warning_inner_operation;
        }

        ~VmtTeardownWarningProbeScope() noexcept { DetourModKit::detail::g_vmt_teardown_warning_probe = nullptr; }

        VmtTeardownWarningProbeScope(const VmtTeardownWarningProbeScope &) = delete;
        VmtTeardownWarningProbeScope &operator=(const VmtTeardownWarningProbeScope &) = delete;
    };
#endif
} // namespace

TEST(HookCreateWitness, InlineFailureReturnsTypedErrorAndRollsBack)
{
    const Address target = addr_of(&witness_failure_inline_target);
    {
        const HookCreateWitnessFailureScope fail_scope;
        const Result<Hook> failed =
            inline_at(InlineRequest{.name = "InlineWitnessFailure", .target = target}, &echo_detour);
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(failed.error().code, ErrorCode::BackendFailed);
    }

    EXPECT_FALSE(is_target_hooked(target));
    EXPECT_EQ(call_unfolded(&witness_failure_inline_target, 7), 24);

    const Result<Hook> retry = inline_at(InlineRequest{.name = "InlineWitnessRetry", .target = target}, &echo_detour);
    ASSERT_TRUE(retry.has_value()) << retry.error().message();
    EXPECT_EQ(call_unfolded(&witness_failure_inline_target, 7), 107);
}

TEST(HookCreateWitness, MidFailureReturnsTypedErrorAndRollsBack)
{
    const Address target = addr_of(&witness_failure_mid_target);
    const auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 100; };
    {
        const HookCreateWitnessFailureScope fail_scope;
        const Result<Hook> failed = mid_at(MidRequest{.name = "MidWitnessFailure", .target = target}, detour);
        ASSERT_FALSE(failed.has_value());
        EXPECT_EQ(failed.error().code, ErrorCode::BackendFailed);
    }

    EXPECT_FALSE(is_target_hooked(target));
    EXPECT_EQ(call_unfolded(&witness_failure_mid_target, 9, 4), 5);

    const Result<Hook> retry = mid_at(MidRequest{.name = "MidWitnessRetry", .target = target}, detour);
    ASSERT_TRUE(retry.has_value()) << retry.error().message();
    EXPECT_EQ(call_unfolded(&witness_failure_mid_target, 9, 4), 96);
}

TEST(HookModuleRef, InlineAtAcquireFailurePopulatesErrorDetail)
{
    HookModuleRefFailureScope fail_scope;
    Result<Hook> r = inline_at(InlineRequest{.name = "InlineAcquireFail", .target = addr_of(&real_hook_target_add)},
                               &real_hook_detour_add);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::SystemCallFailed);
    EXPECT_EQ(r.error().detail, static_cast<std::uintptr_t>(INJECTED_ACQUIRE_ERROR));
}

TEST(HookModuleRef, MidAtAcquireFailurePopulatesErrorDetail)
{
    auto detour = [](MidContext &) {};
    HookModuleRefFailureScope fail_scope;
    Result<Hook> r = mid_at(MidRequest{.name = "MidAcquireFail", .target = addr_of(&real_hook_target_mul)}, detour);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::SystemCallFailed);
    EXPECT_EQ(r.error().detail, static_cast<std::uintptr_t>(INJECTED_ACQUIRE_ERROR));
}

TEST(HookModuleRef, VmtForAcquireFailurePopulatesErrorDetail)
{
    auto target = std::make_unique<VmtTestTarget>();
    HookModuleRefFailureScope fail_scope;
    Result<VmtHook> r = vmt_for("VmtAcquireFail", target.get());
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::SystemCallFailed);
    EXPECT_EQ(r.error().detail, static_cast<std::uintptr_t>(INJECTED_ACQUIRE_ERROR));
}

// vmt_for must RELEASE the process-wide object gate BEFORE dispatching its Created lifecycle event: emit_lifecycle
// runs arbitrary subscriber code (CP.22 -- never call unknown code under a lock), and holding the non-recursive
// object mutex across it would let a subscriber that re-enters a VMT operation deadlock. This confirms the gate is
// free during the emit: a subscriber launches a concurrent VMT op on another object and it completes promptly. If the
// gate were still held, the concurrent op would block on it for the whole wait window (a regression fails this
// EXPECT_TRUE rather than hanging the suite -- the probe is on a separate thread with a bounded wait).
TEST(HookVmt, ObjectGateReleasedBeforeCreateLifecycleEmit)
{
    auto outer_target = std::make_unique<VmtTestTarget>();
    auto inner_target = std::make_unique<VmtTestTarget>();

    std::atomic<bool> reentered{false};
    std::atomic<bool> inner_done{false};
    std::atomic<bool> inner_ok{false};
    std::atomic<bool> inner_done_in_window{false};
    std::thread inner_thread;

    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.kind != diagnostics::HookKind::Vmt || e.transition != diagnostics::HookTransition::Created)
            {
                return;
            }
            // The concurrent vmt_for below also emits Created (on inner_thread); re-enter the probe only once.
            if (reentered.exchange(true))
            {
                return;
            }
            inner_thread = std::thread(
                [&]
                {
                    Result<VmtHook> inner = vmt_for("InnerConcurrent", inner_target.get());
                    inner_ok.store(inner.has_value(), std::memory_order_release);
                    inner_done.store(true, std::memory_order_release);
                    // `inner` (if present) destructs here, restoring inner_target's vptr under the free object gate.
                });
            // A released gate lets the concurrent vmt_for finish in microseconds; a still-held gate blocks it for the
            // whole window (this thread holds the gate, so it could only proceed after this outer vmt_for returns).
            for (int i = 0; i < 500 && !inner_done.load(std::memory_order_acquire); ++i)
            {
                Sleep(1);
            }
            inner_done_in_window.store(inner_done.load(std::memory_order_acquire), std::memory_order_release);
        });

    Result<VmtHook> outer = vmt_for("OuterConcurrent", outer_target.get());
    ASSERT_TRUE(outer.has_value()) << outer.error().message();
    VmtHook outer_hold = std::move(*outer);

    if (inner_thread.joinable())
    {
        inner_thread.join();
    }
    EXPECT_TRUE(reentered.load(std::memory_order_acquire)) << "the Created lifecycle event was never observed";
    EXPECT_TRUE(inner_done_in_window.load(std::memory_order_acquire))
        << "vmt_for held the object gate across its Created emit; a concurrent VMT op could not proceed";
    EXPECT_TRUE(inner_ok.load(std::memory_order_acquire)) << "the concurrent re-entrant vmt_for failed";
}

// fail_if_already_hooked refuses a second clone of an object already on a clone owned by this kit.
TEST(HookVmt, FailIfAlreadyHookedRefusesDoubleCreate)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> first = vmt_for("FirstVmt", target.get(), VmtOptions{.fail_if_already_hooked = true});
    ASSERT_TRUE(first.has_value()) << first.error().message();
    VmtHook vh = std::move(*first);

    Result<VmtHook> second = vmt_for("SecondVmt", target.get(), VmtOptions{.fail_if_already_hooked = true});
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::HookAlreadyExists);
}

namespace
{
    // The VMT clone-detection warnings are emitted through the process-default logger. A capture test redirects that
    // logger to a private file at Warning level (so the vmt_for success Info lines are suppressed and only the
    // clone-detection warnings land) for the scope's duration, then restores the prior level. On teardown it first
    // re-points the logger at a throwaway drain file: a logger sink holds its file open, so the capture file cannot be
    // removed while it is still the active sink. The process id plus an atomic counter keep the filenames unique across
    // parallel ctest processes and repeated captures in one process.
    class ScopedLogCapture
    {
    public:
        ScopedLogCapture() : m_previous_level(log().get_log_level())
        {
            static std::atomic<int> s_counter{0};
            const std::string stamp =
                std::to_string(::GetCurrentProcessId()) + "_" + std::to_string(s_counter.fetch_add(1));
            m_capture_file = std::filesystem::temp_directory_path() / ("test_hook_vmt_capture_" + stamp + ".log");
            m_drain_file = std::filesystem::temp_directory_path() / ("test_hook_vmt_drain_" + stamp + ".log");
            Logger::configure("VMTCAP", m_capture_file.string());
            log().set_log_level(LogLevel::Warning);
        }

        ScopedLogCapture(const ScopedLogCapture &) = delete;
        ScopedLogCapture &operator=(const ScopedLogCapture &) = delete;

        ~ScopedLogCapture() noexcept
        {
            try
            {
                Logger::configure("DMK", m_drain_file.string());
                log().set_log_level(m_previous_level);
                if (std::filesystem::exists(m_capture_file))
                    std::filesystem::remove(m_capture_file);
            }
            catch (...)
            {
            }
        }

        // Flushes the logger and returns everything written to the capture file so far.
        [[nodiscard]] std::string drain() const
        {
            log().flush();
            std::ifstream ifs(m_capture_file);
            return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        }

        // Counts non-overlapping occurrences of @p needle in @p haystack, used to assert exactly how many warnings
        // fired.
        [[nodiscard]] static std::size_t count(const std::string &haystack, std::string_view needle)
        {
            std::size_t hits = 0;
            for (std::size_t pos = haystack.find(needle, 0); pos != std::string::npos;
                 pos = haystack.find(needle, pos + needle.size()))
                ++hits;
            return hits;
        }

    private:
        LogLevel m_previous_level;
        std::filesystem::path m_capture_file;
        std::filesystem::path m_drain_file;
    };
} // namespace

// On the permissive default (no fail_if_already_hooked), cloning an object whose vptr is already a clone owned by
// another kit VmtHook is the silent double-hook: the second clone captures the first's hooked slots as its "original".
// The permissive contract proceeds (it does not refuse), but the condition is detected and warned so a multi-mod stack
// is diagnosable. Prove the warning fires on the clone-of-clone and not on a clean first clone, and that the second
// create still succeeds.
TEST(HookVmt, PermissiveCloneOfCloneWarnsButProceeds)
{
    ScopedLogCapture capture;
    auto object = std::make_unique<VmtTestTarget>();

    {
        // First clone (permissive): a clean create; the object is not yet on any clone, so no warning.
        Result<VmtHook> first = vmt_for("CloneWarnFirst", object.get());
        ASSERT_TRUE(first.has_value()) << first.error().message();
        VmtHook a = std::move(*first);

        // Second clone (permissive) on the SAME object: its vptr is now a's clone base, so the detection fires. It
        // still succeeds -- the permissive contract proceeds rather than refuses.
        Result<VmtHook> second = vmt_for("CloneWarnSecond", object.get());
        ASSERT_TRUE(second.has_value()) << second.error().message();
        VmtHook b = std::move(*second);

        const std::string content = capture.drain();
        EXPECT_NE(content.find("CloneWarnSecond"), std::string::npos)
            << "the clone-of-clone must be detected and warned on the permissive path";
        EXPECT_NE(content.find("already a clone owned by another"), std::string::npos);
        EXPECT_EQ(content.find("CloneWarnFirst"), std::string::npos) << "a clean first clone must not warn";

        // b (newest) then a (oldest) destruct here as the scope closes: newest-first, so each restores its vptr layer
        // cleanly with no leak-on-inversion.
    }
}

// The destructor restores the original vptr (the remove-entire-hook equivalent is dropping the handle).
TEST(HookVmt, DestructorRestoresVptr)
{
    auto target = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(target.get());
    EXPECT_EQ(target->compute(1, 2), 3);

    {
        Result<VmtHook> r = vmt_for("RestoreVmt", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook vh = std::move(*r);
        EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr); // on the clone now
    }

    // Dropping the handle restored the original vptr.
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr);
    EXPECT_EQ(target->compute(1, 2), 3);
}

// apply_to puts the clone onto an additional object; remove_from restores it. Newest-first restore on destruction.
TEST(HookVmt, ApplyToAndRemoveFromMultipleObjects)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();
    const auto vptr2_original = *reinterpret_cast<std::uintptr_t *>(target2.get());

    Result<VmtHook> r = vmt_for("MultiVmt", target1.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    ASSERT_TRUE(vh.apply_to(target2.get()).has_value());
    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(target2.get()), vptr2_original); // target2 on the clone

    ASSERT_TRUE(vh.remove_from(target2.get()).has_value());
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(target2.get()), vptr2_original); // restored
}

// Re-applying onto the handle's OWN clone is a success no-op; applying an object held by another live clone fails.
TEST(HookVmt, ApplyToOwnCloneIsNoOpAnotherCloneFails)
{
    auto target_a = std::make_unique<VmtTestTarget>();
    auto target_b = std::make_unique<VmtTestTarget>();

    Result<VmtHook> ra = vmt_for("CloneOwnerA", target_a.get());
    ASSERT_TRUE(ra.has_value()) << ra.error().message();
    VmtHook va = std::move(*ra);

    Result<VmtHook> rb = vmt_for("CloneOwnerB", target_b.get());
    ASSERT_TRUE(rb.has_value()) << rb.error().message();
    VmtHook vb = std::move(*rb);

    // target_b is already on vb's clone. Applying va onto target_b with fail_if_already_hooked must be refused.
    Result<void> cross = va.apply_to(target_b.get(), VmtOptions{.fail_if_already_hooked = true});
    ASSERT_FALSE(cross.has_value());
    EXPECT_EQ(cross.error().code, ErrorCode::HookAlreadyExists);
}

// The permissive apply_to path mirrors the vmt_for clone-of-clone warning, but a tracked re-apply returns before that
// path: applying onto an object already on ANOTHER kit VmtHook's clone base warns and proceeds, while re-applying onto
// an object already on THIS handle's own clone stays quiet. Drive both in one capture and assert exactly one warning
// fires -- so removing the foreign-clone warning or the tracked no-op's early return is caught.
TEST(HookVmt, PermissiveApplyOntoForeignCloneWarnsOwnCloneStaysQuiet)
{
    ScopedLogCapture capture;
    auto owner_object = std::make_unique<VmtTestTarget>();
    auto mover_object = std::make_unique<VmtTestTarget>();

    {
        // owner holds owner_object on its clone; mover holds mover_object on its clone. Both are clean first clones on
        // pristine objects, so neither vmt_for warns.
        Result<VmtHook> ro = vmt_for("ApplyOwner", owner_object.get());
        ASSERT_TRUE(ro.has_value()) << ro.error().message();
        VmtHook owner = std::move(*ro);

        Result<VmtHook> rm = vmt_for("ApplyMover", mover_object.get());
        ASSERT_TRUE(rm.has_value()) << rm.error().message();
        VmtHook mover = std::move(*rm);

        // Foreign clone: owner_object's vptr is owner's clone base, not mover's. mover.apply_to sees a clone owned by
        // another handle, warns, and proceeds. Undo the cross-apply immediately so each object is restored by a single
        // owning handle at teardown (remove_from restores owner_object to owner's clone base).
        ASSERT_TRUE(mover.apply_to(owner_object.get()).has_value());
        ASSERT_TRUE(mover.remove_from(owner_object.get()).has_value());

        // Own clone: mover_object is already tracked on mover's clone, so the early success no-op suppresses the
        // warning.
        ASSERT_TRUE(mover.apply_to(mover_object.get()).has_value());

        const std::string content = capture.drain();
        EXPECT_EQ(ScopedLogCapture::count(content, "already a clone owned by another"), 1u)
            << "exactly the foreign-clone apply warns; the own-clone re-apply must stay quiet";
        EXPECT_NE(content.find("ApplyMover"), std::string::npos) << "the foreign-clone warning names the applying hook";

        // mover (newest) then owner destruct here: mover restores mover_object, owner restores owner_object, each a
        // single-owner restore with no cross-ownership left over.
    }
}

TEST(HookVmt, ApplyNullObject)
{
    auto target = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("ApplyNullVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    Result<void> applied = vh.apply_to(nullptr);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code, ErrorCode::InvalidObject);
}

TEST(HookVmt, RemoveFromNullObject)
{
    auto target = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("RemNullVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    Result<void> removed = vh.remove_from(nullptr);
    EXPECT_FALSE(removed.has_value());
}

TEST(HookVmt, MovedFromVmtHandleIsInert)
{
    auto target = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(target.get());
    {
        Result<VmtHook> r = vmt_for("MovedVmt", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook a = std::move(*r);
        VmtHook b = std::move(a);
        EXPECT_FALSE(static_cast<bool>(a)); // a is inert; only b restores on destruction
        EXPECT_TRUE(static_cast<bool>(b));
    }
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr);
}

// VMT slot pre-flight: refuse to clone an object whose vtable's first slot is an int3 padding/breakpoint byte, or a
// same-module jump stub; accept a real function prologue. The pre-flight is opt-in (fail_on_non_function_pointer).
//
// The slot bodies live on an executable page rather than in static data. A slot is only counted as callable when its
// value is an executable address, and only a counted slot reaches the byte classifier, so bodies planted in .rdata
// make every case here refused as a zero-slot table before its first byte is ever read: the refusal cases would pass
// without exercising the classifier and the acceptance cases would fail outright.
namespace
{
    // Offsets are spaced well past the longest body so no case can decode into its neighbour. The page is prefilled
    // 0xCC, which also terminates the slot walk at the first unwritten offset.
    struct SlotBodyPage
    {
        dmk_test::ScratchPage page;

        static constexpr std::size_t INT3 = 0x000;
        static constexpr std::size_t RET = 0x040;
        static constexpr std::size_t PROLOGUE = 0x080;

        SlotBodyPage() noexcept
        {
            if (!page.ok())
            {
                return;
            }
            page.put(INT3, {0xCC, 0xCC, 0xC3, 0x90});
            page.put(RET, {0xC3, 0x90, 0x90, 0x90});
            // First byte 0x48 (REX.W prefix opening a standard x64 prologue, here sub rsp, 0x28): the decoder must
            // classify the slot as a function body.
            page.put(PROLOGUE, {0x48, 0x83, 0xEC, 0x28, 0xC3, 0x90, 0x90, 0x90});
        }

        [[nodiscard]] void *at(std::size_t offset) const noexcept
        {
            return reinterpret_cast<void *>(page.addr(offset));
        }
    };

    // One page for every case below: the bodies are immutable once written and none of them is ever hooked.
    const SlotBodyPage &slot_bodies()
    {
        static const SlotBodyPage bodies;
        return bodies;
    }

} // namespace

// A jump stub has to sit in this image's own code section, not on the scratch page. The classifier resolves the module
// of the slot address FIRST and refuses outright when there is none, so a stub on privately allocated memory is
// rejected before the same-module comparison it exists to pin is ever reached. Planted in .text, both the stub and the
// address its rel32 resolves to map to this module, which is the shape of an incremental-link thunk or a patched slot.
// E9 jmp +3, landing on the ret three bytes past the instruction's end; the trailing int3s stop a decode running on.
#if defined(_MSC_VER)
#pragma section(".text$dmk", read, execute)
__declspec(allocate(".text$dmk")) extern const std::uint8_t SAME_MODULE_JMP_STUB[16] = {
    0xE9, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
#else
__attribute__((section(".text$dmk"), used)) extern const std::uint8_t SAME_MODULE_JMP_STUB[16] = {
    0xE9, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
#endif

TEST(HookVmt, PreFlightRefusesInt3FirstSlot)
{
    // DMK captures the RTTI header below the vptr plus every counted slot. That header is one word on the MSVC ABI and
    // two on the Itanium ABI (MinGW), so the prefix is sized for the wider of the two: a single word would put the
    // capture's start 8 bytes before this struct on MinGW. The leading words and non-executable terminator keep that
    // capture inside this fixture.
    struct Int3VTable
    {
        void *rtti[2];
        void *methods[3];
    };
    Int3VTable vtable{};
    vtable.methods[0] = slot_bodies().at(SlotBodyPage::INT3);
    vtable.methods[1] = slot_bodies().at(SlotBodyPage::RET);
    vtable.methods[2] = nullptr; // terminates the slot walk in bounds
    void *vptr = &vtable.methods[0];

    // The default policy admits this object, which is what makes the refusal below attributable to the classifier
    // rather than to a slot that was never counted. The handle is dropped so the vptr is back on the local table
    // before the strict attempt.
    {
        Result<VmtHook> permissive = vmt_for("Int3VmtPermissive", &vptr);
        ASSERT_TRUE(permissive.has_value()) << permissive.error().message();
        VmtHook dropped = std::move(*permissive);
    }
    ASSERT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));

    Result<VmtHook> r = vmt_for("Int3Vmt", &vptr, VmtOptions{.fail_on_non_function_pointer = true});
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);

    // The refused create did not touch the vptr: it still points at our local vtable.
    EXPECT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));
}

TEST(HookVmt, PreFlightAcceptsFunctionPrologue)
{
    // Slot 0 carries a normal x64 prologue first byte (0x48), so pre-flight with fail_on_non_function_pointer=true must
    // accept the vtable and the create must succeed. The rtti members sit below the vptr, sized for the wider of the
    // two RTTI headers (see PreFlightRefusesInt3FirstSlot), so the clone's copy starts inside this fixture.
    struct PrologueVTable
    {
        void *rtti[2];
        void *methods[2];
    };
    PrologueVTable vtable{};
    vtable.methods[0] = slot_bodies().at(SlotBodyPage::PROLOGUE);
    void *vptr = &vtable.methods[0];

    Result<VmtHook> r = vmt_for("PrologueVmt", &vptr, VmtOptions{.fail_on_non_function_pointer = true});
    ASSERT_TRUE(r.has_value()) << r.error().message();
    {
        VmtHook vh = std::move(*r);
        EXPECT_EQ(vh.name(), "PrologueVmt");
    }
    // The accepted create swapped the vptr onto the clone; dropping the handle restores the original vtable pointer.
    EXPECT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));
}

TEST(HookVmt, PreFlightOffByDefault)
{
    // The pre-flight is opt-in: an object the classifier would reject still creates under the default options. The
    // contrast has to be drawn on ONE object that both policies agree is structurally valid, so the only difference is
    // the classifier. Slot 0 is a bare `ret` -- executable, so it counts as a callable slot and the table is not
    // zero-slot, but its first byte is one the classifier refuses. The rtti members sit below the vptr.
    struct RetVTable
    {
        void *rtti[2];
        void *methods[2];
    };
    RetVTable vtable{};
    vtable.methods[0] = slot_bodies().at(SlotBodyPage::RET);
    void *vptr = &vtable.methods[0];

    {
        Result<VmtHook> r = vmt_for("RetSlotVmt", &vptr);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook dropped = std::move(*r);
    }
    ASSERT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));

    Result<VmtHook> strict = vmt_for("RetSlotVmtStrict", &vptr, VmtOptions{.fail_on_non_function_pointer = true});
    ASSERT_FALSE(strict.has_value());
    EXPECT_EQ(strict.error().code, ErrorCode::InvalidObject);
}

TEST(HookVmt, PreFlightRefusesSameModuleJumpStub)
{
    // As in the int3 case: the leading rtti words and the terminator keep the backend's clone copy in bounds.
    struct StubVTable
    {
        void *rtti[2];
        void *methods[3];
    };
    StubVTable vtable{};
    vtable.methods[0] = const_cast<std::uint8_t *>(&SAME_MODULE_JMP_STUB[0]);
    vtable.methods[1] = slot_bodies().at(SlotBodyPage::RET);
    vtable.methods[2] = nullptr;
    void *vptr = &vtable.methods[0];

    // As above: prove the default admits it, so the strict refusal is the classifier's verdict and not a slot walk
    // that counted nothing.
    {
        Result<VmtHook> permissive = vmt_for("JmpStubVmtPermissive", &vptr);
        ASSERT_TRUE(permissive.has_value()) << permissive.error().message();
        VmtHook dropped = std::move(*permissive);
    }
    ASSERT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));

    Result<VmtHook> r = vmt_for("JmpStubVmt", &vptr, VmtOptions{.fail_on_non_function_pointer = true});
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
    EXPECT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));
}

TEST(HookVmt, ApplyPreFlightRefusesInt3FirstSlot)
{
    // The apply path runs the same slot-0 pre-flight as create: applying onto an object whose current vtable starts
    // with an int3 slot must be refused.
    auto seed = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("ApplyPreFlightVmt", seed.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    struct Int3VTable
    {
        void *methods[2];
    };
    Int3VTable vtable{};
    vtable.methods[0] = slot_bodies().at(SlotBodyPage::INT3);
    vtable.methods[1] = slot_bodies().at(SlotBodyPage::RET);
    void *vptr = &vtable;

    Result<void> applied = vh.apply_to(&vptr, VmtOptions{.fail_on_non_function_pointer = true});
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code, ErrorCode::InvalidObject);
    EXPECT_EQ(vptr, static_cast<void *>(&vtable));
}

// apply_to installs an existing clone, so its default path needs a readable, writable object word but does not clone or
// inspect the displaced vtable. The opt-in slot policy owns that additional classification.
TEST(HookVmt, ApplyDefaultNeedsOnlyWritableObjectWord)
{
    auto seed = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("ApplyWritableWordSeed", seed.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    struct FakeObject
    {
        std::uintptr_t vptr{0};
    } object;

    ASSERT_TRUE(vh.apply_to(&object).has_value());
    EXPECT_NE(object.vptr, 0u);
    ASSERT_TRUE(vh.remove_from(&object).has_value());
    EXPECT_EQ(object.vptr, 0u);
}

TEST(HookVmt, ReleaseLeavesCloneInstalled)
{
    auto target = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(target.get());

    Result<VmtHook> r = vmt_for("ReleasedVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    vh.release();

    EXPECT_FALSE(static_cast<bool>(vh));
    // No vptr restore: the clone is leaked for the process lifetime, so the vptr still points at the clone.
    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr);
    // Manually restore so the stack object does not dispatch through a leaked clone after this scope.
    *reinterpret_cast<std::uintptr_t *>(target.get()) = original_vptr;
}

// VMT per-method hooking (hook_method / original<Fn>(index) / remove_method)

// A method hook redirects one vtable slot in the clone, and original<Fn>(index) reaches the pre-hook method: a hooked
// compute returns original + 1000, and the typed snapshot yields the unmodified sum.
TEST(HookVmtMethod, HookMethodRedirectsSlotAndOriginalReachesPreHook)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(dispatch_compute(target.get(), 3, 4), 7);

    Result<VmtHook> r = vmt_for("MethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());

    // Dispatch through the object now routes to the detour: original(3, 4) + 1000.
    EXPECT_EQ(dispatch_compute(target.get(), 3, 4), 1007);

    // The typed snapshot reaches the original body directly, so it yields the unmodified 7.
    auto *orig = vh.original<VmtComputeFn>(VMT_COMPUTE_INDEX);
    ASSERT_NE(orig, nullptr);
    EXPECT_EQ(orig(target.get(), 3, 4), 7);
}

// Two independent slots hook without cross-talk, and each original<Fn>(index) resolves to its own method.
TEST(HookVmtMethod, MultipleSlotsHookIndependently)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(dispatch_compute(target.get(), 2, 3), 5);
    EXPECT_EQ(dispatch_transform(target.get(), 6), 12);

    Result<VmtHook> r = vmt_for("MultiSlotVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    ASSERT_TRUE(vh.hook_method(VMT_TRANSFORM_INDEX, &vmt_detour_transform).has_value());

    EXPECT_EQ(dispatch_compute(target.get(), 2, 3), 1005);
    EXPECT_EQ(dispatch_transform(target.get(), 6), 512);
}

// Hooking the same slot twice is refused: a second install would read the first detour as the "original".
TEST(HookVmtMethod, DuplicateMethodHookFails)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("DupMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());

    Result<void> second = vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::MethodAlreadyHooked);
}

// A null detour is rejected before it can be stored into a vtable slot.
TEST(HookVmtMethod, NullDetourRejected)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("NullDetourVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    VmtComputeFn null_detour = nullptr;
    Result<void> hooked = vh.hook_method(VMT_COMPUTE_INDEX, null_detour);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidArg);
}

// An out-of-range index is rejected before the backend can index through the cloned vtable.
TEST(HookVmtMethod, OutOfRangeIndexRejected)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("OutOfRangeMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    constexpr std::size_t INVALID_INDEX = VMT_TRANSFORM_INDEX + 1;
    Result<void> hooked = vh.hook_method(INVALID_INDEX, &vmt_detour_compute);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidArg);
    EXPECT_EQ(dispatch_compute(target.get(), 4, 5), 9);
    EXPECT_EQ(vh.original<VmtComputeFn>(INVALID_INDEX), nullptr);
}

// remove_method restores the cloned slot; a second removal reports MethodNotFound.
TEST(HookVmtMethod, RemoveMethodRestoresSlot)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("RemMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    EXPECT_EQ(dispatch_compute(target.get(), 5, 5), 1010);

    ASSERT_TRUE(vh.remove_method(VMT_COMPUTE_INDEX).has_value());
    EXPECT_EQ(dispatch_compute(target.get(), 5, 5), 10);
    EXPECT_EQ(vh.original<VmtComputeFn>(VMT_COMPUTE_INDEX), nullptr);

    Result<void> re_remove = vh.remove_method(VMT_COMPUTE_INDEX);
    ASSERT_FALSE(re_remove.has_value());
    EXPECT_EQ(re_remove.error().code, ErrorCode::MethodNotFound);
}

// Dropping the whole handle restores the original method (the remove-entire-hook path for method hooks).
TEST(HookVmtMethod, DroppingHandleRestoresMethod)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(dispatch_compute(target.get(), 1, 2), 3);

    {
        Result<VmtHook> r = vmt_for("DropMethodVmt", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook vh = std::move(*r);
        MethodVmtScope method_scope(vh);

        ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
        EXPECT_EQ(dispatch_compute(target.get(), 1, 2), 1003);
    }

    // The handle's destructor restored the original vptr, so the method hook is gone with it.
    EXPECT_EQ(dispatch_compute(target.get(), 1, 2), 3);
}

// A method hook lives in one clone, so an object added later via apply_to inherits it; remove_from restores that
// object without disturbing the seed.
TEST(HookVmtMethod, MethodHookAppliesToAdditionalObjects)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("MultiObjMethodVmt", target1.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    EXPECT_EQ(dispatch_compute(target1.get(), 1, 1), 1002);
    EXPECT_EQ(dispatch_compute(target2.get(), 1, 1), 2);

    ASSERT_TRUE(vh.apply_to(target2.get()).has_value());
    EXPECT_EQ(dispatch_compute(target2.get(), 1, 1), 1002);

    ASSERT_TRUE(vh.remove_from(target2.get()).has_value());
    EXPECT_EQ(dispatch_compute(target2.get(), 1, 1), 2);
    EXPECT_EQ(dispatch_compute(target1.get(), 1, 1), 1002);
}

// original<Fn>(index) is a null snapshot for a slot that was never hooked.
TEST(HookVmtMethod, OriginalForUnhookedSlotIsNull)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("UnhookedSlotVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    EXPECT_EQ(vh.original<VmtComputeFn>(VMT_COMPUTE_INDEX), nullptr);
}

// A disengaged (moved-from) handle fails every per-method entry point closed: InvalidHookState for the mutators and a
// null snapshot for the reader, mirroring the flat Hook's moved-from contract.
TEST(HookVmtMethod, DisengagedHandleFailsClosed)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("DisengagedMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook a = std::move(*r);
    VmtHook b = std::move(a);
    EXPECT_TRUE(static_cast<bool>(b));

    Result<void> hooked = a.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidHookState);

    Result<void> removed = a.remove_method(VMT_COMPUTE_INDEX);
    ASSERT_FALSE(removed.has_value());
    EXPECT_EQ(removed.error().code, ErrorCode::InvalidHookState);

    EXPECT_EQ(a.original<VmtComputeFn>(VMT_COMPUTE_INDEX), nullptr);
}

// Lifecycle events: typed transitions on the diagnostic bus
namespace
{
    struct CapturedLifecycle
    {
        std::string name;
        diagnostics::HookKind kind;
        diagnostics::HookTransition transition;
    };
} // namespace

TEST(HookLifecycle, InlineEventsAreEmitted)
{
    std::vector<CapturedLifecycle> events;
    auto sub =
        diagnostics::hook_lifecycle().subscribe([&events](const diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    {
        Result<Hook> r = inline_at(InlineRequest{.name = "LifecycleHook", .target = addr_of(&echo)}, &echo_detour);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        // Created on install, then a real disable -> enable transition pair, then Removed when h leaves scope.
        ASSERT_TRUE(h.disable().has_value());
        ASSERT_TRUE(h.enable().has_value());
    }

    ASSERT_EQ(events.size(), 4u);
    EXPECT_EQ(events[0].transition, diagnostics::HookTransition::Created);
    EXPECT_EQ(events[1].transition, diagnostics::HookTransition::Disabled);
    EXPECT_EQ(events[2].transition, diagnostics::HookTransition::Enabled);
    EXPECT_EQ(events[3].transition, diagnostics::HookTransition::Removed);
    for (const auto &e : events)
    {
        EXPECT_EQ(e.name, "LifecycleHook");
        EXPECT_EQ(e.kind, diagnostics::HookKind::Inline);
    }
}

TEST(HookLifecycle, MidEventReportsMidKind)
{
    std::vector<CapturedLifecycle> events;
    auto sub =
        diagnostics::hook_lifecycle().subscribe([&events](const diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    auto detour = [](MidContext &) {};
    Result<Hook> r = mid_at(MidRequest{.name = "MidLifecycleHook", .target = addr_of(&real_hook_target_mul)}, detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    ASSERT_GE(events.size(), 1u);
    EXPECT_EQ(events[0].transition, diagnostics::HookTransition::Created);
    EXPECT_EQ(events[0].kind, diagnostics::HookKind::Mid);
}

TEST(HookLifecycle, VmtEventReportsVmtKind)
{
    auto target = std::make_unique<VmtTestTarget>();
    std::vector<CapturedLifecycle> events;
    auto sub =
        diagnostics::hook_lifecycle().subscribe([&events](const diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    {
        Result<VmtHook> r = vmt_for("VmtLifecycleHook", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook vh = std::move(*r);
    }

    ASSERT_EQ(events.size(), 2u);
    EXPECT_EQ(events[0].name, "VmtLifecycleHook");
    EXPECT_EQ(events[0].kind, diagnostics::HookKind::Vmt);
    EXPECT_EQ(events[0].transition, diagnostics::HookTransition::Created);
    EXPECT_EQ(events[1].name, "VmtLifecycleHook");
    EXPECT_EQ(events[1].kind, diagnostics::HookKind::Vmt);
    EXPECT_EQ(events[1].transition, diagnostics::HookTransition::Removed);
}

TEST(HookLifecycle, NotEmittedForFailedCreate)
{
    int count = 0;
    auto sub = diagnostics::hook_lifecycle().subscribe([&count](const diagnostics::HookLifecycleEvent &) { ++count; });

    // A failed create (null object) is not a transition, so nothing is emitted.
    Result<VmtHook> r = vmt_for("FailedVmtLifecycleHook", nullptr);
    EXPECT_FALSE(r.has_value());
    EXPECT_EQ(count, 0);
}

TEST(HookLifecycle, NotEmittedForNoOpTransition)
{
    std::vector<CapturedLifecycle> events;
    auto sub =
        diagnostics::hook_lifecycle().subscribe([&events](const diagnostics::HookLifecycleEvent &e)
                                                { events.push_back({std::string(e.name), e.kind, e.transition}); });

    // Dedicated leak target: this test ends with release(), leaking the detour for the process lifetime.
    Result<Hook> r = inline_at(InlineRequest{.name = "NoOpLifecycleHook", .target = addr_of(&leak_target_lifecycle)},
                               &real_hook_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_EQ(events.size(), 1u); // Created only

    // The hook is already enabled, so a second enable() is a no-op and emits nothing.
    ASSERT_TRUE(h.enable().has_value());
    EXPECT_EQ(events.size(), 1u);
    h.release(); // detach without a Removed transition path through teardown
}

namespace
{
    // Dedicated targets for the HookStack ordering tests. HookStack always restores newest-first (the safe order), so
    // these are left cleanly unhooked after every test; giving the ordering cases their own functions still keeps them
    // isolated from the shared real_hook_target_* functions other tests call.
    DMK_TEST_NOINLINE int stack_target_primary(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_TEST_NOINLINE int stack_target_secondary(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    // A trivial layering detour: the ordering tests never call the target while it is hooked (they only observe
    // teardown order), so the detour body is immaterial; it just has to be a valid int(int, int) to patch in.
    DMK_TEST_NOINLINE int stack_detour(int a, int b)
    {
        return a + b + 1;
    }
} // namespace

// A HookStack owning two hooks layered on one target restores them newest-first, the only safe order: the newer
// layer's trampoline chains through the base hook's jump, so the base must be restored last. The Removed lifecycle
// events make the teardown order observable without forcing a faulting repro; if teardown_newest_first() ever became a
// forward loop, removed would flip to {StackBase, StackLayer} and this fails.
TEST(HookStackTest, TearsDownLayeredHooksNewestFirst)
{
    std::vector<std::string> removed;
    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&removed](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.transition == diagnostics::HookTransition::Removed)
            {
                removed.emplace_back(e.name);
            }
        });

    {
        HookStack stack;
        Result<Hook> base =
            inline_at(InlineRequest{.name = "StackBase", .target = addr_of(&stack_target_primary)}, &stack_detour);
        ASSERT_TRUE(base.has_value()) << base.error().message();
        stack.push(std::move(*base));

        Result<Hook> layer =
            inline_at(InlineRequest{.name = "StackLayer", .target = addr_of(&stack_target_primary)}, &stack_detour);
        ASSERT_TRUE(layer.has_value()) << layer.error().message();
        stack.push(std::move(*layer));

        EXPECT_EQ(stack.size(), 2u);
        EXPECT_TRUE(is_target_hooked(addr_of(&stack_target_primary)));
        // Scope exit destroys the HookStack, which tears the two hooks down newest-first.
    }

    ASSERT_EQ(removed.size(), 2u);
    EXPECT_EQ(removed[0], "StackLayer"); // pushed second, restored first
    EXPECT_EQ(removed[1], "StackBase");  // pushed first, restored last
    // Both released and the prologue cleanly restored, which only holds because teardown ran in the safe order.
    EXPECT_FALSE(is_target_hooked(addr_of(&stack_target_primary)));
    EXPECT_EQ(stack_target_primary(5, 3), 8);
}

TEST(HookStackTest, MoveConstructTransfersOwnershipAndLeavesSourceEmpty)
{
    HookStack source;
    Result<Hook> r =
        inline_at(InlineRequest{.name = "MoveCtorHook", .target = addr_of(&stack_target_secondary)}, &stack_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    source.push(std::move(*r));

    HookStack moved(std::move(source));

    EXPECT_TRUE(source.empty());
    EXPECT_EQ(source.size(), 0u);
    EXPECT_EQ(moved.size(), 1u);
    EXPECT_FALSE(moved.empty());
    EXPECT_TRUE(is_target_hooked(addr_of(&stack_target_secondary)));
    EXPECT_EQ(stack_target_secondary(2, 6), 9);
}

// Move-assignment must also drain the overwritten stack newest-first. Defaulted move-assignment would destroy or
// overwrite the replaced hooks in a container-defined order, reopening the layered-hook use-after-free; the
// hand-written operator= drains newest-first before adopting the source. A defaulted operator= flips removed to
// {MoveBase, MoveLayer}.
TEST(HookStackTest, MoveAssignDrainsOverwrittenHooksNewestFirst)
{
    std::vector<std::string> removed;
    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&removed](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.transition == diagnostics::HookTransition::Removed)
            {
                removed.emplace_back(e.name);
            }
        });

    HookStack dest;
    {
        Result<Hook> base =
            inline_at(InlineRequest{.name = "MoveBase", .target = addr_of(&stack_target_secondary)}, &stack_detour);
        ASSERT_TRUE(base.has_value()) << base.error().message();
        dest.push(std::move(*base));

        Result<Hook> layer =
            inline_at(InlineRequest{.name = "MoveLayer", .target = addr_of(&stack_target_secondary)}, &stack_detour);
        ASSERT_TRUE(layer.has_value()) << layer.error().message();
        dest.push(std::move(*layer));
    }
    ASSERT_EQ(dest.size(), 2u);
    ASSERT_TRUE(removed.empty()); // nothing torn down yet (setup only emits Created)

    HookStack replacement;
    Result<Hook> adopted =
        inline_at(InlineRequest{.name = "MoveAdopted", .target = addr_of(&stack_target_primary)}, &stack_detour);
    ASSERT_TRUE(adopted.has_value()) << adopted.error().message();
    replacement.push(std::move(*adopted));

    // Overwrite the live stack: dest's two layered hooks must be released newest-first here.
    dest = std::move(replacement);

    ASSERT_EQ(removed.size(), 2u);
    EXPECT_EQ(removed[0], "MoveLayer");
    EXPECT_EQ(removed[1], "MoveBase");
    EXPECT_TRUE(replacement.empty());
    EXPECT_EQ(replacement.size(), 0u);
    EXPECT_EQ(dest.size(), 1u);
    EXPECT_FALSE(is_target_hooked(addr_of(&stack_target_secondary)));
    EXPECT_EQ(stack_target_secondary(9, 4), 13);
    EXPECT_TRUE(is_target_hooked(addr_of(&stack_target_primary)));
    EXPECT_EQ(stack_target_primary(9, 4), 14);

    dest.clear();
    ASSERT_EQ(removed.size(), 3u);
    EXPECT_EQ(removed[2], "MoveAdopted");
}

// clear() releases every owned hook newest-first and leaves the stack empty and reusable.
TEST(HookStackTest, ClearTearsDownNewestFirstAndEmpties)
{
    std::vector<std::string> removed;
    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&removed](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.transition == diagnostics::HookTransition::Removed)
            {
                removed.emplace_back(e.name);
            }
        });

    HookStack stack;
    Result<Hook> base =
        inline_at(InlineRequest{.name = "ClearBase", .target = addr_of(&stack_target_primary)}, &stack_detour);
    ASSERT_TRUE(base.has_value()) << base.error().message();
    stack.push(std::move(*base));

    Result<Hook> layer =
        inline_at(InlineRequest{.name = "ClearLayer", .target = addr_of(&stack_target_primary)}, &stack_detour);
    ASSERT_TRUE(layer.has_value()) << layer.error().message();
    stack.push(std::move(*layer));

    stack.clear();

    EXPECT_TRUE(stack.empty());
    EXPECT_EQ(stack.size(), 0u);
    ASSERT_EQ(removed.size(), 2u);
    EXPECT_EQ(removed[0], "ClearLayer");
    EXPECT_EQ(removed[1], "ClearBase");
    EXPECT_FALSE(is_target_hooked(addr_of(&stack_target_primary)));
}

// The reference push() returns reaches the live hook, so a caller can capture the trampoline right after pushing.
TEST(HookStackTest, PushReturnsUsableHandleAndReportsSize)
{
    HookStack stack;
    EXPECT_TRUE(stack.empty());
    EXPECT_EQ(stack.size(), 0u);

    Result<Hook> r = inline_at(InlineRequest{.name = "StackEcho", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook &stored = stack.push(std::move(*r));

    EXPECT_EQ(stack.size(), 1u);
    EXPECT_FALSE(stack.empty());
    EXPECT_TRUE(static_cast<bool>(stored));
    EXPECT_EQ(stored.name(), "StackEcho");

    // The returned reference reaches the live trampoline (the capture-now pattern) and the detour is armed.
    auto *orig = stored.original<EchoFn>();
    ASSERT_NE(orig, nullptr);
    EXPECT_EQ(orig(7), 7);                   // trampoline yields the original body
    EXPECT_EQ(call_unfolded(&echo, 7), 107); // detour active while the stack owns the hook
    // Scope exit restores echo cleanly (single hook, so order is moot but the stack still owns the teardown).
}

// Concurrency + reentrancy: the per-hook status machine and the call() guard under thread stress and self-reentry. The
// per-hook recursive_mutex is held across call(), and disable()/~Hook must drain that mutex before the trampoline can
// be restored or freed. These tests pin the caller-visible guarantees directly, including a parked original that keeps
// the guard held until the test releases it.
namespace
{
    // Reentrancy fixture: a recursive target whose self-call re-enters the hooked prologue, so a detour that forwards
    // through call() is invoked again on the SAME thread while call() already holds the per-hook guard.
    std::atomic<int> s_reentrant_detour_calls{0};
    Hook *s_reentrant_hook = nullptr;

    DMK_TEST_NOINLINE int reentrant_target(int n)
    {
        if (n <= 0)
        {
            return 0;
        }
        // The recursive call must resolve to reentrant_target's patched ENTRY so each level re-enters the detour.
        // Routed through the unfoldable indirection because an optimizer turns direct self-recursion into a loop,
        // which would re-enter nothing and leave this proving only that the outermost call was hooked.
        return call_unfolded(&reentrant_target, n - 1) + 1;
    }

    int reentrant_detour(int n)
    {
        s_reentrant_detour_calls.fetch_add(1, std::memory_order_relaxed);
        // Forward to the original through the guarded call(): it re-acquires the per-hook recursive_mutex. The original
        // recurses back into this detour on the same thread, so the guard MUST be recursive or this self-deadlocks.
        return s_reentrant_hook->call<int>(n);
    }

    // Drain fixture: an original that parks inside call() (so call() keeps holding the guard) until the test releases
    // it, giving a second thread a window to attempt disable() and observe that it waits for the in-flight call.
    std::atomic<bool> s_original_parked{false};
    std::atomic<bool> s_release_original{false};

    DMK_TEST_NOINLINE int parking_original(int x)
    {
        s_original_parked.store(true, std::memory_order_release);
        while (!s_release_original.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        volatile int r = x;
        return r;
    }
} // namespace

TEST(HookConcurrency, ConcurrentEnableDisableIsRaceSafe)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "ConcEnableDisable", .target = addr_of(&echo)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    // Several threads hammer enable()/disable() on the same hook. The per-hook guard and status machine must fold the
    // storm into legal transitions, and the backend must remain callable afterward.
    constexpr int THREADS = 6;
    constexpr int ITERATIONS = 500;
    std::atomic<bool> go{false};
    std::vector<std::thread> pool;
    pool.reserve(THREADS);
    for (int t = 0; t < THREADS; ++t)
    {
        pool.emplace_back(
            [&h, &go, t]()
            {
                while (!go.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                for (int i = 0; i < ITERATIONS; ++i)
                {
                    if (((t + i) & 1) == 0)
                    {
                        (void)h.enable();
                    }
                    else
                    {
                        (void)h.disable();
                    }
                }
            });
    }
    go.store(true, std::memory_order_release);
    for (std::thread &worker : pool)
    {
        worker.join();
    }

    // The hook survived the storm: brought to a known state, both dispatch paths still work end to end.
    ASSERT_TRUE(h.enable().has_value());
    EXPECT_EQ(call_unfolded(&echo, 7), 107); // enabled: the detour adds 100
    EXPECT_EQ(h.call<int>(7), 7);            // original body through the trampoline
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(call_unfolded(&echo, 7), 7); // disabled: original prologue restored
}

TEST(HookConcurrency, ReentrantCallFromDetourRequiresRecursiveGuard)
{
    Result<Hook> r =
        inline_at(InlineRequest{.name = "Reentrant", .target = addr_of(&reentrant_target)}, &reentrant_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    s_reentrant_hook = &h;
    s_reentrant_detour_calls.store(0, std::memory_order_relaxed);

    // Invoking the hooked entry fires the detour, which forwards through the guarded call(); the original recurses into
    // the hooked entry, re-entering the detour on the same thread. call() holds a per-hook recursive_mutex across the
    // whole invocation, so the nested call() re-locks instead of self-deadlocking. A plain mutex would hang this line.
    const int result = call_unfolded(&reentrant_target, 4);
    EXPECT_EQ(result, 4);                                                   // recursion adds 1 four times down to 0
    EXPECT_EQ(s_reentrant_detour_calls.load(std::memory_order_relaxed), 5); // detour fired at depths 4,3,2,1,0

    s_reentrant_hook = nullptr;
}

TEST(HookConcurrency, DisableDrainsAnInFlightCall)
{
    Result<Hook> r = inline_at(InlineRequest{.name = "DrainCall", .target = addr_of(&parking_original)}, &echo_detour);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    s_original_parked.store(false, std::memory_order_release);
    s_release_original.store(false, std::memory_order_release);

    // Thread A enters call(), which acquires the per-hook guard and runs the original; the original parks, so the guard
    // stays held for as long as the test wants.
    std::thread caller([&h]() { (void)h.call<int>(7); });
    while (!s_original_parked.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // Thread B attempts disable() while the call is parked. disable() acquires the SAME guard, so it MUST block until
    // the call releases it -- it must never free the trampoline out from under the in-flight original.
    std::atomic<bool> disable_started{false};
    std::atomic<bool> disable_returned{false};
    std::thread disabler(
        [&h, &disable_started, &disable_returned]()
        {
            disable_started.store(true, std::memory_order_release);
            (void)h.disable();
            disable_returned.store(true, std::memory_order_release);
        });
    while (!disable_started.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // While the original is parked the guard is physically held, so disable() must not complete. A broken drain
    // (disable freeing the trampoline without waiting) can flip this flag before the release below.
    for (int spin = 0; spin < 1000; ++spin)
    {
        ASSERT_FALSE(disable_returned.load(std::memory_order_acquire))
            << "disable() completed while a guarded call() was still in flight (drain violated)";
        std::this_thread::yield();
    }

    // Release the original; the call returns, the guard drops, and disable() drains through to completion.
    s_release_original.store(true, std::memory_order_release);
    disabler.join();
    caller.join();
    EXPECT_TRUE(disable_returned.load(std::memory_order_acquire));
    EXPECT_FALSE(h.is_enabled());
}

// The load-bearing property behind ~Hook's decide-vs-restore atomicity: while a teardown holds a target's
// serialization slot (acquire_teardown_slot), a concurrent install on the same target cannot reach the Reserved
// state, so it cannot read the target's still-patched prologue as its resume. That closes the peek/restore window in
// which a hook layered after a bare newer-count peek but before the backend restore would be clobbered (a trampoline
// use-after-free). This exercises only the bookkeeping, on a synthetic target no real hook uses.
TEST(HookLedgerTeardownSlot, BlocksConcurrentInstallUntilSlotReleased)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();
    const std::uintptr_t target = 0xB0BA5000;

    const auto reserved = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(reserved.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ledger.commit_hook(target, reserved.id);

    // Claim the teardown slot for the sole (newest) hook: no newer layer, so a restore would be safe.
    EXPECT_EQ(ledger.acquire_teardown_slot(target, reserved.id), 0u);

    std::atomic<bool> install_started{false};
    std::atomic<bool> install_returned{false};
    std::atomic<bool> allow_install_cleanup{false};
    std::uint64_t install_id = 0;

    auto wait_for_flag = [](const std::atomic<bool> &flag, int attempts) -> bool
    {
        for (int i = 0; i < attempts; ++i)
        {
            if (flag.load(std::memory_order_acquire))
            {
                return true;
            }
            Sleep(1);
        }
        return flag.load(std::memory_order_acquire);
    };

    std::thread installer(
        [&]
        {
            install_started.store(true, std::memory_order_release);
            // Must block until the teardown slot is released: the teardown holds front-of-pending.
            const auto second = ledger.try_reserve_hook(target, false);
            EXPECT_EQ(second.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
            install_id = second.id;
            install_returned.store(true, std::memory_order_release);
            while (!allow_install_cleanup.load(std::memory_order_acquire))
            {
                Sleep(1);
            }
            ledger.commit_hook(target, second.id);
            (void)ledger.release_hook(target, second.id);
        });

    if (!wait_for_flag(install_started, 100))
    {
        // Release everything so the still-joinable thread cannot wedge the join, then fail.
        (void)ledger.release_hook(target, reserved.id);
        allow_install_cleanup.store(true, std::memory_order_release);
        installer.join();
        FAIL() << "installer thread did not start within the timeout";
    }
    // The install must NOT complete while the teardown slot is held.
    EXPECT_FALSE(wait_for_flag(install_returned, 20));

    // Release the slot the newest-first way (restore path): release_hook drops the sentinel AND the order entry,
    // waking the blocked installer. Its return (the newer-live count) is incidental here: the installer has already
    // layered its own id into the order while it was parked, so the count is not necessarily zero.
    (void)ledger.release_hook(target, reserved.id);

    const bool install_completed = wait_for_flag(install_returned, 1000);
    EXPECT_TRUE(install_completed) << "install must proceed once the teardown releases the slot";
    EXPECT_NE(install_id, 0u);

    allow_install_cleanup.store(true, std::memory_order_release);
    installer.join();
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// The leak path's slot release keeps the target physically represented: release_teardown_slot frees the
// serialization sentinel (so later installs proceed) but leaves the creation-order entry, so is_target_hooked and
// fail_if_already_hooked keep reporting the leaked-but-installed backend.
TEST(HookLedgerTeardownSlot, ReleaseTeardownSlotKeepsOrderEntry)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();
    const std::uintptr_t target = 0xB0BA6000;

    const auto older = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(older.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ledger.commit_hook(target, older.id);
    const auto newer = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(newer.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ledger.commit_hook(target, newer.id);

    // Tearing down the OLDER hook sees one newer layer, so the caller must leak and release via the slot-only path.
    EXPECT_EQ(ledger.acquire_teardown_slot(target, older.id), 1u);
    ledger.release_teardown_slot(target, older.id);

    // The order entry survives: the target is still hooked, and a fail-if-already-hooked reserve is refused.
    EXPECT_TRUE(ledger.is_target_hooked(target));
    const auto refused = ledger.try_reserve_hook(target, true);
    EXPECT_EQ(refused.status, DetourModKit::detail::HookLedger::ReserveStatus::AlreadyHooked);

    // The freed sentinel does not block a permissive layering install.
    const auto layered = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(layered.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ledger.commit_hook(target, layered.id);

    // Drain the ledger so the synthetic target does not leak into later assertions.
    (void)ledger.release_hook(target, older.id);
    (void)ledger.release_hook(target, newer.id);
    (void)ledger.release_hook(target, layered.id);
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// Missing bookkeeping cannot provide the serialization guarantee required for a safe restore. The teardown query
// must therefore fail closed to a positive count for both an unknown target and an unknown id on a tracked target.
TEST(HookLedgerTeardownSlot, MissingEntryFailsClosedToLeakDecision)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();
    constexpr std::uintptr_t target = 0xB0BA7000;

    EXPECT_GT(ledger.acquire_teardown_slot(target, 12345u), 0u);

    const auto reserved = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(reserved.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ledger.commit_hook(target, reserved.id);

    EXPECT_GT(ledger.acquire_teardown_slot(target, reserved.id + 1), 0u);
    EXPECT_EQ(ledger.release_hook(target, reserved.id), 0u);
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// End-to-end: two inline hooks layered on one target, then the OLDER one destroyed first. That is the oldest-first
// order a bare std::vector<Hook> (e.g. install_all's outcomes) produces. ~Hook must contain the trampoline
// use-after-free by leaking the older backend (recorded as an intentional HookManager leak) rather than restoring a
// prologue the newer layer's live trampoline still chains through.
TEST(HookInlineLayered, OldestFirstTeardownLeaksOlderBackend)
{
    // Measure a delta rather than resetting the process-wide counters, so this test does not perturb any other
    // leak-count assertion in the suite.
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    Result<Hook> older =
        inline_at(InlineRequest{.name = "LayerOld", .target = addr_of(&leak_target_layered)}, &real_hook_detour_add);
    ASSERT_TRUE(older.has_value()) << older.error().message();
    Result<Hook> newer =
        inline_at(InlineRequest{.name = "LayerNew", .target = addr_of(&leak_target_layered)}, &real_hook_detour_add);
    ASSERT_TRUE(newer.has_value()) << newer.error().message();

    std::optional<Hook> old_handle(std::move(older.value()));
    std::optional<Hook> new_handle(std::move(newer.value()));

    // Destroy the OLDER layer while the newer one is still live: the inverted (oldest-first) order.
    old_handle.reset();

    // The older backend must have been leaked, not restored -- exactly one new intentional HookManager leak event.
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1)
        << "oldest-first layered teardown must leak the older backend, not restore it";

    // Tearing the newer layer down now is the safe newest-first order and must not add another leak.
    new_handle.reset();
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1);

    Result<Hook> blocked = inline_at(InlineRequest{.name = "LayerAfterLeak",
                                                   .target = addr_of(&leak_target_layered),
                                                   .options = Options{.fail_if_already_hooked = true}},
                                     &real_hook_detour_add);
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(blocked.error().code, ErrorCode::TargetAlreadyHookedInProcess)
        << "a leaked backend remains physically installed and must stay represented in the ledger";
}

// VMT object-word fault boundary. DMK validates the object word, snapshots the table through guarded reads, and
// publishes through a guarded atomic compare-exchange. Every invalid state must fail before a backend clone is exposed.
namespace
{
    /// The x86-64 base page size; every hostile object word below gets a page of its own.
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
     * @brief Builds a one-page object whose vptr word sits in @p state, or nullptr if the page could not be pinned.
     * @param state The hostile state to pin the word's page to.
     * @param planted_vptr A genuine vtable pointer, stored into the word while the page is still writable.
     * @details @p planted_vptr is what makes the readable states meaningful: the word names a real, cloneable vtable,
     *          so the page's protection is the only thing left that can refuse the object. A word holding garbage
     *          would be refused by the slot walk instead and would prove nothing about the object-word gate.
     * @note Every page is leaked ON PURPOSE, the discipline NoAccessPage in fixtures/fault_injection.hpp documents: a
     *       released VA can be recycled by a later allocation, and a subsequent case's word would then land on live
     *       writable memory and be accepted, passing for the wrong reason. One page per call is negligible in a test
     *       process that exits immediately.
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

// The object-word gate is not a policy. vmt_for and apply_to must refuse an object whose vptr word DMK cannot safely
// capture and publish under EVERY VmtOptions set, the permissive default included. Drive both entry points across
// every policy and every hostile word state, and assert the typed code rather than mere failure.
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
        VmtOptions{.fail_if_already_hooked = true},
        VmtOptions{.fail_on_non_function_pointer = true},
        VmtOptions{.fail_if_already_hooked = true, .fail_on_non_function_pointer = true},
    };
    const std::array<ObjectWordState, 4> states{ObjectWordState::NoAccess, ObjectWordState::ReadOnly,
                                                ObjectWordState::Reserved, ObjectWordState::Guarded};

    for (const ObjectWordState state : states)
    {
        for (const VmtOptions &options : policies)
        {
            const std::string context = describe_word_case(state, options);

            // A fresh page per call keeps each case independent of what the last one did to its word. The guard state
            // in particular survives being tripped: swallowing a guard-page fault re-arms the fence before reporting
            // the read as failed, so a fired guard is not a way for a later case to pass on a disarmed word.
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

    // Every refusal left the handle intact. A refused apply must also leave no binding for the hostile object: one
    // would fault this handle's teardown, which no assertion could survive to report.
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

// The PAGE_READONLY word per entry point, in isolation. This is the state no read-based pre-flight can catch: the word
// is readable and names a genuine vtable, so the slot walk and header-prefix capture both pass. The explicit
// writability check must refuse it before publication.
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

// The gate's other half: it must refuse hostile object words without refusing ordinary ones, and a refusal must be
// inert. An ordinary writable object applies and restores, a hooked seed keeps dispatching through its clone across a
// refused apply, and the refused object leaves no backend record behind.
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

    // The detour firing is what proves the ABI-dependent slot index above is the right one: a wrong pick would leave
    // compute unhooked and yield the plain 5.
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

// The pre-count walks the live vtable, but the backend sizes its clone from the snapshot captured a moment later. If
// the table shrinks in between, the count that bounds hook_method must follow the snapshot rather than the pre-count:
// the backend bounds-checks no slot write, so a bound naming slots the clone does not hold would index past the clone
// allocation. The seam shrinks the table in exactly that window.
#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(VmtHookFaultProof, CaptureRaceBoundsMethodCountToTheClonedTable)
{
    // Two leading words so the RTTI prefix copy stays inside the fixture on the Itanium ABI (MinGW), where
    // VMT_HEADER is 2; the trailing null terminates the pre-count in bounds.
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

    // The pre-count sees three callable slots; the probe drops the run to one before the capture reads it.
    Result<VmtHook> created = [&]()
    {
        VmtCaptureShrinkScope scope(&vtable.methods[1]);
        return vmt_for("CaptureRaceShrink", &vptr);
    }();
    ASSERT_TRUE(created.has_value()) << created.error().message();
    VmtHook vh = std::move(*created);

    // Slot 0 was cloned, so it is hookable. Slot 1 was counted by the pre-flight but never cloned: admitting it would
    // hand the backend an index past its allocation.
    EXPECT_TRUE(vh.hook_method(0, &vmt_detour_compute).has_value());
    const Result<void> past_clone = vh.hook_method(1, &vmt_detour_compute);
    ASSERT_FALSE(past_clone.has_value());
    EXPECT_EQ(past_clone.error().code, ErrorCode::InvalidArg);
}

// Pointer words do not fully determine SafetyHook's slot count: it re-queries whether each target page is executable.
// This seam removes execute permission from slot 1 after DMK counts the captured words but before the backend walks
// its surrogate. The backend allocation must still contain both captured slots, and method 1 must retain its captured
// original. A one-slot allocation would place the next clone at method 1's address and expose the unchecked overrun.
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

    // The backend allocator is first-fit and packs these uninterrupted allocations without padding beyond two-byte
    // alignment. If SafetyHook counted only slot 0, the neighbour would start at raced method 1 instead.
    const std::uintptr_t header_bytes = TEST_VMT_HEADER_WORDS * sizeof(std::uintptr_t);
    const std::uintptr_t neighbour_allocation_base = reinterpret_cast<std::uintptr_t>(neighbour_vptr) - header_bytes;
    ASSERT_EQ(neighbour_allocation_base, raced_clone_base + (2 * sizeof(std::uintptr_t)));

    ASSERT_TRUE(raced_hook.hook_method(1, &vmt_detour_compute).has_value());
    EXPECT_EQ(raced_hook.original<VmtComputeFn>(1), reinterpret_cast<VmtComputeFn>(second_method.addr()));
}
#endif

// The state no pre-flight can catch: the object word is valid when captured and changes before publication. The seam
// first confirms the expected vptr, then fires immediately before the atomic compare-exchange, so Displace lands in the
// former read/store window. A fault or mismatch must return InvalidObject without overwriting the newer vptr or leaving
// a binding or ledger entry. The surviving seed hook proves the object gate and handle remain usable; a later create
// reuses and releases the failed create's allocator slot so a stale ledger entry at that base is directly observable.
#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(VmtHookFaultProof, PublicationRaceReturnsTypedFailureWithoutResidue)
{
    auto donor = std::make_unique<VmtTestTarget>();
    const std::uintptr_t genuine_vptr = *reinterpret_cast<std::uintptr_t *>(donor.get());
    auto seed_object = std::make_unique<VmtTestTarget>();
    Result<VmtHook> seeded = vmt_for("PublicationRaceSeed", seed_object.get());
    ASSERT_TRUE(seeded.has_value()) << seeded.error().message();
    VmtHook vh = std::move(*seeded);

    const std::array<VmtPublishRace, 3> races{VmtPublishRace::Unmap, VmtPublishRace::Displace,
                                              VmtPublishRace::ReadOnly};
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
            // The refusal must leave the racing writer's word intact: a publish that ran anyway would have
            // overwritten it with the clone base.
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

// A vtable whose FIRST slot is not a callable address: the slot walk succeeds and returns an engaged count of ZERO.
// That is a different failure from an unreadable table (the walk worked), and the backend has no check for it -- it
// would size a clone to the RTTI prefix alone and produce an unusable address point. vmt_for rejects the engaged zero
// before snapshotting or publishing it.
TEST(HookVmt, PreFlightRefusesVtableWithNoCallableSlots)
{
    // Mapped and readable but not executable, so the walk reads slot 0 fine and terminates on it, yielding zero.
    static std::uintptr_t data_sink = 0;
    // The fake vptr points into the MIDDLE of the table so the RTTI header prefix below it (vptr - VMT_HEADER) is
    // mapped and readable. That keeps the engaged-zero check the only thing that can refuse this object.
    static std::uintptr_t data_vtable[8];
    for (std::uintptr_t &slot : data_vtable)
    {
        slot = reinterpret_cast<std::uintptr_t>(&data_sink);
    }

    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(&data_vtable[4])};
    const std::uintptr_t vptr_before = object.vptr;

    const Result<VmtHook> created = vmt_for("ZeroSlotVmt", &object);
    ASSERT_FALSE(created.has_value());
    EXPECT_EQ(created.error().code, ErrorCode::InvalidObject);
    // A zero-slot clone would expose a one-past-the-end address point, so an unchanged vptr proves the refusal
    // published nothing.
    EXPECT_EQ(object.vptr, vptr_before) << "a refused create must leave the object's vptr untouched";
}

// Two VMT clones stacked on ONE object, torn down newest-first: B unwinds onto A's clone base, then A unwinds onto the
// pristine table. No layer is ever outranked at its own teardown, so nothing may be leaked and the object must land
// back on its original vtable.
TEST(HookVmtLayered, NewestFirstTeardownRestoresPristineTable)
{
    auto object = std::make_unique<VmtTestTarget>();
    const std::uintptr_t pristine_vptr = *reinterpret_cast<std::uintptr_t *>(object.get());
    // Measure a delta rather than resetting the process-wide counters, so this test does not perturb any other
    // leak-count assertion in the suite.
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    {
        // Stacking is the permissive clone-of-clone, which warns by contract; keep that off the default sink.
        ScopedLogCapture capture;

        Result<VmtHook> ra = vmt_for("LayerVmtOrderA", object.get());
        ASSERT_TRUE(ra.has_value()) << ra.error().message();
        std::optional<VmtHook> a(std::move(*ra));

        Result<VmtHook> rb = vmt_for("LayerVmtOrderB", object.get());
        ASSERT_TRUE(rb.has_value()) << rb.error().message();
        std::optional<VmtHook> b(std::move(*rb));

        b.reset();
        a.reset();
    }

    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), pristine_vptr)
        << "newest-first VMT teardown must land the object back on its pristine table";
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before)
        << "no layer is outranked in newest-first order, so nothing may be leaked";
    EXPECT_EQ(dispatch_compute(object.get(), 2, 3), 5);
}

// The same two clones torn down OLDEST-first, the order a bare std::vector<VmtHook> produces. A's clone base is the
// original B recorded and will write back at ~B, so ~A must leak its clone rather than let the backend free a table a
// live successor still points at. The accepted, documented trade is that the object ends on A's LEAKED clone rather
// than its pristine table: not a restore, but not a use-after-free either.
TEST(HookVmtLayered, OldestFirstTeardownLeaksOutrankedClone)
{
    auto object = std::make_unique<VmtTestTarget>();
    auto peer = std::make_unique<VmtTestTarget>();
    const std::uintptr_t pristine_vptr = *reinterpret_cast<std::uintptr_t *>(object.get());
    const std::uintptr_t peer_pristine_vptr = *reinterpret_cast<std::uintptr_t *>(peer.get());
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    std::uintptr_t a_clone_base = 0;

    {
        ScopedLogCapture capture;

        Result<VmtHook> ra = vmt_for("LayerVmtLeakA", object.get());
        ASSERT_TRUE(ra.has_value()) << ra.error().message();
        std::optional<VmtHook> a(std::move(*ra));
        a_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());
        ASSERT_TRUE(a->apply_to(peer.get()).has_value());
        ASSERT_NE(*reinterpret_cast<std::uintptr_t *>(peer.get()), peer_pristine_vptr);

        Result<VmtHook> rb = vmt_for("LayerVmtLeakB", object.get());
        ASSERT_TRUE(rb.has_value()) << rb.error().message();
        std::optional<VmtHook> b(std::move(*rb));

        // Inverted order: destroy the OLDER clone while B still records A's clone base as the original it will write
        // back into the live object.
        a.reset();
        EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1)
            << "an outranked VMT clone must be leaked, not freed under its successor's recorded original";
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(peer.get()), peer_pristine_vptr)
            << "an outranked object must not prevent independent objects from being restored";
        EXPECT_NE(capture.drain().find("leaked this clone to avoid a vtable use-after-free"), std::string::npos)
            << "the leak-on-inversion branch must warn so the condition is diagnosable";

        // B unwinds onto A's leaked clone base. Leaked, so still mapped: the store is not a dangling pointer.
        b.reset();
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), a_clone_base);
    }

    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(object.get()), pristine_vptr)
        << "the documented trade: an inverted teardown leaves the object on the leaked clone, not the original table";
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1);
    // The leaked clone is a faithful copy of the original table, so dispatch still works rather than jumping through
    // freed memory.
    EXPECT_EQ(dispatch_compute(object.get(), 2, 3), 5);
}

TEST(HookVmt, TeardownReleasesAlreadyOriginalReadOnlyBinding)
{
    auto donor = std::make_unique<VmtTestTarget>();
    const std::uintptr_t original_vptr = *reinterpret_cast<std::uintptr_t *>(donor.get());
    dmk_test::ScratchPage object_page;
    ASSERT_TRUE(object_page.ok());
    auto *const object_word = static_cast<std::uintptr_t *>(object_page.base());
    *object_word = original_vptr;
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    Result<VmtHook> created = vmt_for("AlreadyOriginalReadOnly", object_word);
    ASSERT_TRUE(created.has_value()) << created.error().message();
    std::optional<VmtHook> hook(std::move(*created));
    ASSERT_NE(*object_word, original_vptr);

    *object_word = original_vptr;
    DWORD previous_protection = 0;
    ASSERT_NE(::VirtualProtect(object_word, sizeof(*object_word), PAGE_READONLY, &previous_protection), 0);
    EXPECT_EQ(previous_protection, PAGE_EXECUTE_READWRITE);

    hook.reset();
    EXPECT_EQ(*object_word, original_vptr);
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before)
        << "an already-original binding needs no write and must not force a clone leak";
}

#if defined(DMK_ENABLE_TEST_SEAMS)
// The warning probe pauses teardown at the logging boundary while another thread enters vmt_for. A bounded wait fails
// without hanging if teardown still owns the object gate there.
TEST(HookVmtLayered, TeardownWarningRunsAfterObjectGateRelease)
{
    auto object = std::make_unique<VmtTestTarget>();
    auto inner_object = std::make_unique<VmtTestTarget>();
    ScopedLogCapture capture;

    Result<VmtHook> older_result = vmt_for("WarningGateOlder", object.get());
    ASSERT_TRUE(older_result.has_value()) << older_result.error().message();
    std::optional<VmtHook> older(std::move(*older_result));

    Result<VmtHook> newer_result = vmt_for("WarningGateNewer", object.get());
    ASSERT_TRUE(newer_result.has_value()) << newer_result.error().message();
    std::optional<VmtHook> newer(std::move(*newer_result));

    const VmtTeardownWarningProbeScope probe_scope;
    std::atomic<bool> inner_ok{false};
    std::thread inner_thread(
        [&]
        {
            for (int i = 0; i < 500 && !s_vmt_warning_probe_entered.load(std::memory_order_acquire); ++i)
            {
                Sleep(1);
            }
            if (!s_vmt_warning_probe_entered.load(std::memory_order_acquire))
            {
                return;
            }
            Result<VmtHook> inner = vmt_for("WarningGateInner", inner_object.get());
            inner_ok.store(inner.has_value(), std::memory_order_release);
            s_vmt_warning_inner_done.store(true, std::memory_order_release);
        });

    older.reset();
    inner_thread.join();

    EXPECT_TRUE(s_vmt_warning_probe_entered.load(std::memory_order_acquire));
    EXPECT_TRUE(s_vmt_warning_inner_done_in_window.load(std::memory_order_acquire))
        << "the teardown warning path held the process-wide VMT object gate while logging";
    EXPECT_TRUE(inner_ok.load(std::memory_order_acquire));
    newer.reset();
}
#endif

TEST(HookVmtLayered, OutrankedRemoveRetainsOriginalForLaterRestore)
{
    auto object = std::make_unique<VmtTestTarget>();
    const std::uintptr_t pristine_vptr = *reinterpret_cast<std::uintptr_t *>(object.get());
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    ScopedLogCapture capture;
    Result<VmtHook> ra = vmt_for("RemoveRestoreA", object.get());
    ASSERT_TRUE(ra.has_value()) << ra.error().message();
    std::optional<VmtHook> a(std::move(*ra));
    const std::uintptr_t a_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());

    Result<VmtHook> rb = vmt_for("RemoveRestoreB", object.get());
    ASSERT_TRUE(rb.has_value()) << rb.error().message();
    std::optional<VmtHook> b(std::move(*rb));

    // A cannot restore while B outranks it, so remove_from must retain A's DMK binding.
    ASSERT_TRUE(a->remove_from(object.get()).has_value());

    b.reset();
    ASSERT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), a_clone_base);

    // A's retained binding restores the pristine table after B unwinds to A's clone.
    a.reset();
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), pristine_vptr);
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before);
    EXPECT_EQ(dispatch_compute(object.get(), 2, 3), 5);
}

// remove_from called while a NEWER clone is layered on the object. The detached backend has no object bookkeeping;
// DMK's binding is the complete restoration record. Dropping it would let ~A free a clone that B still records as the
// original it will write back at ~B.
TEST(HookVmtLayered, RemoveFromOutrankedObjectKeepsCloneReachable)
{
    auto object = std::make_unique<VmtTestTarget>();
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    std::uintptr_t a_clone_base = 0;

    {
        ScopedLogCapture capture;

        Result<VmtHook> ra = vmt_for("RemoveOutrankedA", object.get());
        ASSERT_TRUE(ra.has_value()) << ra.error().message();
        std::optional<VmtHook> a(std::move(*ra));
        a_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());

        std::optional<VmtHook> b;
        {
            MethodVmtScope scope(*a);
            ASSERT_TRUE(a->hook_method<VmtTransformFn>(VMT_TRANSFORM_INDEX, &vmt_detour_transform).has_value());
            EXPECT_EQ(dispatch_transform(object.get(), 7), 514);

            Result<VmtHook> rb = vmt_for("RemoveOutrankedB", object.get());
            ASSERT_TRUE(rb.has_value()) << rb.error().message();
            b.emplace(std::move(*rb));

            // B cloned A's clone, so A's detour came along and still fires through B's table.
            EXPECT_EQ(dispatch_transform(object.get(), 7), 514);

            // A releases its object while B outranks it. DMK must retain the binding that keeps A's clone reachable.
            ASSERT_TRUE(a->remove_from(object.get()).has_value());
        }

        // The leaked clone retains the detour, so clear its handle publication before destroying the handle.
        a.reset();
        EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1)
            << "remove_from must not drop the binding of an object it could not release: ~A then frees a "
               "clone B still records as its original";

        b.reset();
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), a_clone_base);
    }

    // Churn the backend's own clone allocator: a FREED clone's bytes would be handed to one of these and overwritten,
    // turning the dispatch below into a jump through scribbled memory. A leaked clone is untouched by this. The CRT
    // heap is the wrong pool to churn -- the backend allocates clones from its own VirtualAlloc-backed allocator.
    for (int i = 0; i < 16; ++i)
    {
        auto churn_object = std::make_unique<VmtTestTarget>();
        Result<VmtHook> churn = vmt_for("RemoveOutrankedChurn", churn_object.get());
        ASSERT_TRUE(churn.has_value()) << churn.error().message();
        VmtHook churn_hook = std::move(*churn);
        ASSERT_TRUE(churn_hook.hook_method<VmtComputeFn>(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    }

    // The object still dispatches through A's leaked clone, whose transform slot still holds A's detour. s_method_vmt
    // is null now, so that detour returns its unhooked marker: a defined value only reachable if the slot survived.
    EXPECT_EQ(dispatch_transform(object.get(), 7), -1)
        << "the object must still dispatch through A's leaked clone rather than freed or recycled memory";
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1);
}

// Re-applying an object this handle already tracks, after a newer layer moved it off the vptr the handle recorded.
// Teardown restores from the binding, so admitting this would leave the binding naming a vptr the object never had:
// A would read its own object as restored, free its clone, and ~B would then write that freed clone into the live
// object. Republishing is also wrong on its own terms, since A's clone was copied before B existed and putting it back
// would discard B's slots. Refusing is what keeps every recorded original true.
TEST(HookVmtLayered, ReapplyAcrossNewerLayerIsRefused)
{
    auto object = std::make_unique<VmtTestTarget>();
    const std::uintptr_t pristine_vptr = *reinterpret_cast<std::uintptr_t *>(object.get());
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    {
        ScopedLogCapture capture;

        Result<VmtHook> ra = vmt_for("ReapplyLayerA", object.get());
        ASSERT_TRUE(ra.has_value()) << ra.error().message();
        std::optional<VmtHook> a(std::move(*ra));
        const std::uintptr_t a_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());

        Result<VmtHook> rb = vmt_for("ReapplyLayerB", object.get());
        ASSERT_TRUE(rb.has_value()) << rb.error().message();
        std::optional<VmtHook> b(std::move(*rb));
        const std::uintptr_t b_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());
        ASSERT_NE(a_clone_base, b_clone_base);

        const Result<void> reapplied = a->apply_to(object.get());
        ASSERT_FALSE(reapplied.has_value()) << "a re-apply across a newer layer must not silently republish";
        EXPECT_EQ(reapplied.error().code, ErrorCode::HookAlreadyExists);
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), b_clone_base)
            << "a refused apply must leave the object where the newer layer put it";

        // A's binding is still truthful, so the inverted teardown can still see that B outranks it and leaks rather
        // than freeing a clone B records as the original it will write back.
        a.reset();
        EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1)
            << "the refused re-apply must leave A's binding able to detect that it is outranked";

        b.reset();
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), a_clone_base);
    }

    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(object.get()), pristine_vptr);
    EXPECT_EQ(dispatch_compute(object.get(), 2, 3), 5);
}

// An object sitting on this handle's own clone base that the handle never applied: the kit holds no original vptr for
// it, so recording one now would name the clone base as the object's own original, and teardown would read it as
// already restored and free the clone out from under it. Both policies must refuse, or the strict opt-in would be the
// laxer of the two.
TEST(HookVmt, ApplyToUntrackedObjectOnOwnCloneIsRefusedUnderEveryPolicy)
{
    auto seed = std::make_unique<VmtTestTarget>();
    auto stowaway = std::make_unique<VmtTestTarget>();
    const std::uintptr_t stowaway_pristine = *reinterpret_cast<std::uintptr_t *>(stowaway.get());

    Result<VmtHook> r = vmt_for("StowawaySeed", seed.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    const std::uintptr_t clone_base = *reinterpret_cast<std::uintptr_t *>(seed.get());

    // The shape a host produces by byte-copying, pooling or recycling an instance whose vptr word was captured while
    // it was on the clone. No kit call put this object here, so no binding exists for it.
    *reinterpret_cast<std::uintptr_t *>(stowaway.get()) = clone_base;

    // The stowaway must come off the clone even when an assertion below returns early. Declared after vh, this guard
    // restores before vh frees the clone and before ~VmtTestTarget dispatches its virtual destructor.
    struct RestoreStowaway
    {
        void *object;
        std::uintptr_t vptr;
        ~RestoreStowaway() noexcept { *reinterpret_cast<std::uintptr_t *>(object) = vptr; }
    } const restore{stowaway.get(), stowaway_pristine};

    const std::array<VmtOptions, 2> policies{VmtOptions{}, VmtOptions{.fail_if_already_hooked = true}};
    for (const VmtOptions &options : policies)
    {
        const Result<void> applied = vh.apply_to(stowaway.get(), options);
        ASSERT_FALSE(applied.has_value()) << "fail_if_already_hooked=" << options.fail_if_already_hooked;
        EXPECT_EQ(applied.error().code, ErrorCode::HookAlreadyExists)
            << "fail_if_already_hooked=" << options.fail_if_already_hooked;
    }
}
