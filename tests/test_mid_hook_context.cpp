#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include "DetourModKit/hook.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "fixtures/scratch_page.hpp"
#include "internal/drain_backoff.hpp"

using namespace DetourModKit;
// The mid-hook detours below exercise the DMK-owned MidContext accessor surface (gpr / stack_pointer /
// resume_stack_pointer / instruction_pointer / flags / xmm). The SafetyHook backend is confined to the library, so a
// detour names only these DMK types, exactly as a shipping consumer would.
using namespace DetourModKit::hook;

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

// Mid-hook captured-context save/restore semantics.
//
// A mid-hook detour receives the CPU register state captured at the hook point as a MidContext (a
// reinterpret_cast view onto the backend's Context64). The mid-hook stub saves the full context at the hook
// point, calls the detour, then reloads every GPR/XMM/rflags and resumes via a `ret` that pops the
// (possibly-modified) rip slot. These tests confirm, against the real backend, the exact operations a
// mid-hook detour relies on:
//   * GPR READS  (rcx/rdx/r8/...): the detour observes the live argument registers.
//   * GPR WRITES (r8):             an overwritten general-purpose register survives the trampoline resume;
//                                  the gating case (gate-skip with r8=1, or redirect a source pointer).
//   * a real rsp:                  the captured stack pointer is a genuine pointer into the live stack.
//   * rip redirect:                a context-modified rip is honored on resume.
//
// Win64 integer-arg ABI (MinGW and MSVC both target it on Windows): 1st=rcx, 2nd=rdx, 3rd=r8, 4th=r9. The
// hook is installed at the function ENTRY, so the detour runs before the prologue homes the argument
// registers, and a write to a captured register is therefore observed by the resumed body.

namespace
{
    DMK_TEST_NOINLINE int sum_first_second(int a, int b)
    {
        volatile int r = a + b; // a<-rcx, b<-rdx
        return r;
    }

    DMK_TEST_NOINLINE int return_third(int a, int b, int c)
    {
        (void)a;
        (void)b;
        volatile int r = c; // c<-r8 : the register the shipping mods write
        return r;
    }

    DMK_TEST_NOINLINE int read_probe(int a, int b, int c)
    {
        volatile int r = a + b + c;
        return r;
    }

    DMK_TEST_NOINLINE int rip_original()
    {
        volatile int r = 11;
        return r;
    }

    DMK_TEST_NOINLINE int rip_replacement()
    {
        volatile int r = 22;
        return r;
    }

    DMK_TEST_NOINLINE float pass_float(float x)
    {
        volatile float r = x; // x <- xmm0 (Win64 float-arg ABI)
        return r;
    }

    volatile double s_vector_sink = 0.0;
    std::atomic<int> s_vector_calls{0};

    DMK_TEST_NOINLINE double xmm0_clobber_value() noexcept
    {
        return 1234.5;
    }

    void xmm0_clobbering_detour(MidContext &)
    {
        s_vector_calls.fetch_add(1, std::memory_order_relaxed);
        s_vector_sink = xmm0_clobber_value();
    }

    std::atomic<int> s_calls{0};
    std::atomic<std::uint64_t> s_rcx{0};
    std::atomic<std::uint64_t> s_rdx{0};
    std::atomic<std::uint64_t> s_r8{0};
    std::atomic<std::uint64_t> s_rsp{0};
    std::atomic<std::uint64_t> s_resume_rsp{0};
    std::atomic<std::uint64_t> s_rflags{0};
    std::atomic<std::uint32_t> s_xmm0_bits{0};

    /**
     * @brief Builds and arms a mid hook at @p target; returns the armed RAII handle the caller holds.
     * @details Templated on the target's function type so a plain `&fn` argument reinterpret_casts cleanly to an
     *          Address (a function pointer does not implicitly convert to void*). `mid_at` returns a hook whose
     *          target is not yet patched, so the handle is armed here and an arming failure is surfaced as the
     *          returned error.
     */
    template <class Fn> [[nodiscard]] Result<Hook> install_mid(std::string name, Fn *target, MidHookFn detour)
    {
        Result<Hook> hook = mid_at(
            MidRequest{.name = std::move(name), .target = Address{reinterpret_cast<std::uintptr_t>(target)}}, detour);
        if (!hook.has_value())
        {
            return hook;
        }
        if (const Result<void> armed = hook->enable(); !armed.has_value())
        {
            return std::unexpected(armed.error());
        }
        return hook;
    }
} // namespace

class MidHookContextTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        s_calls.store(0);
        s_rcx.store(0);
        s_rdx.store(0);
        s_r8.store(0);
        s_rsp.store(0);
        s_resume_rsp.store(0);
        s_rflags.store(0);
        s_xmm0_bits.store(0);
        s_vector_calls.store(0);
    }
};

// 1. GPR READ INTEGRITY: the detour observes the live argument registers.
TEST_F(MidHookContextTest, DetourReadsLiveArgumentRegisters)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    auto detour = [](MidContext &ctx)
    {
        s_calls.fetch_add(1, std::memory_order_relaxed);
        s_rcx.store(gpr(ctx, Gpr::Rcx), std::memory_order_relaxed);
        s_rdx.store(gpr(ctx, Gpr::Rdx), std::memory_order_relaxed);
        s_r8.store(gpr(ctx, Gpr::R8), std::memory_order_relaxed);
    };

    Result<Hook> result = install_mid("MidRead", &read_probe, detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);
    EXPECT_TRUE(hook.is_enabled());

    volatile int observed = read_probe(0x11, 0x22, 0x33);
    EXPECT_EQ(observed, 0x11 + 0x22 + 0x33); // unmodified path still computes correctly
    EXPECT_GE(s_calls.load(), 1);
    EXPECT_EQ(static_cast<int>(s_rcx.load() & 0xFFFFFFFFu), 0x11);
    EXPECT_EQ(static_cast<int>(s_rdx.load() & 0xFFFFFFFFu), 0x22);
    EXPECT_EQ(static_cast<int>(s_r8.load() & 0xFFFFFFFFu), 0x33);
}

// 2. The captured rsp is a real, populated stack pointer.
TEST_F(MidHookContextTest, RspIsRealStackPointer)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    auto detour = [](MidContext &ctx) { s_rsp.store(stack_pointer(ctx), std::memory_order_relaxed); };

    Result<Hook> result = install_mid("MidRsp", &read_probe, detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    int local = 0;
    volatile int observed = read_probe(1, 2, 3);
    (void)observed;

    std::uint64_t rsp = s_rsp.load();
    EXPECT_NE(rsp, 0u);
    EXPECT_EQ(rsp & 0x7u, 0u) << "rsp must be at least 8-byte aligned";
    // The detour runs deeper on the SAME stack as this frame; a real rsp lands within a
    // small window of a caller local (not a dummy / zero / garbage value).
    std::uint64_t probe = reinterpret_cast<std::uint64_t>(&local);
    std::uint64_t delta = (probe > rsp) ? (probe - rsp) : (rsp - probe);
    EXPECT_LT(delta, static_cast<std::uint64_t>(0x100000)) << "ctx.rsp not within the caller's stack region";
}

// 3. GPR WRITE survives resume: rcx (the SafetyHook-proven write pattern).
TEST_F(MidHookContextTest, GprWriteRcxSurvivesResume)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::Rcx) = 1000; }; // overwrite first arg (a)

    Result<Hook> result = install_mid("MidWriteRcx", &sum_first_second, detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    // unhooked: 1+2=3 ; with ctx.rcx:=1000 the resumed body computes 1000+2.
    volatile int observed = sum_first_second(1, 2);
    EXPECT_EQ(observed, 1000 + 2);
}

// 4. r8 write survives resume: the gating general-purpose-register write. A detour that overwrites r8
// (gate-skip with r8=1, or redirect a source pointer via r8=&buf) must see that write survive the trampoline,
// or it breaks silently.
TEST_F(MidHookContextTest, GprWriteR8SurvivesResume)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    auto detour = [](MidContext &ctx) { gpr(ctx, Gpr::R8) = 777; }; // overwrite third arg (c)

    Result<Hook> result = install_mid("MidWriteR8", &return_third, detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    // unhooked: returns c=3 ; with ctx.r8:=777 the resumed body returns 777.
    volatile int observed = return_third(1, 2, 3);
    EXPECT_EQ(observed, 777) << "ctx.r8 write did not survive mid-hook resume";
}

// 5. A context-modified rip is honored on resume. Redirecting ctx.rip to another same-signature function at
// the entry hook makes the stub's final `ret` resume into that function instead of the original body.
TEST_F(MidHookContextTest, RipWriteRedirectsExecution)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    ASSERT_EQ(rip_original(), 11); // sanity, unmodified
    ASSERT_EQ(rip_replacement(), 22);

    auto detour = [](MidContext &ctx) { instruction_pointer(ctx) = reinterpret_cast<uintptr_t>(&rip_replacement); };

    Result<Hook> result = install_mid("MidWriteRip", &rip_original, detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    volatile int observed = rip_original();
    EXPECT_EQ(observed, 22) << "context-modified rip not honored on resume";
}

// 6. XMM READ: the detour observes the live xmm0 float argument. xmm() is read-only by design; backend
// XMM writes are proven by SafetyHook's own suite and are not surfaced writably here.
TEST_F(MidHookContextTest, DetourReadsXmm0FloatArg)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    auto detour = [](MidContext &ctx)
    {
        float v = xmm(ctx, 0).lane<float>(0);
        std::uint32_t bits = 0;
        std::memcpy(&bits, &v, sizeof(bits));
        s_xmm0_bits.store(bits, std::memory_order_relaxed);
    };

    Result<Hook> result = install_mid("MidXmmRead", &pass_float, detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    volatile float observed = pass_float(3.5f);
    EXPECT_EQ(observed, 3.5f); // unmodified path still correct

    float got = 0.0f;
    std::uint32_t bits = s_xmm0_bits.load();
    std::memcpy(&got, &bits, sizeof(got));
    EXPECT_EQ(got, 3.5f) << "detour did not observe the live xmm0 float argument";
}

// Opt-in probe for the xmm() XMM0-15 preservation warning in hook.hpp: it proves callback entry and XMM0
// restoration after a deliberate clobber. It is a capability probe rather than a per-run regression gate, so it
// runs only under --gtest_also_run_disabled_tests.
TEST_F(MidHookContextTest, DISABLED_MidHookVectorFrame)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    s_vector_sink = 0.0;
    Result<Hook> result = install_mid("MidVectorFrame", &pass_float, &xmm0_clobbering_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    volatile float observed = pass_float(7.25f);
    EXPECT_EQ(s_vector_calls.load(std::memory_order_relaxed), 1);
    const double sink = s_vector_sink;
    EXPECT_EQ(sink, 1234.5) << "the detour did not run its xmm0 clobber store";
    EXPECT_EQ(observed, 7.25f) << "the mid-hook frame did not restore xmm0 across a detour that clobbered vector state";
}

// 7. The resume stack pointer (trampoline_rsp) and the flags register (rflags) are readable at the hook point.
// These two accessors expose the resume stack pointer (trampoline_rsp) and flags (rflags) the trampoline restores on
// resume, which a detour may need to read or rewrite. The captured resume rsp is a real stack pointer, and rflags
// always has the reserved bit 1 set on x86-64, so a zeroed view would mean the accessor missed the live register.
TEST_F(MidHookContextTest, ResumeStackPointerAndFlagsAreReadable)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    auto detour = [](MidContext &ctx)
    {
        s_resume_rsp.store(resume_stack_pointer(ctx), std::memory_order_relaxed);
        s_rflags.store(flags(ctx), std::memory_order_relaxed);
    };

    Result<Hook> result = install_mid("MidResumeFlags", &read_probe, detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    volatile int observed = read_probe(1, 2, 3);
    (void)observed;

    std::uint64_t resume_rsp = s_resume_rsp.load();
    EXPECT_NE(resume_rsp, 0u) << "resume stack pointer (trampoline_rsp) must be a live stack pointer";
    EXPECT_EQ(resume_rsp & 0x7u, 0u) << "resume stack pointer must be at least 8-byte aligned";
    // rflags bit 1 is the always-set reserved bit on x86-64; its presence proves a live flags capture.
    EXPECT_NE(s_rflags.load() & 0x2u, 0u) << "flags() did not capture the live rflags register";
}

// The routed gateway and exit thunk bracket the backend MID stub, so both must preserve the arithmetic flags at the
// hook point. This planted leaf establishes a known flag word immediately before a NOP hook site, then captures the
// callback's replacement with SETcc instructions before anything else can modify it.
TEST_F(MidHookContextTest, ArithmeticFlagsAreCapturedAndRestoredExactly)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "requires x86-64 (Win64) calling convention";
#endif
    constexpr std::size_t hook_offset = 8;
    constexpr std::size_t probe_offset = 40;
    constexpr std::uintptr_t carry = 1u << 0;
    constexpr std::uintptr_t parity = 1u << 2;
    constexpr std::uintptr_t auxiliary = 1u << 4;
    constexpr std::uintptr_t zero = 1u << 6;
    constexpr std::uintptr_t sign = 1u << 7;
    constexpr std::uintptr_t overflow = 1u << 11;
    constexpr std::uintptr_t arithmetic_mask = carry | parity | auxiliary | zero | sign | overflow;
    constexpr std::uintptr_t captured_arithmetic = parity | auxiliary | sign | overflow;

    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok()) << "could not allocate the executable flag fixture";
    // mov eax, 0x7fffffff; add eax, 1. The ADD leaves CF=0, PF=1, AF=1, ZF=0, SF=1, OF=1.
    page.put(0, {0xB8, 0xFF, 0xFF, 0xFF, 0x7F, 0x83, 0xC0, 0x01});
    std::memset(static_cast<std::uint8_t *>(page.base()) + hook_offset, 0x90, probe_offset - hook_offset);
    // setc al; setz cl; seto dl; movzx each byte; shift/OR into CF|ZF|OF bits; ret.
    page.put(probe_offset, {0x0F, 0x92, 0xC0, 0x0F, 0x94, 0xC1, 0x0F, 0x90, 0xC2, 0x0F, 0xB6, 0xC0, 0x0F, 0xB6,
                            0xC9, 0x0F, 0xB6, 0xD2, 0xD1, 0xE1, 0xC1, 0xE2, 0x02, 0x09, 0xC8, 0x09, 0xD0, 0xC3});
    ASSERT_NE(::FlushInstructionCache(::GetCurrentProcess(), page.base(), dmk_test::ScratchPage::PAGE_SIZE), 0);

    using FlagProbe = int();
    auto *const probe = reinterpret_cast<FlagProbe *>(page.addr());
    auto *const hook_site = reinterpret_cast<FlagProbe *>(page.addr(hook_offset));
    ASSERT_EQ(probe(), 0b100) << "the unhooked fixture did not establish the expected flags";

    auto detour = [](MidContext &ctx)
    {
        const std::uintptr_t captured = flags(ctx);
        s_rflags.store(captured, std::memory_order_relaxed);
        flags(ctx) = (captured & ~(carry | zero | overflow)) | carry | zero;
    };
    Result<Hook> result = install_mid("MidArithmeticFlags", hook_site, +detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    EXPECT_EQ(probe(), 0b011) << "the callback's CF/ZF/OF replacement did not survive resume";
    EXPECT_EQ(s_rflags.load(std::memory_order_relaxed) & arithmetic_mask, captured_arithmetic)
        << "the callback did not receive the arithmetic flags established at the hook point";
}

// XmmView::lane fails closed on an out-of-range lane instead of reading past the 16-byte register. This needs no
// live hook: XmmView is a plain value type, so it pins the bounds contract directly.
TEST(MidContextXmmViewTest, LaneFailsClosedOutOfRange)
{
    XmmView view{};
    const float stored = 12.5f;
    std::memcpy(view.bytes.data(), &stored, sizeof(stored));

    EXPECT_EQ(view.lane<float>(0), 12.5f);      // in-range lane reads the stored value
    EXPECT_EQ(view.lane<float>(4), 0.0f);       // lane 4 starts at byte 16 (out of range) -> zero
    EXPECT_EQ(view.lane<float>(99), 0.0f);      // far out of range -> zero, no out-of-bounds read
    EXPECT_EQ(view.lane<std::uint64_t>(2), 0u); // lane 2 starts at byte 16 (out of range) -> zero
}

// T-XMM: every one of the 16 accessors selects its register by explicit member selection, pinned to the assembly
// frame's fixed 16-byte slots by the compile-time offset/size assertions beside xmm() in src/hook.cpp. This runtime
// half drives a synthetic context image carrying a distinct pattern per slot through all 16 indices in the optimized
// lanes; the UB proof is the member-selecting source itself, not these passing values.
TEST(MidContextXmmViewTest, AllSixteenAccessorsReadTheirOwnSlot)
{
    // A Context64-shaped image: 16 XMM slots of 16 bytes each ahead of the integer block. Only the XMM slots are
    // read. Every byte value (reg * 16 + byte + 1, mod 256) is unique across the 256 slot bytes, so an accessor that
    // read any neighbouring slot, or straddled two, cannot reproduce its own slot's pattern. Starting the byte
    // array's lifetime implicitly creates the implicit-lifetime backend context in its storage ([intro.object]), so
    // this view is defined behavior; a live mid-hook capture cannot pin 16 distinct XMM values deterministically.
    alignas(16) std::byte image[512]{};
    for (std::size_t reg = 0; reg < 16; ++reg)
    {
        for (std::size_t lane_byte = 0; lane_byte < 16; ++lane_byte)
        {
            image[reg * 16 + lane_byte] = static_cast<std::byte>(reg * 16 + lane_byte + 1);
        }
    }
    // A nonzero guard catches an off-by-one implementation that reads a seventeenth slot for index 16.
    for (std::size_t i = 256; i < 512; ++i)
    {
        image[i] = std::byte{0xA5};
    }

    const auto &ctx = *reinterpret_cast<const MidContext *>(image);
    for (std::size_t reg = 0; reg < 16; ++reg)
    {
        const XmmView view = xmm(ctx, reg);
        for (std::size_t lane_byte = 0; lane_byte < 16; ++lane_byte)
        {
            ASSERT_EQ(view.bytes[lane_byte], static_cast<std::byte>(reg * 16 + lane_byte + 1))
                << "xmm(" << reg << ") byte " << lane_byte << " was read outside its own slot";
        }
    }

    // Out-of-range indices fail closed with a zeroed view instead of reading past the captured context.
    for (const std::size_t bad_index : {std::size_t{16}, std::size_t{255}, std::numeric_limits<std::size_t>::max()})
    {
        const XmmView out_of_range = xmm(ctx, bad_index);
        for (const std::byte value : out_of_range.bytes)
        {
            EXPECT_EQ(value, std::byte{0});
        }
    }
}

// The mid-hook callback boundary: exception containment, rundown, and the adapter pool.
//
// These pin the contracts that exist because DMK owns a frame between the backend's generated stub and the user
// callback. Without that frame there is nowhere to catch and nothing to count, so each case below fails loudly (several
// by terminating the process) if the adapter is removed or neutered.

namespace
{
    // Forces the call to reach the patched entry even where the optimizer can see the callee, so a Release build proves
    // the same thing a Debug build does.
    template <class Fn, class... Args> auto call_unfolded(Fn *fn, Args... args)
    {
        Fn *const volatile indirect = fn;
        return indirect(args...);
    }

    DMK_TEST_NOINLINE int throwing_site(int a)
    {
        volatile int result = a;
        return result;
    }

    DMK_TEST_NOINLINE int recursion_site(int depth)
    {
        volatile int result = depth;
        return result;
    }

    DMK_TEST_NOINLINE int rundown_site(int a)
    {
        volatile int result = a;
        return result;
    }

    DMK_TEST_NOINLINE int self_destroy_site(int a)
    {
        volatile int result = a;
        return result;
    }

    DMK_TEST_NOINLINE int pinned_site(int a)
    {
        volatile int result = a;
        return result;
    }

    DMK_TEST_NOINLINE int pinned_rundown_site(int a)
    {
        volatile int result = a;
        return result;
    }

    DMK_TEST_NOINLINE int late_entrant_site(int a)
    {
        volatile int result = a;
        return result;
    }

    DMK_TEST_NOINLINE int route_timeout_site(int a)
    {
        volatile int result = a;
        return result;
    }

    DMK_TEST_NOINLINE int untracked_self_destroy_site(int a)
    {
        volatile int result = a;
        return result;
    }

    std::atomic<int> s_entered{0};
    std::atomic<int> s_recursion_depth{0};
    std::atomic<bool> s_callback_parked{false};
    std::atomic<bool> s_release_callback{false};
    std::atomic<bool> s_precommit_parked{false};
    std::atomic<bool> s_precommit_release{false};
    std::unique_ptr<Hook> s_self_destroy_hook;
    std::unique_ptr<Hook> s_untracked_self_destroy_hook;

    // Parks inside the adapter until released, so a teardown racing it has a genuinely in-flight callback to drain.
    void parking_detour(MidContext &)
    {
        s_entered.fetch_add(1, std::memory_order_relaxed);
        s_callback_parked.store(true, std::memory_order_release);
        while (!s_release_callback.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }

    void throwing_detour(MidContext &)
    {
        s_entered.fetch_add(1, std::memory_order_relaxed);
        throw std::runtime_error("mid-hook callbacks must not throw; DMK contains this at the adapter");
    }

    void recursive_detour(MidContext &)
    {
        s_entered.fetch_add(1, std::memory_order_relaxed);
        // Re-enter the hooked target from inside its own callback. The adapter is re-entered on the same thread, so
        // this also proves the in-flight count nests rather than saturating at one.
        if (s_recursion_depth.fetch_add(1, std::memory_order_relaxed) < 3)
        {
            (void)call_unfolded(&recursion_site, 1);
        }
    }

    void counting_detour(MidContext &)
    {
        s_entered.fetch_add(1, std::memory_order_relaxed);
    }

    void self_destroying_detour(MidContext &)
    {
        s_entered.fetch_add(1, std::memory_order_relaxed);
        if (s_self_destroy_hook)
        {
            // Destroying the hook from inside its own callback. Teardown must detect that this very thread is the
            // in-flight entrant and pin rather than wait for itself.
            s_self_destroy_hook.reset();
        }
    }

    void untracked_self_destroying_detour(MidContext &)
    {
        s_entered.fetch_add(1, std::memory_order_relaxed);
        if (s_untracked_self_destroy_hook)
        {
            s_untracked_self_destroy_hook.reset();
        }
    }
} // namespace

// The teardown restore decision seam (defined in hook.cpp) can deterministically leave the target patched so the pin
// branch remains directly testable.
namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    // Redeclared rather than included: internal/mid_hook_adapter.hpp pulls in safetyhook.hpp, and this target
    // deliberately carries no backend include path. mid_hook_adapter.hpp pins these same three values, so a reordered
    // enumerator fails to compile there instead of silently changing which interval this host selects.
    enum class MidRouteParkStage : std::uint8_t
    {
        None,
        BeforeAdapter,
        AfterAdapter
    };
    static_assert(static_cast<std::uint8_t>(MidRouteParkStage::None) == 0);
    static_assert(static_cast<std::uint8_t>(MidRouteParkStage::BeforeAdapter) == 1);
    static_assert(static_cast<std::uint8_t>(MidRouteParkStage::AfterAdapter) == 2);

    extern bool (*g_hook_teardown_restore_override)();
    extern void (*g_mid_adapter_precommit_probe)() noexcept;
    // Same redeclaration discipline: mid_hook_adapter.hpp owns the definition and pins its meaning.
    extern std::atomic<std::uint32_t> g_mid_entry_store_failure_thread;
    extern std::atomic<std::uint64_t> g_mid_entry_store_failure_hits;
    void set_mid_route_park_for_test(MidRouteParkStage stage) noexcept;
    [[nodiscard]] bool mid_route_park_reached_for_test() noexcept;
#endif
} // namespace DetourModKit::detail

namespace
{
    class HookTeardownRestoreOverrideScope
    {
    public:
        explicit HookTeardownRestoreOverrideScope([[maybe_unused]] bool (*override_fn)()) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            DetourModKit::detail::g_hook_teardown_restore_override = override_fn;
#endif
        }

        ~HookTeardownRestoreOverrideScope() noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            DetourModKit::detail::g_hook_teardown_restore_override = nullptr;
#endif
        }

        HookTeardownRestoreOverrideScope(const HookTeardownRestoreOverrideScope &) = delete;
        HookTeardownRestoreOverrideScope &operator=(const HookTeardownRestoreOverrideScope &) = delete;
        HookTeardownRestoreOverrideScope(HookTeardownRestoreOverrideScope &&) = delete;
        HookTeardownRestoreOverrideScope &operator=(HookTeardownRestoreOverrideScope &&) = delete;
    };

    /**
     * @brief Arms the adapter's precommit probe for one case.
     * @details The probe fires on every mid-hook dispatch while set, so it is scoped rather than left installed.
     */
    class MidPrecommitProbeScope
    {
    public:
        explicit MidPrecommitProbeScope([[maybe_unused]] void (*probe)() noexcept) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            DetourModKit::detail::g_mid_adapter_precommit_probe = probe;
#endif
        }

        ~MidPrecommitProbeScope() noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            DetourModKit::detail::g_mid_adapter_precommit_probe = nullptr;
#endif
        }

        MidPrecommitProbeScope(const MidPrecommitProbeScope &) = delete;
        MidPrecommitProbeScope &operator=(const MidPrecommitProbeScope &) = delete;
        MidPrecommitProbeScope(MidPrecommitProbeScope &&) = delete;
        MidPrecommitProbeScope &operator=(MidPrecommitProbeScope &&) = delete;
    };
} // namespace

class MidHookRundownTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        s_entered.store(0);
        s_recursion_depth.store(0);
        s_callback_parked.store(false);
        s_release_callback.store(false);
        s_precommit_parked.store(false);
        s_precommit_release.store(false);
        s_self_destroy_hook.reset();
        s_untracked_self_destroy_hook.reset();
#if defined(DMK_ENABLE_TEST_SEAMS)
        DetourModKit::detail::g_mid_entry_store_failure_thread.store(0, std::memory_order_release);
        DetourModKit::detail::set_mid_route_park_for_test(DetourModKit::detail::MidRouteParkStage::None);
#endif
    }
};

// A throwing callback is contained at the adapter and the hooked call returns normally.
//
// This is the case the adapter exists for. Without it the backend calls the user function directly, so the throw
// unwinds into a hand-emitted stub that carries no unwind data: the process terminates instead of reporting. The
// assertion that the call RETURNS is the proof: a leaked exception cannot reach it.
TEST_F(MidHookRundownTest, ThrowingCallbackIsContainedAndTargetStillReturns)
{
    Result<Hook> result = install_mid("MidThrowContained", &throwing_site, &throwing_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    const int observed = call_unfolded(&throwing_site, 41);

    EXPECT_EQ(s_entered.load(), 1) << "the callback must have run";
    EXPECT_EQ(observed, 41) << "the target must resume and return normally after the exception is contained";
}

// Containment is not a one-shot: a callback that throws on every call keeps being contained.
TEST_F(MidHookRundownTest, RepeatedThrowingCallbackStaysContained)
{
    Result<Hook> result = install_mid("MidThrowRepeated", &throwing_site, &throwing_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    for (int i = 0; i < 16; ++i)
    {
        EXPECT_EQ(call_unfolded(&throwing_site, i), i);
    }
    EXPECT_EQ(s_entered.load(), 16);
}

// A callback that re-enters its own hooked target nests and unwinds cleanly.
TEST_F(MidHookRundownTest, RecursiveCallbackReentersAndCompletes)
{
    Result<Hook> result = install_mid("MidRecursive", &recursion_site, &recursive_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    Hook hook = std::move(*result);

    (void)call_unfolded(&recursion_site, 1);

    // 1 outer entry + 3 nested re-entries: the fourth sees the depth guard and stops.
    EXPECT_EQ(s_entered.load(), 4) << "the adapter must permit re-entry from inside the callback";
}

// Teardown WAITS for a callback that is already running before it frees the stub that callback is executing.
//
// A counting test cannot prove this: restoring the prologue alone stops new entries, so an entry count freezes after
// teardown whether or not a drain exists. The discriminating question is whether ~Hook BLOCKS while a callback is
// in flight, so this pins a callback inside the adapter and asserts the destructor cannot finish until it is released.
// Without the drain the destructor returns immediately and frees a stub the parked thread is still inside.
TEST_F(MidHookRundownTest, TeardownWaitsForAnInFlightCallbackToLeave)
{
    Result<Hook> result = install_mid("MidDrain", &rundown_site, &parking_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    auto hook = std::make_unique<Hook>(std::move(*result));

    std::thread caller([] { (void)call_unfolded(&rundown_site, 7); });

    // Wait until the callback is genuinely inside the adapter, so the teardown below has something to drain.
    while (!s_callback_parked.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    std::atomic<bool> teardown_returned{false};
    std::thread destroyer(
        [&]
        {
            hook.reset(); // must block in the drain while the callback is parked
            teardown_returned.store(true, std::memory_order_release);
        });

    // The callback is still parked, so the drain must still be waiting. This is the assertion the drain exists for.
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    EXPECT_FALSE(teardown_returned.load(std::memory_order_acquire))
        << "~Hook returned while a callback was still executing inside the stub it frees";

    s_release_callback.store(true, std::memory_order_release);
    destroyer.join();
    caller.join();

    EXPECT_TRUE(teardown_returned.load()) << "teardown must complete once the in-flight callback leaves";
    EXPECT_EQ(s_entered.load(), 1);
}

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace
{
    void expect_teardown_waits_for_backend_route(DetourModKit::detail::MidRouteParkStage stage, int expected_callbacks)
    {
        Result<Hook> result = install_mid("MidRouteDrain", &rundown_site, &counting_detour);
        ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
        auto hook = std::make_unique<Hook>(std::move(*result));

        DetourModKit::detail::set_mid_route_park_for_test(stage);
        std::thread caller([] { (void)call_unfolded(&rundown_site, 7); });

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!DetourModKit::detail::mid_route_park_reached_for_test() && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::yield();
        }
        if (!DetourModKit::detail::mid_route_park_reached_for_test())
        {
            DetourModKit::detail::set_mid_route_park_for_test(DetourModKit::detail::MidRouteParkStage::None);
            caller.join();
            FAIL() << "the caller never reached the selected backend route interval";
            return;
        }
        EXPECT_EQ(s_entered.load(std::memory_order_relaxed), expected_callbacks);

        std::atomic<bool> teardown_returned{false};
        std::thread destroyer(
            [&]
            {
                hook.reset();
                teardown_returned.store(true, std::memory_order_release);
            });

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        EXPECT_FALSE(teardown_returned.load(std::memory_order_acquire))
            << "~Hook reclaimed the generated stub while a caller remained inside its backend route";

        DetourModKit::detail::set_mid_route_park_for_test(DetourModKit::detail::MidRouteParkStage::None);
        destroyer.join();
        caller.join();

        EXPECT_TRUE(teardown_returned.load(std::memory_order_acquire));
        EXPECT_EQ(s_entered.load(std::memory_order_relaxed), expected_callbacks);
    }
} // namespace

TEST_F(MidHookRundownTest, TeardownWaitsForCallerBeforeMidAdapterEntry)
{
    expect_teardown_waits_for_backend_route(DetourModKit::detail::MidRouteParkStage::BeforeAdapter, 0);
}

TEST_F(MidHookRundownTest, TeardownWaitsForCallerAfterMidAdapterReturn)
{
    expect_teardown_waits_for_backend_route(DetourModKit::detail::MidRouteParkStage::AfterAdapter, 1);
}

// The wait above is bounded. An entrant that is parked indefinitely (descheduled, suspended by a profiler, or stopped
// at a debugger breakpoint inside the generated stub) must not turn a destructor into a hung process. Teardown gives
// up on proving the route empty and retains the backend instead, which is the only answer that stays memory-safe while
// that thread can still return through the stub. The proof is that the destructor returns at all while the park is
// still held: an unbounded drain spins here until the CTest timeout.
TEST_F(MidHookRundownTest, TeardownReturnsWhenTheBackendRouteCannotBeDrained)
{
    Result<Hook> result = install_mid("MidRouteTimeout", &route_timeout_site, &counting_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    auto hook = std::make_unique<Hook>(std::move(*result));

    DetourModKit::detail::set_mid_route_park_for_test(DetourModKit::detail::MidRouteParkStage::BeforeAdapter);
    std::thread caller([] { (void)call_unfolded(&route_timeout_site, 11); });

    const auto park_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!DetourModKit::detail::mid_route_park_reached_for_test() && std::chrono::steady_clock::now() < park_deadline)
    {
        std::this_thread::yield();
    }
    if (!DetourModKit::detail::mid_route_park_reached_for_test())
    {
        DetourModKit::detail::set_mid_route_park_for_test(DetourModKit::detail::MidRouteParkStage::None);
        caller.join();
        FAIL() << "the caller never reached the backend route interval";
        return;
    }

    const auto started = std::chrono::steady_clock::now();
    const std::uint64_t sleeps_before = DetourModKit::detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
    std::atomic<bool> teardown_returned{false};
    std::thread destroyer(
        [&]
        {
            hook.reset();
            teardown_returned.store(true, std::memory_order_release);
        });
    const auto teardown_deadline = started + std::chrono::seconds(10);
    while (!teardown_returned.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < teardown_deadline)
    {
        std::this_thread::yield();
    }
    if (!teardown_returned.load(std::memory_order_acquire))
    {
        DetourModKit::detail::set_mid_route_park_for_test(DetourModKit::detail::MidRouteParkStage::None);
        caller.join();
        destroyer.join();
        FAIL() << "teardown exceeded its backend-route deadline";
        return;
    }
    destroyer.join();
    const auto elapsed = std::chrono::steady_clock::now() - started;

    // The route remains parked after the destructor returns, which proves the retention decision.
    EXPECT_TRUE(DetourModKit::detail::mid_route_park_reached_for_test())
        << "the entrant left on its own, so this run proves nothing about the bound";
    EXPECT_LT(elapsed, std::chrono::seconds(10)) << "teardown did not give up on an undrainable route";
    EXPECT_GT(DetourModKit::detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed), sleeps_before)
        << "the backend-route drain must reach the sleep tier";

    // The retained stub must still carry the parked caller all the way out. Releasing after the destructor returned is
    // the point: a reclaimed gateway or trampoline would be a use-after-free on this exact resume.
    DetourModKit::detail::set_mid_route_park_for_test(DetourModKit::detail::MidRouteParkStage::None);
    caller.join();
    EXPECT_EQ(s_entered.load(std::memory_order_relaxed), 0)
        << "the park sits before the adapter, so no callback may have run";
    EXPECT_EQ(call_unfolded(&route_timeout_site, 11), 11) << "the retained hook must be inert and pass through";
}

// The entry chain is what lets teardown answer "is THIS thread inside this adapter" exactly. When the per-thread store
// backing that chain fails, the chain walk cannot see the entrant, and a teardown reached from inside the callback
// would wait on itself forever. The untracked count is what closes that: it makes the rundown unprovable rather than
// falsely drained. Driving the store failure directly is the only way to reach the branch; the platform condition it
// stands in for is a heap refusal for the reserved slot's lazily allocated expansion array.
TEST_F(MidHookRundownTest, SelfDestroyWithAnUnrecordableEntryPinsInsteadOfWaiting)
{
    Result<Hook> result =
        install_mid("MidUntrackedSelfDestroy", &untracked_self_destroy_site, &untracked_self_destroying_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    s_untracked_self_destroy_hook = std::make_unique<Hook>(std::move(*result));

    const std::uint64_t hits_before = DetourModKit::detail::g_mid_entry_store_failure_hits.load();
    DetourModKit::detail::g_mid_entry_store_failure_thread.store(static_cast<std::uint32_t>(::GetCurrentThreadId()),
                                                                 std::memory_order_release);
    (void)call_unfolded(&untracked_self_destroy_site, 5);
    DetourModKit::detail::g_mid_entry_store_failure_thread.store(0, std::memory_order_release);

    EXPECT_EQ(s_entered.load(), 1) << "the callback must have run and destroyed its own hook";
    EXPECT_EQ(DetourModKit::detail::g_mid_entry_store_failure_hits.load(), hits_before + 1)
        << "the exact failed-store branch was not reached";

    // Pinned, so the tombstone is the only thing holding the contract: no further callback begins.
    const int frozen = s_entered.load();
    for (int i = 0; i < 1000; ++i)
    {
        (void)call_unfolded(&untracked_self_destroy_site, 5);
    }
    EXPECT_EQ(s_entered.load(), frozen) << "the pinned hook must be inert, not still dispatching";
}

// One failed store is transient: after that entry returns, the untracked balance must be zero on the same slot. The
// second call proves the live hook still uses the ordinary tracked path, and clean teardown proves no stale count made
// the slot look self-entered after both callbacks completed.
TEST_F(MidHookRundownTest, TransientUnrecordableEntryBalancesBeforeTrackedReuse)
{
    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    const std::uint64_t hits_before = DetourModKit::detail::g_mid_entry_store_failure_hits.load();
    {
        Result<Hook> result = install_mid("MidTransientUntracked", &rundown_site, &counting_detour);
        ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
        Hook hook = std::move(*result);

        DetourModKit::detail::g_mid_entry_store_failure_thread.store(static_cast<std::uint32_t>(::GetCurrentThreadId()),
                                                                     std::memory_order_release);
        EXPECT_EQ(call_unfolded(&rundown_site, 3), 3);
        DetourModKit::detail::g_mid_entry_store_failure_thread.store(0, std::memory_order_release);
        EXPECT_EQ(DetourModKit::detail::g_mid_entry_store_failure_hits.load(), hits_before + 1)
            << "the first call did not exercise the selected store failure";

        EXPECT_EQ(call_unfolded(&rundown_site, 4), 4);
        EXPECT_EQ(DetourModKit::detail::g_mid_entry_store_failure_hits.load(), hits_before + 1)
            << "the disarmed seam remained sticky on the ordinary call";
        EXPECT_EQ(s_entered.load(), 2) << "both deliveries must reach the callback";
    }
    EXPECT_EQ(DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
              leaks_before)
        << "a completed untracked entry left a stale balance that pinned clean teardown";
}

// The positive control for the case above: with the store working, an ordinary entry is recorded, the pool recovers,
// and a drained teardown still recycles. Without it, a store seam left armed by accident would look like a pass.
TEST_F(MidHookRundownTest, OrdinaryEntryChainStoreStillRecordsAndRecycles)
{
    for (int i = 0; i < 4; ++i)
    {
        Result<Hook> result = install_mid("MidTrackedRecycle", &rundown_site, &counting_detour);
        ASSERT_TRUE(result.has_value()) << "install " << i << " failed: " << result.error().message();
        Hook hook = std::move(*result);
        EXPECT_EQ(call_unfolded(&rundown_site, 3), 3);
    }
    EXPECT_EQ(s_entered.load(), 4) << "every tracked delivery must have reached the callback";
}
#endif

// A mid hook whose backend teardown cannot be completed is PINNED and stays physically installed, so its stub keeps
// entering the adapter for the process lifetime. The tombstone is the only thing that stops it calling a callback
// whose owning handle is gone (and whose code the caller may be about to unload), so it must go inert rather than keep
// firing. The restore override drives this retained-patch branch without altering the target.
TEST_F(MidHookRundownTest, PinnedMidHookGoesInertRatherThanKeepCallingBack)
{
    Result<Hook> result = install_mid("MidPinned", &pinned_site, &counting_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    auto hook = std::make_unique<Hook>(std::move(*result));

    EXPECT_EQ(call_unfolded(&pinned_site, 3), 3);
    ASSERT_EQ(s_entered.load(), 1) << "the hook must be live before teardown";

    {
        // Report a failed restore, so ~Hook pins the backend and leaves the target patched.
        HookTeardownRestoreOverrideScope deny([] { return false; });
        hook.reset();
    }

    // The target is still patched and its stub still runs, but the callback must never be entered again.
    const int frozen = s_entered.load();
    for (int i = 0; i < 1000; ++i)
    {
        (void)call_unfolded(&pinned_site, 3);
    }
    EXPECT_EQ(s_entered.load(), frozen)
        << "a pinned mid hook kept calling back after its handle was destroyed; the teardown tombstone is missing";
}

// An off-loader-lock pin still runs down user callbacks before returning. The backend remains installed, so this case
// distinguishes the callback counter from the adapter-entry counter: new adapter entries keep backing out through the
// tombstone while teardown waits only for the callback already executing.
TEST_F(MidHookRundownTest, PinnedTeardownWaitsForAnInFlightCallbackToLeave)
{
    Result<Hook> result = install_mid("MidPinnedDrain", &pinned_rundown_site, &parking_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    auto hook = std::make_unique<Hook>(std::move(*result));

    std::thread caller([] { (void)call_unfolded(&pinned_rundown_site, 9); });
    while (!s_callback_parked.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    HookTeardownRestoreOverrideScope deny([] { return false; });
    std::atomic<bool> teardown_returned{false};
    std::thread destroyer(
        [&]
        {
            hook.reset();
            teardown_returned.store(true, std::memory_order_release);
        });

    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    EXPECT_FALSE(teardown_returned.load(std::memory_order_acquire))
        << "pinned teardown returned while its user callback was still executing";

    s_release_callback.store(true, std::memory_order_release);
    destroyer.join();
    caller.join();

    EXPECT_TRUE(teardown_returned.load());
    EXPECT_EQ(s_entered.load(), 1);
}

// An entrant that has already passed the fast-path live check must still not run a callback once a rundown completes.
//
// This is the exact window the tombstone recheck closes, and no stress schedule reaches it reliably: the entrant has
// to be suspended between observing live and committing, while a whole teardown runs underneath it. The precommit
// probe parks it there deliberately. Without the recheck the parked thread commits and calls back after teardown has
// already returned, which is precisely the "no callback begins after rundown returns" contract breaking.
//
// It must drive the PIN path: the clean path drains adapter entries, and the parked thread is itself an outstanding
// entry, so a restoring teardown would wait on the very thread waiting for it.
TEST_F(MidHookRundownTest, LateEntrantCannotCommitACallbackAfterRundownReturns)
{
    Result<Hook> result = install_mid("MidLateEntrant", &late_entrant_site, &counting_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    auto hook = std::make_unique<Hook>(std::move(*result));

    MidPrecommitProbeScope probe(
        []() noexcept
        {
            // Only the first entrant parks; the teardown below must not deadlock behind a later one.
            if (s_precommit_parked.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            while (!s_precommit_release.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        });

    std::thread caller([] { (void)call_unfolded(&late_entrant_site, 4); });
    while (!s_precommit_parked.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // The entrant is now past the live check and has not committed. Run the whole teardown underneath it.
    {
        HookTeardownRestoreOverrideScope deny([] { return false; });
        hook.reset();
    }

    // Teardown has RETURNED. Only now let the parked entrant proceed to its commit.
    s_precommit_release.store(true, std::memory_order_release);
    caller.join();

    EXPECT_EQ(s_entered.load(), 0)
        << "an entrant that passed the live check before teardown still ran its callback afterwards; the tombstone "
           "recheck is missing";
}

// Destroying a mid hook from inside its own callback must not wait on its outstanding adapter or backend-route entry.
//
// The drain would never observe zero, because the waiting thread IS the in-flight entrant. Teardown detects that and
// pins the backend instead. The proof is that this test terminates at all: a self-wait hangs until the CTest timeout.
TEST_F(MidHookRundownTest, SelfDestroyFromInsideCallbackPinsInsteadOfWaiting)
{
    Result<Hook> result = install_mid("MidSelfDestroy", &self_destroy_site, &self_destroying_detour);
    ASSERT_TRUE(result.has_value()) << "mid_at failed: " << result.error().message();
    s_self_destroy_hook = std::make_unique<Hook>(std::move(*result));

    (void)call_unfolded(&self_destroy_site, 5);
    EXPECT_EQ(s_entered.load(), 1) << "the callback must have run and destroyed its own hook";

    // The tombstone still holds the contract even though the backend was pinned: the callback is never entered again.
    const int frozen = s_entered.load();
    for (int i = 0; i < 1000; ++i)
    {
        (void)call_unfolded(&self_destroy_site, 5);
    }
    EXPECT_EQ(s_entered.load(), frozen) << "the pinned hook must be inert, not still dispatching";
}

namespace
{
    // A family of distinct hookable functions. Each instantiation returns a different constant, so neither inlining nor
    // MSVC's identical-COMDAT folding can collapse them into one address, and the ledger refuses a second hook on the
    // same target, so distinct addresses are what make a pool-exhaustion test possible at all.
    template <int N> DMK_TEST_NOINLINE int pool_site()
    {
        volatile int result = N;
        return result;
    }

    template <std::size_t... Is> [[nodiscard]] auto make_pool_sites(std::index_sequence<Is...>)
    {
        return std::array<int (*)(), sizeof...(Is)>{&pool_site<static_cast<int>(Is)>...};
    }

    // Comfortably above the adapter capacity, so exhaustion is reachable even when an earlier case has pinned a slot.
    constexpr std::size_t POOL_SITE_COUNT = 96;
    const auto POOL_SITES = make_pool_sites(std::make_index_sequence<POOL_SITE_COUNT>{});

    void inert_detour(MidContext &) {}
} // namespace

// The adapter pool is finite, so exhaustion must be a typed refusal that patches nothing, never an untyped failure
// and never a silently shared adapter. Installing until refusal (rather than assuming a fixed free count) keeps this
// independent of any slot an earlier case pinned.
TEST(MidHookCapacityTest, ExhaustionIsTypedAndInstallsNothing)
{
    std::vector<Hook> held;
    held.reserve(POOL_SITE_COUNT);
    std::optional<Error> refusal;
    std::size_t used = 0;

    for (std::size_t i = 0; i < POOL_SITE_COUNT; ++i)
    {
        Result<Hook> hook =
            mid_at(MidRequest{.name = "MidPool", .target = Address{reinterpret_cast<std::uintptr_t>(POOL_SITES[i])}},
                   &inert_detour);
        if (!hook.has_value())
        {
            refusal = hook.error();
            used = i;
            break;
        }
        held.push_back(std::move(*hook));
    }

    ASSERT_TRUE(refusal.has_value()) << "the pool did not exhaust within " << POOL_SITE_COUNT << " distinct targets";
    EXPECT_EQ(refusal->code, ErrorCode::MidHookCapacityExhausted)
        << "exhaustion must be typed, not collapsed into a generic failure: " << refusal->message();
    // The count is bounded, NOT fixed, and asserting a fixed 64 here would be wrong: a teardown that pins never
    // returns its adapter (by design: its stub stays reachable), so every earlier case that drives a pin branch
    // spends a slot for the process lifetime. Measured: this case refuses at 64 run alone, but at 60 after the four
    // pinning cases above, so `EXPECT_EQ(used, 64)` is red in the real suite and green in isolation. The upper bound
    // is the half that can be pinned: exceeding capacity would mean adapters are shared or the pool is not its
    // documented size, which is what a per-hook identity guarantee forbids.
    EXPECT_GT(used, 0u) << "at least one mid hook must install before the pool exhausts";
    EXPECT_LE(used, 64u) << "more hooks installed than the adapter pool holds; adapters are being shared or the pool "
                            "is not its documented size";

    // The refusal must leave NOTHING behind. The install reserves a ledger entry before it claims an adapter, so the
    // refusal has to hand that reservation back; if it did not, the target would stay tracked as hooked forever and no
    // later hook could ever install there. Asserting the target is callable would prove nothing here: mid_at returns
    // an unarmed hook, so no target in this test is ever patched.
    EXPECT_FALSE(is_target_hooked(Address{reinterpret_cast<std::uintptr_t>(POOL_SITES[used])}))
        << "the refused install left its ledger reservation behind, permanently poisoning the target";
}

// A drained teardown returns its adapter to the pool, so hook churn is not a slow leak of capacity. Cycling more hooks
// than the pool holds, one at a time, can only succeed if each teardown recycles.
TEST(MidHookCapacityTest, DrainedTeardownRecyclesItsAdapter)
{
    for (std::size_t i = 0; i < POOL_SITE_COUNT; ++i)
    {
        Result<Hook> hook =
            mid_at(MidRequest{.name = "MidRecycle", .target = Address{reinterpret_cast<std::uintptr_t>(POOL_SITES[i])}},
                   &inert_detour);
        ASSERT_TRUE(hook.has_value()) << "install " << i << " failed, so a prior teardown did not recycle its adapter: "
                                      << hook.error().message();
        // Destroyed at end of iteration: tombstone, restore, drain, release.
    }
}
