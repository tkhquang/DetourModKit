#include <gtest/gtest.h>
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>

#include "DetourModKit/hook.hpp"

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
//   * GPR READS  (rcx/rdx/r8/...) -- the detour observes the live argument registers.
//   * GPR WRITES (r8)             -- an overwritten general-purpose register survives the trampoline resume;
//                                    the gating case (gate-skip with r8=1, or redirect a source pointer).
//   * a real rsp                  -- the captured stack pointer is a genuine pointer into the live stack.
//   * rip redirect                -- a context-modified rip is honored on resume.
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
    }
};

// 1. GPR READ INTEGRITY -- the detour observes the live argument registers.
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

// 3. GPR WRITE survives resume -- rcx (the SafetyHook-proven write pattern).
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

// 4. r8 write survives resume -- the gating general-purpose-register write. A detour that overwrites r8
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

// 6. XMM READ -- the detour observes the live xmm0 float argument. xmm() is read-only by design; backend
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
