#include <gtest/gtest.h>
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>

#include "DetourModKit/hook_manager.hpp"

using namespace DetourModKit;
// The mid-hook detours below exercise the DMK-owned MidContext accessor surface (gpr / stack_pointer /
// instruction_pointer / xmm). v4 confines the SafetyHook backend to the library, so a detour names only these DMK
// types, exactly as a shipping consumer would.
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
    std::atomic<std::uint32_t> s_xmm0_bits{0};
} // namespace

class MidHookContextTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_hook_manager = &HookManager::get_instance();
        m_hook_manager->remove_all_hooks();
        s_calls.store(0);
        s_rcx.store(0);
        s_rdx.store(0);
        s_r8.store(0);
        s_rsp.store(0);
        s_xmm0_bits.store(0);
    }

    void TearDown() override
    {
        if (m_hook_manager)
        {
            m_hook_manager->remove_all_hooks();
        }
    }

    HookManager *m_hook_manager = nullptr;
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

    auto result = m_hook_manager->create_mid_hook("MidRead", reinterpret_cast<uintptr_t>(&read_probe), detour);
    ASSERT_TRUE(result.has_value()) << "create_mid_hook failed: " << Hook::error_to_string(result.error());

    auto status = m_hook_manager->get_hook_status("MidRead");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Active);

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

    auto result = m_hook_manager->create_mid_hook("MidRsp", reinterpret_cast<uintptr_t>(&read_probe), detour);
    ASSERT_TRUE(result.has_value()) << "create_mid_hook failed: " << Hook::error_to_string(result.error());

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

    auto result =
        m_hook_manager->create_mid_hook("MidWriteRcx", reinterpret_cast<uintptr_t>(&sum_first_second), detour);
    ASSERT_TRUE(result.has_value()) << "create_mid_hook failed: " << Hook::error_to_string(result.error());

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

    auto result = m_hook_manager->create_mid_hook("MidWriteR8", reinterpret_cast<uintptr_t>(&return_third), detour);
    ASSERT_TRUE(result.has_value()) << "create_mid_hook failed: " << Hook::error_to_string(result.error());

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

    auto result = m_hook_manager->create_mid_hook("MidWriteRip", reinterpret_cast<uintptr_t>(&rip_original), detour);
    ASSERT_TRUE(result.has_value()) << "create_mid_hook failed: " << Hook::error_to_string(result.error());

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

    auto result = m_hook_manager->create_mid_hook("MidXmmRead", reinterpret_cast<uintptr_t>(&pass_float), detour);
    ASSERT_TRUE(result.has_value()) << "create_mid_hook failed: " << Hook::error_to_string(result.error());

    volatile float observed = pass_float(3.5f);
    EXPECT_EQ(observed, 3.5f); // unmodified path still correct

    float got = 0.0f;
    std::uint32_t bits = s_xmm0_bits.load();
    std::memcpy(&got, &bits, sizeof(got));
    EXPECT_EQ(got, 3.5f) << "detour did not observe the live xmm0 float argument";
}
