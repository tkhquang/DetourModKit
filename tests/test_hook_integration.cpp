#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/scan.hpp"

#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>

using namespace DetourModKit;
// Mid-hook detours name only the DMK-owned hook::MidContext now that the SafetyHook backend is library-private.
using namespace DetourModKit::hook;

using ComputeDamageFn = int (*)(int, int);
using ComputeArmorFn = int (*)(int, int);
using ComputeSpeedFn = int (*)(int, int);
using ComputeCriticalFn = int (*)(int, int);

static ComputeDamageFn s_original_compute_damage = nullptr;
static ComputeArmorFn s_original_compute_armor = nullptr;

static std::atomic<int> s_detour_call_count{0};

static constexpr size_t AOB_SIGNATURE_LENGTH = 16;

static int detour_compute_damage(int base, int modifier)
{
    s_detour_call_count.fetch_add(1, std::memory_order_relaxed);
    if (s_original_compute_damage)
    {
        return s_original_compute_damage(base, modifier) * 2;
    }
    return (base + modifier) * 2;
}

static int detour_compute_armor(int defense, int level)
{
    s_detour_call_count.fetch_add(1, std::memory_order_relaxed);
    if (s_original_compute_armor)
    {
        return s_original_compute_armor(defense, level) + 999;
    }
    return defense * level + 999;
}

static int detour_compute_speed(int agility, int bonus)
{
    s_detour_call_count.fetch_add(1, std::memory_order_relaxed);
    return (agility - bonus) * 3;
}

static std::string build_aob_from_bytes(const unsigned char *bytes, size_t count)
{
    std::string aob;
    for (size_t i = 0; i < count; ++i)
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

class HookIntegrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        s_detour_call_count.store(0);
        s_original_compute_damage = nullptr;
        s_original_compute_armor = nullptr;

        m_dll_handle = LoadLibraryA("hook_target_lib.dll");
        ASSERT_NE(m_dll_handle, nullptr) << "Failed to load hook_target_lib.dll. Error: " << GetLastError();

        m_fn_compute_damage =
            reinterpret_cast<ComputeDamageFn>(reinterpret_cast<void *>(GetProcAddress(m_dll_handle, "compute_damage")));
        m_fn_compute_armor =
            reinterpret_cast<ComputeArmorFn>(reinterpret_cast<void *>(GetProcAddress(m_dll_handle, "compute_armor")));
        m_fn_compute_speed =
            reinterpret_cast<ComputeSpeedFn>(reinterpret_cast<void *>(GetProcAddress(m_dll_handle, "compute_speed")));
        m_fn_compute_critical = reinterpret_cast<ComputeCriticalFn>(
            reinterpret_cast<void *>(GetProcAddress(m_dll_handle, "compute_critical")));

        ASSERT_NE(m_fn_compute_damage, nullptr) << "compute_damage export not found";
        ASSERT_NE(m_fn_compute_armor, nullptr) << "compute_armor export not found";
        ASSERT_NE(m_fn_compute_speed, nullptr) << "compute_speed export not found";
        ASSERT_NE(m_fn_compute_critical, nullptr) << "compute_critical export not found";
    }

    // Drops every held handle (each ~Hook restores its prologue). std::optional<Hook> is move-only, so reset each slot
    // rather than std::array::fill, which would require copy-assignment.
    void drop_all_hooks()
    {
        for (auto &slot : m_hooks)
        {
            slot.reset();
        }
    }

    void TearDown() override
    {
        // Drop every RAII handle first so each ~Hook restores its prologue before the target image is unmapped.
        drop_all_hooks();
        s_original_compute_damage = nullptr;
        s_original_compute_armor = nullptr;

        if (m_dll_handle)
        {
            FreeLibrary(m_dll_handle);
            m_dll_handle = nullptr;
        }
    }

    // A small fixed pool of optional Hook slots so a test can hold several handles and drop them individually:
    // dropping a slot (reset to nullopt) runs ~Hook and restores that target's prologue.
    std::array<std::optional<Hook>, 4> m_hooks{};

    HMODULE m_dll_handle = nullptr;

    ComputeDamageFn m_fn_compute_damage = nullptr;
    ComputeArmorFn m_fn_compute_armor = nullptr;
    ComputeSpeedFn m_fn_compute_speed = nullptr;
    ComputeCriticalFn m_fn_compute_critical = nullptr;
};

TEST_F(HookIntegrationTest, InlineHook_AlterReturnValue)
{
    EXPECT_EQ(m_fn_compute_damage(10, 5), 15);

    auto result = hook::inline_at(
        InlineRequest{.name = "DamageHook", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
        &detour_compute_damage);

    ASSERT_TRUE(result.has_value()) << "Hook creation failed: " << result.error().message();
    m_hooks[0] = std::move(*result);

    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();
    ASSERT_NE(s_original_compute_damage, nullptr);

    int hooked_result = m_fn_compute_damage(10, 5);
    EXPECT_EQ(hooked_result, 30);
    EXPECT_GE(s_detour_call_count.load(), 1);
}

TEST_F(HookIntegrationTest, IsTargetHooked_TracksLedger)
{
    const Address target{reinterpret_cast<uintptr_t>(m_fn_compute_damage)};

    // Before any install the kit's ledger has no record of this target.
    EXPECT_FALSE(hook::is_target_hooked(target));

    auto result = hook::inline_at(InlineRequest{.name = "LedgerQueryHook", .target = target}, &detour_compute_damage);
    ASSERT_TRUE(result.has_value()) << "Hook creation failed: " << result.error().message();
    m_hooks[0] = std::move(*result);

    // is_target_hooked() is a plain process-wide ledger query, callable normally (the old reentrant-from-callback
    // registry glue is gone, so there is nothing left to exercise from inside a callback).
    EXPECT_TRUE(hook::is_target_hooked(target));
    EXPECT_TRUE(m_hooks[0]->is_enabled());
    EXPECT_TRUE(static_cast<bool>(*m_hooks[0]));

    // Dropping the handle unhooks and clears the ledger entry.
    m_hooks[0] = std::nullopt;
    EXPECT_FALSE(hook::is_target_hooked(target));
}

TEST_F(HookIntegrationTest, InlineHook_RemoveRestoresOriginal)
{
    EXPECT_EQ(m_fn_compute_damage(20, 10), 30);

    auto result = hook::inline_at(
        InlineRequest{.name = "DamageHookRemove", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
        &detour_compute_damage);
    ASSERT_TRUE(result.has_value()) << result.error().message();
    m_hooks[0] = std::move(*result);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    EXPECT_EQ(m_fn_compute_damage(20, 10), 60);

    // Drop the handle: ~Hook restores the original prologue.
    m_hooks[0] = std::nullopt;
    s_original_compute_damage = nullptr;

    EXPECT_EQ(m_fn_compute_damage(20, 10), 30);
}

TEST_F(HookIntegrationTest, InlineHook_MultipleExports)
{
    EXPECT_EQ(m_fn_compute_damage(5, 3), 8);
    EXPECT_EQ(m_fn_compute_armor(4, 6), 24);
    EXPECT_EQ(m_fn_compute_speed(10, 3), 7);

    auto r1 = hook::inline_at(
        InlineRequest{.name = "MultiDamage", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
        &detour_compute_damage);
    ASSERT_TRUE(r1.has_value()) << r1.error().message();
    m_hooks[0] = std::move(*r1);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    auto r2 = hook::inline_at(
        InlineRequest{.name = "MultiArmor", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_armor)}},
        &detour_compute_armor);
    ASSERT_TRUE(r2.has_value()) << r2.error().message();
    m_hooks[1] = std::move(*r2);
    s_original_compute_armor = m_hooks[1]->original<ComputeArmorFn>();

    auto r3 = hook::inline_at(
        InlineRequest{.name = "MultiSpeed", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_speed)}},
        &detour_compute_speed);
    ASSERT_TRUE(r3.has_value()) << r3.error().message();
    m_hooks[2] = std::move(*r3);

    EXPECT_EQ(m_fn_compute_damage(5, 3), 16);
    EXPECT_EQ(m_fn_compute_armor(4, 6), 1023);
    EXPECT_EQ(m_fn_compute_speed(10, 3), 21);

    EXPECT_GE(s_detour_call_count.load(), 3);

    EXPECT_TRUE(m_hooks[0]->is_enabled());
    EXPECT_TRUE(m_hooks[1]->is_enabled());
    EXPECT_TRUE(m_hooks[2]->is_enabled());
}

TEST_F(HookIntegrationTest, MidHook_InspectAndModifyArgs)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "Mid hook register test requires x86-64 calling convention";
#endif

    EXPECT_EQ(m_fn_compute_armor(5, 10), 50);

    auto mid_detour = [](MidContext &ctx)
    {
        gpr(ctx, Gpr::Rcx) = 100;
        gpr(ctx, Gpr::Rdx) = 2;
    };

    auto result = hook::mid_at(
        MidRequest{.name = "ArmorMidHook", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_armor)}},
        mid_detour);

    ASSERT_TRUE(result.has_value()) << "Mid hook creation failed: " << result.error().message();
    m_hooks[0] = std::move(*result);

    int hooked_result = m_fn_compute_armor(5, 10);
    EXPECT_EQ(hooked_result, 200);
}

TEST_F(HookIntegrationTest, AOBScan_FindAndHook)
{
    auto *target_bytes = reinterpret_cast<const unsigned char *>(m_fn_compute_damage);
    std::string aob_str = build_aob_from_bytes(target_bytes, AOB_SIGNATURE_LENGTH);

    auto pattern = scan::Pattern::compile(aob_str);
    ASSERT_TRUE(pattern.has_value()) << "Failed to compile AOB pattern: " << aob_str;

    // The four fixture functions share an identical prologue shape, so a module-wide UNIQUE scan for one's leading
    // bytes is ambiguous (require_unique would reject it as NoMatch). Scope to a small window at the function and take
    // the first match: offset 0 is the function's own start, so the scan deterministically resolves to its entry while
    // still exercising the compile -> resolve -> hook pipeline end to end.
    const auto fn_addr = reinterpret_cast<uintptr_t>(m_fn_compute_damage);
    const std::array<scan::Candidate, 1> ladder = {scan::Candidate::direct("compute_damage", *pattern)};
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = Region{Address{fn_addr}, AOB_SIGNATURE_LENGTH + 32}, .require_unique = false});
    ASSERT_TRUE(hit.has_value()) << "AOB pattern not found: " << hit.error().message();
    EXPECT_EQ(hit->address.raw(), fn_addr)
        << "AOB match at " << hit->address.raw() << " does not equal export at " << fn_addr;

    auto result =
        hook::inline_at(InlineRequest{.name = "AOBFoundDamageHook", .target = hit->address}, &detour_compute_damage);
    ASSERT_TRUE(result.has_value()) << result.error().message();
    m_hooks[0] = std::move(*result);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    EXPECT_EQ(m_fn_compute_damage(7, 3), 20);
}

TEST_F(HookIntegrationTest, AOBScan_ResolveThenHook_EndToEnd)
{
    auto *target_bytes = reinterpret_cast<const unsigned char *>(m_fn_compute_damage);
    std::string aob_str = build_aob_from_bytes(target_bytes, AOB_SIGNATURE_LENGTH);

    auto pattern = scan::Pattern::compile(aob_str);
    ASSERT_TRUE(pattern.has_value()) << "Failed to compile AOB pattern: " << aob_str;

    // Scope to a window at the function and take the first match (the four fixture functions share a prologue, so a
    // module-wide unique scan would be ambiguous); offset 0 is the function's entry.
    const auto fn_addr = reinterpret_cast<uintptr_t>(m_fn_compute_damage);
    const std::array<scan::Candidate, 1> ladder = {scan::Candidate::direct("compute_damage", *pattern)};
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = Region{Address{fn_addr}, AOB_SIGNATURE_LENGTH + 32}, .require_unique = false});
    ASSERT_TRUE(hit.has_value()) << "AOB pattern not found: " << hit.error().message();
    EXPECT_EQ(hit->address.raw(), fn_addr);

    auto result = hook::inline_at(InlineRequest{.name = "AOBEndToEnd", .target = hit->address}, &detour_compute_damage);
    ASSERT_TRUE(result.has_value()) << "AOB end-to-end hook failed: " << result.error().message();
    m_hooks[0] = std::move(*result);

    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();
    ASSERT_NE(s_original_compute_damage, nullptr);

    EXPECT_EQ(m_fn_compute_damage(8, 2), 20);

    // Drop the handle: the export reverts to its original behaviour.
    m_hooks[0] = std::nullopt;
    s_original_compute_damage = nullptr;

    EXPECT_EQ(m_fn_compute_damage(8, 2), 10);
}

TEST_F(HookIntegrationTest, HotReload_FullCycle)
{
    EXPECT_EQ(m_fn_compute_damage(10, 5), 15);

    // Cycle 1: hook, verify, teardown
    auto r1 = hook::inline_at(
        InlineRequest{.name = "HotReloadDamage", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
        &detour_compute_damage);
    ASSERT_TRUE(r1.has_value()) << r1.error().message();
    m_hooks[0] = std::move(*r1);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    EXPECT_EQ(m_fn_compute_damage(10, 5), 30);

    m_hooks[0] = std::nullopt;
    s_original_compute_damage = nullptr;

    EXPECT_EQ(m_fn_compute_damage(10, 5), 15);

    // Cycle 2: re-hook same function, verify, teardown
    auto r2 = hook::inline_at(
        InlineRequest{.name = "HotReloadDamage", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
        &detour_compute_damage);
    ASSERT_TRUE(r2.has_value()) << "Re-hook after drop must succeed: " << r2.error().message();
    m_hooks[0] = std::move(*r2);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    EXPECT_EQ(m_fn_compute_damage(10, 5), 30);

    m_hooks[0] = std::nullopt;
    s_original_compute_damage = nullptr;

    EXPECT_EQ(m_fn_compute_damage(10, 5), 15);
}

TEST_F(HookIntegrationTest, HotReload_ShutdownAndRecreate)
{
    EXPECT_EQ(m_fn_compute_damage(4, 6), 10);

    auto r1 = hook::inline_at(InlineRequest{.name = "ShutdownRecreateDmg",
                                            .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
                              &detour_compute_damage);
    ASSERT_TRUE(r1.has_value()) << r1.error().message();
    m_hooks[0] = std::move(*r1);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    EXPECT_EQ(m_fn_compute_damage(4, 6), 20);

    // Simulate a Session teardown sequence: drop every handle, which restores every prologue.
    drop_all_hooks();
    s_original_compute_damage = nullptr;

    EXPECT_EQ(m_fn_compute_damage(4, 6), 10);
    EXPECT_FALSE(hook::is_target_hooked(Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}));

    // Simulate re-initialization after hot-reload.
    auto r2 = hook::inline_at(InlineRequest{.name = "ShutdownRecreateDmg",
                                            .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
                              &detour_compute_damage);
    ASSERT_TRUE(r2.has_value()) << "Hook recreation after shutdown must succeed: " << r2.error().message();
    m_hooks[0] = std::move(*r2);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    EXPECT_EQ(m_fn_compute_damage(4, 6), 20);
}

TEST_F(HookIntegrationTest, HotReload_MultipleHookTypes)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "Mid hook test requires x86-64 calling convention";
#endif

    EXPECT_EQ(m_fn_compute_damage(3, 7), 10);
    EXPECT_EQ(m_fn_compute_armor(5, 10), 50);

    auto mid_detour = [](MidContext &ctx)
    {
        gpr(ctx, Gpr::Rcx) = 100;
        gpr(ctx, Gpr::Rdx) = 1;
    };

    // Cycle 1: inline + mid hooks
    auto r1 = hook::inline_at(
        InlineRequest{.name = "ReloadInline", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
        &detour_compute_damage);
    ASSERT_TRUE(r1.has_value()) << r1.error().message();
    m_hooks[0] = std::move(*r1);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    auto r2 = hook::mid_at(
        MidRequest{.name = "ReloadMid", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_armor)}},
        mid_detour);
    ASSERT_TRUE(r2.has_value()) << r2.error().message();
    m_hooks[1] = std::move(*r2);

    EXPECT_EQ(m_fn_compute_damage(3, 7), 20);
    EXPECT_EQ(m_fn_compute_armor(5, 10), 100);

    EXPECT_TRUE(m_hooks[0]->is_enabled());
    EXPECT_TRUE(m_hooks[1]->is_enabled());

    // Teardown
    drop_all_hooks();
    s_original_compute_damage = nullptr;

    EXPECT_EQ(m_fn_compute_damage(3, 7), 10);
    EXPECT_EQ(m_fn_compute_armor(5, 10), 50);
    EXPECT_FALSE(hook::is_target_hooked(Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}));
    EXPECT_FALSE(hook::is_target_hooked(Address{reinterpret_cast<uintptr_t>(m_fn_compute_armor)}));

    // Cycle 2: recreate both
    auto r3 = hook::inline_at(
        InlineRequest{.name = "ReloadInline", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
        &detour_compute_damage);
    ASSERT_TRUE(r3.has_value()) << r3.error().message();
    m_hooks[0] = std::move(*r3);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    auto r4 = hook::mid_at(
        MidRequest{.name = "ReloadMid", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_armor)}},
        mid_detour);
    ASSERT_TRUE(r4.has_value()) << r4.error().message();
    m_hooks[1] = std::move(*r4);

    EXPECT_EQ(m_fn_compute_damage(3, 7), 20);
    EXPECT_EQ(m_fn_compute_armor(5, 10), 100);
}

TEST_F(HookIntegrationTest, HotReload_EnableDisableCycle)
{
    EXPECT_EQ(m_fn_compute_damage(2, 3), 5);

    auto r1 = hook::inline_at(
        InlineRequest{.name = "ToggleHook", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
        &detour_compute_damage);
    ASSERT_TRUE(r1.has_value()) << r1.error().message();
    m_hooks[0] = std::move(*r1);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    EXPECT_EQ(m_fn_compute_damage(2, 3), 10);

    // Disable
    EXPECT_TRUE(m_hooks[0]->disable().has_value());
    EXPECT_FALSE(m_hooks[0]->is_enabled());
    EXPECT_EQ(m_fn_compute_damage(2, 3), 5);

    // Re-enable
    EXPECT_TRUE(m_hooks[0]->enable().has_value());
    EXPECT_TRUE(m_hooks[0]->is_enabled());
    EXPECT_EQ(m_fn_compute_damage(2, 3), 10);

    // Disable again, drop, recreate (simulating a config reload).
    EXPECT_TRUE(m_hooks[0]->disable().has_value());
    m_hooks[0] = std::nullopt;
    s_original_compute_damage = nullptr;

    EXPECT_EQ(m_fn_compute_damage(2, 3), 5);

    auto r2 = hook::inline_at(
        InlineRequest{.name = "ToggleHook", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
        &detour_compute_damage);
    ASSERT_TRUE(r2.has_value()) << r2.error().message();
    m_hooks[0] = std::move(*r2);
    s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

    EXPECT_EQ(m_fn_compute_damage(2, 3), 10);
}

TEST_F(HookIntegrationTest, HotReload_MultipleCycles)
{
    constexpr int num_cycles = 5;

    for (int cycle = 0; cycle < num_cycles; ++cycle)
    {
        EXPECT_EQ(m_fn_compute_damage(1, 1), 2) << "Original behavior broken before cycle " << cycle;

        auto result = hook::inline_at(
            InlineRequest{.name = "CycleHook", .target = Address{reinterpret_cast<uintptr_t>(m_fn_compute_damage)}},
            &detour_compute_damage);
        ASSERT_TRUE(result.has_value()) << "Hook creation failed on cycle " << cycle << ": "
                                        << result.error().message();
        m_hooks[0] = std::move(*result);
        s_original_compute_damage = m_hooks[0]->original<ComputeDamageFn>();

        EXPECT_EQ(m_fn_compute_damage(1, 1), 4) << "Hooked behavior wrong on cycle " << cycle;

        m_hooks[0] = std::nullopt;
        s_original_compute_damage = nullptr;
    }

    EXPECT_EQ(m_fn_compute_damage(1, 1), 2);
}
