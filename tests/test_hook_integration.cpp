#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/scanner.hpp"
#include "DetourModKit/logger.hpp"

#include <gtest/gtest.h>
#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

using namespace DetourModKit;

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
        m_hook_manager = &HookManager::get_instance();
        m_hook_manager->remove_all_hooks();
        s_detour_call_count.store(0);
        s_original_compute_damage = nullptr;
        s_original_compute_armor = nullptr;

        m_dll_handle = LoadLibraryA("hook_target_lib.dll");
        ASSERT_NE(m_dll_handle, nullptr)
            << "Failed to load hook_target_lib.dll. Error: " << GetLastError();

        m_fn_compute_damage = reinterpret_cast<ComputeDamageFn>(
            reinterpret_cast<void *>(GetProcAddress(m_dll_handle, "compute_damage")));
        m_fn_compute_armor = reinterpret_cast<ComputeArmorFn>(
            reinterpret_cast<void *>(GetProcAddress(m_dll_handle, "compute_armor")));
        m_fn_compute_speed = reinterpret_cast<ComputeSpeedFn>(
            reinterpret_cast<void *>(GetProcAddress(m_dll_handle, "compute_speed")));
        m_fn_compute_critical = reinterpret_cast<ComputeCriticalFn>(
            reinterpret_cast<void *>(GetProcAddress(m_dll_handle, "compute_critical")));

        ASSERT_NE(m_fn_compute_damage, nullptr) << "compute_damage export not found";
        ASSERT_NE(m_fn_compute_armor, nullptr) << "compute_armor export not found";
        ASSERT_NE(m_fn_compute_speed, nullptr) << "compute_speed export not found";
        ASSERT_NE(m_fn_compute_critical, nullptr) << "compute_critical export not found";

        MODULEINFO mod_info{};
        BOOL info_ok = GetModuleInformation(
            GetCurrentProcess(), m_dll_handle, &mod_info, sizeof(mod_info));
        ASSERT_TRUE(info_ok) << "GetModuleInformation failed";

        m_module_base = reinterpret_cast<uintptr_t>(mod_info.lpBaseOfDll);
        m_module_size = mod_info.SizeOfImage;
    }

    void TearDown() override
    {
        if (m_hook_manager)
        {
            m_hook_manager->remove_all_hooks();
        }
        s_original_compute_damage = nullptr;
        s_original_compute_armor = nullptr;

        if (m_dll_handle)
        {
            FreeLibrary(m_dll_handle);
            m_dll_handle = nullptr;
        }
    }

    HookManager *m_hook_manager = nullptr;
    HMODULE m_dll_handle = nullptr;

    ComputeDamageFn m_fn_compute_damage = nullptr;
    ComputeArmorFn m_fn_compute_armor = nullptr;
    ComputeSpeedFn m_fn_compute_speed = nullptr;
    ComputeCriticalFn m_fn_compute_critical = nullptr;

    uintptr_t m_module_base = 0;
    size_t m_module_size = 0;
};

TEST_F(HookIntegrationTest, InlineHook_AlterReturnValue)
{
    EXPECT_EQ(m_fn_compute_damage(10, 5), 15);

    void *trampoline = nullptr;
    auto result = m_hook_manager->create_inline_hook(
        "DamageHook",
        reinterpret_cast<uintptr_t>(m_fn_compute_damage),
        reinterpret_cast<void *>(&detour_compute_damage),
        &trampoline);

    ASSERT_TRUE(result.has_value())
        << "Hook creation failed: " << Hook::error_to_string(result.error());
    ASSERT_NE(trampoline, nullptr);

    s_original_compute_damage = reinterpret_cast<ComputeDamageFn>(trampoline);

    int hooked_result = m_fn_compute_damage(10, 5);
    EXPECT_EQ(hooked_result, 30);
    EXPECT_GE(s_detour_call_count.load(), 1);
}

TEST_F(HookIntegrationTest, InlineHook_RemoveRestoresOriginal)
{
    EXPECT_EQ(m_fn_compute_damage(20, 10), 30);

    void *trampoline = nullptr;
    auto result = m_hook_manager->create_inline_hook(
        "DamageHookRemove",
        reinterpret_cast<uintptr_t>(m_fn_compute_damage),
        reinterpret_cast<void *>(&detour_compute_damage),
        &trampoline);
    ASSERT_TRUE(result.has_value());
    s_original_compute_damage = reinterpret_cast<ComputeDamageFn>(trampoline);

    EXPECT_EQ(m_fn_compute_damage(20, 10), 60);

    EXPECT_TRUE(m_hook_manager->remove_hook("DamageHookRemove"));
    s_original_compute_damage = nullptr;

    EXPECT_EQ(m_fn_compute_damage(20, 10), 30);
}

TEST_F(HookIntegrationTest, InlineHook_MultipleExports)
{
    EXPECT_EQ(m_fn_compute_damage(5, 3), 8);
    EXPECT_EQ(m_fn_compute_armor(4, 6), 24);
    EXPECT_EQ(m_fn_compute_speed(10, 3), 7);

    void *tramp_damage = nullptr;
    void *tramp_armor = nullptr;
    void *tramp_speed = nullptr;

    auto r1 = m_hook_manager->create_inline_hook(
        "MultiDamage",
        reinterpret_cast<uintptr_t>(m_fn_compute_damage),
        reinterpret_cast<void *>(&detour_compute_damage),
        &tramp_damage);
    ASSERT_TRUE(r1.has_value());
    s_original_compute_damage = reinterpret_cast<ComputeDamageFn>(tramp_damage);

    auto r2 = m_hook_manager->create_inline_hook(
        "MultiArmor",
        reinterpret_cast<uintptr_t>(m_fn_compute_armor),
        reinterpret_cast<void *>(&detour_compute_armor),
        &tramp_armor);
    ASSERT_TRUE(r2.has_value());
    s_original_compute_armor = reinterpret_cast<ComputeArmorFn>(tramp_armor);

    auto r3 = m_hook_manager->create_inline_hook(
        "MultiSpeed",
        reinterpret_cast<uintptr_t>(m_fn_compute_speed),
        reinterpret_cast<void *>(&detour_compute_speed),
        &tramp_speed);
    ASSERT_TRUE(r3.has_value());

    EXPECT_EQ(m_fn_compute_damage(5, 3), 16);
    EXPECT_EQ(m_fn_compute_armor(4, 6), 1023);
    EXPECT_EQ(m_fn_compute_speed(10, 3), 21);

    EXPECT_GE(s_detour_call_count.load(), 3);

    auto ids = m_hook_manager->get_hook_ids(HookStatus::Active);
    EXPECT_GE(ids.size(), 3u);
}

TEST_F(HookIntegrationTest, MidHook_InspectAndModifyArgs)
{
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "Mid hook register test requires x86-64 calling convention";
#endif

    EXPECT_EQ(m_fn_compute_armor(5, 10), 50);

    auto mid_detour = [](safetyhook::Context &ctx)
    {
        ctx.rcx = 100;
        ctx.rdx = 2;
    };

    auto result = m_hook_manager->create_mid_hook(
        "ArmorMidHook",
        reinterpret_cast<uintptr_t>(m_fn_compute_armor),
        mid_detour);

    ASSERT_TRUE(result.has_value())
        << "Mid hook creation failed: " << Hook::error_to_string(result.error());

    int hooked_result = m_fn_compute_armor(5, 10);
    EXPECT_EQ(hooked_result, 200);
}

TEST_F(HookIntegrationTest, AOBScan_FindAndHook)
{
    auto *target_bytes = reinterpret_cast<const unsigned char *>(m_fn_compute_damage);
    std::string aob_str = build_aob_from_bytes(target_bytes, AOB_SIGNATURE_LENGTH);

    auto pattern = Scanner::parse_aob(aob_str);
    ASSERT_TRUE(pattern.has_value()) << "Failed to parse AOB pattern: " << aob_str;

    const auto *found = Scanner::find_pattern(
        reinterpret_cast<const std::byte *>(m_module_base),
        m_module_size,
        pattern.value());
    ASSERT_NE(found, nullptr) << "AOB pattern not found in module";

    auto fn_addr = reinterpret_cast<uintptr_t>(m_fn_compute_damage);
    auto found_addr = reinterpret_cast<uintptr_t>(found);

    EXPECT_EQ(found_addr, fn_addr)
        << "AOB match at " << found_addr << " does not equal export at " << fn_addr;

    void *trampoline = nullptr;
    auto result = m_hook_manager->create_inline_hook(
        "AOBFoundDamageHook",
        fn_addr,
        reinterpret_cast<void *>(&detour_compute_damage),
        &trampoline);

    ASSERT_TRUE(result.has_value());
    s_original_compute_damage = reinterpret_cast<ComputeDamageFn>(trampoline);

    EXPECT_EQ(m_fn_compute_damage(7, 3), 20);
}

TEST_F(HookIntegrationTest, AOBScan_HookManager_EndToEnd)
{
    auto *target_bytes = reinterpret_cast<const unsigned char *>(m_fn_compute_damage);
    std::string aob_str = build_aob_from_bytes(target_bytes, AOB_SIGNATURE_LENGTH);

    auto pattern = Scanner::parse_aob(aob_str);
    ASSERT_TRUE(pattern.has_value()) << "Failed to parse AOB pattern: " << aob_str;

    const auto *found = Scanner::find_pattern(
        reinterpret_cast<const std::byte *>(m_module_base),
        m_module_size,
        pattern.value());
    ASSERT_NE(found, nullptr) << "AOB pattern not found in module";
    EXPECT_EQ(reinterpret_cast<uintptr_t>(found), reinterpret_cast<uintptr_t>(m_fn_compute_damage));

    void *trampoline = nullptr;
    auto result = m_hook_manager->create_inline_hook_aob(
        "AOBEndToEnd",
        m_module_base,
        m_module_size,
        aob_str,
        0,
        reinterpret_cast<void *>(&detour_compute_damage),
        &trampoline);

    ASSERT_TRUE(result.has_value())
        << "AOB end-to-end hook failed with pattern: " << aob_str;
    ASSERT_NE(trampoline, nullptr);

    s_original_compute_damage = reinterpret_cast<ComputeDamageFn>(trampoline);

    EXPECT_EQ(m_fn_compute_damage(8, 2), 20);

    EXPECT_TRUE(m_hook_manager->remove_hook("AOBEndToEnd"));
    s_original_compute_damage = nullptr;

    EXPECT_EQ(m_fn_compute_damage(8, 2), 10);
}
