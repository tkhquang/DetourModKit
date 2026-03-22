#include <gtest/gtest.h>
#include <windows.h>
#include <psapi.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/scanner.hpp"
#include "DetourModKit/logger.hpp"

using namespace DetourModKit;

using ComputeDamageFn = int (*)(int, int);
using ComputeArmorFn = int (*)(int, int);
using ComputeSpeedFn = int (*)(int, int);
using ComputeCriticalFn = int (*)(int, int);

static ComputeDamageFn g_original_compute_damage = nullptr;
static ComputeArmorFn g_original_compute_armor = nullptr;

static std::atomic<int> g_detour_call_count{0};

static int detour_compute_damage(int base, int modifier)
{
    g_detour_call_count.fetch_add(1, std::memory_order_relaxed);
    if (g_original_compute_damage) {
        return g_original_compute_damage(base, modifier) * 2;
    }
    return (base + modifier) * 2;
}

static int detour_compute_armor(int defense, int level)
{
    g_detour_call_count.fetch_add(1, std::memory_order_relaxed);
    if (g_original_compute_armor) {
        return g_original_compute_armor(defense, level) + 999;
    }
    return defense * level + 999;
}

static int detour_compute_speed(int agility, int bonus)
{
    g_detour_call_count.fetch_add(1, std::memory_order_relaxed);
    return (agility - bonus) * 3;
}

class HookIntegrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        hook_manager_ = &HookManager::get_instance();
        hook_manager_->remove_all_hooks();
        g_detour_call_count.store(0);
        g_original_compute_damage = nullptr;
        g_original_compute_armor = nullptr;

        dll_handle_ = LoadLibraryA("hook_target_lib.dll");
        ASSERT_NE(dll_handle_, nullptr)
            << "Failed to load hook_target_lib.dll. Error: " << GetLastError();

        fn_compute_damage_ = reinterpret_cast<ComputeDamageFn>(
            GetProcAddress(dll_handle_, "compute_damage"));
        fn_compute_armor_ = reinterpret_cast<ComputeArmorFn>(
            GetProcAddress(dll_handle_, "compute_armor"));
        fn_compute_speed_ = reinterpret_cast<ComputeSpeedFn>(
            GetProcAddress(dll_handle_, "compute_speed"));
        fn_compute_critical_ = reinterpret_cast<ComputeCriticalFn>(
            GetProcAddress(dll_handle_, "compute_critical"));

        ASSERT_NE(fn_compute_damage_, nullptr) << "compute_damage export not found";
        ASSERT_NE(fn_compute_armor_, nullptr) << "compute_armor export not found";
        ASSERT_NE(fn_compute_speed_, nullptr) << "compute_speed export not found";
        ASSERT_NE(fn_compute_critical_, nullptr) << "compute_critical export not found";

        MODULEINFO mod_info{};
        BOOL info_ok = GetModuleInformation(
            GetCurrentProcess(), dll_handle_, &mod_info, sizeof(mod_info));
        ASSERT_TRUE(info_ok) << "GetModuleInformation failed";

        module_base_ = reinterpret_cast<uintptr_t>(mod_info.lpBaseOfDll);
        module_size_ = mod_info.SizeOfImage;
    }

    void TearDown() override
    {
        if (hook_manager_) {
            hook_manager_->remove_all_hooks();
        }
        g_original_compute_damage = nullptr;
        g_original_compute_armor = nullptr;

        if (dll_handle_) {
            FreeLibrary(dll_handle_);
            dll_handle_ = nullptr;
        }
    }

    HookManager *hook_manager_ = nullptr;
    HMODULE dll_handle_ = nullptr;

    ComputeDamageFn fn_compute_damage_ = nullptr;
    ComputeArmorFn fn_compute_armor_ = nullptr;
    ComputeSpeedFn fn_compute_speed_ = nullptr;
    ComputeCriticalFn fn_compute_critical_ = nullptr;

    uintptr_t module_base_ = 0;
    size_t module_size_ = 0;
};

TEST_F(HookIntegrationTest, InlineHook_AlterReturnValue)
{
    EXPECT_EQ(fn_compute_damage_(10, 5), 15);

    void *trampoline = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "DamageHook",
        reinterpret_cast<uintptr_t>(fn_compute_damage_),
        reinterpret_cast<void *>(&detour_compute_damage),
        &trampoline);

    ASSERT_TRUE(result.has_value())
        << "Hook creation failed: " << Hook::error_to_string(result.error());
    ASSERT_NE(trampoline, nullptr);

    g_original_compute_damage = reinterpret_cast<ComputeDamageFn>(trampoline);

    int hooked_result = fn_compute_damage_(10, 5);
    EXPECT_EQ(hooked_result, 30);
    EXPECT_GE(g_detour_call_count.load(), 1);
}

TEST_F(HookIntegrationTest, InlineHook_RemoveRestoresOriginal)
{
    EXPECT_EQ(fn_compute_damage_(20, 10), 30);

    void *trampoline = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "DamageHookRemove",
        reinterpret_cast<uintptr_t>(fn_compute_damage_),
        reinterpret_cast<void *>(&detour_compute_damage),
        &trampoline);
    ASSERT_TRUE(result.has_value());
    g_original_compute_damage = reinterpret_cast<ComputeDamageFn>(trampoline);

    EXPECT_EQ(fn_compute_damage_(20, 10), 60);

    EXPECT_TRUE(hook_manager_->remove_hook("DamageHookRemove"));
    g_original_compute_damage = nullptr;

    EXPECT_EQ(fn_compute_damage_(20, 10), 30);
}

TEST_F(HookIntegrationTest, InlineHook_MultipleExports)
{
    EXPECT_EQ(fn_compute_damage_(5, 3), 8);
    EXPECT_EQ(fn_compute_armor_(4, 6), 24);
    EXPECT_EQ(fn_compute_speed_(10, 3), 7);

    void *tramp_damage = nullptr;
    void *tramp_armor = nullptr;
    void *tramp_speed = nullptr;

    auto r1 = hook_manager_->create_inline_hook(
        "MultiDamage",
        reinterpret_cast<uintptr_t>(fn_compute_damage_),
        reinterpret_cast<void *>(&detour_compute_damage),
        &tramp_damage);
    ASSERT_TRUE(r1.has_value());
    g_original_compute_damage = reinterpret_cast<ComputeDamageFn>(tramp_damage);

    auto r2 = hook_manager_->create_inline_hook(
        "MultiArmor",
        reinterpret_cast<uintptr_t>(fn_compute_armor_),
        reinterpret_cast<void *>(&detour_compute_armor),
        &tramp_armor);
    ASSERT_TRUE(r2.has_value());
    g_original_compute_armor = reinterpret_cast<ComputeArmorFn>(tramp_armor);

    auto r3 = hook_manager_->create_inline_hook(
        "MultiSpeed",
        reinterpret_cast<uintptr_t>(fn_compute_speed_),
        reinterpret_cast<void *>(&detour_compute_speed),
        &tramp_speed);
    ASSERT_TRUE(r3.has_value());

    EXPECT_EQ(fn_compute_damage_(5, 3), 16);
    EXPECT_EQ(fn_compute_armor_(4, 6), 1023);
    EXPECT_EQ(fn_compute_speed_(10, 3), 21);

    EXPECT_GE(g_detour_call_count.load(), 3);

    auto ids = hook_manager_->get_hook_ids(HookStatus::Active);
    EXPECT_GE(ids.size(), 3u);
}

TEST_F(HookIntegrationTest, MidHook_InspectAndModifyArgs)
{
    EXPECT_EQ(fn_compute_armor_(5, 10), 50);

    auto mid_detour = [](safetyhook::Context &ctx)
    {
        ctx.rcx = 100;
        ctx.rdx = 2;
    };

    auto result = hook_manager_->create_mid_hook(
        "ArmorMidHook",
        reinterpret_cast<uintptr_t>(fn_compute_armor_),
        mid_detour);

    ASSERT_TRUE(result.has_value())
        << "Mid hook creation failed: " << Hook::error_to_string(result.error());

    int hooked_result = fn_compute_armor_(5, 10);
    EXPECT_EQ(hooked_result, 200);
}

TEST_F(HookIntegrationTest, AOBScan_FindAndHook)
{
    auto pattern = Scanner::parse_aob("AD DE");
    ASSERT_TRUE(pattern.has_value()) << "Failed to parse AOB pattern";

    const auto *found = Scanner::find_pattern(
        reinterpret_cast<const std::byte *>(module_base_),
        module_size_,
        pattern.value());
    ASSERT_NE(found, nullptr) << "AOB pattern not found in module";

    auto fn_addr = reinterpret_cast<uintptr_t>(fn_compute_damage_);
    auto found_addr = reinterpret_cast<uintptr_t>(found);

    EXPECT_GE(found_addr, module_base_);
    EXPECT_LT(found_addr, module_base_ + module_size_);

    void *trampoline = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "AOBFoundDamageHook",
        fn_addr,
        reinterpret_cast<void *>(&detour_compute_damage),
        &trampoline);

    ASSERT_TRUE(result.has_value());
    g_original_compute_damage = reinterpret_cast<ComputeDamageFn>(trampoline);

    EXPECT_EQ(fn_compute_damage_(7, 3), 20);
}

TEST_F(HookIntegrationTest, AOBScan_HookManager_EndToEnd)
{
    auto *target_bytes = reinterpret_cast<const unsigned char *>(fn_compute_damage_);
    std::string aob_str;
    for (int i = 0; i < 8; ++i) {
        if (i > 0) {
            aob_str += ' ';
        }
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X", target_bytes[i]);
        aob_str += hex;
    }

    void *trampoline = nullptr;
    auto result = hook_manager_->create_inline_hook_aob(
        "AOBEndToEnd",
        module_base_,
        module_size_,
        aob_str,
        0,
        reinterpret_cast<void *>(&detour_compute_damage),
        &trampoline);

    ASSERT_TRUE(result.has_value())
        << "AOB end-to-end hook failed with pattern: " << aob_str;
    ASSERT_NE(trampoline, nullptr);

    g_original_compute_damage = reinterpret_cast<ComputeDamageFn>(trampoline);

    EXPECT_EQ(fn_compute_damage_(8, 2), 20);

    EXPECT_TRUE(hook_manager_->remove_hook("AOBEndToEnd"));
    g_original_compute_damage = nullptr;

    EXPECT_EQ(fn_compute_damage_(8, 2), 10);
}
