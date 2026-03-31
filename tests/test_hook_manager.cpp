#include <gtest/gtest.h>
#include <functional>
#include <thread>
#include <chrono>
#include <latch>
#include <windows.h>

#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/logger.hpp"

using namespace DetourModKit;

class HookManagerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        hook_manager_ = &HookManager::get_instance();
        hook_manager_->remove_all_hooks();
    }

    void TearDown() override
    {
        if (hook_manager_)
        {
            hook_manager_->remove_all_hooks();
        }
    }

    HookManager *hook_manager_;
};

TEST(HookManagerSingletonTest, GetInstance)
{
    HookManager &instance1 = HookManager::get_instance();
    HookManager &instance2 = HookManager::get_instance();

    EXPECT_EQ(&instance1, &instance2);
}

TEST_F(HookManagerTest, HookStatus)
{
    HookStatus status1 = HookStatus::Active;
    HookStatus status2 = HookStatus::Disabled;
    HookStatus status3 = HookStatus::Enabling;
    HookStatus status4 = HookStatus::Disabling;
    HookStatus status5 = HookStatus::Failed;
    HookStatus status6 = HookStatus::Removed;

    EXPECT_NE(status1, status2);
    EXPECT_NE(status2, status3);
    EXPECT_NE(status3, status4);
    EXPECT_NE(status4, status5);
    EXPECT_NE(status5, status6);
}

TEST_F(HookManagerTest, HookType)
{
    HookType type1 = HookType::Inline;
    HookType type2 = HookType::Mid;

    EXPECT_NE(type1, type2);
}

TEST_F(HookManagerTest, HookConfig)
{
    HookConfig config;

    EXPECT_TRUE(config.auto_enable);
}

TEST_F(HookManagerTest, HookConfig_Custom)
{
    HookConfig config;
    config.auto_enable = false;

    EXPECT_FALSE(config.auto_enable);
}

TEST_F(HookManagerTest, CreateInlineHook_InvalidAddress)
{
    void *detour_fn = reinterpret_cast<void *>(0x87654321);
    void *original_trampoline = nullptr;

    auto result = hook_manager_->create_inline_hook(
        "TestInvalidHook",
        0,
        detour_fn,
        &original_trampoline);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, CreateInlineHook_NullDetour)
{
    void *original_trampoline = nullptr;

    auto result = hook_manager_->create_inline_hook(
        "TestNullDetour",
        0x12345678,
        nullptr,
        &original_trampoline);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidDetourFunction);
}

TEST_F(HookManagerTest, CreateInlineHook_NullTrampoline)
{
    void *detour_fn = reinterpret_cast<void *>(0x87654321);

    auto result = hook_manager_->create_inline_hook(
        "TestNullTrampoline",
        0x12345678,
        detour_fn,
        nullptr);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTrampolinePointer);
}

TEST_F(HookManagerTest, GetHookStatus_NonExistent)
{
    auto status = hook_manager_->get_hook_status("NonExistentHook");

    EXPECT_FALSE(status.has_value());
}

TEST_F(HookManagerTest, EnableHook_NonExistent)
{
    bool result = hook_manager_->enable_hook("NonExistentHook");
    EXPECT_FALSE(result);
}

TEST_F(HookManagerTest, DisableHook_NonExistent)
{
    bool result = hook_manager_->disable_hook("NonExistentHook");
    EXPECT_FALSE(result);
}

TEST_F(HookManagerTest, RemoveHook_NonExistent)
{
    bool result = hook_manager_->remove_hook("NonExistentHook");
    EXPECT_FALSE(result);
}

TEST_F(HookManagerTest, GetHookIds)
{
    auto ids = hook_manager_->get_hook_ids();

    EXPECT_TRUE(ids.empty());
}

TEST_F(HookManagerTest, GetHookIds_WithFilter)
{
    auto active_ids = hook_manager_->get_hook_ids(HookStatus::Active);
    EXPECT_TRUE(active_ids.empty());

    auto disabled_ids = hook_manager_->get_hook_ids(HookStatus::Disabled);
    EXPECT_TRUE(disabled_ids.empty());

    auto failed_ids = hook_manager_->get_hook_ids(HookStatus::Failed);
    EXPECT_TRUE(failed_ids.empty());
}

TEST_F(HookManagerTest, RemoveAllHooks)
{
    EXPECT_NO_THROW(hook_manager_->remove_all_hooks());
}

TEST_F(HookManagerTest, CreateInlineHookAob_EmptyPattern)
{
    void *detour_fn = reinterpret_cast<void *>(0x87654321);
    void *original_trampoline = nullptr;

    auto result = hook_manager_->create_inline_hook_aob(
        "TestAobHook",
        0,
        0,
        "",
        0,
        detour_fn,
        &original_trampoline);

    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, CreateInlineHookAob_InvalidPattern)
{
    void *detour_fn = reinterpret_cast<void *>(0x87654321);
    void *original_trampoline = nullptr;

    auto result = hook_manager_->create_inline_hook_aob(
        "TestAobHookInvalid",
        0,
        0,
        "ZZ ?? XX",
        0,
        detour_fn,
        &original_trampoline);

    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, CreateMidHook_InvalidAddress)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook(
        "TestMidInvalid",
        0,
        detour_fn);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, CreateMidHook_NullDetour)
{
    auto result = hook_manager_->create_mid_hook(
        "TestMidNull",
        0x12345678,
        nullptr);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidDetourFunction);
}

TEST_F(HookManagerTest, CreateMidHookAob_EmptyPattern)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook_aob(
        "TestMidAobEmpty",
        0,
        0,
        "",
        0,
        detour_fn);

    EXPECT_FALSE(result.has_value());
}

TEST(HookErrorTest, ErrorValuesExist)
{
    HookError err1 = HookError::AllocatorNotAvailable;
    HookError err2 = HookError::InvalidTargetAddress;
    HookError err3 = HookError::InvalidDetourFunction;
    HookError err4 = HookError::InvalidTrampolinePointer;
    HookError err5 = HookError::HookAlreadyExists;
    HookError err6 = HookError::SafetyHookError;
    HookError err7 = HookError::UnknownError;

    EXPECT_NE(err1, err2);
    EXPECT_NE(err2, err3);
    (void)err4;
    (void)err5;
    (void)err6;
    (void)err7;
}

TEST_F(HookManagerTest, ThreadSafety)
{
    const int num_threads = 4;

    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([this, i]()
                             {
            for (int j = 0; j < 10; ++j)
            {
                (void)hook_manager_->get_hook_status("Thread" + std::to_string(i) + "_" + std::to_string(j));
                (void)hook_manager_->get_hook_counts();
                (void)hook_manager_->get_hook_ids();
                (void)hook_manager_->enable_hook("nonexistent_" + std::to_string(i));
                (void)hook_manager_->disable_hook("nonexistent_" + std::to_string(i));
            } });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    SUCCEED();
}

TEST(HookErrorStringTest, ErrorToString_All)
{
    EXPECT_EQ(Hook::error_to_string(HookError::AllocatorNotAvailable), "Allocator not available");
    EXPECT_EQ(Hook::error_to_string(HookError::InvalidTargetAddress), "Invalid target address");
    EXPECT_EQ(Hook::error_to_string(HookError::InvalidDetourFunction), "Invalid detour function");
    EXPECT_EQ(Hook::error_to_string(HookError::InvalidTrampolinePointer), "Invalid trampoline pointer");
    EXPECT_EQ(Hook::error_to_string(HookError::HookAlreadyExists), "Hook already exists");
    EXPECT_EQ(Hook::error_to_string(HookError::SafetyHookError), "SafetyHook error");
    EXPECT_EQ(Hook::error_to_string(HookError::UnknownError), "Unknown error");
}

TEST_F(HookManagerTest, HookConfig_Flags)
{
    HookConfig config;
    config.auto_enable = false;

    EXPECT_FALSE(config.auto_enable);

    config.inline_flags = static_cast<safetyhook::InlineHook::Flags>(0);
    config.mid_flags = static_cast<safetyhook::MidHook::Flags>(0);

    (void)config.inline_flags;
    (void)config.mid_flags;
}

TEST_F(HookManagerTest, GetHookCounts_Empty)
{
    auto counts = hook_manager_->get_hook_counts();

    EXPECT_EQ(counts[HookStatus::Active], 0u);
    EXPECT_EQ(counts[HookStatus::Disabled], 0u);
    EXPECT_EQ(counts[HookStatus::Failed], 0u);
    EXPECT_EQ(counts[HookStatus::Removed], 0u);
}

TEST_F(HookManagerTest, Shutdown_Multiple)
{
    EXPECT_NO_THROW(hook_manager_->shutdown());
    EXPECT_NO_THROW(hook_manager_->shutdown());
    EXPECT_NO_THROW(hook_manager_->shutdown());
}

TEST_F(HookManagerTest, RemoveAllHooks_Multiple)
{
    EXPECT_NO_THROW(hook_manager_->remove_all_hooks());
    EXPECT_NO_THROW(hook_manager_->remove_all_hooks());
    EXPECT_NO_THROW(hook_manager_->remove_all_hooks());
}

// Real hook tests using valid function addresses in the test binary

[[gnu::noinline]] static int real_hook_target_add(int a, int b)
{
    volatile int r = a + b;
    return r;
}

[[gnu::noinline]] static int real_hook_target_mul(int a, int b)
{
    volatile int r = a * b;
    return r;
}

static std::atomic<int> g_real_detour_calls{0};

[[gnu::noinline]] static int real_hook_detour_add(int a, int b)
{
    g_real_detour_calls.fetch_add(1, std::memory_order_relaxed);
    return a + b + 1000;
}

[[gnu::noinline]] static int real_hook_detour_mul(int a, int b)
{
    g_real_detour_calls.fetch_add(1, std::memory_order_relaxed);
    return a * b + 1000;
}

static std::atomic<int> g_mid_detour_calls{0};

TEST_F(HookManagerTest, RealInlineHook_CreateSuccess)
{
    g_real_detour_calls.store(0);
    void *original_trampoline = nullptr;

    auto result = hook_manager_->create_inline_hook(
        "RealAddHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &original_trampoline);

    ASSERT_TRUE(result.has_value()) << "Hook creation on real test function should succeed";
    EXPECT_EQ(*result, "RealAddHook");
    EXPECT_NE(original_trampoline, nullptr);

    auto status = hook_manager_->get_hook_status("RealAddHook");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Active);

    auto ids = hook_manager_->get_hook_ids();
    EXPECT_FALSE(ids.empty());

    auto active_ids = hook_manager_->get_hook_ids(HookStatus::Active);
    EXPECT_FALSE(active_ids.empty());

    auto counts = hook_manager_->get_hook_counts();
    EXPECT_GE(counts[HookStatus::Active], 1u);
}

TEST_F(HookManagerTest, RealInlineHook_CreateDisabled)
{
    void *original_trampoline = nullptr;
    HookConfig config;
    config.auto_enable = false;

    auto result = hook_manager_->create_inline_hook(
        "RealDisabledHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &original_trampoline,
        config);

    ASSERT_TRUE(result.has_value());
    auto status = hook_manager_->get_hook_status("RealDisabledHook");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Disabled);
}

TEST_F(HookManagerTest, RealInlineHook_DuplicateName)
{
    void *tramp1 = nullptr, *tramp2 = nullptr;

    auto result1 = hook_manager_->create_inline_hook(
        "DupRealHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp1);
    ASSERT_TRUE(result1.has_value());

    auto result2 = hook_manager_->create_inline_hook(
        "DupRealHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp2);
    EXPECT_FALSE(result2.has_value());
    EXPECT_EQ(result2.error(), HookError::HookAlreadyExists);
}

TEST_F(HookManagerTest, RealInlineHook_EnableDisable)
{
    void *original_trampoline = nullptr;

    auto result = hook_manager_->create_inline_hook(
        "RealEnDisHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &original_trampoline);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(hook_manager_->enable_hook("RealEnDisHook"));

    EXPECT_TRUE(hook_manager_->disable_hook("RealEnDisHook"));
    EXPECT_EQ(*hook_manager_->get_hook_status("RealEnDisHook"), HookStatus::Disabled);

    EXPECT_TRUE(hook_manager_->disable_hook("RealEnDisHook"));

    EXPECT_TRUE(hook_manager_->enable_hook("RealEnDisHook"));
    EXPECT_EQ(*hook_manager_->get_hook_status("RealEnDisHook"), HookStatus::Active);
}

TEST_F(HookManagerTest, RealInlineHook_Remove)
{
    void *original_trampoline = nullptr;

    auto result = hook_manager_->create_inline_hook(
        "RealRemoveHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &original_trampoline);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(hook_manager_->remove_hook("RealRemoveHook"));
    EXPECT_FALSE(hook_manager_->get_hook_status("RealRemoveHook").has_value());
}

TEST_F(HookManagerTest, RealInlineHook_WithCallback)
{
    void *original_trampoline = nullptr;

    auto result = hook_manager_->create_inline_hook(
        "RealCallbackHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &original_trampoline);
    ASSERT_TRUE(result.has_value());

    bool callback_called = false;
    auto hook_result = hook_manager_->with_inline_hook(
        "RealCallbackHook",
        [&callback_called](InlineHook &hook) -> bool
        {
            callback_called = true;
            EXPECT_EQ(hook.get_name(), "RealCallbackHook");
            EXPECT_EQ(hook.get_type(), HookType::Inline);
            EXPECT_EQ(hook.get_status(), HookStatus::Active);
            EXPECT_NE(hook.get_target_address(), 0u);
            auto orig = hook.get_original<int (*)(int, int)>();
            EXPECT_NE(orig, nullptr);
            return true;
        });

    EXPECT_TRUE(hook_result.has_value());
    EXPECT_TRUE(callback_called);
}

TEST_F(HookManagerTest, RealInlineHook_RemoveAll)
{
    void *tramp1 = nullptr, *tramp2 = nullptr;

    auto result1 = hook_manager_->create_inline_hook(
        "RemAll1",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp1);
    EXPECT_TRUE(result1.has_value());

    auto result2 = hook_manager_->create_inline_hook(
        "RemAll2",
        reinterpret_cast<uintptr_t>(&real_hook_target_mul),
        reinterpret_cast<void *>(&real_hook_detour_mul),
        &tramp2);
    EXPECT_TRUE(result2.has_value());

    hook_manager_->remove_all_hooks();
    EXPECT_EQ(hook_manager_->get_hook_ids().size(), 0u);
}

TEST_F(HookManagerTest, RealMidHook_CreateSuccess)
{
    g_mid_detour_calls.store(0);

    auto detour_fn = [](safetyhook::Context &)
    {
        g_mid_detour_calls.fetch_add(1, std::memory_order_relaxed);
    };

    auto result = hook_manager_->create_mid_hook(
        "RealMidHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);

    ASSERT_TRUE(result.has_value()) << "Real mid hook creation should succeed";
    EXPECT_EQ(*result, "RealMidHook");

    auto status = hook_manager_->get_hook_status("RealMidHook");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Active);

    real_hook_target_add(1, 2);
    EXPECT_GE(g_mid_detour_calls.load(), 1);
}

TEST_F(HookManagerTest, RealMidHook_WithCallback)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook(
        "RealMidCallbackHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    bool callback_called = false;
    auto hook_result = hook_manager_->with_mid_hook(
        "RealMidCallbackHook",
        [&callback_called](MidHook &hook) -> bool
        {
            callback_called = true;
            EXPECT_EQ(hook.get_name(), "RealMidCallbackHook");
            EXPECT_EQ(hook.get_type(), HookType::Mid);
            EXPECT_EQ(hook.get_status(), HookStatus::Active);
            return true;
        });

    EXPECT_TRUE(hook_result.has_value());
    EXPECT_TRUE(callback_called);
}

TEST_F(HookManagerTest, RealMidHook_EnableDisable)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook(
        "RealMidEnDis",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(hook_manager_->disable_hook("RealMidEnDis"));
    EXPECT_EQ(*hook_manager_->get_hook_status("RealMidEnDis"), HookStatus::Disabled);

    EXPECT_TRUE(hook_manager_->enable_hook("RealMidEnDis"));
    EXPECT_EQ(*hook_manager_->get_hook_status("RealMidEnDis"), HookStatus::Active);
}

TEST_F(HookManagerTest, InlineHook_WindowsApiAddress)
{
    void *api_func = reinterpret_cast<void *>(&GetTickCount);
    void *detour_fn = reinterpret_cast<void *>(&real_hook_detour_add);
    void *original_trampoline = nullptr;

    auto result = hook_manager_->create_inline_hook(
        "WindowsApiHook",
        reinterpret_cast<uintptr_t>(api_func),
        detour_fn,
        &original_trampoline);

    if (result.has_value())
    {
        EXPECT_TRUE(hook_manager_->remove_hook("WindowsApiHook"));
    }
}

TEST_F(HookManagerTest, MidHook_WindowsApiAddress)
{
    void *api_func = reinterpret_cast<void *>(&GetTickCount);
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook(
        "MidWindowsApiHook",
        reinterpret_cast<uintptr_t>(api_func),
        detour_fn);

    if (result.has_value())
    {
        EXPECT_TRUE(hook_manager_->remove_hook("MidWindowsApiHook"));
    }
}

TEST_F(HookManagerTest, CreateMidHook_NullAddress)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook("MidNullAddr", 0, detour_fn);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, CreateMidHook_DuplicateName)
{
    auto detour_fn = [](safetyhook::Context &) {};
    void *tramp = nullptr;

    auto result1 = hook_manager_->create_inline_hook(
        "DupMidName",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result1.has_value());

    auto result2 = hook_manager_->create_mid_hook(
        "DupMidName",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    EXPECT_FALSE(result2.has_value());
    EXPECT_EQ(result2.error(), HookError::HookAlreadyExists);
}

TEST_F(HookManagerTest, CreateInlineHookAOB_InvalidPattern)
{
    void *detour_fn = reinterpret_cast<void *>(&real_hook_detour_add);
    void *tramp = nullptr;

    auto result = hook_manager_->create_inline_hook_aob(
        "AOBInvalidPat",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        256,
        "ZZ XX INVALID",
        0,
        detour_fn,
        &tramp);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
    EXPECT_EQ(tramp, nullptr);
}

TEST_F(HookManagerTest, CreateInlineHookAOB_PatternNotFound)
{
    void *detour_fn = reinterpret_cast<void *>(&real_hook_detour_add);
    void *tramp = nullptr;

    auto result = hook_manager_->create_inline_hook_aob(
        "AOBNotFound",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        16,
        "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
        0,
        detour_fn,
        &tramp);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
    EXPECT_EQ(tramp, nullptr);
}

TEST_F(HookManagerTest, CreateMidHookAOB_InvalidPattern)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook_aob(
        "MidAOBInvalid",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        256,
        "ZZ XX INVALID",
        0,
        detour_fn);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, CreateMidHookAOB_PatternNotFound)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook_aob(
        "MidAOBNotFound",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        16,
        "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
        0,
        detour_fn);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, RealMidHook_CreateDisabled)
{
    auto detour_fn = [](safetyhook::Context &) {};
    HookConfig config;
    config.auto_enable = false;

    auto result = hook_manager_->create_mid_hook(
        "RealMidDisabled",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn,
        config);

    ASSERT_TRUE(result.has_value());
    auto status = hook_manager_->get_hook_status("RealMidDisabled");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Disabled);
}

TEST_F(HookManagerTest, WithInlineHook_NotFound)
{
    auto result = hook_manager_->with_inline_hook(
        "NonExistentHook",
        [](InlineHook &) -> bool
        { return true; });
    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, WithMidHook_NotFound)
{
    auto result = hook_manager_->with_mid_hook(
        "NonExistentMidHook",
        [](MidHook &) -> bool
        { return true; });
    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, HotReload_InlineHookAfterShutdown)
{
    void *tramp = nullptr;

    auto r1 = hook_manager_->create_inline_hook(
        "PreShutdownHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(r1.has_value());

    hook_manager_->shutdown();
    EXPECT_TRUE(hook_manager_->get_hook_ids().empty());

    tramp = nullptr;
    auto r2 = hook_manager_->create_inline_hook(
        "PostShutdownHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(r2.has_value()) << "Hook creation must succeed after shutdown (hot-reload)";
    EXPECT_NE(tramp, nullptr);
}

TEST_F(HookManagerTest, HotReload_MidHookAfterShutdown)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto r1 = hook_manager_->create_mid_hook(
        "PreShutdownMid",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(r1.has_value());

    hook_manager_->shutdown();

    auto r2 = hook_manager_->create_mid_hook(
        "PostShutdownMid",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(r2.has_value()) << "Mid hook creation must succeed after shutdown (hot-reload)";
}

TEST_F(HookManagerTest, ShutdownThenRemoveAll_Succeeds)
{
    void *tramp = nullptr;

    auto r1 = hook_manager_->create_inline_hook(
        "ShutRemAll",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(r1.has_value());

    hook_manager_->shutdown();
    hook_manager_->remove_all_hooks();

    tramp = nullptr;
    auto r2 = hook_manager_->create_inline_hook(
        "AfterShutRemAll",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(r2.has_value());
}

TEST_F(HookManagerTest, WithInlineHook_WrongType)
{
    auto detour_fn = [](safetyhook::Context &) {};
    auto result = hook_manager_->create_mid_hook(
        "MidForWrongType",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    auto cb_result = hook_manager_->with_inline_hook(
        "MidForWrongType",
        [](InlineHook &) -> bool
        { return true; });
    EXPECT_FALSE(cb_result.has_value());
}

TEST_F(HookManagerTest, WithMidHook_WrongType)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "InlineForWrongType",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    auto cb_result = hook_manager_->with_mid_hook(
        "InlineForWrongType",
        [](MidHook &) -> bool
        { return true; });
    EXPECT_FALSE(cb_result.has_value());
}

TEST_F(HookManagerTest, StatusToString_AllValues)
{
    EXPECT_EQ(Hook::status_to_string(HookStatus::Active), "Active");
    EXPECT_EQ(Hook::status_to_string(HookStatus::Disabled), "Disabled");
    EXPECT_EQ(Hook::status_to_string(HookStatus::Enabling), "Enabling");
    EXPECT_EQ(Hook::status_to_string(HookStatus::Disabling), "Disabling");
    EXPECT_EQ(Hook::status_to_string(HookStatus::Failed), "Failed");
    EXPECT_EQ(Hook::status_to_string(HookStatus::Removed), "Removed");
    EXPECT_EQ(Hook::status_to_string(static_cast<HookStatus>(999)), "Unknown");
}

TEST_F(HookManagerTest, EnableHook_NotFound)
{
    EXPECT_FALSE(hook_manager_->enable_hook("NonExistent"));
}

TEST_F(HookManagerTest, DisableHook_NotFound)
{
    EXPECT_FALSE(hook_manager_->disable_hook("NonExistent"));
}

TEST_F(HookManagerTest, RemoveHook_NotFound)
{
    EXPECT_FALSE(hook_manager_->remove_hook("NonExistent"));
}

TEST_F(HookManagerTest, RemoveAllHooks_Empty)
{
    hook_manager_->remove_all_hooks();
    EXPECT_NO_THROW(hook_manager_->remove_all_hooks());
    EXPECT_EQ(hook_manager_->get_hook_ids().size(), 0u);
}

TEST_F(HookManagerTest, GetHookStatus_NotFound)
{
    auto status = hook_manager_->get_hook_status("NonExistent");
    EXPECT_FALSE(status.has_value());
}

TEST_F(HookManagerTest, GetHookIds_FilteredEmpty)
{
    auto ids = hook_manager_->get_hook_ids(HookStatus::Failed);
    EXPECT_TRUE(ids.empty());
}

TEST_F(HookManagerTest, ShutdownWithHooks)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "ShutdownHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);

    EXPECT_NO_THROW(hook_manager_->shutdown());
    EXPECT_EQ(hook_manager_->get_hook_ids().size(), 0u);
    EXPECT_NO_THROW(hook_manager_->shutdown());
}

TEST_F(HookManagerTest, RealMidHook_Remove)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook(
        "MidRemoveHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(hook_manager_->remove_hook("MidRemoveHook"));
    EXPECT_FALSE(hook_manager_->get_hook_status("MidRemoveHook").has_value());
}

TEST_F(HookManagerTest, CreateInlineHookAOB_Success)
{
    void *detour_fn = reinterpret_cast<void *>(&real_hook_detour_add);
    void *tramp = nullptr;

    auto *target_bytes = reinterpret_cast<unsigned char *>(&real_hook_target_add);

    std::string pattern;
    for (int i = 0; i < 4; ++i)
    {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", target_bytes[i]);
        pattern += hex;
    }

    auto result = hook_manager_->create_inline_hook_aob(
        "AOBSuccessHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        256,
        pattern,
        0,
        detour_fn,
        &tramp);

    if (result.has_value())
    {
        EXPECT_NE(tramp, nullptr);
        EXPECT_TRUE(hook_manager_->remove_hook("AOBSuccessHook"));
    }
}

TEST_F(HookManagerTest, CreateMidHookAOB_Success)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto *target_bytes = reinterpret_cast<unsigned char *>(&real_hook_target_mul);

    std::string pattern;
    for (int i = 0; i < 4; ++i)
    {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", target_bytes[i]);
        pattern += hex;
    }

    auto result = hook_manager_->create_mid_hook_aob(
        "MidAOBSuccess",
        reinterpret_cast<uintptr_t>(&real_hook_target_mul),
        256,
        pattern,
        0,
        detour_fn);

    if (result.has_value())
    {
        EXPECT_TRUE(hook_manager_->remove_hook("MidAOBSuccess"));
    }
}

TEST_F(HookManagerTest, WithInlineHook_SuccessCallback)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "WithInlineCB",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    auto name_opt = hook_manager_->with_inline_hook("WithInlineCB",
                                                    [](InlineHook &hook) -> std::string
                                                    {
                                                        return std::string(hook.get_name());
                                                    });
    ASSERT_TRUE(name_opt.has_value());
    EXPECT_EQ(*name_opt, "WithInlineCB");

    EXPECT_TRUE(hook_manager_->remove_hook("WithInlineCB"));
}

TEST_F(HookManagerTest, WithMidHook_SuccessCallback)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook(
        "WithMidCB",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    auto name_opt = hook_manager_->with_mid_hook("WithMidCB",
                                                 [](MidHook &hook) -> std::string
                                                 {
                                                     return std::string(hook.get_name());
                                                 });
    ASSERT_TRUE(name_opt.has_value());
    EXPECT_EQ(*name_opt, "WithMidCB");

    EXPECT_TRUE(hook_manager_->remove_hook("WithMidCB"));
}

TEST_F(HookManagerTest, TryWithInlineHook_Success)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "TryInlineCB",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    auto name_opt = hook_manager_->try_with_inline_hook(
        "TryInlineCB",
        [](InlineHook &hook) -> std::string
        {
            return std::string(hook.get_name());
        });
    ASSERT_TRUE(name_opt.has_value());
    EXPECT_EQ(*name_opt, "TryInlineCB");

    EXPECT_TRUE(hook_manager_->remove_hook("TryInlineCB"));
}

TEST_F(HookManagerTest, TryWithInlineHook_NotFound)
{
    auto result = hook_manager_->try_with_inline_hook(
        "NonExistentTryHook",
        [](InlineHook &) -> bool
        { return true; });
    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, TryWithMidHook_Success)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook(
        "TryMidCB",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    auto name_opt = hook_manager_->try_with_mid_hook(
        "TryMidCB",
        [](MidHook &hook) -> std::string
        {
            return std::string(hook.get_name());
        });
    ASSERT_TRUE(name_opt.has_value());
    EXPECT_EQ(*name_opt, "TryMidCB");

    EXPECT_TRUE(hook_manager_->remove_hook("TryMidCB"));
}

TEST_F(HookManagerTest, TryWithMidHook_NotFound)
{
    auto result = hook_manager_->try_with_mid_hook(
        "NonExistentTryMidHook",
        [](MidHook &) -> bool
        { return true; });
    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, RealMidHook_CreateDisabledAutoEnable)
{
    auto detour_fn = [](safetyhook::Context &) {};
    HookConfig config;
    config.auto_enable = false;

    auto result = hook_manager_->create_mid_hook(
        "MidDisabledAE",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn,
        config);
    ASSERT_TRUE(result.has_value());

    auto status = hook_manager_->get_hook_status("MidDisabledAE");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Disabled);

    EXPECT_TRUE(hook_manager_->enable_hook("MidDisabledAE"));
    EXPECT_EQ(*hook_manager_->get_hook_status("MidDisabledAE"), HookStatus::Active);

    EXPECT_TRUE(hook_manager_->disable_hook("MidDisabledAE"));
    EXPECT_EQ(*hook_manager_->get_hook_status("MidDisabledAE"), HookStatus::Disabled);

    EXPECT_TRUE(hook_manager_->remove_hook("MidDisabledAE"));
}

TEST_F(HookManagerTest, ConcurrentEnableDisable)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "ConcurrentHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    constexpr int num_threads = 4;
    constexpr int iterations = 50;
    std::vector<std::thread> threads;
    std::latch start_latch(num_threads);
    std::atomic<bool> saw_active{false};
    std::atomic<bool> saw_disabled{false};

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([this, i, &start_latch, &saw_active, &saw_disabled]()
                             {
            start_latch.arrive_and_wait();
            for (int j = 0; j < iterations; ++j)
            {
                if (j % 2 == (i % 2))
                {
                    (void)hook_manager_->enable_hook("ConcurrentHook");
                }
                else
                {
                    (void)hook_manager_->disable_hook("ConcurrentHook");
                }
                auto s = hook_manager_->get_hook_status("ConcurrentHook");
                if (s.has_value())
                {
                    if (*s == HookStatus::Active)
                        saw_active.store(true, std::memory_order_relaxed);
                    else if (*s == HookStatus::Disabled)
                        saw_disabled.store(true, std::memory_order_relaxed);
                }
            } });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    EXPECT_TRUE(saw_active.load()) << "Expected Active to be observed during concurrent toggling";
    EXPECT_TRUE(saw_disabled.load()) << "Expected Disabled to be observed during concurrent toggling";

    EXPECT_TRUE(hook_manager_->disable_hook("ConcurrentHook"));
    EXPECT_EQ(*hook_manager_->get_hook_status("ConcurrentHook"), HookStatus::Disabled);
    int disabled_result = real_hook_target_add(2, 3);
    EXPECT_EQ(disabled_result, 5);

    EXPECT_TRUE(hook_manager_->enable_hook("ConcurrentHook"));
    EXPECT_EQ(*hook_manager_->get_hook_status("ConcurrentHook"), HookStatus::Active);
    int enabled_result = real_hook_target_add(2, 3);
    EXPECT_NE(enabled_result, 5);
}

TEST_F(HookManagerTest, WithInlineHook_DirectEnableDisable)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "DirectEnDisHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    auto cb_result = hook_manager_->with_inline_hook(
        "DirectEnDisHook",
        [](InlineHook &hook) -> bool
        {
            EXPECT_EQ(hook.get_status(), HookStatus::Active);

            EXPECT_TRUE(hook.disable());
            EXPECT_EQ(hook.get_status(), HookStatus::Disabled);

            EXPECT_TRUE(hook.enable());
            EXPECT_EQ(hook.get_status(), HookStatus::Active);

            EXPECT_TRUE(hook.enable());

            return true;
        });

    ASSERT_TRUE(cb_result.has_value());
    EXPECT_TRUE(*cb_result);
}

TEST_F(HookManagerTest, WithMidHook_DirectEnableDisable)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook(
        "DirectMidEnDisHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    auto cb_result = hook_manager_->with_mid_hook(
        "DirectMidEnDisHook",
        [](MidHook &hook) -> bool
        {
            EXPECT_EQ(hook.get_status(), HookStatus::Active);

            EXPECT_TRUE(hook.disable());
            EXPECT_EQ(hook.get_status(), HookStatus::Disabled);

            EXPECT_TRUE(hook.enable());
            EXPECT_EQ(hook.get_status(), HookStatus::Active);

            EXPECT_TRUE(hook.disable());

            return true;
        });

    ASSERT_TRUE(cb_result.has_value());
    EXPECT_TRUE(*cb_result);
}

TEST_F(HookManagerTest, RemoveAllHooks_WithRealHooks)
{
    void *tramp1 = nullptr;
    auto r1 = hook_manager_->create_inline_hook(
        "BulkRemove1",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp1);
    ASSERT_TRUE(r1.has_value());

    auto detour_fn = [](safetyhook::Context &) {};
    auto r2 = hook_manager_->create_mid_hook(
        "BulkRemove2",
        reinterpret_cast<uintptr_t>(&real_hook_target_mul),
        detour_fn);
    ASSERT_TRUE(r2.has_value());

    EXPECT_EQ(hook_manager_->get_hook_ids().size(), 2u);

    hook_manager_->remove_all_hooks();
    EXPECT_EQ(hook_manager_->get_hook_ids().size(), 0u);
}

TEST_F(HookManagerTest, RealInlineHook_DisabledEnableDisableCycle)
{
    void *tramp = nullptr;
    HookConfig config;
    config.auto_enable = false;

    auto result = hook_manager_->create_inline_hook(
        "InlineDisabled",
        reinterpret_cast<uintptr_t>(&real_hook_target_mul),
        reinterpret_cast<void *>(&real_hook_detour_mul),
        &tramp,
        config);
    ASSERT_TRUE(result.has_value());

    auto status = hook_manager_->get_hook_status("InlineDisabled");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Disabled);

    EXPECT_TRUE(hook_manager_->enable_hook("InlineDisabled"));
    EXPECT_EQ(*hook_manager_->get_hook_status("InlineDisabled"), HookStatus::Active);

    EXPECT_TRUE(hook_manager_->disable_hook("InlineDisabled"));
    EXPECT_EQ(*hook_manager_->get_hook_status("InlineDisabled"), HookStatus::Disabled);

    [[maybe_unused]] bool removed = hook_manager_->remove_hook("InlineDisabled");
    EXPECT_TRUE(removed);
}

TEST_F(HookManagerTest, WithInlineHook_CallbackExecutesSuccessfully)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "CallbackExecHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    auto hook_result = hook_manager_->with_inline_hook(
        "CallbackExecHook",
        [&callback_executed]([[maybe_unused]] InlineHook &hook) -> bool
        {
            callback_executed = true;
            return true;
        });

    EXPECT_TRUE(hook_result.has_value());
    EXPECT_TRUE(callback_executed);
    EXPECT_TRUE(*hook_result);
}

TEST_F(HookManagerTest, WithMidHook_CallbackExecutesSuccessfully)
{
    auto detour_fn = [](safetyhook::Context &) {};
    auto result = hook_manager_->create_mid_hook(
        "MidCallbackExecHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    auto hook_result = hook_manager_->with_mid_hook(
        "MidCallbackExecHook",
        [&callback_executed]([[maybe_unused]] MidHook &hook) -> bool
        {
            callback_executed = true;
            return true;
        });

    EXPECT_TRUE(hook_result.has_value());
    EXPECT_TRUE(callback_executed);
    EXPECT_TRUE(*hook_result);
}

TEST_F(HookManagerTest, TryWithInlineHook_CallbackExecutesSuccessfully)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "TryCallbackExecHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    auto hook_result = hook_manager_->try_with_inline_hook(
        "TryCallbackExecHook",
        [&callback_executed]([[maybe_unused]] InlineHook &hook) -> bool
        {
            callback_executed = true;
            return true;
        });

    EXPECT_TRUE(hook_result.has_value());
    EXPECT_TRUE(callback_executed);
    EXPECT_TRUE(*hook_result);
}

TEST_F(HookManagerTest, TryWithMidHook_CallbackExecutesSuccessfully)
{
    auto detour_fn = [](safetyhook::Context &) {};
    auto result = hook_manager_->create_mid_hook(
        "TryMidCallbackExecHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    auto hook_result = hook_manager_->try_with_mid_hook(
        "TryMidCallbackExecHook",
        [&callback_executed]([[maybe_unused]] MidHook &hook) -> bool
        {
            callback_executed = true;
            return true;
        });

    EXPECT_TRUE(hook_result.has_value());
    EXPECT_TRUE(callback_executed);
    EXPECT_TRUE(*hook_result);
}

TEST_F(HookManagerTest, WithInlineHook_ReturnsNulloptForNonExistentHook)
{
    bool callback_executed = false;
    auto hook_result = hook_manager_->with_inline_hook(
        "NonExistentHook",
        [&callback_executed]([[maybe_unused]] InlineHook &hook) -> bool
        {
            callback_executed = true;
            return true;
        });

    EXPECT_FALSE(hook_result.has_value());
    EXPECT_FALSE(callback_executed);
}

TEST_F(HookManagerTest, InlineHook_GetOriginal_Noexcept)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "NoexceptHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    auto hook_result = hook_manager_->with_inline_hook(
        "NoexceptHook",
        [](InlineHook &hook) -> bool
        {
            static_assert(noexcept(hook.get_original<int (*)(int, int)>()));
            auto orig = hook.get_original<int (*)(int, int)>();
            return orig != nullptr;
        });

    EXPECT_TRUE(hook_result.has_value());
    EXPECT_TRUE(*hook_result);
}

TEST_F(HookManagerTest, MidHook_GetDestination_Noexcept)
{
    auto detour_fn = [](safetyhook::Context &) {};
    auto result = hook_manager_->create_mid_hook(
        "NoexceptMidHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    auto hook_result = hook_manager_->with_mid_hook(
        "NoexceptMidHook",
        [](MidHook &hook) -> bool
        {
            static_assert(noexcept(hook.get_destination()));
            auto dest = hook.get_destination();
            return dest != nullptr;
        });

    EXPECT_TRUE(hook_result.has_value());
    EXPECT_TRUE(*hook_result);
}

TEST_F(HookManagerTest, CreateInlineHook_TrampolineNotSetOnFailure)
{
    void *tramp = reinterpret_cast<void *>(0xDEADBEEF);
    auto result = hook_manager_->create_inline_hook(
        "NullTargetHook",
        0,
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);

    ASSERT_FALSE(result.has_value());
    // Trampoline should remain unchanged on early validation failure
    EXPECT_EQ(tramp, reinterpret_cast<void *>(0xDEADBEEF));
}

TEST_F(HookManagerTest, ShutdownResetsFlag)
{
    // After shutdown(), the manager accepts new hook creation requests
    // (returns validation errors, not ShutdownInProgress).
    // Use a real target address so the test depends on the shutdown flag
    // rather than the validation ordering of target_address == 0.
    hook_manager_->shutdown();

    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "PostShutdownHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        nullptr,
        &tramp);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidDetourFunction);
}
