#include <gtest/gtest.h>
#include <atomic>
#include <format>
#include <functional>
#include <mutex>
#include <thread>
#include <chrono>
#include <latch>
#include <type_traits>
#include <windows.h>

#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/logger.hpp"

using namespace DetourModKit;

// VmtHookEntry owns a safetyhook::VmtHook and must be move-only.
// The HookManager destructor's loader-lock fallback path relies on these
// guarantees when storing VmtHookEntry values inside an unordered_map: any
// container operation that selects a copy fallback for VmtHookEntry would
// fail to compile, so guard the contract here.
static_assert(!std::is_copy_constructible_v<VmtHookEntry>,
              "VmtHookEntry must remain non-copyable to preserve VmtHook ownership semantics.");
static_assert(!std::is_copy_assignable_v<VmtHookEntry>,
              "VmtHookEntry must remain non-copy-assignable to preserve VmtHook ownership semantics.");
static_assert(std::is_move_constructible_v<VmtHookEntry>,
              "VmtHookEntry must be move-constructible so it can live in standard containers.");
static_assert(std::is_move_assignable_v<VmtHookEntry>,
              "VmtHookEntry must be move-assignable so it can live in standard containers.");

// The loader-lock fallback in HookManager::~HookManager heap-allocates the
// move-constructed hook maps directly. Guard that the exact map types stay
// move-constructible so that path keeps compiling if the hasher, comparator,
// or value types are ever retuned.
using VmtHookMapForAsserts = std::unordered_map<std::string, VmtHookEntry, detail::TransparentStringHash, std::equal_to<>>;
using HookMapForAsserts = std::unordered_map<std::string, std::unique_ptr<Hook>, detail::TransparentStringHash, std::equal_to<>>;
static_assert(std::is_move_constructible_v<VmtHookMapForAsserts>,
              "unordered_map<string, VmtHookEntry, ...> must be move-constructible for the loader-lock leak path.");
static_assert(std::is_move_constructible_v<HookMapForAsserts>,
              "unordered_map<string, unique_ptr<Hook>, ...> must be move-constructible for the loader-lock leak path.");

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

    EXPECT_NE(status1, status2);
    EXPECT_NE(status2, status3);
    EXPECT_NE(status3, status4);
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

    ASSERT_FALSE(result.has_value());
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

    ASSERT_FALSE(result.has_value());
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

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTrampolinePointer);
}

TEST_F(HookManagerTest, GetHookStatus_NonExistent)
{
    auto status = hook_manager_->get_hook_status("NonExistentHook");

    EXPECT_FALSE(status.has_value());
}

TEST_F(HookManagerTest, EnableHook_NonExistent)
{
    auto result = hook_manager_->enable_hook("NonExistentHook");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, DisableHook_NonExistent)
{
    auto result = hook_manager_->disable_hook("NonExistentHook");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, RemoveHook_NonExistent)
{
    auto result = hook_manager_->remove_hook("NonExistentHook");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
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

    auto enabling_ids = hook_manager_->get_hook_ids(HookStatus::Enabling);
    EXPECT_TRUE(enabling_ids.empty());
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

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, CreateMidHook_NullDetour)
{
    auto result = hook_manager_->create_mid_hook(
        "TestMidNull",
        0x12345678,
        nullptr);

    ASSERT_FALSE(result.has_value());
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

TEST_F(HookManagerTest, GetHookCounts_Empty)
{
    auto counts = hook_manager_->get_hook_counts();

    EXPECT_EQ(counts[HookStatus::Active], 0u);
    EXPECT_EQ(counts[HookStatus::Disabled], 0u);
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
    ASSERT_FALSE(result2.has_value());
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

    EXPECT_TRUE(hook_manager_->enable_hook("RealEnDisHook").has_value());

    EXPECT_TRUE(hook_manager_->disable_hook("RealEnDisHook").has_value());
    EXPECT_EQ(*hook_manager_->get_hook_status("RealEnDisHook"), HookStatus::Disabled);

    EXPECT_TRUE(hook_manager_->disable_hook("RealEnDisHook").has_value());

    EXPECT_TRUE(hook_manager_->enable_hook("RealEnDisHook").has_value());
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

    EXPECT_TRUE(hook_manager_->remove_hook("RealRemoveHook").has_value());
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

    EXPECT_TRUE(hook_manager_->disable_hook("RealMidEnDis").has_value());
    EXPECT_EQ(*hook_manager_->get_hook_status("RealMidEnDis"), HookStatus::Disabled);

    EXPECT_TRUE(hook_manager_->enable_hook("RealMidEnDis").has_value());
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
        EXPECT_TRUE(hook_manager_->remove_hook("WindowsApiHook").has_value());
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
        EXPECT_TRUE(hook_manager_->remove_hook("MidWindowsApiHook").has_value());
    }
}

TEST_F(HookManagerTest, CreateMidHook_NullAddress)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = hook_manager_->create_mid_hook("MidNullAddr", 0, detour_fn);
    ASSERT_FALSE(result.has_value());
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
    ASSERT_FALSE(result2.has_value());
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
    ASSERT_FALSE(result.has_value());
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
    ASSERT_FALSE(result.has_value());
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
    ASSERT_FALSE(result.has_value());
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
    ASSERT_FALSE(result.has_value());
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
    EXPECT_EQ(Hook::status_to_string(static_cast<HookStatus>(999)), "Unknown");
}

TEST_F(HookManagerTest, EnableHook_NotFound)
{
    auto result = hook_manager_->enable_hook("NonExistent");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, DisableHook_NotFound)
{
    auto result = hook_manager_->disable_hook("NonExistent");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, RemoveHook_NotFound)
{
    auto result = hook_manager_->remove_hook("NonExistent");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
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
    auto ids = hook_manager_->get_hook_ids(HookStatus::Disabled);
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

    EXPECT_TRUE(hook_manager_->remove_hook("MidRemoveHook").has_value());
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
        EXPECT_TRUE(hook_manager_->remove_hook("AOBSuccessHook").has_value());
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
        EXPECT_TRUE(hook_manager_->remove_hook("MidAOBSuccess").has_value());
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

    EXPECT_TRUE(hook_manager_->remove_hook("WithInlineCB").has_value());
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

    EXPECT_TRUE(hook_manager_->remove_hook("WithMidCB").has_value());
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

    EXPECT_TRUE(hook_manager_->remove_hook("TryInlineCB").has_value());
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

    EXPECT_TRUE(hook_manager_->remove_hook("TryMidCB").has_value());
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

    EXPECT_TRUE(hook_manager_->enable_hook("MidDisabledAE").has_value());
    EXPECT_EQ(*hook_manager_->get_hook_status("MidDisabledAE"), HookStatus::Active);

    EXPECT_TRUE(hook_manager_->disable_hook("MidDisabledAE").has_value());
    EXPECT_EQ(*hook_manager_->get_hook_status("MidDisabledAE"), HookStatus::Disabled);

    EXPECT_TRUE(hook_manager_->remove_hook("MidDisabledAE").has_value());
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

    constexpr int num_toggling_threads = 4;
    constexpr int iterations = 200;
    // +1 for the dedicated observer thread that only reads status
    constexpr int total_threads = num_toggling_threads + 1;
    std::vector<std::thread> threads;
    std::latch start_latch(total_threads);
    std::atomic<bool> saw_active{false};
    std::atomic<bool> saw_disabled{false};
    std::atomic<bool> done{false};

    // Toggling threads: concurrently enable/disable the hook
    for (int i = 0; i < num_toggling_threads; ++i)
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

    // Dedicated observer thread: polls status without toggling to reliably
    // catch both terminal states between concurrent enable/disable transitions
    threads.emplace_back([this, &start_latch, &saw_active, &saw_disabled, &done]()
                         {
        start_latch.arrive_and_wait();
        while (!done.load(std::memory_order_acquire))
        {
            auto s = hook_manager_->get_hook_status("ConcurrentHook");
            if (s.has_value())
            {
                if (*s == HookStatus::Active)
                    saw_active.store(true, std::memory_order_relaxed);
                else if (*s == HookStatus::Disabled)
                    saw_disabled.store(true, std::memory_order_relaxed);
            }
        } });

    // Wait for toggling threads first, then signal the observer to stop
    for (int i = 0; i < num_toggling_threads; ++i)
    {
        threads[i].join();
    }
    done.store(true, std::memory_order_release);
    threads[num_toggling_threads].join();

    EXPECT_TRUE(saw_active.load()) << "Expected Active to be observed during concurrent toggling";
    EXPECT_TRUE(saw_disabled.load()) << "Expected Disabled to be observed during concurrent toggling";

    EXPECT_TRUE(hook_manager_->disable_hook("ConcurrentHook").has_value());
    EXPECT_EQ(*hook_manager_->get_hook_status("ConcurrentHook"), HookStatus::Disabled);
    int disabled_result = real_hook_target_add(2, 3);
    EXPECT_EQ(disabled_result, 5);

    EXPECT_TRUE(hook_manager_->enable_hook("ConcurrentHook").has_value());
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

            EXPECT_TRUE(hook.disable().has_value());
            EXPECT_EQ(hook.get_status(), HookStatus::Disabled);

            EXPECT_TRUE(hook.enable().has_value());
            EXPECT_EQ(hook.get_status(), HookStatus::Active);

            EXPECT_TRUE(hook.enable().has_value());

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

            EXPECT_TRUE(hook.disable().has_value());
            EXPECT_EQ(hook.get_status(), HookStatus::Disabled);

            EXPECT_TRUE(hook.enable().has_value());
            EXPECT_EQ(hook.get_status(), HookStatus::Active);

            EXPECT_TRUE(hook.disable().has_value());

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

    EXPECT_TRUE(hook_manager_->enable_hook("InlineDisabled").has_value());
    EXPECT_EQ(*hook_manager_->get_hook_status("InlineDisabled"), HookStatus::Active);

    EXPECT_TRUE(hook_manager_->disable_hook("InlineDisabled").has_value());
    EXPECT_EQ(*hook_manager_->get_hook_status("InlineDisabled"), HookStatus::Disabled);

    auto removed = hook_manager_->remove_hook("InlineDisabled");
    EXPECT_TRUE(removed.has_value());
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
    // After shutdown(), the manager resets its flag and accepts new hook
    // creation requests. A null detour should yield InvalidDetourFunction,
    // not ShutdownInProgress.
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

TEST_F(HookManagerTest, WithInlineHook_VoidCallback)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "VoidInlineCB",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    bool found = hook_manager_->with_inline_hook(
        "VoidInlineCB",
        [&callback_executed](InlineHook &hook)
        {
            callback_executed = true;
            EXPECT_EQ(hook.get_type(), HookType::Inline);
        });

    EXPECT_TRUE(found);
    EXPECT_TRUE(callback_executed);
}

TEST_F(HookManagerTest, WithInlineHook_VoidCallback_NotFound)
{
    bool callback_executed = false;
    bool found = hook_manager_->with_inline_hook(
        "NonExistentVoidCB",
        [&callback_executed]([[maybe_unused]] InlineHook &hook)
        {
            callback_executed = true;
        });

    EXPECT_FALSE(found);
    EXPECT_FALSE(callback_executed);
}

TEST_F(HookManagerTest, WithMidHook_VoidCallback)
{
    auto detour_fn = [](safetyhook::Context &) {};
    auto result = hook_manager_->create_mid_hook(
        "VoidMidCB",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        detour_fn);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    bool found = hook_manager_->with_mid_hook(
        "VoidMidCB",
        [&callback_executed](MidHook &hook)
        {
            callback_executed = true;
            EXPECT_EQ(hook.get_type(), HookType::Mid);
        });

    EXPECT_TRUE(found);
    EXPECT_TRUE(callback_executed);
}

TEST_F(HookManagerTest, WithMidHook_VoidCallback_NotFound)
{
    bool callback_executed = false;
    bool found = hook_manager_->with_mid_hook(
        "NonExistentVoidMidCB",
        [&callback_executed]([[maybe_unused]] MidHook &hook)
        {
            callback_executed = true;
        });

    EXPECT_FALSE(found);
    EXPECT_FALSE(callback_executed);
}

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

// Vtable layout differs between MSVC (single destructor slot) and
// Itanium ABI (two destructor slots used by GCC/MinGW).
#if defined(_MSC_VER)
static constexpr size_t VMT_COMPUTE_INDEX = 1;
static constexpr size_t VMT_TRANSFORM_INDEX = 2;
#else
static constexpr size_t VMT_COMPUTE_INDEX = 2;
static constexpr size_t VMT_TRANSFORM_INDEX = 3;
#endif

static safetyhook::VmHook *g_compute_vm_hook = nullptr;

class VmtTestHook : public VmtTestTarget
{
public:
    int hooked_compute(int a, int b)
    {
        return g_compute_vm_hook->thiscall<int>(this, a, b) + 1000;
    }
};

TEST_F(HookManagerTest, VmtHook_CreateSuccess)
{
    auto target = std::make_unique<VmtTestTarget>();

    auto result = hook_manager_->create_vmt_hook("TestVmt", target.get());
    ASSERT_TRUE(result.has_value()) << "VMT hook creation should succeed";
    EXPECT_EQ(*result, "TestVmt");

    auto names = hook_manager_->get_vmt_hook_names();
    EXPECT_EQ(names.size(), 1u);
    EXPECT_EQ(names[0], "TestVmt");

    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_CreateNullObject)
{
    auto result = hook_manager_->create_vmt_hook("NullVmt", nullptr);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidObject);
}

TEST_F(HookManagerTest, VmtHook_CreateDuplicate)
{
    auto target = std::make_unique<VmtTestTarget>();

    auto r1 = hook_manager_->create_vmt_hook("DupVmt", target.get());
    ASSERT_TRUE(r1.has_value());

    auto r2 = hook_manager_->create_vmt_hook("DupVmt", target.get());
    ASSERT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), HookError::HookAlreadyExists);

    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_HookMethod)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(target->compute(3, 4), 7);

    auto vmt_result = hook_manager_->create_vmt_hook("MethodVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto method_result = hook_manager_->hook_vmt_method(
        "MethodVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(method_result.has_value()) << "Method hook should succeed";
    EXPECT_EQ(*method_result, VMT_COMPUTE_INDEX);

    ASSERT_TRUE(hook_manager_->with_vmt_method(
        "MethodVmt", VMT_COMPUTE_INDEX,
        [](safetyhook::VmHook &hook)
        { g_compute_vm_hook = &hook; }));

    EXPECT_EQ(target->compute(3, 4), 1007);

    g_compute_vm_hook = nullptr;
    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_HookMethodDuplicate)
{
    auto target = std::make_unique<VmtTestTarget>();

    auto vmt_result = hook_manager_->create_vmt_hook("DupMethodVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto r1 = hook_manager_->hook_vmt_method(
        "DupMethodVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(r1.has_value());

    auto r2 = hook_manager_->hook_vmt_method(
        "DupMethodVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), HookError::MethodAlreadyHooked);

    g_compute_vm_hook = nullptr;
    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_HookMethodNotFound)
{
    auto result = hook_manager_->hook_vmt_method(
        "NonExistentVmt", 0, &VmtTestHook::hooked_compute);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::VmtHookNotFound);
}

TEST_F(HookManagerTest, VmtHook_RemoveMethod)
{
    auto target = std::make_unique<VmtTestTarget>();

    auto vmt_result = hook_manager_->create_vmt_hook("RemMethodVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto method_result = hook_manager_->hook_vmt_method(
        "RemMethodVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(method_result.has_value());

    ASSERT_TRUE(hook_manager_->with_vmt_method(
        "RemMethodVmt", VMT_COMPUTE_INDEX,
        [](safetyhook::VmHook &hook)
        { g_compute_vm_hook = &hook; }));

    EXPECT_EQ(target->compute(5, 5), 1010);

    g_compute_vm_hook = nullptr;
    EXPECT_TRUE(hook_manager_->remove_vmt_method("RemMethodVmt", VMT_COMPUTE_INDEX).has_value());

    EXPECT_EQ(target->compute(5, 5), 10);

    auto re_remove = hook_manager_->remove_vmt_method("RemMethodVmt", VMT_COMPUTE_INDEX);
    ASSERT_FALSE(re_remove.has_value());
    EXPECT_EQ(re_remove.error(), HookError::MethodNotFound);

    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_RemoveEntireHook)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(target->compute(1, 2), 3);

    auto vmt_result = hook_manager_->create_vmt_hook("RemVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto method_result = hook_manager_->hook_vmt_method(
        "RemVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(method_result.has_value());

    ASSERT_TRUE(hook_manager_->with_vmt_method(
        "RemVmt", VMT_COMPUTE_INDEX,
        [](safetyhook::VmHook &hook)
        { g_compute_vm_hook = &hook; }));

    EXPECT_EQ(target->compute(1, 2), 1003);

    g_compute_vm_hook = nullptr;
    EXPECT_TRUE(hook_manager_->remove_vmt_hook("RemVmt").has_value());

    EXPECT_EQ(target->compute(1, 2), 3);
    EXPECT_TRUE(hook_manager_->get_vmt_hook_names().empty());
}

TEST_F(HookManagerTest, VmtHook_RemoveNotFound)
{
    auto result = hook_manager_->remove_vmt_hook("NonExistent");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::VmtHookNotFound);
}

TEST_F(HookManagerTest, VmtHook_ApplyToMultipleObjects)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();

    auto vmt_result = hook_manager_->create_vmt_hook("MultiVmt", target1.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto method_result = hook_manager_->hook_vmt_method(
        "MultiVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(method_result.has_value());

    ASSERT_TRUE(hook_manager_->with_vmt_method(
        "MultiVmt", VMT_COMPUTE_INDEX,
        [](safetyhook::VmHook &hook)
        { g_compute_vm_hook = &hook; }));

    EXPECT_EQ(target1->compute(1, 1), 1002);
    EXPECT_EQ(target2->compute(1, 1), 2);

    EXPECT_TRUE(hook_manager_->apply_vmt_hook("MultiVmt", target2.get()));
    EXPECT_EQ(target2->compute(1, 1), 1002);

    EXPECT_TRUE(hook_manager_->remove_vmt_from_object("MultiVmt", target2.get()));
    EXPECT_EQ(target2->compute(1, 1), 2);
    EXPECT_EQ(target1->compute(1, 1), 1002);

    g_compute_vm_hook = nullptr;
    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_RemoveAllVmt)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(hook_manager_->create_vmt_hook("Vmt1", target1.get()).has_value());
    ASSERT_TRUE(hook_manager_->create_vmt_hook("Vmt2", target2.get()).has_value());

    EXPECT_EQ(hook_manager_->get_vmt_hook_names().size(), 2u);

    hook_manager_->remove_all_vmt_hooks();
    EXPECT_TRUE(hook_manager_->get_vmt_hook_names().empty());
}

TEST_F(HookManagerTest, VmtHook_RemoveAllHooksClearsVmt)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(hook_manager_->create_vmt_hook("VmtCleared", target.get()).has_value());
    EXPECT_EQ(hook_manager_->get_vmt_hook_names().size(), 1u);

    hook_manager_->remove_all_hooks();
    EXPECT_TRUE(hook_manager_->get_vmt_hook_names().empty());
}

TEST_F(HookManagerTest, VmtHook_ShutdownClearsVmt)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(hook_manager_->create_vmt_hook("VmtShutdown", target.get()).has_value());

    hook_manager_->shutdown();
    EXPECT_TRUE(hook_manager_->get_vmt_hook_names().empty());

    ASSERT_TRUE(hook_manager_->create_vmt_hook("VmtPostShutdown", target.get()).has_value());

    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_WithVmtMethod_ValueCallback)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(hook_manager_->create_vmt_hook("CbVmt", target.get()).has_value());
    ASSERT_TRUE(hook_manager_->hook_vmt_method(
                                 "CbVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute)
                    .has_value());

    auto result = hook_manager_->with_vmt_method(
        "CbVmt", VMT_COMPUTE_INDEX,
        [](safetyhook::VmHook &hook) -> bool
        {
            return hook.original<void *>() != nullptr;
        });

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);

    g_compute_vm_hook = nullptr;
    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_WithVmtMethod_NotFound)
{
    auto result = hook_manager_->with_vmt_method(
        "NonExistentVmt", 0,
        [](safetyhook::VmHook &) -> bool
        { return true; });

    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, VmtHook_WithVmtMethod_MethodNotFound)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(hook_manager_->create_vmt_hook("NoMethodVmt", target.get()).has_value());

    auto result = hook_manager_->with_vmt_method(
        "NoMethodVmt", 99,
        [](safetyhook::VmHook &) -> bool
        { return true; });

    EXPECT_FALSE(result.has_value());

    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_WithVmtMethod_VoidCallback)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(hook_manager_->create_vmt_hook("VoidCbVmt", target.get()).has_value());
    ASSERT_TRUE(hook_manager_->hook_vmt_method(
                                 "VoidCbVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute)
                    .has_value());

    bool callback_executed = false;
    bool found = hook_manager_->with_vmt_method(
        "VoidCbVmt", VMT_COMPUTE_INDEX,
        [&callback_executed](safetyhook::VmHook &)
        {
            callback_executed = true;
        });

    EXPECT_TRUE(found);
    EXPECT_TRUE(callback_executed);

    g_compute_vm_hook = nullptr;
    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_ErrorStrings)
{
    EXPECT_EQ(Hook::error_to_string(HookError::ShutdownInProgress), "Shutdown in progress");
    EXPECT_EQ(Hook::error_to_string(HookError::InvalidObject), "Invalid object pointer");
    EXPECT_EQ(Hook::error_to_string(HookError::VmtHookNotFound), "VMT hook not found");
    EXPECT_EQ(Hook::error_to_string(HookError::MethodAlreadyHooked), "VMT method already hooked");
}

TEST_F(HookManagerTest, VmtHook_ApplyNullObject)
{
    auto target = std::make_unique<VmtTestTarget>();
    ASSERT_TRUE(hook_manager_->create_vmt_hook("ApplyNullVmt", target.get()).has_value());

    EXPECT_FALSE(hook_manager_->apply_vmt_hook("ApplyNullVmt", nullptr));

    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_RemoveFromNullObject)
{
    auto target = std::make_unique<VmtTestTarget>();
    ASSERT_TRUE(hook_manager_->create_vmt_hook("RemNullVmt", target.get()).has_value());

    EXPECT_FALSE(hook_manager_->remove_vmt_from_object("RemNullVmt", nullptr));

    hook_manager_->remove_all_vmt_hooks();
}

TEST(HookErrorStringTest, ErrorToString_ShutdownInProgress)
{
    EXPECT_EQ(Hook::error_to_string(HookError::ShutdownInProgress), "Shutdown in progress");
}

TEST(HookErrorStringTest, StatusToString_Constexpr)
{
    static_assert(Hook::status_to_string(HookStatus::Active) == "Active");
    static_assert(Hook::status_to_string(HookStatus::Disabled) == "Disabled");
}

TEST(HookErrorStringTest, ErrorToString_Constexpr)
{
    static_assert(Hook::error_to_string(HookError::InvalidTargetAddress) == "Invalid target address");
    static_assert(Hook::error_to_string(HookError::ShutdownInProgress) == "Shutdown in progress");
}

TEST_F(HookManagerTest, Shutdown_AllowsNewHooksAfterReset)
{
    hook_manager_->shutdown();

    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "AfterShutdownHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "AfterShutdownHook");
    EXPECT_NE(tramp, nullptr);
}

TEST_F(HookManagerTest, ErrorToString_ShutdownAndAllocatorErrors)
{
    // These error codes are emitted during shutdown sequences when the
    // allocator is torn down. Verify the string representations are stable.
    EXPECT_EQ(Hook::error_to_string(HookError::ShutdownInProgress), "Shutdown in progress");
    EXPECT_EQ(Hook::error_to_string(HookError::AllocatorNotAvailable), "Allocator not available");
}

TEST_F(HookManagerTest, ErrorToString_AllErrorValues)
{
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::AllocatorNotAvailable)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::InvalidTargetAddress)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::InvalidDetourFunction)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::InvalidTrampolinePointer)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::HookAlreadyExists)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::HookNotFound)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::ShutdownInProgress)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::SafetyHookError)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::EnableFailed)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::DisableFailed)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::InvalidHookState)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::InvalidObject)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::VmtHookNotFound)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::MethodAlreadyHooked)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::MethodNotFound)).empty());
    EXPECT_FALSE(std::string_view(Hook::error_to_string(HookError::UnknownError)).empty());
}

TEST_F(HookManagerTest, CreateInlineHookAob_NullStartAddress)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook_aob(
        "AobNullBase",
        0,
        0x1000,
        "48 8B 05",
        0,
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);

    ASSERT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, CreateMidHookAob_NullStartAddress)
{
    auto result = hook_manager_->create_mid_hook_aob(
        "MidAobNullBase",
        0,
        0x1000,
        "48 8B 05",
        0,
        [](safetyhook::Context &) {});

    ASSERT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, GetHookCounts_AfterCreation)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "CountTestHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    auto counts = hook_manager_->get_hook_counts();
    EXPECT_GE(counts[HookStatus::Active], 1u);
}

TEST_F(HookManagerTest, VmtHook_CreateAfterShutdownSucceeds)
{
    // shutdown() resets the shutdown flag for hot-reload, so subsequent
    // create calls succeed against a clean HookManager.
    auto target = std::make_unique<VmtTestTarget>();

    hook_manager_->shutdown();

    auto result = hook_manager_->create_vmt_hook("VmtAfterShutdown", target.get());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "VmtAfterShutdown");

    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_MethodHookAfterShutdownNotFound)
{
    // shutdown() clears all VMT hooks, so hook_vmt_method returns VmtHookNotFound.
    auto target = std::make_unique<VmtTestTarget>();

    auto vmt_result = hook_manager_->create_vmt_hook("MethodShutdownVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    hook_manager_->shutdown();

    auto method_result = hook_manager_->hook_vmt_method(
        "MethodShutdownVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_FALSE(method_result.has_value());
    EXPECT_EQ(method_result.error(), HookError::VmtHookNotFound);
}

TEST_F(HookManagerTest, VmtHook_ConcurrentCreateAndShutdown)
{
    constexpr int kThreads = 8;
    std::latch start_latch(kThreads + 1);
    std::atomic<int> success_count{0};
    std::atomic<int> rejected_count{0};
    std::mutex errors_mutex;
    std::vector<HookError> errors;

    std::vector<std::unique_ptr<VmtTestTarget>> targets;
    for (int i = 0; i < kThreads; ++i)
        targets.push_back(std::make_unique<VmtTestTarget>());

    std::vector<std::jthread> threads;
    for (int i = 0; i < kThreads; ++i)
    {
        threads.emplace_back([&, i]
        {
            start_latch.arrive_and_wait();
            auto result = hook_manager_->create_vmt_hook(
                std::format("ConcVmt{}", i), targets[i].get());
            if (result.has_value())
            {
                success_count.fetch_add(1, std::memory_order_relaxed);
            }
            else
            {
                rejected_count.fetch_add(1, std::memory_order_relaxed);
                std::lock_guard<std::mutex> lock(errors_mutex);
                errors.push_back(result.error());
            }
        });
    }

    start_latch.arrive_and_wait();
    hook_manager_->shutdown();

    for (auto &t : threads)
        t.join();

    EXPECT_EQ(success_count.load() + rejected_count.load(), kThreads);

    for (const auto &err : errors)
    {
        EXPECT_EQ(err, HookError::ShutdownInProgress);
    }

    // Clean up any VMT hooks that were created before shutdown took effect.
    // shutdown() resets the flag, so surviving hooks must be removed before
    // the test-local targets are destroyed.
    hook_manager_->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, ApplyVmtHook_NotFoundName_ReturnsFalse)
{
    int dummy_object = 0;
    EXPECT_FALSE(hook_manager_->apply_vmt_hook("NonExistentVmt", &dummy_object));
}

TEST_F(HookManagerTest, RemoveVmtFromObject_NotFoundName_ReturnsFalse)
{
    int dummy_object = 0;
    EXPECT_FALSE(hook_manager_->remove_vmt_from_object("NonExistentVmt", &dummy_object));
}

TEST_F(HookManagerTest, RemoveAllVmtHooks_WhenEmpty_NoOp)
{
    EXPECT_NO_THROW(hook_manager_->remove_all_vmt_hooks());
    EXPECT_TRUE(hook_manager_->get_vmt_hook_names().empty());
}

TEST_F(HookManagerTest, GetHookIds_FilterByActive_ReturnsMatching)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "ActiveFilterHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    auto active_ids = hook_manager_->get_hook_ids(HookStatus::Active);
    ASSERT_FALSE(active_ids.empty());

    bool found = false;
    for (const auto &id : active_ids)
    {
        if (id == "ActiveFilterHook")
        {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(HookManagerTest, GetHookIds_FilterByDisabled_AfterDisable)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "DisableFilterHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(hook_manager_->disable_hook("DisableFilterHook").has_value());

    auto disabled_ids = hook_manager_->get_hook_ids(HookStatus::Disabled);
    ASSERT_FALSE(disabled_ids.empty());

    bool found = false;
    for (const auto &id : disabled_ids)
    {
        if (id == "DisableFilterHook")
        {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(HookManagerTest, ShutdownThenEnable_ReturnsNotFound)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "ShutEnableHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    hook_manager_->shutdown();

    auto enable_result = hook_manager_->enable_hook("ShutEnableHook");
    ASSERT_FALSE(enable_result.has_value());
    EXPECT_EQ(enable_result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, ShutdownThenDisable_ReturnsNotFound)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "ShutDisableHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    hook_manager_->shutdown();

    auto disable_result = hook_manager_->disable_hook("ShutDisableHook");
    ASSERT_FALSE(disable_result.has_value());
    EXPECT_EQ(disable_result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, ShutdownThenRemove_ReturnsNotFound)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "ShutRemoveHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    hook_manager_->shutdown();

    auto remove_result = hook_manager_->remove_hook("ShutRemoveHook");
    ASSERT_FALSE(remove_result.has_value());
    EXPECT_EQ(remove_result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, ShutdownThenGetStatus_ReturnsNullopt)
{
    void *tramp = nullptr;
    auto result = hook_manager_->create_inline_hook(
        "ShutStatusHook",
        reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add),
        &tramp);
    ASSERT_TRUE(result.has_value());

    hook_manager_->shutdown();

    auto status = hook_manager_->get_hook_status("ShutStatusHook");
    EXPECT_FALSE(status.has_value());
}

TEST(HookErrorStringTest, ErrorToString_InvalidEnum_ReturnsInvalidCode)
{
    auto result = Hook::error_to_string(static_cast<HookError>(9999));
    EXPECT_EQ(result, "Invalid error code");
}

TEST(HookStatusStringTest, StatusToString_InvalidEnum_ReturnsUnknown)
{
    auto result = Hook::status_to_string(static_cast<HookStatus>(9999));
    EXPECT_EQ(result, "Unknown");
}

TEST_F(HookManagerTest, RemoveAllHooks_WithOnlyVmtHooks)
{
    struct FakeVtable
    {
        void *methods[4]{};
    };
    FakeVtable vtable{};
    void *vptr = &vtable;

    auto vmt_result = hook_manager_->create_vmt_hook("VmtOnlyHook", &vptr);
    ASSERT_TRUE(vmt_result.has_value());
    EXPECT_FALSE(hook_manager_->get_vmt_hook_names().empty());

    hook_manager_->remove_all_hooks();

    EXPECT_TRUE(hook_manager_->get_vmt_hook_names().empty());
}

TEST(HookDuplicateDetection, FailIfAlreadyHookedIsStoredInConfig)
{
    HookConfig cfg;
    EXPECT_FALSE(cfg.fail_if_already_hooked);
    cfg.fail_if_already_hooked = true;
    EXPECT_TRUE(cfg.fail_if_already_hooked);
}

TEST(HookDuplicateDetection, TargetAlreadyHookedErrorStringExists)
{
    const std::string_view msg = Hook::error_to_string(HookError::TargetAlreadyHookedInProcess);
    EXPECT_FALSE(msg.empty());
    EXPECT_NE(msg.find("already"), std::string_view::npos);
}

namespace
{
    [[gnu::noinline]] void duplicate_hook_target_function() noexcept
    {
        volatile int x = 0;
        x = x + 1;
        (void)x;
    }

    void duplicate_hook_detour_a() noexcept {}
    void duplicate_hook_detour_b() noexcept {}
} // namespace

TEST_F(HookManagerTest, DuplicateHook_StrictMode_ReturnsTargetAlreadyHooked)
{
    auto &hm = *hook_manager_;
    const auto target =
        reinterpret_cast<std::uintptr_t>(&duplicate_hook_target_function);

    void *trampoline_a = nullptr;
    auto first = hm.create_inline_hook(
        "dup-first",
        target,
        reinterpret_cast<void *>(&duplicate_hook_detour_a),
        &trampoline_a);
    ASSERT_TRUE(first.has_value()) << "initial inline hook should succeed";

    HookConfig strict;
    strict.fail_if_already_hooked = true;

    void *trampoline_b = nullptr;
    auto second = hm.create_inline_hook(
        "dup-second",
        target,
        reinterpret_cast<void *>(&duplicate_hook_detour_b),
        &trampoline_b,
        strict);

    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error(), HookError::TargetAlreadyHookedInProcess);
    EXPECT_EQ(trampoline_b, nullptr);

    (void)hm.remove_hook("dup-first");
}

TEST_F(HookManagerTest, DuplicateHook_DefaultMode_LayersOnTop)
{
    auto &hm = *hook_manager_;
    const auto target =
        reinterpret_cast<std::uintptr_t>(&duplicate_hook_target_function);

    void *trampoline_a = nullptr;
    auto first = hm.create_inline_hook(
        "dup-layer-first",
        target,
        reinterpret_cast<void *>(&duplicate_hook_detour_a),
        &trampoline_a);
    ASSERT_TRUE(first.has_value());

    void *trampoline_b = nullptr;
    auto second = hm.create_inline_hook(
        "dup-layer-second",
        target,
        reinterpret_cast<void *>(&duplicate_hook_detour_b),
        &trampoline_b);

    EXPECT_TRUE(second.has_value());

    (void)hm.remove_hook("dup-layer-second");
    (void)hm.remove_hook("dup-layer-first");
}

namespace
{
    [[gnu::noinline]] void late_destruction_target_function() noexcept
    {
        volatile int x = 0;
        x = x + 1;
        (void)x;
    }

    void late_destruction_detour() noexcept {}
} // namespace

// Covers the destructor fallback path: a late shutdown() must serialize
// against readers holding shared_lock via with_inline_hook() so their
// callbacks never observe the maps being cleared under them. The
// destructor only fires at static-destruction time, so the contract we
// can verify in a unit test is the equivalent serialization provided by
// shutdown(): a reader callback finishes cleanly, and a subsequent
// shutdown() does not deadlock or crash.
TEST_F(HookManagerTest, LateShutdown_DrainsReadersBeforeClearingMaps)
{
    auto &hm = *hook_manager_;
    const auto target =
        reinterpret_cast<std::uintptr_t>(&late_destruction_target_function);

    void *trampoline = nullptr;
    auto created = hm.create_inline_hook(
        "late-shutdown-hook",
        target,
        reinterpret_cast<void *>(&late_destruction_detour),
        &trampoline);
    ASSERT_TRUE(created.has_value());

    std::atomic<bool> reader_started{false};
    std::atomic<bool> reader_may_return{false};
    std::atomic<bool> reader_observed_valid{false};

    std::thread reader([&]() {
        bool invoked = hm.with_inline_hook("late-shutdown-hook", [&](InlineHook &hook) {
            reader_started.store(true, std::memory_order_release);
            // Hold the shared_lock while the main thread races shutdown().
            while (!reader_may_return.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            // Dereference the hook while still holding the shared_lock.
            // If the destructor cleared the maps out from under us the
            // name would be dangling; any UAF surfaces here under ASan.
            reader_observed_valid.store(!hook.get_name().empty(),
                                        std::memory_order_release);
        });
        EXPECT_TRUE(invoked);
    });

    while (!reader_started.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // Spawn the shutdown racer. shutdown() must block on m_mutator_gate
    // until the reader releases the shared_lock, which proves the
    // destructor-equivalent ordering.
    std::atomic<bool> shutdown_returned{false};
    std::thread killer([&]() {
        hm.shutdown();
        shutdown_returned.store(true, std::memory_order_release);
    });

    // Give the killer a chance to start; it must not return while the
    // reader holds shared_lock (shutdown path acquires exclusive on
    // m_hooks_mutex after the shared disable pass). Assert that
    // ordering directly so a premature-return regression fails the
    // test even if reader_observed_valid still happens to hold.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(shutdown_returned.load(std::memory_order_acquire));
    reader_may_return.store(true, std::memory_order_release);

    reader.join();
    killer.join();

    EXPECT_TRUE(reader_observed_valid.load());
    EXPECT_TRUE(shutdown_returned.load());
}
