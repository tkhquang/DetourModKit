// Unit tests for Hook Manager module
#include <gtest/gtest.h>
#include <functional>
#include <thread>
#include <chrono>

#include "DetourModKit/hook_manager.hpp"

using namespace DetourModKit;

// Test fixture for Hook Manager tests
class HookManagerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Get the hook manager instance
        hook_manager_ = &HookManager::getInstance();
    }

    HookManager *hook_manager_;
};

// Test HookManager singleton
TEST(HookManagerSingletonTest, GetInstance)
{
    HookManager &instance1 = HookManager::getInstance();
    HookManager &instance2 = HookManager::getInstance();

    EXPECT_EQ(&instance1, &instance2);
}

// Test HookStatus enum
TEST_F(HookManagerTest, HookStatus)
{
    // Verify HookStatus values exist and can be compared
    HookStatus status1 = HookStatus::Active;
    HookStatus status2 = HookStatus::Disabled;
    HookStatus status3 = HookStatus::Failed;
    HookStatus status4 = HookStatus::Removed;

    // These should all be different
    EXPECT_NE(status1, status2);
    EXPECT_NE(status2, status3);
    EXPECT_NE(status3, status4);
}

// Test HookType enum
TEST_F(HookManagerTest, HookType)
{
    HookType type1 = HookType::Inline;
    HookType type2 = HookType::Mid;

    EXPECT_NE(type1, type2);
}

// Test hook configuration
TEST_F(HookManagerTest, HookConfig)
{
    HookConfig config;

    // Default values
    EXPECT_TRUE(config.autoEnable);
    // inlineFlags and midFlags are safetyhook types, just check they exist
}

// Test create_inline_hook with invalid address
TEST_F(HookManagerTest, CreateInlineHook_InvalidAddress)
{
    // Try to create a hook with address 0 - should fail
    void *detour_fn = reinterpret_cast<void *>(0x87654321);
    void *original_trampoline = nullptr;

    // This should return an error (std::expected has no value)
    auto result = hook_manager_->create_inline_hook(
        "TestInvalidHook",
        0, // invalid address
        detour_fn,
        &original_trampoline);

    // Should have an error (no value)
    EXPECT_FALSE(result.has_value());
}

// Test get_hook_status for non-existent hook
TEST_F(HookManagerTest, GetHookStatus_NonExistent)
{
    auto status = hook_manager_->get_hook_status("NonExistentHook");

    // Should return empty optional for non-existent hook
    EXPECT_FALSE(status.has_value());
}

// Test enable_hook for non-existent hook
TEST_F(HookManagerTest, EnableHook_NonExistent)
{
    bool result = hook_manager_->enable_hook("NonExistentHook");
    EXPECT_FALSE(result);
}

// Test disable_hook for non-existent hook
TEST_F(HookManagerTest, DisableHook_NonExistent)
{
    bool result = hook_manager_->disable_hook("NonExistentHook");
    EXPECT_FALSE(result);
}

// Test remove_hook for non-existent hook
TEST_F(HookManagerTest, RemoveHook_NonExistent)
{
    bool result = hook_manager_->remove_hook("NonExistentHook");
    EXPECT_FALSE(result);
}

// Test get_hook_ids
TEST_F(HookManagerTest, GetHookIds)
{
    auto ids = hook_manager_->get_hook_ids();

    // Should return a vector (may be empty)
    EXPECT_GE(ids.size(), 0u);
}

// Test create_inline_hook_aob with empty pattern
TEST_F(HookManagerTest, CreateInlineHookAob_EmptyPattern)
{
    void *detour_fn = reinterpret_cast<void *>(0x87654321);
    void *original_trampoline = nullptr;

    // This should fail due to empty pattern
    auto result = hook_manager_->create_inline_hook_aob(
        "TestAobHook",
        0,  // module_base
        0,  // module_size
        "", // empty pattern
        0,  // offset
        detour_fn,
        &original_trampoline);

    // Should have an error
    EXPECT_FALSE(result.has_value());
}
