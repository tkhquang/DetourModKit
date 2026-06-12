#include <gtest/gtest.h>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <mutex>
#include <thread>
#include <chrono>
#include <latch>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <windows.h>

#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/logger.hpp"

using namespace DetourModKit;

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

namespace
{
    [[nodiscard]] void *test_pointer(std::uintptr_t value) noexcept
    {
        return reinterpret_cast<void *>(value);
    }
} // namespace

// VmtHookEntry owns a safetyhook::VmtHook and must be move-only. The HookManager destructor's loader-lock fallback path
// relies on these guarantees when storing VmtHookEntry values inside an unordered_map: any container operation that
// selects a copy fallback for VmtHookEntry would fail to compile, so guard the contract here.
static_assert(!std::is_copy_constructible_v<detail::VmtHookEntry>,
              "VmtHookEntry must remain non-copyable to preserve VmtHook ownership semantics.");
static_assert(!std::is_copy_assignable_v<detail::VmtHookEntry>,
              "VmtHookEntry must remain non-copy-assignable to preserve VmtHook ownership semantics.");
static_assert(std::is_move_constructible_v<detail::VmtHookEntry>,
              "VmtHookEntry must be move-constructible so it can live in standard containers.");
static_assert(std::is_move_assignable_v<detail::VmtHookEntry>,
              "VmtHookEntry must be move-assignable so it can live in standard containers.");

// The loader-lock fallback in HookManager::~HookManager heap-allocates an empty map and then swaps the live map's
// contents into the leaked storage. Guard that swap stays nothrow for these exact map types so the call cannot turn a
// noexcept destructor into std::terminate if the hasher, comparator, allocator, or value types are ever changed. Member
// swap on unordered_map is specified noexcept when the allocator is always-equal (std::allocator is) and the hasher and
// key_equal are nothrow-swappable.
static_assert(std::is_nothrow_swappable_v<detail::VmtHookMap>,
              "unordered_map<string, VmtHookEntry, ...> must be nothrow-swappable for the loader-lock leak path.");
static_assert(std::is_nothrow_swappable_v<detail::HookMap>,
              "unordered_map<string, unique_ptr<Hook>, ...> must be nothrow-swappable for the loader-lock leak path.");

class HookManagerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_hook_manager = &HookManager::get_instance();
        m_hook_manager->remove_all_hooks();
    }

    void TearDown() override
    {
        if (m_hook_manager)
        {
            m_hook_manager->remove_all_hooks();
        }
    }

    HookManager *m_hook_manager;
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
    void *detour_fn = test_pointer(0x87654321u);
    void *original_trampoline = nullptr;

    auto result = m_hook_manager->create_inline_hook("TestInvalidHook", 0, detour_fn, &original_trampoline);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, CreateInlineHook_NullDetour)
{
    void *original_trampoline = nullptr;

    auto result = m_hook_manager->create_inline_hook("TestNullDetour", 0x12345678, nullptr, &original_trampoline);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidDetourFunction);
}

TEST_F(HookManagerTest, CreateInlineHook_NullTrampoline)
{
    void *detour_fn = test_pointer(0x87654321u);

    auto result = m_hook_manager->create_inline_hook("TestNullTrampoline", 0x12345678, detour_fn, nullptr);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTrampolinePointer);
}

TEST_F(HookManagerTest, GetHookStatus_NonExistent)
{
    auto status = m_hook_manager->get_hook_status("NonExistentHook");

    EXPECT_FALSE(status.has_value());
}

TEST_F(HookManagerTest, EnableHook_NonExistent)
{
    auto result = m_hook_manager->enable_hook("NonExistentHook");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, DisableHook_NonExistent)
{
    auto result = m_hook_manager->disable_hook("NonExistentHook");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, RemoveHook_NonExistent)
{
    auto result = m_hook_manager->remove_hook("NonExistentHook");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, GetHookIds)
{
    auto ids = m_hook_manager->get_hook_ids();

    EXPECT_TRUE(ids.empty());
}

TEST_F(HookManagerTest, GetHookIds_WithFilter)
{
    auto active_ids = m_hook_manager->get_hook_ids(HookStatus::Active);
    EXPECT_TRUE(active_ids.empty());

    auto disabled_ids = m_hook_manager->get_hook_ids(HookStatus::Disabled);
    EXPECT_TRUE(disabled_ids.empty());

    auto enabling_ids = m_hook_manager->get_hook_ids(HookStatus::Enabling);
    EXPECT_TRUE(enabling_ids.empty());
}

TEST_F(HookManagerTest, RemoveAllHooks)
{
    EXPECT_NO_THROW(m_hook_manager->remove_all_hooks());
}

TEST_F(HookManagerTest, CreateInlineHookAob_EmptyPattern)
{
    void *detour_fn = test_pointer(0x87654321u);
    void *original_trampoline = nullptr;

    auto result = m_hook_manager->create_inline_hook_aob("TestAobHook", 0, 0, "", 0, detour_fn, &original_trampoline);

    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, CreateInlineHookAob_InvalidPattern)
{
    void *detour_fn = test_pointer(0x87654321u);
    void *original_trampoline = nullptr;

    auto result = m_hook_manager->create_inline_hook_aob("TestAobHookInvalid", 0, 0, "ZZ ?? XX", 0, detour_fn,
                                                         &original_trampoline);

    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, CreateMidHook_InvalidAddress)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = m_hook_manager->create_mid_hook("TestMidInvalid", 0, detour_fn);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, CreateMidHook_NullDetour)
{
    auto result = m_hook_manager->create_mid_hook("TestMidNull", 0x12345678, nullptr);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidDetourFunction);
}

TEST_F(HookManagerTest, CreateMidHookAob_EmptyPattern)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = m_hook_manager->create_mid_hook_aob("TestMidAobEmpty", 0, 0, "", 0, detour_fn);

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
        threads.emplace_back(
            [this, i]()
            {
                for (int j = 0; j < 10; ++j)
                {
                    (void)m_hook_manager->get_hook_status("Thread" + std::to_string(i) + "_" + std::to_string(j));
                    (void)m_hook_manager->get_hook_counts();
                    (void)m_hook_manager->get_hook_ids();
                    (void)m_hook_manager->enable_hook("nonexistent_" + std::to_string(i));
                    (void)m_hook_manager->disable_hook("nonexistent_" + std::to_string(i));
                }
            });
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
    auto counts = m_hook_manager->get_hook_counts();

    EXPECT_EQ(counts[HookStatus::Active], 0u);
    EXPECT_EQ(counts[HookStatus::Disabled], 0u);
}

TEST_F(HookManagerTest, Shutdown_Multiple)
{
    EXPECT_NO_THROW(m_hook_manager->shutdown());
    EXPECT_NO_THROW(m_hook_manager->shutdown());
    EXPECT_NO_THROW(m_hook_manager->shutdown());
}

TEST_F(HookManagerTest, RemoveAllHooks_Multiple)
{
    EXPECT_NO_THROW(m_hook_manager->remove_all_hooks());
    EXPECT_NO_THROW(m_hook_manager->remove_all_hooks());
    EXPECT_NO_THROW(m_hook_manager->remove_all_hooks());
}

// Real hook tests using valid function addresses in the test binary

DMK_TEST_NOINLINE static int real_hook_target_add(int a, int b)
{
    volatile int r = a + b;
    return r;
}

DMK_TEST_NOINLINE static int real_hook_target_mul(int a, int b)
{
    volatile int r = a * b;
    return r;
}

static std::atomic<int> s_real_detour_calls{0};

DMK_TEST_NOINLINE static int real_hook_detour_add(int a, int b)
{
    s_real_detour_calls.fetch_add(1, std::memory_order_relaxed);
    return a + b + 1000;
}

DMK_TEST_NOINLINE static int real_hook_detour_mul(int a, int b)
{
    s_real_detour_calls.fetch_add(1, std::memory_order_relaxed);
    return a * b + 1000;
}

static std::atomic<int> s_mid_detour_calls{0};

TEST_F(HookManagerTest, RealInlineHook_CreateSuccess)
{
    s_real_detour_calls.store(0);
    void *original_trampoline = nullptr;

    auto result =
        m_hook_manager->create_inline_hook("RealAddHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &original_trampoline);

    ASSERT_TRUE(result.has_value()) << "Hook creation on real test function should succeed";
    EXPECT_EQ(*result, "RealAddHook");
    EXPECT_NE(original_trampoline, nullptr);

    auto status = m_hook_manager->get_hook_status("RealAddHook");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Active);

    auto ids = m_hook_manager->get_hook_ids();
    EXPECT_FALSE(ids.empty());

    auto active_ids = m_hook_manager->get_hook_ids(HookStatus::Active);
    EXPECT_FALSE(active_ids.empty());

    auto counts = m_hook_manager->get_hook_counts();
    EXPECT_GE(counts[HookStatus::Active], 1u);
}

TEST_F(HookManagerTest, RealInlineHook_CreateDisabled)
{
    void *original_trampoline = nullptr;
    HookConfig config;
    config.auto_enable = false;

    auto result = m_hook_manager->create_inline_hook(
        "RealDisabledHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
        reinterpret_cast<void *>(&real_hook_detour_add), &original_trampoline, config);

    ASSERT_TRUE(result.has_value());
    auto status = m_hook_manager->get_hook_status("RealDisabledHook");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Disabled);
}

TEST_F(HookManagerTest, RealInlineHook_DuplicateName)
{
    void *tramp1 = nullptr, *tramp2 = nullptr;

    auto result1 = m_hook_manager->create_inline_hook("DupRealHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                      reinterpret_cast<void *>(&real_hook_detour_add), &tramp1);
    ASSERT_TRUE(result1.has_value());

    auto result2 = m_hook_manager->create_inline_hook("DupRealHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                      reinterpret_cast<void *>(&real_hook_detour_add), &tramp2);
    ASSERT_FALSE(result2.has_value());
    EXPECT_EQ(result2.error(), HookError::HookAlreadyExists);
}

TEST_F(HookManagerTest, RealInlineHook_EnableDisable)
{
    void *original_trampoline = nullptr;

    auto result =
        m_hook_manager->create_inline_hook("RealEnDisHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &original_trampoline);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(m_hook_manager->enable_hook("RealEnDisHook").has_value());

    EXPECT_TRUE(m_hook_manager->disable_hook("RealEnDisHook").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("RealEnDisHook"), HookStatus::Disabled);

    EXPECT_TRUE(m_hook_manager->disable_hook("RealEnDisHook").has_value());

    EXPECT_TRUE(m_hook_manager->enable_hook("RealEnDisHook").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("RealEnDisHook"), HookStatus::Active);
}

// Creates two real inline hooks on the two distinct test targets; returns their ids. Each TEST_F gets a fresh manager
// (SetUp/TearDown call remove_all_hooks).
static std::vector<std::string> make_two_real_hooks(HookManager &manager)
{
    void *tramp_add = nullptr;
    void *tramp_mul = nullptr;
    EXPECT_TRUE(manager
                    .create_inline_hook("BatchHookAdd", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                        reinterpret_cast<void *>(&real_hook_detour_add), &tramp_add)
                    .has_value());
    EXPECT_TRUE(manager
                    .create_inline_hook("BatchHookMul", reinterpret_cast<uintptr_t>(&real_hook_target_mul),
                                        reinterpret_cast<void *>(&real_hook_detour_mul), &tramp_mul)
                    .has_value());
    return {"BatchHookAdd", "BatchHookMul"};
}

TEST_F(HookManagerTest, BatchDisableThenEnable_RealHooks)
{
    const auto ids = make_two_real_hooks(*m_hook_manager);
    const std::vector<std::string_view> id_views{ids[0], ids[1]};

    EXPECT_EQ(m_hook_manager->disable_hooks(id_views), 2u);
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookAdd"), HookStatus::Disabled);
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookMul"), HookStatus::Disabled);

    EXPECT_EQ(m_hook_manager->enable_hooks(id_views), 2u);
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookAdd"), HookStatus::Active);
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookMul"), HookStatus::Active);
}

TEST_F(HookManagerTest, BatchToggle_SkipsUnknownIds)
{
    const auto ids = make_two_real_hooks(*m_hook_manager);
    // One real id plus one that does not exist: only the real one counts.
    const std::vector<std::string_view> mixed{ids[0], "NoSuchHook"};

    EXPECT_EQ(m_hook_manager->disable_hooks(mixed), 1u);
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookAdd"), HookStatus::Disabled);
    // The other real hook was not in the batch, so it stays active.
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookMul"), HookStatus::Active);
}

TEST_F(HookManagerTest, BatchToggle_IsIdempotent)
{
    const auto ids = make_two_real_hooks(*m_hook_manager);
    const std::vector<std::string_view> id_views{ids[0], ids[1]};

    EXPECT_EQ(m_hook_manager->disable_hooks(id_views), 2u);
    // Disabling again is a success per hook (disable is idempotent).
    EXPECT_EQ(m_hook_manager->disable_hooks(id_views), 2u);
}

TEST_F(HookManagerTest, EnableAllAndDisableAll_RealHooks)
{
    make_two_real_hooks(*m_hook_manager);

    EXPECT_EQ(m_hook_manager->disable_all_hooks(), 2u);
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookAdd"), HookStatus::Disabled);
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookMul"), HookStatus::Disabled);

    EXPECT_EQ(m_hook_manager->enable_all_hooks(), 2u);
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookAdd"), HookStatus::Active);
    EXPECT_EQ(*m_hook_manager->get_hook_status("BatchHookMul"), HookStatus::Active);
}

TEST_F(HookManagerTest, BatchToggle_EmptyInputs)
{
    // No hooks and an empty span: both batch entry points report zero work.
    const std::vector<std::string_view> empty;
    EXPECT_EQ(m_hook_manager->enable_hooks(empty), 0u);
    EXPECT_EQ(m_hook_manager->enable_all_hooks(), 0u);
    EXPECT_EQ(m_hook_manager->disable_all_hooks(), 0u);
}

TEST_F(HookManagerTest, RealInlineHook_Remove)
{
    void *original_trampoline = nullptr;

    auto result =
        m_hook_manager->create_inline_hook("RealRemoveHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &original_trampoline);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(m_hook_manager->remove_hook("RealRemoveHook").has_value());
    EXPECT_FALSE(m_hook_manager->get_hook_status("RealRemoveHook").has_value());
}

TEST_F(HookManagerTest, RealInlineHook_WithCallback)
{
    void *original_trampoline = nullptr;

    auto result =
        m_hook_manager->create_inline_hook("RealCallbackHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &original_trampoline);
    ASSERT_TRUE(result.has_value());

    bool callback_called = false;
    auto hook_result = m_hook_manager->with_inline_hook("RealCallbackHook",
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

    auto result1 = m_hook_manager->create_inline_hook("RemAll1", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                      reinterpret_cast<void *>(&real_hook_detour_add), &tramp1);
    EXPECT_TRUE(result1.has_value());

    auto result2 = m_hook_manager->create_inline_hook("RemAll2", reinterpret_cast<uintptr_t>(&real_hook_target_mul),
                                                      reinterpret_cast<void *>(&real_hook_detour_mul), &tramp2);
    EXPECT_TRUE(result2.has_value());

    m_hook_manager->remove_all_hooks();
    EXPECT_EQ(m_hook_manager->get_hook_ids().size(), 0u);
}

TEST_F(HookManagerTest, RealMidHook_CreateSuccess)
{
    s_mid_detour_calls.store(0);

    auto detour_fn = [](safetyhook::Context &) { s_mid_detour_calls.fetch_add(1, std::memory_order_relaxed); };

    auto result =
        m_hook_manager->create_mid_hook("RealMidHook", reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);

    ASSERT_TRUE(result.has_value()) << "Real mid hook creation should succeed";
    EXPECT_EQ(*result, "RealMidHook");

    auto status = m_hook_manager->get_hook_status("RealMidHook");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Active);

    real_hook_target_add(1, 2);
    EXPECT_GE(s_mid_detour_calls.load(), 1);
}

TEST_F(HookManagerTest, RealMidHook_WithCallback)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = m_hook_manager->create_mid_hook("RealMidCallbackHook",
                                                  reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_TRUE(result.has_value());

    bool callback_called = false;
    auto hook_result = m_hook_manager->with_mid_hook("RealMidCallbackHook",
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

    auto result =
        m_hook_manager->create_mid_hook("RealMidEnDis", reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(m_hook_manager->disable_hook("RealMidEnDis").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("RealMidEnDis"), HookStatus::Disabled);

    EXPECT_TRUE(m_hook_manager->enable_hook("RealMidEnDis").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("RealMidEnDis"), HookStatus::Active);
}

TEST_F(HookManagerTest, InlineHook_WindowsApiAddress)
{
    void *api_func = reinterpret_cast<void *>(&GetTickCount);
    void *detour_fn = reinterpret_cast<void *>(&real_hook_detour_add);
    void *original_trampoline = nullptr;

    auto result = m_hook_manager->create_inline_hook("WindowsApiHook", reinterpret_cast<uintptr_t>(api_func), detour_fn,
                                                     &original_trampoline);

    if (result.has_value())
    {
        EXPECT_TRUE(m_hook_manager->remove_hook("WindowsApiHook").has_value());
    }
}

TEST_F(HookManagerTest, MidHook_WindowsApiAddress)
{
    void *api_func = reinterpret_cast<void *>(&GetTickCount);
    auto detour_fn = [](safetyhook::Context &) {};

    auto result =
        m_hook_manager->create_mid_hook("MidWindowsApiHook", reinterpret_cast<uintptr_t>(api_func), detour_fn);

    if (result.has_value())
    {
        EXPECT_TRUE(m_hook_manager->remove_hook("MidWindowsApiHook").has_value());
    }
}

TEST_F(HookManagerTest, CreateMidHook_NullAddress)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = m_hook_manager->create_mid_hook("MidNullAddr", 0, detour_fn);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, CreateMidHook_DuplicateName)
{
    auto detour_fn = [](safetyhook::Context &) {};
    void *tramp = nullptr;

    auto result1 = m_hook_manager->create_inline_hook("DupMidName", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                      reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result1.has_value());

    auto result2 =
        m_hook_manager->create_mid_hook("DupMidName", reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_FALSE(result2.has_value());
    EXPECT_EQ(result2.error(), HookError::HookAlreadyExists);
}

TEST_F(HookManagerTest, CreateInlineHookAOB_InvalidPattern)
{
    void *detour_fn = reinterpret_cast<void *>(&real_hook_detour_add);
    void *tramp = nullptr;

    auto result =
        m_hook_manager->create_inline_hook_aob("AOBInvalidPat", reinterpret_cast<uintptr_t>(&real_hook_target_add), 256,
                                               "ZZ XX INVALID", 0, detour_fn, &tramp);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
    EXPECT_EQ(tramp, nullptr);
}

TEST_F(HookManagerTest, CreateInlineHookAOB_PatternNotFound)
{
    void *detour_fn = reinterpret_cast<void *>(&real_hook_detour_add);
    void *tramp = nullptr;

    auto result = m_hook_manager->create_inline_hook_aob(
        "AOBNotFound", reinterpret_cast<uintptr_t>(&real_hook_target_add), 16,
        "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF", 0, detour_fn, &tramp);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
    EXPECT_EQ(tramp, nullptr);
}

TEST_F(HookManagerTest, CreateMidHookAOB_InvalidPattern)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result = m_hook_manager->create_mid_hook_aob(
        "MidAOBInvalid", reinterpret_cast<uintptr_t>(&real_hook_target_add), 256, "ZZ XX INVALID", 0, detour_fn);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, CreateMidHookAOB_PatternNotFound)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result =
        m_hook_manager->create_mid_hook_aob("MidAOBNotFound", reinterpret_cast<uintptr_t>(&real_hook_target_add), 16,
                                            "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF", 0, detour_fn);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidTargetAddress);
}

TEST_F(HookManagerTest, RealMidHook_CreateDisabled)
{
    auto detour_fn = [](safetyhook::Context &) {};
    HookConfig config;
    config.auto_enable = false;

    auto result = m_hook_manager->create_mid_hook("RealMidDisabled", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                  detour_fn, config);

    ASSERT_TRUE(result.has_value());
    auto status = m_hook_manager->get_hook_status("RealMidDisabled");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Disabled);
}

TEST_F(HookManagerTest, WithInlineHook_NotFound)
{
    auto result = m_hook_manager->with_inline_hook("NonExistentHook", [](InlineHook &) -> bool { return true; });
    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, WithMidHook_NotFound)
{
    auto result = m_hook_manager->with_mid_hook("NonExistentMidHook", [](MidHook &) -> bool { return true; });
    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, HotReload_InlineHookAfterShutdown)
{
    void *tramp = nullptr;

    auto r1 = m_hook_manager->create_inline_hook("PreShutdownHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                 reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(r1.has_value());

    m_hook_manager->shutdown();
    EXPECT_TRUE(m_hook_manager->get_hook_ids().empty());

    tramp = nullptr;
    auto r2 = m_hook_manager->create_inline_hook("PostShutdownHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                 reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(r2.has_value()) << "Hook creation must succeed after shutdown (hot-reload)";
    EXPECT_NE(tramp, nullptr);
}

TEST_F(HookManagerTest, HotReload_MidHookAfterShutdown)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto r1 = m_hook_manager->create_mid_hook("PreShutdownMid", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                              detour_fn);
    ASSERT_TRUE(r1.has_value());

    m_hook_manager->shutdown();

    auto r2 = m_hook_manager->create_mid_hook("PostShutdownMid", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                              detour_fn);
    ASSERT_TRUE(r2.has_value()) << "Mid hook creation must succeed after shutdown (hot-reload)";
}

TEST_F(HookManagerTest, ShutdownThenRemoveAll_Succeeds)
{
    void *tramp = nullptr;

    auto r1 = m_hook_manager->create_inline_hook("ShutRemAll", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                 reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(r1.has_value());

    m_hook_manager->shutdown();
    m_hook_manager->remove_all_hooks();

    tramp = nullptr;
    auto r2 = m_hook_manager->create_inline_hook("AfterShutRemAll", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                 reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(r2.has_value());
}

TEST_F(HookManagerTest, WithInlineHook_WrongType)
{
    auto detour_fn = [](safetyhook::Context &) {};
    auto result = m_hook_manager->create_mid_hook("MidForWrongType", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                  detour_fn);
    ASSERT_TRUE(result.has_value());

    auto cb_result = m_hook_manager->with_inline_hook("MidForWrongType", [](InlineHook &) -> bool { return true; });
    EXPECT_FALSE(cb_result.has_value());
}

TEST_F(HookManagerTest, WithMidHook_WrongType)
{
    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("InlineForWrongType", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    auto cb_result = m_hook_manager->with_mid_hook("InlineForWrongType", [](MidHook &) -> bool { return true; });
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
    auto result = m_hook_manager->enable_hook("NonExistent");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, DisableHook_NotFound)
{
    auto result = m_hook_manager->disable_hook("NonExistent");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, RemoveHook_NotFound)
{
    auto result = m_hook_manager->remove_hook("NonExistent");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, RemoveAllHooks_Empty)
{
    m_hook_manager->remove_all_hooks();
    EXPECT_NO_THROW(m_hook_manager->remove_all_hooks());
    EXPECT_EQ(m_hook_manager->get_hook_ids().size(), 0u);
}

TEST_F(HookManagerTest, GetHookStatus_NotFound)
{
    auto status = m_hook_manager->get_hook_status("NonExistent");
    EXPECT_FALSE(status.has_value());
}

TEST_F(HookManagerTest, GetHookIds_FilteredEmpty)
{
    auto ids = m_hook_manager->get_hook_ids(HookStatus::Disabled);
    EXPECT_TRUE(ids.empty());
}

TEST_F(HookManagerTest, ShutdownWithHooks)
{
    void *tramp = nullptr;
    auto result = m_hook_manager->create_inline_hook("ShutdownHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                     reinterpret_cast<void *>(&real_hook_detour_add), &tramp);

    EXPECT_NO_THROW(m_hook_manager->shutdown());
    EXPECT_EQ(m_hook_manager->get_hook_ids().size(), 0u);
    EXPECT_NO_THROW(m_hook_manager->shutdown());
}

TEST_F(HookManagerTest, RealMidHook_Remove)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result =
        m_hook_manager->create_mid_hook("MidRemoveHook", reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(m_hook_manager->remove_hook("MidRemoveHook").has_value());
    EXPECT_FALSE(m_hook_manager->get_hook_status("MidRemoveHook").has_value());
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

    auto result = m_hook_manager->create_inline_hook_aob(
        "AOBSuccessHook", reinterpret_cast<uintptr_t>(&real_hook_target_add), 256, pattern, 0, detour_fn, &tramp);

    if (result.has_value())
    {
        EXPECT_NE(tramp, nullptr);
        EXPECT_TRUE(m_hook_manager->remove_hook("AOBSuccessHook").has_value());
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

    auto result = m_hook_manager->create_mid_hook_aob(
        "MidAOBSuccess", reinterpret_cast<uintptr_t>(&real_hook_target_mul), 256, pattern, 0, detour_fn);

    if (result.has_value())
    {
        EXPECT_TRUE(m_hook_manager->remove_hook("MidAOBSuccess").has_value());
    }
}

TEST_F(HookManagerTest, WithInlineHook_SuccessCallback)
{
    void *tramp = nullptr;
    auto result = m_hook_manager->create_inline_hook("WithInlineCB", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                     reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    auto name_opt = m_hook_manager->with_inline_hook("WithInlineCB", [](InlineHook &hook) -> std::string
                                                     { return std::string(hook.get_name()); });
    ASSERT_TRUE(name_opt.has_value());
    EXPECT_EQ(*name_opt, "WithInlineCB");

    EXPECT_TRUE(m_hook_manager->remove_hook("WithInlineCB").has_value());
}

TEST_F(HookManagerTest, WithMidHook_SuccessCallback)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result =
        m_hook_manager->create_mid_hook("WithMidCB", reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_TRUE(result.has_value());

    auto name_opt = m_hook_manager->with_mid_hook("WithMidCB", [](MidHook &hook) -> std::string
                                                  { return std::string(hook.get_name()); });
    ASSERT_TRUE(name_opt.has_value());
    EXPECT_EQ(*name_opt, "WithMidCB");

    EXPECT_TRUE(m_hook_manager->remove_hook("WithMidCB").has_value());
}

TEST_F(HookManagerTest, TryWithInlineHook_Success)
{
    void *tramp = nullptr;
    auto result = m_hook_manager->create_inline_hook("TryInlineCB", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                     reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    auto name_opt = m_hook_manager->try_with_inline_hook("TryInlineCB", [](InlineHook &hook) -> std::string
                                                         { return std::string(hook.get_name()); });
    ASSERT_TRUE(name_opt.has_value());
    EXPECT_EQ(*name_opt, "TryInlineCB");

    EXPECT_TRUE(m_hook_manager->remove_hook("TryInlineCB").has_value());
}

TEST_F(HookManagerTest, TryWithInlineHook_NotFound)
{
    auto result = m_hook_manager->try_with_inline_hook("NonExistentTryHook", [](InlineHook &) -> bool { return true; });
    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, TryWithMidHook_Success)
{
    auto detour_fn = [](safetyhook::Context &) {};

    auto result =
        m_hook_manager->create_mid_hook("TryMidCB", reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_TRUE(result.has_value());

    auto name_opt = m_hook_manager->try_with_mid_hook("TryMidCB", [](MidHook &hook) -> std::string
                                                      { return std::string(hook.get_name()); });
    ASSERT_TRUE(name_opt.has_value());
    EXPECT_EQ(*name_opt, "TryMidCB");

    EXPECT_TRUE(m_hook_manager->remove_hook("TryMidCB").has_value());
}

TEST_F(HookManagerTest, TryWithMidHook_NotFound)
{
    auto result = m_hook_manager->try_with_mid_hook("NonExistentTryMidHook", [](MidHook &) -> bool { return true; });
    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, RealMidHook_CreateDisabledAutoEnable)
{
    auto detour_fn = [](safetyhook::Context &) {};
    HookConfig config;
    config.auto_enable = false;

    auto result = m_hook_manager->create_mid_hook("MidDisabledAE", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                  detour_fn, config);
    ASSERT_TRUE(result.has_value());

    auto status = m_hook_manager->get_hook_status("MidDisabledAE");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Disabled);

    EXPECT_TRUE(m_hook_manager->enable_hook("MidDisabledAE").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("MidDisabledAE"), HookStatus::Active);

    EXPECT_TRUE(m_hook_manager->disable_hook("MidDisabledAE").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("MidDisabledAE"), HookStatus::Disabled);

    EXPECT_TRUE(m_hook_manager->remove_hook("MidDisabledAE").has_value());
}

TEST_F(HookManagerTest, ConcurrentEnableDisable)
{
    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("ConcurrentHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
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
        threads.emplace_back(
            [this, i, &start_latch, &saw_active, &saw_disabled]()
            {
                start_latch.arrive_and_wait();
                for (int j = 0; j < iterations; ++j)
                {
                    if (j % 2 == (i % 2))
                    {
                        (void)m_hook_manager->enable_hook("ConcurrentHook");
                    }
                    else
                    {
                        (void)m_hook_manager->disable_hook("ConcurrentHook");
                    }
                    auto s = m_hook_manager->get_hook_status("ConcurrentHook");
                    if (s.has_value())
                    {
                        if (*s == HookStatus::Active)
                            saw_active.store(true, std::memory_order_relaxed);
                        else if (*s == HookStatus::Disabled)
                            saw_disabled.store(true, std::memory_order_relaxed);
                    }
                }
            });
    }

    // Dedicated observer thread: polls status without toggling to reliably catch both terminal states between
    // concurrent enable/disable transitions
    threads.emplace_back(
        [this, &start_latch, &saw_active, &saw_disabled, &done]()
        {
            start_latch.arrive_and_wait();
            while (!done.load(std::memory_order_acquire))
            {
                auto s = m_hook_manager->get_hook_status("ConcurrentHook");
                if (s.has_value())
                {
                    if (*s == HookStatus::Active)
                        saw_active.store(true, std::memory_order_relaxed);
                    else if (*s == HookStatus::Disabled)
                        saw_disabled.store(true, std::memory_order_relaxed);
                }
            }
        });

    // Wait for toggling threads first, then signal the observer to stop
    for (int i = 0; i < num_toggling_threads; ++i)
    {
        threads[i].join();
    }
    done.store(true, std::memory_order_release);
    threads[num_toggling_threads].join();

    EXPECT_TRUE(saw_active.load()) << "Expected Active to be observed during concurrent toggling";
    EXPECT_TRUE(saw_disabled.load()) << "Expected Disabled to be observed during concurrent toggling";

    EXPECT_TRUE(m_hook_manager->disable_hook("ConcurrentHook").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("ConcurrentHook"), HookStatus::Disabled);
    int disabled_result = real_hook_target_add(2, 3);
    EXPECT_EQ(disabled_result, 5);

    EXPECT_TRUE(m_hook_manager->enable_hook("ConcurrentHook").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("ConcurrentHook"), HookStatus::Active);
    int enabled_result = real_hook_target_add(2, 3);
    EXPECT_NE(enabled_result, 5);
}

TEST_F(HookManagerTest, WithInlineHook_DirectEnableDisable)
{
    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("DirectEnDisHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    auto cb_result = m_hook_manager->with_inline_hook("DirectEnDisHook",
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

    auto result = m_hook_manager->create_mid_hook("DirectMidEnDisHook",
                                                  reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_TRUE(result.has_value());

    auto cb_result = m_hook_manager->with_mid_hook("DirectMidEnDisHook",
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
    auto r1 = m_hook_manager->create_inline_hook("BulkRemove1", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                 reinterpret_cast<void *>(&real_hook_detour_add), &tramp1);
    ASSERT_TRUE(r1.has_value());

    auto detour_fn = [](safetyhook::Context &) {};
    auto r2 =
        m_hook_manager->create_mid_hook("BulkRemove2", reinterpret_cast<uintptr_t>(&real_hook_target_mul), detour_fn);
    ASSERT_TRUE(r2.has_value());

    EXPECT_EQ(m_hook_manager->get_hook_ids().size(), 2u);

    m_hook_manager->remove_all_hooks();
    EXPECT_EQ(m_hook_manager->get_hook_ids().size(), 0u);
}

TEST_F(HookManagerTest, RealInlineHook_DisabledEnableDisableCycle)
{
    void *tramp = nullptr;
    HookConfig config;
    config.auto_enable = false;

    auto result =
        m_hook_manager->create_inline_hook("InlineDisabled", reinterpret_cast<uintptr_t>(&real_hook_target_mul),
                                           reinterpret_cast<void *>(&real_hook_detour_mul), &tramp, config);
    ASSERT_TRUE(result.has_value());

    auto status = m_hook_manager->get_hook_status("InlineDisabled");
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(*status, HookStatus::Disabled);

    EXPECT_TRUE(m_hook_manager->enable_hook("InlineDisabled").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("InlineDisabled"), HookStatus::Active);

    EXPECT_TRUE(m_hook_manager->disable_hook("InlineDisabled").has_value());
    EXPECT_EQ(*m_hook_manager->get_hook_status("InlineDisabled"), HookStatus::Disabled);

    auto removed = m_hook_manager->remove_hook("InlineDisabled");
    EXPECT_TRUE(removed.has_value());
}

TEST_F(HookManagerTest, WithInlineHook_CallbackExecutesSuccessfully)
{
    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("CallbackExecHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    auto hook_result = m_hook_manager->with_inline_hook("CallbackExecHook",
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
    auto result = m_hook_manager->create_mid_hook("MidCallbackExecHook",
                                                  reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    auto hook_result = m_hook_manager->with_mid_hook("MidCallbackExecHook",
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
    auto result =
        m_hook_manager->create_inline_hook("TryCallbackExecHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    auto hook_result =
        m_hook_manager->try_with_inline_hook("TryCallbackExecHook",
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
    auto result = m_hook_manager->create_mid_hook("TryMidCallbackExecHook",
                                                  reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    auto hook_result = m_hook_manager->try_with_mid_hook("TryMidCallbackExecHook",
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
    auto hook_result = m_hook_manager->with_inline_hook("NonExistentHook",
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
    auto result = m_hook_manager->create_inline_hook("NoexceptHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                     reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    auto hook_result =
        m_hook_manager->with_inline_hook("NoexceptHook",
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
    auto result = m_hook_manager->create_mid_hook("NoexceptMidHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                  detour_fn);
    ASSERT_TRUE(result.has_value());

    auto hook_result = m_hook_manager->with_mid_hook("NoexceptMidHook",
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
    void *tramp = test_pointer(0xDEADBEEFu);
    auto result = m_hook_manager->create_inline_hook("NullTargetHook", 0,
                                                     reinterpret_cast<void *>(&real_hook_detour_add), &tramp);

    ASSERT_FALSE(result.has_value());
    // Trampoline should remain unchanged on early validation failure
    EXPECT_EQ(tramp, test_pointer(0xDEADBEEFu));
}

TEST_F(HookManagerTest, ShutdownResetsFlag)
{
    // After shutdown(), the manager resets its flag and accepts new hook creation requests. A null detour should yield
    // InvalidDetourFunction, not ShutdownInProgress.
    m_hook_manager->shutdown();

    void *tramp = nullptr;
    auto result = m_hook_manager->create_inline_hook(
        "PostShutdownHook", reinterpret_cast<uintptr_t>(&real_hook_target_add), nullptr, &tramp);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidDetourFunction);
}

TEST_F(HookManagerTest, WithInlineHook_VoidCallback)
{
    void *tramp = nullptr;
    auto result = m_hook_manager->create_inline_hook("VoidInlineCB", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                                     reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    bool found = m_hook_manager->with_inline_hook("VoidInlineCB",
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
    bool found = m_hook_manager->with_inline_hook(
        "NonExistentVoidCB", [&callback_executed]([[maybe_unused]] InlineHook &hook) { callback_executed = true; });

    EXPECT_FALSE(found);
    EXPECT_FALSE(callback_executed);
}

TEST_F(HookManagerTest, WithMidHook_VoidCallback)
{
    auto detour_fn = [](safetyhook::Context &) {};
    auto result =
        m_hook_manager->create_mid_hook("VoidMidCB", reinterpret_cast<uintptr_t>(&real_hook_target_add), detour_fn);
    ASSERT_TRUE(result.has_value());

    bool callback_executed = false;
    bool found = m_hook_manager->with_mid_hook("VoidMidCB",
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
    bool found = m_hook_manager->with_mid_hook(
        "NonExistentVoidMidCB", [&callback_executed]([[maybe_unused]] MidHook &hook) { callback_executed = true; });

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

static safetyhook::VmHook *s_compute_vm_hook = nullptr;

class VmtTestHook : public VmtTestTarget
{
public:
    int hooked_compute(int a, int b) { return s_compute_vm_hook->thiscall<int>(this, a, b) + 1000; }
};

TEST_F(HookManagerTest, VmtHook_CreateSuccess)
{
    auto target = std::make_unique<VmtTestTarget>();

    auto result = m_hook_manager->create_vmt_hook("TestVmt", target.get());
    ASSERT_TRUE(result.has_value()) << "VMT hook creation should succeed";
    EXPECT_EQ(*result, "TestVmt");

    auto names = m_hook_manager->get_vmt_hook_names();
    EXPECT_EQ(names.size(), 1u);
    EXPECT_EQ(names[0], "TestVmt");

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_CreateNullObject)
{
    auto result = m_hook_manager->create_vmt_hook("NullVmt", nullptr);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidObject);
}

TEST_F(HookManagerTest, VmtHook_CreateDuplicate)
{
    auto target = std::make_unique<VmtTestTarget>();

    auto r1 = m_hook_manager->create_vmt_hook("DupVmt", target.get());
    ASSERT_TRUE(r1.has_value());

    auto r2 = m_hook_manager->create_vmt_hook("DupVmt", target.get());
    ASSERT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), HookError::HookAlreadyExists);

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_HookMethod)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(target->compute(3, 4), 7);

    auto vmt_result = m_hook_manager->create_vmt_hook("MethodVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto method_result = m_hook_manager->hook_vmt_method("MethodVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(method_result.has_value()) << "Method hook should succeed";
    EXPECT_EQ(*method_result, VMT_COMPUTE_INDEX);

    ASSERT_TRUE(m_hook_manager->with_vmt_method("MethodVmt", VMT_COMPUTE_INDEX,
                                                [](safetyhook::VmHook &hook) { s_compute_vm_hook = &hook; }));

    EXPECT_EQ(target->compute(3, 4), 1007);

    s_compute_vm_hook = nullptr;
    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_HookMethodDuplicate)
{
    auto target = std::make_unique<VmtTestTarget>();

    auto vmt_result = m_hook_manager->create_vmt_hook("DupMethodVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto r1 = m_hook_manager->hook_vmt_method("DupMethodVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(r1.has_value());

    auto r2 = m_hook_manager->hook_vmt_method("DupMethodVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), HookError::MethodAlreadyHooked);

    s_compute_vm_hook = nullptr;
    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_HookMethodNotFound)
{
    auto result = m_hook_manager->hook_vmt_method("NonExistentVmt", 0, &VmtTestHook::hooked_compute);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::VmtHookNotFound);
}

TEST_F(HookManagerTest, VmtHook_RemoveMethod)
{
    auto target = std::make_unique<VmtTestTarget>();

    auto vmt_result = m_hook_manager->create_vmt_hook("RemMethodVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto method_result =
        m_hook_manager->hook_vmt_method("RemMethodVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(method_result.has_value());

    ASSERT_TRUE(m_hook_manager->with_vmt_method("RemMethodVmt", VMT_COMPUTE_INDEX,
                                                [](safetyhook::VmHook &hook) { s_compute_vm_hook = &hook; }));

    EXPECT_EQ(target->compute(5, 5), 1010);

    s_compute_vm_hook = nullptr;
    EXPECT_TRUE(m_hook_manager->remove_vmt_method("RemMethodVmt", VMT_COMPUTE_INDEX).has_value());

    EXPECT_EQ(target->compute(5, 5), 10);

    auto re_remove = m_hook_manager->remove_vmt_method("RemMethodVmt", VMT_COMPUTE_INDEX);
    ASSERT_FALSE(re_remove.has_value());
    EXPECT_EQ(re_remove.error(), HookError::MethodNotFound);

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_RemoveEntireHook)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(target->compute(1, 2), 3);

    auto vmt_result = m_hook_manager->create_vmt_hook("RemVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto method_result = m_hook_manager->hook_vmt_method("RemVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(method_result.has_value());

    ASSERT_TRUE(m_hook_manager->with_vmt_method("RemVmt", VMT_COMPUTE_INDEX,
                                                [](safetyhook::VmHook &hook) { s_compute_vm_hook = &hook; }));

    EXPECT_EQ(target->compute(1, 2), 1003);

    s_compute_vm_hook = nullptr;
    EXPECT_TRUE(m_hook_manager->remove_vmt_hook("RemVmt").has_value());

    EXPECT_EQ(target->compute(1, 2), 3);
    EXPECT_TRUE(m_hook_manager->get_vmt_hook_names().empty());
}

TEST_F(HookManagerTest, VmtHook_RemoveNotFound)
{
    auto result = m_hook_manager->remove_vmt_hook("NonExistent");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::VmtHookNotFound);
}

TEST_F(HookManagerTest, VmtHook_ApplyToMultipleObjects)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();

    auto vmt_result = m_hook_manager->create_vmt_hook("MultiVmt", target1.get());
    ASSERT_TRUE(vmt_result.has_value());

    auto method_result = m_hook_manager->hook_vmt_method("MultiVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
    ASSERT_TRUE(method_result.has_value());

    ASSERT_TRUE(m_hook_manager->with_vmt_method("MultiVmt", VMT_COMPUTE_INDEX,
                                                [](safetyhook::VmHook &hook) { s_compute_vm_hook = &hook; }));

    EXPECT_EQ(target1->compute(1, 1), 1002);
    EXPECT_EQ(target2->compute(1, 1), 2);

    EXPECT_TRUE(m_hook_manager->apply_vmt_hook("MultiVmt", target2.get()));
    EXPECT_EQ(target2->compute(1, 1), 1002);

    EXPECT_TRUE(m_hook_manager->remove_vmt_from_object("MultiVmt", target2.get()));
    EXPECT_EQ(target2->compute(1, 1), 2);
    EXPECT_EQ(target1->compute(1, 1), 1002);

    s_compute_vm_hook = nullptr;
    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_RemoveAllVmt)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("Vmt1", target1.get()).has_value());
    ASSERT_TRUE(m_hook_manager->create_vmt_hook("Vmt2", target2.get()).has_value());

    EXPECT_EQ(m_hook_manager->get_vmt_hook_names().size(), 2u);

    m_hook_manager->remove_all_vmt_hooks();
    EXPECT_TRUE(m_hook_manager->get_vmt_hook_names().empty());
}

// VmtHookConfig::fail_if_already_hooked is a soft guard: when set, a second create on the same vtable chain
// (i.e. a vptr already pointing at a clone owned by this HookManager) returns HookError::HookAlreadyExists rather
// than silently layering a second clone on top of the first. The default false preserves the legacy always-succeed
// path, so a regular create_vmt_hook(name, object) call without a config still layers.
TEST_F(HookManagerTest, VmtHookConfig_DefaultMatchesLegacyBehavior)
{
    auto target1 = std::make_unique<VmtTestTarget>();

    VmtHookConfig cfg;
    EXPECT_FALSE(cfg.fail_if_already_hooked);
    EXPECT_FALSE(cfg.fail_on_non_function_pointer);

    // First clone succeeds with the default config.
    ASSERT_TRUE(m_hook_manager->create_vmt_hook("CfgDefaultA", target1.get(), cfg).has_value());

    // Re-cloning the same vtable again with a different name layers (legacy behavior), no fail-if-already.
    auto r2 = m_hook_manager->create_vmt_hook("CfgDefaultB", target1.get(), cfg);
    ASSERT_TRUE(r2.has_value());
    // The clones are layered on the same object, so they must be removed in reverse creation order: each removal's
    // conditional restore then writes a vptr that is still alive. An unordered teardown can restore a freed clone
    // into the object's vptr.
    EXPECT_TRUE(m_hook_manager->remove_vmt_hook("CfgDefaultB").has_value());
    EXPECT_TRUE(m_hook_manager->remove_vmt_hook("CfgDefaultA").has_value());
}

TEST_F(HookManagerTest, VmtHookConfig_FailIfAlreadyHookedRefusesDoubleCreate)
{
    auto target = std::make_unique<VmtTestTarget>();

    VmtHookConfig cfg;
    cfg.fail_if_already_hooked = true;

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("FirstVmt", target.get(), cfg).has_value());

    // The vptr is now on the first clone. A second create with fail_if_already_hooked must refuse.
    auto r2 = m_hook_manager->create_vmt_hook("SecondVmt", target.get(), cfg);
    ASSERT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), HookError::HookAlreadyExists);

    // The refused create did not add a second VMT hook; only the first one is in the registry.
    EXPECT_EQ(m_hook_manager->get_vmt_hook_names().size(), 1u);
    EXPECT_EQ(m_hook_manager->get_vmt_hook_names()[0], "FirstVmt");

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHookConfig_ApplyWithFailIfAlreadyHookedIsNoOp)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("ReapplyVmt", target1.get()).has_value());

    // First apply succeeds (target2 was not on the clone).
    VmtHookConfig cfg;
    cfg.fail_if_already_hooked = true;
    EXPECT_TRUE(m_hook_manager->apply_vmt_hook("ReapplyVmt", target2.get(), cfg));

    // Second apply to the same target2 with the same config is a no-op (target2 is now on the clone) -- the apply
    // is still reported as a success because the desired post-state holds; a warning is logged at Debug.
    EXPECT_TRUE(m_hook_manager->apply_vmt_hook("ReapplyVmt", target2.get(), cfg));

    m_hook_manager->remove_all_vmt_hooks();
}

// VMT slot pre-flight refuses to clone an object whose vtable's first slot is an int3 padding/breakpoint byte.
// The pre-flight is opt-in (default false). A real int3 is the canonical bad case: dispatching through the cloned
// vtable would call __debugbreak and crash in shipping. The MinGW compiler is free to emit a standard function
// prologue (push rbp) ahead of an __debugbreak intrinsic, so the test cannot rely on a function symbol starting
// with 0xCC. Instead the test plants an int3 byte at a known address in a static buffer and points the vtable slot
// at that buffer.
namespace
{
    // Aligned to a 16-byte boundary so the byte at offset 0 is the absolute function-pointer target the pre-flight
    // decoder reads. The page the buffer lives in is committed and readable, so the SEH-guarded read in
    // looks_like_function_vmt_slot succeeds and returns 0xCC.
    alignas(16) const std::uint8_t INT3_SLOT_BYTES[] = {0xCC, 0xCC, 0xC3, 0x90};
    alignas(16) const std::uint8_t RET_SLOT_BYTES[] = {0xC3, 0x90, 0x90, 0x90};

    // First byte E9 (jmp rel32) with a displacement that lands a few bytes ahead inside this same buffer. The buffer
    // lives in the test image's static storage, so the slot address and the resolved jump target map to the same
    // HMODULE and the pre-flight decoder classifies the slot as a same-module jump stub.
    alignas(16) const std::uint8_t JMP_STUB_SLOT_BYTES[] = {0xE9, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90,
                                                            0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

    // First byte 0x48 (REX.W prefix opening a standard x64 prologue, here sub rsp, 0x28): the decoder must classify
    // the slot as a function body. A static buffer keeps the byte deterministic across toolchains and linker modes;
    // a real method symbol can resolve to an incremental-link jump thunk whose first byte is E9, which the decoder
    // deliberately refuses as a same-module jump stub.
    alignas(16) const std::uint8_t PROLOGUE_SLOT_BYTES[] = {0x48, 0x83, 0xEC, 0x28, 0xC3, 0x90, 0x90, 0x90};
} // namespace

TEST_F(HookManagerTest, VmtHookConfig_PreFlightRefusesInt3FirstSlot)
{
    struct Int3VTable
    {
        void *methods[2];
    };
    Int3VTable vtable{};
    vtable.methods[0] = const_cast<void *>(static_cast<const void *>(INT3_SLOT_BYTES));
    vtable.methods[1] = const_cast<void *>(static_cast<const void *>(RET_SLOT_BYTES));
    void *vptr = &vtable;

    VmtHookConfig cfg;
    cfg.fail_on_non_function_pointer = true;
    auto result = m_hook_manager->create_vmt_hook("Int3Vmt", &vptr, cfg);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidObject);

    // The refused create did not touch the vptr: it still points at our local vtable.
    EXPECT_EQ(vptr, static_cast<void *>(&vtable));
    EXPECT_TRUE(m_hook_manager->get_vmt_hook_names().empty());
}

TEST_F(HookManagerTest, VmtHookConfig_PreFlightAcceptsFunctionPrologue)
{
    // Slot 0 carries a normal x64 prologue first byte (0x48), so pre-flight on create_vmt_hook with
    // fail_on_non_function_pointer=true must accept the vtable and the create must succeed end to end. The rtti
    // member sits at vptr[-1]: SafetyHook's clone copies the RTTI slot ahead of the vtable, so the vptr must point
    // past an in-bounds leading member.
    struct PrologueVTable
    {
        void *rtti;
        void *methods[2];
    };
    PrologueVTable vtable{};
    vtable.methods[0] = const_cast<void *>(static_cast<const void *>(PROLOGUE_SLOT_BYTES));
    void *vptr = &vtable.methods[0];

    VmtHookConfig cfg;
    cfg.fail_on_non_function_pointer = true;
    auto result = m_hook_manager->create_vmt_hook("PrologueVmt", &vptr, cfg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "PrologueVmt");

    // The accepted create swapped the vptr onto the clone; removal restores the original vtable pointer.
    m_hook_manager->remove_all_vmt_hooks();
    EXPECT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));
}

TEST_F(HookManagerTest, VmtHookConfig_PreFlightOffByDefault)
{
    // The default config (fail_on_non_function_pointer = false) does not run the pre-flight, so a synthetic vtable
    // with a null first slot still creates successfully. This pins the backward-compat guarantee that the new
    // check is opt-in, not on-by-default. The rtti member sits at vptr[-1]: SafetyHook's clone copies the RTTI slot
    // ahead of the vtable, so the vptr must point past an in-bounds leading member.
    struct NullVTable
    {
        void *rtti;
        void *methods[2];
    };
    NullVTable vtable{};
    void *vptr = &vtable.methods[0];

    auto result = m_hook_manager->create_vmt_hook("NullSlotVmt", &vptr);
    ASSERT_TRUE(result.has_value());

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHookConfig_PreFlightRefusesSameModuleJumpStub)
{
    // The synthetic first slot starts with E9 (jmp rel32) whose target lands inside the same static buffer, so the
    // slot and the jump target resolve to the same module: the decoder must classify it as a jump stub and refuse.
    struct StubVTable
    {
        void *methods[2];
    };
    StubVTable vtable{};
    vtable.methods[0] = const_cast<void *>(static_cast<const void *>(JMP_STUB_SLOT_BYTES));
    vtable.methods[1] = const_cast<void *>(static_cast<const void *>(RET_SLOT_BYTES));
    void *vptr = &vtable;

    VmtHookConfig cfg;
    cfg.fail_on_non_function_pointer = true;
    auto result = m_hook_manager->create_vmt_hook("JmpStubVmt", &vptr, cfg);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), HookError::InvalidObject);

    // The refused create did not touch the vptr: it still points at our local vtable.
    EXPECT_EQ(vptr, static_cast<void *>(&vtable));
    EXPECT_TRUE(m_hook_manager->get_vmt_hook_names().empty());
}

TEST_F(HookManagerTest, VmtHookConfig_ApplyPreFlightRefusesInt3FirstSlot)
{
    // The apply path runs the same slot-0 pre-flight as create: applying an existing hook to an object whose current
    // vtable starts with an int3 slot must be refused, not installed.
    auto target = std::make_unique<VmtTestTarget>();
    ASSERT_TRUE(m_hook_manager->create_vmt_hook("ApplyPreFlightVmt", target.get()).has_value());

    struct Int3VTable
    {
        void *methods[2];
    };
    Int3VTable vtable{};
    vtable.methods[0] = const_cast<void *>(static_cast<const void *>(INT3_SLOT_BYTES));
    vtable.methods[1] = const_cast<void *>(static_cast<const void *>(RET_SLOT_BYTES));
    void *vptr = &vtable;

    VmtHookConfig cfg;
    cfg.fail_on_non_function_pointer = true;
    EXPECT_FALSE(m_hook_manager->apply_vmt_hook("ApplyPreFlightVmt", &vptr, cfg));

    // The refused apply did not touch the vptr: it still points at our local vtable.
    EXPECT_EQ(vptr, static_cast<void *>(&vtable));

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHookConfig_ApplyRefusesObjectOnAnotherHooksClone)
{
    // The re-apply guard is registry-wide: an object already on a clone owned by a *different* hook of this manager
    // must be refused, not silently layered onto.
    auto target_a = std::make_unique<VmtTestTarget>();
    auto target_b = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("CloneOwnerA", target_a.get()).has_value());
    ASSERT_TRUE(m_hook_manager->create_vmt_hook("CloneOwnerB", target_b.get()).has_value());

    VmtHookConfig cfg;
    cfg.fail_if_already_hooked = true;
    EXPECT_FALSE(m_hook_manager->apply_vmt_hook("CloneOwnerA", target_b.get(), cfg));

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_RemoveAllHooksClearsVmt)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("VmtCleared", target.get()).has_value());
    EXPECT_EQ(m_hook_manager->get_vmt_hook_names().size(), 1u);

    m_hook_manager->remove_all_hooks();
    EXPECT_TRUE(m_hook_manager->get_vmt_hook_names().empty());
}

TEST_F(HookManagerTest, VmtHook_ShutdownClearsVmt)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("VmtShutdown", target.get()).has_value());

    m_hook_manager->shutdown();
    EXPECT_TRUE(m_hook_manager->get_vmt_hook_names().empty());

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("VmtPostShutdown", target.get()).has_value());

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_WithVmtMethod_ValueCallback)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("CbVmt", target.get()).has_value());
    ASSERT_TRUE(m_hook_manager->hook_vmt_method("CbVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute).has_value());

    auto result = m_hook_manager->with_vmt_method("CbVmt", VMT_COMPUTE_INDEX, [](safetyhook::VmHook &hook) -> bool
                                                  { return hook.original<void *>() != nullptr; });

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);

    s_compute_vm_hook = nullptr;
    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_WithVmtMethod_NotFound)
{
    auto result =
        m_hook_manager->with_vmt_method("NonExistentVmt", 0, [](safetyhook::VmHook &) -> bool { return true; });

    EXPECT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, VmtHook_WithVmtMethod_MethodNotFound)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("NoMethodVmt", target.get()).has_value());

    auto result = m_hook_manager->with_vmt_method("NoMethodVmt", 99, [](safetyhook::VmHook &) -> bool { return true; });

    EXPECT_FALSE(result.has_value());

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_WithVmtMethod_VoidCallback)
{
    auto target = std::make_unique<VmtTestTarget>();

    ASSERT_TRUE(m_hook_manager->create_vmt_hook("VoidCbVmt", target.get()).has_value());
    ASSERT_TRUE(
        m_hook_manager->hook_vmt_method("VoidCbVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute).has_value());

    bool callback_executed = false;
    bool found = m_hook_manager->with_vmt_method(
        "VoidCbVmt", VMT_COMPUTE_INDEX, [&callback_executed](safetyhook::VmHook &) { callback_executed = true; });

    EXPECT_TRUE(found);
    EXPECT_TRUE(callback_executed);

    s_compute_vm_hook = nullptr;
    m_hook_manager->remove_all_vmt_hooks();
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
    ASSERT_TRUE(m_hook_manager->create_vmt_hook("ApplyNullVmt", target.get()).has_value());

    EXPECT_FALSE(m_hook_manager->apply_vmt_hook("ApplyNullVmt", nullptr));

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_RemoveFromNullObject)
{
    auto target = std::make_unique<VmtTestTarget>();
    ASSERT_TRUE(m_hook_manager->create_vmt_hook("RemNullVmt", target.get()).has_value());

    EXPECT_FALSE(m_hook_manager->remove_vmt_from_object("RemNullVmt", nullptr));

    m_hook_manager->remove_all_vmt_hooks();
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
    m_hook_manager->shutdown();

    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("AfterShutdownHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "AfterShutdownHook");
    EXPECT_NE(tramp, nullptr);
}

TEST_F(HookManagerTest, ErrorToString_ShutdownAndAllocatorErrors)
{
    // These error codes are emitted during shutdown sequences when the allocator is torn down. Verify the string
    // representations are stable.
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
    auto result = m_hook_manager->create_inline_hook_aob("AobNullBase", 0, 0x1000, "48 8B 05", 0,
                                                         reinterpret_cast<void *>(&real_hook_detour_add), &tramp);

    ASSERT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, CreateMidHookAob_NullStartAddress)
{
    auto result =
        m_hook_manager->create_mid_hook_aob("MidAobNullBase", 0, 0x1000, "48 8B 05", 0, [](safetyhook::Context &) {});

    ASSERT_FALSE(result.has_value());
}

TEST_F(HookManagerTest, GetHookCounts_AfterCreation)
{
    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("CountTestHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    auto counts = m_hook_manager->get_hook_counts();
    EXPECT_GE(counts[HookStatus::Active], 1u);
}

TEST_F(HookManagerTest, VmtHook_CreateAfterShutdownSucceeds)
{
    // shutdown() resets the shutdown flag for hot-reload, so subsequent create calls succeed against a clean
    // HookManager.
    auto target = std::make_unique<VmtTestTarget>();

    m_hook_manager->shutdown();

    auto result = m_hook_manager->create_vmt_hook("VmtAfterShutdown", target.get());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "VmtAfterShutdown");

    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, VmtHook_MethodHookAfterShutdownNotFound)
{
    // shutdown() clears all VMT hooks, so hook_vmt_method returns VmtHookNotFound.
    auto target = std::make_unique<VmtTestTarget>();

    auto vmt_result = m_hook_manager->create_vmt_hook("MethodShutdownVmt", target.get());
    ASSERT_TRUE(vmt_result.has_value());

    m_hook_manager->shutdown();

    auto method_result =
        m_hook_manager->hook_vmt_method("MethodShutdownVmt", VMT_COMPUTE_INDEX, &VmtTestHook::hooked_compute);
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
        threads.emplace_back(
            [&, i]
            {
                start_latch.arrive_and_wait();
                auto result = m_hook_manager->create_vmt_hook(std::format("ConcVmt{}", i), targets[i].get());
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
    m_hook_manager->shutdown();

    for (auto &t : threads)
        t.join();

    EXPECT_EQ(success_count.load() + rejected_count.load(), kThreads);

    for (const auto &err : errors)
    {
        EXPECT_EQ(err, HookError::ShutdownInProgress);
    }

    // Clean up any VMT hooks that were created before shutdown took effect. shutdown() resets the flag, so surviving
    // hooks must be removed before the test-local targets are destroyed.
    m_hook_manager->remove_all_vmt_hooks();
}

TEST_F(HookManagerTest, ApplyVmtHook_NotFoundName_ReturnsFalse)
{
    int dummy_object = 0;
    EXPECT_FALSE(m_hook_manager->apply_vmt_hook("NonExistentVmt", &dummy_object));
}

TEST_F(HookManagerTest, RemoveVmtFromObject_NotFoundName_ReturnsFalse)
{
    int dummy_object = 0;
    EXPECT_FALSE(m_hook_manager->remove_vmt_from_object("NonExistentVmt", &dummy_object));
}

TEST_F(HookManagerTest, RemoveAllVmtHooks_WhenEmpty_NoOp)
{
    EXPECT_NO_THROW(m_hook_manager->remove_all_vmt_hooks());
    EXPECT_TRUE(m_hook_manager->get_vmt_hook_names().empty());
}

TEST_F(HookManagerTest, GetHookIds_FilterByActive_ReturnsMatching)
{
    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("ActiveFilterHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    auto active_ids = m_hook_manager->get_hook_ids(HookStatus::Active);
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
    auto result =
        m_hook_manager->create_inline_hook("DisableFilterHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(m_hook_manager->disable_hook("DisableFilterHook").has_value());

    auto disabled_ids = m_hook_manager->get_hook_ids(HookStatus::Disabled);
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
    auto result =
        m_hook_manager->create_inline_hook("ShutEnableHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    m_hook_manager->shutdown();

    auto enable_result = m_hook_manager->enable_hook("ShutEnableHook");
    ASSERT_FALSE(enable_result.has_value());
    EXPECT_EQ(enable_result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, ShutdownThenDisable_ReturnsNotFound)
{
    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("ShutDisableHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    m_hook_manager->shutdown();

    auto disable_result = m_hook_manager->disable_hook("ShutDisableHook");
    ASSERT_FALSE(disable_result.has_value());
    EXPECT_EQ(disable_result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, ShutdownThenRemove_ReturnsNotFound)
{
    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("ShutRemoveHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    m_hook_manager->shutdown();

    auto remove_result = m_hook_manager->remove_hook("ShutRemoveHook");
    ASSERT_FALSE(remove_result.has_value());
    EXPECT_EQ(remove_result.error(), HookError::HookNotFound);
}

TEST_F(HookManagerTest, ShutdownThenGetStatus_ReturnsNullopt)
{
    void *tramp = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("ShutStatusHook", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &tramp);
    ASSERT_TRUE(result.has_value());

    m_hook_manager->shutdown();

    auto status = m_hook_manager->get_hook_status("ShutStatusHook");
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

    auto vmt_result = m_hook_manager->create_vmt_hook("VmtOnlyHook", &vptr);
    ASSERT_TRUE(vmt_result.has_value());
    EXPECT_FALSE(m_hook_manager->get_vmt_hook_names().empty());

    m_hook_manager->remove_all_hooks();

    EXPECT_TRUE(m_hook_manager->get_vmt_hook_names().empty());
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
    DMK_TEST_NOINLINE void duplicate_hook_target_function() noexcept
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
    auto &hm = *m_hook_manager;
    const auto target = reinterpret_cast<std::uintptr_t>(&duplicate_hook_target_function);

    void *trampoline_a = nullptr;
    auto first =
        hm.create_inline_hook("dup-first", target, reinterpret_cast<void *>(&duplicate_hook_detour_a), &trampoline_a);
    ASSERT_TRUE(first.has_value()) << "initial inline hook should succeed";

    HookConfig strict;
    strict.fail_if_already_hooked = true;

    void *trampoline_b = nullptr;
    auto second = hm.create_inline_hook("dup-second", target, reinterpret_cast<void *>(&duplicate_hook_detour_b),
                                        &trampoline_b, strict);

    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error(), HookError::TargetAlreadyHookedInProcess);
    EXPECT_EQ(trampoline_b, nullptr);

    (void)hm.remove_hook("dup-first");
}

TEST_F(HookManagerTest, DuplicateHook_DefaultMode_LayersOnTop)
{
    auto &hm = *m_hook_manager;
    const auto target = reinterpret_cast<std::uintptr_t>(&duplicate_hook_target_function);

    void *trampoline_a = nullptr;
    auto first = hm.create_inline_hook("dup-layer-first", target, reinterpret_cast<void *>(&duplicate_hook_detour_a),
                                       &trampoline_a);
    ASSERT_TRUE(first.has_value());

    void *trampoline_b = nullptr;
    auto second = hm.create_inline_hook("dup-layer-second", target, reinterpret_cast<void *>(&duplicate_hook_detour_b),
                                        &trampoline_b);

    EXPECT_TRUE(second.has_value());

    (void)hm.remove_hook("dup-layer-second");
    (void)hm.remove_hook("dup-layer-first");
}

namespace
{
    DMK_TEST_NOINLINE void late_destruction_target_function() noexcept
    {
        volatile int x = 0;
        x = x + 1;
        (void)x;
    }

    void late_destruction_detour() noexcept {}
} // namespace

// Covers the destructor fallback path: a late shutdown() must serialize against readers holding shared_lock via
// with_inline_hook() so their callbacks never observe the maps being cleared under them. The destructor only fires at
// static-destruction time, so the contract we can verify in a unit test is the equivalent serialization provided by
// shutdown(): a reader callback finishes cleanly, and a subsequent
// shutdown() does not deadlock or crash.
TEST_F(HookManagerTest, LateShutdown_DrainsReadersBeforeClearingMaps)
{
    auto &hm = *m_hook_manager;
    const auto target = reinterpret_cast<std::uintptr_t>(&late_destruction_target_function);

    void *trampoline = nullptr;
    auto created = hm.create_inline_hook("late-shutdown-hook", target,
                                         reinterpret_cast<void *>(&late_destruction_detour), &trampoline);
    ASSERT_TRUE(created.has_value());

    std::atomic<bool> reader_started{false};
    std::atomic<bool> reader_may_return{false};
    std::atomic<bool> reader_observed_valid{false};

    std::thread reader(
        [&]()
        {
            bool invoked = hm.with_inline_hook("late-shutdown-hook",
                                               [&](InlineHook &hook)
                                               {
                                                   reader_started.store(true, std::memory_order_release);
                                                   // Hold the shared_lock while the main thread races shutdown().
                                                   while (!reader_may_return.load(std::memory_order_acquire))
                                                   {
                                                       std::this_thread::yield();
                                                   }
                                                   // Dereference the hook while still holding the shared_lock. If the
                                                   // destructor cleared the maps out from under us the name would be
                                                   // dangling; any UAF surfaces here under ASan.
                                                   reader_observed_valid.store(!hook.get_name().empty(),
                                                                               std::memory_order_release);
                                               });
            EXPECT_TRUE(invoked);
        });

    while (!reader_started.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }

    // Spawn the shutdown racer. shutdown() must block on m_mutator_gate until the reader releases the shared_lock,
    // which proves the destructor-equivalent ordering.
    std::atomic<bool> killer_started{false};
    std::atomic<bool> shutdown_returned{false};
    std::thread killer(
        [&]()
        {
            // Publish entry into hm.shutdown() before the call so the main thread can wait on this flag instead of an
            // unconditional sleep. Without this, shutdown_returned == false could mean "blocked on the mutator gate as
            // intended" or "killer not scheduled yet", letting a premature-return regression slip through.
            killer_started.store(true, std::memory_order_release);
            hm.shutdown();
            shutdown_returned.store(true, std::memory_order_release);
        });

    // Wait until the killer has actually entered hm.shutdown() before we assert it is blocked. After that, a short
    // sleep lets the m_mutator_gate acquisition attempt settle so we can observe the blocked state. The final assertion
    // proves shutdown is held off while the reader still holds the shared_lock.
    while (!killer_started.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(shutdown_returned.load(std::memory_order_acquire));
    reader_may_return.store(true, std::memory_order_release);

    reader.join();
    killer.join();

    EXPECT_TRUE(reader_observed_valid.load());
    EXPECT_TRUE(shutdown_returned.load());
}

TEST_F(HookManagerTest, IsTargetAlreadyHooked_TrueAfterInstall)
{
    void *trampoline = nullptr;
    auto result =
        m_hook_manager->create_inline_hook("TargetHookedQuery", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                           reinterpret_cast<void *>(&real_hook_detour_add), &trampoline);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(m_hook_manager->is_target_already_hooked(reinterpret_cast<uintptr_t>(&real_hook_target_add)));
    EXPECT_FALSE(m_hook_manager->is_target_already_hooked(reinterpret_cast<uintptr_t>(&real_hook_target_mul)));
}

TEST_F(HookManagerTest, IsTargetAlreadyHooked_FalseForZero)
{
    EXPECT_FALSE(m_hook_manager->is_target_already_hooked(0));
}

TEST_F(HookManagerTest, TryInstallInline_ReturnsNameOnSuccess)
{
    void *trampoline = nullptr;
    auto name = try_install_inline("TryInstallSuccess", reinterpret_cast<uintptr_t>(&real_hook_target_add),
                                   reinterpret_cast<void *>(&real_hook_detour_add), &trampoline);

    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(*name, "TryInstallSuccess");
    EXPECT_NE(trampoline, nullptr);
}

TEST_F(HookManagerTest, TryInstallInline_NulloptOnInvalidTarget)
{
    // Seed with a non-null sentinel so a regression that erroneously writes through *trampoline on the failure path is
    // caught. A buggy try_install_inline that copied a stale trampoline value into the output on failure would change
    // this byte pattern; the assertion below pins the failure-path contract that no write occurs.
    void *const sentinel = reinterpret_cast<void *>(static_cast<uintptr_t>(0xDEADBEEFu));
    void *trampoline = sentinel;
    auto name = try_install_inline("TryInstallFail", 0, reinterpret_cast<void *>(&real_hook_detour_add), &trampoline);

    EXPECT_FALSE(name.has_value());
    // The early validation branches in create_inline_hook (target_address == 0 here) return before the explicit
    // *original_trampoline = nullptr write, so the sentinel must be observed unchanged on this failure path.
    EXPECT_EQ(trampoline, sentinel) << "Failure path must not write through original_trampoline";
}

namespace
{
    // Routes a single test's log lines through a dedicated file so the failing try_install_* path can be counted
    // without interference from background tests. Restores the previous configuration on destruction so subsequent
    // suites keep their own log target.
    class ScopedTestLogFile
    {
    public:
        ScopedTestLogFile()
        {
            static std::atomic<int> counter{0};
            const int n = counter.fetch_add(1, std::memory_order_relaxed);
            m_path =
                std::filesystem::temp_directory_path() /
                ("dmk_try_install_log_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(n) + ".log");
            // Force synchronous mode so the deferred Error lines from the
            // HookManager deferred_logs flush land in the file before the count step below; async mode is opt-in and
            // the flush ordering varies test-to-test depending on the writer thread state.
            Logger::get_instance().disable_async_mode();
            Logger::configure("TRY_INSTALL_TEST", m_path.string(), "%Y-%m-%d %H:%M:%S");
            Logger::get_instance().set_log_level(LogLevel::Error);
            Logger::get_instance().flush();
        }

        ~ScopedTestLogFile()
        {
            Logger::get_instance().flush();
            const auto temp = std::filesystem::temp_directory_path() / "dmk_try_install_log_restore.log";
            Logger::configure("TEMP", temp.string(), "%Y-%m-%d %H:%M:%S");
            Logger::get_instance().set_log_level(LogLevel::Info);
            try
            {
                if (std::filesystem::exists(m_path))
                {
                    std::filesystem::remove(m_path);
                }
                if (std::filesystem::exists(temp))
                {
                    std::filesystem::remove(temp);
                }
            }
            catch (const std::filesystem::filesystem_error &)
            {
            }
        }

        size_t count_error_lines() const
        {
            Logger::get_instance().flush();
            std::ifstream in(m_path);
            size_t n = 0;
            for (std::string line; std::getline(in, line);)
            {
                // Logger formats the level inside a left-padded 7-char field
                // ("[ERROR  ] :: ..."), so match the padded token rather than
                // a bare "[ERROR]" that never appears on disk.
                if (line.find("[ERROR  ]") != std::string::npos)
                {
                    ++n;
                }
            }
            return n;
        }

    private:
        std::filesystem::path m_path;
    };
} // namespace

// The try_install_* helpers must not double-log: every failure code is logged exactly once by the underlying
// create_*_hook path.
TEST_F(HookManagerTest, TryInstallInline_LogsOnceOnFailure)
{
    ScopedTestLogFile logfile;
    void *trampoline = nullptr;
    auto name =
        try_install_inline("TryInstallInline_LogOnce", 0, reinterpret_cast<void *>(&real_hook_detour_add), &trampoline);
    EXPECT_FALSE(name.has_value());
    EXPECT_EQ(logfile.count_error_lines(), static_cast<size_t>(1));
}

TEST_F(HookManagerTest, TryInstallMid_LogsOnceOnFailure)
{
    ScopedTestLogFile logfile;
    auto name = try_install_mid("TryInstallMid_LogOnce", 0, +[](safetyhook::Context &) {});
    EXPECT_FALSE(name.has_value());
    EXPECT_EQ(logfile.count_error_lines(), static_cast<size_t>(1));
}

// The AOB try_install_* variants must not multi-log when the pattern resolves and the underlying create_*_hook then
// fails: every failure code is logged exactly once. The pattern-not-found path emits exactly one log line; the
// pattern-resolved-then-create-fails path is covered by the direct-address try_install_* tests above.
TEST_F(HookManagerTest, TryInstallInlineAob_LogsOnceOnPatternFailure)
{
    ScopedTestLogFile logfile;
    void *trampoline = nullptr;
    auto name =
        try_install_inline_aob("TryInstallInlineAob_LogOnce", reinterpret_cast<uintptr_t>(&real_hook_target_add), 16,
                               "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF", 0,
                               reinterpret_cast<void *>(&real_hook_detour_add), &trampoline);
    EXPECT_FALSE(name.has_value());
    EXPECT_EQ(logfile.count_error_lines(), static_cast<size_t>(1));
}

TEST_F(HookManagerTest, TryInstallMidAob_LogsOnceOnPatternFailure)
{
    ScopedTestLogFile logfile;
    auto name = try_install_mid_aob(
        "TryInstallMidAob_LogOnce", reinterpret_cast<uintptr_t>(&real_hook_target_add), 16,
        "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF", 0, +[](safetyhook::Context &) {});
    EXPECT_FALSE(name.has_value());
    EXPECT_EQ(logfile.count_error_lines(), static_cast<size_t>(1));
}
