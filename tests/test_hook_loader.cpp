/**
 * @file test_hook_loader.cpp
 * @brief Implements the T-HOOK-LOADER boundary proof.
 * @details The post-veto mask and allocation counts distinguish all ten
 * mutation entries.
 */

#include <gtest/gtest.h>
#include <windows.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"

#include "internal/hook_publication.hpp"

#include "platform.hpp"
#include "fixtures/loader_lock_scope.hpp"
#include "test_alloc_probe.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

namespace
{
    // Real, hookable targets: DMK_TEST_NOINLINE plus a volatile result forces a real call with a patchable prologue.
    DMK_TEST_NOINLINE int loader_reject_target_a(int x)
    {
        volatile int r = x + 3;
        return r;
    }

    DMK_TEST_NOINLINE int loader_reject_target_b(int x)
    {
        volatile int r = x + 7;
        return r;
    }

    int loader_reject_detour(int x)
    {
        return x + 100;
    }

    void loader_reject_mid_detour(MidContext &) {}

    std::uint32_t s_post_loader_veto_entries = 0;

    [[nodiscard]] constexpr std::uint32_t entry_bit(DetourModKit::detail::HookLoaderEntry entry) noexcept
    {
        return 1U << static_cast<std::uint8_t>(entry);
    }

    constexpr std::uint32_t ALL_HOOK_LOADER_ENTRIES =
        (1U << static_cast<std::uint8_t>(DetourModKit::detail::HookLoaderEntry::Count)) - 1U;

    void record_post_loader_veto_entry(DetourModKit::detail::HookLoaderEntry entry) noexcept
    {
        s_post_loader_veto_entries |= entry_bit(entry);
    }

    // Records any mutation entry that passes its loader-lock veto.
    class PostLoaderVetoProbe
    {
    public:
        PostLoaderVetoProbe() noexcept
        {
            s_post_loader_veto_entries = 0;
            DetourModKit::detail::g_hook_post_loader_veto_probe = &record_post_loader_veto_entry;
        }

        ~PostLoaderVetoProbe() noexcept { DetourModKit::detail::g_hook_post_loader_veto_probe = nullptr; }
        PostLoaderVetoProbe(const PostLoaderVetoProbe &) = delete;
        PostLoaderVetoProbe &operator=(const PostLoaderVetoProbe &) = delete;

        [[nodiscard]] std::uint32_t entries() const noexcept { return s_post_loader_veto_entries; }
    };

    class VmtLoaderInterface
    {
    public:
        virtual int value() = 0;

    protected:
        ~VmtLoaderInterface() = default;
    };

    class VmtLoaderTarget final : public VmtLoaderInterface
    {
    public:
        int value() override { return 41; }
    };

    [[nodiscard]] std::uintptr_t vptr_of(const VmtLoaderInterface &object) noexcept
    {
        std::uintptr_t vptr = 0;
        std::memcpy(&vptr, std::addressof(object), sizeof(vptr));
        return vptr;
    }

    DMK_TEST_NOINLINE int call_vmt_value(VmtLoaderInterface &object)
    {
        std::uintptr_t method = 0;
        const std::uintptr_t vptr = vptr_of(object);
        std::memcpy(&method, reinterpret_cast<const void *>(vptr), sizeof(method));
        return reinterpret_cast<int (*)(void *)>(method)(std::addressof(object));
    }

    int vmt_loader_detour(void *)
    {
        return 42;
    }
} // namespace

TEST(HookLoaderLock, InstallVerbsRejectAtEntry)
{
    const Address target{reinterpret_cast<std::uintptr_t>(&loader_reject_target_a)};
    VmtLoaderTarget object;
    const std::uintptr_t object_vptr = vptr_of(object);
    InlineRequest inline_request{.name = "loader_reject_inline", .target = target};
    MidRequest mid_request{.name = "loader_reject_mid", .target = target};
    std::string vmt_name{"loader_reject_vmt"};

    Result<Hook> inline_result = std::unexpected(Error{ErrorCode::Ok, "seed"});
    Result<Hook> mid_result = std::unexpected(Error{ErrorCode::Ok, "seed"});
    Result<VmtHook> vmt_result = std::unexpected(Error{ErrorCode::Ok, "seed"});
    long long inline_allocations_before = 0;
    long long inline_allocations_after = 0;
    long long mid_allocations_before = 0;
    long long mid_allocations_after = 0;
    long long vmt_allocations_before = 0;
    long long vmt_allocations_after = 0;
    PostLoaderVetoProbe boundary_probe;
    {
        const dmk_test::ForcedLoaderProbe probe;
        inline_allocations_before = dmk_test::thread_new_calls();
        inline_result = inline_at(std::move(inline_request), &loader_reject_detour);
        inline_allocations_after = dmk_test::thread_new_calls();
        mid_allocations_before = dmk_test::thread_new_calls();
        mid_result = mid_at(std::move(mid_request), &loader_reject_mid_detour);
        mid_allocations_after = dmk_test::thread_new_calls();
        vmt_allocations_before = dmk_test::thread_new_calls();
        vmt_result = vmt_for(std::move(vmt_name), &object);
        vmt_allocations_after = dmk_test::thread_new_calls();
    }

    ASSERT_FALSE(inline_result.has_value());
    EXPECT_EQ(inline_result.error().code, ErrorCode::LoaderLockActive);
    ASSERT_FALSE(mid_result.has_value());
    EXPECT_EQ(mid_result.error().code, ErrorCode::LoaderLockActive);
    ASSERT_FALSE(vmt_result.has_value());
    EXPECT_EQ(vmt_result.error().code, ErrorCode::LoaderLockActive);
    EXPECT_EQ(boundary_probe.entries(), 0U);
    if (dmk_test::stl_supports_exact_allocation_budgets())
    {
        EXPECT_EQ(inline_allocations_after, inline_allocations_before);
        EXPECT_EQ(mid_allocations_after, mid_allocations_before);
        EXPECT_EQ(vmt_allocations_after, vmt_allocations_before);
    }
    EXPECT_EQ(vptr_of(object), object_vptr);

    // The refusal reaches no ledger seam, so the target has no record.
    EXPECT_FALSE(is_target_hooked(target));
}

TEST(HookLoaderLock, InstallAllRejectsBeforeAnyRow)
{
    // An empty scan request suffices: the refusal precedes every row, so no row is ever resolved.
    const HookSpec table[] = {
        HookSpec::inline_hook("loader_reject_table_row", scan::OwnedScanRequest{}, &loader_reject_detour),
    };

    Result<std::vector<InstallOutcome>> outcomes = std::unexpected(Error{ErrorCode::Ok, "seed"});
    long long allocations_before = 0;
    long long allocations_after = 0;
    PostLoaderVetoProbe boundary_probe;
    {
        const dmk_test::ForcedLoaderProbe probe;
        allocations_before = dmk_test::thread_new_calls();
        outcomes = install_all(table);
        allocations_after = dmk_test::thread_new_calls();
    }
    ASSERT_FALSE(outcomes.has_value());
    EXPECT_EQ(outcomes.error().code, ErrorCode::LoaderLockActive);
    EXPECT_EQ(boundary_probe.entries(), 0U);
    EXPECT_EQ(allocations_after, allocations_before);
}

TEST(HookLoaderLock, EnableAndDisableRejectAtEntry)
{
    const Address target{reinterpret_cast<std::uintptr_t>(&loader_reject_target_b)};
    Result<Hook> installed =
        inline_at(InlineRequest{.name = "loader_reject_toggle", .target = target}, &loader_reject_detour);
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);

    {
        Result<void> enabled;
        long long allocations_before = 0;
        long long allocations_after = 0;
        PostLoaderVetoProbe boundary_probe;
        {
            const dmk_test::ForcedLoaderProbe probe;
            allocations_before = dmk_test::thread_new_calls();
            enabled = hook.enable();
            allocations_after = dmk_test::thread_new_calls();
        }
        ASSERT_FALSE(enabled.has_value());
        EXPECT_EQ(enabled.error().code, ErrorCode::LoaderLockActive);
        EXPECT_EQ(boundary_probe.entries(), 0U);
        EXPECT_EQ(allocations_after, allocations_before);
    }
    EXPECT_FALSE(hook.is_enabled()) << "a refused enable must leave the hook disabled";
    EXPECT_EQ(loader_reject_target_b(1), 8) << "a refused enable must leave the target's bytes unpatched";

    ASSERT_TRUE(hook.enable().has_value());
    ASSERT_EQ(loader_reject_target_b(1), 101);

    {
        Result<void> disabled;
        long long allocations_before = 0;
        long long allocations_after = 0;
        PostLoaderVetoProbe boundary_probe;
        {
            const dmk_test::ForcedLoaderProbe probe;
            allocations_before = dmk_test::thread_new_calls();
            disabled = hook.disable();
            allocations_after = dmk_test::thread_new_calls();
        }
        ASSERT_FALSE(disabled.has_value());
        EXPECT_EQ(disabled.error().code, ErrorCode::LoaderLockActive);
        EXPECT_EQ(boundary_probe.entries(), 0U);
        EXPECT_EQ(allocations_after, allocations_before);
    }
    EXPECT_TRUE(hook.is_enabled()) << "a refused disable must leave the hook armed";
    EXPECT_EQ(loader_reject_target_b(1), 101) << "a refused disable must leave the detour dispatching";

    ASSERT_TRUE(hook.disable().has_value());
    EXPECT_EQ(loader_reject_target_b(1), 8);
}

TEST(HookLoaderLock, VmtOperationsRejectAtEntry)
{
    auto seed = std::make_unique<VmtLoaderTarget>();
    auto peer = std::make_unique<VmtLoaderTarget>();
    const std::uintptr_t original_vptr = vptr_of(*seed);
    ASSERT_EQ(vptr_of(*peer), original_vptr);
    Result<VmtHook> created = vmt_for("loader_reject_vmt_ops", seed.get());
    ASSERT_TRUE(created.has_value()) << created.error().message();
    VmtHook vmt = std::move(*created);
    const std::uintptr_t cloned_vptr = vptr_of(*seed);
    ASSERT_NE(cloned_vptr, original_vptr);
    ASSERT_EQ(call_vmt_value(*seed), 41);
    ASSERT_EQ(call_vmt_value(*peer), 41);

    {
        Result<void> applied;
        Result<void> hooked;
        long long apply_allocations_before = 0;
        long long apply_allocations_after = 0;
        long long hook_allocations_before = 0;
        long long hook_allocations_after = 0;
        std::uintptr_t peer_vptr_after_apply = 0;
        decltype(&vmt_loader_detour) method_after_hook = nullptr;
        int seed_value_after_hook = 0;
        PostLoaderVetoProbe boundary_probe;
        {
            const dmk_test::ForcedLoaderProbe probe;
            apply_allocations_before = dmk_test::thread_new_calls();
            applied = vmt.apply_to(peer.get());
            apply_allocations_after = dmk_test::thread_new_calls();
            peer_vptr_after_apply = vptr_of(*peer);

            hook_allocations_before = dmk_test::thread_new_calls();
            hooked = vmt.hook_method(0, &vmt_loader_detour);
            hook_allocations_after = dmk_test::thread_new_calls();
            method_after_hook = vmt.original<decltype(&vmt_loader_detour)>(0);
            seed_value_after_hook = call_vmt_value(*seed);
        }

        ASSERT_FALSE(applied.has_value());
        EXPECT_EQ(applied.error().code, ErrorCode::LoaderLockActive);
        ASSERT_FALSE(hooked.has_value());
        EXPECT_EQ(hooked.error().code, ErrorCode::LoaderLockActive);
        EXPECT_EQ(boundary_probe.entries(), 0U);
        EXPECT_EQ(apply_allocations_after, apply_allocations_before);
        EXPECT_EQ(hook_allocations_after, hook_allocations_before);
        EXPECT_EQ(peer_vptr_after_apply, original_vptr);
        EXPECT_EQ(method_after_hook, nullptr);
        EXPECT_EQ(seed_value_after_hook, 41);
    }

    EXPECT_EQ(vptr_of(*seed), cloned_vptr);
    EXPECT_EQ(vptr_of(*peer), original_vptr);
    ASSERT_TRUE(vmt.hook_method(0, &vmt_loader_detour).has_value());
    ASSERT_NE(vmt.original<decltype(&vmt_loader_detour)>(0), nullptr);
    ASSERT_EQ(call_vmt_value(*seed), 42);

    {
        Result<void> removed_method;
        Result<void> removed;
        long long remove_method_allocations_before = 0;
        long long remove_method_allocations_after = 0;
        long long remove_allocations_before = 0;
        long long remove_allocations_after = 0;
        decltype(&vmt_loader_detour) method_after_remove = nullptr;
        int seed_value_after_method_remove = 0;
        std::uintptr_t seed_vptr_after_remove = 0;
        int seed_value_after_remove = 0;
        PostLoaderVetoProbe boundary_probe;
        {
            const dmk_test::ForcedLoaderProbe probe;
            remove_method_allocations_before = dmk_test::thread_new_calls();
            removed_method = vmt.remove_method(0);
            remove_method_allocations_after = dmk_test::thread_new_calls();
            method_after_remove = vmt.original<decltype(&vmt_loader_detour)>(0);
            seed_value_after_method_remove = call_vmt_value(*seed);

            remove_allocations_before = dmk_test::thread_new_calls();
            removed = vmt.remove_from(seed.get());
            remove_allocations_after = dmk_test::thread_new_calls();
            seed_vptr_after_remove = vptr_of(*seed);
            seed_value_after_remove = call_vmt_value(*seed);
        }

        ASSERT_FALSE(removed_method.has_value());
        EXPECT_EQ(removed_method.error().code, ErrorCode::LoaderLockActive);
        ASSERT_FALSE(removed.has_value());
        EXPECT_EQ(removed.error().code, ErrorCode::LoaderLockActive);
        EXPECT_EQ(boundary_probe.entries(), 0U);
        EXPECT_EQ(remove_method_allocations_after, remove_method_allocations_before);
        EXPECT_EQ(remove_allocations_after, remove_allocations_before);
        EXPECT_NE(method_after_remove, nullptr);
        EXPECT_EQ(seed_value_after_method_remove, 42);
        EXPECT_EQ(seed_vptr_after_remove, cloned_vptr);
        EXPECT_EQ(seed_value_after_remove, 42);
    }

    EXPECT_TRUE(static_cast<bool>(vmt));
    ASSERT_TRUE(vmt.remove_method(0).has_value());
    EXPECT_EQ(call_vmt_value(*seed), 41);
    ASSERT_TRUE(vmt.remove_from(seed.get()).has_value());
    EXPECT_EQ(vptr_of(*seed), original_vptr);
    EXPECT_EQ(vptr_of(*peer), original_vptr);
}

TEST(HookLoaderLock, PostVetoSeamNamesEveryMutationEntry)
{
    const Address target{reinterpret_cast<std::uintptr_t>(&loader_reject_target_a)};
    Result<Hook> installed =
        inline_at(InlineRequest{.name = "loader_probe_owner", .target = target}, &loader_reject_detour);
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook moved_from_hook = std::move(*installed);
    Hook hook_owner = std::move(moved_from_hook);

    VmtLoaderTarget object;
    Result<VmtHook> created = vmt_for("loader_probe_vmt_owner", &object);
    ASSERT_TRUE(created.has_value()) << created.error().message();
    VmtHook moved_from_vmt = std::move(*created);
    VmtHook vmt_owner = std::move(moved_from_vmt);

    PostLoaderVetoProbe boundary_probe;
    const Result<Hook> inline_result = inline_at(InlineRequest{.name = "", .target = target}, &loader_reject_detour);
    const Result<Hook> mid_result = mid_at(MidRequest{.name = "", .target = target}, &loader_reject_mid_detour);
    const Result<std::vector<InstallOutcome>> batch_result = install_all(std::span<const HookSpec>{});
    const Result<VmtHook> vmt_result = vmt_for(std::string{}, &object);
    const Result<void> enabled = moved_from_hook.enable();
    const Result<void> disabled = moved_from_hook.disable();
    const Result<void> applied = moved_from_vmt.apply_to(&object);
    const Result<void> removed = moved_from_vmt.remove_from(&object);
    const Result<void> hooked = moved_from_vmt.hook_method(0, &vmt_loader_detour);
    const Result<void> removed_method = moved_from_vmt.remove_method(0);

    ASSERT_FALSE(inline_result.has_value());
    EXPECT_EQ(inline_result.error().code, ErrorCode::InvalidArg);
    ASSERT_FALSE(mid_result.has_value());
    EXPECT_EQ(mid_result.error().code, ErrorCode::InvalidArg);
    EXPECT_TRUE(batch_result.has_value());
    ASSERT_FALSE(vmt_result.has_value());
    EXPECT_EQ(vmt_result.error().code, ErrorCode::InvalidArg);
    ASSERT_FALSE(enabled.has_value());
    EXPECT_EQ(enabled.error().code, ErrorCode::InvalidHookState);
    ASSERT_FALSE(disabled.has_value());
    EXPECT_EQ(disabled.error().code, ErrorCode::InvalidHookState);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code, ErrorCode::InvalidHookState);
    ASSERT_FALSE(removed.has_value());
    EXPECT_EQ(removed.error().code, ErrorCode::InvalidHookState);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidHookState);
    ASSERT_FALSE(removed_method.has_value());
    EXPECT_EQ(removed_method.error().code, ErrorCode::InvalidHookState);
    EXPECT_EQ(boundary_probe.entries(), ALL_HOOK_LOADER_ENTRIES);
    EXPECT_TRUE(static_cast<bool>(hook_owner));
    EXPECT_TRUE(static_cast<bool>(vmt_owner));
}
