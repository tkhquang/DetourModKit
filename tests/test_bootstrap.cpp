#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <windows.h>

#include "DetourModKit/bootstrap.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/input.hpp"

using namespace DetourModKit;
using namespace std::chrono_literals;
using DetourModKit::keyboard_key;

namespace
{
    constexpr auto kTestTimeout = 5s;

    std::string current_exe_basename()
    {
        char exe_path[MAX_PATH]{};
        const DWORD len = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH)
        {
            return {};
        }
        const char *name = std::strrchr(exe_path, '\\');
        return name ? std::string(name + 1) : std::string(exe_path);
    }

    struct CallbackSignals
    {
        std::mutex m;
        std::condition_variable cv;
        std::atomic<int> init_calls{0};
        std::atomic<int> shutdown_calls{0};
        std::atomic<bool> init_done{false};
        std::atomic<bool> shutdown_done{false};

        bool wait_for_init(std::chrono::steady_clock::duration timeout)
        {
            std::unique_lock lock(m);
            return cv.wait_for(lock, timeout, [this]
                               { return init_done.load(std::memory_order_acquire); });
        }

        bool wait_for_shutdown(std::chrono::steady_clock::duration timeout)
        {
            std::unique_lock lock(m);
            return cv.wait_for(lock, timeout, [this]
                               { return shutdown_done.load(std::memory_order_acquire); });
        }
    };
} // namespace

TEST(BootstrapUnitTest, ModInfoDefaults)
{
    const Bootstrap::ModInfo info{};
    EXPECT_TRUE(info.prefix.empty());
    EXPECT_TRUE(info.log_file.empty());
    EXPECT_TRUE(info.game_process_name.empty());
    EXPECT_TRUE(info.instance_mutex_prefix.empty());
}

TEST(BootstrapUnitTest, RequestShutdownBeforeAttachIsNoOp)
{
    EXPECT_NO_THROW(Bootstrap::request_shutdown());
    EXPECT_NO_THROW(Bootstrap::request_shutdown());
}

TEST(BootstrapUnitTest, ModuleHandleReturnsNullBeforeAttach)
{
    EXPECT_EQ(Bootstrap::module_handle(), nullptr);
}

TEST(BootstrapUnitTest, NullHModuleSkipsDisableThreadLibraryCalls)
{
    CallbackSignals sig;
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_nullmod.log";
    info.game_process_name = "DefinitelyNotTheCurrentProcess_null.exe";
    info.instance_mutex_prefix = "BS_Test_Mutex_NullMod_";

    const BOOL result = Bootstrap::on_dll_attach(
        nullptr,
        info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);
}

TEST(BootstrapUnitTest, EmptyProcessNamePassesGateButMutexCollisionStillFails)
{
    // Pre-own the mutex name so the attach still fails without arming the
    // shutdown event or the worker thread.
    const std::string_view prefix = "BS_Test_Mutex_EmptyGate_";

    wchar_t expected_name[128]{};
    std::wstring wprefix;
    wprefix.reserve(prefix.size());
    for (char c : prefix)
    {
        wprefix.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    const int n = wsprintfW(expected_name, L"%s%lu", wprefix.c_str(),
                            GetCurrentProcessId());
    ASSERT_GT(n, 0);

    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, expected_name);
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u);

    CallbackSignals sig;
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_emptygate.log";
    info.game_process_name = "";
    info.instance_mutex_prefix = prefix;

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr),
        info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    CloseHandle(pre_owned);
}

TEST(BootstrapUnitTest, ProcessGateMismatchReturnsFalse)
{
    CallbackSignals sig;
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_procgate.log";
    info.game_process_name = "DefinitelyNotTheCurrentProcess_xyz.exe";
    info.instance_mutex_prefix = "BS_Test_Mutex_ProcGate_";

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr),
        info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);
}

TEST(BootstrapUnitTest, InstanceMutexCollisionReturnsFalse)
{
    const std::string_view prefix = "BS_Test_Mutex_Collision_";

    wchar_t expected_name[128]{};
    std::wstring wprefix;
    wprefix.reserve(prefix.size());
    for (char c : prefix)
    {
        wprefix.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    const int n = wsprintfW(expected_name, L"%s%lu", wprefix.c_str(), GetCurrentProcessId());
    ASSERT_GT(n, 0);

    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, expected_name);
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u) << "Mutex name collided with an existing one before the test";

    CallbackSignals sig;
    const std::string exe_name = current_exe_basename();
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_mutex.log";
    info.game_process_name = exe_name;
    info.instance_mutex_prefix = prefix;

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr),
        info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);

    CloseHandle(pre_owned);
}

class BootstrapIntegrationTest : public ::testing::Test
{
protected:
    CallbackSignals sig;
    bool attached{false};

    void TearDown() override
    {
        if (attached)
        {
            Bootstrap::request_shutdown();
            sig.wait_for_shutdown(kTestTimeout);
            Bootstrap::on_dll_detach(FALSE);
        }
    }
};

TEST_F(BootstrapIntegrationTest, HappyPathAttachInitShutdown)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_happy.log";
    info.game_process_name = exe_name;
    info.instance_mutex_prefix = "BS_Test_Mutex_Happy_";

    auto init_fn = [this]() noexcept
    {
        sig.init_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(sig.m);
            sig.init_done.store(true, std::memory_order_release);
        }
        sig.cv.notify_all();
        return true;
    };

    auto shutdown_fn = [this]() noexcept
    {
        sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(sig.m);
            sig.shutdown_done.store(true, std::memory_order_release);
        }
        sig.cv.notify_all();
    };

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr), info, init_fn, shutdown_fn);
    ASSERT_EQ(result, TRUE);
    attached = true;

    ASSERT_TRUE(sig.wait_for_init(kTestTimeout)) << "init_fn did not complete within timeout";
    EXPECT_EQ(sig.init_calls.load(), 1);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);

    EXPECT_NE(Bootstrap::module_handle(), nullptr);

    const BOOL second = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr), info,
        [this]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [this]() noexcept
        {
            sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        });
    EXPECT_EQ(second, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 1);

    const auto signal_start = std::chrono::steady_clock::now();
    Bootstrap::request_shutdown();

    ASSERT_TRUE(sig.wait_for_shutdown(kTestTimeout)) << "shutdown_fn did not complete within timeout";
    const auto elapsed = std::chrono::steady_clock::now() - signal_start;

    EXPECT_EQ(sig.init_calls.load(), 1);
    EXPECT_EQ(sig.shutdown_calls.load(), 1);
    EXPECT_LT(elapsed, 2s);

    attached = false;
}

TEST_F(BootstrapIntegrationTest, InitAndShutdownExceptionsAreCaught)
{
    // Drain any globals left set by a prior successful attach (HappyPath
    // leaves g_shutdown_event / g_worker_thread non-null for its design);
    // this is the first on_dll_detach call in the process and will win
    // the CAS and clear the static handles.
    Bootstrap::on_dll_detach(FALSE);

    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_throws.log";
    info.game_process_name = exe_name;
    info.instance_mutex_prefix = "BS_Test_Mutex_Throws_";

    auto init_fn = [this]() -> bool
    {
        sig.init_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(sig.m);
            sig.init_done.store(true, std::memory_order_release);
        }
        sig.cv.notify_all();
        throw std::runtime_error("init failure");
    };

    auto shutdown_fn = [this]()
    {
        sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(sig.m);
            sig.shutdown_done.store(true, std::memory_order_release);
        }
        sig.cv.notify_all();
        throw std::runtime_error("shutdown failure");
    };

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr), info, init_fn, shutdown_fn);
    ASSERT_EQ(result, TRUE);
    attached = true;

    ASSERT_TRUE(sig.wait_for_init(kTestTimeout));
    EXPECT_EQ(sig.init_calls.load(), 1);

    Bootstrap::request_shutdown();
    ASSERT_TRUE(sig.wait_for_shutdown(kTestTimeout));
    EXPECT_EQ(sig.shutdown_calls.load(), 1);
}

namespace
{
    [[gnu::noinline]] int logic_unload_target_add(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    [[gnu::noinline]] int logic_unload_detour_add(int a, int b)
    {
        return a + b + 1;
    }

    // Distinct target keeps the prologue-restore assertion meaningful in the
    // _all() tests when two hooks are installed at once.
    [[gnu::noinline]] int logic_unload_target_sub(int a, int b)
    {
        volatile int r = a - b;
        return r;
    }

    [[gnu::noinline]] int logic_unload_detour_sub(int a, int b)
    {
        return a - b - 1;
    }
} // namespace

TEST(BootstrapOnLogicDllUnload, RemovesHooksAndBindings)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    void *trampoline = nullptr;
    auto hook_result = HookManager::get_instance().create_inline_hook(
        "logic_unload_hook",
        reinterpret_cast<uintptr_t>(&logic_unload_target_add),
        reinterpret_cast<void *>(&logic_unload_detour_add),
        &trampoline);
    ASSERT_TRUE(hook_result.has_value());

    InputManager::get_instance().register_press(
        "logic_unload_binding", {keyboard_key(0x41)}, []() {});
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(1));
    EXPECT_TRUE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_add)));

    const std::string_view hooks[] = {"logic_unload_hook"};
    const std::string_view bindings[] = {"logic_unload_binding"};
    Bootstrap::on_logic_dll_unload(hooks, bindings);

    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_add)));
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));
}

TEST(BootstrapOnLogicDllUnload, IsIdempotent)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    void *trampoline = nullptr;
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "logic_unload_idem",
        reinterpret_cast<uintptr_t>(&logic_unload_target_add),
        reinterpret_cast<void *>(&logic_unload_detour_add),
        &trampoline).has_value());
    InputManager::get_instance().register_press(
        "logic_unload_idem_bind", {keyboard_key(0x42)}, []() {});

    const std::string_view hooks[] = {"logic_unload_idem"};
    const std::string_view bindings[] = {"logic_unload_idem_bind"};
    Bootstrap::on_logic_dll_unload(hooks, bindings);
    Bootstrap::on_logic_dll_unload(hooks, bindings);

    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_add)));
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));
}

TEST(BootstrapOnLogicDllUnloadAll, RemovesAllHooksAndBindings)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    void *trampoline_add = nullptr;
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "logic_unload_all_add",
        reinterpret_cast<uintptr_t>(&logic_unload_target_add),
        reinterpret_cast<void *>(&logic_unload_detour_add),
        &trampoline_add).has_value());

    void *trampoline_sub = nullptr;
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "logic_unload_all_sub",
        reinterpret_cast<uintptr_t>(&logic_unload_target_sub),
        reinterpret_cast<void *>(&logic_unload_detour_sub),
        &trampoline_sub).has_value());

    InputManager::get_instance().register_press(
        "logic_unload_all_bind_a", {keyboard_key(0x43)}, []() {});
    InputManager::get_instance().register_press(
        "logic_unload_all_bind_b", {keyboard_key(0x44)}, []() {});
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(2));
    EXPECT_TRUE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_add)));
    EXPECT_TRUE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_sub)));

    Bootstrap::on_logic_dll_unload_all();

    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_add)));
    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_sub)));
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));
}

TEST(BootstrapOnLogicDllUnloadAll, IsIdempotent)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    void *trampoline = nullptr;
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "logic_unload_all_idem",
        reinterpret_cast<uintptr_t>(&logic_unload_target_add),
        reinterpret_cast<void *>(&logic_unload_detour_add),
        &trampoline).has_value());
    InputManager::get_instance().register_press(
        "logic_unload_all_idem_bind", {keyboard_key(0x45)}, []() {});

    Bootstrap::on_logic_dll_unload_all();
    Bootstrap::on_logic_dll_unload_all();

    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_add)));
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));
}

TEST(BootstrapOnLogicDllUnloadAll, EmptyRegistriesIsNoOp)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));

    Bootstrap::on_logic_dll_unload_all();

    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));
}

TEST(BootstrapOnLogicDllUnloadAll, CoexistsWithNamedOverload)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    void *trampoline_named = nullptr;
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "logic_unload_mixed_named",
        reinterpret_cast<uintptr_t>(&logic_unload_target_add),
        reinterpret_cast<void *>(&logic_unload_detour_add),
        &trampoline_named).has_value());
    void *trampoline_residual = nullptr;
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "logic_unload_mixed_residual",
        reinterpret_cast<uintptr_t>(&logic_unload_target_sub),
        reinterpret_cast<void *>(&logic_unload_detour_sub),
        &trampoline_residual).has_value());

    InputManager::get_instance().register_press(
        "logic_unload_mixed_named_bind", {keyboard_key(0x46)}, []() {});
    InputManager::get_instance().register_press(
        "logic_unload_mixed_residual_bind", {keyboard_key(0x47)}, []() {});

    // Named overload first peels off the explicit subset.
    const std::string_view hooks[] = {"logic_unload_mixed_named"};
    const std::string_view bindings[] = {"logic_unload_mixed_named_bind"};
    Bootstrap::on_logic_dll_unload(hooks, bindings);

    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_add)));
    EXPECT_TRUE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_sub)));
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(1));

    // Catch-all sweeps the residual hook and binding without leaks.
    Bootstrap::on_logic_dll_unload_all();

    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(&logic_unload_target_sub)));
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));
}

TEST(BootstrapOnLogicDllUnload, SuppressesHoldReleaseCallbacks)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    auto release_count = std::make_shared<std::atomic<int>>(0);
    auto press_count = std::make_shared<std::atomic<int>>(0);

    InputManager::get_instance().register_hold(
        "loader_lock_hold",
        {keyboard_key(0x48)},
        [release_count, press_count](bool pressed) noexcept
        {
            if (pressed)
            {
                press_count->fetch_add(1, std::memory_order_relaxed);
            }
            else
            {
                release_count->fetch_add(1, std::memory_order_relaxed);
            }
        });
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(1));

    const std::string_view bindings[] = {"loader_lock_hold"};
    Bootstrap::on_logic_dll_unload({}, bindings);

    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));
    EXPECT_EQ(release_count->load(), 0)
        << "Bootstrap unload helpers must not invoke user release callbacks under loader lock";
    EXPECT_EQ(press_count->load(), 0);
}

TEST(BootstrapOnLogicDllUnloadAll, SuppressesHoldReleaseCallbacks)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    auto release_count = std::make_shared<std::atomic<int>>(0);

    InputManager::get_instance().register_hold(
        "loader_lock_hold_all",
        {keyboard_key(0x49)},
        [release_count](bool pressed) noexcept
        {
            if (!pressed)
            {
                release_count->fetch_add(1, std::memory_order_relaxed);
            }
        });

    Bootstrap::on_logic_dll_unload_all();

    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));
    EXPECT_EQ(release_count->load(), 0);
}

namespace
{
    using ComputeDamageFn = int(__cdecl *)(int, int);
    using ComputeArmorFn = int(__cdecl *)(int, int);

    struct LoadedFixtureModule
    {
        HMODULE handle{nullptr};
        ComputeDamageFn compute_damage{nullptr};
        ComputeArmorFn compute_armor{nullptr};

        bool load()
        {
            handle = LoadLibraryA("hook_target_lib.dll");
            if (!handle)
            {
                return false;
            }
            compute_damage = reinterpret_cast<ComputeDamageFn>(
                reinterpret_cast<void *>(GetProcAddress(handle, "compute_damage")));
            compute_armor = reinterpret_cast<ComputeArmorFn>(
                reinterpret_cast<void *>(GetProcAddress(handle, "compute_armor")));
            return compute_damage != nullptr && compute_armor != nullptr;
        }

        void unload()
        {
            if (handle)
            {
                FreeLibrary(handle);
                handle = nullptr;
                compute_damage = nullptr;
                compute_armor = nullptr;
            }
        }

        ~LoadedFixtureModule() { unload(); }
    };

    int __cdecl fixture_detour_compute_damage(int, int) { return 0xC0DE; }
    int __cdecl fixture_detour_compute_armor(int, int) { return 0xCAFE; }
} // namespace

// Drives the Bootstrap helpers through a real LoadLibrary / FreeLibrary cycle
// against the hook_target_lib fixture so trampoline restoration, code-page
// lifetime, and idempotency are exercised end-to-end rather than only against
// in-process function targets.
TEST(BootstrapOnLogicDllUnload, FixtureDllRoundTrip)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    LoadedFixtureModule mod;
    ASSERT_TRUE(mod.load()) << "hook_target_lib.dll must be loadable";

    void *tramp_damage = nullptr;
    void *tramp_armor = nullptr;
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "fixture_dll_damage",
        reinterpret_cast<uintptr_t>(mod.compute_damage),
        reinterpret_cast<void *>(&fixture_detour_compute_damage),
        &tramp_damage).has_value());
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "fixture_dll_armor",
        reinterpret_cast<uintptr_t>(mod.compute_armor),
        reinterpret_cast<void *>(&fixture_detour_compute_armor),
        &tramp_armor).has_value());

    InputManager::get_instance().register_press(
        "fixture_dll_bind_a", {keyboard_key(0x4A)}, []() {});
    InputManager::get_instance().register_press(
        "fixture_dll_bind_b", {keyboard_key(0x4B)}, []() {});
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(2));
    EXPECT_TRUE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(mod.compute_damage)));
    EXPECT_TRUE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(mod.compute_armor)));

    const std::string_view hooks[] = {"fixture_dll_damage", "fixture_dll_armor"};
    const std::string_view bindings[] = {"fixture_dll_bind_a", "fixture_dll_bind_b"};
    Bootstrap::on_logic_dll_unload(hooks, bindings);

    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(mod.compute_damage)));
    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(mod.compute_armor)));
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));

    // Idempotent: a second sweep of the same names is a no-op.
    Bootstrap::on_logic_dll_unload(hooks, bindings);
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));

    // Free and reload the fixture so a fresh prologue can be hooked. If the
    // unload had failed to restore the bytes, the second create_inline_hook
    // would return TargetAlreadyHookedInProcess against any module that
    // happened to remap to the same address.
    mod.unload();
    ASSERT_TRUE(mod.load()) << "hook_target_lib.dll must reload cleanly";

    void *tramp_reload = nullptr;
    HookConfig strict;
    strict.fail_if_already_hooked = true;
    auto reload_result = HookManager::get_instance().create_inline_hook(
        "fixture_dll_damage_reloaded",
        reinterpret_cast<uintptr_t>(mod.compute_damage),
        reinterpret_cast<void *>(&fixture_detour_compute_damage),
        &tramp_reload,
        strict);
    EXPECT_TRUE(reload_result.has_value())
        << "Fresh hook on the reloaded fixture must succeed; "
        << "TargetAlreadyHookedInProcess would mean the prologue was not restored";

    HookManager::get_instance().remove_all_hooks();
}

TEST(BootstrapOnLogicDllUnloadAll, FixtureDllRoundTrip)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();

    LoadedFixtureModule mod;
    ASSERT_TRUE(mod.load());

    void *tramp_damage = nullptr;
    void *tramp_armor = nullptr;
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "fixture_all_damage",
        reinterpret_cast<uintptr_t>(mod.compute_damage),
        reinterpret_cast<void *>(&fixture_detour_compute_damage),
        &tramp_damage).has_value());
    ASSERT_TRUE(HookManager::get_instance().create_inline_hook(
        "fixture_all_armor",
        reinterpret_cast<uintptr_t>(mod.compute_armor),
        reinterpret_cast<void *>(&fixture_detour_compute_armor),
        &tramp_armor).has_value());
    InputManager::get_instance().register_press(
        "fixture_all_bind", {keyboard_key(0x4C)}, []() {});

    Bootstrap::on_logic_dll_unload_all();

    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(mod.compute_damage)));
    EXPECT_FALSE(HookManager::get_instance().is_target_already_hooked(
        reinterpret_cast<uintptr_t>(mod.compute_armor)));
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));

    // Idempotency.
    Bootstrap::on_logic_dll_unload_all();
    EXPECT_EQ(InputManager::get_instance().binding_count(), static_cast<size_t>(0));

    // Reload the fixture and re-hook to confirm the restored prologue is
    // hookable from a clean slate.
    mod.unload();
    ASSERT_TRUE(mod.load());
    void *tramp_reload = nullptr;
    HookConfig strict;
    strict.fail_if_already_hooked = true;
    EXPECT_TRUE(HookManager::get_instance().create_inline_hook(
        "fixture_all_damage_reloaded",
        reinterpret_cast<uintptr_t>(mod.compute_damage),
        reinterpret_cast<void *>(&fixture_detour_compute_damage),
        &tramp_reload,
        strict).has_value());

    HookManager::get_instance().remove_all_hooks();
}

// Verifies that on_logic_dll_unload chains Config::clear_registered_items
// after the hook and binding teardown so registered std::function
// setters (whose call operator and destructor live in the unloading
// Logic DLL) cannot survive into a second attach as use-after-unload
// hazards.
//
// The verification path: a registered setter captures a shared_ptr by
// value, so the setter closure stored inside the registry holds a
// strong reference. While the registry retains the entry, use_count
// stays >= 2 (one local sentinel ref plus one inside the captured
// closure). Once the helper wipes the registry, the captured closure
// is destroyed and the local sentinel is the sole owner.
TEST(BootstrapOnLogicDllUnload, ClearsConfigRegisteredItems)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();
    Config::clear_registered_items();

    auto sentinel = std::make_shared<int>(0);
    EXPECT_EQ(sentinel.use_count(), 1L);

    Config::register_string(
        "BootstrapUnloadCfgClear", "Key", "Bootstrap unload key",
        [sentinel](const std::string &) { /* keeps sentinel alive */ },
        "default");

    // After registration the captured-by-value shared_ptr lives inside
    // the setter closure stored in the Config registry, so use_count
    // includes both the local sentinel and the closure copy.
    EXPECT_GE(sentinel.use_count(), 2L);

    Bootstrap::on_logic_dll_unload({}, {});

    // The unload helper must have dropped the registry entry, releasing
    // its captured copy of the sentinel. The local variable is the
    // only remaining owner.
    EXPECT_EQ(sentinel.use_count(), 1L);
}

TEST(BootstrapOnLogicDllUnloadAll, ClearsConfigRegisteredItems)
{
    HookManager::get_instance().remove_all_hooks();
    InputManager::get_instance().shutdown();
    Config::clear_registered_items();

    auto sentinel = std::make_shared<int>(0);
    EXPECT_EQ(sentinel.use_count(), 1L);

    Config::register_string(
        "BootstrapUnloadAllCfgClear", "Key", "Bootstrap unload-all key",
        [sentinel](const std::string &) { /* keeps sentinel alive */ },
        "default");
    EXPECT_GE(sentinel.use_count(), 2L);

    Bootstrap::on_logic_dll_unload_all();

    EXPECT_EQ(sentinel.use_count(), 1L);
}
