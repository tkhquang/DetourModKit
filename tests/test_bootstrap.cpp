#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <windows.h>

#include "DetourModKit/address.hpp"
#include "DetourModKit/bootstrap.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/input.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace std::chrono_literals;
using DetourModKit::keyboard_key;

#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

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
            return cv.wait_for(lock, timeout, [this] { return init_done.load(std::memory_order_acquire); });
        }

        bool wait_for_shutdown(std::chrono::steady_clock::duration timeout)
        {
            std::unique_lock lock(m);
            return cv.wait_for(lock, timeout, [this] { return shutdown_done.load(std::memory_order_acquire); });
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
        nullptr, info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept { sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed); });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);
}

TEST(BootstrapUnitTest, EmptyProcessNamePassesGateButMutexCollisionStillFails)
{
    // Pre-own the mutex name so the attach still fails without arming the shutdown event or the worker thread.
    const std::string_view prefix = "BS_Test_Mutex_EmptyGate_";

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
    ASSERT_EQ(GetLastError(), 0u);

    CallbackSignals sig;
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_emptygate.log";
    info.game_process_name = "";
    info.instance_mutex_prefix = prefix;

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr), info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept { sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed); });

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
        GetModuleHandleW(nullptr), info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept { sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed); });

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
        GetModuleHandleW(nullptr), info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept { sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed); });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);

    CloseHandle(pre_owned);
}

TEST(BootstrapUnitTest, InstanceMutexLongPrefixDoesNotOverflow)
{
    // A prefix far longer than any fixed-size formatting buffer must be handled without overflow. Reconstruct the
    // expected name exactly as the bootstrap builds it (each prefix byte widened, then the decimal PID) and pre-own it
    // so the attach fails on the collision: a clean FALSE proves the long name was formed intact rather than truncated
    // or written past a fixed buffer.
    const std::string prefix(200, 'A');

    std::wstring expected_name;
    expected_name.reserve(prefix.size() + 10);
    for (char c : prefix)
    {
        expected_name.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    expected_name += std::to_wstring(GetCurrentProcessId());

    HANDLE pre_owned = CreateMutexW(nullptr, FALSE, expected_name.c_str());
    ASSERT_NE(pre_owned, nullptr);
    ASSERT_EQ(GetLastError(), 0u) << "Long mutex name collided with an existing one before the test";

    CallbackSignals sig;
    const std::string exe_name = current_exe_basename();
    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_mutex_long.log";
    info.game_process_name = exe_name;
    info.instance_mutex_prefix = prefix;

    const BOOL result = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr), info,
        [&sig]() noexcept
        {
            sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [&sig]() noexcept { sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed); });

    EXPECT_EQ(result, FALSE);
    EXPECT_EQ(sig.init_calls.load(), 0);
    EXPECT_EQ(sig.shutdown_calls.load(), 0);

    CloseHandle(pre_owned);
}

class BootstrapIntegrationTest : public ::testing::Test
{
protected:
    CallbackSignals m_sig;
    bool m_attached{false};

    void TearDown() override
    {
        if (m_attached)
        {
            Bootstrap::request_shutdown();
            m_sig.wait_for_shutdown(kTestTimeout);
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
        m_sig.init_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(m_sig.m);
            m_sig.init_done.store(true, std::memory_order_release);
        }
        m_sig.cv.notify_all();
        return true;
    };

    auto shutdown_fn = [this]() noexcept
    {
        m_sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(m_sig.m);
            m_sig.shutdown_done.store(true, std::memory_order_release);
        }
        m_sig.cv.notify_all();
    };

    const BOOL result = Bootstrap::on_dll_attach(GetModuleHandleW(nullptr), info, init_fn, shutdown_fn);
    ASSERT_EQ(result, TRUE);
    m_attached = true;

    ASSERT_TRUE(m_sig.wait_for_init(kTestTimeout)) << "init_fn did not complete within timeout";
    EXPECT_EQ(m_sig.init_calls.load(), 1);
    EXPECT_EQ(m_sig.shutdown_calls.load(), 0);

    EXPECT_NE(Bootstrap::module_handle(), nullptr);

    const BOOL second = Bootstrap::on_dll_attach(
        GetModuleHandleW(nullptr), info,
        [this]() noexcept
        {
            m_sig.init_calls.fetch_add(1, std::memory_order_relaxed);
            return true;
        },
        [this]() noexcept { m_sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed); });
    EXPECT_EQ(second, FALSE);
    EXPECT_EQ(m_sig.init_calls.load(), 1);

    const auto signal_start = std::chrono::steady_clock::now();
    Bootstrap::request_shutdown();

    ASSERT_TRUE(m_sig.wait_for_shutdown(kTestTimeout)) << "shutdown_fn did not complete within timeout";
    const auto elapsed = std::chrono::steady_clock::now() - signal_start;

    EXPECT_EQ(m_sig.init_calls.load(), 1);
    EXPECT_EQ(m_sig.shutdown_calls.load(), 1);
    EXPECT_LT(elapsed, 2s);

    // Leave m_attached = true so the fixture TearDown runs on_dll_detach(FALSE) and clears the static handles, leaving
    // a clean slate for the next test instead of leaking them for a later drain.
}

TEST_F(BootstrapIntegrationTest, AttachDetachCyclesAreReentrant)
{
    // A successful attach re-arms the detach gate, so attach/detach cycles repeat and each detach runs its teardown
    // instead of no-opping. Drive two full cycles and assert the second detach actually fired: init and shutdown each
    // ran once per cycle and the module handle is cleared after every detach (before the gate reset, the second detach
    // CAS-failed and left the handle set).
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_reentrant.log";
    info.game_process_name = exe_name;
    info.instance_mutex_prefix = "BS_Test_Mutex_Reentrant_";

    auto init_fn = [this]() noexcept
    {
        m_sig.init_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(m_sig.m);
            m_sig.init_done.store(true, std::memory_order_release);
        }
        m_sig.cv.notify_all();
        return true;
    };
    auto shutdown_fn = [this]() noexcept
    {
        m_sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(m_sig.m);
            m_sig.shutdown_done.store(true, std::memory_order_release);
        }
        m_sig.cv.notify_all();
    };

    for (int cycle = 1; cycle <= 2; ++cycle)
    {
        m_sig.init_done.store(false, std::memory_order_release);
        m_sig.shutdown_done.store(false, std::memory_order_release);

        const BOOL attached = Bootstrap::on_dll_attach(GetModuleHandleW(nullptr), info, init_fn, shutdown_fn);
        ASSERT_EQ(attached, TRUE) << "cycle " << cycle << " attach must succeed";
        EXPECT_NE(Bootstrap::module_handle(), nullptr);

        ASSERT_TRUE(m_sig.wait_for_init(kTestTimeout)) << "cycle " << cycle << " init_fn did not complete";
        EXPECT_EQ(m_sig.init_calls.load(), cycle);

        Bootstrap::request_shutdown();
        ASSERT_TRUE(m_sig.wait_for_shutdown(kTestTimeout)) << "cycle " << cycle << " shutdown_fn did not complete";
        EXPECT_EQ(m_sig.shutdown_calls.load(), cycle);

        Bootstrap::on_dll_detach(FALSE);
        EXPECT_EQ(Bootstrap::module_handle(), nullptr) << "cycle " << cycle << " detach must clear the module handle";
    }

    // The test drove its own attach/detach pairs, so the fixture TearDown must not detach again.
    m_attached = false;
}

TEST_F(BootstrapIntegrationTest, InitAndShutdownExceptionsAreCaught)
{
    const std::string exe_name = current_exe_basename();
    ASSERT_FALSE(exe_name.empty());

    Bootstrap::ModInfo info{};
    info.prefix = "BS_TEST";
    info.log_file = "bs_test_throws.log";
    info.game_process_name = exe_name;
    info.instance_mutex_prefix = "BS_Test_Mutex_Throws_";

    auto init_fn = [this]() -> bool
    {
        m_sig.init_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(m_sig.m);
            m_sig.init_done.store(true, std::memory_order_release);
        }
        m_sig.cv.notify_all();
        throw std::runtime_error("init failure");
    };

    auto shutdown_fn = [this]()
    {
        m_sig.shutdown_calls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard lock(m_sig.m);
            m_sig.shutdown_done.store(true, std::memory_order_release);
        }
        m_sig.cv.notify_all();
        throw std::runtime_error("shutdown failure");
    };

    const BOOL result = Bootstrap::on_dll_attach(GetModuleHandleW(nullptr), info, init_fn, shutdown_fn);
    ASSERT_EQ(result, TRUE);
    m_attached = true;

    ASSERT_TRUE(m_sig.wait_for_init(kTestTimeout));
    EXPECT_EQ(m_sig.init_calls.load(), 1);

    Bootstrap::request_shutdown();
    ASSERT_TRUE(m_sig.wait_for_shutdown(kTestTimeout));
    EXPECT_EQ(m_sig.shutdown_calls.load(), 1);
}

namespace
{
    DMK_TEST_NOINLINE int logic_unload_target_add(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_TEST_NOINLINE int logic_unload_detour_add(int a, int b)
    {
        return a + b + 1;
    }

    // A second distinct target so a test can hold two caller-owned hooks at once and prove the unload helpers leave
    // both untouched.
    DMK_TEST_NOINLINE int logic_unload_target_sub(int a, int b)
    {
        volatile int r = a - b;
        return r;
    }

    DMK_TEST_NOINLINE int logic_unload_detour_sub(int a, int b)
    {
        return a - b - 1;
    }
} // namespace

// on_logic_dll_unload tears down the named bindings and the Config registry, but it does NOT
// touch hooks: the hook_names span is accepted but ignored because each hook is owned by the caller's Hook handle.
// Install a real RAII hook, pass its name in hook_names, and prove the helper leaves the hook fully live while it
// clears the binding -- the caller still owns the hook lifetime.
TEST(BootstrapOnLogicDllUnload, BindingsTornDownButHooksAreCallerOwned)
{
    input::Input::instance().shutdown();

    const Address target{reinterpret_cast<std::uintptr_t>(&logic_unload_target_add)};
    Result<Hook> r = inline_at(InlineRequest{.name = "logic_unload_hook", .target = target}, &logic_unload_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(is_target_hooked(target));

    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_binding"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x41)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    const std::string_view hooks[] = {"logic_unload_hook"};
    const std::string_view bindings[] = {"logic_unload_binding"};
    Bootstrap::on_logic_dll_unload(hooks, bindings);

    // Binding gone; hook untouched (still live and enabled) because the helper ignores hook_names.
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    EXPECT_TRUE(static_cast<bool>(h)) << "passing a hook name must be a no-op; the caller still owns the hook";
    EXPECT_TRUE(h.is_enabled());
    EXPECT_TRUE(is_target_hooked(target));

    // h drops here: RAII unhooks, proving lifetime is the caller's, not the unload helper's.
}

TEST(BootstrapOnLogicDllUnload, IsIdempotent)
{
    input::Input::instance().shutdown();

    const Address target{reinterpret_cast<std::uintptr_t>(&logic_unload_target_add)};
    Result<Hook> r = inline_at(InlineRequest{.name = "logic_unload_idem", .target = target}, &logic_unload_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_idem_bind"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x42)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});

    const std::string_view hooks[] = {"logic_unload_idem"};
    const std::string_view bindings[] = {"logic_unload_idem_bind"};
    Bootstrap::on_logic_dll_unload(hooks, bindings);
    Bootstrap::on_logic_dll_unload(hooks, bindings);

    // A repeated sweep is a no-op for the (already gone) binding and leaves the caller-owned hook live both times.
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    EXPECT_TRUE(static_cast<bool>(h));
    EXPECT_TRUE(is_target_hooked(target));
}

// on_logic_dll_unload_all() clears every binding registered through the singletons, but it does NOT touch hooks.
// Hold two caller-owned hooks across the catch-all sweep and prove both survive while every binding is cleared.
TEST(BootstrapOnLogicDllUnloadAll, ClearsAllBindingsButHooksAreCallerOwned)
{
    input::Input::instance().shutdown();

    const Address target_add{reinterpret_cast<std::uintptr_t>(&logic_unload_target_add)};
    const Address target_sub{reinterpret_cast<std::uintptr_t>(&logic_unload_target_sub)};

    Result<Hook> r_add =
        inline_at(InlineRequest{.name = "logic_unload_all_add", .target = target_add}, &logic_unload_detour_add);
    ASSERT_TRUE(r_add.has_value()) << r_add.error().message();
    Hook h_add = std::move(*r_add);

    Result<Hook> r_sub =
        inline_at(InlineRequest{.name = "logic_unload_all_sub", .target = target_sub}, &logic_unload_detour_sub);
    ASSERT_TRUE(r_sub.has_value()) << r_sub.error().message();
    Hook h_sub = std::move(*r_sub);

    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_all_bind_a"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x43)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});
    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_all_bind_b"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x44)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(2));
    ASSERT_TRUE(is_target_hooked(target_add));
    ASSERT_TRUE(is_target_hooked(target_sub));

    Bootstrap::on_logic_dll_unload_all();

    // Both hooks remain live (caller-owned); all bindings are cleared.
    EXPECT_TRUE(static_cast<bool>(h_add));
    EXPECT_TRUE(static_cast<bool>(h_sub));
    EXPECT_TRUE(is_target_hooked(target_add));
    EXPECT_TRUE(is_target_hooked(target_sub));
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
}

TEST(BootstrapOnLogicDllUnloadAll, IsIdempotent)
{
    input::Input::instance().shutdown();

    const Address target{reinterpret_cast<std::uintptr_t>(&logic_unload_target_add)};
    Result<Hook> r =
        inline_at(InlineRequest{.name = "logic_unload_all_idem", .target = target}, &logic_unload_detour_add);
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_all_idem_bind"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x45)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});

    Bootstrap::on_logic_dll_unload_all();
    Bootstrap::on_logic_dll_unload_all();

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    EXPECT_TRUE(static_cast<bool>(h));
    EXPECT_TRUE(is_target_hooked(target));
}

TEST(BootstrapOnLogicDllUnloadAll, EmptyRegistriesIsNoOp)
{
    input::Input::instance().shutdown();

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));

    Bootstrap::on_logic_dll_unload_all();

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
}

// The named overload and the catch-all coexist on the binding/Config side: the named overload peels off its explicit
// binding subset, then the catch-all sweeps the residual binding. Neither touches the two caller-owned hooks held
// across both calls.
TEST(BootstrapOnLogicDllUnloadAll, CoexistsWithNamedOverload)
{
    input::Input::instance().shutdown();

    const Address target_named{reinterpret_cast<std::uintptr_t>(&logic_unload_target_add)};
    const Address target_residual{reinterpret_cast<std::uintptr_t>(&logic_unload_target_sub)};

    Result<Hook> r_named =
        inline_at(InlineRequest{.name = "logic_unload_mixed_named", .target = target_named}, &logic_unload_detour_add);
    ASSERT_TRUE(r_named.has_value()) << r_named.error().message();
    Hook h_named = std::move(*r_named);

    Result<Hook> r_residual = inline_at(InlineRequest{.name = "logic_unload_mixed_residual", .target = target_residual},
                                        &logic_unload_detour_sub);
    ASSERT_TRUE(r_residual.has_value()) << r_residual.error().message();
    Hook h_residual = std::move(*r_residual);

    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_mixed_named_bind"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x46)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});
    (void)input::register_combo(input::ComboBinding{.name = std::string{"logic_unload_mixed_residual_bind"},
                                                    .trigger = input::Trigger::Press,
                                                    .combos = {{{keyboard_key(0x47)}, {}}},
                                                    .on_press = []() {},
                                                    .on_state_change = {}});

    // Named overload first peels off the explicit binding subset (hook_names is accepted but ignored).
    const std::string_view hooks[] = {"logic_unload_mixed_named"};
    const std::string_view bindings[] = {"logic_unload_mixed_named_bind"};
    Bootstrap::on_logic_dll_unload(hooks, bindings);

    EXPECT_TRUE(static_cast<bool>(h_named)) << "named hook must survive; hook_names is a no-op";
    EXPECT_TRUE(is_target_hooked(target_named));
    EXPECT_TRUE(is_target_hooked(target_residual));
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    // Catch-all sweeps the residual binding; both hooks stay caller-owned.
    Bootstrap::on_logic_dll_unload_all();

    EXPECT_TRUE(static_cast<bool>(h_named));
    EXPECT_TRUE(static_cast<bool>(h_residual));
    EXPECT_TRUE(is_target_hooked(target_named));
    EXPECT_TRUE(is_target_hooked(target_residual));
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
}

TEST(BootstrapOnLogicDllUnload, SuppressesHoldReleaseCallbacks)
{
    input::Input::instance().shutdown();

    auto release_count = std::make_shared<std::atomic<int>>(0);
    auto press_count = std::make_shared<std::atomic<int>>(0);

    (void)input::register_combo(
        input::ComboBinding{.name = std::string{"loader_lock_hold"},
                            .trigger = input::Trigger::Hold,
                            .combos = {{{keyboard_key(0x48)}, {}}},
                            .on_press = {},
                            .on_state_change = [release_count, press_count](bool pressed) noexcept
                            {
                                if (pressed)
                                {
                                    press_count->fetch_add(1, std::memory_order_relaxed);
                                }
                                else
                                {
                                    release_count->fetch_add(1, std::memory_order_relaxed);
                                }
                            }});
    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(1));

    const std::string_view bindings[] = {"loader_lock_hold"};
    Bootstrap::on_logic_dll_unload({}, bindings);

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
    EXPECT_EQ(release_count->load(), 0)
        << "Bootstrap unload helpers must not invoke user release callbacks under loader lock";
    EXPECT_EQ(press_count->load(), 0);
}

TEST(BootstrapOnLogicDllUnloadAll, SuppressesHoldReleaseCallbacks)
{
    input::Input::instance().shutdown();

    auto release_count = std::make_shared<std::atomic<int>>(0);

    (void)input::register_combo(input::ComboBinding{.name = std::string{"loader_lock_hold_all"},
                                                    .trigger = input::Trigger::Hold,
                                                    .combos = {{{keyboard_key(0x49)}, {}}},
                                                    .on_press = {},
                                                    .on_state_change = [release_count](bool pressed) noexcept
                                                    {
                                                        if (!pressed)
                                                        {
                                                            release_count->fetch_add(1, std::memory_order_relaxed);
                                                        }
                                                    }});

    Bootstrap::on_logic_dll_unload_all();

    EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
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
            compute_damage =
                reinterpret_cast<ComputeDamageFn>(reinterpret_cast<void *>(GetProcAddress(handle, "compute_damage")));
            compute_armor =
                reinterpret_cast<ComputeArmorFn>(reinterpret_cast<void *>(GetProcAddress(handle, "compute_armor")));
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

    int __cdecl fixture_detour_compute_damage(int, int)
    {
        return 0xC0DE;
    }
    int __cdecl fixture_detour_compute_armor(int, int)
    {
        return 0xCAFE;
    }
} // namespace

// Drives on_logic_dll_unload through a real LoadLibrary / FreeLibrary cycle against the hook_target_lib fixture. Under
// the helper tears down only bindings + Config; hooks are caller-owned (a Hook handle unhooks when dropped). This
// proves that across a real cross- module load the binding teardown still works, the helper leaves the caller's hooks
// alone, and once the caller drops its Hook handles the fixture's prologue is restored so a fresh strict re-hook on a
// reloaded fixture succeeds.
TEST(BootstrapOnLogicDllUnload, FixtureDllRoundTrip)
{
    input::Input::instance().shutdown();

    LoadedFixtureModule mod;
    ASSERT_TRUE(mod.load()) << "hook_target_lib.dll must be loadable";

    const Address target_damage{reinterpret_cast<std::uintptr_t>(mod.compute_damage)};
    const Address target_armor{reinterpret_cast<std::uintptr_t>(mod.compute_armor)};

    {
        Result<Hook> r_damage = inline_at(InlineRequest{.name = "fixture_dll_damage", .target = target_damage},
                                          &fixture_detour_compute_damage);
        ASSERT_TRUE(r_damage.has_value()) << r_damage.error().message();
        Hook h_damage = std::move(*r_damage);

        Result<Hook> r_armor = inline_at(InlineRequest{.name = "fixture_dll_armor", .target = target_armor},
                                         &fixture_detour_compute_armor);
        ASSERT_TRUE(r_armor.has_value()) << r_armor.error().message();
        Hook h_armor = std::move(*r_armor);

        (void)input::register_combo(input::ComboBinding{.name = std::string{"fixture_dll_bind_a"},
                                                        .trigger = input::Trigger::Press,
                                                        .combos = {{{keyboard_key(0x4A)}, {}}},
                                                        .on_press = []() {},
                                                        .on_state_change = {}});
        (void)input::register_combo(input::ComboBinding{.name = std::string{"fixture_dll_bind_b"},
                                                        .trigger = input::Trigger::Press,
                                                        .combos = {{{keyboard_key(0x4B)}, {}}},
                                                        .on_press = []() {},
                                                        .on_state_change = {}});
        EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(2));
        ASSERT_TRUE(is_target_hooked(target_damage));
        ASSERT_TRUE(is_target_hooked(target_armor));

        const std::string_view hooks[] = {"fixture_dll_damage", "fixture_dll_armor"};
        const std::string_view bindings[] = {"fixture_dll_bind_a", "fixture_dll_bind_b"};
        Bootstrap::on_logic_dll_unload(hooks, bindings);

        // Bindings cleared; the caller's hooks are untouched (hook_names ignored).
        EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
        EXPECT_TRUE(static_cast<bool>(h_damage));
        EXPECT_TRUE(static_cast<bool>(h_armor));
        EXPECT_TRUE(is_target_hooked(target_damage));
        EXPECT_TRUE(is_target_hooked(target_armor));

        // Idempotent on the binding side: a second sweep of the same names is a no-op and still spares the hooks.
        Bootstrap::on_logic_dll_unload(hooks, bindings);
        EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
        EXPECT_TRUE(is_target_hooked(target_damage));

        // The Hook handles drop here: RAII restores the fixture's prologues.
    }
    EXPECT_FALSE(is_target_hooked(target_damage)) << "dropping the handle must unhook the fixture export";
    EXPECT_FALSE(is_target_hooked(target_armor));

    // Free and reload the fixture so a fresh prologue can be hooked. If RAII had failed to restore the bytes, a strict
    // re-hook on the reloaded fixture would report TargetAlreadyHookedInProcess.
    mod.unload();
    ASSERT_TRUE(mod.load()) << "hook_target_lib.dll must reload cleanly";

    Result<Hook> reload =
        inline_at(InlineRequest{.name = "fixture_dll_damage_reloaded",
                                .target = Address{reinterpret_cast<std::uintptr_t>(mod.compute_damage)},
                                .options = Options{.fail_if_already_hooked = true}},
                  &fixture_detour_compute_damage);
    EXPECT_TRUE(reload.has_value()) << "Fresh strict hook on the reloaded fixture must succeed; "
                                    << "TargetAlreadyHookedInProcess would mean the prologue was not restored";
}

TEST(BootstrapOnLogicDllUnloadAll, FixtureDllRoundTrip)
{
    input::Input::instance().shutdown();

    LoadedFixtureModule mod;
    ASSERT_TRUE(mod.load());

    const Address target_damage{reinterpret_cast<std::uintptr_t>(mod.compute_damage)};
    const Address target_armor{reinterpret_cast<std::uintptr_t>(mod.compute_armor)};

    {
        Result<Hook> r_damage = inline_at(InlineRequest{.name = "fixture_all_damage", .target = target_damage},
                                          &fixture_detour_compute_damage);
        ASSERT_TRUE(r_damage.has_value()) << r_damage.error().message();
        Hook h_damage = std::move(*r_damage);

        Result<Hook> r_armor = inline_at(InlineRequest{.name = "fixture_all_armor", .target = target_armor},
                                         &fixture_detour_compute_armor);
        ASSERT_TRUE(r_armor.has_value()) << r_armor.error().message();
        Hook h_armor = std::move(*r_armor);

        (void)input::register_combo(input::ComboBinding{.name = std::string{"fixture_all_bind"},
                                                        .trigger = input::Trigger::Press,
                                                        .combos = {{{keyboard_key(0x4C)}, {}}},
                                                        .on_press = []() {},
                                                        .on_state_change = {}});

        Bootstrap::on_logic_dll_unload_all();

        // The catch-all cleared the binding but left both caller-owned hooks live.
        EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));
        EXPECT_TRUE(static_cast<bool>(h_damage));
        EXPECT_TRUE(static_cast<bool>(h_armor));
        EXPECT_TRUE(is_target_hooked(target_damage));
        EXPECT_TRUE(is_target_hooked(target_armor));

        // Idempotency on the binding side.
        Bootstrap::on_logic_dll_unload_all();
        EXPECT_EQ(input::Input::instance().binding_count(), static_cast<size_t>(0));

        // Hook handles drop here: RAII restores the fixture prologues.
    }
    EXPECT_FALSE(is_target_hooked(target_damage));
    EXPECT_FALSE(is_target_hooked(target_armor));

    // Reload the fixture and re-hook strictly to confirm the restored prologue is hookable from a clean slate.
    mod.unload();
    ASSERT_TRUE(mod.load());
    Result<Hook> reload =
        inline_at(InlineRequest{.name = "fixture_all_damage_reloaded",
                                .target = Address{reinterpret_cast<std::uintptr_t>(mod.compute_damage)},
                                .options = Options{.fail_if_already_hooked = true}},
                  &fixture_detour_compute_damage);
    EXPECT_TRUE(reload.has_value()) << reload.error().message();
}

// Verifies that on_logic_dll_unload chains config::clear after the hook and binding teardown so
// registered std::function setters (whose call operator and destructor live in the unloading
// Logic DLL) cannot survive into a second attach as use-after-unload hazards.
//
// The verification path: a registered setter captures a shared_ptr by value, so the setter closure stored inside the
// registry holds a strong reference. While the registry retains the entry, use_count stays >= 2 (one local sentinel ref
// plus one inside the captured closure). Once the helper wipes the registry, the captured closure is destroyed and the
// local sentinel is the sole owner.
TEST(BootstrapOnLogicDllUnload, ClearsConfigRegisteredItems)
{
    input::Input::instance().shutdown();
    config::clear();

    auto sentinel = std::make_shared<int>(0);
    EXPECT_EQ(sentinel.use_count(), 1L);

    config::bind_string(
        "BootstrapUnloadCfgClear", "Key", "Bootstrap unload key",
        [sentinel](std::string_view) { /* keeps sentinel alive */ }, "default");

    // After registration the captured-by-value shared_ptr lives inside the setter closure stored in the Config
    // registry, so use_count includes both the local sentinel and the closure copy.
    EXPECT_GE(sentinel.use_count(), 2L);

    Bootstrap::on_logic_dll_unload({}, {});

    // The unload helper must have dropped the registry entry, releasing its captured copy of the sentinel. The local
    // variable is the only remaining owner.
    EXPECT_EQ(sentinel.use_count(), 1L);
}

TEST(BootstrapOnLogicDllUnloadAll, ClearsConfigRegisteredItems)
{
    input::Input::instance().shutdown();
    config::clear();

    auto sentinel = std::make_shared<int>(0);
    EXPECT_EQ(sentinel.use_count(), 1L);

    config::bind_string(
        "BootstrapUnloadAllCfgClear", "Key", "Bootstrap unload-all key",
        [sentinel](std::string_view) { /* keeps sentinel alive */ }, "default");
    EXPECT_GE(sentinel.use_count(), 2L);

    Bootstrap::on_logic_dll_unload_all();

    EXPECT_EQ(sentinel.use_count(), 1L);
}

namespace
{
    // Builds a temp INI and arms the auto-reload watcher over it. Returns the INI path so the caller can clean up.
    std::filesystem::path arm_auto_reload_watcher(std::string_view item_name)
    {
        const auto ini_path = std::filesystem::temp_directory_path() /
                              ("test_bootstrap_autoreload_" + std::to_string(GetCurrentProcessId()) + "_" +
                               std::string(item_name) + ".ini");
        {
            std::ofstream ofs(ini_path);
            ofs << "[Section]\nKey=1\n";
        }
        config::bind_int("Section", "Key", std::string(item_name), [](int) {}, 1);
        EXPECT_NO_THROW(config::load(ini_path.string()));
        EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started);
        return ini_path;
    }
} // namespace

// The hot-unload helpers must stop the Config auto-reload watcher before clearing the registry: the watcher's on_reload
// callback and the registered setters live in the unloading Logic DLL, so a survivor would call into unmapped pages and
// would also make the next attach's enable_auto_reload() report AlreadyRunning instead of starting fresh. A fresh
// Started after re-loading proves the watcher was stopped.
TEST(BootstrapOnLogicDllUnload, StopsAutoReloadWatcher)
{
    input::Input::instance().shutdown();
    config::clear();
    config::disable_auto_reload();

    const auto ini_path = arm_auto_reload_watcher("bootstrap_unload_watcher");

    Bootstrap::on_logic_dll_unload({}, {});

    config::bind_int("Section", "Key", "bootstrap_unload_watcher_2", [](int) {}, 1);
    EXPECT_NO_THROW(config::load(ini_path.string()));
    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started)
        << "on_logic_dll_unload must stop the auto-reload watcher; a survivor would report AlreadyRunning";

    config::disable_auto_reload();
    config::clear();
    if (std::filesystem::exists(ini_path))
    {
        std::filesystem::remove(ini_path);
    }
}

TEST(BootstrapOnLogicDllUnloadAll, StopsAutoReloadWatcher)
{
    input::Input::instance().shutdown();
    config::clear();
    config::disable_auto_reload();

    const auto ini_path = arm_auto_reload_watcher("bootstrap_unload_all_watcher");

    Bootstrap::on_logic_dll_unload_all();

    config::bind_int("Section", "Key", "bootstrap_unload_all_watcher_2", [](int) {}, 1);
    EXPECT_NO_THROW(config::load(ini_path.string()));
    EXPECT_EQ(config::enable_auto_reload(std::chrono::milliseconds{50}), config::AutoReloadStatus::Started)
        << "on_logic_dll_unload_all must stop the auto-reload watcher; a survivor would report AlreadyRunning";

    config::disable_auto_reload();
    config::clear();
    if (std::filesystem::exists(ini_path))
    {
        std::filesystem::remove(ini_path);
    }
}
