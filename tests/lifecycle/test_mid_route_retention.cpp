/**
 * @file test_mid_route_retention.cpp
 * @brief Verifies route reclamation through a process-wide VirtualQuery census and retention counters.
 * @details The exit code reports the result. docs/design/hooking.md owns the contract under "Clean x64 mid teardown".
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"

#include <safetyhook/inline_hook.hpp>
#include <safetyhook/os.hpp>

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace DetourModKit::detail
{
    extern void (*g_logger_record_probe)(LogLevel, std::string_view) noexcept;
} // namespace DetourModKit::detail

namespace
{
#if defined(_MSC_VER)
#define DMK_PROOF_NOINLINE __declspec(noinline)
#else
#define DMK_PROOF_NOINLINE __attribute__((noinline))
#endif

    constexpr int CYCLES = 5;
    constexpr int HOOKS = 6;
    constexpr int PARK_VALUE = 41;
    constexpr int CALLEE_VALUE = 7;
    // The pinned numbers assume the Windows x64 allocation granularity: the backend rounds every block to it.
    constexpr std::uint64_t BLOCK_BYTES = 0x10000;
    // A retained x64 mid chain stays charged at three granules: stub block, trampoline block, and gateway block.
    constexpr std::uint64_t CHARGED_BYTES_PER_CHAIN = 3 * BLOCK_BYTES;

    volatile int s_sink = 0;
    volatile int s_mid_hits = 0;
    volatile int s_inline_hits = 0;

    // docs/design/testing.md owns the private-section rule. Distinct seeds prevent code folding, and volatile work
    // preserves enough prologue bytes for either patch form. Unsigned arithmetic avoids overflow.
#if defined(_MSC_VER)
#pragma code_seg(push, ".proof")
#define DMK_PROOF_TARGET DMK_PROOF_NOINLINE
#else
#define DMK_PROOF_TARGET __attribute__((section(".proof"))) DMK_PROOF_NOINLINE
#endif
#define DMK_ROUTE_TARGET(NAME, SEED)                                                                                   \
    DMK_PROOF_TARGET int NAME(int value)                                                                               \
    {                                                                                                                  \
        constexpr std::uint32_t SEED_VALUE = static_cast<std::uint32_t>(SEED);                                         \
        volatile std::uint32_t accumulator = static_cast<std::uint32_t>(value) * SEED_VALUE;                           \
        for (std::uint32_t i = 0; i < 8; ++i)                                                                          \
        {                                                                                                              \
            accumulator = accumulator + ((accumulator >> 3) ^ (i * SEED_VALUE));                                       \
            accumulator = accumulator ^ (accumulator << 5);                                                            \
        }                                                                                                              \
        const int bounded = static_cast<int>(accumulator & 0xFFFFu);                                                   \
        s_sink = bounded;                                                                                              \
        return bounded + (SEED);                                                                                       \
    }
    DMK_ROUTE_TARGET(route_target_3, 3)
    DMK_ROUTE_TARGET(route_target_5, 5)
    DMK_ROUTE_TARGET(route_target_7, 7)
    DMK_ROUTE_TARGET(route_target_11, 11)
    DMK_ROUTE_TARGET(route_target_13, 13)
    DMK_ROUTE_TARGET(route_target_17, 17)
#undef DMK_ROUTE_TARGET
#undef DMK_PROOF_TARGET
#if defined(_MSC_VER)
#pragma code_seg(pop)
#endif

    template <int Seed> int route_inline_detour(int value)
    {
        s_inline_hits = s_inline_hits + 1;
        return value + Seed;
    }

    void route_mid_detour(DetourModKit::hook::MidContext &) noexcept
    {
        s_mid_hits = s_mid_hits + 1;
    }

    using TargetFn = int (*)(int);

    constexpr TargetFn TARGETS[HOOKS] = {
        &route_target_3,
        &route_target_5,
        &route_target_7,
        &route_target_11,
        &route_target_13,
        &route_target_17,
    };

    constexpr TargetFn INLINE_DETOURS[HOOKS] = {
        &route_inline_detour<3>,
        &route_inline_detour<5>,
        &route_inline_detour<7>,
        &route_inline_detour<11>,
        &route_inline_detour<13>,
        &route_inline_detour<17>,
    };

    constexpr int SEEDS[HOOKS] = {3, 5, 7, 11, 13, 17};

    /// Calls through a volatile indirection so the optimizer cannot fold the call past the patched entry.
    int call_unfolded(TargetFn function, int value)
    {
        TargetFn const volatile indirect = function;
        return indirect(value);
    }

    struct ExecutableWalk
    {
        std::uint64_t bytes{0};
        std::uint64_t regions{0};
        std::uint64_t block_regions{0};
    };

    /// Sums every committed private region with an execute protection over the whole user address space.
    ExecutableWalk walk_private_executable()
    {
        ExecutableWalk out{};
        SYSTEM_INFO system_info{};
        GetSystemInfo(&system_info);
        const auto max_address = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);
        constexpr DWORD EXECUTE_MASK =
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        std::uintptr_t cursor = 0;
        MEMORY_BASIC_INFORMATION info{};
        while (cursor < max_address)
        {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info)) == 0)
            {
                break;
            }
            if (info.State == MEM_COMMIT && info.Type == MEM_PRIVATE && (info.Protect & EXECUTE_MASK) != 0)
            {
                out.bytes += info.RegionSize;
                out.regions += 1;
                if (info.RegionSize == BLOCK_BYTES)
                {
                    out.block_regions += 1;
                }
            }
            const std::uintptr_t next = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
            if (next <= cursor)
            {
                break;
            }
            cursor = next;
        }
        return out;
    }

    std::size_t leak_count()
    {
        namespace diagnostics = DetourModKit::diagnostics;
        return diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    }

    // The callee keeps a trampoline return address on the stack while its instruction pointer stays outside the route.
    std::atomic<bool> s_callee_hold{false};
    std::atomic<bool> s_callee_entered{false};
    std::atomic<DetourModKit::hook::HookStack *> s_teardown_from_callee{nullptr};

    DMK_PROOF_NOINLINE int call_site_callee()
    {
        s_callee_entered.store(true, std::memory_order_release);
        while (s_callee_hold.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        // The callee retires the hook itself: the calling thread still has to return into the trampoline.
        if (DetourModKit::hook::HookStack *const stack = s_teardown_from_callee.exchange(nullptr))
        {
            stack->clear();
        }
        return CALLEE_VALUE;
    }

    /// Writes a target whose first patch window ends inside a call into a fresh executable page.
    std::uint8_t *make_call_site_target()
    {
        constexpr std::size_t PAGE_BYTES = 4096;
        auto *const page = static_cast<std::uint8_t *>(
            VirtualAlloc(nullptr, PAGE_BYTES, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        );
        if (page == nullptr)
        {
            return nullptr;
        }
        // The 40-byte frame supplies shadow space and alignment. The five-byte patch window intersects the call.
        constexpr std::uint8_t CODE[] =
            {0x48, 0x83, 0xEC, 0x28, 0xFF, 0x15, 0x06, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xCC};
        std::memcpy(page, CODE, sizeof(CODE));

        // This leaf homes all four registers before a tail jump. An undersized caller frame corrupts its return
        // address.
        constexpr std::size_t home_offset = 32;
        constexpr std::uint8_t home_register_code[] = {
            0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10, 0x4C, 0x89, 0x44,
            0x24, 0x18, 0x4C, 0x89, 0x4C, 0x24, 0x20, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        };
        const auto home_registers = reinterpret_cast<std::uintptr_t>(page + home_offset);
        std::memcpy(page + sizeof(CODE), &home_registers, sizeof(home_registers));
        std::memcpy(page + home_offset, home_register_code, sizeof(home_register_code));
        const auto callee = reinterpret_cast<std::uintptr_t>(&call_site_callee);
        std::memcpy(page + home_offset + sizeof(home_register_code), &callee, sizeof(callee));
        FlushInstructionCache(GetCurrentProcess(), page, PAGE_BYTES);
        return page;
    }

    /// Waits until the helper is inside the callee, with a deadline so a lost call fails instead of hangs.
    bool wait_for_callee()
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
        while (!s_callee_entered.load(std::memory_order_acquire))
        {
            if (std::chrono::steady_clock::now() > deadline)
            {
                return false;
            }
            std::this_thread::yield();
        }
        return true;
    }

    enum class Kind
    {
        PublishedMid,
        PublishedInline,
        NeverEnabledMid
    };

    const char *kind_name(Kind kind)
    {
        switch (kind)
        {
        case Kind::PublishedMid:
            return "published mid";
        case Kind::PublishedInline:
            return "published inline";
        case Kind::NeverEnabledMid:
            return "never-enabled mid";
        }
        return "?";
    }

    DetourModKit::Result<DetourModKit::hook::Hook> install(Kind kind, const std::string &name, int index)
    {
        const DetourModKit::Address target{reinterpret_cast<std::uintptr_t>(TARGETS[index])};
        if (kind == Kind::PublishedInline)
        {
            return DetourModKit::hook::inline_at(
                DetourModKit::hook::InlineRequest{
                    .name = name,
                    .target = target,
                },
                INLINE_DETOURS[index]
            );
        }
        return DetourModKit::hook::mid_at(
            DetourModKit::hook::MidRequest{
                .name = name,
                .target = target,
            },
            &route_mid_detour
        );
    }

    void print_walk(const char *label, const ExecutableWalk &walk)
    {
        std::printf(
            "  %s: bytes=%llu regions=%llu block_regions=%llu\n",
            label,
            static_cast<unsigned long long>(walk.bytes),
            static_cast<unsigned long long>(walk.regions),
            static_cast<unsigned long long>(walk.block_regions)
        );
    }

    /// Installs six hooks, drives them, tears them down, and returns a nonzero step code on the first failure.
    int run_cycle(Kind kind, int cycle)
    {
        DetourModKit::hook::HookStack stack;
        for (int i = 0; i < HOOKS; ++i)
        {
            const std::string name =
                std::string{kind_name(kind)} + " " + std::to_string(cycle) + "/" + std::to_string(i);
            DetourModKit::Result<DetourModKit::hook::Hook> created = install(kind, name, i);
            if (!created)
            {
                std::fprintf(
                    stderr,
                    "FAIL: install of '%s' refused: %s\n",
                    name.c_str(),
                    created.error().message().c_str()
                );
                return 1;
            }
            DetourModKit::hook::Hook &held = stack.push(std::move(*created));
            if (kind != Kind::NeverEnabledMid)
            {
                if (const DetourModKit::Result<void> enabled = held.enable(); !enabled)
                {
                    std::fprintf(
                        stderr,
                        "FAIL: enable of '%s' refused: %s\n",
                        name.c_str(),
                        enabled.error().message().c_str()
                    );
                    return 2;
                }
            }
        }
        s_mid_hits = 0;
        s_inline_hits = 0;
        for (int i = 0; i < HOOKS; ++i)
        {
            const int observed = call_unfolded(TARGETS[i], cycle + i);
            if (kind == Kind::PublishedInline && observed != cycle + i + SEEDS[i])
            {
                std::fprintf(stderr, "FAIL: inline hook %d did not route the call (returned %d)\n", i, observed);
                return 3;
            }
        }
        const int expected_mid_hits = kind == Kind::PublishedMid ? HOOKS : 0;
        const int expected_inline_hits = kind == Kind::PublishedInline ? HOOKS : 0;
        if (s_mid_hits != expected_mid_hits || s_inline_hits != expected_inline_hits)
        {
            std::fprintf(
                stderr,
                "FAIL: %s cycle %d saw %d mid hits and %d inline hits\n",
                kind_name(kind),
                cycle,
                static_cast<int>(s_mid_hits),
                static_cast<int>(s_inline_hits)
            );
            return 4;
        }
        stack.clear();
        return 0;
    }

    /// Runs the cycles of one scenario. Every kind must leave the executable walk and the route charge unchanged.
    int run_scenario(Kind kind, int base_code)
    {
        std::printf("%s: %d cycles x %d hooks\n", kind_name(kind), CYCLES, HOOKS);
        for (int cycle = 1; cycle <= CYCLES; ++cycle)
        {
            const ExecutableWalk before = walk_private_executable();
            const safetyhook::RouteRetentionStats charged_before = safetyhook::route_retention_stats();
            if (const int step = run_cycle(kind, cycle); step != 0)
            {
                return base_code + step;
            }
            const ExecutableWalk after = walk_private_executable();
            const safetyhook::RouteRetentionStats charged_after = safetyhook::route_retention_stats();
            print_walk("after cycle", after);

            if (after.bytes != before.bytes || after.regions != before.regions ||
                after.block_regions != before.block_regions)
            {
                std::fprintf(
                    stderr,
                    "FAIL: %s cycle %d changed the executable walk by %lld bytes and %lld regions\n",
                    kind_name(kind),
                    cycle,
                    static_cast<long long>(after.bytes) - static_cast<long long>(before.bytes),
                    static_cast<long long>(after.regions) - static_cast<long long>(before.regions)
                );
                return base_code + 5;
            }
            if (charged_after.committed_charged != charged_before.committed_charged ||
                charged_after.logical_charged != charged_before.logical_charged)
            {
                std::fprintf(
                    stderr,
                    "FAIL: %s cycle %d changed the committed charge by %lld bytes\n",
                    kind_name(kind),
                    cycle,
                    static_cast<long long>(charged_after.committed_charged) -
                        static_cast<long long>(charged_before.committed_charged)
                );
                return base_code + 6;
            }
            if (charged_after.committed_reserved != 0 || charged_after.refusals != 0)
            {
                std::fprintf(
                    stderr,
                    "FAIL: %s cycle %d left %llu committed bytes reserved and %llu refusals\n",
                    kind_name(kind),
                    cycle,
                    static_cast<unsigned long long>(charged_after.committed_reserved),
                    static_cast<unsigned long long>(charged_after.refusals)
                );
                return base_code + 7;
            }
        }
        return 0;
    }

    /// Waits until the armed park is reached, with a deadline so a lost park fails instead of hangs.
    bool wait_for_park()
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
        while (!safetyhook::route_park_reached_for_test())
        {
            if (std::chrono::steady_clock::now() > deadline)
            {
                return false;
            }
            std::this_thread::yield();
        }
        return true;
    }

    std::uintptr_t s_warning_target{0};
    int s_retention_warnings{0};
    bool s_warning_after_release{true};

    /**
     * @brief Observes the ledger state when the retained-route warning reaches the logger.
     */
    void observe_retention_warning(DetourModKit::LogLevel level, std::string_view message) noexcept
    {
        if (level == DetourModKit::LogLevel::Warning &&
            message.find("retained its published route chain") != std::string_view::npos)
        {
            ++s_retention_warnings;
            s_warning_after_release = !DetourModKit::hook::is_target_hooked(DetourModKit::Address{s_warning_target}) &&
                                      s_warning_after_release;
        }
    }

    /**
     * @brief Installs @p layers published mid hooks on one target, parks a helper at the newest gateway entry, tears
     *        every layer down, and asserts that each layer retained exactly one block.
     * @details The helper sits before the entry increment, where only the instruction-pointer scan can see it. After
     *          the park releases it must complete through every bypass with the unhooked result, and no callback
     *          runs.
     */
    int run_parked_scenario(int layers, int target_index, int base_code)
    {
        std::printf("parked mid: %d layer(s) on one target, helper parked at the newest gateway entry\n", layers);
        const int expected_unhooked = call_unfolded(TARGETS[target_index], PARK_VALUE);
        const ExecutableWalk before = walk_private_executable();
        const safetyhook::RouteRetentionStats charged_before = safetyhook::route_retention_stats();
        const std::size_t leaks_before = leak_count();

        DetourModKit::hook::HookStack stack;
        for (int layer = 0; layer < layers; ++layer)
        {
            const std::string name = "parked mid layer " + std::to_string(layer);
            DetourModKit::Result<DetourModKit::hook::Hook> created = install(Kind::PublishedMid, name, target_index);
            if (!created)
            {
                std::fprintf(
                    stderr,
                    "FAIL: install of '%s' refused: %s\n",
                    name.c_str(),
                    created.error().message().c_str()
                );
                return base_code + 1;
            }
            DetourModKit::hook::Hook &held = stack.push(std::move(*created));
            if (const DetourModKit::Result<void> enabled = held.enable(); !enabled)
            {
                std::fprintf(
                    stderr,
                    "FAIL: enable of '%s' refused: %s\n",
                    name.c_str(),
                    enabled.error().message().c_str()
                );
                return base_code + 2;
            }
        }

        s_mid_hits = 0;
        safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::AT_ENTRY);
        std::atomic<int> observed{0};
        std::thread helper{[&observed, target_index]
                           { observed.store(call_unfolded(TARGETS[target_index], PARK_VALUE)); }};
        const bool reached = wait_for_park();
        if (!reached)
        {
            safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
            helper.join();
            std::fprintf(stderr, "FAIL: the helper never reached the gateway entry park\n");
            return base_code + 3;
        }

        // Newest first, with the helper parked. Every layer must retain: the newest holds the helper, and each older
        // one is still reachable from the retained newer trampoline.
        const auto previous_probe = DetourModKit::detail::g_logger_record_probe;
        const auto previous_level = DetourModKit::log().get_log_level();
        if (layers == 1)
        {
            s_warning_target = reinterpret_cast<std::uintptr_t>(TARGETS[target_index]);
            s_retention_warnings = 0;
            s_warning_after_release = true;
            DetourModKit::log().set_log_level(DetourModKit::LogLevel::Warning);
            DetourModKit::detail::g_logger_record_probe = &observe_retention_warning;
        }
        stack.clear();
        DetourModKit::detail::g_logger_record_probe = previous_probe;
        DetourModKit::log().set_log_level(previous_level);

        safetyhook::set_route_park_for_test(safetyhook::RouteParkStage::NONE);
        helper.join();

        if (layers == 1 && (s_retention_warnings != 1 || !s_warning_after_release))
        {
            std::fputs("FAIL: retained-route warning precedes ledger release or is missing\n", stderr);
            return base_code + 8;
        }
        const ExecutableWalk after = walk_private_executable();
        const safetyhook::RouteRetentionStats charged_after = safetyhook::route_retention_stats();
        print_walk("after parked teardown", after);
        const auto expected_regions = static_cast<std::uint64_t>(layers);
        if (after.bytes - before.bytes != expected_regions * BLOCK_BYTES ||
            after.regions - before.regions != expected_regions ||
            after.block_regions - before.block_regions != expected_regions)
        {
            std::fprintf(
                stderr,
                "FAIL: the parked teardown retained %llu bytes in %llu regions, expected %llu region(s) of one "
                "granule\n",
                static_cast<unsigned long long>(after.bytes - before.bytes),
                static_cast<unsigned long long>(after.regions - before.regions),
                static_cast<unsigned long long>(expected_regions)
            );
            return base_code + 4;
        }
        if (charged_after.committed_charged - charged_before.committed_charged !=
            expected_regions * CHARGED_BYTES_PER_CHAIN)
        {
            std::fprintf(
                stderr,
                "FAIL: the parked teardown left %llu committed bytes charged, expected %llu\n",
                static_cast<unsigned long long>(charged_after.committed_charged - charged_before.committed_charged),
                static_cast<unsigned long long>(expected_regions * CHARGED_BYTES_PER_CHAIN)
            );
            return base_code + 5;
        }
        if (leak_count() - leaks_before != static_cast<std::size_t>(layers))
        {
            std::fprintf(
                stderr,
                "FAIL: the parked teardown booked %zu HookManager leaks, expected %d\n",
                leak_count() - leaks_before,
                layers
            );
            return base_code + 6;
        }
        if (observed.load() != expected_unhooked || s_mid_hits != 0)
        {
            std::fprintf(
                stderr,
                "FAIL: the parked call returned %d with %d callback hits, expected %d and none\n",
                observed.load(),
                static_cast<int>(s_mid_hits),
                expected_unhooked
            );
            return base_code + 7;
        }
        return 0;
    }

    /// How one call-site teardown is driven, and whether the chain must survive it.
    enum class CallSiteMode
    {
        HelperInsideCallee,
        Idle,
        TeardownFromCallee
    };

    const char *call_site_mode_name(CallSiteMode mode)
    {
        switch (mode)
        {
        case CallSiteMode::HelperInsideCallee:
            return "helper inside the callee at teardown, retained";
        case CallSiteMode::Idle:
            return "no thread inside or returning, reclaimed";
        case CallSiteMode::TeardownFromCallee:
            return "torn down by the callee itself, retained";
        }
        return "?";
    }

    /**
     * @brief Verifies route lifetime for a relocated call under @p mode.
     * @param page Generated target that exercises every Windows x64 parameter home slot.
     * @param mode Selects helper-thread, idle, or self-thread teardown.
     * @param base_code First failure code for this scenario.
     */
    int run_call_site_mode(std::uint8_t *page, CallSiteMode mode, int base_code)
    {
        std::printf("call-site mid: %s\n", call_site_mode_name(mode));
        const auto target = reinterpret_cast<TargetFn>(page);
        const bool retains = mode != CallSiteMode::Idle;
        const ExecutableWalk before = walk_private_executable();
        const safetyhook::RouteRetentionStats charged_before = safetyhook::route_retention_stats();
        const std::size_t leaks_before = leak_count();

        int observed = 0;
        {
            DetourModKit::hook::HookStack stack;
            const DetourModKit::Address target_address{reinterpret_cast<std::uintptr_t>(page)};
            DetourModKit::Result<DetourModKit::hook::Hook> created = DetourModKit::hook::mid_at(
                DetourModKit::hook::MidRequest{
                    .name = "call-site mid",
                    .target = target_address,
                },
                &route_mid_detour
            );
            if (!created)
            {
                std::fprintf(
                    stderr,
                    "FAIL: install of the call-site hook refused: %s\n",
                    created.error().message().c_str()
                );
                return base_code + 1;
            }
            DetourModKit::hook::Hook &held = stack.push(std::move(*created));
            if (const DetourModKit::Result<void> enabled = held.enable(); !enabled)
            {
                std::fprintf(
                    stderr,
                    "FAIL: enable of the call-site hook refused: %s\n",
                    enabled.error().message().c_str()
                );
                return base_code + 2;
            }

            s_mid_hits = 0;
            s_callee_entered.store(false, std::memory_order_relaxed);
            s_callee_hold.store(mode == CallSiteMode::HelperInsideCallee, std::memory_order_release);
            s_teardown_from_callee.store(mode == CallSiteMode::TeardownFromCallee ? &stack : nullptr);
            std::atomic<int> helper_result{0};
            std::thread helper{[&helper_result, target] { helper_result.store(call_unfolded(target, 0)); }};
            if (mode == CallSiteMode::HelperInsideCallee)
            {
                if (!wait_for_callee())
                {
                    s_callee_hold.store(false, std::memory_order_release);
                    helper.join();
                    std::fprintf(stderr, "FAIL: the helper never reached the callee\n");
                    return base_code + 3;
                }
                // The helper's instruction pointer is in call_site_callee and its return address is in the trampoline.
                stack.clear();
                s_callee_hold.store(false, std::memory_order_release);
            }
            helper.join();
            observed = helper_result.load();
            if (mode == CallSiteMode::Idle)
            {
                // The helper is gone, so no thread is inside the chain or still returning into it.
                stack.clear();
            }
        }

        const ExecutableWalk after = walk_private_executable();
        const safetyhook::RouteRetentionStats charged_after = safetyhook::route_retention_stats();
        print_walk("after call-site teardown", after);
        const std::uint64_t expected_regions = retains ? 1 : 0;
        if (after.bytes - before.bytes != expected_regions * BLOCK_BYTES ||
            after.regions - before.regions != expected_regions ||
            after.block_regions - before.block_regions != expected_regions)
        {
            std::fprintf(
                stderr,
                "FAIL: the call-site teardown retained %llu bytes in %llu regions, expected %llu granule(s)\n",
                static_cast<unsigned long long>(after.bytes - before.bytes),
                static_cast<unsigned long long>(after.regions - before.regions),
                static_cast<unsigned long long>(expected_regions)
            );
            return base_code + 4;
        }
        if (charged_after.committed_charged - charged_before.committed_charged !=
            expected_regions * CHARGED_BYTES_PER_CHAIN)
        {
            std::fprintf(
                stderr,
                "FAIL: the call-site teardown left %llu committed bytes charged, expected %llu\n",
                static_cast<unsigned long long>(charged_after.committed_charged - charged_before.committed_charged),
                static_cast<unsigned long long>(expected_regions * CHARGED_BYTES_PER_CHAIN)
            );
            return base_code + 5;
        }
        if (leak_count() - leaks_before != static_cast<std::size_t>(expected_regions))
        {
            std::fprintf(
                stderr,
                "FAIL: the call-site teardown booked %zu HookManager leaks, expected %llu\n",
                leak_count() - leaks_before,
                static_cast<unsigned long long>(expected_regions)
            );
            return base_code + 6;
        }
        if (observed != CALLEE_VALUE || s_mid_hits != 1)
        {
            std::fprintf(
                stderr,
                "FAIL: the call through the trampoline returned %d with %d callback hits, expected %d and 1\n",
                observed,
                static_cast<int>(s_mid_hits),
                CALLEE_VALUE
            );
            return base_code + 7;
        }
        return 0;
    }

    /**
     * @brief Verifies one-way relocation through the live handler with both map representations.
     */
    int run_trap_mapping()
    {
        auto *const pages =
            static_cast<std::uint8_t *>(VirtualAlloc(nullptr, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (pages == nullptr)
        {
            return 2;
        }
        std::uint8_t *const original = pages;
        std::uint8_t *const trampoline = pages + 4096;
        constexpr safetyhook::InstructionBoundary boundaries[] = {
            {0, 0},
            {2, 6},
            {4, 8},
        };
        bool passed = true;
        for (const bool mapped : {false, true})
        {
            for (const bool enable : {false, true})
            {
                const auto check = [&]() -> void
                {
                    for (const bool from_original : {false, true})
                    {
                        for (const auto &boundary : boundaries)
                        {
                            const std::size_t to_offset =
                                mapped ? boundary.trampoline_offset : boundary.original_offset;
                            std::uint8_t *const source =
                                from_original ? original + boundary.original_offset : trampoline + to_offset;
                            std::uint8_t *const expected =
                                from_original == enable
                                    ? (enable ? trampoline + to_offset : original + boundary.original_offset)
                                    : source;
                            CONTEXT context{};
                            context.Rip = reinterpret_cast<DWORD64>(source);
                            context.Rax = 0x1234;
                            context.EFlags = 0x246;
                            passed = safetyhook::dispatch_trap_fault_for_test(&context, source) && passed;
                            passed = context.Rip == reinterpret_cast<DWORD64>(expected) && context.Rax == 0x1234 &&
                                     context.EFlags == 0x246 && passed;
                        }
                    }
                };
                const auto result = safetyhook::trap_threads(
                    original,
                    trampoline,
                    6,
                    10,
                    mapped ? std::span<const safetyhook::InstructionBoundary>{boundaries}
                           : std::span<const safetyhook::InstructionBoundary>{},
                    check,
                    enable ? safetyhook::TrapDirection::ORIGINAL_TO_TRAMPOLINE
                           : safetyhook::TrapDirection::TRAMPOLINE_TO_ORIGINAL
                );
                passed = result.has_value() && passed;
            }
        }
        VirtualFree(pages, 0, MEM_RELEASE);

        auto created =
            safetyhook::InlineHook::create(TARGETS[0], INLINE_DETOURS[0], safetyhook::InlineHook::StartDisabled);
        if (!created)
        {
            return 3;
        }
        auto *const target = reinterpret_cast<std::uint8_t *>(TARGETS[0]);
        auto *const relocated = created->trampoline().data();
        for (const bool enable : {true, false})
        {
            safetyhook::g_trap_transaction_reached.store(false);
            safetyhook::g_trap_transaction_hold.store(true);
            bool toggled = false;
            std::thread worker{
                [&created, &toggled, enable]() -> void
                {
                    try
                    {
                        toggled = (enable ? created->enable() : created->disable()).has_value();
                    }
                    catch (...)
                    {
                        toggled = false;
                    }
                }
            };
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
            while (!safetyhook::g_trap_transaction_reached.load() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::yield();
            }
            const bool reached = safetyhook::g_trap_transaction_reached.load();
            if (reached)
            {
                for (const bool from_original : {false, true})
                {
                    std::uint8_t *const source = from_original ? target : relocated;
                    std::uint8_t *const expected = enable ? relocated : target;
                    CONTEXT context{};
                    context.Rip = reinterpret_cast<DWORD64>(source);
                    passed = safetyhook::dispatch_trap_fault_for_test(&context, source) && passed;
                    passed = context.Rip == reinterpret_cast<DWORD64>(expected) && passed;
                }
            }
            safetyhook::g_trap_transaction_hold.store(false);
            worker.join();
            passed = reached && toggled && passed;
        }
        std::puts(
            passed ? "PASS: each trap fault preserves the patch direction and maps once"
                   : "FAIL: a trap fault reverses or violates the patch direction"
        );
        return passed ? 0 : 4;
    }

    /**
     * @brief Verifies that a destroy lock failure retains route storage and charges it once.
     */
    int run_destroy_lock_failure()
    {
        for (const bool published : {false, true})
        {
            auto created = safetyhook::InlineHook::create(
                TARGETS[0],
                INLINE_DETOURS[0],
                static_cast<safetyhook::InlineHook::Flags>(
                    safetyhook::InlineHook::StartDisabled | safetyhook::InlineHook::RoutedExternal
                )
            );
            if (!created || (published && !created->enable()))
            {
                return 2;
            }
            const auto before = safetyhook::route_retention_stats();
            const auto *const gateway = created->route_region_for_test(0);
            const auto *const trampoline = created->trampoline().data();
            safetyhook::g_destroy_lock_failure_target.store(reinterpret_cast<std::uint8_t *>(TARGETS[0]));
            created->reset();
            const auto after = safetyhook::route_retention_stats();
            MEMORY_BASIC_INFORMATION gateway_info{};
            MEMORY_BASIC_INFORMATION trampoline_info{};
            if (!created->route_retained() || safetyhook::g_destroy_lock_failure_target.load() != nullptr ||
                VirtualQuery(gateway, &gateway_info, sizeof(gateway_info)) != sizeof(gateway_info) ||
                gateway_info.State != MEM_COMMIT ||
                VirtualQuery(trampoline, &trampoline_info, sizeof(trampoline_info)) != sizeof(trampoline_info) ||
                trampoline_info.State != MEM_COMMIT || after.committed_charged == 0 ||
                (published && after.committed_charged != before.committed_charged) ||
                (!published && after.committed_charged <= before.committed_charged))
            {
                std::fputs("FAIL: destroy lock failure lost route storage or its charge\n", stderr);
                return 3;
            }
            created->reset();
            if (safetyhook::route_retention_stats().committed_charged != after.committed_charged)
            {
                return 4;
            }
        }
        std::puts("PASS: destroy lock failure retains published and unpublished routes without a duplicate charge");
        return 0;
    }

    /// Runs the three call-site teardowns on one generated target.
    int run_call_site_scenario(int base_code)
    {
        std::uint8_t *const page = make_call_site_target();
        if (page == nullptr)
        {
            std::fprintf(stderr, "FAIL: no executable page for the call-site target\n");
            return base_code + 1;
        }
        const auto target = reinterpret_cast<TargetFn>(page);
        if (const int unhooked = call_unfolded(target, 0); unhooked != CALLEE_VALUE)
        {
            std::fprintf(stderr, "FAIL: the generated call-site target returned %d before any hook\n", unhooked);
            return base_code + 2;
        }
        int code = run_call_site_mode(page, CallSiteMode::HelperInsideCallee, base_code + 10);
        if (code == 0)
        {
            code = run_call_site_mode(page, CallSiteMode::Idle, base_code + 20);
        }
        if (code == 0)
        {
            code = run_call_site_mode(page, CallSiteMode::TeardownFromCallee, base_code + 30);
        }
        VirtualFree(page, 0, MEM_RELEASE);
        return code;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc == 2)
    {
        const std::string_view scenario{argv[1]};
        if (scenario == "trap-mapping")
        {
            return run_trap_mapping();
        }
        if (scenario == "destroy-lock-failure")
        {
            return run_destroy_lock_failure();
        }
        return 2;
    }
    if (argc != 1)
    {
        return 2;
    }
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    if (system_info.dwAllocationGranularity != BLOCK_BYTES)
    {
        std::fprintf(
            stderr,
            "FAIL: allocation granularity is %lu, the pinned numbers assume 0x10000\n",
            static_cast<unsigned long>(system_info.dwAllocationGranularity)
        );
        return 10;
    }

    // One throwaway inline hook constructs the process-lifetime DMK and backend statics. The baseline walk then
    // already holds them, so every scenario's delta is retention alone.
    if (const int step = run_cycle(Kind::PublishedInline, 0); step != 0)
    {
        return 10 + step;
    }
    print_walk("baseline", walk_private_executable());

    if (const int code = run_scenario(Kind::PublishedMid, 20); code != 0)
    {
        return code;
    }
    if (const int code = run_scenario(Kind::PublishedInline, 30); code != 0)
    {
        return code;
    }
    if (const int code = run_scenario(Kind::NeverEnabledMid, 40); code != 0)
    {
        return code;
    }
    if (const int code = run_parked_scenario(1, 0, 50); code != 0)
    {
        return code;
    }
    if (const int code = run_parked_scenario(2, 1, 60); code != 0)
    {
        return code;
    }
    if (const int code = run_call_site_scenario(80); code != 0)
    {
        return code;
    }

    // One block per parked layer, two for the call-site teardowns with a thread still returning, and nothing else.
    const std::size_t leaks = leak_count();
    if (leaks != 5)
    {
        std::fprintf(stderr, "FAIL: the run booked %zu HookManager leaks, expected exactly 5\n", leaks);
        return 70;
    }
    std::puts("PASS: a published mid hook reclaims its route chain unless a thread is parked inside it");
    return 0;
}
