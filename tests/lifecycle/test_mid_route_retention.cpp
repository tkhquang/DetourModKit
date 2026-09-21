/**
 * @file test_mid_route_retention.cpp
 * @brief Pins the measured route retention of a published x64 mid hook: one allocation-granularity executable block
 *        per hook per install cycle, for the process lifetime.
 * @details Only a host-side VirtualQuery walk sees the retention. The backend counters are per linked copy and die with
 *          the image. Five cycles of six published mid hooks must each add six private executable regions of exactly
 *          one allocation granularity. route_retention_stats() must charge three granules per hook. Six inline
 *          hooks and six never-enabled mid hooks change nothing. The exit code is the oracle, so a retention change in
 *          either direction is a decision (docs/design/hooking.md, "Clean x64 mid teardown").
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"

#include <safetyhook/inline_hook.hpp>

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>

namespace
{
#if defined(_MSC_VER)
#define DMK_PROOF_NOINLINE __declspec(noinline)
#else
#define DMK_PROOF_NOINLINE __attribute__((noinline))
#endif

    constexpr int CYCLES = 5;
    constexpr int HOOKS = 6;
    // The pinned numbers assume the Windows x64 allocation granularity: the backend rounds every block to it.
    constexpr std::uint64_t BLOCK_BYTES = 0x10000;
    constexpr std::uint64_t RETAINED_BYTES_PER_CYCLE = static_cast<std::uint64_t>(HOOKS) * BLOCK_BYTES;
    // A complete x64 mid chain charges at most three granules: stub block, trampoline block, and gateway block.
    constexpr std::uint64_t CHARGED_BYTES_PER_CYCLE = static_cast<std::uint64_t>(HOOKS) * 3 * BLOCK_BYTES;

    volatile int s_sink = 0;
    volatile int s_mid_hits = 0;
    volatile int s_inline_hits = 0;

    // Six distinct targets. The seed keeps the bodies distinct so no optimizer folds them, and the volatile work keeps
    // each prologue long enough for either backend patch form.
    template <int Seed> DMK_PROOF_NOINLINE int route_target(int value)
    {
        volatile int accumulator = value * Seed;
        for (int i = 0; i < 8; ++i)
        {
            accumulator = accumulator + ((accumulator >> 3) ^ (i * Seed));
            accumulator = accumulator ^ (accumulator << 5);
        }
        s_sink = accumulator;
        return accumulator + Seed;
    }

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
        &route_target<3>,
        &route_target<5>,
        &route_target<7>,
        &route_target<11>,
        &route_target<13>,
        &route_target<17>,
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

    /// Runs the cycles of one scenario and asserts the per-cycle deltas the scenario pins.
    int run_scenario(Kind kind, int base_code)
    {
        std::printf("%s: %d cycles x %d hooks\n", kind_name(kind), CYCLES, HOOKS);
        const bool retains = kind == Kind::PublishedMid;
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

            const std::uint64_t expected_bytes = retains ? RETAINED_BYTES_PER_CYCLE : 0;
            const std::uint64_t expected_regions = retains ? HOOKS : 0;
            const std::uint64_t expected_charged = retains ? CHARGED_BYTES_PER_CYCLE : 0;
            if (after.bytes - before.bytes != expected_bytes)
            {
                std::fprintf(
                    stderr,
                    "FAIL: %s cycle %d retained %llu executable bytes, expected %llu\n",
                    kind_name(kind),
                    cycle,
                    static_cast<unsigned long long>(after.bytes - before.bytes),
                    static_cast<unsigned long long>(expected_bytes)
                );
                return base_code + 5;
            }
            if (after.regions - before.regions != expected_regions ||
                after.block_regions - before.block_regions != expected_regions)
            {
                std::fprintf(
                    stderr,
                    "FAIL: %s cycle %d retained %llu regions (%llu of one granule), expected %llu\n",
                    kind_name(kind),
                    cycle,
                    static_cast<unsigned long long>(after.regions - before.regions),
                    static_cast<unsigned long long>(after.block_regions - before.block_regions),
                    static_cast<unsigned long long>(expected_regions)
                );
                return base_code + 6;
            }
            if (charged_after.committed_charged - charged_before.committed_charged != expected_charged)
            {
                std::fprintf(
                    stderr,
                    "FAIL: %s cycle %d charged %llu committed bytes, expected %llu\n",
                    kind_name(kind),
                    cycle,
                    static_cast<unsigned long long>(charged_after.committed_charged - charged_before.committed_charged),
                    static_cast<unsigned long long>(expected_charged)
                );
                return base_code + 7;
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
                return base_code + 8;
            }
        }
        return 0;
    }
} // namespace

int main()
{
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
    // already holds them, so the first scenario's delta is retention alone.
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

    namespace diagnostics = DetourModKit::diagnostics;
    const std::size_t leaks = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    if (leaks != 0)
    {
        std::fprintf(stderr, "FAIL: retention booked %zu HookManager leaks, expected none\n", leaks);
        return 50;
    }
    std::puts("PASS: a published mid hook retains exactly one executable block per install cycle");
    return 0;
}
