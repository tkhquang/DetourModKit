/**
 * @file layered_generation_reload.cpp
 * @brief Proves layered reload of two separately linked DetourModKit copies on one external target.
 * @details Two tagged families of staged_generation_dll hook one export of hook_target_lib. Each family has its own
 *          hook name and detour bonuses, so a call result names the layers that it crossed. The host installs no DMK
 *          hook. It reads the process route records through its own archive and writes each foreign layer as machine
 *          code. CTest removes the staged copies and their logs after exit.
 */

#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"

#include "staged_generation_host.hpp"
#include "staged_generation_protocol.hpp"

#include <array>
#include <atomic>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <windows.h>

namespace DetourModKit::detail
{
    // Redeclared from internal/hook_backend.hpp, which needs the backend headers. One program holds both definitions,
    // so this one must match that one token for token.
    struct BackendCoordinatorCounts
    {
        std::size_t live{0};
        std::size_t retained{0};
        std::size_t vacant{0};
        std::size_t free{0};
    };

    [[nodiscard]] BackendCoordinatorCounts backend_coordinator_counts_for_test() noexcept;
} // namespace DetourModKit::detail

namespace
{
    using DetourModKit::ErrorCode;
    using DetourModKit::hook::RetirementOutcome;
    using staged_gen::DetourPark;
    using staged_gen::HookKind;
    using staged_gen::TeardownMode;
    using CoordinatorCounts = DetourModKit::detail::BackendCoordinatorCounts;

    constexpr int SKIP_EXIT_CODE = 77;
    constexpr int SETUP_FAILURE = 2;
    constexpr int PROOF_FAILURE = 1;

    constexpr int CALL_BASE = 19;
    constexpr int CALL_MODIFIER = 6;

    /**
     * @struct TargetExport
     * @brief One hook_target_lib export and its result for CALL_BASE and CALL_MODIFIER.
     */
    struct TargetExport
    {
        const char *symbol = nullptr;
        int original_result = 0;
    };

    /// compute_damage returns base + modifier.
    constexpr TargetExport DAMAGE_EXPORT{
        .symbol = staged_gen::HOOK_TARGET_SYMBOL,
        .original_result = CALL_BASE + CALL_MODIFIER,
    };
    /// compute_armor returns defense * level.
    constexpr TargetExport ARMOR_EXPORT{
        .symbol = "compute_armor",
        .original_result = CALL_BASE * CALL_MODIFIER,
    };
    /// compute_speed returns agility - bonus.
    constexpr TargetExport SPEED_EXPORT{
        .symbol = "compute_speed",
        .original_result = CALL_BASE - CALL_MODIFIER,
    };

    /// The bonus that the foreign layer that chains adds to each call result.
    constexpr int FOREIGN_BONUS = 100000;
    /// The result of the foreign hijack. No sum of positive bonuses produces it.
    constexpr int HIJACK_RESULT = -0x4A1;
    /// The result of the foreign detour while it has no trampoline.
    constexpr int FOREIGN_UNCHAINED_RESULT = -0x4A2;

    /// Mirrors the depth limit of the residue budget in src/hook.cpp.
    constexpr std::size_t RESIDUE_LAYER_LIMIT = 16;

    /// The reloads of the constancy soak. The two families reload in turn.
    constexpr unsigned CONSTANT_DEPTH_CYCLES = 1000;
    /// The reloads of the mid soak in each install order.
    constexpr unsigned MID_CYCLES_PER_ORDER = 64;

    /// Bounds the wait for a host call to park in a counted detour.
    constexpr std::uint32_t PARK_BUDGET_MS = 10000;
    /// The drain deadline of a family whose Shutdown runs while a call stays parked, so the BUSY verdict comes fast.
    constexpr std::uint32_t BUSY_DRAIN_TIMEOUT_MS = 250;

#if defined(__SANITIZE_ADDRESS__)
    // ASan keeps VEH wrapper pages for each copy, so the RWX census holds only in an uninstrumented process.
    constexpr bool RWX_CENSUS_AVAILABLE = false;
#else
    constexpr bool RWX_CENSUS_AVAILABLE = true;
#endif

    constexpr std::uint8_t RELATIVE_JUMP_OPCODE = 0xE9;
    constexpr std::size_t RELATIVE_JUMP_BYTES = 5;
    /// The size of `jmp qword ptr [rip+0]` plus its 8-byte destination.
    constexpr std::size_t ABSOLUTE_JUMP_BYTES = 14;
    constexpr std::size_t FOREIGN_PAGE_BYTES = 4096;
    constexpr std::size_t CHAIN_ENTRY_OFFSET = 0;
    constexpr std::size_t CHAIN_TRAMPOLINE_OFFSET = 32;
    constexpr std::size_t HIJACK_ENTRY_OFFSET = 96;
    /// Keeps the foreign page well inside rel32 reach of the target.
    constexpr std::uintptr_t NEAR_PAGE_REACH = 0x40000000;

    /// The target bytes that a retirement or a claim must not change. They cover the 14-byte far patch.
    constexpr std::size_t TARGET_WINDOW_BYTES = 16;
    using TargetWindow = std::array<std::uint8_t, TARGET_WINDOW_BYTES>;

    using TargetFn = int (*)(int, int);

    std::atomic<TargetFn> s_foreign_trampoline{nullptr};
    std::atomic<std::uint64_t> s_foreign_chain_calls{0};
    std::atomic<std::uint64_t> s_hijack_calls{0};

    int foreign_chain_detour(int base, int modifier)
    {
        s_foreign_chain_calls.fetch_add(1, std::memory_order_relaxed);
        const TargetFn trampoline = s_foreign_trampoline.load(std::memory_order_acquire);
        return trampoline != nullptr ? trampoline(base, modifier) + FOREIGN_BONUS : FOREIGN_UNCHAINED_RESULT;
    }

    int hijack_detour(int, int)
    {
        s_hijack_calls.fetch_add(1, std::memory_order_relaxed);
        return HIJACK_RESULT;
    }

    /// Writes `jmp qword ptr [rip+0]` and its @p destination at @p at.
    void emit_absolute_jump(std::uint8_t *at, std::uintptr_t destination) noexcept
    {
        at[0] = 0xFF;
        at[1] = 0x25;
        std::memset(at + 2, 0, sizeof(std::int32_t));
        std::memcpy(at + 6, &destination, sizeof(destination));
    }

    /// Reports whether @p window starts with `jmp qword ptr [rip+0]`, the patch of a far hook.
    [[nodiscard]] bool holds_far_jump(const TargetWindow &window) noexcept
    {
        return window[0] == 0xFF && window[1] == 0x25 && window[2] == 0 && window[3] == 0 && window[4] == 0 &&
               window[5] == 0;
    }

    /**
     * @brief Writes @p size bytes over executable code at @p address.
     * @details No other thread calls the target while the host writes, so a plain copy is safe.
     */
    [[nodiscard]] bool write_code(void *address, const std::uint8_t *bytes, std::size_t size) noexcept
    {
        DWORD previous = 0;
        if (::VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &previous) == 0)
            return false;
        std::memcpy(address, bytes, size);
        DWORD replaced = 0;
        const bool reprotected = ::VirtualProtect(address, size, previous, &replaced) != 0;
        return ::FlushInstructionCache(::GetCurrentProcess(), address, size) != 0 && reprotected;
    }

    /**
     * @brief Commits one RWX page within rel32 reach of @p anchor.
     * @return Null when no free page lies within NEAR_PAGE_REACH.
     */
    [[nodiscard]] std::uint8_t *allocate_near(const void *anchor) noexcept
    {
        SYSTEM_INFO system{};
        ::GetSystemInfo(&system);
        const std::uintptr_t granularity = system.dwAllocationGranularity;
        const auto lowest = reinterpret_cast<std::uintptr_t>(system.lpMinimumApplicationAddress);
        const auto highest = reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
        const std::uintptr_t origin = reinterpret_cast<std::uintptr_t>(anchor) & ~(granularity - 1);
        for (std::uintptr_t distance = granularity; distance < NEAR_PAGE_REACH; distance += granularity)
        {
            const std::array<std::uintptr_t, 2> candidates{
                origin - lowest >= distance ? origin - distance : 0,
                highest - origin > distance + FOREIGN_PAGE_BYTES ? origin + distance : 0,
            };
            for (const std::uintptr_t candidate : candidates)
            {
                if (candidate == 0)
                    continue;
                void *const page = ::VirtualAlloc(
                    reinterpret_cast<void *>(candidate),
                    FOREIGN_PAGE_BYTES,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                );
                if (page != nullptr)
                    return static_cast<std::uint8_t *>(page);
            }
        }
        return nullptr;
    }

    /// Keeps the MinGW thread runtime mapped, so a generation load takes no new TLS index for it.
    [[nodiscard]] bool hold_thread_runtime() noexcept
    {
#if defined(__MINGW32__)
        const HMODULE runtime = ::LoadLibraryW(L"libwinpthread-1.dll");
        const auto thread_self =
            runtime != nullptr ? staged_gen::resolve<std::uintptr_t (*)()>(runtime, "pthread_self") : nullptr;
        if (thread_self == nullptr)
            return false;
        (void)thread_self();
#endif
        return true;
    }

    /**
     * @struct Family
     * @brief One staged copy and the Init options of each generation that maps it.
     * @details The generations of a family alternate between @ref bonus and @ref successor_bonus, so a call result
     *          shows which generation's detour ran.
     */
    struct Family
    {
        const char *tag = nullptr;
        const char *hook_name = nullptr;
        /// Starts with "staged_gen_", so the fixture cleanup removes the logs.
        const char *log_stem = nullptr;
        int bonus = 0;
        int successor_bonus = 0;
        HookKind kind = HookKind::Raw;
        TeardownMode teardown = TeardownMode::Destroy;
        bool far_hook = false;
        bool refuse_position_claims = false;
        /// Gives every generation one log file, so a long loop leaves one file per family.
        bool reuse_log_name = false;
        DetourPark park = DetourPark::None;
        std::uint32_t drain_timeout_ms = 5000;
        staged_gen::Generation generation{};
        std::string log_name{};
        unsigned started = 0;
        int active_bonus = 0;
    };

    [[nodiscard]] Family first_family(const char *hook_name)
    {
        return Family{
            .tag = "LAYERFIRST",
            .hook_name = hook_name,
            .log_stem = "staged_gen_layered_first",
            .bonus = 1000,
            .successor_bonus = 2000,
        };
    }

    [[nodiscard]] Family second_family(const char *hook_name)
    {
        return Family{
            .tag = "LAYERSECOND",
            .hook_name = hook_name,
            .log_stem = "staged_gen_layered_second",
            .bonus = 10000,
            .successor_bonus = 20000,
        };
    }

    /// Switches @p family to the counted kind, the Retire teardown, and the detour @p park.
    [[nodiscard]] Family counted_family(Family family, DetourPark park = DetourPark::None)
    {
        family.kind = HookKind::Counted;
        family.teardown = TeardownMode::Retire;
        family.park = park;
        return family;
    }

    /// Returns the Shutdown verdict of a retirement that pins when @p pinned is true. Every mode returns ABI 3 values.
    [[nodiscard]] int expected_verdict(bool pinned) noexcept
    {
        return static_cast<int>(pinned ? DMK_STAGED_RELOAD_RESTART_REQUIRED : DMK_STAGED_RELOAD_OK);
    }

    /// The family state that a retire call which changes nothing leaves as it was.
    struct Snapshot
    {
        staged_gen::Status status{};
        CoordinatorCounts records{};
        TargetWindow window{};
    };

    /// Where a generation's hook lands at Init.
    enum class Placement
    {
        /// A new record on top of the target chain.
        Fresh,
        /// The Vacant position of an earlier generation with the same hook name.
        Claim,
    };

    /// How a generation's hook leaves at Shutdown.
    enum class Retirement
    {
        /// The top layer writes its saved bytes back and removes its record.
        Restore,
        /// A fresh lower layer bypasses its relay and leaves one Vacant position with one HookResidue.
        VacateFresh,
        /// A claimed layer bypasses its relay and gives the position back with no HookResidue.
        VacateClaimed,
        /// A fresh lower layer over the residue budget keeps its detour reachable, and Shutdown refuses.
        PinOverBudget,
    };

    /// The non-DMK layer that the host writes over the target.
    enum class ForeignLayer
    {
        None,
        /// A stub that relocates the displaced jump and adds FOREIGN_BONUS.
        Chaining,
        /// A jump to a detour that returns HIJACK_RESULT and never calls the chain.
        Hijack,
    };

    /**
     * @class LayeredHost
     * @brief The hook target, the process record census, and the foreign layer of one scenario.
     * @details Each check prints its failure and returns false. The host keeps its reference on the target module
     *          for the process, because a Vacant position stays in the target chain.
     */
    class LayeredHost
    {
    public:
        explicit LayeredHost(const char *scenario, const TargetExport &target = DAMAGE_EXPORT) noexcept
            : m_scenario(scenario), m_export(target)
        {
        }

        LayeredHost(const LayeredHost &) = delete;
        LayeredHost &operator=(const LayeredHost &) = delete;

        [[nodiscard]] bool fail(const char *what) const noexcept
        {
            if (m_cycle != 0)
                std::fprintf(stderr, "FAIL[%s] cycle %u: %s\n", m_scenario, m_cycle, what);
            else
                std::fprintf(stderr, "FAIL[%s]: %s\n", m_scenario, what);
            return false;
        }

        [[nodiscard]] bool fail(const Family &family, const char *what) const noexcept
        {
            return fail(describe(family, what).data());
        }

        [[nodiscard]] bool fail_value(const char *what, std::uint64_t expected, std::uint64_t actual) const noexcept
        {
            char message[256]{};
            std::snprintf(
                message,
                sizeof(message),
                "%s (expected %" PRIu64 ", observed %" PRIu64 ")",
                what,
                expected,
                actual
            );
            return fail(message);
        }

        [[nodiscard]] bool
        fail_value(const Family &family, const char *what, std::uint64_t expected, std::uint64_t actual) const noexcept
        {
            return fail_value(describe(family, what).data(), expected, actual);
        }

        /// Prints the outcome, removes each unmapped staged copy, and returns the process exit code.
        [[nodiscard]] static int
        finish(bool proved, const char *outcome, std::initializer_list<const Family *> families) noexcept
        {
            for (const Family *family : families)
            {
                if (family->generation.module == nullptr)
                    staged_gen::remove_unmapped_staged_file_best_effort(family->generation);
            }
            if (!proved)
                return PROOF_FAILURE;
            std::fprintf(stderr, "OK: %s\n", outcome);
            return 0;
        }

        void set_cycle(unsigned cycle) noexcept { m_cycle = cycle; }

        [[nodiscard]] static CoordinatorCounts records() noexcept
        {
            return DetourModKit::detail::backend_coordinator_counts_for_test();
        }

        [[nodiscard]] TargetWindow read_window() const noexcept
        {
            TargetWindow window{};
            std::memcpy(window.data(), reinterpret_cast<const void *>(m_target), window.size());
            return window;
        }

        [[nodiscard]] int original_result() const noexcept { return m_export.original_result; }

        /// Calls the target once with the probe arguments and checks nothing.
        [[nodiscard]] int call_target() const noexcept { return m_target(CALL_BASE, CALL_MODIFIER); }

        [[nodiscard]] bool window_equals(const TargetWindow &expected, const char *what) const noexcept
        {
            return read_window() == expected || fail(what);
        }

        [[nodiscard]] bool
        records_added(const CoordinatorCounts &baseline, std::size_t live, std::size_t vacant) const noexcept
        {
            const CoordinatorCounts now = records();
            if (now.live != baseline.live + live)
                return fail_value("the live record count differs", baseline.live + live, now.live);
            if (now.vacant != baseline.vacant + vacant)
                return fail_value("the Vacant record count differs", baseline.vacant + vacant, now.vacant);
            return now.retained == baseline.retained || fail("the retained record count changed");
        }

        [[nodiscard]] bool open_target() noexcept
        {
            m_target_module = ::LoadLibraryA(staged_gen::HOOK_TARGET_MODULE_NAME);
            if (m_target_module == nullptr)
                return fail("failed to load the hook target fixture");
            m_target = staged_gen::resolve<TargetFn>(m_target_module, m_export.symbol);
            if (m_target == nullptr)
                return fail("the hook target fixture did not export its symbol");
            return m_target(CALL_BASE, CALL_MODIFIER) == m_export.original_result ||
                   fail("the hook target did not return its baseline result");
        }

        [[nodiscard]] bool stage(Family &family) const
        {
            return staged_gen::stage_copy(family.tag, family.generation.path) ||
                   fail(family, "failed to stage the family copy");
        }

        /**
         * @brief Maps the family copy, runs Init, and checks where the hook landed.
         * @details A claim adds no record, turns one Vacant record Owned, and writes no target byte.
         */
        [[nodiscard]] bool start(Family &family, Placement placement)
        {
            const CoordinatorCounts before = records();
            const TargetWindow window_before = read_window();
            if (!staged_gen::load_staged_generation(family.generation))
                return fail(family, "LoadLibrary or an export lookup failed");
            if (!tag_matches(family))
                return fail(family, "the mapped image does not carry the staged tag");
            // A count above zero means that the loader handed back an image that an earlier generation initialized.
            if (family.generation.read_status().init_calls != 0)
                return fail(family, "the image did not map fresh");

            const int bonus = family.started % 2 == 0 ? family.bonus : family.successor_bonus;
            if (family.log_name.empty() || !family.reuse_log_name)
                family.log_name = staged_gen::make_log_name(family.log_stem);
            staged_gen::InitOptions options{};
            options.log_file = family.log_name.c_str();
            options.hook_kind = static_cast<int>(family.kind);
            options.teardown_mode = static_cast<int>(family.teardown);
            options.detour_bonus = bonus;
            options.hook_name = family.hook_name;
            options.far_hook = family.far_hook ? 1 : 0;
            options.refuse_position_claims = family.refuse_position_claims ? 1 : 0;
            options.detour_park = static_cast<int>(family.park);
            options.drain_timeout_ms = family.drain_timeout_ms;
            options.target_symbol = m_export.symbol;
            ++family.started;
            family.active_bonus = bonus;
            if (family.generation.init(&options) == 0)
                return fail(family, "Init returned 0");

            const CoordinatorCounts after = records();
            if (after.retained != before.retained)
                return fail(family, "the install changed the retained record count");
            if (placement == Placement::Fresh)
            {
                if (after.live != before.live + 1 || after.vacant != before.vacant)
                    return fail(family, "the install did not add exactly one Owned record");
                return true;
            }
            if (after.live != before.live || after.vacant + 1 != before.vacant)
                return fail(family, "the successor did not claim the Vacant position");
            return read_window() == window_before || fail(family, "the claim wrote a target byte");
        }

        /// Runs Shutdown and checks the verdict, the leak buckets, the Hook module pins, and the records.
        [[nodiscard]] bool retire(Family &family, Retirement retirement)
        {
            const staged_gen::Status before = family.generation.read_status();
            const CoordinatorCounts records_before = records();
            const TargetWindow window_before = read_window();
            const int verdict = family.generation.shutdown();
            const staged_gen::Status after = family.generation.read_status();
            const CoordinatorCounts records_after = records();

            const bool restored = retirement == Retirement::Restore;
            const bool pinned = retirement == Retirement::PinOverBudget;
            const bool vacated = retirement == Retirement::VacateFresh || retirement == Retirement::VacateClaimed;
            if (verdict != expected_verdict(pinned))
                return fail(family, pinned ? "Shutdown accepted a pin over the residue budget" : "Shutdown refused");
            if (family.teardown == TeardownMode::Retire)
            {
                if (!retire_call_reads(family, before, after, RetirementOutcome::Retired, ErrorCode::Ok))
                    return false;
                if (after.retire_restored != (restored ? 1U : 0U) || after.retire_vacated != (vacated ? 1U : 0U) ||
                    after.retire_pinned != (pinned ? 1U : 0U) || after.held_hooks != 0)
                {
                    return fail(family, "the retire counts do not match the retirement");
                }
            }
            const std::uint64_t manager_leaks = pinned ? 1U : 0U;
            if (after.hook_manager_leaks != before.hook_manager_leaks + manager_leaks)
                return fail(family, pinned ? "the pin booked no HookManager leak" : "Shutdown booked HookManager");
            const std::uint64_t residue_leaks = retirement == Retirement::VacateFresh ? 1U : 0U;
            if (after.hook_residue_leaks != before.hook_residue_leaks + residue_leaks)
            {
                return fail(
                    family,
                    residue_leaks != 0 ? "the vacate booked no HookResidue" : "Shutdown booked HookResidue"
                );
            }
            // A pinned detour stays reachable, so its Hook module reference stays. Every other outcome releases it.
            const bool pin_kept = after.hook_module_pins == before.hook_module_pins && before.hook_module_pins != 0;
            if (pinned ? !pin_kept : after.hook_module_pins != 0)
                return fail(family, pinned ? "the pin released its Hook module reference" : "a Hook module pin stayed");

            if (records_after.retained != records_before.retained)
                return fail(family, "Shutdown changed the retained record count");
            const std::size_t live_expected = restored ? records_before.live - 1 : records_before.live;
            if (records_after.live != live_expected)
                return fail(family, restored ? "the restore kept its record" : "the retirement removed its record");
            if (records_after.vacant != records_before.vacant + (vacated ? 1U : 0U))
                return fail(family, vacated ? "the position did not turn Vacant" : "the Vacant record count changed");
            return restored || read_window() == window_before || fail(family, "the retirement wrote a target byte");
        }

        /// Checks that exactly one retire call ran between @p before and @p after and ended as @p outcome.
        [[nodiscard]] bool retire_call_reads(
            const Family &family,
            const staged_gen::Status &before,
            const staged_gen::Status &after,
            RetirementOutcome outcome,
            ErrorCode refusal
        ) const noexcept
        {
            if (after.retire_calls != before.retire_calls + 1)
                return fail_value(family, "the retire call count differs", before.retire_calls + 1, after.retire_calls);
            if (after.retire_outcome != static_cast<int>(outcome))
            {
                const auto expected = static_cast<std::uint64_t>(outcome);
                const auto actual = static_cast<std::uint64_t>(after.retire_outcome);
                return fail_value(family, "the retire outcome differs", expected, actual);
            }
            if (after.retire_refusal != static_cast<int>(refusal))
            {
                const auto expected = static_cast<std::uint64_t>(refusal);
                const auto actual = static_cast<std::uint64_t>(after.retire_refusal);
                return fail_value(family, "the retire refusal differs", expected, actual);
            }
            return true;
        }

        [[nodiscard]] Snapshot snapshot(const Family &family) const noexcept
        {
            return Snapshot{
                .status = family.generation.read_status(),
                .records = records(),
                .window = read_window(),
            };
        }

        /**
         * @brief Checks that @p family keeps the hooks, the hook leak buckets, and the Hook module pins of @p before.
         * @details The process records and the target bytes must also match @p before.
         */
        [[nodiscard]] bool unchanged_since(const Family &family, const Snapshot &before) const noexcept
        {
            const staged_gen::Status now = family.generation.read_status();
            if (now.held_hooks == 0 || now.held_hooks != before.status.held_hooks)
                return fail_value(family, "the held hook count changed", before.status.held_hooks, now.held_hooks);
            if (now.hook_manager_leaks != before.status.hook_manager_leaks ||
                now.hook_residue_leaks != before.status.hook_residue_leaks)
            {
                return fail(family, "the generation booked a hook leak");
            }
            if (now.hook_module_pins != before.status.hook_module_pins)
                return fail(family, "the Hook module pin count changed");
            const CoordinatorCounts counts = records();
            if (counts.live != before.records.live || counts.vacant != before.records.vacant ||
                counts.retained != before.records.retained || counts.free != before.records.free)
            {
                return fail(family, "the process record counts changed");
            }
            return read_window() == before.window || fail(family, "a target byte changed");
        }

        /**
         * @brief Runs Shutdown while a call stays inside the counted detour of @p family.
         * @details The verdict must be BUSY with one call in flight. The generation keeps every hook and its Session.
         */
        [[nodiscard]] bool retire_busy(const Family &family) const noexcept
        {
            const Snapshot before = snapshot(family);
            const int verdict = family.generation.shutdown();
            if (verdict != static_cast<int>(DMK_STAGED_RELOAD_BUSY))
            {
                const auto actual = static_cast<std::uint64_t>(verdict);
                return fail_value(family, "Shutdown did not return BUSY", DMK_STAGED_RELOAD_BUSY, actual);
            }
            const staged_gen::Status after = family.generation.read_status();
            if (!retire_call_reads(family, before.status, after, RetirementOutcome::Busy, ErrorCode::Ok))
                return false;
            if (after.retire_in_flight != 1)
                return fail_value(family, "the Busy drain did not count one call in flight", 1, after.retire_in_flight);
            return unchanged_since(family, before);
        }

        [[nodiscard]] bool unload(Family &family) const noexcept
        {
            const void *const marker = family.generation.marker;
            if (!staged_gen::unload_generation(family.generation))
                return fail(family, "FreeLibrary failed");
            return staged_gen::wait_for_unmap(marker) || fail(family, "the image stayed mapped after Shutdown");
        }

        /**
         * @brief Calls the target once and checks which layers the call crossed.
         * @details The expected result is the original result plus the active bonus of each crossed family and of
         *          the foreign layer that chains. Under the hijack it is HIJACK_RESULT. Each crossed detour runs once,
         *          and each skipped detour does not run.
         */
        [[nodiscard]] bool call_crosses(
            std::initializer_list<const Family *> crossed,
            std::initializer_list<const Family *> skipped = {}
        ) const noexcept
        {
            constexpr std::size_t LIST_CAPACITY = 2;
            if (crossed.size() > LIST_CAPACITY || skipped.size() > LIST_CAPACITY)
                return fail("a call check names too many families");
            std::array<std::uint64_t, LIST_CAPACITY> crossed_before{};
            std::array<std::uint64_t, LIST_CAPACITY> skipped_before{};
            int expected = m_foreign == ForeignLayer::Hijack ? HIJACK_RESULT : m_export.original_result;
            if (m_foreign == ForeignLayer::Chaining)
                expected += FOREIGN_BONUS;
            std::size_t index = 0;
            for (const Family *family : crossed)
            {
                crossed_before[index++] = family->generation.read_status().hook_calls;
                expected += family->active_bonus;
            }
            index = 0;
            for (const Family *family : skipped)
                skipped_before[index++] = family->generation.read_status().hook_calls;
            const std::uint64_t chain_before = s_foreign_chain_calls.load(std::memory_order_relaxed);
            const std::uint64_t hijack_before = s_hijack_calls.load(std::memory_order_relaxed);

            const int result = m_target(CALL_BASE, CALL_MODIFIER);
            if (result != expected)
            {
                char message[128]{};
                std::snprintf(message, sizeof(message), "the call returned %d, expected %d", result, expected);
                return fail(message);
            }
            index = 0;
            for (const Family *family : crossed)
            {
                if (family->generation.read_status().hook_calls != crossed_before[index++] + 1)
                    return fail(*family, "the call did not run its detour once");
            }
            index = 0;
            for (const Family *family : skipped)
            {
                if (family->generation.read_status().hook_calls != skipped_before[index++])
                    return fail(*family, "the call ran a retired detour");
            }
            const std::uint64_t chain_calls = m_foreign == ForeignLayer::Chaining ? 1U : 0U;
            const std::uint64_t hijack_calls = m_foreign == ForeignLayer::Hijack ? 1U : 0U;
            if (s_foreign_chain_calls.load(std::memory_order_relaxed) != chain_before + chain_calls ||
                s_hijack_calls.load(std::memory_order_relaxed) != hijack_before + hijack_calls)
                return fail("the call did not cross the foreign layer exactly as installed");
            return true;
        }

        /**
         * @brief Writes a foreign E9 jump over the first five target bytes.
         * @details The stub that chains relocates the displaced E9 as an absolute jump and ends with a jump back to the
         *          byte after it. A hook library that relocates whole instructions emits the same shape.
         */
        [[nodiscard]] bool install_foreign(ForeignLayer layer) noexcept
        {
            if (m_foreign != ForeignLayer::None || layer == ForeignLayer::None)
                return fail("the host holds one foreign layer at a time");
            if (m_foreign_page == nullptr)
                m_foreign_page = allocate_near(reinterpret_cast<const void *>(m_target));
            if (m_foreign_page == nullptr)
                return fail("no free page lies within rel32 reach of the target");
            auto *const target_bytes = reinterpret_cast<std::uint8_t *>(m_target);
            std::memcpy(m_foreign_saved.data(), target_bytes, m_foreign_saved.size());
            const auto jump_end = reinterpret_cast<std::uintptr_t>(target_bytes) + RELATIVE_JUMP_BYTES;

            std::uint8_t *entry = m_foreign_page + HIJACK_ENTRY_OFFSET;
            if (layer == ForeignLayer::Chaining)
            {
                if (m_foreign_saved[0] != RELATIVE_JUMP_OPCODE)
                    return fail("the foreign stub relocates only an E9 jump");
                std::int32_t displacement = 0;
                std::memcpy(&displacement, m_foreign_saved.data() + 1, sizeof(displacement));
                std::uint8_t *const trampoline = m_foreign_page + CHAIN_TRAMPOLINE_OFFSET;
                emit_absolute_jump(trampoline, jump_end + static_cast<std::uintptr_t>(std::intptr_t{displacement}));
                emit_absolute_jump(trampoline + ABSOLUTE_JUMP_BYTES, jump_end);
                entry = m_foreign_page + CHAIN_ENTRY_OFFSET;
                emit_absolute_jump(entry, reinterpret_cast<std::uintptr_t>(&foreign_chain_detour));
                s_foreign_trampoline.store(reinterpret_cast<TargetFn>(trampoline), std::memory_order_release);
            }
            else
            {
                emit_absolute_jump(entry, reinterpret_cast<std::uintptr_t>(&hijack_detour));
            }
            if (::FlushInstructionCache(::GetCurrentProcess(), m_foreign_page, FOREIGN_PAGE_BYTES) == 0)
                return fail("FlushInstructionCache failed for the foreign page");

            const auto distance = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(entry) - jump_end);
            if (distance > INT32_MAX || distance < INT32_MIN)
                return fail("the foreign entry lies outside rel32 reach");
            const auto relative = static_cast<std::int32_t>(distance);
            m_foreign_patch[0] = RELATIVE_JUMP_OPCODE;
            std::memcpy(m_foreign_patch.data() + 1, &relative, sizeof(relative));
            if (!write_code(target_bytes, m_foreign_patch.data(), m_foreign_patch.size()))
                return fail("the host failed to write the foreign jump");
            m_foreign = layer;
            return true;
        }

        /// Writes the saved bytes back after a check that the foreign jump is still intact.
        [[nodiscard]] bool remove_foreign() noexcept
        {
            auto *const target_bytes = reinterpret_cast<std::uint8_t *>(m_target);
            if (m_foreign == ForeignLayer::None)
                return fail("no foreign layer is installed");
            if (std::memcmp(target_bytes, m_foreign_patch.data(), m_foreign_patch.size()) != 0)
                return fail("another writer changed the foreign jump");
            if (!write_code(target_bytes, m_foreign_saved.data(), m_foreign_saved.size()))
                return fail("the host failed to restore the bytes under the foreign jump");
            m_foreign = ForeignLayer::None;
            return true;
        }

    private:
        using Message = std::array<char, 256>;

        /// Prefixes @p what with the tag, the hook name, and the generation number of @p family.
        [[nodiscard]] static Message describe(const Family &family, const char *what) noexcept
        {
            Message message{};
            std::snprintf(
                message.data(),
                message.size(),
                "%s %s generation %u: %s",
                family.tag,
                family.hook_name,
                family.started,
                what
            );
            return message;
        }

        [[nodiscard]] static bool tag_matches(const Family &family) noexcept
        {
            const std::string_view tag{family.tag};
            const char *const embedded = family.generation.tag();
            for (std::size_t i = 0; i < staged_gen::TAG_LENGTH; ++i)
            {
                if (embedded[i] != (i < tag.size() ? tag[i] : '0'))
                    return false;
            }
            return true;
        }

        const char *m_scenario;
        TargetExport m_export;
        unsigned m_cycle = 0;
        HMODULE m_target_module = nullptr;
        TargetFn m_target = nullptr;
        ForeignLayer m_foreign = ForeignLayer::None;
        std::uint8_t *m_foreign_page = nullptr;
        std::array<std::uint8_t, RELATIVE_JUMP_BYTES> m_foreign_saved{};
        std::array<std::uint8_t, RELATIVE_JUMP_BYTES> m_foreign_patch{};
    };

    /// A pass or a check over two copies on one host.
    using LayeredPass = bool (*)(LayeredHost &host, Family &lower, Family &upper);

    /**
     * @brief Reloads @p lower under @p upper, then retires both copies.
     * @details The lower copy retires by bypass, unmaps, and leaves its position Vacant. Its successor claims that
     *          position under the upper copy. The claimed successor vacates again, and the upper copy restores. One
     *          Vacant position stays on the target. A non-null @p probe runs before the first lower retirement.
     */
    [[nodiscard]] bool
    reload_lower_under_upper(LayeredHost &host, Family &lower, Family &upper, LayeredPass probe = nullptr)
    {
        const CoordinatorCounts baseline = LayeredHost::records();
        if (!host.start(lower, Placement::Fresh) || !host.call_crosses({&lower}))
            return false;
        if (lower.far_hook && !holds_far_jump(host.read_window()))
            return host.fail(lower, "the far install did not write an indirect jump over the target");
        return host.start(upper, Placement::Fresh) && host.call_crosses({&lower, &upper}) &&
               (probe == nullptr || probe(host, lower, upper)) && host.retire(lower, Retirement::VacateFresh) &&
               host.call_crosses({&upper}, {&lower}) && host.unload(lower) && host.call_crosses({&upper}) &&
               host.start(lower, Placement::Claim) && host.call_crosses({&lower, &upper}) &&
               host.retire(lower, Retirement::VacateClaimed) && host.call_crosses({&upper}, {&lower}) &&
               host.unload(lower) && host.retire(upper, Retirement::Restore) && host.call_crosses({}, {&upper}) &&
               host.unload(upper) && host.call_crosses({}) && host.records_added(baseline, 1, 1);
    }

    /**
     * @brief Reloads the two copies in turn for @p cycles reloads, lower copy first.
     * @details The lower copy vacates and its successor claims the position. The upper copy restores and its
     *          successor installs fresh on top. Each cycle end shows the same record counts. From cycle 2 on, it also
     *          shows the same committed private RWX bytes when @p census is true.
     */
    [[nodiscard]] bool reload_alternately(LayeredHost &host, Family &lower, Family &upper, unsigned cycles, bool census)
    {
        const CoordinatorCounts baseline = LayeredHost::records();
        if (!host.start(lower, Placement::Fresh) || !host.start(upper, Placement::Fresh) ||
            !host.call_crosses({&lower, &upper}))
        {
            return false;
        }
        std::uint64_t reference_bytes = 0;
        for (unsigned cycle = 1; cycle <= cycles; ++cycle)
        {
            host.set_cycle(cycle);
            const bool lower_turn = cycle % 2 == 1;
            Family &reloading = lower_turn ? lower : upper;
            // Only the first lower generation owns a fresh position. Every later one claimed it.
            Retirement retirement = Retirement::Restore;
            if (lower_turn)
                retirement = lower.started == 1 ? Retirement::VacateFresh : Retirement::VacateClaimed;
            if (!host.retire(reloading, retirement) || !host.unload(reloading) ||
                !host.start(reloading, lower_turn ? Placement::Claim : Placement::Fresh) ||
                !host.call_crosses({&lower, &upper}))
            {
                return false;
            }

            const CoordinatorCounts now = LayeredHost::records();
            if (now.live != baseline.live + 2)
                return host.fail_value("the cycle end changed the live record count", baseline.live + 2, now.live);
            if (now.free + 2 != baseline.free)
                return host.fail_value("the cycle end changed the free record count", baseline.free - 2, now.free);
            if (now.vacant != baseline.vacant)
                return host.fail_value("the cycle end left a Vacant record", baseline.vacant, now.vacant);
            if (!census || cycle < 2)
                continue;
            const std::uint64_t bytes = staged_gen::committed_private_execute_read_write_bytes();
            if (bytes == UINT64_MAX)
                return host.fail("the RWX census failed to walk the address space");
            if (cycle == 2)
                reference_bytes = bytes;
            else if (bytes != reference_bytes)
                return host.fail_value("the cycle end changed the committed private RWX bytes", reference_bytes, bytes);
        }
        host.set_cycle(0);
        const Retirement lower_retirement = lower.started == 1 ? Retirement::VacateFresh : Retirement::VacateClaimed;
        return host.retire(lower, lower_retirement) && host.unload(lower) && host.retire(upper, Retirement::Restore) &&
               host.unload(upper) && host.call_crosses({});
    }

    int run_lower_copy_field_order()
    {
        LayeredHost host{"lower-copy-field-order"};
        Family first = first_family("layered_first_hook");
        Family second = second_family("layered_second_hook");
        const bool proved = host.open_target() && host.stage(first) && host.stage(second) &&
                            reload_lower_under_upper(host, first, second);
        return LayeredHost::finish(
            proved,
            "the first copy retired under the second copy and unmapped, and its successor claimed the position",
            {&first, &second}
        );
    }

    int run_lower_copy_reverse_order()
    {
        LayeredHost host{"lower-copy-reverse-order"};
        Family first = first_family("layered_first_hook");
        Family second = second_family("layered_second_hook");
        const bool proved = host.open_target() && host.stage(first) && host.stage(second) &&
                            reload_lower_under_upper(host, second, first);
        return LayeredHost::finish(
            proved,
            "the second copy retired under the first copy and unmapped, and its successor claimed the position",
            {&first, &second}
        );
    }

    int run_disable_first_consumer()
    {
        LayeredHost host{"disable-first-consumer"};
        Family first = first_family("layered_first_hook");
        Family second = second_family("layered_second_hook");
        first.teardown = TeardownMode::DisableFirst;
        second.teardown = TeardownMode::DisableFirst;
        const bool proved = host.open_target() && host.stage(first) && host.stage(second) &&
                            reload_lower_under_upper(host, first, second);
        return LayeredHost::finish(
            proved,
            "a newest-first disable and destroy retired the lower copy, and both copies unmapped",
            {&first, &second}
        );
    }

    /**
     * @brief Retires @p upper before the Shutdown of @p lower, so the lower copy is the top layer at its Shutdown.
     * @details Both copies restore, so the pass leaves the target bytes as it found them and books no residue.
     */
    [[nodiscard]] bool hand_back_before_shutdown(LayeredHost &host, Family &lower, Family &upper)
    {
        const CoordinatorCounts baseline = LayeredHost::records();
        const TargetWindow window_before = host.read_window();
        if (!host.start(lower, Placement::Fresh) || !host.call_crosses({&lower}))
            return false;
        const TargetWindow lower_patch = host.read_window();
        return host.start(upper, Placement::Fresh) && host.call_crosses({&lower, &upper}) &&
               host.retire(upper, Retirement::Restore) &&
               host.window_equals(lower_patch, "the upper restore did not leave the lower patch") &&
               host.call_crosses({&lower}, {&upper}) && host.unload(upper) && host.call_crosses({&lower}) &&
               host.retire(lower, Retirement::Restore) &&
               host.window_equals(window_before, "the lower restore did not leave the bytes under the pass") &&
               host.call_crosses({}, {&lower}) && host.unload(lower) && host.call_crosses({}) &&
               host.records_added(baseline, 0, 0);
    }

    /**
     * @brief Retires @p upper between the Shutdown of @p lower and the Init of its successor.
     * @details The successor claims the vacated position, which is then the top layer, and vacates it again.
     */
    [[nodiscard]] bool hand_back_before_successor_init(LayeredHost &host, Family &lower, Family &upper)
    {
        const CoordinatorCounts baseline = LayeredHost::records();
        if (!host.start(lower, Placement::Fresh) || !host.call_crosses({&lower}))
            return false;
        const TargetWindow lower_patch = host.read_window();
        return host.start(upper, Placement::Fresh) && host.call_crosses({&lower, &upper}) &&
               host.retire(lower, Retirement::VacateFresh) && host.call_crosses({&upper}, {&lower}) &&
               host.unload(lower) && host.retire(upper, Retirement::Restore) &&
               host.window_equals(lower_patch, "the upper restore did not leave the vacated patch") &&
               host.call_crosses({}, {&upper}) && host.unload(upper) && host.call_crosses({}) &&
               host.start(lower, Placement::Claim) && host.call_crosses({&lower}) &&
               host.retire(lower, Retirement::VacateClaimed) && host.call_crosses({}, {&lower}) && host.unload(lower) &&
               host.call_crosses({}) && host.records_added(baseline, 1, 1);
    }

    /**
     * @brief Retires @p upper after the successor of @p lower claimed the vacated position.
     * @details The claimed position survives the upper restore and vacates again.
     */
    [[nodiscard]] bool hand_back_after_successor_init(LayeredHost &host, Family &lower, Family &upper)
    {
        const CoordinatorCounts baseline = LayeredHost::records();
        if (!host.start(lower, Placement::Fresh) || !host.call_crosses({&lower}))
            return false;
        const TargetWindow lower_patch = host.read_window();
        return host.start(upper, Placement::Fresh) && host.call_crosses({&lower, &upper}) &&
               host.retire(lower, Retirement::VacateFresh) && host.call_crosses({&upper}, {&lower}) &&
               host.unload(lower) && host.start(lower, Placement::Claim) && host.call_crosses({&lower, &upper}) &&
               host.retire(upper, Retirement::Restore) &&
               host.window_equals(lower_patch, "the upper restore did not leave the claimed patch") &&
               host.call_crosses({&lower}, {&upper}) && host.unload(upper) && host.call_crosses({&lower}) &&
               host.retire(lower, Retirement::VacateClaimed) && host.call_crosses({}, {&lower}) && host.unload(lower) &&
               host.call_crosses({}) && host.records_added(baseline, 1, 1);
    }

    /**
     * @brief Retires @p lower under a foreign stub that chains.
     * @details The retirement writes none of the stub bytes, and calls skip the retired detour.
     */
    [[nodiscard]] bool retire_under_foreign_chain(LayeredHost &host, Family &lower)
    {
        const CoordinatorCounts baseline = LayeredHost::records();
        return host.start(lower, Placement::Fresh) && host.call_crosses({&lower}) &&
               host.install_foreign(ForeignLayer::Chaining) && host.call_crosses({&lower}) &&
               host.retire(lower, Retirement::VacateFresh) && host.call_crosses({}, {&lower}) && host.unload(lower) &&
               host.call_crosses({}) && host.remove_foreign() && host.call_crosses({}) &&
               host.records_added(baseline, 1, 1);
    }

    /**
     * @brief Retires @p lower under a foreign hijack that does not chain, then reloads it.
     * @details The retirement writes none of the hijack bytes. After the hijack goes, the call reaches the original
     *          through the Vacant relay, and the successor claims that position.
     */
    [[nodiscard]] bool retire_under_hijack(LayeredHost &host, Family &lower)
    {
        const CoordinatorCounts baseline = LayeredHost::records();
        return host.start(lower, Placement::Fresh) && host.call_crosses({&lower}) &&
               host.install_foreign(ForeignLayer::Hijack) && host.call_crosses({}, {&lower}) &&
               host.retire(lower, Retirement::VacateFresh) && host.call_crosses({}, {&lower}) && host.unload(lower) &&
               host.call_crosses({}) && host.remove_foreign() && host.call_crosses({}) &&
               host.start(lower, Placement::Claim) && host.call_crosses({&lower}) &&
               host.retire(lower, Retirement::VacateClaimed) && host.call_crosses({}, {&lower}) && host.unload(lower) &&
               host.call_crosses({}) && host.records_added(baseline, 1, 1);
    }

    /// Runs @p pass over raw copies of both families on compute_damage and returns the process exit code.
    int run_raw_pass(const char *scenario, LayeredPass pass, const char *outcome)
    {
        LayeredHost host{scenario};
        Family first = first_family("layered_first_hook");
        Family second = second_family("layered_second_hook");
        const bool proved = host.open_target() && host.stage(first) && host.stage(second) && pass(host, first, second);
        return LayeredHost::finish(proved, outcome, {&first, &second});
    }

    int run_hand_back_before_shutdown()
    {
        return run_raw_pass(
            "hand-back-before-shutdown",
            &hand_back_before_shutdown,
            "the upper copy handed the target back, and the lower copy restored it with no residue"
        );
    }

    int run_hand_back_before_successor_init()
    {
        return run_raw_pass(
            "hand-back-before-successor-init",
            &hand_back_before_successor_init,
            "the upper copy handed back before the successor Init, and the successor claimed the top position"
        );
    }

    int run_hand_back_after_successor_init()
    {
        return run_raw_pass(
            "hand-back-after-successor-init",
            &hand_back_after_successor_init,
            "the claimed position survived the upper restore and vacated again"
        );
    }

    int run_foreign_chaining_layer()
    {
        LayeredHost host{"foreign-chaining-layer"};
        Family first = first_family("layered_first_hook");
        const bool proved = host.open_target() && host.stage(first) && retire_under_foreign_chain(host, first);
        return LayeredHost::finish(
            proved,
            "the lower copy retired under a foreign stub that chains, wrote none of its bytes, and unmapped",
            {&first}
        );
    }

    int run_non_chaining_hijack()
    {
        LayeredHost host{"non-chaining-hijack"};
        Family first = first_family("layered_first_hook");
        const bool proved = host.open_target() && host.stage(first) && retire_under_hijack(host, first);
        return LayeredHost::finish(
            proved,
            "the lower copy retired under a hijack that does not chain and wrote none of its bytes",
            {&first}
        );
    }

    int run_lower_mid_copy()
    {
        LayeredHost host{"lower-mid-copy"};
        Family first = first_family("layered_mid_first_field");
        Family second = second_family("layered_mid_second_field");
        first.kind = HookKind::Mid;
        second.kind = HookKind::Mid;
        if (!host.open_target() || !host.stage(first) || !host.stage(second) ||
            !reload_lower_under_upper(host, first, second))
        {
            return LayeredHost::finish(false, "", {&first, &second});
        }

        // The reverse order maps the same copies under new hook names, so no install claims the field-order position.
        Family second_reverse = second_family("layered_mid_second_reverse");
        Family first_reverse = first_family("layered_mid_first_reverse");
        second_reverse.kind = HookKind::Mid;
        first_reverse.kind = HookKind::Mid;
        second_reverse.generation.path = second.generation.path;
        first_reverse.generation.path = first.generation.path;
        if (!reload_lower_under_upper(host, second_reverse, first_reverse))
            return LayeredHost::finish(false, "", {&first_reverse, &second_reverse});

        // The disable pass also takes new hook names. Shutdown disables every hook newest first before any destroy.
        Family first_disable = first_family("layered_mid_first_disable");
        Family second_disable = second_family("layered_mid_second_disable");
        for (Family *family : {&first_disable, &second_disable})
        {
            family->kind = HookKind::Mid;
            family->teardown = TeardownMode::DisableFirst;
        }
        first_disable.generation.path = first.generation.path;
        second_disable.generation.path = second.generation.path;
        const bool proved = reload_lower_under_upper(host, first_disable, second_disable);
        return LayeredHost::finish(
            proved,
            "a lower mid copy closed its route and retired in both install orders and after a newest-first disable",
            {&first_disable, &second_disable}
        );
    }

    int run_far_hook()
    {
        LayeredHost host{"far-hook"};
        Family first = first_family("layered_far_hook");
        Family second = second_family("layered_second_hook");
        first.far_hook = true;
        const bool proved = host.open_target() && host.stage(first) && host.stage(second) &&
                            reload_lower_under_upper(host, first, second);
        return LayeredHost::finish(
            proved,
            "a lower far hook retired through its relay, and its successor claimed that relay",
            {&first, &second}
        );
    }

    int run_alternating_constant_depth()
    {
        if constexpr (!RWX_CENSUS_AVAILABLE)
        {
            std::fprintf(
                stderr,
                "SKIP: the RWX census requires an uninstrumented process. ASan keeps VEH wrapper pages.\n"
            );
            return SKIP_EXIT_CODE;
        }
        else
        {
            LayeredHost host{"alternating-constant-depth"};
            Family first = first_family("layered_alternating_first");
            Family second = second_family("layered_alternating_second");
            first.reuse_log_name = true;
            second.reuse_log_name = true;
            if (!hold_thread_runtime())
                return LayeredHost::finish(host.fail("the host did not initialize libwinpthread-1.dll"), "", {});
            if (!host.open_target() || !host.stage(first) || !host.stage(second))
                return LayeredHost::finish(false, "", {&first, &second});
            const bool fresh_process =
                LayeredHost::records().vacant == 0 || host.fail("the process started with a Vacant record");
            const bool proved = fresh_process && reload_alternately(host, first, second, CONSTANT_DEPTH_CYCLES, true);
            return LayeredHost::finish(
                proved,
                "two copies reloaded in turn 1000 times with constant records and RWX bytes and no Vacant record",
                {&first, &second}
            );
        }
    }

    int run_mid_successor_claims_closed_route()
    {
        LayeredHost host{"mid-successor-claims-closed-route"};
        Family first = first_family("layered_mid_first_field");
        Family second = second_family("layered_mid_second_field");
        first.kind = HookKind::Mid;
        second.kind = HookKind::Mid;
        first.reuse_log_name = true;
        second.reuse_log_name = true;
        if (!hold_thread_runtime())
            return LayeredHost::finish(host.fail("the host did not initialize libwinpthread-1.dll"), "", {});
        if (!host.open_target() || !host.stage(first) || !host.stage(second) ||
            !reload_alternately(host, first, second, MID_CYCLES_PER_ORDER, RWX_CENSUS_AVAILABLE))
        {
            return LayeredHost::finish(false, "", {&first, &second});
        }

        // The reverse order maps the same copies under new hook names, so no install claims the field-order position.
        Family second_reverse = second_family("layered_mid_second_reverse");
        Family first_reverse = first_family("layered_mid_first_reverse");
        for (Family *family : {&second_reverse, &first_reverse})
        {
            family->kind = HookKind::Mid;
            family->reuse_log_name = true;
        }
        second_reverse.generation.path = second.generation.path;
        first_reverse.generation.path = first.generation.path;
        const bool proved =
            reload_alternately(host, second_reverse, first_reverse, MID_CYCLES_PER_ORDER, RWX_CENSUS_AVAILABLE);
        return LayeredHost::finish(
            proved,
            "mid successors claimed the closed route in turn in both install orders with constant records",
            {&first_reverse, &second_reverse}
        );
    }

    int run_claimed_position_under_foreign_layer()
    {
        LayeredHost host{"claimed-position-under-foreign-layer"};
        Family first = first_family("layered_first_hook");
        Family second = second_family("layered_second_hook");
        if (!host.open_target() || !host.stage(first) || !host.stage(second))
            return LayeredHost::finish(false, "", {&first, &second});
        const CoordinatorCounts baseline = LayeredHost::records();
        // The second copy makes the first position Vacant and then hands the target back, so the foreign stub
        // relocates the jump of a Vacant position.
        const bool proved = host.start(first, Placement::Fresh) && host.start(second, Placement::Fresh) &&
                            host.call_crosses({&first, &second}) && host.retire(first, Retirement::VacateFresh) &&
                            host.unload(first) && host.retire(second, Retirement::Restore) && host.unload(second) &&
                            host.call_crosses({}) && host.install_foreign(ForeignLayer::Chaining) &&
                            host.call_crosses({}) && host.start(first, Placement::Claim) &&
                            host.call_crosses({&first}) && host.retire(first, Retirement::VacateClaimed) &&
                            host.call_crosses({}, {&first}) && host.unload(first) && host.call_crosses({}) &&
                            host.remove_foreign() && host.call_crosses({}) && host.records_added(baseline, 1, 1);
        return LayeredHost::finish(
            proved,
            "a successor claimed and vacated a position under a foreign stub and wrote none of its bytes",
            {&first, &second}
        );
    }

    int run_residue_budget_pin()
    {
        LayeredHost host{"residue-budget-pin"};
        Family first = first_family("layered_budget_first");
        Family second = second_family("layered_budget_second");
        first.refuse_position_claims = true;
        second.refuse_position_claims = true;
        if (!host.open_target() || !host.stage(first) || !host.stage(second))
            return LayeredHost::finish(false, "", {&first, &second});
        const CoordinatorCounts baseline = LayeredHost::records();
        if (!host.start(first, Placement::Fresh) || !host.start(second, Placement::Fresh) ||
            !host.call_crosses({&first, &second}))
        {
            return LayeredHost::finish(false, "", {&first, &second});
        }

        // With claims refused, each reload leaves one more position, and the copy that reloads is always the lower.
        Family *lower = &first;
        Family *upper = &second;
        for (unsigned reload = 1; reload <= RESIDUE_LAYER_LIMIT; ++reload)
        {
            host.set_cycle(reload);
            const std::size_t layers = LayeredHost::records().live - baseline.live;
            if (layers != std::size_t{reload} + 1)
            {
                const bool counted =
                    host.fail_value("the target did not gain one layer per reload", reload + 1, layers);
                return LayeredHost::finish(counted, "", {&first, &second});
            }
            if (layers > RESIDUE_LAYER_LIMIT)
            {
                // The loader keeps the refused generation mapped, and its detour stays reachable. The upper copy
                // still restores over it.
                const bool proved = host.retire(*lower, Retirement::PinOverBudget) &&
                                    host.call_crosses({lower, upper}) && host.retire(*upper, Retirement::Restore) &&
                                    host.unload(*upper) && host.call_crosses({lower});
                return LayeredHost::finish(
                    proved,
                    "the residue budget engaged past 16 layers, and the lower generation pinned with HookManager",
                    {&first, &second}
                );
            }
            if (!host.retire(*lower, Retirement::VacateFresh) || !host.call_crosses({upper}, {lower}) ||
                !host.unload(*lower) || !host.start(*lower, Placement::Fresh) || !host.call_crosses({lower, upper}))
            {
                return LayeredHost::finish(false, "", {&first, &second});
            }
            // The successor installed on top, so the other copy is now the lower one.
            std::swap(lower, upper);
        }
        return LayeredHost::finish(host.fail("the residue budget did not engage"), "", {&first, &second});
    }

    /**
     * @brief Parks one host call in the lower counted detour and checks that Shutdown defers the retirement.
     * @details Shutdown returns BUSY and keeps every hook armed, so a fresh call crosses both copies. After its
     *          release, the parked call returns through both copies.
     */
    [[nodiscard]] bool parked_call_defers_retirement(LayeredHost &host, Family &lower, Family &upper)
    {
        std::atomic<int> parked_result{0};
        std::atomic<bool> parked_returned{false};
        lower.generation.arm_park();
        std::thread caller;
        try
        {
            caller = std::thread(
                [&host, &parked_result, &parked_returned]() noexcept
                {
                    parked_result.store(host.call_target(), std::memory_order_relaxed);
                    parked_returned.store(true, std::memory_order_release);
                }
            );
        }
        catch (...)
        {
            lower.generation.release_park();
            return host.fail(lower, "the host failed to start the parked caller");
        }
        const bool parked =
            lower.generation.wait_parked(PARK_BUDGET_MS) != 0 || host.fail(lower, "no call parked in the detour");
        const bool deferred =
            parked && host.retire_busy(lower) && host.call_crosses({&lower, &upper}) &&
            (!parked_returned.load(std::memory_order_acquire) || host.fail(lower, "the parked call left early"));
        lower.generation.release_park();
        caller.join();
        const int expected = host.original_result() + lower.active_bonus + upper.active_bonus;
        return deferred && (parked_result.load(std::memory_order_relaxed) == expected ||
                            host.fail(lower, "the released call did not cross both copies"));
    }

    /**
     * @brief Arms one self-retirement in the lower counted detour and checks that the retire call changes nothing.
     * @details The armed call runs HookStack::retire from inside the detour and still crosses both copies.
     */
    [[nodiscard]] bool self_retirement_changes_nothing(LayeredHost &host, Family &lower, Family &upper)
    {
        const Snapshot before = host.snapshot(lower);
        lower.generation.arm_park();
        const bool crossed = host.call_crosses({&lower, &upper});
        lower.generation.release_park();
        if (!crossed)
            return false;
        const staged_gen::Status after = lower.generation.read_status();
        if (after.self_retire_calls != before.status.self_retire_calls + 1)
            return host.fail(lower, "the armed call ran no self-retirement");
        const RetirementOutcome refused = RetirementOutcome::Refused;
        return host.retire_call_reads(lower, before.status, after, refused, ErrorCode::ReentrantCallRejected) &&
               host.unchanged_since(lower, before) && host.call_crosses({&lower, &upper}) &&
               (lower.generation.read_status().retire_calls == after.retire_calls ||
                host.fail(lower, "an unarmed call ran a retire call"));
    }

    int run_parked_counted_detour()
    {
        LayeredHost host{"parked-counted-detour"};
        Family first = counted_family(first_family("layered_first_hook"), DetourPark::Wait);
        Family second = counted_family(second_family("layered_second_hook"));
        first.drain_timeout_ms = BUSY_DRAIN_TIMEOUT_MS;
        const bool proved = host.open_target() && host.stage(first) && host.stage(second) &&
                            reload_lower_under_upper(host, first, second, &parked_call_defers_retirement);
        return LayeredHost::finish(
            proved,
            "a parked counted call deferred the lower retirement with every hook armed, and the retry unmapped it",
            {&first, &second}
        );
    }

    int run_self_retirement()
    {
        LayeredHost host{"self-retirement"};
        Family first = counted_family(first_family("layered_first_hook"), DetourPark::SelfRetire);
        Family second = counted_family(second_family("layered_second_hook"));
        const bool proved = host.open_target() && host.stage(first) && host.stage(second) &&
                            reload_lower_under_upper(host, first, second, &self_retirement_changes_nothing);
        return LayeredHost::finish(
            proved,
            "a counted detour that retired its own stack was refused, and the later Shutdown unmapped the copy",
            {&first, &second}
        );
    }

    /**
     * @struct CountedTeardown
     * @brief One teardown mode of the counted matrix and the export that holds the Vacant positions of that mode.
     * @details The passes of one mode leave six Vacant positions. Three modes on one export leave 18, more than the
     *          16 layers of the residue budget, so each mode takes its own export.
     */
    struct CountedTeardown
    {
        TeardownMode teardown;
        const char *scenario;
        TargetExport target;
    };

    constexpr std::array<CountedTeardown, 3> COUNTED_TEARDOWNS{{
        {TeardownMode::Retire, "counted-lower-copy-retire", DAMAGE_EXPORT},
        {TeardownMode::Destroy, "counted-lower-copy-destroy", ARMOR_EXPORT},
        {TeardownMode::DisableFirst, "counted-lower-copy-disable-first", SPEED_EXPORT},
    }};

    /// Returns a counted copy of @p family under @p teardown that maps the staged file of @p staged.
    [[nodiscard]] Family counted_copy(Family family, TeardownMode teardown, const Family &staged)
    {
        Family counted = counted_family(std::move(family));
        counted.teardown = teardown;
        counted.generation.path = staged.generation.path;
        return counted;
    }

    /**
     * @brief Runs every layered pass of the counted kind under @p mode.
     * @details The passes cover both install orders, a foreign stub that chains, a hijack that does not chain, and
     *          the three hand-back points. Each pass takes new hook names, so no install claims a position that an
     *          earlier pass left Vacant.
     */
    [[nodiscard]] bool run_counted_teardown(const CountedTeardown &mode, const Family &first, const Family &second)
    {
        const TeardownMode teardown = mode.teardown;
        Family first_shutdown = counted_copy(first_family("layered_counted_first_shutdown"), teardown, first);
        Family second_shutdown = counted_copy(second_family("layered_counted_second_shutdown"), teardown, second);
        Family first_field = counted_copy(first_family("layered_counted_first_field"), teardown, first);
        Family second_field = counted_copy(second_family("layered_counted_second_field"), teardown, second);
        Family second_reverse = counted_copy(second_family("layered_counted_second_reverse"), teardown, second);
        Family first_reverse = counted_copy(first_family("layered_counted_first_reverse"), teardown, first);
        Family chaining = counted_copy(first_family("layered_counted_chaining"), teardown, first);
        Family hijack = counted_copy(first_family("layered_counted_hijack"), teardown, first);
        Family first_before = counted_copy(first_family("layered_counted_first_before_init"), teardown, first);
        Family second_before = counted_copy(second_family("layered_counted_second_before_init"), teardown, second);
        Family first_after = counted_copy(first_family("layered_counted_first_after_init"), teardown, first);
        Family second_after = counted_copy(second_family("layered_counted_second_after_init"), teardown, second);

        LayeredHost host{mode.scenario, mode.target};
        return host.open_target() && hand_back_before_shutdown(host, first_shutdown, second_shutdown) &&
               reload_lower_under_upper(host, first_field, second_field) &&
               reload_lower_under_upper(host, second_reverse, first_reverse) &&
               retire_under_foreign_chain(host, chaining) && retire_under_hijack(host, hijack) &&
               hand_back_before_successor_init(host, first_before, second_before) &&
               hand_back_after_successor_init(host, first_after, second_after);
    }

    int run_counted_lower_copy()
    {
        LayeredHost host{"counted-lower-copy"};
        Family first = first_family("layered_counted_first");
        Family second = second_family("layered_counted_second");
        bool proved = host.stage(first) && host.stage(second);
        for (const CountedTeardown &mode : COUNTED_TEARDOWNS)
            proved = proved && run_counted_teardown(mode, first, second);
        return LayeredHost::finish(
            proved,
            "lower counted copies unmapped and successors claimed their positions in every teardown mode and pass",
            {&first, &second}
        );
    }

    /// Maps one command-line token to its scenario.
    struct ScenarioEntry
    {
        std::string_view token;
        int (*run)();
    };

    constexpr std::array<ScenarioEntry, 17> SCENARIOS{{
        {"lower-copy-field-order", &run_lower_copy_field_order},
        {"lower-copy-reverse-order", &run_lower_copy_reverse_order},
        {"disable-first-consumer", &run_disable_first_consumer},
        {"hand-back-before-shutdown", &run_hand_back_before_shutdown},
        {"hand-back-before-successor-init", &run_hand_back_before_successor_init},
        {"hand-back-after-successor-init", &run_hand_back_after_successor_init},
        {"foreign-chaining-layer", &run_foreign_chaining_layer},
        {"non-chaining-hijack", &run_non_chaining_hijack},
        {"lower-mid-copy", &run_lower_mid_copy},
        {"far-hook", &run_far_hook},
        {"alternating-constant-depth", &run_alternating_constant_depth},
        {"mid-successor-claims-closed-route", &run_mid_successor_claims_closed_route},
        {"claimed-position-under-foreign-layer", &run_claimed_position_under_foreign_layer},
        {"residue-budget-pin", &run_residue_budget_pin},
        {"parked-counted-detour", &run_parked_counted_detour},
        {"self-retirement", &run_self_retirement},
        {"counted-lower-copy", &run_counted_lower_copy},
    }};
} // namespace

int main(int argc, char **argv)
{
    const std::string_view scenario = argc > 1 ? std::string_view{argv[1]} : std::string_view{};
    for (const ScenarioEntry &entry : SCENARIOS)
    {
        if (entry.token == scenario)
            return entry.run();
    }
    std::fprintf(stderr, "usage: %s <scenario>\nscenarios:", argc > 0 ? argv[0] : "layered_generation_reload");
    for (const ScenarioEntry &entry : SCENARIOS)
        std::fprintf(stderr, " %.*s", static_cast<int>(entry.token.size()), entry.token.data());
    std::fprintf(stderr, "\n");
    return SETUP_FAILURE;
}
