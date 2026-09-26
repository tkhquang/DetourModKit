/**
 * @file tls_index_return.cpp
 * @brief Fresh-process proofs that each DMK Win32 TLS index returns with its last owner and stays with a live one.
 * @details The return scenarios reserve an index, read the process TLS bitmaps, and require the exact return after the
 *          last owner retires. The live-owner scenarios keep one owner live across another owner's release and require
 *          the index to stay reserved and usable. The diagnostics scenarios drive the teardown release of the two
 *          never-destroyed diagnostics dispatchers. Exit status is the oracle.
 */

#include "DetourModKit/config.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/session.hpp"

#include "internal/drain_backoff.hpp"
#include "internal/input_binding_gate.hpp"
#include "internal/input_delivery_scope.hpp"
#include "internal/memory_fault.hpp"
#include "internal/memory_guarded.hpp"

#include "fixtures/loader_lock_scope.hpp"
#include "fixtures/log_capture.hpp"
#include "fixtures/proof_section.hpp"
#include "tls_census.hpp"

#include <process.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace
{
    using namespace DetourModKit;
    using namespace std::chrono_literals;

    constexpr int SKIP_EXIT_CODE = 77;
    constexpr auto WAIT_LIMIT = 10s;
    // A release that frees under a live owner completes inside this window. A correct release cannot free until that
    // owner retires.
    constexpr auto OWNER_WINDOW = 50ms;

    int fail(int code, const char *message) noexcept
    {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return code;
    }

    template <class Predicate> [[nodiscard]] bool wait_until(Predicate predicate) noexcept
    {
        const auto deadline = std::chrono::steady_clock::now() + WAIT_LIMIT;
        while (!predicate())
        {
            if (std::chrono::steady_clock::now() >= deadline)
                return false;
            std::this_thread::yield();
        }
        return true;
    }

    // Materializes the runtime's lazy per-thread and per-process state before any census, so the census counts only
    // the subject under test.
    void warm_runtime()
    {
        std::thread warm([] {});
        warm.join();
    }

    volatile int s_sink = 0;

    DMK_PROOF_SEEDED_TARGET(tls_target_3, 3)
    DMK_PROOF_SEEDED_TARGET(tls_target_5, 5)
    DMK_PROOF_SEEDED_TARGET(tls_target_7, 7)

    using Target = int (*)(int);

    std::atomic<int> s_mid_hits{0};
    std::optional<hook::Hook> s_self_hook;

    void count_mid(hook::MidContext &) noexcept
    {
        s_mid_hits.fetch_add(1, std::memory_order_relaxed);
    }

    // Destroys its own hook from inside the callback, which retains the slot as Unwaitable.
    void reset_own_hook(hook::MidContext &) noexcept
    {
        s_mid_hits.fetch_add(1, std::memory_order_relaxed);
        s_self_hook.reset();
    }

    [[nodiscard]] Result<hook::Hook> enabled_mid_hook(Target target, hook::MidHookFn callback)
    {
        auto installed = hook::mid_at(
            {
                .name = "tls_index_mid",
                .target = Address{reinterpret_cast<std::uintptr_t>(target)},
            },
            callback
        );
        if (installed && !installed->enable())
            return std::unexpected(Error{ErrorCode::EnableFailed, "tls_index_return"});
        return installed;
    }

    // Installs, fires, and tears down one mid hook, and reports whether the callback ran once.
    [[nodiscard]] bool mid_cycle(Target target) noexcept
    {
        const int before = s_mid_hits.load();
        {
            auto installed = enabled_mid_hook(target, &count_mid);
            if (!installed)
                return false;
            Target volatile call = target;
            (void)call(1);
        }
        return s_mid_hits.load() == before + 1;
    }

    int run_mid_return()
    {
        warm_runtime();
        if (!mid_cycle(&tls_target_3))
            return fail(10, "the warm-up mid hook did not fire");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        const std::size_t leaks = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
        for (Target target : {&tls_target_5, &tls_target_7})
        {
            {
                auto installed = enabled_mid_hook(target, &count_mid);
                if (!installed)
                    return fail(11, "the mid hook did not install");
                if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
                    return fail(12, "a live mid hook did not hold exactly one TLS index");
                const int before = s_mid_hits.load();
                Target volatile call = target;
                (void)call(1);
                if (s_mid_hits.load() != before + 1)
                    return fail(13, "the mid hook on a re-reserved index did not fire");
            }
            if (dmk_lifecycle::free_tls_indices() != baseline)
                return fail(14, "the last released mid slot did not return its TLS index");
        }
        if (diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager) != leaks)
            return fail(15, "a clean mid teardown recorded a leak");
        std::puts("MID_ENTRY_TLS_INDEX_RETURNS_WITH_THE_LAST_SLOT");
        return 0;
    }

    int run_mid_retained()
    {
        warm_runtime();
        if (!mid_cycle(&tls_target_3))
            return fail(20, "the warm-up mid hook did not fire");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        const std::size_t leaks = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
        {
            auto installed = enabled_mid_hook(&tls_target_5, &reset_own_hook);
            if (!installed)
                return fail(21, "the self-retiring mid hook did not install");
            s_self_hook.emplace(std::move(*installed));
        }
        Target volatile retiring = &tls_target_5;
        (void)retiring(1);
        if (s_self_hook.has_value() ||
            diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager) != leaks + 1)
            return fail(22, "the hook destroyed inside its own callback was not retained");
        if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
            return fail(23, "the retained slot did not keep its TLS index");
        if (!mid_cycle(&tls_target_7))
            return fail(24, "a mid hook beside the retained slot did not fire");
        if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
            return fail(25, "a clean release returned the index that the retained slot owns");
        std::puts("MID_ENTRY_TLS_INDEX_STAYS_WITH_A_RETAINED_SLOT");
        return 0;
    }

    int run_mid_exhausted()
    {
        warm_runtime();
        if (!mid_cycle(&tls_target_3))
            return fail(90, "the warm-up mid hook did not fire");
        const std::size_t leaks = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
        std::vector<DWORD> taken;
        taken.reserve(4096);
        for (DWORD index = TlsAlloc(); index != TLS_OUT_OF_INDEXES; index = TlsAlloc())
            taken.push_back(index);
        // No thread starts or ends while every index is taken.
        const auto refused = enabled_mid_hook(&tls_target_5, &count_mid);
        const bool typed = !refused && refused.error().code == ErrorCode::SystemCallFailed;
        for (const DWORD index : taken)
            (void)TlsFree(index);
        if (taken.empty())
            return fail(91, "the process had no TLS index to take");
        if (!typed)
            return fail(92, "mid_at did not refuse with SystemCallFailed while no TLS index was free");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        if (!mid_cycle(&tls_target_7))
            return fail(93, "a mid hook after the refusal did not fire");
        if (dmk_lifecycle::free_tls_indices() != baseline)
            return fail(94, "the refused claim left an owner that keeps the index reserved");
        if (diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager) != leaks)
            return fail(95, "the refused claim recorded a leak");
        std::puts("MID_ENTRY_TLS_INDEX_REFUSAL_RELEASES_ITS_CLAIM");
        return 0;
    }

    struct EmitProbe
    {
        const void *dispatcher = nullptr;
        bool tracked = false;
        int calls = 0;
    };

    // Subscribes, emits once, and reports whether the handler ran inside a recorded emit frame.
    [[nodiscard]] bool emit_cycle(EventDispatcher<int> &dispatcher, Subscription &subscription, EmitProbe &probe)
    {
        probe.dispatcher = &dispatcher;
        subscription = dispatcher.subscribe(
            [&probe](const int &) noexcept
            {
                ++probe.calls;
                probe.tracked = detail::thread_is_emitting_dispatcher(probe.dispatcher);
            }
        );
        dispatcher.emit_safe(1);
        return subscription.active() && probe.calls == 1 && probe.tracked;
    }

    int run_emit_return()
    {
        warm_runtime();
        {
            EventDispatcher<int> warm;
            Subscription subscription;
            EmitProbe probe;
            if (!emit_cycle(warm, subscription, probe))
                return fail(30, "the warm-up emit was not tracked");
        }
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        for (int round = 0; round < 2; ++round)
        {
            {
                EventDispatcher<int> dispatcher;
                Subscription subscription;
                EmitProbe probe;
                if (!emit_cycle(dispatcher, subscription, probe))
                    return fail(31, "an emit on a re-reserved index was not tracked");
                if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
                    return fail(32, "a subscribed dispatcher did not hold exactly one TLS index");
                // A second publish and a refused publish each return their surplus registration.
                Subscription second = dispatcher.subscribe([](const int &) noexcept {});
                if (!second.active())
                    return fail(35, "a second publish on one dispatcher was refused");
                (void)dispatcher.tombstone_and_wait();
                const Subscription refused = dispatcher.subscribe([](const int &) noexcept {});
                if (refused.active())
                    return fail(36, "a publish after the rundown was admitted");
                second.reset();
                subscription.reset();
                if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
                    return fail(33, "the dispatcher returned its index before its destruction");
            }
            if (dmk_lifecycle::free_tls_indices() != baseline)
                return fail(34, "the last subscribed dispatcher did not return its TLS index");
        }
        std::puts("EMIT_TLS_INDEX_RETURNS_WITH_THE_LAST_SUBSCRIBED_DISPATCHER");
        return 0;
    }

    int run_emit_live_owner()
    {
        warm_runtime();
        {
            EventDispatcher<int> warm;
            Subscription subscription;
            EmitProbe probe;
            if (!emit_cycle(warm, subscription, probe))
                return fail(40, "the warm-up emit was not tracked");
        }
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        {
            EventDispatcher<int> live;
            Subscription live_subscription;
            EmitProbe live_probe;
            if (!emit_cycle(live, live_subscription, live_probe))
                return fail(41, "the live dispatcher's emit was not tracked");
            {
                EventDispatcher<int> transient;
                Subscription transient_subscription;
                EmitProbe transient_probe;
                if (!emit_cycle(transient, transient_subscription, transient_probe))
                    return fail(42, "the transient dispatcher's emit was not tracked");
            }
            if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
                return fail(43, "another dispatcher's destruction returned the live dispatcher's index");
            live_probe.calls = 0;
            live_probe.tracked = false;
            live.emit_safe(1);
            if (live_probe.calls != 1 || !live_probe.tracked)
                return fail(44, "the live dispatcher lost its emit frame record");

            // A diagnostics dispatcher is never destroyed. Only a teardown returns its ownership, and none runs here.
            Subscription lifecycle_subscription =
                diagnostics::hook_lifecycle().subscribe([](const diagnostics::HookLifecycleEvent &) noexcept {});
            if (!lifecycle_subscription.active())
                return fail(45, "the diagnostics subscription was refused");
        }
        if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
            return fail(46, "the diagnostics dispatcher returned its index without a teardown");
        std::puts("EMIT_TLS_INDEX_STAYS_WITH_A_LIVE_DISPATCHER");
        return 0;
    }

    int run_delivery_return()
    {
        warm_runtime();
        {
            const detail::DeliveryTlsOwner warm;
            const detail::DeliveryScope scope;
            if (!warm.reserved() || !scope.admitted())
                return fail(50, "the warm-up delivery frame was not recorded");
        }
        if (detail::delivery_scope_tls_index_for_test() != TLS_OUT_OF_INDEXES)
            return fail(51, "the warm-up owner did not return its index");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        for (int round = 0; round < 2; ++round)
        {
            {
                detail::HoldGate gate;
                if (detail::delivery_scope_tls_index_for_test() == TLS_OUT_OF_INDEXES ||
                    dmk_lifecycle::free_tls_indices() + 1 != baseline)
                    return fail(52, "a live gate did not hold exactly one TLS index");
                int calls = 0;
                bool in_delivery = false;
                gate.on_state_change = [&](bool)
                {
                    ++calls;
                    in_delivery = detail::current_thread_in_delivery();
                };
                gate.deliver(true);
                if (calls != 1 || !in_delivery)
                    return fail(53, "a delivery on a re-reserved index was not recorded");
                gate.release();
            }
            if (detail::delivery_scope_tls_index_for_test() != TLS_OUT_OF_INDEXES ||
                dmk_lifecycle::free_tls_indices() != baseline)
                return fail(54, "the last gate did not return its TLS index");
        }
        std::puts("DELIVERY_TLS_INDEX_RETURNS_WITH_THE_LAST_GATE");
        return 0;
    }

    int run_delivery_live_owner()
    {
        warm_runtime();
        {
            const detail::DeliveryTlsOwner warm;
        }
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        std::atomic<bool> parked{false};
        std::atomic<bool> proceed{false};
        std::atomic<bool> in_delivery_after{false};
        int status = 0;
        {
            detail::HoldGate live;
            live.on_state_change = [&](bool active)
            {
                if (!active)
                    return;
                parked.store(true, std::memory_order_release);
                while (!proceed.load(std::memory_order_acquire))
                    std::this_thread::yield();
                in_delivery_after.store(detail::current_thread_in_delivery(), std::memory_order_release);
            };
            std::thread deliverer([&live] { live.deliver(true); });
            if (!wait_until([&] { return parked.load(std::memory_order_acquire); }))
                status = fail(60, "the delivery never parked");
            const DWORD index = detail::delivery_scope_tls_index_for_test();
            if (status == 0 && index == TLS_OUT_OF_INDEXES)
                status = fail(61, "the live gate held no index");
            if (status == 0)
            {
                {
                    detail::PressGate transient;
                }
                {
                    const detail::DeliveryTlsOwner transient_owner;
                }
                std::this_thread::sleep_for(OWNER_WINDOW);
                if (detail::delivery_scope_tls_index_for_test() != index ||
                    dmk_lifecycle::free_tls_indices() + 1 != baseline)
                    status = fail(62, "another owner's release returned the index under a live frame");
            }
            proceed.store(true, std::memory_order_release);
            deliverer.join();
            if (status == 0 && !in_delivery_after.load(std::memory_order_acquire))
                status = fail(63, "the parked frame lost its record");
            live.on_state_change = nullptr;
            live.release();
        }
        if (status == 0 && (detail::delivery_scope_tls_index_for_test() != TLS_OUT_OF_INDEXES ||
                            dmk_lifecycle::free_tls_indices() != baseline))
            status = fail(64, "the last gate did not return its index");
        if (status == 0)
            std::puts("DELIVERY_TLS_INDEX_STAYS_WITH_A_LIVE_GATE");
        return status;
    }

#if !defined(_MSC_VER)
    struct NoAccessPage
    {
        void *base = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
        ~NoAccessPage() noexcept
        {
            if (base != nullptr)
                (void)VirtualFree(base, 0, MEM_RELEASE);
        }
        NoAccessPage() = default;
        NoAccessPage(const NoAccessPage &) = delete;
        NoAccessPage &operator=(const NoAccessPage &) = delete;
        [[nodiscard]] std::uintptr_t address() const noexcept { return reinterpret_cast<std::uintptr_t>(base); }
    };

    constexpr std::uint32_t NO_INDEX = 0xFFFFFFFFu;

    [[nodiscard]] bool guarded_copy(std::uintptr_t address, std::uint64_t &out) noexcept
    {
        return detail::guarded_read_bytes(address, &out, sizeof(out));
    }
#endif

    int run_guarded_read_return()
    {
#if defined(_MSC_VER)
        std::fputs("SKIP: MSVC guarded reads use frame-based SEH and reserve no TLS index\n", stderr);
        return SKIP_EXIT_CODE;
#else
        warm_runtime();
        const std::uint64_t value = 0x1122334455667788ULL;
        const auto value_address = reinterpret_cast<std::uintptr_t>(&value);
        std::uint64_t copy = 0;
        if (!guarded_copy(value_address, copy) || copy != value)
            return fail(70, "the warm-up guarded read failed");
        detail::release_guarded_engine();
        if (detail::guarded_engine_tls_index_for_test() != NO_INDEX)
            return fail(71, "release kept the guarded-read index");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();

        if (!guarded_copy(value_address, copy) || detail::guarded_engine_tls_index_for_test() == NO_INDEX ||
            dmk_lifecycle::free_tls_indices() + 1 != baseline)
            return fail(72, "a reinstall did not reserve exactly one index");
        detail::release_guarded_engine();
        if (detail::guarded_engine_tls_index_for_test() != NO_INDEX || dmk_lifecycle::free_tls_indices() != baseline)
            return fail(73, "release did not return the index");

        // A foreign owner takes the lowest free index, which the release just returned. The next install must reserve
        // another index and never write through the foreign one.
        int sentinel = 0;
        const DWORD foreign = TlsAlloc();
        if (foreign == TLS_OUT_OF_INDEXES || !TlsSetValue(foreign, &sentinel))
            return fail(74, "the foreign owner failed to take an index");
        const NoAccessPage page;
        if (page.base == nullptr)
            return fail(75, "the no-access page was not reserved");
        std::uint64_t sink = 0;
        if (guarded_copy(page.address(), sink))
            return fail(76, "a guarded read of a no-access page reported success");
        const std::uint32_t reinstalled = detail::guarded_engine_tls_index_for_test();
        if (reinstalled == NO_INDEX || reinstalled == foreign || TlsGetValue(foreign) != &sentinel)
            return fail(77, "the reinstall reused or wrote through the foreign index");

        // A refused arm store routes a copy or a write to its fallback and fails a region closed before it touches the
        // range.
        detail::set_guard_arm_failure_for_test(true);
        copy = 0;
        const bool fallback_copied = guarded_copy(value_address, copy) && copy == value;
        const bool fallback_refused = !guarded_copy(page.address(), sink);
        std::uint64_t written = 0;
        const std::uint64_t source = 0xC0FFEEULL;
        const bool fallback_wrote =
            detail::guarded_write_bytes(reinterpret_cast<std::uintptr_t>(&written), &source, sizeof(source)) ==
                detail::GuardedWriteStatus::Ok &&
            written == source;
        const bool fallback_write_refused = detail::guarded_write_bytes(page.address(), &source, sizeof(source)) ==
                                            detail::GuardedWriteStatus::NotWritten;
        bool region_ran = false;
        const bool region_refused = !detail::run_guarded_region(
            page.address(),
            page.address() + 4096,
            [](void *ran) noexcept { *static_cast<bool *>(ran) = true; },
            &region_ran
        );
        detail::set_guard_arm_failure_for_test(false);
        if (!fallback_copied || !fallback_refused || !fallback_wrote || !fallback_write_refused || !region_refused ||
            region_ran)
            return fail(78, "an unarmed guarded access did not take its fallback or fail closed");

        detail::release_guarded_engine();
        (void)TlsFree(foreign);
        if (detail::guarded_engine_tls_index_for_test() != NO_INDEX || dmk_lifecycle::free_tls_indices() != baseline)
            return fail(79, "the final release did not return the index");
        std::puts("GUARDED_READ_TLS_INDEX_RETURNS_ON_RELEASE");
        return 0;
#endif
    }

#if !defined(_MSC_VER)
    struct ParkedRegion
    {
        std::uintptr_t page = 0;
        std::atomic<bool> inside{false};
        std::atomic<bool> proceed{false};
        std::atomic<bool> fault{false};
    };

    void park_in_region(void *context) noexcept
    {
        auto *const region = static_cast<ParkedRegion *>(context);
        region->inside.store(true, std::memory_order_release);
        while (!region->proceed.load(std::memory_order_acquire))
            std::this_thread::yield();
        if (region->fault.load(std::memory_order_acquire))
            s_sink = *reinterpret_cast<volatile int *>(region->page);
    }
#endif

    int run_guarded_read_in_flight()
    {
#if defined(_MSC_VER)
        std::fputs("SKIP: MSVC guarded reads use frame-based SEH and reserve no TLS index\n", stderr);
        return SKIP_EXIT_CODE;
#else
        warm_runtime();
        const std::uint64_t value = 0x5A5A5A5A5A5A5A5AULL;
        std::uint64_t copy = 0;
        if (!guarded_copy(reinterpret_cast<std::uintptr_t>(&value), copy))
            return fail(80, "the install read failed");
        detail::release_guarded_engine();
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        if (!guarded_copy(reinterpret_cast<std::uintptr_t>(&value), copy))
            return fail(81, "the reinstall read failed");
        const std::uint32_t index = detail::guarded_engine_tls_index_for_test();
        const NoAccessPage page;
        if (index == NO_INDEX || page.base == nullptr)
            return fail(82, "the parked region had no index or no page");

        // This thread must not run a guarded access while the release holds the engine lock.
        ParkedRegion region{
            .page = page.address(),
        };
        std::atomic<bool> region_completed{true};
        std::atomic<bool> released{false};
        std::thread accessor(
            [&]
            {
                region_completed.store(
                    detail::run_guarded_region(page.address(), page.address() + 4096, &park_in_region, &region),
                    std::memory_order_release
                );
            }
        );
        int status = 0;
        if (!wait_until([&] { return region.inside.load(std::memory_order_acquire); }))
            status = fail(83, "the guarded region never parked");
        std::thread releaser;
        if (status == 0)
        {
            releaser = std::thread(
                [&]
                {
                    detail::release_guarded_engine();
                    released.store(true, std::memory_order_release);
                }
            );
            std::this_thread::sleep_for(OWNER_WINDOW);
            if (released.load(std::memory_order_acquire) || detail::guarded_engine_tls_index_for_test() != index ||
                dmk_lifecycle::free_tls_indices() + 1 != baseline)
                status = fail(84, "the release returned the index under an in-flight access");
        }
        // Fault inside the range only when the handler and its index are still live, so a defect exits cleanly.
        region.fault.store(status == 0, std::memory_order_release);
        region.proceed.store(true, std::memory_order_release);
        accessor.join();
        if (releaser.joinable())
            releaser.join();
        if (status == 0 && region_completed.load(std::memory_order_acquire))
            status = fail(85, "the fault inside the in-flight region was not contained");
        if (status == 0 &&
            (detail::guarded_engine_tls_index_for_test() != NO_INDEX || dmk_lifecycle::free_tls_indices() != baseline))
            status = fail(86, "the drained release did not return the index");
        if (status == 0)
            std::puts("GUARDED_READ_TLS_INDEX_WAITS_FOR_THE_IN_FLIGHT_ACCESS");
        return status;
#endif
    }

    // The diagnostics teardown waits up to one second for a running emit. These bounds sit on either side of it.
    constexpr auto HANDLER_RESUME_DELAY = 200ms;
    constexpr auto WAITED_FLOOR = 150ms;
    constexpr auto TEARDOWN_WAIT_FLOOR = 900ms;
    constexpr auto NO_WAIT_CEILING = 500ms;

    [[nodiscard]] std::size_t diagnostics_leaks() noexcept
    {
        return diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::Diagnostics);
    }

    void emit_lifecycle() noexcept
    {
        diagnostics::hook_lifecycle().emit_safe(
            diagnostics::HookLifecycleEvent{
                .name = "tls_index_return",
                .transition = diagnostics::HookTransition::Created,
            }
        );
    }

    void emit_scanner_fault() noexcept
    {
        diagnostics::scanner_faults().emit_safe(
            diagnostics::ScannerFaultEvent{
                .faulted_regions = 1,
            }
        );
    }

    [[nodiscard]] std::chrono::milliseconds elapsed_since(std::chrono::steady_clock::time_point start) noexcept
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    }

    /// Counts diagnostics handler calls and records whether the last one ran inside a tracked frame.
    struct DiagnosticsProbe
    {
        std::atomic<int> calls{0};
        std::atomic<bool> tracked{false};
    };

    template <class Event>
    [[nodiscard]] Subscription subscribe_probe(EventDispatcher<Event> &dispatcher, DiagnosticsProbe &probe)
    {
        return dispatcher.subscribe(
            [&dispatcher, &probe](const Event &) noexcept
            {
                probe.calls.fetch_add(1, std::memory_order_relaxed);
                probe.tracked.store(detail::thread_is_emitting_dispatcher(&dispatcher), std::memory_order_relaxed);
            }
        );
    }

    /// Returns true when one emit on each dispatcher reached its subscription inside a tracked frame.
    [[nodiscard]] bool diagnostics_emits_tracked(Subscription &lifecycle, Subscription &faults, DiagnosticsProbe &probe)
    {
        const int before = probe.calls.load(std::memory_order_relaxed);
        emit_lifecycle();
        const bool lifecycle_tracked = probe.tracked.load(std::memory_order_relaxed);
        probe.tracked.store(false, std::memory_order_relaxed);
        emit_scanner_fault();
        return lifecycle.active() && faults.active() && lifecycle_tracked &&
               probe.tracked.load(std::memory_order_relaxed) &&
               probe.calls.load(std::memory_order_relaxed) == before + 2;
    }

    [[nodiscard]] std::string session_log_name(const char *tag)
    {
        return std::string("tls_index_return_") + tag + "_" + std::to_string(_getpid()) + ".log";
    }

    [[nodiscard]] bool start_session(std::optional<Session> &session, const std::string &log_file) noexcept
    {
        Result<Session> started = Session::start(
            ModInfo{
                .name = "TLS_INDEX_RETURN",
                .log_file = log_file,
            }
        );
        if (!started)
            return false;
        session.emplace(std::move(*started));
        return true;
    }

    [[nodiscard]] std::string read_text(const std::string &path)
    {
        std::ifstream in(path);
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }

    void remove_file(const std::string &path) noexcept
    {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    /**
     * @brief Runs one subscribe, emit, and teardown cycle on both dispatchers before a census.
     * @details The first cycle constructs both dispatchers and the logger state that a later census must not count.
     */
    [[nodiscard]] bool warm_diagnostics(const std::string &log_file)
    {
        warm_runtime();
        std::optional<Session> session;
        if (!log_file.empty() && !start_session(session, log_file))
            return false;
        DiagnosticsProbe probe;
        bool tracked = false;
        {
            Subscription lifecycle = subscribe_probe(diagnostics::hook_lifecycle(), probe);
            Subscription faults = subscribe_probe(diagnostics::scanner_faults(), probe);
            tracked = diagnostics_emits_tracked(lifecycle, faults, probe);
        }
        session.reset();
        memory::shutdown_cache();
        return tracked && diagnostics_leaks() == 0;
    }

    /// Parks one diagnostics handler invocation on its own thread until the case resumes it.
    template <class Event> class ParkedHandler
    {
    public:
        ParkedHandler(EventDispatcher<Event> &dispatcher, void (*emit)() noexcept)
            : m_dispatcher(dispatcher), m_subscription(dispatcher.subscribe(
                                            [this](const Event &) noexcept
                                            {
                                                m_parked.store(true, std::memory_order_release);
                                                while (!m_proceed.load(std::memory_order_acquire))
                                                    std::this_thread::yield();
                                                m_tracked_after_resume.store(
                                                    detail::thread_is_emitting_dispatcher(&m_dispatcher),
                                                    std::memory_order_release
                                                );
                                            }
                                        )),
              m_emitter(emit)
        {
        }

        ~ParkedHandler() { resume(); }

        ParkedHandler(const ParkedHandler &) = delete;
        ParkedHandler &operator=(const ParkedHandler &) = delete;
        ParkedHandler(ParkedHandler &&) = delete;
        ParkedHandler &operator=(ParkedHandler &&) = delete;

        [[nodiscard]] bool wait_parked() noexcept
        {
            return wait_until([this] { return m_parked.load(std::memory_order_acquire); });
        }

        /// Compacts the running entry out of the current list.
        void reset_subscription() noexcept { m_subscription.reset(); }

        /// Lets the handler return without a join.
        void signal() noexcept { m_proceed.store(true, std::memory_order_release); }

        void resume()
        {
            signal();
            if (m_emitter.joinable())
                m_emitter.join();
        }

        [[nodiscard]] bool tracked_after_resume() const noexcept
        {
            return m_tracked_after_resume.load(std::memory_order_acquire);
        }

    private:
        EventDispatcher<Event> &m_dispatcher;
        std::atomic<bool> m_parked{false};
        std::atomic<bool> m_proceed{false};
        std::atomic<bool> m_tracked_after_resume{false};
        Subscription m_subscription;
        std::thread m_emitter;
    };

    /// Counts each destruction of a callable copy that still owns the counter.
    class CountedHandler
    {
    public:
        explicit CountedHandler(std::atomic<int> *destroyed) noexcept : m_destroyed(destroyed) {}
        CountedHandler(const CountedHandler &other) noexcept = default;
        CountedHandler &operator=(const CountedHandler &) = delete;
        CountedHandler(CountedHandler &&other) noexcept : m_destroyed(std::exchange(other.m_destroyed, nullptr)) {}
        CountedHandler &operator=(CountedHandler &&) = delete;
        ~CountedHandler() noexcept
        {
            if (m_destroyed != nullptr)
                m_destroyed->fetch_add(1, std::memory_order_relaxed);
        }

        void operator()(const diagnostics::HookLifecycleEvent &) const noexcept {}

    private:
        std::atomic<int> *m_destroyed;
    };

    int run_diagnostics_session()
    {
        const std::string log_file = session_log_name("session");
        if (!warm_diagnostics(log_file))
            return fail(100, "the warm-up diagnostics cycle was not tracked");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        std::optional<Session> session;
        if (!start_session(session, log_file))
            return fail(101, "the Session did not start");
        DiagnosticsProbe probe;
        {
            const auto lifecycle =
                std::make_shared<Subscription>(subscribe_probe(diagnostics::hook_lifecycle(), probe));
            Subscription faults = subscribe_probe(diagnostics::scanner_faults(), probe);
            if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
                return fail(102, "two diagnostics subscriptions did not share exactly one TLS index");
            if (!diagnostics_emits_tracked(*lifecycle, faults, probe))
                return fail(103, "a diagnostics emit was not tracked");
            // The production emit path, a hook transition, also records its frame.
            probe.tracked.store(false, std::memory_order_relaxed);
            if (!mid_cycle(&tls_target_3) || !probe.tracked.load(std::memory_order_relaxed))
                return fail(104, "a hook transition emit was not tracked");
            // A config callback keeps the lifecycle subscription live until config::clear() inside ~Session.
            config::bind_int("TlsIndexReturn", "Owner", "tls_index_return_owner", [lifecycle](int) noexcept {}, 0);
        }
        session.reset();
        if (dmk_lifecycle::free_tls_indices() != baseline)
            return fail(105, "Session teardown did not return the diagnostics TLS index");
        if (diagnostics_leaks() != 0)
            return fail(106, "a clean Session teardown recorded a diagnostics leak");

        // A later subscription reserves a fresh index through the first publish and records its frames.
        {
            Subscription lifecycle = subscribe_probe(diagnostics::hook_lifecycle(), probe);
            Subscription faults = subscribe_probe(diagnostics::scanner_faults(), probe);
            if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
                return fail(107, "a later subscription did not reserve exactly one TLS index");
            if (!diagnostics_emits_tracked(lifecycle, faults, probe))
                return fail(108, "an emit after the teardown release was not tracked");
        }
        memory::shutdown_cache();
        if (dmk_lifecycle::free_tls_indices() != baseline || diagnostics_leaks() != 0)
            return fail(109, "the later subscription's index did not return");
        remove_file(log_file);
        std::puts("DIAGNOSTICS_TLS_INDEX_RETURNS_WITH_THE_SESSION");
        return 0;
    }

    int run_diagnostics_cache_shutdown()
    {
        if (!warm_diagnostics({}))
            return fail(110, "the warm-up diagnostics cycle was not tracked");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        DiagnosticsProbe probe;
        {
            Subscription lifecycle = subscribe_probe(diagnostics::hook_lifecycle(), probe);
            Subscription faults = subscribe_probe(diagnostics::scanner_faults(), probe);
            if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
                return fail(111, "two diagnostics subscriptions did not share exactly one TLS index");
            // A live subscription stays an ordinary owner across a cache shutdown without a Session.
            memory::shutdown_cache();
            if (dmk_lifecycle::free_tls_indices() + 1 != baseline || diagnostics_leaks() != 0)
                return fail(112, "a cache shutdown under a live subscription returned the index or recorded a leak");
            if (!diagnostics_emits_tracked(lifecycle, faults, probe))
                return fail(113, "an emit after the cache shutdown was not tracked");
        }
        memory::shutdown_cache();
        if (dmk_lifecycle::free_tls_indices() != baseline)
            return fail(114, "a cache shutdown without a Session did not return the index");
        if (diagnostics_leaks() != 0)
            return fail(115, "a clean cache shutdown recorded a diagnostics leak");
        std::puts("DIAGNOSTICS_TLS_INDEX_RETURNS_ON_CACHE_SHUTDOWN_WITHOUT_A_SESSION");
        return 0;
    }

    int run_diagnostics_cache_restart()
    {
        const std::string log_file = session_log_name("restart");
        if (!warm_diagnostics(log_file))
            return fail(120, "the warm-up diagnostics cycle was not tracked");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        std::optional<Session> session;
        if (!start_session(session, log_file))
            return fail(121, "the Session did not start");
        DiagnosticsProbe probe;
        {
            Subscription lifecycle = subscribe_probe(diagnostics::hook_lifecycle(), probe);
            Subscription faults = subscribe_probe(diagnostics::scanner_faults(), probe);
            // A cache restart inside a Session is ordinary operation, not a teardown.
            memory::shutdown_cache();
            if (!memory::init_cache())
                return fail(122, "the cache did not restart");
            memory::shutdown_cache();
            if (dmk_lifecycle::free_tls_indices() + 1 != baseline || diagnostics_leaks() != 0)
                return fail(123, "a cache restart inside a Session returned the index or recorded a leak");
            if (!diagnostics_emits_tracked(lifecycle, faults, probe))
                return fail(124, "an emit after the cache restart was not tracked");
        }
        // Inside a Session, the Session teardown owns the release.
        memory::shutdown_cache();
        if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
            return fail(125, "a cache shutdown inside a Session returned the index");
        session.reset();
        if (dmk_lifecycle::free_tls_indices() != baseline || diagnostics_leaks() != 0)
            return fail(126, "Session teardown after a cache restart did not return the index cleanly");
        remove_file(log_file);
        std::puts("DIAGNOSTICS_TLS_INDEX_STAYS_THROUGH_A_CACHE_RESTART");
        return 0;
    }

    int run_diagnostics_live()
    {
        const std::string log_file = session_log_name("live");
        if (!warm_diagnostics(log_file))
            return fail(130, "the warm-up diagnostics cycle was not tracked");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        DiagnosticsProbe probe;
        Subscription lifecycle;
        {
            std::optional<Session> session;
            if (!start_session(session, log_file))
                return fail(131, "the Session did not start");
            lifecycle = subscribe_probe(diagnostics::hook_lifecycle(), probe);
        }
        if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
            return fail(132, "Session teardown returned the index under a live subscription");
        if (diagnostics_leaks() != 1)
            return fail(133, "the index kept by a live subscription did not record one diagnostics leak");
        const std::string text = read_text(log_file);
        if (text.find("hook_lifecycle dispatcher kept its emit TLS index") == std::string::npos ||
            text.find("a subscription is still live") == std::string::npos)
            return fail(134, "the kept index did not log its cause");
        probe.tracked.store(false, std::memory_order_relaxed);
        emit_lifecycle();
        if (!probe.tracked.load(std::memory_order_relaxed))
            return fail(135, "an emit on the kept index was not tracked");
        {
            std::optional<Session> session;
            if (!start_session(session, log_file))
                return fail(136, "the second Session did not start");
        }
        if (diagnostics_leaks() != 1)
            return fail(137, "a second teardown counted the same kept index again");
        lifecycle.reset();
        memory::shutdown_cache();
        if (dmk_lifecycle::free_tls_indices() != baseline || diagnostics_leaks() != 1)
            return fail(138, "a later cache shutdown did not return the kept index");
        // A return ends that ownership, so a new kept ownership records again.
        {
            std::optional<Session> session;
            if (!start_session(session, log_file))
                return fail(131, "the Session did not start");
            lifecycle = subscribe_probe(diagnostics::hook_lifecycle(), probe);
        }
        lifecycle.reset();
        memory::shutdown_cache();
        if (diagnostics_leaks() != 2 || dmk_lifecycle::free_tls_indices() != baseline)
            return fail(139, "a new kept ownership after a return did not record again");
        remove_file(log_file);
        std::puts("DIAGNOSTICS_TLS_INDEX_STAYS_WITH_A_LIVE_SUBSCRIPTION");
        return 0;
    }

    int run_diagnostics_running()
    {
        const std::string log_file = session_log_name("running");
        if (!warm_diagnostics(log_file))
            return fail(140, "the warm-up diagnostics cycle was not tracked");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        std::optional<Session> session;
        if (!start_session(session, log_file))
            return fail(141, "the Session did not start");
        ParkedHandler<diagnostics::HookLifecycleEvent> parked{diagnostics::hook_lifecycle(), &emit_lifecycle};
        if (!parked.wait_parked())
            return fail(142, "the diagnostics handler never parked");
        // reset() compacts the running entry out of the current list, so only the held list shows the handler.
        parked.reset_subscription();
        std::thread resumer(
            [&parked]
            {
                std::this_thread::sleep_for(HANDLER_RESUME_DELAY);
                parked.signal();
            }
        );
        const auto start = std::chrono::steady_clock::now();
        session.reset();
        const auto waited = elapsed_since(start);
        resumer.join();
        parked.resume();
        if (waited < WAITED_FLOOR || waited >= TEARDOWN_WAIT_FLOOR)
            return fail(143, "Session teardown did not wait for the running handler inside its bound");
        if (!parked.tracked_after_resume())
            return fail(144, "the index was returned while the handler still ran");
        if (dmk_lifecycle::free_tls_indices() != baseline || diagnostics_leaks() != 0)
            return fail(145, "the teardown that outwaited the handler did not return the index cleanly");
        remove_file(log_file);
        std::puts("DIAGNOSTICS_TLS_INDEX_WAITS_FOR_A_RUNNING_HANDLER");
        return 0;
    }

    int run_diagnostics_parked()
    {
        const std::string log_file = session_log_name("parked");
        if (!warm_diagnostics(log_file))
            return fail(150, "the warm-up diagnostics cycle was not tracked");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        std::optional<Session> session;
        if (!start_session(session, log_file))
            return fail(151, "the Session did not start");
        ParkedHandler<diagnostics::HookLifecycleEvent> parked{diagnostics::hook_lifecycle(), &emit_lifecycle};
        if (!parked.wait_parked())
            return fail(152, "the diagnostics handler never parked");
        parked.reset_subscription();
        const auto start = std::chrono::steady_clock::now();
        session.reset();
        const auto waited = elapsed_since(start);
        int status = 0;
        if (waited < TEARDOWN_WAIT_FLOOR)
            status = fail(153, "Session teardown did not wait out its bound for the parked handler");
        if (status == 0 && dmk_lifecycle::free_tls_indices() + 1 != baseline)
            status = fail(154, "Session teardown returned the index under a parked handler");
        if (status == 0 && diagnostics_leaks() != 1)
            status = fail(155, "the index kept by a parked handler did not record one diagnostics leak");
        if (status == 0 && read_text(log_file).find("an emit still held a handler list") == std::string::npos)
            status = fail(156, "the kept index did not log its cause");
        parked.resume();
        if (status == 0 && !parked.tracked_after_resume())
            status = fail(157, "the parked handler lost its tracked frame");
        memory::shutdown_cache();
        if (status == 0 && (dmk_lifecycle::free_tls_indices() != baseline || diagnostics_leaks() != 1))
            status = fail(158, "a later cache shutdown did not return the kept index");
        if (status == 0)
        {
            remove_file(log_file);
            std::puts("DIAGNOSTICS_TLS_INDEX_STAYS_WITH_A_PARKED_HANDLER");
        }
        return status;
    }

    int run_diagnostics_self()
    {
        if (!warm_diagnostics({}))
            return fail(160, "the warm-up diagnostics cycle was not tracked");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        // The other dispatcher holds a running handler too, so a wait on either lasts the whole bound.
        ParkedHandler<diagnostics::ScannerFaultEvent> parked{diagnostics::scanner_faults(), &emit_scanner_fault};
        if (!parked.wait_parked())
            return fail(161, "the scanner-fault handler never parked");
        parked.reset_subscription();
        std::chrono::milliseconds waited{-1};
        std::uint64_t pauses = ~std::uint64_t{0};
        Subscription self;
        self = diagnostics::hook_lifecycle().subscribe(
            [&](const diagnostics::HookLifecycleEvent &) noexcept
            {
                self.tombstone();
                const std::uint64_t pauses_before = detail::g_drain_backoff_yields.load(std::memory_order_relaxed) +
                                                    detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
                const auto start = std::chrono::steady_clock::now();
                memory::shutdown_cache();
                waited = elapsed_since(start);
                pauses = detail::g_drain_backoff_yields.load(std::memory_order_relaxed) +
                         detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed) - pauses_before;
            }
        );
        emit_lifecycle();
        int status = 0;
        if (pauses != 0 || waited >= NO_WAIT_CEILING)
            status = fail(162, "a teardown inside a diagnostics handler waited");
        if (status == 0 && dmk_lifecycle::free_tls_indices() + 1 != baseline)
            status = fail(163, "a teardown inside a diagnostics handler returned the index");
        if (status == 0 && diagnostics_leaks() != 2)
            status = fail(164, "the two kept ownerships did not record one diagnostics leak each");
        self.reset();
        parked.resume();
        memory::shutdown_cache();
        if (status == 0 && (dmk_lifecycle::free_tls_indices() != baseline || diagnostics_leaks() != 2))
            status = fail(165, "a later cache shutdown did not return the kept index");
        if (status == 0)
            std::puts("DIAGNOSTICS_TLS_INDEX_TEARDOWN_INSIDE_A_HANDLER_NEVER_WAITS");
        return status;
    }

    int run_diagnostics_loader_lock()
    {
        if (!warm_diagnostics({}))
            return fail(170, "the warm-up diagnostics cycle was not tracked");
        const dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Trace};
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();

        // An idle owner returns its index in one attempt, without the prune and its callable destruction.
        std::atomic<int> destroyed{0};
        Subscription retired = diagnostics::hook_lifecycle().subscribe(CountedHandler{&destroyed});
        retired.tombstone();
        if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
            return fail(171, "the retired subscription did not hold exactly one TLS index");
        const int destroyed_before = destroyed.load(std::memory_order_relaxed);
        {
            const dmk_test::ForcedLoaderProbe held;
            memory::shutdown_cache();
        }
        if (dmk_lifecycle::free_tls_indices() != baseline ||
            destroyed.load(std::memory_order_relaxed) != destroyed_before || diagnostics_leaks() != 0)
            return fail(172, "a loader-lock release did not return the idle index without a callable destruction");
        retired.reset();

        // A running handler keeps the index at once, with a record and no log.
        int status = 0;
        {
            ParkedHandler<diagnostics::HookLifecycleEvent> parked{diagnostics::hook_lifecycle(), &emit_lifecycle};
            if (!parked.wait_parked())
                return fail(173, "the diagnostics handler never parked");
            parked.reset_subscription();
            const std::uint64_t pauses_before = detail::g_drain_backoff_yields.load(std::memory_order_relaxed) +
                                                detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
            const auto start = std::chrono::steady_clock::now();
            {
                const dmk_test::ForcedLoaderProbe held;
                memory::shutdown_cache();
            }
            const auto waited = elapsed_since(start);
            const std::uint64_t pauses = detail::g_drain_backoff_yields.load(std::memory_order_relaxed) +
                                         detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed) - pauses_before;
            if (pauses != 0 || waited >= NO_WAIT_CEILING)
                status = fail(174, "a loader-lock release waited for a running handler");
            if (status == 0 && dmk_lifecycle::free_tls_indices() + 1 != baseline)
                status = fail(175, "a loader-lock release returned the index under a running handler");
            if (status == 0 && diagnostics_leaks() != 1)
                status = fail(176, "the index kept under the loader lock did not record one diagnostics leak");
            if (status == 0 && capture.read_all().find("kept its emit TLS index") != std::string::npos)
                status = fail(177, "a loader-lock release logged");
        }
        memory::shutdown_cache();
        if (status == 0 && (dmk_lifecycle::free_tls_indices() != baseline || diagnostics_leaks() != 1))
            status = fail(178, "a later cache shutdown did not return the kept index");
        if (status == 0)
            std::puts("DIAGNOSTICS_TLS_INDEX_LOADER_LOCK_RELEASE_NEVER_WAITS");
        return status;
    }

    int run_diagnostics_process_exit()
    {
        if (!warm_diagnostics({}))
            return fail(180, "the warm-up diagnostics cycle was not tracked");
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        DiagnosticsProbe probe;
        {
            Subscription lifecycle = subscribe_probe(diagnostics::hook_lifecycle(), probe);
            emit_lifecycle();
            if (!probe.tracked.load(std::memory_order_relaxed))
                return fail(181, "the diagnostics emit was not tracked");
        }
        {
            const dmk_test::ForcedLoaderProbe held;
            detail::lifecycle().set_loader_context(detail::LoaderContext::ProcessExit);
            memory::shutdown_cache();
        }
        if (dmk_lifecycle::free_tls_indices() + 1 != baseline || diagnostics_leaks() != 0)
            return fail(182, "a process-exit teardown touched the diagnostics ownership");
        memory::shutdown_cache();
        if (dmk_lifecycle::free_tls_indices() != baseline || diagnostics_leaks() != 0)
            return fail(183, "a later cache shutdown did not return the idle index");
        std::puts("DIAGNOSTICS_TLS_INDEX_PROCESS_EXIT_SKIPS_THE_RELEASE");
        return 0;
    }

    int run_diagnostics_untracked()
    {
        if (!warm_diagnostics({}))
            return fail(190, "the warm-up diagnostics cycle was not tracked");
        const dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Trace};
        const std::size_t baseline = dmk_lifecycle::free_tls_indices();
        int status = 0;
        {
            ParkedHandler<diagnostics::HookLifecycleEvent> parked{diagnostics::hook_lifecycle(), &emit_lifecycle};
            if (!parked.wait_parked())
                return fail(191, "the diagnostics handler never parked");
            parked.reset_subscription();
            // An emit without a recorded frame can run on the teardown thread, so the teardown cannot prove that a wait
            // ends.
            detail::untracked_emit_frames().fetch_add(1, std::memory_order_seq_cst);
            const std::uint64_t pauses_before = detail::g_drain_backoff_yields.load(std::memory_order_relaxed) +
                                                detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed);
            const auto start = std::chrono::steady_clock::now();
            memory::shutdown_cache();
            const auto waited = elapsed_since(start);
            const std::uint64_t pauses = detail::g_drain_backoff_yields.load(std::memory_order_relaxed) +
                                         detail::g_drain_backoff_sleeps.load(std::memory_order_relaxed) - pauses_before;
            detail::untracked_emit_frames().fetch_sub(1, std::memory_order_seq_cst);
            if (pauses != 0 || waited >= NO_WAIT_CEILING)
                status = fail(192, "a teardown waited while an untracked emit ran");
            if (status == 0 && dmk_lifecycle::free_tls_indices() + 1 != baseline)
                status = fail(193, "a teardown returned the index while an untracked emit ran");
            if (status == 0 && diagnostics_leaks() != 1)
                status = fail(194, "the index kept while an untracked emit ran did not record one diagnostics leak");
            if (status == 0 && capture.read_all().find("or while an untracked emit ran") == std::string::npos)
                status = fail(195, "the kept index did not log its cause");
        }
        memory::shutdown_cache();
        if (status == 0 && (dmk_lifecycle::free_tls_indices() != baseline || diagnostics_leaks() != 1))
            status = fail(196, "a later cache shutdown did not return the kept index");
        if (status == 0)
            std::puts("DIAGNOSTICS_TLS_INDEX_TEARDOWN_WITH_AN_UNTRACKED_EMIT_NEVER_WAITS");
        return status;
    }
    int run_loader_shutdown_child(int schedule, const char *marker)
    {
        const HMODULE fixture = LoadLibraryW(L"process_exit_release_dll.dll");
        if (fixture == nullptr)
            return fail(200, "the process-exit fixture did not load");
        using Prepare = int (*)(int, const wchar_t *);
        const auto prepare =
            reinterpret_cast<Prepare>(reinterpret_cast<void *>(GetProcAddress(fixture, "dmk_prepare_process_exit")));
        if (prepare == nullptr || prepare(schedule, std::filesystem::path(marker).c_str()) != 0)
            return fail(201, "the process-exit resource did not park");
        // Return through main so the loader terminates the parked thread before DLL_PROCESS_DETACH.
        return 0;
    }

    int run_loader_shutdown(int schedule)
    {
#if defined(_MSC_VER)
        if (schedule != 2)
            return SKIP_EXIT_CODE;
#endif
        static unsigned int s_marker_counter = 0;
        const auto marker = std::filesystem::temp_directory_path() / ("dmk_exit_" + std::to_string(_getpid()) + "_" +
                                                                      std::to_string(s_marker_counter++) + ".marker");
        wchar_t executable[MAX_PATH]{};
        if (GetModuleFileNameW(nullptr, executable, MAX_PATH) == 0)
            return fail(202, "the host path was unavailable");
        std::wstring command = L"\"" + std::wstring(executable) + L"\" process-exit-child " +
                               std::to_wstring(schedule) + L" \"" + marker.wstring() + L"\"";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION child{};
        if (!CreateProcessW(
                executable,
                command.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &startup,
                &child
            ))
            return fail(203, "the exit child did not start");
        CloseHandle(child.hThread);
        const DWORD wait = WaitForSingleObject(child.hProcess, 10000);
        if (wait != WAIT_OBJECT_0)
        {
            TerminateProcess(child.hProcess, 204);
            WaitForSingleObject(child.hProcess, 5000);
        }
        DWORD code = 0;
        GetExitCodeProcess(child.hProcess, &code);
        CloseHandle(child.hProcess);
        std::ifstream stream(marker, std::ios::binary);
        const std::string contents{std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
        stream.close();
        std::error_code ignored;
        std::filesystem::remove(marker, ignored);
        if (wait != WAIT_OBJECT_0 || code != 0)
            return fail(204, "the child did not exit cleanly within the deadline");
        if (contents != std::string("EXIT_RELEASE_RETURNED", sizeof("EXIT_RELEASE_RETURNED")))
            return fail(205, "the loader teardown did not return without a diagnostics leak");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc == 4 && std::string_view{argv[1]} == "process-exit-child")
    {
        const std::string_view schedule{argv[2]};
        if (schedule != "0" && schedule != "1" && schedule != "2")
            return 1;
        return run_loader_shutdown_child(argv[2][0] - '0', argv[3]);
    }
    const std::string_view scenario = argc == 2 ? std::string_view{argv[1]} : std::string_view{};
    if (scenario == "guarded-process-exit")
        return run_loader_shutdown(0);
    if (scenario == "guarded-lock-process-exit")
        return run_loader_shutdown(1);
    if (scenario == "diagnostics-loader-shutdown")
        return run_loader_shutdown(2);
    if (scenario == "mid-return")
        return run_mid_return();
    if (scenario == "mid-retained")
        return run_mid_retained();
    if (scenario == "mid-exhausted")
        return run_mid_exhausted();
    if (scenario == "emit-return")
        return run_emit_return();
    if (scenario == "emit-live-owner")
        return run_emit_live_owner();
    if (scenario == "delivery-return")
        return run_delivery_return();
    if (scenario == "delivery-live-owner")
        return run_delivery_live_owner();
    if (scenario == "guarded-read-return")
        return run_guarded_read_return();
    if (scenario == "guarded-read-in-flight")
        return run_guarded_read_in_flight();
    if (scenario == "diagnostics-session")
        return run_diagnostics_session();
    if (scenario == "diagnostics-cache-shutdown")
        return run_diagnostics_cache_shutdown();
    if (scenario == "diagnostics-cache-restart")
        return run_diagnostics_cache_restart();
    if (scenario == "diagnostics-live")
        return run_diagnostics_live();
    if (scenario == "diagnostics-running")
        return run_diagnostics_running();
    if (scenario == "diagnostics-parked")
        return run_diagnostics_parked();
    if (scenario == "diagnostics-self")
        return run_diagnostics_self();
    if (scenario == "diagnostics-loader-lock")
        return run_diagnostics_loader_lock();
    if (scenario == "diagnostics-process-exit")
        return run_diagnostics_process_exit();
    if (scenario == "diagnostics-untracked")
        return run_diagnostics_untracked();
    // Exit status is the only oracle, so an unimplemented token must fail rather than fall through to a scenario.
    std::fputs(
        "usage: tls_index_return <mid-return|mid-retained|mid-exhausted|emit-return|emit-live-owner|delivery-return|"
        "delivery-live-owner|guarded-read-return|guarded-read-in-flight|diagnostics-session|"
        "diagnostics-cache-shutdown|diagnostics-cache-restart|diagnostics-live|diagnostics-running|diagnostics-parked|"
        "diagnostics-self|diagnostics-loader-lock|diagnostics-process-exit|diagnostics-untracked>\n",
        stderr
    );
    return 1;
}
