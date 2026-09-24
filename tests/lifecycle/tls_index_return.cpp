/**
 * @file tls_index_return.cpp
 * @brief Fresh-process proofs that each DMK Win32 TLS index returns with its last owner and stays with a live one.
 * @details The return scenarios reserve an index, read the process TLS bitmaps, and require the exact return after the
 *          last owner retires. The live-owner scenarios keep one owner live across another owner's release and require
 *          the index to stay reserved and usable. Exit status is the oracle.
 */

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"

#include "internal/input_binding_gate.hpp"
#include "internal/input_delivery_scope.hpp"
#include "internal/memory_fault.hpp"
#include "internal/memory_guarded.hpp"

#include "tls_census.hpp"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string_view>
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

#if defined(_MSC_VER)
#define DMK_PROOF_NOINLINE __declspec(noinline)
#else
#define DMK_PROOF_NOINLINE __attribute__((noinline))
#endif

    volatile int s_sink = 0;

    // docs/design/testing.md owns the private-section rule. Distinct seeds prevent code folding, and volatile work
    // preserves enough prologue bytes for the patch.
#if defined(_MSC_VER)
#pragma code_seg(push, ".proof")
#define DMK_PROOF_TARGET DMK_PROOF_NOINLINE
#else
#define DMK_PROOF_TARGET __attribute__((section(".proof"))) DMK_PROOF_NOINLINE
#endif
#define DMK_TLS_TARGET(NAME, SEED)                                                                                     \
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
    DMK_TLS_TARGET(tls_target_3, 3)
    DMK_TLS_TARGET(tls_target_5, 5)
    DMK_TLS_TARGET(tls_target_7, 7)
#undef DMK_TLS_TARGET
#undef DMK_PROOF_TARGET
#if defined(_MSC_VER)
#pragma code_seg(pop)
#endif

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

            // The diagnostics dispatchers are never destroyed, so a subscription registers an owner that never returns
            // its index.
            Subscription lifecycle_subscription =
                diagnostics::hook_lifecycle().subscribe([](const diagnostics::HookLifecycleEvent &) noexcept {});
            if (!lifecycle_subscription.active())
                return fail(45, "the diagnostics subscription was refused");
        }
        if (dmk_lifecycle::free_tls_indices() + 1 != baseline)
            return fail(46, "the never-destroyed diagnostics dispatcher did not keep its index");
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
        ParkedRegion region{.page = page.address()};
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
} // namespace

int main(int argc, char **argv)
{
    const std::string_view scenario = argc == 2 ? std::string_view{argv[1]} : std::string_view{};
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
    // Exit status is the only oracle, so an unimplemented token must fail rather than fall through to a scenario.
    std::fputs(
        "usage: tls_index_return <mid-return|mid-retained|mid-exhausted|emit-return|emit-live-owner|delivery-return|"
        "delivery-live-owner|guarded-read-return|guarded-read-in-flight>\n",
        stderr
    );
    return 1;
}
