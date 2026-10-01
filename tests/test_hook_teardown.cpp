#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"

#include "internal/hook_ledger.hpp"

#include "fixtures/proof_section.hpp"
#include "fixtures/hook_fixture.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace dmk_test::hook_fixture;

// release(): detach but stay installed for the process lifetime

TEST(HookRelease, ReleaseLeavesHookInstalledAndFiring)
{
    // This target stays patched for the process lifetime. No other case can share it.
    const Address target = addr_of(&leak_target_inline);
    EXPECT_EQ(call_unfolded(&leak_target_inline, 7), 7); // sanity: clean before the hook
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "Released",
            .target = target,
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()) << "enable failed";

    h.release();
    EXPECT_FALSE(static_cast<bool>(h));                    // handle disengaged
    EXPECT_TRUE(is_target_hooked(target));                 // The retained hook stays installed.
    EXPECT_EQ(call_unfolded(&leak_target_inline, 7), 107); // the detour still fires
    // No restore: leak_target_inline stays hooked for the process lifetime. Intentional leak.
}

// RAII teardown + moved-from inertness

TEST(HookTeardown, DestructorRestoresPrologue)
{
    EXPECT_EQ(call_unfolded(&echo, 7), 7); // sanity: unhooked
    {
        Result<Hook> r = inline_at(
            InlineRequest{
                .name = "TeardownRestore",
                .target = addr_of(&echo),
            },
            &echo_detour
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook h = std::move(*r);
        ASSERT_TRUE(h.enable().has_value()) << "enable failed";
        EXPECT_EQ(call_unfolded(&echo, 7), 107); // hooked
    }
    EXPECT_EQ(call_unfolded(&echo, 7), 7); // prologue restored on scope exit
}

TEST(HookTeardown, MovedFromHandleIsInert)
{
    EXPECT_EQ(call_unfolded(&echo, 7), 7);
    {
        Result<Hook> r = inline_at(
            InlineRequest{
                .name = "MovedFrom",
                .target = addr_of(&echo),
            },
            &echo_detour
        );
        ASSERT_TRUE(r.has_value()) << r.error().message();
        Hook a = std::move(*r);
        ASSERT_TRUE(a.enable().has_value()) << "enable failed";
        Hook b = std::move(a);
        // The moved-from handle must remain inert.
        EXPECT_FALSE(static_cast<bool>(a));
        EXPECT_TRUE(static_cast<bool>(b));
        EXPECT_EQ(a.call<int>(7), int{});
        EXPECT_EQ(call_unfolded(&echo, 7), 107);
    } // Only b owns teardown.
    EXPECT_EQ(call_unfolded(&echo, 7), 7);
}

namespace
{
    // Separate HookStack targets isolate order observations from shared hook fixtures. Newest-first teardown leaves
    // those entries clean.
    DMK_PROOF_TARGET int stack_target_primary(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    DMK_PROOF_TARGET int stack_target_secondary(int a, int b)
    {
        volatile int r = a + b;
        return r;
    }

    // The order tests never call this detour. It only needs the valid int(int, int) ABI.
    DMK_TEST_NOINLINE int stack_detour(int a, int b)
    {
        return a + b + 1;
    }

    // Dedicated single-arg target and two distinct detours for the layered-while-disabled characterization below.
    DMK_PROOF_TARGET int layered_disabled_target(int x)
    {
        volatile int r = x;
        return r;
    }

    int layered_disabled_detour_a(int x)
    {
        return x + 100;
    }

    int layered_disabled_detour_b(int x)
    {
        return x + 200;
    }

    // Dedicated target for the concurrent is_enabled query proof.
    DMK_PROOF_TARGET int gate_query_target(int x)
    {
        volatile int r = x;
        return r;
    }

    int gate_query_detour(int x)
    {
        return x + 300;
    }

    // Distinct +1000 and +2000 detours prevent MSVC /OPT:ICF folding. The dedicated target isolates these state proofs.
    DMK_PROOF_TARGET int layer_state_target(int x)
    {
        volatile int r = x;
        return r;
    }

    int layer_state_detour_base(int x)
    {
        return x + 1000;
    }

    int layer_state_detour_top(int x)
    {
        return x + 2000;
    }

    /// Copies the first bytes of a function's entry, the span an inline patch overwrites.
    template <class Fn> [[nodiscard]] std::array<std::uint8_t, 16> entry_bytes(Fn *fn) noexcept
    {
        std::array<std::uint8_t, 16> bytes{};
        std::memcpy(bytes.data(), reinterpret_cast<const void *>(fn), bytes.size());
        return bytes;
    }
} // namespace

// Two disabled installs capture the pristine prologue and cannot chain. StacksOnAnArmedLowerLayer covers a second
// install after the first patch becomes live.
TEST(HookLayeredDisabled, OnlyTheNewestLayerArmsInEitherEnableOrder)
{
    for (const bool enable_base_first : {true, false})
    {
        ASSERT_FALSE(is_target_hooked(addr_of(&layered_disabled_target)));
        EXPECT_EQ(call_unfolded(&layered_disabled_target, 5), 5); // pristine before install

        {
            Result<Hook> base = inline_at(
                InlineRequest{
                    .name = "LayeredBase",
                    .target = addr_of(&layered_disabled_target),
                },
                &layered_disabled_detour_a
            );
            ASSERT_TRUE(base.has_value()) << base.error().message();
            Result<Hook> top = inline_at(
                InlineRequest{
                    .name = "LayeredTop",
                    .target = addr_of(&layered_disabled_target),
                },
                &layered_disabled_detour_b
            );
            ASSERT_TRUE(top.has_value()) << top.error().message();

            Hook h_base = std::move(*base);
            Hook h_top = std::move(*top); // declared last, so destroyed first: newest-first teardown

            if (enable_base_first)
            {
                const Result<void> refused = h_base.enable();
                ASSERT_FALSE(refused.has_value());
                EXPECT_EQ(refused.error().code, ErrorCode::LayerConflict);
                ASSERT_TRUE(h_top.enable().has_value());
            }
            else
            {
                ASSERT_TRUE(h_top.enable().has_value());
                const Result<void> refused = h_base.enable();
                ASSERT_FALSE(refused.has_value());
                EXPECT_EQ(refused.error().code, ErrorCode::LayerConflict);
            }

            // The refused base layer stays disabled. The top detour stays reachable in both orders.
            EXPECT_FALSE(h_base.is_enabled());
            EXPECT_TRUE(h_top.is_enabled());
            EXPECT_EQ(call_unfolded(&layered_disabled_target, 5), 205);
        }

        // Both handles dropped newest-first: the target is restored to its original body.
        EXPECT_FALSE(is_target_hooked(addr_of(&layered_disabled_target)));
        EXPECT_EQ(call_unfolded(&layered_disabled_target, 5), 5);
    }
}

// Concurrent queries need coherent states without a gate deadlock. Each missing state stays open until a reader
// observes it, so the counters detect a vacuous run.
TEST(HookGateQueryProof, ConcurrentIsEnabledIsSerializedAgainstToggling)
{
    Result<Hook> created = inline_at(
        InlineRequest{
            .name = "GateQuery",
            .target = addr_of(&gate_query_target),
        },
        &gate_query_detour
    );
    ASSERT_TRUE(created.has_value()) << created.error().message();
    Hook hook = std::move(*created);
    ASSERT_TRUE(hook.enable().has_value());

    constexpr int k_iterations = 2000;
    constexpr int k_readers = 3;
    std::atomic<bool> stop{false};
    std::atomic<int> readers_ready{0};
    std::atomic<int> saw_enabled{0};
    std::atomic<int> saw_disabled{0};
    std::atomic<int> unexpected_result{5};

    std::vector<std::thread> readers;
    for (int i = 0; i < k_readers; ++i)
    {
        readers.emplace_back(
            [&hook, &stop, &readers_ready, &saw_enabled, &saw_disabled, &unexpected_result]() -> void
            {
                readers_ready.fetch_add(1, std::memory_order_release);
                while (!stop.load(std::memory_order_relaxed))
                {
                    if (hook.is_enabled())
                    {
                        saw_enabled.fetch_add(1, std::memory_order_relaxed);
                    }
                    else
                    {
                        saw_disabled.fetch_add(1, std::memory_order_relaxed);
                    }
                    // Concurrent target calls must observe a coherent state during each toggle.
                    const int observed = call_unfolded(&gate_query_target, 5);
                    if (observed != 5 && observed != 305)
                    {
                        unexpected_result.store(observed, std::memory_order_relaxed);
                    }
                }
            }
        );
    }

    // Every reader enters its loop before the storm starts. This prevents an empty observation window.
    while (readers_ready.load(std::memory_order_acquire) < k_readers)
    {
        std::this_thread::yield();
    }

    bool toggle_operations_ok = true;
    for (int i = 0; i < k_iterations; ++i)
    {
        if (!hook.disable().has_value() || !hook.enable().has_value())
        {
            toggle_operations_ok = false;
            break;
        }
    }

    const auto wait_for_observation = [](const std::atomic<int> &count)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        while (count.load(std::memory_order_relaxed) == 0 && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::yield();
        }
        return count.load(std::memory_order_relaxed) != 0;
    };

    // The storm can miss a narrow disabled window. Each missing state stays open until a reader observes it.
    bool convergence_operations_ok = true;
    bool observed_disabled = saw_disabled.load(std::memory_order_relaxed) != 0;
    if (!observed_disabled)
    {
        const Result<void> disabled = hook.disable();
        convergence_operations_ok = disabled.has_value();
        if (disabled.has_value())
        {
            observed_disabled = wait_for_observation(saw_disabled);
            const Result<void> enabled = hook.enable();
            convergence_operations_ok = enabled.has_value();
        }
    }

    const bool observed_enabled = wait_for_observation(saw_enabled);

    stop.store(true, std::memory_order_relaxed);
    for (std::thread &reader : readers)
    {
        reader.join();
    }

    // Each state reached a reader. The check distinguishes coherent observations from torn state.
    EXPECT_TRUE(toggle_operations_ok);
    EXPECT_EQ(unexpected_result.load(std::memory_order_relaxed), 5);
    EXPECT_TRUE(convergence_operations_ok);
    EXPECT_TRUE(observed_enabled);
    EXPECT_TRUE(observed_disabled);

    // The toggler's last act was an enable and every reader has left the gate: the query is truthful again.
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(call_unfolded(&gate_query_target, 5), 305);
}

// The newer trampoline resumes through the lower patch. A lower-layer restore invalidates that continuation.
TEST(HookLayerStateProof, LowerLayerCannotOverwriteNewerLayer)
{
    ASSERT_FALSE(is_target_hooked(addr_of(&layer_state_target)));
    ASSERT_EQ(call_unfolded(&layer_state_target, 5), 5);

    {
        Result<Hook> base = inline_at(
            InlineRequest{
                .name = "LayerStateBase",
                .target = addr_of(&layer_state_target),
            },
            &layer_state_detour_base
        );
        ASSERT_TRUE(base.has_value()) << base.error().message();
        Hook h_base = std::move(*base);
        ASSERT_TRUE(h_base.enable().has_value());
        ASSERT_EQ(call_unfolded(&layer_state_target, 5), 1005);

        {
            // Created while the base is armed, so this layer captures the patched prologue rather than the pristine
            // one.
            Result<Hook> top = inline_at(
                InlineRequest{
                    .name = "LayerStateTop",
                    .target = addr_of(&layer_state_target),
                },
                &layer_state_detour_top
            );
            ASSERT_TRUE(top.has_value()) << top.error().message();
            Hook h_top = std::move(*top);
            ASSERT_TRUE(h_top.enable().has_value());
            ASSERT_EQ(call_unfolded(&layer_state_target, 5), 2005);

            // The older layer is no longer on top: both toggles are refused without touching the target.
            const Result<void> refused_disable = h_base.disable();
            ASSERT_FALSE(refused_disable.has_value());
            EXPECT_EQ(refused_disable.error().code, ErrorCode::LayerConflict);
            const Result<void> refused_enable = h_base.enable();
            ASSERT_FALSE(refused_enable.has_value());
            EXPECT_EQ(refused_enable.error().code, ErrorCode::LayerConflict);

            EXPECT_EQ(call_unfolded(&layer_state_target, 5), 2005);
            EXPECT_TRUE(h_top.is_enabled());
            EXPECT_TRUE(h_base.is_enabled()) << "a refused disable must not publish a false Disabled";
        }

        // After the newer layer ends, the base can toggle again.
        EXPECT_EQ(call_unfolded(&layer_state_target, 5), 1005);
        ASSERT_TRUE(h_base.disable().has_value());
        EXPECT_FALSE(h_base.is_enabled());
        EXPECT_EQ(call_unfolded(&layer_state_target, 5), 5);
    }

    EXPECT_FALSE(is_target_hooked(addr_of(&layer_state_target)));
    EXPECT_EQ(call_unfolded(&layer_state_target, 5), 5);
}

// Call results cannot detect a write followed by a restore. Direct byte comparison covers both refused toggles.
TEST(HookLayerStateProof, NonTopLayerToggleCannotChangeTargetBytes)
{
    ASSERT_FALSE(is_target_hooked(addr_of(&layer_state_target)));

    Result<Hook> base = inline_at(
        InlineRequest{
            .name = "LayerBytesBase",
            .target = addr_of(&layer_state_target),
        },
        &layer_state_detour_base
    );
    ASSERT_TRUE(base.has_value()) << base.error().message();
    Hook h_base = std::move(*base);
    ASSERT_TRUE(h_base.enable().has_value());

    Result<Hook> top = inline_at(
        InlineRequest{
            .name = "LayerBytesTop",
            .target = addr_of(&layer_state_target),
        },
        &layer_state_detour_top
    );
    ASSERT_TRUE(top.has_value()) << top.error().message();
    Hook h_top = std::move(*top);
    ASSERT_TRUE(h_top.enable().has_value());

    const std::array<std::uint8_t, 16> armed = entry_bytes(&layer_state_target);

    const Result<void> refused_disable = h_base.disable();
    ASSERT_FALSE(refused_disable.has_value()) << "the non-top layer was allowed to disable";
    EXPECT_EQ(refused_disable.error().code, ErrorCode::LayerConflict);
    EXPECT_EQ(entry_bytes(&layer_state_target), armed) << "a refused disable altered the target's bytes";

    const Result<void> refused_enable = h_base.enable();
    ASSERT_FALSE(refused_enable.has_value()) << "the non-top layer was allowed to enable";
    EXPECT_EQ(refused_enable.error().code, ErrorCode::LayerConflict);
    EXPECT_EQ(entry_bytes(&layer_state_target), armed) << "a refused enable altered the target's bytes";
    EXPECT_EQ(call_unfolded(&layer_state_target, 5), 2005);
}

// Removed events expose teardown order without a native fault. A forward loop produces {StackBase, StackLayer}.
TEST(HookStackTest, TearsDownLayeredHooksNewestFirst)
{
    std::vector<std::string> removed;
    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&removed](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.transition == diagnostics::HookTransition::Removed)
            {
                removed.emplace_back(e.name);
            }
        }
    );

    {
        HookStack stack;
        Result<Hook> base = inline_at(
            InlineRequest{
                .name = "StackBase",
                .target = addr_of(&stack_target_primary),
            },
            &stack_detour
        );
        ASSERT_TRUE(base.has_value()) << base.error().message();
        stack.push(std::move(*base));

        Result<Hook> layer = inline_at(
            InlineRequest{
                .name = "StackLayer",
                .target = addr_of(&stack_target_primary),
            },
            &stack_detour
        );
        ASSERT_TRUE(layer.has_value()) << layer.error().message();
        stack.push(std::move(*layer));

        EXPECT_EQ(stack.size(), 2u);
        EXPECT_TRUE(is_target_hooked(addr_of(&stack_target_primary)));
        // Scope exit destroys the HookStack, which tears the two hooks down newest-first.
    }

    ASSERT_EQ(removed.size(), 2u);
    EXPECT_EQ(removed[0], "StackLayer"); // pushed second, restored first
    EXPECT_EQ(removed[1], "StackBase");  // pushed first, restored last
    // Both released and the prologue cleanly restored, which only holds because teardown ran in the safe order.
    EXPECT_FALSE(is_target_hooked(addr_of(&stack_target_primary)));
    EXPECT_EQ(stack_target_primary(5, 3), 8);
}

TEST(HookStackTest, MoveConstructTransfersOwnershipAndLeavesSourceEmpty)
{
    HookStack source;
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "MoveCtorHook",
            .target = addr_of(&stack_target_secondary),
        },
        &stack_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    ASSERT_TRUE(source.push(std::move(*r)).enable().has_value());

    HookStack moved(std::move(source));

    EXPECT_TRUE(source.empty());
    EXPECT_EQ(source.size(), 0u);
    EXPECT_EQ(moved.size(), 1u);
    EXPECT_FALSE(moved.empty());
    EXPECT_TRUE(is_target_hooked(addr_of(&stack_target_secondary)));
    EXPECT_EQ(stack_target_secondary(2, 6), 9);
}

// Defaulted move assignment destroys replaced hooks in container order. The removed sequence detects a failure to drain
// newest-first.
TEST(HookStackTest, MoveAssignDrainsOverwrittenHooksNewestFirst)
{
    std::vector<std::string> removed;
    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&removed](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.transition == diagnostics::HookTransition::Removed)
            {
                removed.emplace_back(e.name);
            }
        }
    );

    HookStack dest;
    {
        Result<Hook> base = inline_at(
            InlineRequest{
                .name = "MoveBase",
                .target = addr_of(&stack_target_secondary),
            },
            &stack_detour
        );
        ASSERT_TRUE(base.has_value()) << base.error().message();
        ASSERT_TRUE(dest.push(std::move(*base)).enable().has_value());

        Result<Hook> layer = inline_at(
            InlineRequest{
                .name = "MoveLayer",
                .target = addr_of(&stack_target_secondary),
            },
            &stack_detour
        );
        ASSERT_TRUE(layer.has_value()) << layer.error().message();
        ASSERT_TRUE(dest.push(std::move(*layer)).enable().has_value());
    }
    ASSERT_EQ(dest.size(), 2u);
    ASSERT_TRUE(removed.empty()); // nothing torn down yet (setup only emits Created)

    HookStack replacement;
    Result<Hook> adopted = inline_at(
        InlineRequest{
            .name = "MoveAdopted",
            .target = addr_of(&stack_target_primary),
        },
        &stack_detour
    );
    ASSERT_TRUE(adopted.has_value()) << adopted.error().message();
    ASSERT_TRUE(replacement.push(std::move(*adopted)).enable().has_value());

    // Overwrite the live stack: dest's two layered hooks must be released newest-first here.
    dest = std::move(replacement);

    ASSERT_EQ(removed.size(), 2u);
    EXPECT_EQ(removed[0], "MoveLayer");
    EXPECT_EQ(removed[1], "MoveBase");
    EXPECT_TRUE(replacement.empty());
    EXPECT_EQ(replacement.size(), 0u);
    EXPECT_EQ(dest.size(), 1u);
    EXPECT_FALSE(is_target_hooked(addr_of(&stack_target_secondary)));
    EXPECT_EQ(stack_target_secondary(9, 4), 13);
    EXPECT_TRUE(is_target_hooked(addr_of(&stack_target_primary)));
    EXPECT_EQ(stack_target_primary(9, 4), 14);

    dest.clear();
    ASSERT_EQ(removed.size(), 3u);
    EXPECT_EQ(removed[2], "MoveAdopted");
}

// clear() releases every owned hook newest-first and leaves the stack empty and reusable.
TEST(HookStackTest, ClearTearsDownNewestFirstAndEmpties)
{
    std::vector<std::string> removed;
    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&removed](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.transition == diagnostics::HookTransition::Removed)
            {
                removed.emplace_back(e.name);
            }
        }
    );

    HookStack stack;
    Result<Hook> base = inline_at(
        InlineRequest{
            .name = "ClearBase",
            .target = addr_of(&stack_target_primary),
        },
        &stack_detour
    );
    ASSERT_TRUE(base.has_value()) << base.error().message();
    stack.push(std::move(*base));

    Result<Hook> layer = inline_at(
        InlineRequest{
            .name = "ClearLayer",
            .target = addr_of(&stack_target_primary),
        },
        &stack_detour
    );
    ASSERT_TRUE(layer.has_value()) << layer.error().message();
    stack.push(std::move(*layer));

    stack.clear();

    EXPECT_TRUE(stack.empty());
    EXPECT_EQ(stack.size(), 0u);
    ASSERT_EQ(removed.size(), 2u);
    EXPECT_EQ(removed[0], "ClearLayer");
    EXPECT_EQ(removed[1], "ClearBase");
    EXPECT_FALSE(is_target_hooked(addr_of(&stack_target_primary)));
}

// The reference push() returns reaches the live hook, so a caller can capture the trampoline right after pushing.
TEST(HookStackTest, PushReturnsUsableHandleAndReportsSize)
{
    HookStack stack;
    EXPECT_TRUE(stack.empty());
    EXPECT_EQ(stack.size(), 0u);

    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "StackEcho",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook &stored = stack.push(std::move(*r));
    ASSERT_TRUE(stored.enable().has_value());

    EXPECT_EQ(stack.size(), 1u);
    EXPECT_FALSE(stack.empty());
    EXPECT_TRUE(static_cast<bool>(stored));
    EXPECT_EQ(stored.name(), "StackEcho");

    // The returned reference reaches the live trampoline (the capture-now pattern) and the detour is armed.
    auto *orig = stored.original<EchoFn>();
    ASSERT_NE(orig, nullptr);
    EXPECT_EQ(orig(7), 7);                   // trampoline yields the original body
    EXPECT_EQ(call_unfolded(&echo, 7), 107); // detour active while the stack owns the hook
    // Scope exit restores echo cleanly (single hook, so order is moot but the stack still owns the teardown).
}

// Concurrency + reentrancy: the per-hook status machine and the call() guard under thread stress and self-reentry. The
// per-hook recursive_mutex is held across call(), and disable()/~Hook must drain that mutex before the trampoline can
// be restored or freed. These tests pin the caller-visible guarantees directly, including a parked original that keeps
// the guard held until the test releases it.
namespace
{
    // The recursive original enters its patched prologue again while call() holds the same thread's gate.
    std::atomic<int> s_reentrant_detour_calls{0};
    Hook *s_reentrant_hook = nullptr;

    DMK_PROOF_TARGET int reentrant_target(int n)
    {
        if (n <= 0)
        {
            return 0;
        }
        // The volatile indirection forces recursive entry through the patch. Direct self-recursion can become a loop
        // under optimization.
        return call_unfolded(&reentrant_target, n - 1) + 1;
    }

    int reentrant_detour(int n)
    {
        s_reentrant_detour_calls.fetch_add(1, std::memory_order_relaxed);
        // Forward to the original through the guarded call(): it re-acquires the per-hook recursive_mutex. The original
        // recurses back into this detour on the same thread, so the guard MUST be recursive or this self-deadlocks.
        return s_reentrant_hook->call<int>(n);
    }

    // The original parks inside call() while its guard stays held. A second thread can then test the disable drain.
    std::atomic<bool> s_original_parked{false};
    std::atomic<bool> s_release_original{false};

    DMK_PROOF_TARGET int parking_original(int x)
    {
        s_original_parked.store(true, std::memory_order_release);
        while (!s_release_original.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        volatile int r = x;
        return r;
    }
} // namespace

TEST(HookConcurrency, ConcurrentEnableDisableIsRaceSafe)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "ConcEnableDisable",
            .target = addr_of(&echo),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);

    // Several threads hammer enable()/disable() while a reader queries the backend-backed status. The per-hook guard
    // must serialize the backend's non-atomic enabled flag and fold the storm into legal transitions.
    constexpr int THREADS = 6;
    constexpr int ITERATIONS = 500;
    constexpr int STATUS_READS = THREADS * ITERATIONS;
    std::atomic<bool> go{false};
    std::atomic<int> status_reads{0};
    std::vector<std::thread> pool;
    pool.reserve(THREADS + 1);
    for (int t = 0; t < THREADS; ++t)
    {
        pool.emplace_back(
            [&h, &go, t]()
            {
                while (!go.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                for (int i = 0; i < ITERATIONS; ++i)
                {
                    if (((t + i) & 1) == 0)
                    {
                        (void)h.enable();
                    }
                    else
                    {
                        (void)h.disable();
                    }
                }
            }
        );
    }
    pool.emplace_back(
        [&h, &go, &status_reads]
        {
            while (!go.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            for (int i = 0; i < STATUS_READS; ++i)
            {
                (void)h.is_enabled();
                status_reads.fetch_add(1, std::memory_order_relaxed);
            }
        }
    );
    go.store(true, std::memory_order_release);
    for (std::thread &worker : pool)
    {
        worker.join();
    }
    EXPECT_EQ(status_reads.load(std::memory_order_relaxed), STATUS_READS);

    // The hook survived the storm: brought to a known state, both dispatch paths still work end to end.
    ASSERT_TRUE(h.enable().has_value());
    EXPECT_EQ(call_unfolded(&echo, 7), 107); // enabled: the detour adds 100
    EXPECT_EQ(h.call<int>(7), 7);            // original body through the trampoline
    ASSERT_TRUE(h.disable().has_value());
    EXPECT_EQ(call_unfolded(&echo, 7), 7); // disabled: original prologue restored
}

TEST(HookConcurrency, ReentrantCallFromDetourRequiresRecursiveGuard)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "Reentrant",
            .target = addr_of(&reentrant_target),
        },
        &reentrant_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value());
    s_reentrant_hook = &h;
    s_reentrant_detour_calls.store(0, std::memory_order_relaxed);

    // The original recurses through the patched entry. A plain mutex self-deadlocks where the recursive call gate must
    // permit reentry.
    const int result = call_unfolded(&reentrant_target, 4);
    EXPECT_EQ(result, 4);                                                   // recursion adds 1 four times down to 0
    EXPECT_EQ(s_reentrant_detour_calls.load(std::memory_order_relaxed), 5); // detour fired at depths 4,3,2,1,0

    s_reentrant_hook = nullptr;
}

TEST(HookConcurrency, DisableDrainsAnInFlightCall)
{
    Result<Hook> r = inline_at(
        InlineRequest{
            .name = "DrainCall",
            .target = addr_of(&parking_original),
        },
        &echo_detour
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    Hook h = std::move(*r);
    ASSERT_TRUE(h.enable().has_value()); // publish the trampoline so call() dispatches to the parking original
    s_original_parked.store(false, std::memory_order_release);
    s_release_original.store(false, std::memory_order_release);

    // Thread A parks inside the original while call() retains its guard.
    std::thread caller([&h]() { (void)h.call<int>(7); });
    const auto park_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!s_original_parked.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < park_deadline)
    {
        std::this_thread::yield();
    }
    if (!s_original_parked.load(std::memory_order_acquire))
    {
        s_release_original.store(true, std::memory_order_release);
        caller.join();
        FAIL() << "the original call did not reach its park before the deadline";
    }

    // Thread B attempts disable() while the call is parked. disable() acquires the SAME guard, so it MUST block until
    // the call releases it. It must never free the trampoline out from under the in-flight original.
    std::atomic<bool> disable_started{false};
    std::atomic<bool> disable_returned{false};
    std::thread disabler(
        [&h, &disable_started, &disable_returned]()
        {
            disable_started.store(true, std::memory_order_release);
            (void)h.disable();
            disable_returned.store(true, std::memory_order_release);
        }
    );
    const auto disable_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!disable_started.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < disable_deadline)
    {
        std::this_thread::yield();
    }
    const bool disable_began = disable_started.load(std::memory_order_acquire);

    // The parked original retains the guard. An early disable result detects trampoline disposal before the drain.
    bool disable_returned_early = false;
    for (int spin = 0; spin < 1000; ++spin)
    {
        if (disable_returned.load(std::memory_order_acquire))
        {
            disable_returned_early = true;
            break;
        }
        std::this_thread::yield();
    }

    // Release the original call before the guard can drop and disable() can drain.
    s_release_original.store(true, std::memory_order_release);
    disabler.join();
    caller.join();
    ASSERT_TRUE(disable_began) << "disable() did not start before the deadline";
    EXPECT_FALSE(
        disable_returned_early
    ) << "disable() completed while a guarded call() was still in flight (drain violated)";
    EXPECT_TRUE(disable_returned.load(std::memory_order_acquire));
    EXPECT_FALSE(h.is_enabled());
}

// call() can race ~Hook on retained storage (hook.hpp), so the destructor must run no member destructor over the gate
// word. The MSVC ~atomic<shared_ptr> reads that word unmasked and decrements through a set lock bit, and libstdc++
// releases through it. The worker hammers call() through the retained std::optional while the main thread installs
// and destroys the hook in place. A fault ends the process, which is the verdict.
TEST(HookConcurrency, CallRacesDestructorOnRetainedStorage)
{
    constexpr int ITERATIONS = 400;
    std::optional<Hook> slot;
    std::atomic<Hook *> published{nullptr};
    std::atomic<int> in_flight{0};
    std::atomic<long long> calls{0};

    std::jthread worker(
        [&](const std::stop_token &token)
        {
            while (!token.stop_requested())
            {
                Hook *const hook = published.load(std::memory_order_acquire);
                if (hook == nullptr)
                {
                    std::this_thread::yield();
                    continue;
                }
                in_flight.fetch_add(1, std::memory_order_acq_rel);
                // Re-check after registration: the main thread unpublishes, then waits for in_flight to reach zero
                // before it constructs the next hook in the same storage.
                if (published.load(std::memory_order_acquire) == hook)
                {
                    (void)hook->call<int>(7);
                    calls.fetch_add(1, std::memory_order_relaxed);
                }
                in_flight.fetch_sub(1, std::memory_order_acq_rel);
            }
        }
    );

    for (int i = 0; i < ITERATIONS; ++i)
    {
        Result<Hook> installed = inline_at(
            InlineRequest{
                .name = "RetainedStorageRace",
                .target = addr_of(&echo),
            },
            &echo_detour
        );
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        slot.emplace(std::move(*installed));
        published.store(&*slot, std::memory_order_release);
        for (int spin = 0; spin < 50; ++spin)
        {
            std::this_thread::yield();
        }
        // Destroy while published: the racing call() reads the never-destroyed null slot and fails closed.
        slot.reset();
        published.store(nullptr, std::memory_order_release);
        while (in_flight.load(std::memory_order_acquire) != 0)
        {
            std::this_thread::yield();
        }
    }
    worker.request_stop();
    worker.join();
    EXPECT_GT(calls.load(std::memory_order_relaxed), 0);
    EXPECT_FALSE(is_target_hooked(addr_of(&echo)));
}

// The synthetic ledger target needs no real patch. Its serialization slot must prevent a concurrent install from
// reaching Reserved during teardown.
TEST(HookLedgerTargetSlot, BlocksConcurrentInstallUntilSlotReleased)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();
    const std::uintptr_t target = 0xB0BA5000;

    const auto reserved = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(reserved.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ASSERT_TRUE(ledger.commit_hook(target, reserved.id));

    // The sole newest hook owns the teardown slot.
    EXPECT_EQ(ledger.acquire_target_slot(target, reserved.id), 0u);

    std::atomic<bool> install_started{false};
    std::atomic<bool> install_returned{false};
    std::atomic<bool> allow_install_cleanup{false};
    std::uint64_t install_id = 0;

    auto wait_for_flag = [](const std::atomic<bool> &flag, int attempts) -> bool
    {
        for (int i = 0; i < attempts; ++i)
        {
            if (flag.load(std::memory_order_acquire))
            {
                return true;
            }
            Sleep(1);
        }
        return flag.load(std::memory_order_acquire);
    };

    std::thread installer(
        [&]
        {
            install_started.store(true, std::memory_order_release);
            // Must block until the teardown slot is released: the teardown holds front-of-pending.
            const auto second = ledger.try_reserve_hook(target, false);
            EXPECT_EQ(second.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
            install_id = second.id;
            install_returned.store(true, std::memory_order_release);
            while (!allow_install_cleanup.load(std::memory_order_acquire))
            {
                Sleep(1);
            }
            EXPECT_TRUE(ledger.commit_hook(target, second.id));
            (void)ledger.release_hook(target, second.id);
        }
    );

    if (!wait_for_flag(install_started, 100))
    {
        // Release everything so the still-joinable thread cannot wedge the join, then fail.
        (void)ledger.release_hook(target, reserved.id);
        allow_install_cleanup.store(true, std::memory_order_release);
        installer.join();
        FAIL() << "installer thread did not start within the timeout";
    }
    // The install must NOT complete while the teardown slot is held.
    EXPECT_FALSE(wait_for_flag(install_returned, 20));

    // release_hook removes the sentinel and creation entry, then wakes the installer. The pending installer already
    // owns an ID, so the returned newer count need not be zero.
    (void)ledger.release_hook(target, reserved.id);

    const bool install_completed = wait_for_flag(install_returned, 1000);
    EXPECT_TRUE(install_completed) << "install must proceed once the teardown releases the slot";
    EXPECT_NE(install_id, 0u);

    allow_install_cleanup.store(true, std::memory_order_release);
    installer.join();
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// release_target_slot removes serialization but preserves the creation entry. Queries and strict installs must still
// see the retained backend.
TEST(HookLedgerTargetSlot, ReleaseSlotOnlyKeepsOrderEntry)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();
    const std::uintptr_t target = 0xB0BA6000;

    const auto older = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(older.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ASSERT_TRUE(ledger.commit_hook(target, older.id));
    const auto newer = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(newer.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ASSERT_TRUE(ledger.commit_hook(target, newer.id));

    // Tearing down the OLDER hook sees one newer layer, so the caller must leak and release via the slot-only path.
    EXPECT_EQ(ledger.acquire_target_slot(target, older.id), 1u);
    ledger.release_target_slot(target, older.id);

    // The order entry survives: the target is still hooked, and a fail-if-already-hooked reserve is refused.
    EXPECT_TRUE(ledger.is_target_hooked(target));
    const auto refused = ledger.try_reserve_hook(target, true);
    EXPECT_EQ(refused.status, DetourModKit::detail::HookLedger::ReserveStatus::AlreadyHooked);

    // The freed sentinel does not block a permissive layering install.
    const auto layered = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(layered.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ASSERT_TRUE(ledger.commit_hook(target, layered.id));

    // Drain the ledger so the synthetic target does not leak into later assertions.
    (void)ledger.release_hook(target, older.id);
    (void)ledger.release_hook(target, newer.id);
    (void)ledger.release_hook(target, layered.id);
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// The retained ID must outrank older layers for the process lifetime. Direct ledger assertions isolate that guard
// because the destructor witness independently refuses restoration.
TEST(HookLedgerTargetSlot, RetainedIdStillOutranksAnOlderTeardown)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();
    // Every synthetic ledger key in the unit binary is unique to its case. The sibling key 0xB0BA8000 belongs to
    // HookLedgerFaultProof.AbandonedSlotCannotParkALaterReserver. A shared key lets one case inherit another's pending
    // sentinel and park on the slot claim below rather than assert against it.
    constexpr std::uintptr_t target = 0xB0BA9000;

    const auto older = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(older.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ASSERT_TRUE(ledger.commit_hook(target, older.id));
    const auto newer = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(newer.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ASSERT_TRUE(ledger.commit_hook(target, newer.id));

    // Retire the newer layer the way a pinned teardown does: sentinel freed, creation-order entry kept.
    EXPECT_EQ(ledger.acquire_target_slot(target, newer.id), 0u);
    ledger.release_target_slot(target, newer.id);

    EXPECT_GT(ledger.acquire_target_slot(target, older.id), 0u)
        << "a retained id must keep outranking an older layer; dropping it would authorize a restore over a "
           "still-patched backend";
    ledger.release_target_slot(target, older.id);

    (void)ledger.release_hook(target, older.id);
    (void)ledger.release_hook(target, newer.id);
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// Missing bookkeeping cannot provide the serialization guarantee required for a safe restore. The teardown query
// must therefore fail closed to a positive count for both an unknown target and an unknown id on a tracked target.
TEST(HookLedgerTargetSlot, MissingEntryFailsClosedToLeakDecision)
{
    auto &ledger = DetourModKit::detail::HookLedger::instance();
    constexpr std::uintptr_t target = 0xB0BA7000;

    EXPECT_GT(ledger.acquire_target_slot(target, 12345u), 0u);

    const auto reserved = ledger.try_reserve_hook(target, false);
    ASSERT_EQ(reserved.status, DetourModKit::detail::HookLedger::ReserveStatus::Reserved);
    ASSERT_TRUE(ledger.commit_hook(target, reserved.id));

    EXPECT_GT(ledger.acquire_target_slot(target, reserved.id + 1), 0u);
    EXPECT_EQ(ledger.release_hook(target, reserved.id), 0u);
    EXPECT_FALSE(ledger.is_target_hooked(target));
}

// A bare vector produces oldest-first teardown. The newer trampoline still reaches the older patch, so the older
// backend needs retention.
TEST(HookInlineLayered, OldestFirstTeardownLeaksOlderBackend)
{
    // Measure a delta rather than resetting the process-wide counters, so this test does not perturb any other
    // leak-count assertion in the suite.
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    Result<Hook> older = inline_at(
        InlineRequest{
            .name = "LayerOld",
            .target = addr_of(&leak_target_layered),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(older.has_value()) << older.error().message();
    Result<Hook> newer = inline_at(
        InlineRequest{
            .name = "LayerNew",
            .target = addr_of(&leak_target_layered),
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(newer.has_value()) << newer.error().message();

    std::optional<Hook> old_handle(std::move(older.value()));
    std::optional<Hook> new_handle(std::move(newer.value()));

    // Destroy the OLDER layer while the newer one is still live: the inverted (oldest-first) order.
    old_handle.reset();

    // The HookManager leak bucket must increase by exactly one.
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1)
        << "oldest-first layered teardown must leak the older backend, not restore it";

    // Tearing the newer layer down now is the safe newest-first order and must not add another leak.
    new_handle.reset();
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1);

    Result<Hook> blocked = inline_at(
        InlineRequest{
            .name = "LayerAfterLeak",
            .target = addr_of(&leak_target_layered),
            .options = Options{.fail_if_already_hooked = true},
        },
        &real_hook_detour_add
    );
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(blocked.error().code, ErrorCode::TargetAlreadyHookedByThisKit)
        << "a leaked backend remains physically installed and must stay represented in the ledger";
}

// A pinned newer backend still resumes through the older prologue. Its retained creation ID protects that continuation
// from an older-layer restore.
TEST(HookLedgerRetainedId, LaterLayerOverAPinnedTargetStillRestores)
{
    const Address target = addr_of(&leak_target_retained_id);

    // release() is the explicit pin verb: the backend stays installed and its id stays in the ledger for good.
    Result<Hook> pinned = inline_at(
        InlineRequest{
            .name = "RetainPin",
            .target = target,
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(pinned.has_value()) << pinned.error().message();
    Hook pin_handle = std::move(*pinned);
    ASSERT_TRUE(pin_handle.enable().has_value());
    pin_handle.release();
    ASSERT_TRUE(is_target_hooked(target));

    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    {
        Result<Hook> later = inline_at(
            InlineRequest{
                .name = "RetainLater",
                .target = target,
            },
            &real_hook_detour_add
        );
        ASSERT_TRUE(later.has_value()) << later.error().message();
        Hook later_handle = std::move(*later);
        ASSERT_TRUE(later_handle.enable().has_value());
    }
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before)
        << "a layer installed after a pin is the newest, so its teardown must restore rather than leak";
    EXPECT_TRUE(is_target_hooked(target)) << "the pin itself is still installed and must stay represented";
}

// The destructor witness also refuses this restore if the ledger count is removed. This end-to-end case therefore does
// not isolate the ledger count.
TEST(HookLedgerRetainedId, OlderLayerUnderAPinnedNewerLayerMustLeak)
{
    const Address target = addr_of(&leak_target_retained_newer);

    Result<Hook> older = inline_at(
        InlineRequest{
            .name = "RetainOlder",
            .target = target,
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(older.has_value()) << older.error().message();
    Hook older_handle = std::move(*older);
    ASSERT_TRUE(older_handle.enable().has_value());

    Result<Hook> newer = inline_at(
        InlineRequest{
            .name = "RetainNewer",
            .target = target,
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(newer.has_value()) << newer.error().message();
    Hook newer_handle = std::move(*newer);
    ASSERT_TRUE(newer_handle.enable().has_value());
    newer_handle.release();

    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    {
        const Hook discard = std::move(older_handle);
    }
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1)
        << "the retained id of a pinned newer layer must still outrank an older teardown";
}

// This case proves the toggle half of the same retention contract, which teardown cannot reach. An older layer that
// stays LIVE under a pin must get LayerConflict when it asks to write the target's bytes. A silent no-op or a success
// that stamps its prologue over a still-installed trampoline fails this contract. In every other LayerConflict case of
// the unit binary, a ledger lock failure or a newer layer with a live handle causes the refusal. Here the id that
// outranks the caller belongs to no handle at all, and Hook::release() leaves only that shape behind. Both verbs run
// the layer check before the idempotency check, so an already-armed lower layer gets the refusal, not the no-op success
// on top.
TEST(HookLedgerRetainedId, LiveOlderLayerUnderAPinIsRefusedWithLayerConflict)
{
    const Address target = addr_of(&leak_target_retained_conflict);

    Result<Hook> older = inline_at(
        InlineRequest{
            .name = "ConflictOlder",
            .target = target,
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(older.has_value()) << older.error().message();
    Hook older_handle = std::move(*older);
    ASSERT_TRUE(older_handle.enable().has_value());

    Result<Hook> pin = inline_at(
        InlineRequest{
            .name = "ConflictPin",
            .target = target,
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(pin.has_value()) << pin.error().message();
    Hook pin_handle = std::move(*pin);
    ASSERT_TRUE(pin_handle.enable().has_value());
    pin_handle.release();

    const std::array<std::uint8_t, 16> pinned = entry_bytes(&leak_target_retained_conflict);

    const Result<void> refused_disable = older_handle.disable();
    ASSERT_FALSE(refused_disable.has_value()) << "a layer under a pin was allowed to disable";
    EXPECT_EQ(refused_disable.error().code, ErrorCode::LayerConflict);
    EXPECT_EQ(entry_bytes(&leak_target_retained_conflict), pinned) << "a refused disable altered the pinned prologue";

    const Result<void> refused_enable = older_handle.enable();
    ASSERT_FALSE(refused_enable.has_value()) << "a layer under a pin was allowed to enable";
    EXPECT_EQ(refused_enable.error().code, ErrorCode::LayerConflict);
    EXPECT_EQ(entry_bytes(&leak_target_retained_conflict), pinned) << "a refused enable altered the pinned prologue";

    // The pin is unreachable from any handle, so nothing can lift the refusal for the rest of the process.
    EXPECT_TRUE(is_target_hooked(target));
}

// release() leaves a creation-order entry without a handle. That record must still refuse a strict install over the
// live trampoline.
TEST(HookLedgerRetainedId, StrictInstallAfterAPinIsRefusedNotBlocked)
{
    const Address target = addr_of(&leak_target_retained_strict);

    Result<Hook> pinned = inline_at(
        InlineRequest{
            .name = "RetainStrictPin",
            .target = target,
        },
        &real_hook_detour_add
    );
    ASSERT_TRUE(pinned.has_value()) << pinned.error().message();
    Hook pin_handle = std::move(*pinned);
    ASSERT_TRUE(pin_handle.enable().has_value());
    pin_handle.release();

    // The retained sentinel must refuse this call without an unbounded wait.
    Result<Hook> strict = inline_at(
        InlineRequest{
            .name = "RetainStrict",
            .target = target,
            .options = Options{.fail_if_already_hooked = true},
        },
        &real_hook_detour_add
    );
    ASSERT_FALSE(strict.has_value());
    EXPECT_EQ(strict.error().code, ErrorCode::TargetAlreadyHookedByThisKit);
}

// Both explicit pin verbs contribute to the exported total. Each case also checks the HookManager reason.
TEST(HookRelease, ExplicitReleaseVerbsBookTheirIntentionalLeak)
{
    namespace diag = DetourModKit::diagnostics;

    // The total cannot identify a subsystem. The HookManager bucket detects a leak under the wrong reason.
    const std::size_t hook_bucket_before = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);

    const std::size_t disabled_before = diag::total_intentional_leaks();
    {
        Result<Hook> created = inline_at(
            InlineRequest{
                .name = "ReleaseBooksDisabled",
                .target = addr_of(&leak_target_release_disabled),
            },
            &real_hook_detour_add
        );
        ASSERT_TRUE(created.has_value()) << created.error().message();
        Hook handle = std::move(*created);
        handle.release();
    }
    EXPECT_EQ(diag::total_intentional_leaks(), disabled_before + 1)
        << "Hook::release must book retention even when the hook remains disabled";
    EXPECT_EQ(call_unfolded(&leak_target_release_disabled, 2, 3), 22)
        << "releasing a disabled hook must not arm its detour";
    // Disabled release preserves its ledger entry without a patch. Strict installation must still refuse that target.
    EXPECT_TRUE(is_target_hooked(addr_of(&leak_target_release_disabled)))
        << "a hook released while disabled must keep its ledger record";
    Result<Hook> after_disabled_pin = inline_at(
        InlineRequest{
            .name = "ReleaseDisabledStrict",
            .target = addr_of(&leak_target_release_disabled),
            .options = Options{.fail_if_already_hooked = true},
        },
        &real_hook_detour_add
    );
    ASSERT_FALSE(after_disabled_pin.has_value());
    EXPECT_EQ(after_disabled_pin.error().code, ErrorCode::TargetAlreadyHookedByThisKit);

    const std::size_t inline_before = diag::total_intentional_leaks();
    {
        Result<Hook> created = inline_at(
            InlineRequest{
                .name = "ReleaseBooks",
                .target = addr_of(&leak_target_release_booked),
            },
            &real_hook_detour_add
        );
        ASSERT_TRUE(created.has_value()) << created.error().message();
        Hook handle = std::move(*created);
        ASSERT_TRUE(handle.enable().has_value());
        handle.release();
    }
    EXPECT_EQ(diag::total_intentional_leaks(), inline_before + 1) << "Hook::release must book its deliberate leak";

    auto probe = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(probe.get());
    const std::size_t vmt_before = diag::total_intentional_leaks();
    {
        Result<VmtHook> cloned = vmt_for("ReleaseBooksVmt", probe.get());
        ASSERT_TRUE(cloned.has_value()) << cloned.error().message();
        VmtHook clone = std::move(*cloned);
        clone.release();
    }
    EXPECT_EQ(diag::total_intentional_leaks(), vmt_before + 1) << "VmtHook::release must book its deliberate leak";
    // The object still names the retained clone. A strict re-clone must recognize the ledger record.
    Result<VmtHook> after_vmt_pin = vmt_for(
        "ReleaseBooksVmtStrict",
        probe.get(),
        VmtOptions{
            .fail_if_already_hooked = true,
        }
    );
    ASSERT_FALSE(after_vmt_pin.has_value());
    EXPECT_EQ(after_vmt_pin.error().code, ErrorCode::HookAlreadyExists)
        << "a released clone base must stay recorded for VmtOptions::fail_if_already_hooked";
    // The leaked clone remains live after scope exit. The stack object needs its original vptr before later dispatch.
    *reinterpret_cast<std::uintptr_t *>(probe.get()) = original_vptr;

    EXPECT_EQ(diag::intentional_leak_count(diag::LeakSubsystem::HookManager), hook_bucket_before + 3)
        << "all three retentions belong to the hook subsystem; the VMT clone has no enumerator of its own and books "
           "where the VmtHook destructor's own leak branches book";
}
