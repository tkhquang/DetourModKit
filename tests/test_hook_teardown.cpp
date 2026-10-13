#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"

#include "internal/hook_ledger.hpp"

#include "fixtures/proof_section.hpp"
#include "fixtures/hook_fixture.hpp"
#include "fixtures/log_capture.hpp"

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

    /// A pin whose detour stays reachable books here.
    [[nodiscard]] std::size_t hook_manager_leaks() noexcept
    {
        return diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    }

    /// A retired layer that keeps backend storage while no path reaches its detour books here.
    [[nodiscard]] std::size_t hook_residue_leaks() noexcept
    {
        return diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookResidue);
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

// The newer trampoline resumes through the lower patch. A lower-layer restore invalidates that continuation, so a
// lower layer toggles by its relay and writes no target byte.
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
            const std::array<std::uint8_t, 16> armed = entry_bytes(&layer_state_target);

            // The older layer is no longer on top. Its disable bypasses and its enable resumes, with the bytes intact.
            const Result<void> disabled = h_base.disable();
            ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
            EXPECT_FALSE(h_base.is_enabled());
            EXPECT_EQ(entry_bytes(&layer_state_target), armed) << "a lower-layer disable altered the target's bytes";
            const Result<void> enabled = h_base.enable();
            ASSERT_TRUE(enabled.has_value()) << enabled.error().message();
            EXPECT_TRUE(h_base.is_enabled());
            EXPECT_EQ(entry_bytes(&layer_state_target), armed) << "a lower-layer enable altered the target's bytes";

            EXPECT_EQ(call_unfolded(&layer_state_target, 5), 2005);
            EXPECT_TRUE(h_top.is_enabled());
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

// Call results cannot detect a write followed by a restore. Direct byte comparison covers both lower-layer toggles.
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

    const Result<void> disabled = h_base.disable();
    ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
    EXPECT_EQ(entry_bytes(&layer_state_target), armed) << "a lower-layer disable altered the target's bytes";

    const Result<void> enabled = h_base.enable();
    ASSERT_TRUE(enabled.has_value()) << enabled.error().message();
    EXPECT_EQ(entry_bytes(&layer_state_target), armed) << "a lower-layer enable altered the target's bytes";
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

// A bare vector produces oldest-first teardown. The older layer retires under the newer one. It never armed, so it
// owns no position: the vacate is refused and the Impl leaks. No path reaches its detour, so it books HookResidue.
TEST(HookInlineLayered, OldestFirstTeardownLeaksOlderBackend)
{
    // Measure a delta rather than resetting the process-wide counters, so this test does not perturb any other
    // leak-count assertion in the suite.
    const std::size_t manager_before = hook_manager_leaks();
    const std::size_t residue_before = hook_residue_leaks();

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

    EXPECT_EQ(hook_residue_leaks(), residue_before + 1)
        << "oldest-first layered teardown must retire the older layer as residue, not restore it";
    EXPECT_EQ(hook_manager_leaks(), manager_before) << "a residue reaches no detour, so it books no HookManager pin";

    // The newer layer is now the top layer, so it restores and adds no leak.
    new_handle.reset();
    EXPECT_EQ(hook_residue_leaks(), residue_before + 1);
    EXPECT_EQ(hook_manager_leaks(), manager_before);

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
        << "a residue keeps its ledger entry, so a strict install must still see the hooked target";
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

// A pinned newer layer still resumes through the older relay, so the older teardown retires by bypass. Without the
// ledger count, the destructor witness reads Foreign bytes and also retires it. This end-to-end case therefore does
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
    const std::array<std::uint8_t, 16> pinned = entry_bytes(&leak_target_retained_newer);

    const std::size_t manager_before = hook_manager_leaks();
    const std::size_t residue_before = hook_residue_leaks();
    {
        const Hook discard = std::move(older_handle);
    }
    EXPECT_EQ(hook_residue_leaks(), residue_before + 1)
        << "the retained id of a pinned newer layer must still outrank an older teardown";
    EXPECT_EQ(hook_manager_leaks(), manager_before) << "a residue reaches no detour, so it books no HookManager pin";
    EXPECT_EQ(entry_bytes(&leak_target_retained_newer), pinned) << "the older teardown altered the pinned prologue";
}

// This case proves the toggle half of the same retention contract. An older layer that stays live under a pin
// bypasses on disable and resumes on enable. A restore of its prologue over the still-installed pin fails this
// contract. Here the id that outranks the caller belongs to no handle at all, and Hook::release() leaves only that
// shape behind. The teardown then retires the older layer as residue under the same pin.
TEST(HookLedgerRetainedId, LiveOlderLayerUnderAPinBypasses)
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
    std::optional<Hook> older_handle{std::move(*older)};
    ASSERT_TRUE(older_handle->enable().has_value());

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

    const Result<void> disabled = older_handle->disable();
    ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
    EXPECT_FALSE(older_handle->is_enabled());
    EXPECT_EQ(entry_bytes(&leak_target_retained_conflict), pinned) << "a bypass altered the pinned prologue";

    const Result<void> enabled = older_handle->enable();
    ASSERT_TRUE(enabled.has_value()) << enabled.error().message();
    EXPECT_TRUE(older_handle->is_enabled());
    EXPECT_EQ(entry_bytes(&leak_target_retained_conflict), pinned) << "a resume altered the pinned prologue";

    const std::size_t manager_before = hook_manager_leaks();
    const std::size_t residue_before = hook_residue_leaks();
    older_handle.reset();
    EXPECT_EQ(hook_residue_leaks(), residue_before + 1);
    EXPECT_EQ(hook_manager_leaks(), manager_before);
    EXPECT_EQ(entry_bytes(&leak_target_retained_conflict), pinned) << "the older teardown altered the pinned prologue";

    // The pin is unreachable from any handle, so the target stays hooked for the rest of the process.
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

// A retired position stays in its target's chain for the process lifetime, so each case below owns its target.
namespace
{
    using ChainFn = int (*)(int);

    // Each layer adds its own delta, so one call result names every detour on the path.
    constexpr int BASE_DELTA = 1000;
    constexpr int TOP_DELTA = 2000;
    constexpr int SUCCESSOR_DELTA = 4000;
    constexpr int UPPER_SUCCESSOR_DELTA = 8000;
    constexpr int FOREIGN_DELTA = 16000;
    constexpr int RENAMED_DELTA = 32000;

    DMK_PROOF_SEEDED_TARGET(bypass_disable_target, 101)
    DMK_PROOF_SEEDED_TARGET(bypass_rearm_target, 103)
    DMK_PROOF_SEEDED_TARGET(bypass_restore_target, 107)
    DMK_PROOF_SEEDED_TARGET(foreign_disable_target, 109)
    DMK_PROOF_SEEDED_TARGET(foreign_teardown_target, 113)
    DMK_PROOF_SEEDED_TARGET(mid_lower_target, 127)
    DMK_PROOF_SEEDED_TARGET(residue_target, 131)
    DMK_PROOF_SEEDED_TARGET(module_reference_armed_target, 137)
    DMK_PROOF_SEEDED_TARGET(module_reference_unarmed_target, 139)

    /// The next layer that one detour calls. Each case and delta owns one, so no case redirects another.
    template <int Case, int Delta> std::atomic<ChainFn> chain_next{nullptr};

    template <int Case, int Delta> DMK_TEST_NOINLINE int chain_detour(int value)
    {
        return call_unfolded(chain_next<Case, Delta>.load(std::memory_order_acquire), value) + Delta;
    }

    /// Installs a disabled layer whose detour adds @p Delta to the result of its own trampoline.
    template <int Case, int Delta> [[nodiscard]] Result<Hook> install_chain_layer(const char *name, Address target)
    {
        Result<Hook> created = inline_at(
            InlineRequest{
                .name = name,
                .target = target,
            },
            &chain_detour<Case, Delta>
        );
        if (created.has_value())
        {
            chain_next<Case, Delta>.store(created->original<ChainFn>(), std::memory_order_release);
        }
        return created;
    }

    /// The prefix of every hook log line: the hook name and its zero-padded target address.
    [[nodiscard]] std::string hook_log_prefix(std::string_view name, Address target)
    {
        return std::format("hook: '{}' at 0x{:016X} ", name, target.raw());
    }

    [[nodiscard]] bool write_code(std::uintptr_t address, std::span<const std::uint8_t> bytes) noexcept
    {
        void *const code = reinterpret_cast<void *>(address);
        DWORD previous = 0;
        if (VirtualProtect(code, bytes.size(), PAGE_EXECUTE_READWRITE, &previous) == FALSE)
        {
            return false;
        }
        std::memcpy(code, bytes.data(), bytes.size());
        DWORD ignored = 0;
        (void)VirtualProtect(code, bytes.size(), previous, &ignored);
        return FlushInstructionCache(GetCurrentProcess(), code, bytes.size()) != FALSE;
    }

    /**
     * @brief A layer that a writer outside the kit places over a hooked target, with a jump to its own detour.
     * @details The trampoline holds the relocated first instruction of the target, which is the jump of the layer
     *          below, and a jump back past it. The destructor writes the saved bytes back before it frees the
     *          trampoline.
     */
    class ForeignChainLayer
    {
        static constexpr std::size_t RELATIVE_JUMP_SIZE = 5;
        static constexpr std::size_t ABSOLUTE_JUMP_SIZE = 14;
        static constexpr std::size_t TRAMPOLINE_SIZE = 4096;

    public:
        explicit ForeignChainLayer(std::uintptr_t target) noexcept : m_target(target)
        {
            const auto *const entry = reinterpret_cast<const std::uint8_t *>(target);
            std::memcpy(m_saved.data(), entry, m_saved.size());
            std::uintptr_t next = 0;
            std::size_t length = 0;
            if (entry[0] == 0xE9)
            {
                std::int32_t displacement = 0;
                std::memcpy(&displacement, entry + 1, sizeof(displacement));
                next =
                    target + RELATIVE_JUMP_SIZE + static_cast<std::uintptr_t>(static_cast<std::intptr_t>(displacement));
                length = RELATIVE_JUMP_SIZE;
            }
            else if (entry[0] == 0xFF && entry[1] == 0x25 && entry[2] == 0 && entry[3] == 0 && entry[4] == 0 &&
                     entry[5] == 0)
            {
                std::memcpy(&next, entry + 6, sizeof(next));
                length = ABSOLUTE_JUMP_SIZE;
            }
            else
            {
                return;
            }
            m_trampoline = static_cast<std::uint8_t *>(
                VirtualAlloc(nullptr, TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            );
            if (m_trampoline == nullptr)
            {
                return;
            }
            put_absolute_jump(m_trampoline, next);
            put_absolute_jump(m_trampoline + ABSOLUTE_JUMP_SIZE, target + length);
            (void)FlushInstructionCache(GetCurrentProcess(), m_trampoline, TRAMPOLINE_SIZE);
        }

        ~ForeignChainLayer() noexcept { remove(); }

        ForeignChainLayer(const ForeignChainLayer &) = delete;
        ForeignChainLayer &operator=(const ForeignChainLayer &) = delete;
        ForeignChainLayer(ForeignChainLayer &&) = delete;
        ForeignChainLayer &operator=(ForeignChainLayer &&) = delete;

        /// The trampoline, or nullptr when the target does not start with a jump.
        [[nodiscard]] ChainFn trampoline() const noexcept { return reinterpret_cast<ChainFn>(m_trampoline); }

        /// Points the target at @p detour, which must lie within a relative jump of the target.
        [[nodiscard]] bool attach(std::uintptr_t detour) noexcept
        {
            const std::int64_t displacement =
                static_cast<std::int64_t>(detour) - static_cast<std::int64_t>(m_target + RELATIVE_JUMP_SIZE);
            if (m_trampoline == nullptr || displacement < std::numeric_limits<std::int32_t>::min() ||
                displacement > std::numeric_limits<std::int32_t>::max())
            {
                return false;
            }
            const auto relative = static_cast<std::int32_t>(displacement);
            std::array<std::uint8_t, RELATIVE_JUMP_SIZE> jump{};
            jump[0] = 0xE9;
            std::memcpy(jump.data() + 1, &relative, sizeof(relative));
            m_attached = write_code(m_target, jump);
            return m_attached;
        }

        /// Writes the saved bytes back, then frees the trampoline. A failed write keeps the reachable trampoline.
        void remove() noexcept
        {
            if (m_attached)
            {
                if (!write_code(m_target, m_saved))
                {
                    return;
                }
                m_attached = false;
            }
            if (m_trampoline != nullptr)
            {
                (void)VirtualFree(m_trampoline, 0, MEM_RELEASE);
                m_trampoline = nullptr;
            }
        }

    private:
        static void put_absolute_jump(std::uint8_t *at, std::uintptr_t destination) noexcept
        {
            // jmp qword ptr [rip+0], then the destination word.
            constexpr std::array<std::uint8_t, 6> opcode{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
            std::memcpy(at, opcode.data(), opcode.size());
            std::memcpy(at + opcode.size(), &destination, sizeof(destination));
        }

        std::uintptr_t m_target{0};
        std::array<std::uint8_t, RELATIVE_JUMP_SIZE> m_saved{};
        std::uint8_t *m_trampoline{nullptr};
        bool m_attached{false};
    };

    /**
     * @brief Retires an armed lower layer under a foreign layer that chains to it, by a disable and then a teardown,
     *        or by a teardown alone.
     * @details The foreign bytes stay as the foreign writer left them, and every call skips the retired detour.
     */
    template <int Case>
    void expect_foreign_chain_skips_retired_layer(ChainFn target_function, const char *name, bool disable_first)
    {
        const Address target = addr_of(target_function);
        ASSERT_FALSE(is_target_hooked(target));
        const int pristine = call_unfolded(target_function, 5);
        const std::size_t manager_before = hook_manager_leaks();
        const std::size_t residue_before = hook_residue_leaks();

        Result<Hook> created = install_chain_layer<Case, BASE_DELTA>(name, target);
        ASSERT_TRUE(created.has_value()) << created.error().message();
        std::optional<Hook> lower{std::move(*created)};
        ASSERT_TRUE(lower->enable().has_value());

        ForeignChainLayer foreign{target.raw()};
        ASSERT_TRUE(foreign.trampoline() != nullptr) << "the lower patch does not start with a jump";
        chain_next<Case, FOREIGN_DELTA>.store(foreign.trampoline(), std::memory_order_release);
        const ChainFn foreign_detour = &chain_detour<Case, FOREIGN_DELTA>;
        ASSERT_TRUE(foreign.attach(reinterpret_cast<std::uintptr_t>(foreign_detour)));
        ASSERT_EQ(call_unfolded(target_function, 5), pristine + FOREIGN_DELTA + BASE_DELTA);
        const std::array<std::uint8_t, 16> foreign_bytes = entry_bytes(target_function);

        std::string text;
        {
            dmk_test::LoggerFileCapture capture{LogLevel::Info};
            if (disable_first)
            {
                const Result<void> disabled = lower->disable();
                ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
                EXPECT_FALSE(lower->is_enabled());
                EXPECT_EQ(entry_bytes(target_function), foreign_bytes) << "the bypass wrote over the foreign layer";
                EXPECT_EQ(call_unfolded(target_function, 5), pristine + FOREIGN_DELTA);
            }
            lower.reset();
            text = capture.read_all();
        }
        const std::string prefix = hook_log_prefix(name, target);
        if (disable_first)
        {
            EXPECT_NE(
                text.find(prefix + "bypassed under a newer layer: another writer owns the prologue."),
                std::string::npos
            ) << text;
        }
        EXPECT_NE(
            text.find(
                prefix + "retired by bypass under a newer layer: another writer owns the prologue. Its position "
                         "stays for a later generation."
            ),
            std::string::npos
        ) << text;
        EXPECT_EQ(entry_bytes(target_function), foreign_bytes) << "the retirement wrote over the foreign layer";
        EXPECT_EQ(call_unfolded(target_function, 5), pristine + FOREIGN_DELTA) << "the retired detour still ran";
        EXPECT_EQ(hook_residue_leaks(), residue_before + 1);
        EXPECT_EQ(hook_manager_leaks(), manager_before);

        // The foreign writer unhooks by its saved bytes. Its continuation then runs the vacated trampoline.
        foreign.remove();
        EXPECT_EQ(call_unfolded(target_function, 5), pristine);
        EXPECT_TRUE(is_target_hooked(target));
    }

    std::atomic<int> s_mid_lower_entries{0};

    void count_mid_lower_entry(MidContext &) noexcept
    {
        s_mid_lower_entries.fetch_add(1, std::memory_order_relaxed);
    }

    /**
     * @brief Retires a lower layer under an upper one and checks that the residue gives its module reference back.
     * @param arm False keeps both layers unarmed, so the lower layer owns no position and its vacate is refused.
     */
    template <int Case> void expect_residue_releases_module_reference(ChainFn target_function, bool arm)
    {
        const Address target = addr_of(target_function);
        ASSERT_FALSE(is_target_hooked(target));
        const std::size_t pins_before = diagnostics::module_pin_count(diagnostics::ModulePinReason::Hook);
        const std::size_t manager_before = hook_manager_leaks();
        const std::size_t residue_before = hook_residue_leaks();

        Result<Hook> lower_created = install_chain_layer<Case, BASE_DELTA>("ModuleReferenceLower", target);
        ASSERT_TRUE(lower_created.has_value()) << lower_created.error().message();
        std::optional<Hook> lower{std::move(*lower_created)};
        if (arm)
        {
            ASSERT_TRUE(lower->enable().has_value());
        }
        Result<Hook> upper_created = install_chain_layer<Case, TOP_DELTA>("ModuleReferenceUpper", target);
        ASSERT_TRUE(upper_created.has_value()) << upper_created.error().message();
        std::optional<Hook> upper{std::move(*upper_created)};
        if (arm)
        {
            ASSERT_TRUE(upper->enable().has_value());
        }
        ASSERT_EQ(diagnostics::module_pin_count(diagnostics::ModulePinReason::Hook), pins_before + 2);

        lower.reset();
        EXPECT_EQ(hook_residue_leaks(), residue_before + 1);
        EXPECT_EQ(hook_manager_leaks(), manager_before);
        EXPECT_EQ(diagnostics::module_pin_count(diagnostics::ModulePinReason::Hook), pins_before + 1)
            << "a residue kept the module reference of a detour that no path reaches";

        upper.reset();
        EXPECT_EQ(diagnostics::module_pin_count(diagnostics::ModulePinReason::Hook), pins_before);
    }
} // namespace

// A lower layer under a newer one disables by a switch of its own relay. The target keeps the bytes of the newer
// layer, and every call skips the lower detour.
TEST(HookLayerBypass, LowerLayerDisableBypassesWithoutTargetWrite)
{
    const Address target = addr_of(&bypass_disable_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&bypass_disable_target, 5);
    {
        Result<Hook> base = install_chain_layer<1, BASE_DELTA>("BypassDisableBase", target);
        ASSERT_TRUE(base.has_value()) << base.error().message();
        Hook h_base = std::move(*base);
        ASSERT_TRUE(h_base.enable().has_value());
        Result<Hook> top = install_chain_layer<1, TOP_DELTA>("BypassDisableTop", target);
        ASSERT_TRUE(top.has_value()) << top.error().message();
        Hook h_top = std::move(*top);
        ASSERT_TRUE(h_top.enable().has_value());
        ASSERT_EQ(call_unfolded(&bypass_disable_target, 5), pristine + TOP_DELTA + BASE_DELTA);
        const std::array<std::uint8_t, 16> armed = entry_bytes(&bypass_disable_target);

        std::string text;
        {
            dmk_test::LoggerFileCapture capture{LogLevel::Info};
            const Result<void> disabled = h_base.disable();
            ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
            text = capture.read_all();
        }
        EXPECT_NE(
            text.find(hook_log_prefix("BypassDisableBase", target) + "bypassed under 1 newer layer(s)."),
            std::string::npos
        ) << text;
        EXPECT_EQ(entry_bytes(&bypass_disable_target), armed) << "the bypass wrote the target";
        EXPECT_FALSE(h_base.is_enabled());
        EXPECT_EQ(h_base.call<int>(5), int{}) << "a bypassed hook dispatched its original";
        EXPECT_EQ(call_unfolded(&bypass_disable_target, 5), pristine + TOP_DELTA) << "the bypassed detour still ran";

        // A second disable keeps the bypass, because the newer layer still owns the target.
        ASSERT_TRUE(h_base.disable().has_value());
        EXPECT_EQ(entry_bytes(&bypass_disable_target), armed);
        EXPECT_EQ(call_unfolded(&bypass_disable_target, 5), pristine + TOP_DELTA);
    }
    // The newer layer restores the lower patch. The bypassed lower layer is then the top layer, so it restores too.
    EXPECT_FALSE(is_target_hooked(target));
    EXPECT_EQ(call_unfolded(&bypass_disable_target, 5), pristine);
}

// A bypassed lower layer resumes by the same switch. The enable needs no top-layer authority and writes no byte.
TEST(HookLayerBypass, BypassedLayerReArmsWithoutTargetWrite)
{
    const Address target = addr_of(&bypass_rearm_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&bypass_rearm_target, 5);
    {
        Result<Hook> base = install_chain_layer<2, BASE_DELTA>("BypassRearmBase", target);
        ASSERT_TRUE(base.has_value()) << base.error().message();
        Hook h_base = std::move(*base);
        ASSERT_TRUE(h_base.enable().has_value());
        {
            Result<Hook> top = install_chain_layer<2, TOP_DELTA>("BypassRearmTop", target);
            ASSERT_TRUE(top.has_value()) << top.error().message();
            Hook h_top = std::move(*top);
            ASSERT_TRUE(h_top.enable().has_value());
            const std::array<std::uint8_t, 16> armed = entry_bytes(&bypass_rearm_target);

            for (int cycle = 0; cycle < 3; ++cycle)
            {
                SCOPED_TRACE(std::format("cycle {}", cycle));
                ASSERT_TRUE(h_base.disable().has_value());
                EXPECT_EQ(call_unfolded(&bypass_rearm_target, 5), pristine + TOP_DELTA);
                const Result<void> enabled = h_base.enable();
                ASSERT_TRUE(enabled.has_value()) << enabled.error().message();
                EXPECT_TRUE(h_base.is_enabled());
                EXPECT_EQ(entry_bytes(&bypass_rearm_target), armed) << "the resume wrote the target";
                EXPECT_EQ(call_unfolded(&bypass_rearm_target, 5), pristine + TOP_DELTA + BASE_DELTA);
                EXPECT_EQ(h_base.call<int>(5), pristine) << "the resumed hook did not dispatch its original";
            }
        }
        // The newer layer restored the lower patch, so the resumed lower detour is the whole chain.
        EXPECT_TRUE(h_base.is_enabled());
        EXPECT_EQ(call_unfolded(&bypass_rearm_target, 5), pristine + BASE_DELTA);
    }
    EXPECT_FALSE(is_target_hooked(target));
    EXPECT_EQ(call_unfolded(&bypass_rearm_target, 5), pristine);
}

// A bypassed layer that is the top layer again over its own patch restores on a second disable. The next enable arms
// through the top-layer path and writes the same patch again.
TEST(HookLayerBypass, RestoredBypassedLayerArmsThroughTheTopPath)
{
    const Address target = addr_of(&bypass_restore_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&bypass_restore_target, 5);
    const std::array<std::uint8_t, 16> pristine_bytes = entry_bytes(&bypass_restore_target);
    {
        Result<Hook> base = install_chain_layer<3, BASE_DELTA>("BypassRestoreBase", target);
        ASSERT_TRUE(base.has_value()) << base.error().message();
        Hook h_base = std::move(*base);
        ASSERT_TRUE(h_base.enable().has_value());
        const std::array<std::uint8_t, 16> base_patch = entry_bytes(&bypass_restore_target);
        {
            Result<Hook> top = install_chain_layer<3, TOP_DELTA>("BypassRestoreTop", target);
            ASSERT_TRUE(top.has_value()) << top.error().message();
            Hook h_top = std::move(*top);
            ASSERT_TRUE(h_top.enable().has_value());
            ASSERT_TRUE(h_base.disable().has_value());
            EXPECT_EQ(call_unfolded(&bypass_restore_target, 5), pristine + TOP_DELTA);
        }
        EXPECT_EQ(entry_bytes(&bypass_restore_target), base_patch) << "the newer layer did not restore the lower patch";
        EXPECT_FALSE(h_base.is_enabled());
        EXPECT_EQ(call_unfolded(&bypass_restore_target, 5), pristine) << "the bypassed relay skipped the trampoline";

        const Result<void> restored = h_base.disable();
        ASSERT_TRUE(restored.has_value()) << restored.error().message();
        EXPECT_EQ(entry_bytes(&bypass_restore_target), pristine_bytes) << "the second disable did not restore";
        EXPECT_EQ(call_unfolded(&bypass_restore_target, 5), pristine);

        const Result<void> rearmed = h_base.enable();
        ASSERT_TRUE(rearmed.has_value()) << rearmed.error().message();
        EXPECT_TRUE(h_base.is_enabled());
        EXPECT_EQ(entry_bytes(&bypass_restore_target), base_patch) << "the enable did not write its own patch";
        EXPECT_EQ(call_unfolded(&bypass_restore_target, 5), pristine + BASE_DELTA);
    }
    EXPECT_FALSE(is_target_hooked(target));
    EXPECT_EQ(call_unfolded(&bypass_restore_target, 5), pristine);
}

// A foreign writer chains above an armed lower layer with relocated bytes and a jump back. The lower layer retires by
// its relay under those bytes. One case disables before the teardown, and the other tears down alone.
TEST(HookLayerBypass, ForeignChainedLayerSkipsTheRetiredDetour)
{
    {
        SCOPED_TRACE("disable, then teardown");
        expect_foreign_chain_skips_retired_layer<4>(&foreign_disable_target, "ForeignChainDisabled", true);
    }
    {
        SCOPED_TRACE("teardown alone");
        expect_foreign_chain_skips_retired_layer<5>(&foreign_teardown_target, "ForeignChainDestroyed", false);
    }
}

// A mid layer under a newer inline layer closes its route on disable and reopens it on enable, with no target write.
// Its teardown under that layer closes the route for good and books HookResidue.
TEST(HookLayerBypass, MidLowerLayerClosesItsRoute)
{
    const Address target = addr_of(&mid_lower_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&mid_lower_target, 5);
    const std::size_t manager_before = hook_manager_leaks();
    const std::size_t residue_before = hook_residue_leaks();

    Result<Hook> lower_created = mid_at(
        MidRequest{
            .name = "MidBypassLower",
            .target = target,
        },
        &count_mid_lower_entry
    );
    ASSERT_TRUE(lower_created.has_value()) << lower_created.error().message();
    std::optional<Hook> lower{std::move(*lower_created)};
    ASSERT_TRUE(lower->enable().has_value());
    s_mid_lower_entries.store(0, std::memory_order_relaxed);
    ASSERT_EQ(call_unfolded(&mid_lower_target, 5), pristine);
    ASSERT_EQ(s_mid_lower_entries.load(std::memory_order_relaxed), 1);

    Result<Hook> upper_created = install_chain_layer<6, TOP_DELTA>("MidBypassUpper", target);
    ASSERT_TRUE(upper_created.has_value()) << upper_created.error().message();
    std::optional<Hook> upper{std::move(*upper_created)};
    ASSERT_TRUE(upper->enable().has_value());
    ASSERT_EQ(call_unfolded(&mid_lower_target, 5), pristine + TOP_DELTA);
    ASSERT_EQ(s_mid_lower_entries.load(std::memory_order_relaxed), 2);
    const std::array<std::uint8_t, 16> armed = entry_bytes(&mid_lower_target);

    std::string text;
    {
        dmk_test::LoggerFileCapture capture{LogLevel::Info};
        const Result<void> disabled = lower->disable();
        ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
        text = capture.read_all();
    }
    EXPECT_NE(
        text.find(hook_log_prefix("MidBypassLower", target) + "bypassed under 1 newer layer(s)."),
        std::string::npos
    ) << text;
    EXPECT_FALSE(lower->is_enabled());
    EXPECT_EQ(entry_bytes(&mid_lower_target), armed) << "the route close wrote the target";
    EXPECT_EQ(call_unfolded(&mid_lower_target, 5), pristine + TOP_DELTA);
    EXPECT_EQ(s_mid_lower_entries.load(std::memory_order_relaxed), 2) << "the closed route ran the callback";

    const Result<void> enabled = lower->enable();
    ASSERT_TRUE(enabled.has_value()) << enabled.error().message();
    EXPECT_TRUE(lower->is_enabled());
    EXPECT_EQ(entry_bytes(&mid_lower_target), armed) << "the route reopen wrote the target";
    EXPECT_EQ(call_unfolded(&mid_lower_target, 5), pristine + TOP_DELTA);
    EXPECT_EQ(s_mid_lower_entries.load(std::memory_order_relaxed), 3) << "the reopened route skipped the callback";

    lower.reset();
    EXPECT_EQ(hook_residue_leaks(), residue_before + 1);
    EXPECT_EQ(hook_manager_leaks(), manager_before) << "the drained mid residue booked a HookManager pin";
    EXPECT_EQ(entry_bytes(&mid_lower_target), armed) << "the mid retirement wrote the target";
    EXPECT_EQ(call_unfolded(&mid_lower_target, 5), pristine + TOP_DELTA);
    EXPECT_EQ(s_mid_lower_entries.load(std::memory_order_relaxed), 3);

    // The newer layer restores the mid patch. The closed route then passes every caller to the original.
    upper.reset();
    EXPECT_EQ(call_unfolded(&mid_lower_target, 5), pristine);
    EXPECT_EQ(s_mid_lower_entries.load(std::memory_order_relaxed), 3) << "the retired callback ran again";
    EXPECT_EQ(hook_manager_leaks(), manager_before);
    EXPECT_TRUE(is_target_hooked(target));
}

// An oldest-first teardown under a live newer layer retires the older layer as residue. Its detour leaves the chain
// and the live population, and HookManager stays unchanged.
TEST(HookLayerBypass, OldestFirstTeardownLeavesResidueNotPin)
{
    const Address target = addr_of(&residue_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&residue_target, 5);
    const std::size_t manager_before = hook_manager_leaks();
    const std::size_t residue_before = hook_residue_leaks();

    Result<Hook> base_created = install_chain_layer<7, BASE_DELTA>("ResidueBase", target);
    ASSERT_TRUE(base_created.has_value()) << base_created.error().message();
    std::optional<Hook> base{std::move(*base_created)};
    ASSERT_TRUE(base->enable().has_value());
    Result<Hook> top_created = install_chain_layer<7, TOP_DELTA>("ResidueTop", target);
    ASSERT_TRUE(top_created.has_value()) << top_created.error().message();
    std::optional<Hook> top{std::move(*top_created)};
    ASSERT_TRUE(top->enable().has_value());
    ASSERT_EQ(call_unfolded(&residue_target, 5), pristine + TOP_DELTA + BASE_DELTA);
    const std::array<std::uint8_t, 16> armed = entry_bytes(&residue_target);
    const diagnostics::Snapshot layered = diagnostics::collect();

    std::string text;
    {
        dmk_test::LoggerFileCapture capture{LogLevel::Info};
        base.reset();
        text = capture.read_all();
    }
    EXPECT_NE(
        text.find(
            hook_log_prefix("ResidueBase", target) +
            "retired by bypass under 1 newer layer(s). Its position stays for a later generation."
        ),
        std::string::npos
    ) << text;
    EXPECT_EQ(hook_residue_leaks(), residue_before + 1);
    EXPECT_EQ(hook_manager_leaks(), manager_before) << "a residue reaches no detour, so it books no HookManager pin";
    EXPECT_EQ(entry_bytes(&residue_target), armed) << "the retirement wrote the target";
    EXPECT_EQ(call_unfolded(&residue_target, 5), pristine + TOP_DELTA) << "the retired detour still ran";
    const diagnostics::Snapshot retired = diagnostics::collect();
    EXPECT_EQ(retired.hooks_total, layered.hooks_total - 1) << "a residue stayed in the live population";
    EXPECT_EQ(retired.hooks_active, layered.hooks_active - 1);
    EXPECT_TRUE(is_target_hooked(target));

    // The newer layer is now the top layer, so it restores and books nothing.
    top.reset();
    EXPECT_EQ(call_unfolded(&residue_target, 5), pristine);
    EXPECT_EQ(hook_residue_leaks(), residue_before + 1);
    EXPECT_EQ(hook_manager_leaks(), manager_before);
    EXPECT_TRUE(is_target_hooked(target)) << "the residue lost its ledger entry";
}

// A residue reaches no image code, so it gives its module reference back. A lower layer that never armed owns no
// position, so its vacate is refused, and it gives the reference back too.
TEST(HookLayerBypass, ResidueReleasesTheModuleReference)
{
    {
        SCOPED_TRACE("armed layers");
        expect_residue_releases_module_reference<8>(&module_reference_armed_target, true);
    }
    {
        SCOPED_TRACE("unarmed layers");
        expect_residue_releases_module_reference<9>(&module_reference_unarmed_target, false);
    }
}

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    // Mirrors src/internal/hook_backend.hpp, which this binary cannot include because it names the backend headers.
    struct BackendCoordinatorCounts
    {
        std::size_t live{0};
        std::size_t retained{0};
        std::size_t vacant{0};
        std::size_t free{0};
    };

    [[nodiscard]] BackendCoordinatorCounts backend_coordinator_counts_for_test() noexcept;
    [[nodiscard]] std::size_t fill_backend_coordinator_for_test(std::size_t count) noexcept;
    void clear_backend_coordinator_fill_for_test() noexcept;
    void set_backend_toggle_exception_for_test(void *target, bool after_mutation) noexcept;
    [[nodiscard]] std::size_t backend_toggle_exception_catches_for_test() noexcept;
} // namespace DetourModKit::detail

namespace
{
    using DetourModKit::detail::backend_coordinator_counts_for_test;
    using DetourModKit::detail::BackendCoordinatorCounts;
    using DetourModKit::detail::clear_backend_coordinator_fill_for_test;
    using DetourModKit::detail::fill_backend_coordinator_for_test;

    DMK_PROOF_SEEDED_TARGET(claim_target, 149)
    DMK_PROOF_SEEDED_TARGET(claim_toggle_target, 151)
    DMK_PROOF_SEEDED_TARGET(claim_top_target, 157)
    DMK_PROOF_SEEDED_TARGET(claim_once_target, 163)
    DMK_PROOF_SEEDED_TARGET(claim_local_order_target, 167)
    DMK_PROOF_SEEDED_TARGET(mid_failed_restore_target, 173)
    DMK_PROOF_SEEDED_TARGET(budget_floor_target, 179)

    std::atomic<int> s_mid_failed_restore_entries{0};

    void count_mid_failed_restore_entry(MidContext &) noexcept
    {
        s_mid_failed_restore_entries.fetch_add(1, std::memory_order_relaxed);
    }

    /// Makes each backend toggle on one target throw before it writes, and always disarms the seam.
    class ToggleFailureBeforeWriteScope
    {
    public:
        explicit ToggleFailureBeforeWriteScope(Address target) noexcept
        {
            DetourModKit::detail::set_backend_toggle_exception_for_test(reinterpret_cast<void *>(target.raw()), false);
        }
        ~ToggleFailureBeforeWriteScope() noexcept
        {
            DetourModKit::detail::set_backend_toggle_exception_for_test(nullptr, false);
        }
        ToggleFailureBeforeWriteScope(const ToggleFailureBeforeWriteScope &) = delete;
        ToggleFailureBeforeWriteScope &operator=(const ToggleFailureBeforeWriteScope &) = delete;
        ToggleFailureBeforeWriteScope(ToggleFailureBeforeWriteScope &&) = delete;
        ToggleFailureBeforeWriteScope &operator=(ToggleFailureBeforeWriteScope &&) = delete;
    };

    /**
     * @brief Arms a lower and an upper layer on one target, then destroys the lower one, which vacates its position.
     * @param upper Receives the armed upper layer.
     */
    template <int Case>
    void vacate_under_upper_layer(
        ChainFn target_function,
        const char *lower_name,
        const char *upper_name,
        std::optional<Hook> &upper
    )
    {
        const Address target = addr_of(target_function);
        const int pristine = call_unfolded(target_function, 5);
        Result<Hook> lower_created = install_chain_layer<Case, BASE_DELTA>(lower_name, target);
        ASSERT_TRUE(lower_created.has_value()) << lower_created.error().message();
        std::optional<Hook> lower{std::move(*lower_created)};
        ASSERT_TRUE(lower->enable().has_value());
        Result<Hook> upper_created = install_chain_layer<Case, TOP_DELTA>(upper_name, target);
        ASSERT_TRUE(upper_created.has_value()) << upper_created.error().message();
        upper.emplace(std::move(*upper_created));
        ASSERT_TRUE(upper->enable().has_value());
        ASSERT_EQ(call_unfolded(target_function, 5), pristine + TOP_DELTA + BASE_DELTA);

        const std::size_t vacant_before = backend_coordinator_counts_for_test().vacant;
        lower.reset();
        ASSERT_EQ(backend_coordinator_counts_for_test().vacant, vacant_before + 1) << "the lower layer did not vacate";
        ASSERT_EQ(call_unfolded(target_function, 5), pristine + TOP_DELTA);
    }

    /// Installs a same-name successor and proves that it took a vacated cell in place of a fresh record.
    template <int Case, int Delta>
    void claim_vacated_position(const char *name, Address target, std::optional<Hook> &successor)
    {
        const BackendCoordinatorCounts before = backend_coordinator_counts_for_test();
        Result<Hook> claimed = install_chain_layer<Case, Delta>(name, target);
        ASSERT_TRUE(claimed.has_value()) << claimed.error().message();
        successor.emplace(std::move(*claimed));
        const BackendCoordinatorCounts after = backend_coordinator_counts_for_test();
        ASSERT_EQ(after.live, before.live) << "the successor added a fresh record";
        ASSERT_EQ(after.vacant + 1, before.vacant) << "the successor took no vacated cell";
    }
} // namespace

// A same-name install claims the vacated position under the live upper layer. It writes no target byte, adds no
// record, and logs the claim. After the enable, its own detour runs in that position. Another name installs fresh.
TEST(HookPositionClaim, SuccessorClaimsItsPositionByName)
{
    const Address target = addr_of(&claim_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&claim_target, 5);
    std::optional<Hook> upper;
    ASSERT_NO_FATAL_FAILURE(vacate_under_upper_layer<10>(&claim_target, "ClaimLower", "ClaimUpper", upper));
    const std::array<std::uint8_t, 16> armed = entry_bytes(&claim_target);
    const BackendCoordinatorCounts vacated = backend_coordinator_counts_for_test();
    const std::size_t residue_vacated = hook_residue_leaks();

    {
        Result<Hook> renamed = install_chain_layer<10, RENAMED_DELTA>("ClaimLowerRenamed", target);
        ASSERT_TRUE(renamed.has_value()) << renamed.error().message();
        const BackendCoordinatorCounts fresh = backend_coordinator_counts_for_test();
        EXPECT_EQ(fresh.live, vacated.live + 1) << "another name took the vacated position";
        EXPECT_EQ(fresh.vacant, vacated.vacant);
    }
    ASSERT_EQ(backend_coordinator_counts_for_test().live, vacated.live);

    std::optional<Hook> successor;
    std::string text;
    {
        dmk_test::LoggerFileCapture capture{LogLevel::Info};
        ASSERT_NO_FATAL_FAILURE((claim_vacated_position<10, SUCCESSOR_DELTA>("ClaimLower", target, successor)));
        text = capture.read_all();
    }
    EXPECT_NE(text.find(hook_log_prefix("ClaimLower", target) + "claimed a vacated position."), std::string::npos)
        << text;
    EXPECT_EQ(backend_coordinator_counts_for_test().free, vacated.free);
    EXPECT_EQ(entry_bytes(&claim_target), armed) << "the claim wrote the target";
    EXPECT_FALSE(successor->is_enabled());
    EXPECT_EQ(call_unfolded(&claim_target, 5), pristine + TOP_DELTA) << "a claimed position starts switched off";

    const Result<void> enabled = successor->enable();
    ASSERT_TRUE(enabled.has_value()) << enabled.error().message();
    EXPECT_TRUE(successor->is_enabled());
    EXPECT_EQ(entry_bytes(&claim_target), armed) << "the claimed enable wrote the target";
    EXPECT_EQ(call_unfolded(&claim_target, 5), pristine + TOP_DELTA + SUCCESSOR_DELTA);
    EXPECT_EQ(backend_coordinator_counts_for_test().live, vacated.live);
    EXPECT_EQ(hook_residue_leaks(), residue_vacated) << "a claim booked residue";
}

// A claimed hook toggles by one store to its relay slot. Neither verb writes the target or a record, and neither logs
// a bypass.
TEST(HookPositionClaim, ClaimedHookTogglesWithoutTargetWrite)
{
    const Address target = addr_of(&claim_toggle_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&claim_toggle_target, 5);
    std::optional<Hook> upper;
    ASSERT_NO_FATAL_FAILURE(
        vacate_under_upper_layer<11>(&claim_toggle_target, "ClaimToggleLower", "ClaimToggleUpper", upper)
    );
    std::optional<Hook> successor;
    ASSERT_NO_FATAL_FAILURE((claim_vacated_position<11, SUCCESSOR_DELTA>("ClaimToggleLower", target, successor)));
    const std::array<std::uint8_t, 16> armed = entry_bytes(&claim_toggle_target);
    const BackendCoordinatorCounts claimed = backend_coordinator_counts_for_test();

    std::string text;
    {
        dmk_test::LoggerFileCapture capture{LogLevel::Info};
        for (int cycle = 0; cycle < 3; ++cycle)
        {
            SCOPED_TRACE(std::format("cycle {}", cycle));
            const Result<void> enabled = successor->enable();
            ASSERT_TRUE(enabled.has_value()) << enabled.error().message();
            EXPECT_TRUE(successor->is_enabled());
            EXPECT_EQ(entry_bytes(&claim_toggle_target), armed) << "the claimed enable wrote the target";
            EXPECT_EQ(call_unfolded(&claim_toggle_target, 5), pristine + TOP_DELTA + SUCCESSOR_DELTA);
            EXPECT_EQ(successor->call<int>(5), pristine) << "the claimed trampoline did not reach the original";

            const Result<void> disabled = successor->disable();
            ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
            EXPECT_FALSE(successor->is_enabled());
            EXPECT_EQ(entry_bytes(&claim_toggle_target), armed) << "the claimed disable wrote the target";
            EXPECT_EQ(call_unfolded(&claim_toggle_target, 5), pristine + TOP_DELTA);
        }
        text = capture.read_all();
    }
    EXPECT_EQ(text.find("bypassed"), std::string::npos) << text;
    const BackendCoordinatorCounts toggled = backend_coordinator_counts_for_test();
    EXPECT_EQ(toggled.live, claimed.live);
    EXPECT_EQ(toggled.retained, claimed.retained);
    EXPECT_EQ(toggled.vacant, claimed.vacant);
}

// A claimed position never restores, even as the top layer. Its teardown switches the relay off and vacates, so the
// target keeps the patch of the generation that created the position.
TEST(HookPositionClaim, ClaimedTopLayerVacatesInsteadOfRestoring)
{
    const Address target = addr_of(&claim_top_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&claim_top_target, 5);
    const std::array<std::uint8_t, 16> pristine_bytes = entry_bytes(&claim_top_target);
    {
        std::optional<Hook> upper;
        ASSERT_NO_FATAL_FAILURE(
            vacate_under_upper_layer<12>(&claim_top_target, "ClaimTopLower", "ClaimTopUpper", upper)
        );
    }
    // The upper layer restored the lower patch, so the vacated position is now the top of the chain.
    const std::array<std::uint8_t, 16> lower_patch = entry_bytes(&claim_top_target);
    ASSERT_NE(lower_patch, pristine_bytes);
    ASSERT_EQ(call_unfolded(&claim_top_target, 5), pristine);
    const BackendCoordinatorCounts vacated = backend_coordinator_counts_for_test();

    std::optional<Hook> successor;
    ASSERT_NO_FATAL_FAILURE((claim_vacated_position<12, SUCCESSOR_DELTA>("ClaimTopLower", target, successor)));
    ASSERT_TRUE(successor->enable().has_value());
    EXPECT_EQ(entry_bytes(&claim_top_target), lower_patch) << "the claimed enable wrote the target";
    EXPECT_EQ(call_unfolded(&claim_top_target, 5), pristine + SUCCESSOR_DELTA);

    const std::size_t manager_before = hook_manager_leaks();
    const std::size_t residue_before = hook_residue_leaks();
    std::string text;
    {
        dmk_test::LoggerFileCapture capture{LogLevel::Info};
        successor.reset();
        text = capture.read_all();
    }
    EXPECT_NE(text.find(hook_log_prefix("ClaimTopLower", target) + "retired its claimed position."), std::string::npos)
        << text;
    EXPECT_EQ(entry_bytes(&claim_top_target), lower_patch) << "the claimed top layer restored the target";
    EXPECT_EQ(call_unfolded(&claim_top_target, 5), pristine);
    EXPECT_EQ(hook_residue_leaks(), residue_before) << "a vacated claim booked residue";
    EXPECT_EQ(hook_manager_leaks(), manager_before);
    const BackendCoordinatorCounts retired = backend_coordinator_counts_for_test();
    EXPECT_EQ(retired.live, vacated.live);
    EXPECT_EQ(retired.vacant, vacated.vacant);
    EXPECT_TRUE(is_target_hooked(target));
}

// Claim and retire alternate on one position. Only the first vacate books HookResidue, because each later retirement
// hands a claimed cell back and adds no position. The record counts stay constant across the cycles.
TEST(HookPositionClaim, VacancyBooksHookResidueOnce)
{
    const Address target = addr_of(&claim_once_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&claim_once_target, 5);
    const std::size_t manager_before = hook_manager_leaks();
    const std::size_t residue_before = hook_residue_leaks();
    {
        std::optional<Hook> upper;
        ASSERT_NO_FATAL_FAILURE(vacate_under_upper_layer<13>(&claim_once_target, "OnceLower", "OnceUpper", upper));
    }
    ASSERT_EQ(hook_residue_leaks(), residue_before + 1);
    const BackendCoordinatorCounts vacated = backend_coordinator_counts_for_test();

    for (int cycle = 0; cycle < 4; ++cycle)
    {
        SCOPED_TRACE(std::format("cycle {}", cycle));
        {
            std::optional<Hook> successor;
            ASSERT_NO_FATAL_FAILURE((claim_vacated_position<13, SUCCESSOR_DELTA>("OnceLower", target, successor)));
            ASSERT_TRUE(successor->enable().has_value());
            EXPECT_EQ(call_unfolded(&claim_once_target, 5), pristine + SUCCESSOR_DELTA);
        }
        const BackendCoordinatorCounts retired = backend_coordinator_counts_for_test();
        EXPECT_EQ(retired.live, vacated.live);
        EXPECT_EQ(retired.retained, vacated.retained);
        EXPECT_EQ(retired.vacant, vacated.vacant);
        EXPECT_EQ(retired.free, vacated.free);
        EXPECT_EQ(call_unfolded(&claim_once_target, 5), pristine);
    }
    EXPECT_EQ(hook_residue_leaks(), residue_before + 1) << "a claimed retirement booked residue";
    EXPECT_EQ(hook_manager_leaks(), manager_before);
}

// The ledger orders hooks by creation. A claim under an older fresh layer makes that layer read as not top, so its
// teardown vacates in place of a restore. It writes nothing, and a same-name install claims it in turn.
TEST(HookPositionClaim, OlderFreshLayerVacatesAboveANewerClaim)
{
    const Address target = addr_of(&claim_local_order_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&claim_local_order_target, 5);
    const std::size_t manager_before = hook_manager_leaks();
    const std::size_t residue_before = hook_residue_leaks();
    std::optional<Hook> upper;
    ASSERT_NO_FATAL_FAILURE(
        vacate_under_upper_layer<14>(&claim_local_order_target, "LocalOrderLower", "LocalOrderUpper", upper)
    );
    std::optional<Hook> successor;
    ASSERT_NO_FATAL_FAILURE((claim_vacated_position<14, SUCCESSOR_DELTA>("LocalOrderLower", target, successor)));
    ASSERT_TRUE(successor->enable().has_value());
    ASSERT_EQ(call_unfolded(&claim_local_order_target, 5), pristine + TOP_DELTA + SUCCESSOR_DELTA);
    const std::array<std::uint8_t, 16> armed = entry_bytes(&claim_local_order_target);

    std::string text;
    {
        dmk_test::LoggerFileCapture capture{LogLevel::Info};
        upper.reset();
        text = capture.read_all();
    }
    EXPECT_NE(
        text.find(
            hook_log_prefix("LocalOrderUpper", target) +
            "retired by bypass under 1 newer layer(s). Its position stays for a later generation."
        ),
        std::string::npos
    ) << text;
    EXPECT_EQ(entry_bytes(&claim_local_order_target), armed) << "the older fresh layer restored over the claim";
    EXPECT_EQ(call_unfolded(&claim_local_order_target, 5), pristine + SUCCESSOR_DELTA)
        << "the retired upper detour still ran";
    EXPECT_EQ(hook_residue_leaks(), residue_before + 2) << "each fresh vacate books one residue";
    EXPECT_EQ(hook_manager_leaks(), manager_before);

    std::optional<Hook> upper_successor;
    ASSERT_NO_FATAL_FAILURE(
        (claim_vacated_position<14, UPPER_SUCCESSOR_DELTA>("LocalOrderUpper", target, upper_successor))
    );
    ASSERT_TRUE(upper_successor->enable().has_value());
    EXPECT_EQ(entry_bytes(&claim_local_order_target), armed) << "the upper claim wrote the target";
    EXPECT_EQ(call_unfolded(&claim_local_order_target, 5), pristine + UPPER_SUCCESSOR_DELTA + SUCCESSOR_DELTA);

    upper_successor.reset();
    successor.reset();
    EXPECT_EQ(entry_bytes(&claim_local_order_target), armed);
    EXPECT_EQ(call_unfolded(&claim_local_order_target, 5), pristine);
    EXPECT_EQ(hook_residue_leaks(), residue_before + 2) << "a claimed retirement booked residue";
    EXPECT_EQ(hook_manager_leaks(), manager_before);
    EXPECT_TRUE(is_target_hooked(target));
}

// A bypassed mid layer is the top layer over its own patch again once the newer layer restores. A second disable whose
// restore fails before any write still succeeds, and the route stays closed, so no call runs the callback.
TEST(HookLayerBypass, FailedRestoreKeepsTheMidBypass)
{
    const Address target = addr_of(&mid_failed_restore_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&mid_failed_restore_target, 5);
    const std::array<std::uint8_t, 16> pristine_bytes = entry_bytes(&mid_failed_restore_target);

    Result<Hook> lower_created = mid_at(
        MidRequest{
            .name = "MidFailedRestoreLower",
            .target = target,
        },
        &count_mid_failed_restore_entry
    );
    ASSERT_TRUE(lower_created.has_value()) << lower_created.error().message();
    std::optional<Hook> lower{std::move(*lower_created)};
    ASSERT_TRUE(lower->enable().has_value());
    const std::array<std::uint8_t, 16> mid_patch = entry_bytes(&mid_failed_restore_target);
    {
        Result<Hook> upper_created = install_chain_layer<15, TOP_DELTA>("MidFailedRestoreUpper", target);
        ASSERT_TRUE(upper_created.has_value()) << upper_created.error().message();
        Hook upper = std::move(*upper_created);
        ASSERT_TRUE(upper.enable().has_value());
        ASSERT_TRUE(lower->disable().has_value());
        ASSERT_EQ(call_unfolded(&mid_failed_restore_target, 5), pristine + TOP_DELTA);
    }
    ASSERT_EQ(entry_bytes(&mid_failed_restore_target), mid_patch) << "the newer layer did not restore the mid patch";
    s_mid_failed_restore_entries.store(0, std::memory_order_relaxed);
    ASSERT_EQ(call_unfolded(&mid_failed_restore_target, 5), pristine);
    ASSERT_EQ(s_mid_failed_restore_entries.load(std::memory_order_relaxed), 0) << "the bypassed route ran the callback";

    {
        const ToggleFailureBeforeWriteScope failure{target};
        const Result<void> disabled = lower->disable();
        ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u)
            << "the disable did not reach the backend restore";
    }
    EXPECT_FALSE(lower->is_enabled());
    EXPECT_EQ(entry_bytes(&mid_failed_restore_target), mid_patch) << "the failed restore wrote the target";
    EXPECT_EQ(call_unfolded(&mid_failed_restore_target, 5), pristine);
    EXPECT_EQ(s_mid_failed_restore_entries.load(std::memory_order_relaxed), 0)
        << "the failed restore reopened the route";

    // With the seam disarmed, the next disable restores the target, and teardown reclaims the hook.
    const Result<void> restored = lower->disable();
    ASSERT_TRUE(restored.has_value()) << restored.error().message();
    EXPECT_EQ(entry_bytes(&mid_failed_restore_target), pristine_bytes) << "the second disable did not restore";
    lower.reset();
    EXPECT_FALSE(is_target_hooked(target));
    EXPECT_EQ(call_unfolded(&mid_failed_restore_target, 5), pristine);
    EXPECT_EQ(s_mid_failed_restore_entries.load(std::memory_order_relaxed), 0);
}

// The residue budget keeps at least 64 process records free. A lower layer that leaves 64 free retires as residue.
// One that leaves 63 free keeps the HookManager pin with its detour live.
TEST(HookLayerBypass, FreeRecordFloorDecidesResidueOrPin)
{
    struct FillGuard
    {
        ~FillGuard() noexcept { clear_backend_coordinator_fill_for_test(); }
    };
    const FillGuard fill_guard;
    const Address target = addr_of(&budget_floor_target);
    ASSERT_FALSE(is_target_hooked(target));
    const int pristine = call_unfolded(&budget_floor_target, 5);
    const std::size_t manager_before = hook_manager_leaks();
    const std::size_t residue_before = hook_residue_leaks();
    const auto leave_free = [](std::size_t free_records)
    {
        const std::size_t free_now = backend_coordinator_counts_for_test().free;
        ASSERT_GT(free_now, free_records);
        ASSERT_EQ(fill_backend_coordinator_for_test(free_now - free_records), free_now - free_records);
        ASSERT_EQ(backend_coordinator_counts_for_test().free, free_records);
    };

    // 64 free records fit one more residue.
    Result<Hook> base_created = install_chain_layer<20, BASE_DELTA>("FloorBase", target);
    ASSERT_TRUE(base_created.has_value()) << base_created.error().message();
    std::optional<Hook> base{std::move(*base_created)};
    ASSERT_TRUE(base->enable().has_value());
    Result<Hook> top_created = install_chain_layer<20, TOP_DELTA>("FloorTop", target);
    ASSERT_TRUE(top_created.has_value()) << top_created.error().message();
    std::optional<Hook> top{std::move(*top_created)};
    ASSERT_TRUE(top->enable().has_value());
    ASSERT_EQ(call_unfolded(&budget_floor_target, 5), pristine + TOP_DELTA + BASE_DELTA);
    ASSERT_NO_FATAL_FAILURE(leave_free(64));
    base.reset();
    EXPECT_EQ(hook_residue_leaks(), residue_before + 1) << "64 free records did not fit the residue";
    EXPECT_EQ(hook_manager_leaks(), manager_before);
    EXPECT_EQ(call_unfolded(&budget_floor_target, 5), pristine + TOP_DELTA) << "the retired detour still ran";
    clear_backend_coordinator_fill_for_test();
    top.reset();
    ASSERT_EQ(call_unfolded(&budget_floor_target, 5), pristine);

    // 63 free records keep the pin. The new names claim no position, so both layers install fresh.
    Result<Hook> pinned_created = install_chain_layer<20, SUCCESSOR_DELTA>("FloorPinnedBase", target);
    ASSERT_TRUE(pinned_created.has_value()) << pinned_created.error().message();
    std::optional<Hook> pinned{std::move(*pinned_created)};
    ASSERT_TRUE(pinned->enable().has_value());
    Result<Hook> upper_created = install_chain_layer<20, UPPER_SUCCESSOR_DELTA>("FloorPinnedTop", target);
    ASSERT_TRUE(upper_created.has_value()) << upper_created.error().message();
    std::optional<Hook> upper{std::move(*upper_created)};
    ASSERT_TRUE(upper->enable().has_value());
    ASSERT_EQ(call_unfolded(&budget_floor_target, 5), pristine + UPPER_SUCCESSOR_DELTA + SUCCESSOR_DELTA);
    ASSERT_NO_FATAL_FAILURE(leave_free(63));
    std::string text;
    {
        dmk_test::LoggerFileCapture capture{LogLevel::Warning};
        pinned.reset();
        text = capture.read_all();
    }
    EXPECT_NE(
        text.find(
            hook_log_prefix("FloorPinnedBase", target) +
            "leaked its backend during teardown, so its detour stays reachable: the target or the process route "
            "registry reached the residue budget."
        ),
        std::string::npos
    ) << text;
    EXPECT_EQ(hook_manager_leaks(), manager_before + 1) << "63 free records did not keep the pin";
    EXPECT_EQ(hook_residue_leaks(), residue_before + 1);
    EXPECT_EQ(call_unfolded(&budget_floor_target, 5), pristine + UPPER_SUCCESSOR_DELTA + SUCCESSOR_DELTA)
        << "the pinned detour left the chain";
    clear_backend_coordinator_fill_for_test();
    upper.reset();
    EXPECT_EQ(call_unfolded(&budget_floor_target, 5), pristine + SUCCESSOR_DELTA) << "the pin lost its detour";
    EXPECT_TRUE(is_target_hooked(target));
}
#endif
