#ifndef DETOURMODKIT_INTERNAL_MID_HOOK_ADAPTER_HPP
#define DETOURMODKIT_INTERNAL_MID_HOOK_ADAPTER_HPP

/**
 * @file internal/mid_hook_adapter.hpp
 * @brief The backend-typed mid-hook dispatch pool: per-hook adapters, exception containment, and rundown.
 * @details A mid hook's callback is reached from a hand-emitted assembly stub that the backend calls directly. This
 *          pool places a DMK frame between the stub and the user callback, where exceptions can be contained and
 *          callback entries counted.
 *
 *          The backend's destination type is `void(*)(safetyhook::Context&)` and carries no user-data parameter, so the
 *          only way to reach a per-hook callback from an exactly typed function is to give each hook its own function.
 *          `mid_adapter<I>` is that function, and slot @p I supplies the identity the signature has no room to pass.
 *
 *          The adapter's exact backend type requires no function-pointer conversion or related warning suppression.
 *
 *          The opaque hook::MidContext is recovered by a REFERENCE cast inside the adapter, which is the same
 *          pass-through the public accessors in src/hook.cpp perform and is sound because MidContext is forever
 *          incomplete and is only ever the Context the backend passed.
 *
 *          Only src/hook.cpp includes this header, so the backend stays confined to that translation unit.
 */

#include "DetourModKit/hook.hpp"

#include "platform.hpp"

#include <safetyhook.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace DetourModKit::detail
{
    /**
     * @brief The number of DMK-managed mid hooks that may exist at one time.
     * @details Each slot costs one generated adapter function, so the pool is a compile-time set. Exhaustion is
     *          reported as ErrorCode::MidHookCapacityExhausted rather than degraded into an untyped failure.
     */
    inline constexpr std::size_t MID_ADAPTER_CAPACITY = 64;

    /**
     * @brief Process-lifetime dispatch state for one mid hook.
     * @details Never destroyed. A thread that has already loaded a slot pointer may still be inside its adapter when
     *          teardown releases the slot, so the storage must outlive every hook that ever used it; only the slot's
     *          CONTENTS are recycled, and `claimed` is released only once `adapter_entries` reaches zero.
     */
    struct MidAdapterSlot
    {
        /// Owns the slot for one hook's lifetime. Released only after a witnessed drain.
        std::atomic<bool> claimed{false};
        /// The rundown tombstone: false means no further user callback may begin through this slot.
        std::atomic<bool> live{false};
        /// Threads currently inside this slot's adapter body, including ones that back out at the tombstone.
        std::atomic<std::uint32_t> adapter_entries{0};
        /// User callbacks that passed the tombstone recheck and have not returned.
        std::atomic<std::uint32_t> callbacks_in_flight{0};
        /// Callbacks whose thread could not be recorded in the entry chain, so self-entry cannot be disproven.
        std::atomic<std::uint32_t> untracked_entries{0};
        /// The user callback. Only ever read by a thread that has entered and observed `live`.
        std::atomic<hook::MidHookFn> detour{nullptr};
        /// Counts user exceptions contained at this boundary, for diagnostics.
        std::atomic<std::uint64_t> contained_exceptions{0};
        /// The hooked address, carried here so a containment report can name the site without touching Impl storage.
        std::atomic<std::uintptr_t> target{0};
    };

    /// The pool. Namespace-scope storage with no destructor, by the same never-destroyed discipline the ledger uses.
    [[nodiscard]] MidAdapterSlot *mid_adapter_slots() noexcept;

    /**
     * @brief One frame of the current thread's mid-adapter entry chain.
     * @details Lives on the adapter's own stack, so maintaining the chain allocates nothing. It exists so teardown can
     *          answer "is THIS thread inside THIS slot" exactly, which is what keeps a hook destroyed from inside its
     *          own callback from waiting on itself forever.
     */
    struct MidEntryFrame
    {
        const MidAdapterSlot *slot{nullptr};
        MidEntryFrame *prev{nullptr};
    };

    /**
     * @brief The Win32 TLS index holding this thread's MidEntryFrame chain head.
     * @details Win32 TLS rather than thread_local: MinGW lowers thread_local to __emutls_get_address, which allocates
     *          on every thread's first touch and takes a process-wide lock to do it, inside a callback reached from a
     *          hooked function on an arbitrary host thread. A reserved Win32 index costs a TEB slot read instead.
     *          Reserved by hook::mid_at before any adapter of its slot can run, so a live slot always has a valid
     *          index. Recording a frame under it can still fail (an index past the TEB's inline slots is backed by a
     *          lazily heap-allocated expansion array), which is why an entry that cannot be recorded is counted rather
     *          than assumed absent.
     */
    [[nodiscard]] std::atomic<DWORD> &mid_entry_tls_index() noexcept;

    /// Reserves the TLS index once. Returns false if the process has no index to give.
    [[nodiscard]] bool ensure_mid_entry_tls() noexcept;

    /// True when the calling thread is currently inside @p slot's adapter body.
    [[nodiscard]] bool thread_is_inside_mid_adapter(const MidAdapterSlot &slot) noexcept;

    /// Reports a contained user exception. Defined in src/hook.cpp, where the logger is already visible.
    void note_contained_mid_exception(MidAdapterSlot &slot) noexcept;

#if defined(DMK_ENABLE_TEST_SEAMS)
    /**
     * @brief Fired inside the adapter after the fast-path live check and before the callback commit.
     * @details The window between those two points is the only one the tombstone recheck below exists to close, and it
     *          is a pure thread race: an entrant that has already passed the fast-path check must still not run a
     *          callback if a rundown completes before it commits. No stress schedule reaches that instant reliably, so
     *          a test parks a thread here and runs the teardown to completion underneath it.
     */
    extern void (*g_mid_adapter_precommit_probe)() noexcept;
#endif

    /// Takes ownership of a free slot, or returns @ref MID_ADAPTER_CAPACITY when the pool is full.
    [[nodiscard]] std::size_t claim_mid_adapter_slot() noexcept;

    /// Returns a drained slot to the pool. Never call on a slot that has not been run down.
    void release_mid_adapter_slot(std::size_t index) noexcept;

    /// The outcome of @ref run_down_mid_slot.
    enum class MidRundown : std::uint8_t
    {
        /// No user callback is executing; teardown may proceed.
        Drained,
        /**
         * @brief Waiting cannot be proven to terminate, so the caller must pin instead.
         * @details Either the calling thread is itself inside the adapter (much the likelier cause), or an entrant
         *          could not be recorded and so cannot be ruled out as the caller. The two are not distinguished
         *          because the required action is the same.
         */
        Unwaitable
    };

    /**
     * @brief Waits for every user callback committed before @p slot was tombstoned.
     * @details New adapter entries may still arrive through a pinned backend, but the live recheck prevents them from
     *          committing a callback. Returns Unwaitable rather than start a wait that may never end.
     */
    [[nodiscard]] MidRundown run_down_mid_slot(MidAdapterSlot &slot) noexcept;

    /**
     * @brief Waits for every adapter body to leave after entry through the backend has stopped.
     * @param slot The tombstoned slot to drain.
     * @note This bounds the DMK adapter body, NOT the backend stub that calls it. `adapter_entries` is incremented by
     *       the first statement of @ref dispatch_mid_adapter, which the stub reaches only after ~391 bytes of
     *       register spilling, so a thread parked inside that spill is invisible here. Accounting at stub entry is not
     *       available to us: the stub is a fixed machine-code array in the backend, and `safetyhook::MidHook` exposes
     *       no quiescence primitive and keeps its inner hook and stub allocation private, so closing this would take a
     *       backend patch. The residual window is narrow, is not host-visible (a freed stub's pages stay mapped inside
     *       the allocator's block until a later install recycles the range), and is strictly smaller than the
     *       no-drain-at-all behaviour this replaced. Do not read a clean drain as full stub quiescence.
     */
    void drain_mid_adapter_entries(MidAdapterSlot &slot) noexcept;

    /**
     * @brief The body every generated adapter shares.
     * @details Enter, recheck, invoke, leave. The callback-counter/recheck pair and the tombstone/drain pair are a
     *          Dekker seam: both sides are seq_cst so at least one of them observes the other, which is what makes "no
     *          callback begins after rundown returns" hold without a lock on the callback path.
     *
     *          The reference count is held across the WHOLE body, including the back-out, so a drained slot has no
     *          thread anywhere in this function and its contents may be recycled.
     */
    inline void dispatch_mid_adapter(MidAdapterSlot &slot, safetyhook::Context &ctx) noexcept
    {
        slot.adapter_entries.fetch_add(1, std::memory_order_seq_cst);
        if (slot.live.load(std::memory_order_seq_cst))
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *probe = g_mid_adapter_precommit_probe)
            {
                probe();
            }
#endif
            slot.callbacks_in_flight.fetch_add(1, std::memory_order_seq_cst);
            if (slot.live.load(std::memory_order_seq_cst))
            {
                if (const hook::MidHookFn detour = slot.detour.load(std::memory_order_acquire))
                {
                    const DWORD tls = mid_entry_tls_index().load(std::memory_order_acquire);
                    MidEntryFrame frame{&slot, nullptr};
                    bool tracked = false;
                    if (tls != TLS_OUT_OF_INDEXES)
                    {
                        frame.prev = static_cast<MidEntryFrame *>(::TlsGetValue(tls));
                        tracked = ::TlsSetValue(tls, &frame) != FALSE;
                    }
                    if (!tracked)
                    {
                        // The chain walk cannot see this thread, so a teardown must not conclude it is absent: a wrong
                        // "no" makes the rundown wait on the very thread running it, while a wrong "yes" only pins.
                        // Counted rather than made sticky so the pool recovers once the entry leaves.
                        slot.untracked_entries.fetch_add(1, std::memory_order_seq_cst);
                    }
                    try
                    {
                        // The one boundary that must never let a throw reach the backend's generated stub: that frame
                        // has no unwind data, so an escaping exception is a host crash rather than an error.
                        detour(reinterpret_cast<hook::MidContext &>(ctx));
                    }
                    catch (...)
                    {
                        note_contained_mid_exception(slot);
                    }
                    if (tracked)
                    {
                        (void)::TlsSetValue(tls, frame.prev);
                    }
                    else
                    {
                        slot.untracked_entries.fetch_sub(1, std::memory_order_seq_cst);
                    }
                }
            }
            slot.callbacks_in_flight.fetch_sub(1, std::memory_order_seq_cst);
        }
        slot.adapter_entries.fetch_sub(1, std::memory_order_seq_cst);
    }

    /**
     * @brief The generated per-hook adapter.
     * @details This IS the backend's destination: a genuine `void(safetyhook::Context&)`, so the backend's call through
     *          it is an ordinary call of a function of its own type.
     */
    template <std::size_t Index> void mid_adapter(safetyhook::Context &ctx) noexcept
    {
        dispatch_mid_adapter(mid_adapter_slots()[Index], ctx);
    }

    template <std::size_t... Indices>
    [[nodiscard]] constexpr std::array<safetyhook::MidHookFn, sizeof...(Indices)> make_mid_adapter_table(
        std::index_sequence<Indices...>) noexcept
    {
        // Dropping noexcept from each adapter pointer's type is a standard implicit conversion.
        return {&mid_adapter<Indices>...};
    }

    /// Adapter addresses in the exact type the backend consumes.
    inline constexpr std::array<safetyhook::MidHookFn, MID_ADAPTER_CAPACITY> MID_ADAPTER_TABLE =
        make_mid_adapter_table(std::make_index_sequence<MID_ADAPTER_CAPACITY>{});
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_MID_HOOK_ADAPTER_HPP
