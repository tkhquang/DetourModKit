/**
 * @file internal/mid_hook_adapter.cpp
 * @brief This TU owns the mid-hook dispatch pool state, its rundown drains, and the mid route test seams.
 */

#include "internal/mid_hook_adapter.hpp"

#include "internal/drain_backoff.hpp"

#include "DetourModKit/logger.hpp"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    // This probe fires inside the mid-hook adapter between the fast-path live check and callback commit. See its
    // declaration in internal/mid_hook_adapter.hpp for the race it exists to make reachable.
    void (*g_mid_adapter_precommit_probe)() noexcept = nullptr;
    // Selects one thread whose adapter entry-chain store reports failure. See its declaration in
    // internal/mid_hook_adapter.hpp for the platform condition it stands in for.
    std::atomic<std::uint32_t> g_mid_entry_store_failure_thread{0};
    std::atomic<std::uint64_t> g_mid_entry_store_failure_hits{0};

    void set_mid_route_park_for_test(MidRouteParkStage stage) noexcept
    {
        safetyhook::RouteParkStage backend_stage = safetyhook::RouteParkStage::NONE;
        if (stage == MidRouteParkStage::BeforeAdapter)
        {
            backend_stage = safetyhook::RouteParkStage::BEFORE_DESTINATION;
        }
        else if (stage == MidRouteParkStage::AfterAdapter)
        {
            backend_stage = safetyhook::RouteParkStage::BEFORE_EXIT;
        }
        safetyhook::set_route_park_for_test(backend_stage);
    }

    bool mid_route_park_reached_for_test() noexcept
    {
        return safetyhook::route_park_reached_for_test();
    }
#endif

    // The mid-hook dispatch pool uses constant initialization and trivial destruction. It registers no destructor, so
    // it outlives an adapter that remains active during static destruction.
    namespace
    {
        MidAdapterSlot s_mid_slots[MID_ADAPTER_CAPACITY];
        std::atomic<DWORD> s_mid_entry_tls{TLS_OUT_OF_INDEXES};

        /// Defines the committed callback wait bound. Expiry pins the backend instead of a hang (MidHookDrainTest).
        constexpr auto MID_CALLBACK_DRAIN_TIMEOUT = std::chrono::seconds{5};

        /// Defines the post-restore adapter-body drain bound. Expiry retains the slot and stub (MidHookDrainTest).
        constexpr auto MID_ADAPTER_ENTRY_DRAIN_TIMEOUT = std::chrono::seconds{1};

#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<std::size_t> s_last_claimed_mid_slot{MID_ADAPTER_CAPACITY};
#endif
    } // namespace

    MidAdapterSlot *mid_adapter_slots() noexcept
    {
        return s_mid_slots;
    }

    std::atomic<DWORD> &mid_entry_tls_index() noexcept
    {
        return s_mid_entry_tls;
    }

    bool ensure_mid_entry_tls() noexcept
    {
        if (s_mid_entry_tls.load(std::memory_order_acquire) != TLS_OUT_OF_INDEXES)
        {
            return true;
        }
        const DWORD fresh = ::TlsAlloc();
        if (fresh == TLS_OUT_OF_INDEXES)
        {
            return false;
        }
        DWORD expected = TLS_OUT_OF_INDEXES;
        if (!s_mid_entry_tls
                 .compare_exchange_strong(expected, fresh, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            // Another installer won. Its index is already public, and this slot contains no value.
            ::TlsFree(fresh);
        }
        return true;
    }

    bool thread_is_inside_mid_adapter(const MidAdapterSlot &slot) noexcept
    {
        if (slot.untracked_entries.load(std::memory_order_seq_cst) != 0)
        {
            // An unrecorded entrant is in flight, so self-entry cannot be disproven. Claim it: a wrong "no"
            // deadlocks while a wrong "yes" only pins.
            return true;
        }
        const DWORD tls = s_mid_entry_tls.load(std::memory_order_acquire);
        for (const auto *frame = static_cast<const MidEntryFrame *>(::TlsGetValue(tls)); frame != nullptr;
             frame = frame->prev)
        {
            if (frame->slot == &slot)
            {
                return true;
            }
        }
        return false;
    }

    void note_contained_mid_exception(MidAdapterSlot &slot) noexcept
    {
        // The counter is exact. The log fires only on a slot's first escape, so a per-frame exception cannot flood the
        // host's hot path.
        const std::uint64_t previous = slot.contained_exceptions.fetch_add(1, std::memory_order_relaxed);
        if (previous != 0)
        {
            return;
        }
        (void)log().try_log(
            LogLevel::Error,
            "hook: a mid-hook callback at 0x{:0{}X} threw; the exception was contained at the DMK "
            "adapter "
            "boundary and the callback treated as complete. A mid-hook callback must not throw: the "
            "backend stub it returns into adjusts the stack pointer dynamically and carries no unwind "
            "data. Further escapes at this site are counted but not logged.",
            slot.target.load(std::memory_order_relaxed),
            sizeof(std::uintptr_t) * 2
        );
    }

    std::size_t claim_mid_adapter_slot() noexcept
    {
        for (std::size_t index = 0; index < MID_ADAPTER_CAPACITY; ++index)
        {
            bool expected = false;
            if (s_mid_slots[index].claimed.compare_exchange_strong(
                    expected,
                    true,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed
                ))
            {
                s_mid_slots[index].detour.store(nullptr, std::memory_order_relaxed);
                s_mid_slots[index].live.store(false, std::memory_order_relaxed);
#if defined(DMK_ENABLE_TEST_SEAMS)
                s_last_claimed_mid_slot.store(index, std::memory_order_release);
#endif
                return index;
            }
        }
        return MID_ADAPTER_CAPACITY;
    }

    void release_mid_adapter_slot(std::size_t index) noexcept
    {
        if (index >= MID_ADAPTER_CAPACITY)
        {
            return;
        }
        // This path runs only after the slot is tombstoned and drained. No thread is inside its adapter, so the
        // contents can be recycled. The slot storage itself is never reclaimed.
        s_mid_slots[index].detour.store(nullptr, std::memory_order_relaxed);
        s_mid_slots[index].claimed.store(false, std::memory_order_release);
    }

    MidRundown run_down_mid_slot(MidAdapterSlot &slot) noexcept
    {
        if (thread_is_inside_mid_adapter(slot))
        {
            // This thread can itself be the in-flight entrant. The drain below then never observes zero. The caller
            // pins instead of a wait.
            return MidRundown::Unwaitable;
        }
        return drain_until_zero(
                   [&slot]() noexcept { return slot.callbacks_in_flight.load(std::memory_order_seq_cst); },
                   std::chrono::steady_clock::now() + MID_CALLBACK_DRAIN_TIMEOUT
               )
                   ? MidRundown::Drained
                   : MidRundown::Expired;
    }

    bool drain_mid_adapter_entries(MidAdapterSlot &slot) noexcept
    {
        return drain_until_zero(
            [&slot]() noexcept { return slot.adapter_entries.load(std::memory_order_seq_cst); },
            std::chrono::steady_clock::now() + MID_ADAPTER_ENTRY_DRAIN_TIMEOUT
        );
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    std::size_t last_claimed_mid_slot_for_test() noexcept
    {
        return s_last_claimed_mid_slot.load(std::memory_order_acquire);
    }

    bool mid_slot_claimed_for_test(std::size_t index) noexcept
    {
        return index < MID_ADAPTER_CAPACITY && s_mid_slots[index].claimed.load(std::memory_order_acquire);
    }

    void adjust_mid_adapter_entries_for_test(std::size_t index, std::int32_t delta) noexcept
    {
        if (index >= MID_ADAPTER_CAPACITY)
        {
            return;
        }
        s_mid_slots[index].adapter_entries.fetch_add(static_cast<std::uint32_t>(delta), std::memory_order_seq_cst);
    }
#endif

    // The adapters instantiate here, in the object that defines their pool accessors, so each accessor call
    // resolves in this TU and inlines in Release (EmitPathHasNoEmulatedTls pins this ownership).
    constinit const std::array<safetyhook::MidHookFn, MID_ADAPTER_CAPACITY> MID_ADAPTER_TABLE =
        make_mid_adapter_table(std::make_index_sequence<MID_ADAPTER_CAPACITY>{});
} // namespace DetourModKit::detail
