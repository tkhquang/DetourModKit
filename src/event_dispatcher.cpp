/**
 * @file event_dispatcher.cpp
 * @brief The dispatcher's per-thread emit chain and rundown drain.
 *
 * EventDispatcher is otherwise a header-only template. What lives here is the part that cannot: the emit chain is
 * backed by a Win32 TLS index, and the installed detail/ header must stay Win32-free.
 */

#include "DetourModKit/detail/event_dispatcher.hpp"

#include "internal/drain_backoff.hpp"
#include "internal/shared_tls_index.hpp"
#include "platform.hpp"

#include <atomic>
#include <cstdint>
#include <thread>

namespace DetourModKit::detail
{
    namespace
    {
        static_assert(sizeof(DWORD) == sizeof(std::uint32_t));

        /// The TLS index that holds this thread's EmitFrame chain head. Each dispatcher with a publish owns it.
        constinit SharedTlsIndex s_emit_tls;

        std::atomic<std::uint32_t> s_untracked_emit_frames{0};
    } // namespace

    void acquire_emit_frame_owner() noexcept
    {
        (void)s_emit_tls.acquire();
    }

    void release_emit_frame_owner() noexcept
    {
        s_emit_tls.release();
    }

    bool push_emit_frame(EmitFrame &frame) noexcept
    {
        const DWORD index = s_emit_tls.index();
        if (index == TLS_OUT_OF_INDEXES)
        {
            return false;
        }
        frame.tls_index = index;
        frame.prev = static_cast<EmitFrame *>(::TlsGetValue(index));
        // A store can still fail: an index past the TEB's inline slots is backed by a lazily heap-allocated
        // expansion array. Report it rather than leave the chain claiming this thread is elsewhere.
        return ::TlsSetValue(index, &frame) != FALSE;
    }

    void pop_emit_frame(const EmitFrame &frame) noexcept
    {
        // The matching push succeeded, so the expansion array for this index already exists on this thread and this
        // store cannot fail for want of one. A dispatcher destroyed after a Drained rundown can return the index while
        // an emit that pushed under it unwinds. The recorded index then restores only this thread's own slot.
        (void)::TlsSetValue(frame.tls_index, frame.prev);
    }

    bool thread_is_emitting_dispatcher(const void *dispatcher) noexcept
    {
        const DWORD index = s_emit_tls.index();
        if (index == TLS_OUT_OF_INDEXES)
        {
            return false;
        }
        for (const auto *node = static_cast<const EmitFrame *>(::TlsGetValue(index)); node != nullptr;
             node = node->prev)
        {
            if (node->dispatcher == dispatcher)
            {
                return true;
            }
        }
        return false;
    }

    bool thread_is_emitting_type(const void *type_tag) noexcept
    {
        const DWORD index = s_emit_tls.index();
        if (index == TLS_OUT_OF_INDEXES)
        {
            return false;
        }
        for (const auto *node = static_cast<const EmitFrame *>(::TlsGetValue(index)); node != nullptr;
             node = node->prev)
        {
            if (node->type_tag == type_tag)
            {
                return true;
            }
        }
        return false;
    }

    std::atomic<std::uint32_t> &untracked_emit_frames() noexcept
    {
        return s_untracked_emit_frames;
    }

    Rundown drain_gate(EntryGate &gate, const void *dispatcher) noexcept
    {
        if (thread_is_emitting_dispatcher(dispatcher) || s_untracked_emit_frames.load(std::memory_order_seq_cst) != 0)
        {
            return Rundown::Unwaitable;
        }

        // The tombstone is already published (seq_cst) by the caller, and every invocation increments in_flight
        // seq_cst before rechecking it. Those two orders are the Dekker seam: an entrant that misses the tombstone
        // is guaranteed visible here, so reaching zero means no invocation remains and none can start.
        //
        // This wait has no timeout. The tombstone closes the entrant set, so it cannot grow. A tracked handler can
        // still remain parked indefinitely. Self-entry deadlocks, and an untracked entry makes completion
        // unprovable, so both cases are refused above. Backoff limits CPU use while a tracked handler finishes.
        DrainBackoff backoff;
        while (gate.in_flight.load(std::memory_order_seq_cst) != 0)
        {
            backoff.pause();
        }
        return Rundown::Drained;
    }
} // namespace DetourModKit::detail
