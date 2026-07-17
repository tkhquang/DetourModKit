/**
 * @file event_dispatcher.cpp
 * @brief The dispatcher's per-thread emit chain and rundown drain.
 *
 * EventDispatcher is otherwise a header-only template. What lives here is the part that cannot: the emit chain is
 * backed by a Win32 TLS index, and the installed detail/ header must stay Win32-free.
 */

#include "DetourModKit/detail/event_dispatcher.hpp"

#include "platform.hpp"

#include <atomic>
#include <mutex>
#include <thread>

namespace DetourModKit::detail
{
    namespace
    {
        /**
         * @brief The TLS index holding this thread's EmitFrame chain head.
         * @details Reserved by subscribe() before any emit of a subscribed dispatcher can run, so a dispatcher with
         *          subscribers always has a valid index. TLS_OUT_OF_INDEXES means the process had none to give, which
         *          leaves every emit untracked and every rundown Unwaitable rather than wrong.
         */
        std::atomic<DWORD> s_emit_tls_index{TLS_OUT_OF_INDEXES};

        /// Serializes the one-time reservation. Control-plane only; no emit path reaches it.
        std::mutex s_emit_tls_mutex;

        std::atomic<std::uint32_t> s_untracked_emit_frames{0};
    } // namespace

    bool ensure_emit_frame_tls() noexcept
    {
        if (s_emit_tls_index.load(std::memory_order_acquire) != TLS_OUT_OF_INDEXES)
        {
            return true;
        }

        try
        {
            std::scoped_lock lock{s_emit_tls_mutex};
            if (s_emit_tls_index.load(std::memory_order_relaxed) != TLS_OUT_OF_INDEXES)
            {
                return true;
            }
            const DWORD index = ::TlsAlloc();
            if (index == TLS_OUT_OF_INDEXES)
            {
                return false;
            }
            s_emit_tls_index.store(index, std::memory_order_release);
            return true;
        }
        catch (...)
        {
            // A lock failure here costs tracking, not correctness: the index stays unreserved and every rundown
            // refuses to wait.
            return false;
        }
    }

    bool push_emit_frame(EmitFrame &frame) noexcept
    {
        const DWORD index = s_emit_tls_index.load(std::memory_order_acquire);
        if (index == TLS_OUT_OF_INDEXES)
        {
            return false;
        }
        frame.prev = static_cast<EmitFrame *>(::TlsGetValue(index));
        // A store can still fail: an index past the TEB's inline slots is backed by a lazily heap-allocated
        // expansion array. Report it rather than leave the chain claiming this thread is elsewhere.
        return ::TlsSetValue(index, &frame) != FALSE;
    }

    void pop_emit_frame(const EmitFrame &frame) noexcept
    {
        const DWORD index = s_emit_tls_index.load(std::memory_order_acquire);
        if (index == TLS_OUT_OF_INDEXES)
        {
            return;
        }
        // The matching push succeeded, so the expansion array for this index already exists on this thread and this
        // store cannot fail for want of one.
        (void)::TlsSetValue(index, frame.prev);
    }

    bool thread_is_emitting_dispatcher(const void *dispatcher) noexcept
    {
        const DWORD index = s_emit_tls_index.load(std::memory_order_acquire);
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
        const DWORD index = s_emit_tls_index.load(std::memory_order_acquire);
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
        if (thread_is_emitting_dispatcher(dispatcher) ||
            s_untracked_emit_frames.load(std::memory_order_seq_cst) != 0)
        {
            return Rundown::Unwaitable;
        }

        // The tombstone is already published (seq_cst) by the caller, and every invocation increments in_flight
        // seq_cst before rechecking it. Those two orders are the Dekker seam: an entrant that misses the tombstone
        // is guaranteed visible here, so reaching zero means no invocation remains and none can start.
        //
        // No timeout: the set being waited on is closed the moment the tombstone lands, and a wait that gives up has
        // not drained anything. The self-entrant and untracked cases that could make this unbounded are refused
        // above rather than papered over with a deadline.
        while (gate.in_flight.load(std::memory_order_seq_cst) != 0)
        {
            std::this_thread::yield();
        }
        return Rundown::Drained;
    }
} // namespace DetourModKit::detail
