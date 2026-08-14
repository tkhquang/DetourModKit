# Logger and async logger design

This note explains the log subsystem. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

## Concurrency model

### Logger

`atomic<shared_ptr>` snapshot for async reads (a bounded internal lock on both toolchains, not lock-free; see `[B-23]` in [events.md](events.md)); `shutdown_internal` and `disable_async_mode` are safe across repeated shutdown / enable_async_mode cycles: when the writer thread has to be detached under loader lock, the writer's counted module reference is left outstanding and the `shared_ptr<AsyncLogger>` is moved into a per-call permanent cell (normal path: `new (std::nothrow)`; fallback path: non-CRT permanent storage), so a heap allocation failure cannot drop the last handle while the writer may still be running; the process-default `log()` publishes an inert drop/count logger (no sink, shared sink mutex, or writer) when first-use construction fails under OOM, so the noexcept accessor never terminates, and `dropped_count()` aggregates facade and async drops as best-effort observability

Hot-path mechanism: Single atomic load on log level check

### AsyncLogger

Lock-free MPMC queue (Vyukov-style); single-owner shutdown in which admitted producers finish, later producers drop/count, and the writer alone drains and acknowledges completion; a producer wakes a parked writer by signalling an auto-reset Win32 event (`SetEvent`), never a control-plane mutex: the producer publishes the queue slot then signals only when the writer has published `m_writer_waiting`, and the writer parks on that event rather than on a pending-count predicate, so a producer preempted mid-publish parks the writer for a bounded recheck instead of spinning it and a callback-safe Drop-policy producer never blocks behind a flusher (the separate `m_flush_mutex`/condition variable serve only control-plane flushers awaiting a drain). The busy-writer wake check stays syscall-free because the producer signals only a parked writer. Each record's output timestamp uses its enqueue time with millisecond granularity. A write batch reuses one calendar-time conversion only for consecutive records that share the same second.

Hot-path mechanism: Atomic sequence numbers per slot; flag-gated writer wakeup

## Rules

### [B-34]

Loop over the unwritten remainder so a buffered tail is never silently dropped. A drain that still fails keeps the unwritten tail buffered and recoverable rather than resetting it away, an explicit `close()` reports a failed drain or `CloseHandle` and retains the handle for a retry, and a reopen refuses rather than discards a file it could not close; only the destructor force-closes best-effort (see `WinFileStreamBuf` and the `WinFileStreamBufTest` drain-failure proofs).

### [B-50]

`AsyncLogger`'s writer copies the timestamp format into its private `m_config` at construction, so a `Logger::reconfigure` that changes the format must push the new value into the live writer (`AsyncLogger::set_timestamp_format`), or async lines keep the old format for the life of the writer while sync banner lines use the new one -- in the same file. The setter assigns WITHOUT taking a lock: its precondition is that the caller already holds the shared log mutex the writer reads that field under (`reconfigure` holds it via `scoped_lock`), so a self-locking setter would deadlock against that same non-recursive mutex. Mutate only the one field (distinct memory location); other snapshot fields read locklessly on the worker thread must not be touched on a live worker. Rejecting the change instead would be a capability regression.

### [B-88]


- Treat only an inline DropNewest producer path as callback-safe.
- Keep async-mode transitions outside a facade log call on that path.
- Signal a parked writer through the auto-reset Win32 wake event.
- Never acquire the flush mutex from that producer path.
- Gate `SetEvent` on the writer's published parked flag.
- Keep the active-writer hot path free of wake syscalls.
- Reserve the flush mutex and condition variable for control-plane flushers.
- If a producer stops after its message count increment, keep the writer parked for a bounded recheck.
- Never spin on a count predicate that returns immediately.
- Prove producer completion under a held flush mutex.
- Prove a bounded idle park count.
