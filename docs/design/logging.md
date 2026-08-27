# Logger and async logger design

This note explains the log subsystem. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-34]`, `[B-50]`, `[B-88]`.

## Concurrency model

### Logger

Async reads use an `atomic<shared_ptr>` snapshot. The snapshot takes a bounded internal lock on both toolchains and is not lock-free. See `[B-23]` in [events.md](events.md).

`shutdown_internal` and `disable_async_mode` stay safe across repeated shutdown and `enable_async_mode` cycles:

- When the writer thread detaches under loader lock, the writer's counted module reference stays outstanding.
- The `shared_ptr<AsyncLogger>` moves into a per-call permanent cell. The normal path uses `new (std::nothrow)`. The fallback path uses non-CRT permanent storage. A heap allocation failure therefore cannot drop the last handle while the writer still runs.
- If first-use construction fails under OOM, the process-default `log()` publishes an inert drop/count logger with no sink, shared sink mutex, or writer. The noexcept accessor never terminates.
- `enable_async_mode` is noexcept and fail-soft. A refused activation leaves synchronous delivery and releases the unpublished writer's retention root. A committed activation stays published. `LoggerTest.PostPublicationThrowIsContainedAndKeepsThePublishedWriter` and `LoggerTest.NonStandardThrowBeforePublicationIsContainedAndBreaksTheRoot` prove the boundary.
- `set_log_level` uses a private route that bypasses the level filter. A stricter threshold cannot hide its transition record. `LoggerTest.SetLogLevel_ChangedThresholdsEmitInfoControlRecord` proves the contract.
- `dropped_count()` aggregates facade and async drops as best-effort observability.

Hot-path mechanism: The `log()` level check costs one atomic load.

Formatted records apply one `LogSourceStampMode` policy. `always()` retains every stamp. `at_or_below(level)` retains stamps from Trace through that level. `never()` removes every stamp. The default uses `at_or_below(Debug)`, so the default Info admission produces no stamped records. The policy does not change record admission or the raw record tier. Each formatted path reads one relaxed atomic value before line format.

### AsyncLogger

The queue is a lock-free Vyukov-style MPMC queue. Shutdown has a single owner: admitted producers finish, later producers drop and count, and the writer alone drains and acknowledges completion.

A producer wakes a parked writer through the auto-reset Win32 event (`SetEvent`), never through a control-plane mutex:

- The producer publishes the queue slot, then signals only after the writer publishes `m_writer_waiting`.
- The writer parks on that event, not on a pending-count predicate. A producer preempted mid-publish therefore parks the writer for a bounded recheck instead of a spin.
- A callback-safe Drop-policy producer never blocks behind a flusher. The separate `m_flush_mutex` and condition variable serve only control-plane flushers that await a drain.
- The busy-writer wake check stays syscall-free because the producer signals only a parked writer.

Each record's output timestamp uses its enqueue time with millisecond granularity. A write batch reuses one calendar-time conversion only for consecutive records that share the same second.

Hot-path mechanism: The enqueue costs atomic sequence numbers per slot and a flag-gated writer wake.

## Rules

### [B-34]

Loop over the unwritten remainder so a buffered tail never drops silently. These outcomes apply:

- A drain that still fails keeps the unwritten tail buffered and recoverable. It does not reset the tail away.
- An explicit `close()` reports a failed drain or a `CloseHandle` failure and retains the handle for a retry.
- A reopen refuses a file whose close failed. It does not discard the file.
- Only the destructor force-closes best-effort.

See `WinFileStreamBuf` and the `WinFileStreamBufTest` drain-failure proofs.

### [B-50]

`AsyncLogger`'s writer owns a private timestamp format and a shared sink. `Logger::reconfigure` must update each changed worker field. Use `AsyncLogger::set_timestamp_format` for the format. Use `AsyncLogger::set_file_stream` for the sink. Otherwise async lines retain stale format or use a retired stream.

Both setters assign without a lock. The caller must hold the shared log mutex. The writer reads both fields under that mutex. `reconfigure` holds the mutex through `scoped_lock`. A setter that acquires the same non-recursive mutex deadlocks.

Mutate only those two fields. Each field has a distinct address, and the writer reads both under the shared log mutex. Do not touch other live-worker fields because the worker reads them without a lock. A rejection of the change is a capability regression.

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
