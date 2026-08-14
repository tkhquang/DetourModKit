# Event dispatcher and profiler design

This note explains event delivery and profiling. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

## Concurrency model

### EventDispatcher

`emit()` and `emit_safe()` read an acquire-loaded copy-on-write snapshot without a DMK mutex. The bounded STL lock remains, and the zero-subscriber path skips that load. Each entry owns a tombstone and in-flight gate for retirement, invocation, and drain. `tombstone_and_wait()` closes the dispatcher before the drain, and writers follow `[B-101]`. A reserved Win32 TLS index records each thread's emit chain, while an unrecordable frame returns `Unwaitable`. `emit()` propagates handler exceptions, while `emit_safe()` catches them and continues.

Hot-path mechanism: Each live entry costs one snapshot load, linear iteration, and one atomic gate pass. The path has no reader lock or successful-path allocation.

### Profiler

Lock-free ring buffer (`detail::ProfileRing`): a writer takes the next position with `fetch_add`, then claims its slot with one CAS on a publication word that packs that position as a ticket beside a busy bit. A claim that would take a slot another writer still owns, or one a later ticket already committed, is refused and counted (`dropped_samples()`) instead of overwriting it, so slot reuse after a full ring cycle cannot leave a torn payload. Because the ticket strictly increases per slot, the cold export path is exact: load the word, copy the fields, re-load behind an acquire fence, and drop the sample if the word changed or is odd. Ticks convert to microseconds through a saturating quotient/remainder split that neither overflows nor takes an undefined signed difference. `DMK_PROFILE_SCOPE(name)` requires `name` to be a string literal, enforced at compile time by a `ScopedProfile` constructor that only binds to `const char (&)[N]`

Hot-path mechanism: One `fetch_add` + one CAS + field writes per sample

## Rules

### [B-23]

`std::atomic<std::shared_ptr<T>>` is NOT lock-free on either shipped toolchain: libstdc++ (MinGW) and the MSVC STL both back it with an internal lock, and `EventDispatcherTest.AtomicSharedPtrIsNotLockFree` pins that observed contract. A `Hook::call` gate, an async-logger writer snapshot, or an `EventDispatcher` emit that reads such an atomic therefore takes one bounded internal critical section per read -- callback-safe, but document it as bounded, never as lock-free or wait-free. The genuinely wait-free reads are the plain `atomic<integer>` loads (the log-level check, the async-enabled flag, the zero-subscriber emit fast path); a raw function-pointer call through a pinned trampoline is also lock-free, but the pin that produced it is not.

### [B-46]

An RAII unsubscribe retires its handler synchronously with a preallocated-tombstone store, never by rebuilding the published list, so the handler cannot fire on a later emit and the removal cannot fail for want of an allocation. Physical compaction of the freed slot is a separate best-effort step under the writer mutex. A deferred container rebuild cannot retract a snapshot that an in-flight emit already holds. Only the invocation-site liveness check retires that handler. See `[B-87]`.

### [B-70]

`EventDispatcher::Subscription::reset()` checks the dispatcher's `m_alive` weak_ptr expired and then, as a separate step, calls into the dispatcher. That makes reset() safe after an ordered (happens-before) `~EventDispatcher` -- the token is observed expired and reset() no-ops, the supported teardown path -- but it does not make reset() safe against a `~EventDispatcher` racing on another thread between the check and the call, and the separate `make_shared` token cannot close that gap (holding it alive would not keep the dispatcher alive). The caller must keep the dispatcher outliving every concurrent Subscription operation. Where a weak_ptr guards teardown, the doc must scope the guarantee to ordered teardown and not advertise blanket cross-thread safety the two-step check cannot deliver, backed by a test that resets a subscription after the dispatcher's scope has closed (the ordered case), which is the only case the guard makes safe.

### [B-87]

A subscriber, callback, or handler is retired by flipping a preallocated tombstone, never by rebuilding the container that holds it: allocate the control block when the registration is made, on the control-plane path that is allowed to fail, and leave the removal path with nothing left to fail at. Physical compaction may then be deferred, retried, or skipped, because a tombstoned entry that is still in the list is inert. A removal that must allocate has no bottom to its retry chain -- the destructor is the last retry, it re-runs the same allocating code under the same memory pressure that just failed, and it is `noexcept` with no return channel and no successor -- so its failure is silent and permanent, and the owner then destroys captures the entry can still reach. Do not defer logical death to a later drain either: the deferral only moves when the container is rebuilt, and a container rebuild can never retract a snapshot a reader already captured. Only a liveness check consulted at the invocation site can, which is what makes the tombstone load-bearing rather than an optimization.
