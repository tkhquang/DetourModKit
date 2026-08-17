# Event dispatcher and profiler design

This note explains event delivery and profiling. Rulebook entries with the same `[B-nn]` IDs live in
[AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-23]`, `[B-46]`, `[B-70]`, `[B-87]`.

## Concurrency model

### EventDispatcher

`emit()` and `emit_safe()` read an acquire-loaded copy-on-write snapshot without a DMK mutex. The bounded STL lock
remains, and the zero-subscriber path skips that load. Each entry owns a tombstone and in-flight gate for retirement,
invocation, and drain. `tombstone_and_wait()` closes the dispatcher before the drain, and writers follow `[B-101]`. A
reserved Win32 TLS index records each thread's emit chain, while an unrecordable frame returns `Unwaitable`. `emit()`
propagates handler exceptions, while `emit_safe()` catches them and continues.

Hot-path mechanism: Each live entry costs one snapshot load, linear iteration, and one atomic gate pass. The path has
no reader lock or successful-path allocation.

### Profiler

The profiler records into a lock-free ring buffer (`detail::ProfileRing`):

- A writer takes the next position with `fetch_add`, then claims its slot with one CAS on a publication word. The
  word packs that position as a ticket beside a busy bit.
- A claim on a slot that another writer still owns, or that a later ticket already committed, is refused and counted
  through `dropped_samples()`. It never overwrites the slot, so slot reuse after a full ring cycle cannot leave a
  torn payload.
- The ticket strictly increases per slot, so the cold export path is exact. The export loads the word, copies the
  fields, re-loads behind an acquire fence, and drops the sample if the word changed or is odd.
- Ticks convert to microseconds through a saturating quotient/remainder split. The split neither overflows nor takes
  an undefined signed difference.
- `DMK_PROFILE_SCOPE(name)` requires `name` to be a string literal. A `ScopedProfile` constructor that binds only to
  `const char (&)[N]` enforces that at compile time.

Hot-path mechanism: One sample costs one `fetch_add`, one CAS, and the field writes.

## Rules

### [B-23]

`std::atomic<std::shared_ptr<T>>` is NOT lock-free on either shipped toolchain. libstdc++ (MinGW) and the MSVC STL
both back it with an internal lock, and `EventDispatcherTest.AtomicSharedPtrIsNotLockFree` pins that observed
contract. A `Hook::call` gate, an async-logger writer snapshot, or an `EventDispatcher` emit that reads such an atomic
therefore takes one bounded internal critical section per read. That read is callback-safe. Document it as bounded,
never as lock-free or wait-free.

The genuinely wait-free reads are the plain `atomic<integer>` loads: the log-level check, the async-enabled flag, and
the zero-subscriber emit fast path. A raw function-pointer call through a pinned trampoline is also lock-free, but the
pin that produced it is not.

### [B-46]

An RAII unsubscribe retires its handler synchronously with a preallocated-tombstone store. It never rebuilds the
published list. The handler therefore cannot fire on a later emit, and the removal cannot fail for want of an
allocation. Physical compaction of the freed slot is a separate best-effort step under the writer mutex. A deferred
container rebuild cannot retract a snapshot that an in-flight emit already holds. Only the invocation-site liveness
check retires that handler. See `[B-87]`.

### [B-70]

`EventDispatcher::Subscription::reset()` checks that the dispatcher's `m_alive` weak_ptr expired. It then calls into
the dispatcher as a separate step. That two-step check makes `reset()` safe after an ordered (happens-before)
`~EventDispatcher`: the token reads expired and `reset()` no-ops. That is the supported teardown path.

The check does not make `reset()` safe against a `~EventDispatcher` that races on another thread between the check and
the call. The separate `make_shared` token cannot close that gap, because a held token does not keep the dispatcher
alive. The dispatcher must outlive every concurrent Subscription operation.

Where a weak_ptr guards teardown, the doc must scope the guarantee to ordered teardown. It must not advertise blanket
cross-thread safety that the two-step check cannot deliver. A test that resets a subscription after the dispatcher's
scope closes backs the ordered case, which is the only case the guard makes safe.

### [B-87]

A subscriber, callback, or handler retires through a preallocated tombstone flip, never through a rebuild of the
container that holds it. Allocate the control block at registration, on the control-plane path that is allowed to
fail. The removal path then has nothing left to fail at. Physical compaction can then be deferred, retried, or
skipped, because a tombstoned entry that is still in the list is inert.

A removal that must allocate has no bottom to its retry chain:

- The destructor is the last retry. It re-runs the same allocating code under the memory pressure that caused the
  failure.
- The destructor is `noexcept` with no return channel and no successor, so its failure is silent and permanent.
- The owner then destroys captures that the entry can still reach.

Do not defer logical death to a later drain either. The drain still retires through a container rebuild, and a rebuild
can never retract a snapshot that a reader already captured. Only a liveness check at the invocation site can. That
check makes the tombstone load-bearing rather than an optimization.
