# Memory access and scanning design

This note explains memory access and scans. Rulebook entries with the same `[B-nn]` IDs live in
[AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-05]`, `[B-17]`, `[B-18]`, `[B-19]`, `[B-20]`, `[B-21]`.

## Concurrency model

### Memory cache

One `Stopped/Starting/Running/Stopping` state machine serializes normal init/shutdown and publishes `Running` last.
Loader-lock teardown atomically unpublishes and retains reachable state without a wait. Later off-loader-lock setup or
shutdown drains it. Shards use inline `SrwSharedMutex`, leader coalescing, striped reader counts, per-shard
statistics, and a content generation. Clear and invalidation advance that generation when an in-flight leader or lock
contention prevents physical eviction, so stale entries cannot become later hits. Eviction is insertion/refresh FIFO,
not hit-order LRU.

`memory::is_readable_nonblocking` uses a shared try-lock and cache lookup. It returns `Unknown` after contention, a
cache miss, or the init publication window. Before `init_cache()`, it uses the synchronous `VirtualQuery` range walk.

`memory::walk` resolves a pointer chain in one walk. It issues one guarded read for each intermediate hop. It screens
each dereferenced link against that hop's `min_valid` floor and the user-mode ceiling. A failed link reports its hop
index in `Error::detail`. The MinGW path guards every link through the vectored handler.

Hot-path mechanism: Each cached query costs a shared shard lock, a striped reader increment, a per-shard statistic
increment, and a content-generation load.

## Memory access in hook callbacks

Do not add `memory::is_readable()` or `memory::is_writable()` before every field read in hook callbacks. Use those
predicates for setup validation and diagnostics. Select the primitive by task:

- Use `memory::walk` for unstable live game pointers. Use `memory::unchecked::read` only when the caller can prove
  that the pointer chain is live for the current frame.
- For per-frame WRITES through a resolved address or pointer chain, use `memory::write_in_place` (or `memory::walk`
  then `write_in_place` at a chain's leaf). It changes no protection and fails closed if the target is not already
  writable. A drifted pointer is therefore rejected rather than a silent mutation of a read-only page.
- Reach for the escalating `memory::write<T>` / `write_bytes`, which auto-unprotect on a fault, for a data write to a
  page that can be protected.
- Use `memory::patch_code` for a one-shot CODE patch. It derives writable protection without an execute bit added to a
  data page. It checks an instruction-cache flush on every path that can modify the target, an already-writable page
  and a partially changed prefix included.
- A single foreign byte read as a `bool` uses `memory::read_bool`. The raw `memory::read<bool>` is ill-formed, since
  an arbitrary byte is not a valid `bool` representation.
- Hold a `memory::ProtectGuard` to write a protected page repeatedly.

The typed reads participate over an explicit allowlist, not over every scalar:

- integrals except `bool`,
- padding-free binary floats (so MinGW's 16-byte x87 `long double` is out),
- fixed-underlying enums over an accepted integer,
- object and function pointers under the Windows x64 ABI,
- `Address`,
- bounded arrays of accepted elements,
- aggregates opted in through `detail::enable_representation_safe_aggregate`.

A top-level built-in array returns as the equivalent nested `std::array`. `std::nullptr_t`, both member-pointer
forms, an unbounded array, and an unscoped enum with no fixed base are compile errors. Copy their bytes with
`memory::read_into` instead. `tests/test_memory_representation.cpp` is the participation matrix, and the migration
guide restates the domain for consumers.

The full pattern (worked examples, the primitive selection table, and the anti-patterns to remove) lives in
[hot-path-memory.md](../guides/memory/hot-path-memory.md).

## Scanning process memory

The raw `scan::unchecked::find_pattern(region, pattern, occurrence)` does no page filtering. It reads the whole span
with `memchr` /SIMD, so the caller must guarantee that every byte of `region` is committed and readable, or the host
faults. Use it only on byte buffers or module sections whose readability is already known.

To scan arbitrary process or module memory, prefer the page-filtered `scan::scan(pattern, scope, occurrence, pages)`.
Its engine sweep is `detail::scan_module_pages`, which selects `scan_module_readable` or `scan_module_executable` by
`Pages`. The sweep walks `VirtualQuery` and skips guard, no-access, and non-readable pages.

The per-region `VirtualQuery` gate proves readability only at gate time. On MSVC, each region read additionally runs
inside a structured-exception guard. A region decommitted or reprotected concurrently between the gate and the read is
skipped and counted at `Debug`, not a host fault. On MinGW x64, the bulk `detail::find_pattern_raw` reads run through
the same process-wide vectored fault guard that the `memory::read` copy primitives use. `scan_region_guarded` routes
the per-region sweep through `detail::run_guarded_region`. A region reprotected or decommitted in that TOCTOU window
is skipped and counted, which matches the MSVC behavior. The same guard wraps the per-window reads behind
`find_string_xref`. The global architecture gate in `defines.hpp` rejects a 32-bit build, so guarded scanner code
carries only the MSVC SEH and MinGW x64 VEH arms.

## ASan and foreign reads

The AOB scanner and the SEH-guarded probe deliberately read arbitrary mapped process memory. ASan reports that as
false-positive overflows when it scans this process's own poisoned shadow. The AOB prefilter routes through a
self-provided `dmk_memchr` in all builds, which is immune to libc interceptors by construction. The only ASan-specific
treatment that remains is the `no_sanitize_address` attribute and the `__movsb` copy path under
`#if defined(__SANITIZE_ADDRESS__)`. See [asan-memory-scanner.md](../guides/memory/asan-memory-scanner.md) for the
mechanism and the pattern for any new foreign-memory primitive.

## Guarded primitive mechanisms

### memory::unchecked::read

`memory::unchecked::read<std::uintptr_t>(addr)` is the raw validation-free fast path: a single inlined `memcpy` into
stack storage followed by `std::bit_cast`. It has no SEH, no `VirtualQuery`, no cache lookup, and no range guard of
any kind: no low-address floor, no `USERSPACE_PTR_MAX` ceiling. The caller must prove in advance that every byte of
`[addr, addr + sizeof(T))` is committed and readable. A debug-only `assert(is_readable(...))` trips a violated
precondition at the offending call site but compiles out under `NDEBUG`. A release build is therefore a bare copy
that faults the host on an invalid address, exactly as documented. Reach for the guarded `memory::read` when the
pointer can be stale.

### memory::read / read_into

`memory::read<T>()` and `read_into()` are the typed and raw guarded reads:

- MSVC guards with a single `__try` frame. MinGW runs a single `rep movsb` copy under a process-wide vectored
  exception handler, installed lazily or by `init_cache` and removed by `shutdown_cache`. The handler recovers
  through a non-unwinding `__builtin_setjmp` / `__builtin_longjmp`, so the success path runs no syscall.
- Both toolchains swallow the same foreign-read fault set through the shared predicate `detail::is_guarded_read_fault`
  : `EXCEPTION_ACCESS_VIOLATION`, `STATUS_GUARD_PAGE_VIOLATION`, and `EXCEPTION_IN_PAGE_ERROR`. The last is a
  file-backed or image-mapped page that fails to page in, for example during an RTTI or section walk. Any other fault
  continues the handler search. An access-class fault is claimed only when its address lies in the declared foreign
  range.
- A claimed guard-page fault re-arms the `PAGE_GUARD` bit that the OS consumed on dispatch (
  `rearm_guard_page_if_consumed`) before the read fails closed. A read of a foreign guard page therefore cannot
  disarm the host's fence and let a retry through it.
- A guarded access publishes its foreign range to one per-thread slot and SAVES the enclosing value rather than a
  clear, so guarded accesses can nest. A nested read restores the outer range on the way out, and the enclosing span
  stays armed for the rest of the outer access. The same claimed fault set and guard-page re-arm apply at either
  depth. `FaultContainment.GuardedRegionStaysArmedAcrossANestedGuardedRead` pins that on both toolchains.
- If `AddVectoredExceptionHandler` ever fails, the byte-copy reads fall back to `VirtualQuery` plus
  `ReadProcessMemory`, while bulk region scans fail closed.

`rtti` uses these reads for chained RTTI walks.

### memory::write_in_place / write / patch_code

`memory::write_in_place<T>()` is the guarded per-frame WRITE to game memory (a camera transform, a player field). It
changes no protection and fails closed (`WriteFaulted`) if the target is not already writable. `memory::write<T>()`
and `write_bytes()` are the escalating counterpart: they auto-unprotect on a fault, so a write to a read-only page
succeeds. That serves a one-shot code patch. Hold a `memory::ProtectGuard` for repeated writes to a protected page.
MSVC guards with one `__try` frame, and MinGW x64 guards with the vectored-handler copy path plus a fallback through
`VirtualQuery` and `WriteProcessMemory`. Both return `Result<void>`, so a stale address fails closed instead of a
host fault.

## Rules

### [B-05]

A direct-lookup cache hits only when the key computed on read equals the key that the entry was stored under. The
protection cache stores an entry by its VirtualQuery region base, but a read derives the query's page base. The direct
`unordered_map` probe therefore hits only for an address in a region's first page. A deeper-page query misses that
probe. When the region is already cached in the same shard, the O(log n) containment search over that shard's
`sorted_ranges` serves it. Otherwise it misses entirely, and the caller re-queries through `VirtualQuery` and seeds
that shard (see `find_in_shard` and `check_memory_permission`). When you add or change a keyed cache, keep the two
key derivations equal. Otherwise document the fallback as the real path instead of an advertised O(1) fast path.

### [B-17]

The two obligations have separate triggers and must not collapse into one:

- Every path that possibly modified executed bytes owes an instruction-cache flush. That includes an already-writable
  code patch that changes no protection (`memory::patch_code`'s fast path) and a prefix that a guarded copy possibly
  wrote before it faulted. When portable copy order cannot reveal the exact prefix, flush the full validated request.
- Protection-query cache invalidation (`memory::invalidate_range`) is owed only by a path that CHANGED or RESTORED
  protection. Only that can leave a cached `is_readable` / `is_writable` snapshot stale. A flush-only fast path
  invalidates nothing. A protection-changing path invalidates on every exit, even one whose change failed and was
  rolled back.

Preserve truthful failure precedence: restoration failure outranks a partial write, and a partial write outranks a
flush-only failure. A later retry that writes nothing does not erase or downgrade an earlier possibly-written prefix.

### [B-18]

`VirtualProtect` over a multi-region span reports only the first page's prior protection. A `write_bytes` escalation
or a `ProtectGuard` that straddles a `.rdata` / `.text` boundary then restores the executable region to
`PAGE_READONLY`. The region access-violates under DEP on its next execution. Even a two-byte write can straddle two
regions. Change and restore the span one VirtualQuery region at a time, each with its own captured prior protection.
Fail closed if it crosses more distinct regions than the tracker holds. `detail::protect_across_regions` /
`restore_across_regions` implement this, used by both `patch_bytes` and `ProtectGuard`.

### [B-19]

`VirtualQuery` describes only the region that contains its argument. An `is_readable` / `is_writable` over a span that
crosses a re-protected interior page otherwise fails closed at the first region's end. It does so even when every byte
is committed and permitted. That page shape is one reservation split into several `MEMORY_BASIC_INFORMATION` regions.
That false NotReadable makes a caller skip a valid read.

Walk every region that the range touches. Require each to be committed and to satisfy the permission predicate with no
unmapped gap, and fail closed on the first that is not. `range_permission_uncached` does this, used by
`check_memory_permission`'s cold-cache and miss paths and by `is_readable_nonblocking`'s no-cache path. The miss
path caches the first region, then walks the tail. The cache-hit path is exempt because it already requires a single
cached region to cover the span fully. A spanning range therefore always falls to the walk. This is the read-side
companion to the protection-restore rule above.

### [B-20]

The OS clears `PAGE_GUARD` before it dispatches `STATUS_GUARD_PAGE_VIOLATION`. A guarded read of a foreign guard page
(another thread's stack guard) that merely fails closed therefore permanently disarms the host's fence. An immediate
retry then reads straight through it. Re-arm the guard (`VirtualProtect(page, prot | PAGE_GUARD, ...)`) on a claimed
guard-page fault before the failure report.

This must hold for EVERY frame-based guarded foreign read. Both the memory engine's read/write/chain paths and the
scanner's region/window sweeps route their MSVC `__except` through the shared `detail::guarded_range_fault_filter`
with the exact declared foreign span. The filter is declared in `memory_fault.hpp` beside the `is_guarded_read_fault`
fault set, and the MinGW vectored handler calls `rearm_guard_page_if_consumed` on the same path. A bare
`is_guarded_read_fault(GetExceptionCode())` predicate at a `__except` swallows the fault WITHOUT the re-arm. That is
the fail-open to avoid. The read still fails closed. The fence survives, so the host's next access re-faults as
intended.

### [B-21]

A non-owning view is trivially copyable. A mutable `std::span<std::byte>`, or any other view such as `std::span<int>`
or `std::string_view`, therefore exact-matches the typed template. The call bit-copies the view object (data pointer
plus length) into the target instead of the bytes it references. That is silent memory corruption from a natural
`write_in_place(addr, my_view)` call. An exclusion of byte spans alone is not enough. Every view is bit-copied
identically.

Constrain the typed form with `!detail::is_non_owning_view_v<std::remove_cvref_t<T>>`, true for any
`std::span<U, Extent>` and any `std::basic_string_view`. A byte span then routes to the byte-span overload (
`write_in_place(span)`). A non-byte span or string_view, which has no sink, is a deliberate compile error rather than
a scalar bit-copy. `write`, which has no view sink at all, rejects every view. Inspect `std::remove_cvref_t<T>` at
the constraint site so an explicit cv/ref-qualified argument type cannot slip past the bare trait. Add a
compile-and-run test whenever a `T` -taking and a view-taking overload coexist.
