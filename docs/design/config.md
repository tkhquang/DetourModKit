# Config subsystem design

This note explains the config subsystem. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-36]`, `[B-37]`, `[B-38]`, `[B-79]`, `[B-80]`.

## Concurrency model

### config

Registration takes a `mutex`. Setter callbacks run after that lock releases and can re-enter data-plane config calls. A separate pass lock serializes load and reload and refuses unsafe control-plane re-entry.

Reload semantics:

- `reload()` re-runs the registered items against the stashed INI path with the same deferred pattern.
- A reload skips only when the FNV-1a 64 hash of the on-disk bytes matches AND the binding generation is unchanged. A bind registered after a load therefore still hydrates from disk on the next reload, even when the bytes are unchanged.
- A reload whose read, seek/tell, or parse fails returns before the setter pass. Bound values are then genuinely retained, not snapped to their registered defaults.
- Only a fully applied pass publishes a hash/generation snapshot. A failed parse, or a pass whose setters threw, leaves nothing to skip against, so an identical-byte retry re-applies.
- The INI path is remembered on every load outcome, success or failure. A first run with no file on disk yet can therefore still `enable_auto_reload` against the parent directory.
- Bytes are read once per load or reload and fed to `CSimpleIniA::LoadData`. The cached hash and the parsed INI state therefore reflect the same file snapshot, with no TOCTOU between hash and parse.

Parse semantics:

- Scalar binds parse locale-independently with `std::from_chars`, never `strtod` or `strtol`. A comma-decimal host therefore does not silently snap a fractional value to its default.
- A non-finite float (inf/nan) or a malformed boolean is rejected to the registered default with a diagnostic. It is never stored and never silently defaulted.
- A bound setter that re-enters `load()` or `reload()` on the pass-holding thread is refused. The call logs and returns false instead of a self-deadlock on the non-reentrant apply lock.
- All setters must be reentrant and thread-safe.

Worker topology:

- `enable_auto_reload()` owns the internal `detail::ConfigWatcher` (`src/internal/config_watcher.hpp`) behind a separate `std::mutex`, so start/stop transitions do not contend with registration traffic.
- Setters that the watcher invokes run on the watcher thread. Setters that the reload hotkey invokes run on a dedicated `ReloadServicer` thread, lazily started on the first `reload_hotkey` and torn down in `clear()`. The `input::Input` poll thread therefore never blocks on INI parsing.

`ReloadServicer` teardown:

- Every field that the servicer thread touches (its mutex, its condition variable, its pending/shutdown flags, and its owned `StoppableWorker`) lives in a heap-owned `Channel`. `~ReloadServicer` under the loader lock can therefore leak the whole `Channel`. The alternative destroys the mutex and condition variable out from under the detached `service_loop`, which keeps a raw `Channel*`.
- The authorized arm retires the worker first. It retains the `Channel` on the same terms whenever the body did not yet publish its exit. `StoppableWorker::shutdown()` re-queries the process-global veto for itself, so an arm entered as a join can still finish as a detach.
- Off the loader lock, a servicer torn down from its own worker thread hands the `Channel` to the off-thread reaper ( `src/internal/lifecycle_reaper.hpp`). The self-teardown case is a setter that calls `clear()`. The reaper joins the worker after its body returns and then destroys the `Channel`. That self-retirement neither self-joins nor leaks permanently, and it mirrors `~ConfigWatcher`.
- The press-request path takes the `Channel` mutex around the predicate store before `cv.notify_one` to close the lost-wakeup window.

Watcher mechanism, one `StoppableWorker`:

- The worker opens the parent directory with `FILE_FLAG_BACKUP_SEMANTICS` and `FILE_FLAG_OVERLAPPED`. It pumps `ReadDirectoryChangesW` through `GetOverlappedResultEx` with a 100 ms timeout, so the `stop_token` is observed promptly.
- On stop, the in-flight read is cancelled and drained with a bounded, escalated wait. The wait is a timed `GetOverlappedResultEx`, then a directory-handle close that forces the orphaned IRP to complete. If completion still does not arrive, the worker leaks the heap-bundled I/O buffer. A deleted watched directory therefore cannot hang teardown.
- Debounce uses `steady_clock`. The filename match is case-insensitive. `enable_auto_reload()` and `disable_auto_reload()` are idempotent and serialized by an internal `std::mutex`.
- Under the loader lock, the watcher destructor publishes its own lock-free `stop_requested` flag rather than a stop request. `StoppableWorker`'s vetoed branch detaches without stop callbacks. The worker's own module reference, taken before thread creation and left outstanding on that detach, keeps the code mapped.
- `stop()` publishes the same flag before `shutdown()` re-queries the process-global veto for itself. A predicate that flips mid-teardown therefore cannot abandon the pump unsignalled.
- The destructor then moves `Impl` into a per-call heap cell allocated with `new (std::nothrow)`. On OOM, a `release()` fallback leaks the raw pointer instead of a run of `~Impl`. The noexcept destructor stays honest, and the discipline mirrors `Logger::shutdown_internal`.

Hot-path mechanism: None. The subsystem is control-plane only, and the watcher pump polls `GetOverlappedResultEx` at 100 ms with idle CPU near zero.

## Combo string syntax

`config::press_combo`, `config::hold_combo`, `config::bind_combos`, and the INI-driven `Input::rebind` share one combo-list parser. The table is the contract for the raw INI value. `config.hpp` states the same contract per function.

| Input form                                                     | Result                                                          | Log                                               |
|----------------------------------------------------------------|-----------------------------------------------------------------|---------------------------------------------------|
| Empty string after trimming                                    | Unbound binding. The name stays registered for a later update   | None                                              |
| `NONE`, case-insensitive, whole trimmed value only             | Unbound binding. The name stays registered for a later update   | None                                              |
| Comma-separated list of valid combos, for example `F4,Ctrl+F4` | Binding bound to the OR of the parsed combos                    | None                                              |
| Comma-separated list with one bad token, for example `F4,NONE` | Binding bound to the tokens that parsed. Bad tokens are dropped | None                                              |
| Non-empty, non-`NONE` value where every token fails to parse   | Unbound binding, treated as a typo                              | One WARNING naming the binding and the raw string |

The `NONE` sentinel is whole-string only by design. A `NONE` token inside a list is not distinguishable from a key-name typo without a per-token lookup. An unbound slot inside an OR-list has no meaning. Use `NONE` or an empty value at the whole-value level to opt a binding out without removal of the INI key.

## Rules

### [B-36]

The config watcher pump calls `on_reload` while a `ReadDirectoryChangesW` notify IRP still references the heap `WatchIoState` (its `OVERLAPPED` plus notification buffer). The `CancelIoEx` plus bounded drain that lets the kernel finish with them runs only after the pump loop. A throw that unwinds the worker body therefore frees them under the live IRP, a use-after-free that the kernel writes into. It also silently ends the pump that the header states "continues running".

Catch at the invocation site with a noexcept handler (`try_log`, never a throwing `error()`), log, and continue. The drain is then reached on every path and the watcher keeps its pump (`ConfigWatcher`'s `fire_reload`). A docblock that states a callback's exceptions are caught must point at that site-level `try/catch` and carry a throwing-callback test.

### [B-37]

Parse numbers with `std::from_chars` (locale-independent, `.` -only decimal) and case-fold with an ASCII table. On a non-numeric or out-of-range value, fall back to the default with a Warning, never silently.

These sites all parse this way:

- the config int and float binds,
- the input-code hex tokenizer,
- the input-name `icompare` (an inline ASCII fold, never `std::tolower`),
- the `NONE` sentinel fold.

The config-watcher filename match likewise uses `CompareStringOrdinal` rather than a locale `towupper`. Add a non-C-locale test whenever a new value crosses the parse path.

### [B-38]

On a reload read failure, clear the cached content hash and return before the setter pass (`config::reload_impl`), so "retained" means untouched. Conversely, remember the target INI path on every load outcome, not only success ( `config::load`). A ship-with-defaults first run has no file on disk yet, so its read fails. The path must still be recorded, so that `enable_auto_reload` can watch the parent directory and pick the file up when it appears. A remembered failed path is safe precisely because a later reload of an unreadable path now retains rather than snaps.

### [B-79]

The hazardous shape reads state under a lock, releases the lock, and then acts on the earlier read. The release happens to join a worker, to run a backend restore, or to avoid a self-join deadlock. The gap is a time-of-check/time-of-use window that another thread can invert. Two shapes recur, and a re-check closes both:

1. A hook destructor peeks the newer-live count to choose leak-vs-restore. A concurrent same-target install that lands in the gap then makes the restore clobber the newer layer. The teardown therefore claims the SAME per-target front-of-pending serialization slot that the install path uses (`HookLedger::acquire_target_slot`). It measures the count under that slot and holds it across the restore. No install can then read the patched prologue mid-restore.
2. `load()`'s watcher re-point moves the watcher out under the watcher mutex, then joins the stale worker off-lock, then re-starts. The off-lock join is required: a reload callback that itself calls disable/enable self-joins otherwise. A `disable_auto_reload()` that lands in the join window is lost. The re-point therefore snapshots a monotonic disable generation under the mutex and re-checks it under the mutex before the re-start. A bump means "the caller disabled, do not resurrect", and the re-point honors it.

Do NOT settle for a merely smaller window. A bare re-peek right before the act still leaves a gap between the re-peek and the act. The re-check and the act must be one atomic step under the lock or slot.

### [B-80]

Config setters run with the config mutex released, so they can re-enter the facade. They also run on more than one worker thread: the filesystem watcher's worker AND the hotkey reload servicer's worker. A guard that checks only one worker's id leaves the other free to call a teardown (`disable_auto_reload()`, `clear()`). That teardown then joins its own thread, or joins a peer whose final flush blocks on a lock this thread already holds. The result is a `std::system_error` or a deadlock, asymmetric and easy to miss.

Each worker publishes its thread id on entry and clears it on exit. A default no-thread id never matches, so a recycled OS thread id cannot alias a dead worker. Every guarded teardown checks ALL such ids before it joins or tears down. When a new long-lived worker that can run user code is added, extend the guard to it in the same change.
