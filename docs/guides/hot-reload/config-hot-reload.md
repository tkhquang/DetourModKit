# Config Hot-Reload

DetourModKit exposes two complementary mechanisms for reapplication of INI-driven configuration without a game restart: a background filesystem watcher, and a user-configurable hotkey. Both funnel through the same primitive, `config::reload()`.

This document describes the API surface, the thread-safety contract, what is safe to hot-reload, and the platform-specific edge cases the watcher handles.

> Note: the existing [hot-reload development guide](README.md) covers a different topic, the two-DLL loader pattern for a reload of mod code. This document only covers a reload of config values within an already-loaded mod.

## API surface

All entry points live in `namespace DetourModKit::config` and are declared in `include/DetourModKit/config.hpp`. The filesystem watcher is folded in. There is no separate watcher header and no public watcher type, only `config::enable_auto_reload` / `config::disable_auto_reload` over an engine that lives in the non-installed `src/internal/config_watcher.hpp` (`DetourModKit::detail::ConfigWatcher`).

### `bool config::reload()`

Re-runs every bound setter against the INI path last passed to `config::load()`. Registrations are preserved, and user lambdas persist across reloads. Returns `false` if called before any `load()`, or if the call is refused as same-thread re-entry from a bound setter (see below). Returns `true` otherwise.

Concurrent `reload()` (and `load()`) passes are serialized end to end against one another. The file read, the content-hash decision, and the deferred-setter application run under a single pass lock. Two racing reloads (for example the watcher and the reload hotkey firing at once) therefore apply in a well-defined order. A slower stale pass can never overwrite a fresher one or pin outdated values behind the content-hash short-circuit. The pass lock is held across the setter phase, so a bound setter that calls `reload()`, `load()`, or `disable_auto_reload()` is refused rather than allowed to deadlock. `clear()` is likewise refused except on the reload-servicer thread, whose owner can retire safely through the off-thread reaper. Setters can still freely re-enter the data-plane calls (`bind_*`, getters).

```cpp
if (!config::reload())
{
    log().warning("Config reload did not run");
}
```

### `config::enable_auto_reload(debounce, on_reload)`

Starts the folded-in filesystem watcher on the last-loaded INI path. When the file changes, `reload()` is invoked after the debounce quiet-window elapses, and the optional `on_reload` callback fires immediately after. Both callbacks run on the watcher thread.

The path is remembered from the most recent `config::load()` call whether or not that load found the file. A ship-with-defaults first run whose INI does not exist yet therefore still arms the watcher: it monitors the parent directory and fires once the file is created. `NoPriorLoad` is returned only when `config::load()` was never called at all (there is no path to watch), not when the file was missing.

If a later `config::load()` names a different file than an active watcher monitors, the watcher is re-pointed to the new file and keeps its debounce and `on_reload` callback. A hot-swap of the config file therefore keeps auto-reload working. The re-point is skipped with a logged error when `load()` is called from the watcher thread itself (a self-join hazard). Re-point from another thread in that case.

Returns an `AutoReloadStatus` enum for the outcome (return value is `[[nodiscard]]`):

| Value | Meaning |
|---|---|
| `Started` | Watcher is now running. |
| `AlreadyRunning` | Called twice. The existing watcher was kept. |
| `NoPriorLoad` | `config::load()` was never called. No path to watch. |
| `StartFailed` | The directory failed to open, or the start handshake failed. |

The `on_reload` callback receives a `bool setters_ran` argument. The flag is `true` when bound setters were re-invoked and `false` when the setter pass was skipped. [Content-hash skip](#content-hash-skip) lists the skip paths. The callback still fires on a skip, so derived state can observe the event without wasted work on setter re-invocation.

```cpp
config::load("mymod.ini");
const auto status = config::enable_auto_reload(
    std::chrono::milliseconds{250},
    [](bool setters_ran)
    {
        if (setters_ran)
        {
            log().info("Config reloaded");
        }
    });
if (status != config::AutoReloadStatus::Started)
{
    log().warning("Auto-reload did not start");
}
```

### `config::disable_auto_reload()`

Stops the watcher synchronously. The notification drain, a final debounced `on_reload` callback if a change is still pending, and the worker join all complete before it returns. Idempotent. `noexcept`. Because that final callback is your code, the call is not time-bounded (see [Stopping semantics](#stopping-semantics)). One exception: a call from the watcher thread itself (from inside `on_reload`, or a setter fired by the watcher) is a logged no-op that leaves the watcher running. A join of the worker from itself deadlocks. It is likewise refused when called from a bound setter on any reload worker, because a join of the watcher blocks on the reload pass lock that setter's thread already holds.

### `config::reload_hotkey(ini_key, default_combo)`

Wires a key combo to `reload()` via `config::press_combo`. Can be called before or after `input::Input::instance().start()`. A hotkey registered while the poll engine runs goes live on the next poll cycle. One caveat: a `start()` with no staged bindings builds no engine, so a hotkey registered after such an empty `start()` stays staged until the next `start()`. The combo is sourced from `ini_key` in the `[Input]` section of the INI at load time and re-applied on every subsequent `reload()`. Returns `false` if `default_combo` is empty, is the literal `NONE` sentinel, or fails to parse into any valid combo (a typo default emits a WARNING first). All three cases otherwise register an inert binding.

```cpp
config::load("mymod.ini");
(void)config::reload_hotkey("ReloadConfig", "Ctrl+F5");
if (!input::Input::instance().start())
{
    log().warning("Input engine failed to start");
}
```

## Thread-safety contract

| Callback | Thread it runs on |
|---|---|
| Setters invoked by `config::reload()` called directly | Caller's thread |
| Setters invoked by the filesystem watcher | Watcher worker thread |
| Setters invoked by the reload hotkey | Reload servicer thread |
| `on_reload` passed to `enable_auto_reload` | Watcher worker thread |

All setters bound via `bind` / `bind_int` / `bind_float` / `bind_bool` / `bind_string` / `bind_combos` must therefore be reentrant and thread-safe if the caller uses any mechanism other than direct `reload()` invocation. The config mutex is released before setter callbacks fire (the deferred-setter pattern), so setters can freely call back into the config API.

A C++ exception that escapes a setter is caught at the `reload()` boundary and logged, and the remaining setters still run. It does not propagate to the caller, whichever thread invoked `reload()`. Structured-exception (SEH) faults and a throwing `noexcept` setter bypass this handler and are not recoverable.

### Reload hotkey: deferred servicing

`config::reload_hotkey` does not run `config::reload()` directly on the `input::Input` poll thread. The press callback sets an atomic flag, notifies a condition variable, and returns in microseconds. A dedicated reload servicer thread drains the flag and calls `config::reload()` off the poll path. This keeps a 30-item INI parse from jitter on other hotkeys. Bursts of presses coalesce: five quick presses while a reload is in flight result in at most one follow-up reload when the servicer wakes.

The servicer is spun up lazily on the first `reload_hotkey` call and torn down inside `config::clear()`. Under the Windows loader lock, teardown decides before it touches the servicer mutex or stop source, publishes a lock-free shutdown hint, and detaches without invocation of stop callbacks. Its channel and counted module reference are retained so the abandoned worker cannot outlive either state or code. The wake on that hint is best-effort. A notify without the channel mutex cannot close the waiter's lost-wakeup window, so an already-parked servicer can stay parked for the life of the process. It strands nothing extra, because this branch retains its channel and module reference either way.

### Content-hash skip

`config::reload()` computes an FNV-1a 64 hash over the on-disk bytes before it invokes any setter. Setters are skipped only when BOTH that hash and the binding generation are unchanged since the last fully applied `load()` / `reload()`. The call then returns `true` with a DEBUG-level log line. The hash alone suppresses the common no-op cases: `touch`, editors that overwrite with identical content, and hotkey presses on an unchanged file. The binding generation covers the other half. A `bind_*` registered after the last apply hydrates from disk on the next `reload()` even though the file bytes never changed.

Three conditions skip or abandon the setter pass:

- The file cannot be read (an editor holds an exclusive handle mid-save, or a seek/tell error).
- The file fails to parse.
- The setter pass is interrupted.

The current values are then retained rather than reset to their defaults, and no snapshot is cached. Nothing short of a fully applied pass publishes a hash, so an identical-byte retry always re-applies rather than skips.

The `on_reload` callback passed to `enable_auto_reload` receives a `bool setters_ran` argument that reflects this: `true` when setters ran, `false` when the hash-skip, read-failure, or parse-failure path skipped the setter pass.

## What is safe to hot-reload

**Safe** (values consumed live by mod code):

- Numeric tunables: damage multipliers, timeouts, thresholds.
- Feature flags that branch inside a hook callback.
- Strings displayed in UI.
- Key combos registered via `config::press_combo` / `config::hold_combo`. The combo machinery calls `input::Input::rebind` on reload. A `consume` facet passed to either fusion adds a `"<ini_key>.Consume"` bool that hot-reloads alongside the combo. A rebind is generation-safe against a racing poll cycle regardless of shape. A press or held(true) callback already staged from the old combo when the swap lands is always refused rather than delivered. A reload therefore cannot fire a stale activation from the previous key set. A same-shape reload (the combo count is unchanged) swaps keys and modifiers in place and delivers a staged release(false) as-is, so a binding held as the swap lands is reported released. A shape-changing reload (the number of alternative combos changes) rebuilds the entry set instead. It can reject the staged release and synthesize a single deduplicated balancing release, so a dropped held binding still ends released rather than stranded in the held state.
- The reload hotkey combo itself can be changed at runtime. The cardinality of the new combo list does not need to match the default, and the binding's combo set is rebuilt on the fly. To opt the hotkey out at runtime, set the INI value to either an empty string or the literal `NONE` (case-insensitive, whole-string only). Both forms produce an unbound binding silently. A non-empty value whose every comma-separated token fails to parse is logged at WARNING level with the binding name and the offending raw string. See the [combo string syntax section](../../design/config.md#combo-string-syntax) in the config note for the complete contract (mixed-list behavior, `NONE`-in-list, and so on).

**Restart required** (a reload silently has no effect, or is actively unsafe):

- Hook trampolines: once a hook is installed its target address is baked in. A config-driven "hook installed" toggle cannot flip a live hook on or off, because a `Hook` is a caller-owned RAII handle whose lifetime is not reachable from a Config setter. Removal of a hook means a drop of its `Hook` handle (its destructor unhooks under the loader-lock leaf discipline). That drop must not be driven from the watcher thread while callers can still be in flight. Change the "hook installed" bit only through a proper shutdown cycle.
- Thread pool sizes and `poll_interval` for `input::Input::start()`: these are fixed at start time.
- Log file handle and log prefix: `Logger::configure` rotates the file, which requires coordination with in-flight async writes. Prefer a reconfigure via a full shutdown and start cycle.

## Debounce rationale

Editor save patterns produce bursts of change events rather than a single atomic write:

- **VSCode default save**: truncate, then write. Two events: SIZE + LAST_WRITE.
- **Notepad++ / VSCode atomic save**: write sibling `.tmp`, then rename over target. Three events: FILE_NAME (remove target), FILE_NAME (add via rename), LAST_WRITE.
- **Vim with `writebackup`**: rename target to `~`, write new content, delete backup. Four events.

Without a debounce, each of these patterns fires `reload()` two to four times in ~10-100 ms. The 250 ms default debounce collapses them into a single callback while it stays responsive for interactive editing. Shorten the window only if you profile the watcher callback and know the reload is cheap. Lengthen it if your reload is expensive (for example a recompute of a large lookup table).

The watcher uses `std::chrono::steady_clock` for debounce timing, so wall-clock adjustments (NTP sync, DST transitions) cannot suppress or spuriously fire callbacks.

## Rename-swap-save edge case

`ReadDirectoryChangesW` is configured with `FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE`. The `FILE_NAME` flag is essential. Without it, editors that write to a sibling `.tmp` and rename over the target produce zero events that mention the target filename. Filename matching is case-insensitive (Windows filesystem convention).

The watcher also treats a zero-byte notification buffer as a match (the buffer-overflow path). If the kernel drops events because they arrived faster than the worker drained them, the watcher assumes the target changed and lets the debounce deduplicate.

## Stopping semantics

`config::disable_auto_reload()` is idempotent and synchronous. It is NOT time-bounded, and it never detaches a running callback. Four phases run before it returns:

1. The worker observes the stop token. It polls between `ReadDirectoryChangesW` completions with a 100 ms `GetOverlappedResultEx` timeout, so idle CPU is effectively zero.
2. The notification drain below runs.
3. If a debounced change is still pending, one final `on_reload` callback runs.
4. The worker join completes.

The first two phases are bounded. The final callback is your code, so a callback that blocks blocks this call for exactly as long. Budget your unload path against your own callback, not against a fixed figure.

On stop the worker cancels its in-flight `ReadDirectoryChangesW` and waits for the kernel to release the `OVERLAPPED` and notification buffer before they are freed. Per MSDN both must stay valid until the cancelled I/O completes. Cancellation normally drives the read to completion in microseconds. If the watched directory was deleted, the notify IRP can be orphaned (`CancelIoEx` reports success yet no completion is ever delivered), which a blind unbounded wait turns into a teardown hang. The drain is therefore bounded and escalates through three steps:

1. A timed wait for the cancelled read.
2. A close of the directory handle to force the I/O Manager to cancel and complete the outstanding IRP, which signals the worker's event.
3. If completion still cannot be checked, a leak of the I/O buffer so a late kernel write can never land in freed memory.

Worst-case drain is bounded at roughly two seconds instead of an unbounded hang, and the leak path mirrors the leak-on-teardown discipline used elsewhere under the loader lock. That bound covers the drain only. The final `on_reload` callback that can follow it is unbounded user code.

If the current thread holds the Windows loader lock (`stop()` is called from `DllMain`, for example), the watcher publishes its independent atomic cancellation flag and detaches. It runs no join and no stop callbacks. Its `StoppableWorker` leaves its own module reference outstanding so its code pages stay mapped. That mirrors the discipline used by `Logger::shutdown_internal` and by `~Hook` (which leaks the backend with its install-time module reference under the loader lock).

## Design: single-INI assumption

`DetourModKit::config` is a namespace over a process-wide registry backed by function-local statics (bound items, the last-loaded INI path, the cached content hash, the watcher slot, the hotkey guard list, the reload servicer). There is no per-INI context object. `Ini{}` and `config::section(...)` are thin handles onto the same shared registry.

`reload_hotkey` derives its `input` binding name from the INI key (`"config_reload:" + ini_key`). Two distinct INI files in the same process that register reload hotkeys therefore work as long as their `ini_key` values differ. Two INIs that share the same `ini_key` collide on the binding name, and the last registration wins.

Mods normally own exactly one INI, so this is not a practical constraint. Multi-INI support is out of scope.

## Related

- [`config.hpp`](../../../include/DetourModKit/config.hpp)
- [`input.hpp`](../../../include/DetourModKit/input.hpp) - the combo binding surface `press_combo` / `hold_combo` fuse onto.
- [`worker.hpp`](../../../include/DetourModKit/detail/worker.hpp) - `StoppableWorker` RAII wrapper the watcher builds on.
- [Two-DLL hot-reload guide](README.md) - a reload of mod code, not config values.
