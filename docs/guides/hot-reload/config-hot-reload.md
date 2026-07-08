# Config Hot-Reload

DetourModKit exposes two complementary mechanisms for reapplying INI-driven configuration without restarting the game: a background filesystem watcher, and a user-configurable hotkey. Both funnel through the same primitive, `config::reload()`.

This document describes the API surface, the thread-safety contract, what is safe to hot-reload, and the platform-specific edge cases the watcher handles.

> Note: the existing [the hot-reload development guide](README.md) covers a different topic (the two-DLL loader pattern for reloading mod code). This document only covers reloading config values within an already-loaded mod.

## API surface

All entry points live in `namespace DetourModKit::config` and are declared in `include/DetourModKit/config.hpp`. The filesystem watcher is folded in: there is no separate watcher header and no public watcher type, only `config::enable_auto_reload` / `config::disable_auto_reload` over an engine that lives in the non-installed `src/internal/config_watcher.hpp` (`DetourModKit::detail::ConfigWatcher`).

### `bool config::reload()`

Re-runs every bound setter against the INI path last passed to `config::load()`. Registrations are preserved: user lambdas persist across reloads. Returns `false` if called before any `load()`, `true` otherwise.

```cpp
if (!config::reload())
{
    log().warning("Cannot reload: config::load() was never called");
}
```

### `config::enable_auto_reload(debounce, on_reload)`

Starts the folded-in filesystem watcher on the last-loaded INI path. When the file changes, `reload()` is invoked after the debounce quiet-window has elapsed; the optional `on_reload` callback fires immediately after. Both callbacks run on the watcher thread.

The path is remembered from the most recent `config::load()` call whether or not that load found the file, so a ship-with-defaults first run whose INI does not exist yet still arms the watcher: it monitors the parent directory and fires once the file is created. `NoPriorLoad` is returned only when `config::load()` was never called at all (there is no path to watch), not when the file was simply missing.

Returns an `AutoReloadStatus` enum indicating the outcome (return value is `[[nodiscard]]`):

| Value | Meaning |
|---|---|
| `Started` | Watcher is now running. |
| `AlreadyRunning` | Called twice; the existing watcher was kept. |
| `NoPriorLoad` | `config::load()` was never called; no path to watch. |
| `StartFailed` | Directory could not be opened or start handshake failed. |

The `on_reload` callback receives a `bool setters_ran` argument. The flag is `true` when bound setters were re-invoked. It is `false` when the setter pass was skipped, either because the file's bytes are identical to the last successfully loaded version (a `touch`, a no-op save, an editor that rewrites identical content), or because the file could not be read and the current values were retained. The callback still fires so derived state can observe the event without wasting work on setter re-invocation.

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

Stops the watcher and joins its worker thread. Idempotent. `noexcept`.

### `config::reload_hotkey(ini_key, default_combo)`

Wires a key combo to `reload()` via `config::press_combo`. Must be called before `input::Input::instance().start()`. The combo is sourced from the INI key at load time and re-applied on every subsequent `reload()`. Returns `false` if `default_combo` is empty or the literal `NONE` sentinel (which would otherwise register an inert binding).

```cpp
config::load("mymod.ini");
(void)config::reload_hotkey("ReloadConfig", "Ctrl+F5");
input::Input::instance().start();
```

## Thread-safety contract

| Callback | Thread it runs on |
|---|---|
| Setters invoked by `config::reload()` called directly | Caller's thread |
| Setters invoked by the filesystem watcher | Watcher worker thread |
| Setters invoked by the reload hotkey | Reload servicer thread |
| `on_reload` passed to `enable_auto_reload` | Watcher worker thread |

All setters bound via `bind` / `bind_int` / `bind_float` / `bind_bool` / `bind_string` / `bind_combos` must therefore be reentrant and thread-safe if the caller uses any mechanism other than direct `reload()` invocation. The config mutex is released before setter callbacks fire (the deferred-setter pattern), so setters may freely call back into the config API.

A C++ exception that escapes a setter is caught at the `reload()` boundary, logged, and the remaining setters still run; it does not propagate to the caller, whichever thread invoked `reload()`. Structured-exception (SEH) faults and a throwing `noexcept` setter bypass this handler and are not recoverable.

### Reload hotkey: deferred servicing

`config::reload_hotkey` does not run `config::reload()` directly on the `input::Input` poll thread. The press callback sets an atomic flag and notifies a condition variable, returning in microseconds; a dedicated reload servicer thread drains the flag and calls `config::reload()` off the poll path. This keeps a 30-item INI parse from jittering other hotkeys. Bursts of presses coalesce: five quick presses while a reload is in flight result in at most one follow-up reload when the servicer wakes.

The servicer is spun up lazily on the first `reload_hotkey` call and torn down inside `config::clear()`. Under the Windows loader lock the servicer thread is detached (the `StoppableWorker` discipline used by `Logger` and by `Hook` teardown).

### Content-hash skip

`config::reload()` computes an FNV-1a 64 hash over the on-disk bytes before invoking any setter. If the hash matches the value stored at the last successful `load()` / `reload()`, no setters run and the call returns `true` with a DEBUG-level log line. This suppresses the common no-op cases: `touch`, editors that overwrite with identical content, hotkey presses on an unchanged file. When the file cannot be read (editor holds an exclusive handle mid-save), the cached hash is cleared and the setter pass is skipped so the current values are retained.

The `on_reload` callback passed to `enable_auto_reload` receives a `bool setters_ran` argument reflecting this: `true` when setters ran, `false` when the hash-skip or read-failure path skipped the setter pass.

## What is safe to hot-reload

**Safe** (values consumed live by mod code):

- Numeric tunables: damage multipliers, timeouts, thresholds.
- Feature flags that branch inside a hook callback.
- Strings displayed in UI.
- Key combos registered via `config::press_combo` / `config::hold_combo`: the combo machinery calls `input::Input::rebind` on reload, which swaps keys/modifiers in place without re-registering the binding. A `consume` facet passed to either fusion adds a `"<ini_key>.Consume"` bool that hot-reloads alongside the combo.

**Restart required** (reloading silently has no effect, or is actively unsafe):

- Hook trampolines: once a hook is installed its target address is baked in. A config-driven "hook installed" toggle cannot flip a live hook on or off, because a `Hook` is a caller-owned RAII handle whose lifetime is not reachable from a Config setter. Removing a hook means dropping its `Hook` handle (its destructor unhooks under the loader-lock leaf discipline), which must not be driven from the watcher thread while callers may still be in flight. Change the "hook installed" bit only through a proper shutdown cycle.
- Thread pool sizes and `poll_interval` for `input::Input::start()`: these are fixed at start time.
- Log file handle and log prefix: `Logger::configure` rotates the file, which requires coordinating with in-flight async writes. Prefer reconfiguring via a full shutdown/start cycle.
- The reload hotkey combo itself can be changed at runtime; the cardinality of the new combo list does not need to match the default and the binding's combo set is rebuilt on the fly. To opt the hotkey out at runtime, set the INI value to either an empty string or the literal `NONE` (case-insensitive, whole-string only); both forms produce an unbound binding silently. A non-empty value whose every comma-separated token fails to parse is logged at WARNING level naming the binding and the offending raw string. See the [combo string syntax sub-section](README.md#combo-string-syntax-opt-out-and-parse-failures) in the hot-reload guide for the complete contract (mixed-list behavior, `NONE`-in-list, and so on).

## Debounce rationale

Editor save patterns produce bursts of change events rather than a single atomic write:

- **VSCode default save**: truncate, then write. Two events: SIZE + LAST_WRITE.
- **Notepad++ / VSCode atomic save**: write sibling `.tmp`, then rename over target. Three events: FILE_NAME (remove target), FILE_NAME (add via rename), LAST_WRITE.
- **Vim with `writebackup`**: rename target to `~`, write new content, delete backup. Four events.

Without debouncing, each of these patterns fires `reload()` two to four times in ~10-100 ms. The 250 ms default debounce collapses them into a single callback while remaining responsive for interactive editing. Shorten the window only if you profile the watcher callback and know the reload is cheap; lengthen it if your reload is expensive (e.g. recomputes a large lookup table).

The watcher uses `std::chrono::steady_clock` for debounce timing so wall-clock adjustments (NTP sync, DST transitions) cannot suppress or spuriously fire callbacks.

## Rename-swap-save edge case

`ReadDirectoryChangesW` is configured with `FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE`. The `FILE_NAME` flag is essential: without it, editors that write to a sibling `.tmp` and rename over the target produce zero events that mention the target filename. Filename matching is case-insensitive (Windows filesystem convention).

The watcher also treats a zero-byte notification buffer as a match (buffer overflow path): if the kernel drops events because they arrived faster than the worker could drain them, the watcher assumes the target changed and lets the debounce deduplicate.

## Stopping semantics

`config::disable_auto_reload()` is idempotent and returns within ~100 ms of the request in the common case. The watcher polls its stop token between `ReadDirectoryChangesW` completions with a 100 ms `GetOverlappedResultEx` timeout, so idle CPU is effectively zero.

On stop the worker cancels its in-flight `ReadDirectoryChangesW` and waits for the kernel to release the `OVERLAPPED` and notification buffer before they are freed; per MSDN both must stay valid until the cancelled I/O has actually completed. Cancellation normally drives the read to completion in microseconds, but if the watched directory was deleted the notify IRP can be orphaned (`CancelIoEx` reports success yet no completion is ever delivered), which a blind unbounded wait would turn into a teardown hang. The drain is therefore bounded and escalates: a timed wait for the cancelled read, then closing the directory handle to force the I/O Manager to cancel and complete the outstanding IRP (which signals the worker's event), and finally -- if completion still cannot be confirmed -- leaking the I/O buffer so a late kernel write can never land in freed memory. Worst-case teardown is bounded at roughly two seconds instead of an unbounded hang, and the leak path mirrors the leak-on-teardown discipline used elsewhere under the loader lock.

If the current thread holds the Windows loader lock (e.g. `stop()` is called from `DllMain`), the watcher thread is detached rather than joined -- its `StoppableWorker` leaves its own module reference outstanding so its code pages stay mapped -- mirroring the discipline used by `Logger::shutdown_internal` and by `~Hook` (which leaks the backend with its install-time module reference under the loader lock).

## Design: single-INI assumption

`DetourModKit::config` is a namespace over a process-wide registry backed by function-local statics (bound items, the last-loaded INI path, the cached content hash, the watcher slot, the hotkey guard list, the reload servicer). There is no per-INI context object; `Ini{}` and `config::section(...)` are thin handles onto the same shared registry.

`reload_hotkey` derives its `input` binding name from the INI key (`"config_reload:" + ini_key`). Two distinct INI files in the same process registering reload hotkeys therefore work as long as their `ini_key` values differ. Two INIs sharing the same `ini_key` would collide on the binding name and the last registration wins.

Mods normally own exactly one INI, so this is not a practical constraint. Multi-INI support is out of scope.

## Related

- [`config.hpp`](../../../include/DetourModKit/config.hpp)
- [`input.hpp`](../../../include/DetourModKit/input.hpp) - the combo binding surface `press_combo` / `hold_combo` fuse onto.
- [`worker.hpp`](../../../include/DetourModKit/detail/worker.hpp) - `StoppableWorker` RAII wrapper the watcher builds on.
- [Two-DLL hot-reload guide](README.md) - reloading mod code, not config values.
