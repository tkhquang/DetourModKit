# Config Hot-Reload

DetourModKit exposes two complementary mechanisms for reapplying INI-driven configuration without restarting the game: a background filesystem watcher, and a user-configurable hotkey. Both funnel through the same primitive, `Config::reload()`.

This document describes the API surface, the thread-safety contract, what is safe to hot-reload, and the platform-specific edge cases the watcher handles.

> Note: the existing [docs/hot-reload/README.md](../hot-reload/README.md) covers a different topic (the two-DLL loader pattern for reloading mod code). This document only covers reloading config values within an already-loaded mod.

## API surface

All entry points live in `namespace DetourModKit::Config` and are declared in `include/DetourModKit/config.hpp`. `ConfigWatcher` itself is declared in `include/DetourModKit/config_watcher.hpp` and may be used standalone for watching any file.

### `bool Config::reload()`

Re-runs every registered setter against the INI path last passed to `Config::load()`. Registrations are preserved: user lambdas persist across reloads. Returns `false` if called before any `load()`, `true` otherwise.

```cpp
if (!Config::reload())
{
    Logger::get_instance().warning("Cannot reload: Config::load() was never called");
}
```

### `Config::enable_auto_reload(debounce, on_reload)`

Starts a `ConfigWatcher` on the last-loaded INI path. When the file changes, `reload()` is invoked after the debounce quiet-window has elapsed; the optional `on_reload` callback fires immediately after. Both callbacks run on the watcher thread.

Returns an `AutoReloadStatus` enum indicating the outcome (return value is `[[nodiscard]]`):

| Value | Meaning |
|---|---|
| `Started` | Watcher is now running. |
| `AlreadyRunning` | Called twice; the existing watcher was kept. |
| `NoPriorLoad` | `Config::load()` was never called; no path to watch. |
| `StartFailed` | Directory could not be opened or start handshake failed. |

The `on_reload` callback receives a `bool content_changed` argument. When the file's bytes are identical to the last successfully loaded version (a `touch`, a no-op save, an editor that rewrites identical content), the content-hash skip short-circuits the reload and the flag is `false`; the callback still fires so derived state can observe the event without wasting work on setter re-invocation.

```cpp
Config::load("mymod.ini");
const auto status = Config::enable_auto_reload(
    std::chrono::milliseconds{250},
    [](bool content_changed)
    {
        if (content_changed)
        {
            Logger::get_instance().info("Config reloaded");
        }
    });
if (status != Config::AutoReloadStatus::Started)
{
    Logger::get_instance().warning("Auto-reload did not start");
}
```

### `Config::disable_auto_reload()`

Stops the watcher and joins its worker thread. Idempotent. `noexcept`.

### `Config::register_reload_hotkey(ini_key, default_combo)`

Wires a key combo to `reload()` via `Config::register_press_combo`. Must be called before `InputManager::start()`. The combo is sourced from the INI key at load time and re-applied on every subsequent `reload()`. Returns `false` if `default_combo` is empty (which would otherwise register an inert binding).

```cpp
Config::load("mymod.ini");
(void)Config::register_reload_hotkey("ReloadConfig", "Ctrl+F5");
InputManager::get_instance().start();
```

### `ConfigWatcher` (standalone)

```cpp
ConfigWatcher watcher("/path/to/file.ini", std::chrono::milliseconds{250},
                      []() { /* runs on watcher thread */ });
if (!watcher.start())
{
    // The parent directory could not be opened; is_running() stays false.
    // Fall back to manual Config::reload() or surface an error to the user.
}
// ...
watcher.stop(); // also called by destructor
```

## Thread-safety contract

| Callback | Thread it runs on |
|---|---|
| Setters invoked by `Config::reload()` called directly | Caller's thread |
| Setters invoked by the filesystem watcher | `ConfigWatcher` worker thread |
| Setters invoked by the reload hotkey | Reload servicer thread |
| `on_reload` passed to `enable_auto_reload` | `ConfigWatcher` worker thread |

All setters registered via `register_int`, `register_float`, `register_bool`, `register_string`, and `register_key_combo` must therefore be reentrant and thread-safe if the caller uses any mechanism other than direct `reload()` invocation. The existing config mutex is released before setter callbacks fire (the deferred-setter pattern), so setters may freely call back into the Config API.

Exceptions that escape a setter propagate to the caller of `reload()`. When the watcher or the reload servicer fires `reload()` the surrounding firewall catches the escape, logs it, and keeps the thread alive.

### Reload hotkey: deferred servicing

`Config::register_reload_hotkey` does not run `Config::reload()` directly on the `InputManager` poll thread. The press callback sets an atomic flag and notifies a condition variable, returning in microseconds; a dedicated reload servicer thread drains the flag and calls `Config::reload()` off the poll path. This keeps a 30-item INI parse from jittering other hotkeys. Bursts of presses coalesce: five quick presses while a reload is in flight result in at most one follow-up reload when the servicer wakes.

The servicer is spun up lazily on the first `register_reload_hotkey` call and torn down inside `clear_registered_items()`. Under the Windows loader lock the servicer thread is detached (the `StoppableWorker` discipline used by `Logger` and `HookManager`).

### Content-hash skip

`Config::reload()` computes an FNV-1a 64 hash over the on-disk bytes before invoking any setter. If the hash matches the value stored at the last successful `load()` / `reload()`, no setters run and the call returns `true` with a DEBUG-level log line. This suppresses the common no-op cases: `touch`, editors that overwrite with identical content, hotkey presses on an unchanged file. When the file cannot be read (editor holds an exclusive handle mid-save), the hash check is skipped and the reload proceeds as usual, erring on the side of reloading.

The `on_reload` callback passed to `enable_auto_reload` receives a `bool content_changed` argument reflecting this: `true` when setters ran, `false` when the hash-skip short-circuited.

## What is safe to hot-reload

**Safe** (values consumed live by mod code):

- Numeric tunables: damage multipliers, timeouts, thresholds.
- Feature flags that branch inside a hook callback.
- Strings displayed in UI.
- Key combos registered via `Config::register_press_combo`: the combo machinery calls `InputManager::update_binding_combos` on reload, which swaps keys/modifiers in place without re-registering the binding.

**Restart required** (reloading silently has no effect, or is actively unsafe):

- SafetyHook trampolines: once a hook is installed its target address is baked in. Removing a hook requires `HookManager::remove_*_hook`, which may deadlock with in-flight callers if triggered from the watcher thread. Change the "hook installed" bit only through a proper shutdown cycle.
- Thread pool sizes and `poll_interval` for `InputManager::start()`: these are fixed at start time.
- Log file handle and log prefix: `Logger::configure` rotates the file, which requires coordinating with in-flight async writes. Prefer reconfiguring via a full shutdown/start cycle.
- The reload hotkey combo itself can be changed at runtime, but the binding cardinality (number of independent combos) cannot. If the INI combo string has a different number of comma-separated alternatives than the default, the update is rejected with a Warning and the old combo remains.

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

`ConfigWatcher::stop()` and `Config::disable_auto_reload()` are both idempotent and return within ~100 ms of the request. The watcher polls its stop token between `ReadDirectoryChangesW` completions with a 100 ms `GetOverlappedResultEx` timeout, so idle CPU is effectively zero.

If the current thread holds the Windows loader lock (e.g. `stop()` is called from `DllMain`), the watcher thread is detached rather than joined, mirroring the discipline used by `Logger::shutdown_internal` and `HookManager::~HookManager`.

## Design: single-INI assumption

`DetourModKit::Config` is a namespace singleton backed by function-local statics (registered items, the last-loaded INI path, the cached content hash, the watcher slot, the hotkey guard list, the reload servicer). There is no per-INI context object.

`register_reload_hotkey` derives its `InputManager` binding name from the INI key (`"config_reload:" + ini_key`). Two distinct INI files in the same process registering reload hotkeys therefore work as long as their `ini_key` values differ. Two INIs sharing the same `ini_key` would collide on the binding name and the last registration wins.

Mods normally own exactly one INI, so this is not a practical constraint. Multi-INI support is out of scope.

## Related

- [`config.hpp`](../../include/DetourModKit/config.hpp)
- [`config_watcher.hpp`](../../include/DetourModKit/config_watcher.hpp)
- [`worker.hpp`](../../include/DetourModKit/worker.hpp) - `StoppableWorker` RAII wrapper the watcher builds on.
- [Two-DLL hot-reload guide](../hot-reload/README.md) - reloading mod code, not config values.
