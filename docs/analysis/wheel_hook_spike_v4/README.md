# PR-15 Stage 0: WH_GETMESSAGE wheel spike

This directory records the deterministic `WH_GETMESSAGE` spike for PR-15. Record new measurements in a new folder.

## Method

The harness uses fresh windows and pump threads. Its resident hook counts wheel messages on `PM_REMOVE` only. It leaves `PM_NOREMOVE` state unchanged. A consumed message becomes `WM_NULL` before and after one `CallNextHookEx` call. Older and newer probe hooks verify chain order.

## Host and toolchains

- Windows 10.0 build 26200
- MinGW GCC 15.1.0, C++23 Debug
- MSVC 19.43.34809, C++23 Debug
- Runs from 2026-08-21: `runs/mingw_debug.log` and `runs/msvc_debug.log`

## Results

Both toolchains report 53 passes, two skips, zero failures, and exit code 0. Three repeat runs show identical TAP lines.

| Stage 0 case | Verdict | Evidence |
| --- | --- | --- |
| 1 synthetic vertical and horizontal capture | PASS | checks 1 to 6 |
| 2 partial deltas and four direction counts | PASS | checks 7 to 10 |
| 3 repeated `PM_NOREMOVE` and one `PM_REMOVE` | PASS | checks 11 to 16 |
| 4 filtered peek progress and count isolation | PASS | checks 17 to 22 |
| 5 root, child, popup, and unrelated windows | PASS | checks 23 to 25 |
| 6 `PostMessage`, `SendMessage`, and parent propagation | PASS | checks 26 to 34 |
| 7 older and newer hook order and mutation | PASS | checks 35 to 41 |
| 9 thread migration, window recreation, and thread exit | PASS | checks 42 to 53 |
| 1 live game pump | OPEN | needs a live game session |
| 8 `gameoverlayrenderer64` regression | OPEN | needs a live game session |

## Findings

1. A same-process thread hook with `hMod == nullptr` sees queue retrieval after a successful mount.
2. Partial deltas and four direction counts match the local direction mapping.
3. Repeated `PM_NOREMOVE` peeks leave the queued message and counters unchanged.
4. A filtered remove leaves unmatched wheel input queued and preserves queue progress.
5. The hook sees each target window on its thread. `GetAncestor(GA_ROOT)` distinguishes children from separate roots.
6. Direct `SendMessage` delivery bypasses `WH_GETMESSAGE`. Posted child input reaches the hook once.
7. Hook chains run newest first. A newer hook can defeat resident consumption after `CallNextHookEx` returns.
8. A successful unhook and remount moved capture between pump threads without overlap in this harness.
9. Thread exit removed the thread hook before the later cleanup call.

## Status

The deterministic routes pass on both toolchains. The two live-game routes remain open and require their named environment.

## Reproduce

```bash
g++ -std=c++23 -g -O0 -Wall -Wextra wheel_hook_spike.cpp -o wheel_hook_spike.exe -luser32
./wheel_hook_spike.exe
```

```bat
cl /std:c++latest /EHsc /W4 /Zi wheel_hook_spike.cpp user32.lib
wheel_hook_spike.exe
```

Exit code 0 means each non-skipped route passed. Exit code 3 marks a watchdog abort.
