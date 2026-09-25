# Coordinator refusal measurements

This directory records the teardown cost under a held process coordinator and the recovery after one refused acquisition. Record new measurements in a new folder.

## Method

`route_copy_host` loads two fixture DLLs. Each DLL links its own archive copy. The host installs one mid hook in participant A and times its teardown with `GetTickCount64`.

| Scenario | Proof | Condition |
| --- | --- | --- |
| `timeout` | `Lifecycle.RouteCopiesRetainAfterCoordinatorTimeout` | The hook is disarmed. Participant B holds the coordinator for the complete teardown. |
| `timeout-armed` | `Lifecycle.RouteCopiesRetainArmedHookAfterCoordinatorTimeout` | The hook stays armed. Participant B holds the coordinator for the complete teardown. |
| `teardown-retry` | `Lifecycle.RouteCopiesRetryDisarmedTeardownAfterCoordinatorRefusal` | The hook is disarmed. Participant A refuses its next acquisition once. |
| `teardown-retry-armed` | `Lifecycle.RouteCopiesRetryArmedTeardownAfterCoordinatorRefusal` | The hook stays armed. Participant A refuses its next acquisition once. |

Each timeout run prints one `coordinator teardown` line. Each lane ran all four scenarios three times from `tests/lifecycle`.

## Host and toolchains

- Windows 11 10.0.26200, x64
- MinGW GCC 15.1.0, C++23, Debug and release-tests presets
- MSVC 19.43.34809, C++23, Debug and release-tests presets
- `COORDINATOR_WAIT_MS` is 2000
- Runs from 2026-09-25 over `6e22749`

## Results

| Lane | Disarmed teardown (ms) | Armed teardown (ms) |
| --- | --- | --- |
| MinGW Debug | 8047, 8031, 8031 | 4016, 4016, 4016 |
| MinGW release-tests | 8047, 8031, 8015 | 4032, 4016, 4016 |
| MSVC Debug | 8047, 8031, 8063 | 4015, 4015, 4031 |
| MSVC release-tests | 8110, 8047, 8062 | 4032, 4015, 4016 |

Every timeout run reports one intentional leak and one coordinator record. The disarmed teardown waits four times, and the armed teardown waits two times. Each wait uses the full limit. Scheduler delay adds at most 110 ms.

Every retry run exits 0. Teardown reclaims the route, and the target holds its original bytes. No record and no warning remain.

A MinGW Debug variant retains the backend at the first refused DMK acquisition. `teardown-retry` and `teardown-retry-armed` both exit 1 against it.

## Decision

DMK keeps the repeated acquisitions. After a transient refusal, a later acquisition reclaims the route or marks its record retained. `Lifecycle.RefusedTeardownCompletesRetention` verifies the retained record. Suppression of the later acquisitions removes both capabilities.

A shorter coordinator deadline is a separate policy choice. It needs its own measurements.
