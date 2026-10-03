# Test coverage guide

This guide owns the per-suite table, the run commands, the CTest labels and their inventory gates, the CTest timeout contract, and the coverage tooling. Other test facts have these owners:

- [docs/design/testing.md](../design/testing.md): the test rules.
- `AGENTS.md`: the [test requirements](../../AGENTS.md#testing) and the [build commands](../../AGENTS.md#build-and-test-commands).
- [docs/design/build-ci.md](../design/build-ci.md): the CI lanes, the release soak, the benchmark gate records, and the workflow contract.
- [docs/design/lifecycle.md](../design/lifecycle.md): the lifecycle rules and the loader-lock proof inventory.
- `lifecycle_proof_cases` in [tests/CMakeLists.txt](../../tests/CMakeLists.txt): the authoritative list of lifecycle cases.

`Lifecycle.StagedGenerationResourcesExcludeHostExceptionTls` verifies the resource census after first-use host exception state. Its six generations retain the exact TLS and executable-byte limits. The process timeout is 300 seconds.

`Lifecycle.StagedGenerationResourcesExcludeHostBreakpointTls` applies the same limits to native breakpoint initialization. `Lifecycle.StagedExampleExistingDirectoryUsesFreshName` verifies fresh directory allocation after a process ID recurs. Its timeout is 60 seconds.

The resource host records each generation's successful `TlsAlloc` and `TlsFree` calls through fixture import cells. It transfers pre-Init ownership and preserves the host ledger after image unload. The PEB census verifies that each retained index remains allocated. Executable-byte limits remain exact.

- `Lifecycle.StagedGenerationResourcesExcludeHostLoadTls` verifies three host allocations after the baseline.
- `Lifecycle.StagedGenerationResourcesRejectLoadTlsLeak` rejects a DLL load leak that an unrelated host release masks from the process count.
- `Lifecycle.WerControlClearsInheritedErrorMode` verifies removal of process and thread WER suppression before the native crash control.

The two TLS controls use six generations and a 300-second timeout. The WER mode control uses a 30-second timeout.

## Run

After you build the tree, run the commands from the repository root.

```bash
PATH="/c/msys64/mingw64/bin:$PATH"

# The canonical verdict: each case in its own process
ctest --preset mingw-debug

# Also required: the whole unit binary in one process
./build/mingw-debug/tests/DetourModKit_tests.exe

# One label
ctest --preset mingw-debug -L script-lint

# Fault and lifecycle proofs
bash scripts/run_fault_tests.sh build/mingw-debug
bash scripts/run_lifecycle_proofs.sh build/mingw-debug -R "Lifecycle.FullLifecycle"

# The suite under optimization
ctest --preset mingw-release-tests
```

For MSVC, replace `mingw` with `msvc` in each preset and tree name. Omit the `PATH` line. Run the commands in a Bash shell that has the Developer Command Prompt environment.

Each wrapper script builds its host aggregate, `dmk_fault_proof_hosts` or `dmk_lifecycle_proof_hosts`, and then runs its label. Its first argument is the build tree, `build/mingw-debug` by default. It passes later arguments to `ctest`.

## CTest labels

| Label | Cases | Inventory gate |
| --- | --- | --- |
| `unit` | Every case of `DetourModKit_tests` and `DetourModKit_wheel_host_tests`, and `SameBaseReplacementExecutionRecord` | None |
| `fault-proof` | Every case of `fault_tests`, and the four `fault_scanner_escape_probe` cases | `FaultProof.LabelInventoryIsComplete` |
| `lifecycle-proof` | The `tests/lifecycle/` cases, except the two timeout controls and the `StagedGenerationArtifactCleanup` fixture | `Lifecycle.LabelInventoryIsComplete` |
| `timeout-control` | `CTestTimeoutControl` and `CTestTimeoutControlNegative` | None |
| `script-lint` | Every `*SelfTest` case, `WorkflowTopologyIsBlocking`, `ReleaseIdentityRefusesAMismatchedCandidate`, and `SameBaseReplacementExecutionEvidence`. A MinGW tree adds `EmitPathHasNoEmulatedTls` and `HookTranslationUnitsRegisterNoExitDestructor`. | None |

Each inventory gate runs `scripts/check_test_label_inventory.py` and carries the label that it checks. `tests/CMakeLists.txt` names the cases that each gate requires. [testing.md](../design/testing.md#a-proof-label-needs-an-inventory-gate) owns the rule.

## CTest timeouts

Every case that `tests/CMakeLists.txt`, `tests/fault/`, and `tests/lifecycle/` register carries an execution `TIMEOUT`. CTest fails and stops a case that runs past it, so a hung case cannot block the run.

`dmk_add_gtest_proof` and `dmk_add_raw_proof` in `cmake/DMKTesting.cmake` use `DMK_TEST_TIMEOUT_SECONDS` (default 300), unless the call passes `TEST_TIMEOUT`. Other registrations set `TIMEOUT` explicitly. GoogleTest discovery runs in `PRE_TEST` mode under the separate `DMK_DISCOVERY_TIMEOUT_SECONDS` (default 120), which bounds only the case enumeration.

`CTestTimeoutControl` proves that CTest enforces `TIMEOUT`. `scripts/verify_ctest_timeout.cmake` registers the hung `dmk_timeout_probe` under a two-second `TIMEOUT` in a scratch tree, runs `ctest` there, and requires a `***Timeout` status. `CTestTimeoutControlNegative` (`WILL_FAIL`) runs the script on `fast_fail_probe`, which exits nonzero at once, under a scratch path that contains "timeout". It passes only when the script rejects that result as not a timeout.

## Coverage

Build and run the `mingw-debug-coverage` tree with the commands in `AGENTS.md`. Then run gcovr from the repository root.

```bash
# The gcovr options of pr-check.yml and coverage-pages.yml
gcovr_options=(--root . --filter "src/" --filter "include/" --exclude "external/" --exclude "build/" --exclude "tests/"
    --gcov-ignore-parse-errors=negative_hits.warn_once_per_file)
coverage_tree=build/mingw-debug-coverage

gcovr "${gcovr_options[@]}" --print-summary "$coverage_tree"

# HTML report with the coverage-pages.yml line gate. docs/tests/coverage/ is gitignored.
mkdir -p docs/tests/coverage
gcovr "${gcovr_options[@]}" --fail-under-line 80 --html-details docs/tests/coverage/index.html "$coverage_tree"

# Per-file and total line and function coverage
gcovr "${gcovr_options[@]}" --json docs/tests/coverage/coverage.json "$coverage_tree"
python docs/tests/parse_coverage.py docs/tests/coverage/coverage.json

# One source file. The Missing column lists its uncovered lines.
gcovr --root . --filter "src/hook.cpp" --gcov-ignore-parse-errors=negative_hits.warn_once_per_file "$coverage_tree"
```

gcov from g++ can report a negative hit count on a line. The `negative_hits.warn_once_per_file` option records zero hits for that line and limits the warnings for each file. Without it, gcovr stops with an error.

After you delete or rename a source file, configure a fresh build tree before a coverage run. Ninja keeps the orphaned `.gcno` and `.gcda` files, and gcovr can then abort on a function-line merge conflict.

`docs/tests/test_compile.cpp` checks the toolchain: `g++ -o test_compile.exe docs/tests/test_compile.cpp`.

## Suites

### Unit binary

`DetourModKit_tests` compiles `tests/main.cpp` (the GoogleTest entry point), every `tests/test_*.cpp`, and `tests/fixtures/hook_fixture.cpp`.

| File | Owned surface |
| --- | --- |
| `test_alloc_probe.cpp` | Allocation operator replacement (`test_alloc_probe.hpp`) |
| `test_anchor.cpp` | Resolver core, `ScanProfile`, domains, loader boundary |
| `test_anchor_export.cpp` | `ExportName`, `scan::resolve_export`, `scan::image_identity` |
| `test_anchor_fingerprint.cpp` | `anchor_fingerprint`, `anchor_trust_fingerprint` |
| `test_anchor_gate.cpp` | `assess_quality`, `evaluate_gate` |
| `test_anchor_quorum.cpp` | Quorum corroboration, independence gate |
| `test_anchor_trust.cpp` | Trust transaction, witness, same-base module replacement |
| `test_async_logger.cpp` | Async queue, `StringPool`, `LogMessage` |
| `test_bench_alloc.cpp` | `bench_alloc.hpp` counters |
| `test_code_constant.cpp` | `scan::read_code_constant`, epoch checks |
| `test_config.cpp` | Registration, INI parse, reload, `BindingGuard`, `HoldGate` |
| `test_config_reload_quiesce.cpp` | Reload quiesce and rearm |
| `test_config_watcher.cpp` | File watcher, loader-lock teardown |
| `test_defines.cpp` | `DMK_NO_NAMESPACE_ALIASES` |
| `test_diagnostics.cpp` | Snapshot, event bus, hook events, module pins, counters |
| `test_drain_backoff.cpp` | `detail::drain_until_zero` |
| `test_drift_manifest.cpp` | Drift manifest serialize and parse, files, UTF-8 paths |
| `test_event_dispatcher.cpp` | Copy-on-write snapshot, emit owner release |
| `test_filesystem.cpp` | Runtime paths, UTF-8, loader boundary |
| `test_format.cpp` | The `format::` helpers in `format.hpp` |
| `test_foundation.cpp` | `Address`, `Region`, error codes, `DMK_TRY` |
| `test_gate_race_probe.cpp` | Hook ledger and input gates under contention |
| `test_heal_scheduler.cpp` | `HealScheduler`, healed slots |
| `test_hook.cpp` | Install core, `mid_at`, `install_all`, ledger, publication |
| `test_hook_backend.cpp` | Backend transactions, exception containment |
| `test_hook_fault_proof.cpp` | Every hook `*FaultProof` suite |
| `test_hook_inline.cpp` | `inline_at`, prologue policy, duplicates, `Hook::call` |
| `test_hook_integration.cpp` | Hooks on `hook_target_lib.dll` |
| `test_hook_loader.cpp` | Hook loader-lock boundary |
| `test_hook_teardown.cpp` | Toggle and teardown, `HookStack`, in-flight drain |
| `test_hook_vmt.cpp` | `vmt_for`, `apply_to`, `remove_from`, method hooks |
| `test_input.cpp` | Binding registration and query core, `KeyStateCache` |
| `test_input_codes.cpp` | `InputCode` and `Trigger` names, `InputCodeHash` |
| `test_input_consume.cpp` | The consume flag |
| `test_input_gate.cpp` | `PressGate`, `HoldGate`, delivery marker |
| `test_input_intercept.cpp` | Wheel and XInput interception, live OS hooks |
| `test_xinput_raw_scope.cpp` | Shared raw depth, original buttons, expected returns, poison, descriptor validation, faults, and final release |
| `test_xinput_route_probe.cpp` | Exact receipt identity, nested numeric tokens, epoch and thread rejection, and lease rundown |
| `test_input_lifecycle.cpp` | Binding teardown, unload drain, poller shutdown |
| `test_input_loader.cpp` | Input loader-lock boundary |
| `test_input_pending.cpp` | Bindings staged before `start()` |
| `test_input_reshape.cpp` | Rebind, `update_combos`, hot reload |
| `test_input_wheel.cpp` | Wheel notch counts in the poll loop |
| `test_logger.cpp` | `Logger` facade, async mode, writer live count |
| `test_manifest.cpp` | Parse, compile, overlay, serialize, adopt |
| `test_math.cpp` | `math.hpp` |
| `test_memory.cpp` | Guarded reads, fault frame, typed-read gates |
| `test_memory_cache.cpp` | Protection queries, region cache |
| `test_memory_chain.cpp` | Pointer chains, plausibility |
| `test_memory_module.cpp` | `module_of`, `Region` module views, loader boundary |
| `test_memory_representation.cpp` | Compile-time typed-read matrix |
| `test_memory_write.cpp` | Writes, `patch_code`, `ProtectGuard` |
| `test_mid_drain.cpp` | Mid-hook teardown drain |
| `test_mid_hook_context.cpp` | `MidContext`, mid-hook rundown, capacity |
| `test_noexcept_containment.cpp` | Standard-lock exception facts |
| `test_pattern.cpp` | `Pattern` compile, variable-gap jumps |
| `test_platform.cpp` | Loader-lock probe, module references, `version.hpp` macros |
| `test_profile_ring.cpp` | `ProfileRing` |
| `test_profiler.cpp` | Profiler records, loader boundary |
| `test_rtti.cpp` | RTTI walker, image generation |
| `test_rtti_dissect.cpp` | RTTI dissector, healed offsets |
| `test_rtti_reverse.cpp` | Type-to-vtable lookup |
| `test_scan_resolve.cpp` | `scan::resolve` |
| `test_scanner.cpp` | Scanner, RIP-relative resolve, prologues, region classes |
| `test_scanner_parallel.cpp` | `scan::resolve_batch` |
| `test_scanner_trust.cpp` | Scan trust, exclusions |
| `test_session.cpp` | `Session`, bootstrap, teardown, hot reload |
| `test_session_header.cpp` | `session.hpp` compiles alone |
| `test_sighealth.cpp` | Signature health |
| `test_srw_shared_mutex.cpp` | `SrwSharedMutex` |
| `test_string.cpp` | `string::trim` in `format.hpp` |
| `test_string_xref.cpp` | `scan::find_string_xref` |
| `test_trap_protect.cpp` | Per-region protection restore |
| `test_unchecked_find_pattern_alloc.cpp` | `scan::unchecked::find_pattern` allocations |
| `test_version.cpp` | `version.hpp` macros |
| `test_wheel_host_loader.cpp` | Wheel-host client through the input API |
| `test_win_file_stream.cpp` | `WinFileStream` |
| `test_worker.cpp` | `StoppableWorker`, lifecycle reaper |
| `test_x86_decode.cpp` | x86 decoder |

### Shared fixtures

- `anchor_fixture.hpp`, `hook_fixture.hpp`, `input_fixture.hpp`, and `memory_fixture.hpp` hold the fixtures that the split files of one module share. `hook_fixture.cpp` defines the shared hook targets once.
- `proof_section.hpp`: `DMK_PROOF_TARGET`, `DMK_TEST_NOINLINE`, `dmk_test::call_unfolded`.
- `fault_injection.hpp`: no-access, protected, and executable pages for fault proofs.
- `loader_lock_scope.hpp`, `log_capture.hpp`, `intercept_lease.hpp`, `scratch_page.hpp`, `throwing_copy.hpp`: the forced loader-lock probe, logger capture, an interception-layer lease, an executable scratch page, and a callable whose copy throws.
- `hook_target_lib.cpp` and `.def`: the `hook_target_lib.dll` export fixture.
- `rtti_generation_fixture.cpp` and `.hpp`: the fixed-base RTTI DLL and its two same-base variants.

### Other tests/ sources

| Source | Role |
| --- | --- |
| `wheel_host_isolated_proof.cpp` | `DetourModKit_wheel_host_tests`: the `WheelHost` C ABI with no DetourModKit archive |
| `asan_failure_probe.cpp` | The dispatch control for MSVC ASan, never a CTest case |
| `bench_*`, `corpus_sighealth.cpp` | `DMK_BUILD_BENCHMARKS` drivers and headers. `bench_gate.hpp` also builds `dmk_bench_gate_probe`. |
| `package_smoke/`, `package_build_tree/`, `package_dual_config/` | Consumer projects: `find_package` on an installed package, `add_subdirectory`, Debug and Release from one prefix |

### tests/fault

`tests/fault/CMakeLists.txt` builds `fault_tests` from `tests/fault/test_*.cpp`. It also builds the raw host `fault_scanner_escape_probe`.

| Source | Owned surface |
| --- | --- |
| `test_fault_containment.cpp` | Guarded read, walk, and write fail closed on a no-access page |
| `test_faststring_straddle.cpp` | Write-fault classification of a store across a page boundary |
| `fault_scanner_escape_probe.cpp` | Scanner sweeps contain an in-span fault and let an out-of-span fault escape |

### tests/lifecycle

`tests/lifecycle/CMakeLists.txt` registers each case beside its host.

| Sources | Owned surface |
| --- | --- |
| `timeout_probe.cpp`, `fast_fail_probe.cpp` | The `timeout-control` cases, the WER crash control of the soak |
| `test_hook_static_order.cpp`, `vmt_late_static_owner.cpp`, `never_destroyed_storage.cpp`, `diagnostics_late_emitter.cpp`, `test_profiler_late_uaf.cpp` | Static-destruction order, calls after static teardown |
| `*_oom.cpp`, `first_use_oom_poison.hpp` | First-use allocation failure, writer progress after a failed batch reservation |
| `test_trap_closed_window.cpp`, `vmt_unreadable_header.cpp`, `test_hook_instance_scope.cpp`, `hook_kit_dll.cpp` | Closed trap window, unreadable module header, per-instance ledger |
| `test_mid_route_retention.cpp`, `route_*`, `routed_bypass_*` | Route reclamation, retention, continuation, process route coordinator |
| `veh_*.cpp` | MinGW guarded-read handler after an unmap |
| `tls_*`, `process_exit_release_dll.cpp`, `input_tls_exhaustion.cpp` | Image-owned TLS return, native allocation isolation, input delivery with no TLS index |
| `input_reshape_retirement.cpp`, `test_input_gate_abba.cpp`, `input_control_thread_shutdown.cpp`, `input_self_shutdown.cpp`, `*input_loader_detach*`, `input_seam_cleanup.hpp` | Reshape disposal, gate teardown, shutdown from a callback, loader detach |
| `xinput_*` | Hook lifetime, paired exact and observed routes, raw samples across ten independent copies |
| `cache_shutdown_stall.cpp` | Cache shutdown with a stalled reader |
| `*bootstrap*`, `session_detach_terminal.cpp`, `test_full_lifecycle.cpp`, `test_config_servicer_self_retire.cpp` | Bootstrap module reference, detach after a drain, full lifecycles, servicer self-retirement |
| `*logic_*` | Logic-DLL unmap after typed teardown |
| `staged_generation_*` | Staged-generation reload |
| `logger_generation_log.cpp`, `legacy_acp*` | Log file across generations, paths outside the ANSI code page |
| `test_dispatch_cow.cpp` | Re-entrant `EventDispatcher` writer |
| `raw_proof_error_mode.hpp` | Fault dialog suppression for raw hosts |

TLS refusal proofs override only the executable import cell. Windows DLLs retain their native allocator. Each failure window verifies late CoreMessaging initialization and native TLS use on a new host thread. Delivery refusal, consume disarm, hook error, and recovery assertions remain mandatory.

`Lifecycle.RoutedBypassDrainsBeforeReclaim` keeps both workers alive and waits for the caller's full return before native suspension. The caller returns to a separate driver fiber stack before its native event wait. The provider resumes after a drain pause, without a fixed time delay. `Lifecycle.RoutedBypassWaitsForCompleteCallerReturn` delays the return notice until the first scan requests it. `Lifecycle.RoutedBypassRetainsAfterThreadExitDuringScan` verifies native suspension refusal and charged retention after a snapshotted caller exits. Each route uses a 30-second timeout.

The foreign XInput proof counts explicit host probes by native thread identity. `Lifecycle.StagedGenerationForeignXInputSeparatesBackgroundProbes` verifies a concurrent caller without a change to the exact host count or retained pair assertions.

The XInput diagnostic routes use `xinput_layered_consume` as separate required `lifecycle-proof` processes. Each route has a 60-second timeout.

| Required process | Scenario |
| --- | --- |
| `Lifecycle.XInputDisconnectedStartupRecoversThroughForwarders` | `disconnected-startup` |
| `Lifecycle.XInputObservedPairReconnectReportsOneRecovery` | `observed-reconnect` |
| `Lifecycle.XInputPrimaryFailureReportsTheExactCheck` | `diagnostics-primary` |
| `Lifecycle.XInputExFailureReportsTheExactCheck` | `diagnostics-ex` |
| `Lifecycle.XInputExactHandBackReportsOneRecovery` | `exact-recovery` |
| `Lifecycle.XInputScopeFailureReportsPairCause` | `diagnostics-scope` |

## Staged example proof

`staged_example_reload.cpp` exercises the checked-in loader and logic through required `Lifecycle.StagedExample*` processes. The [hot-reload proof table](../guides/hot-reload/README.md#proof-pointers) defines each scenario. These processes require a wheel host and a synthetic controller, with no game or hardware dependency. Each process has a 60-second timeout.
