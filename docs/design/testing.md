# Test architecture design

This note explains test architecture. The related rulebook entries live in the [AGENTS.md Testing section](../../AGENTS.md#testing).

## Unique temporary files

CTest can run cases as separate parallel processes. A process ID separates concurrent cases. A counter separates multiple files from one process. `tests/test_manifest.cpp` shows the required name components.

## Hot-path proof inventory

The performance list in `AGENTS.md` defines the protected scope. The proof sources are:

- `EventDispatcherTest.EmitDoesNotAllocate` checks the subscribed dispatcher path.
- `LoggerTest.FormattedAsyncLog_FitsInlineBufferWithoutHeapAllocation` checks an inline asynchronous log record.
- The [events note](events.md) states the dispatcher snapshot mechanism.
- The [input note](input.md) states the poll-path synchronization.
- The [logging note](logging.md) states the queue and sink mechanisms.
- The [memory note](memory-scanning.md) states the cache and guarded-memory mechanisms.
- [`rtti.hpp`](../../include/DetourModKit/rtti.hpp) states the allocation and read bounds for `vtable_is_type`.
- The same header states the pointer-table warm path and `TypeIdentity` cache contracts.
- `MemoryWalk.IntermediateHopsEachIssueOneGuardedRead` pins one guarded read for each intermediate hop.
- `MemoryWalk.IdentityAndLeafOnlyWalksIssueNoGuardedRead` pins zero guarded reads for an identity or leaf-only walk.
- `RttiReverseProof.VtableIsTypeIssuesThreeGuardedReadsNotOne` pins the `vtable_is_type` guarded-read count.
- `RttiTest.FindInTable_WarmCacheRevalidatesGenerationTwicePerCall` pins the two generation probes on the
  `PointerTableCache` warm path.
- `RttiReverseProof.TypeIdentityWarmMatchesRevalidatesGenerationEachCall` pins the one generation probe for each warm
  `TypeIdentity::matches`.
- `RttiReverseProof.TypeIdentityWarmMatchesReadsPeHeaders` pins the guarded PE-header reads that probe costs.

Code review compares every other hot-path change against this inventory.

## Lock-order proof locations

Class headers own each multi-lock order. These headers state the current orders:

- [`logger.hpp`](../../include/DetourModKit/logger.hpp) states the logger order.
- [`input_intercept.hpp`](../../src/internal/input_intercept.hpp) states the intercept order.

The subsystem notes describe the related concurrency models.

## Rules

### Test seams compile out of shipping builds

**Test seams must compile out of shipping builds.** A `src/` translation unit may carry a test-only seam -- a null `*_test_hook` function pointer, a `*_for_test` / `seed_*_for_test` helper, or an internal injection point -- ONLY when its definition AND every fire site are wrapped in `#if defined(DMK_ENABLE_TEST_SEAMS)`. That macro is a PRIVATE compile definition set on the `DetourModKit` library and the test targets only when `DMK_BUILD_TESTS` is ON (see the root and `tests/` CMakeLists), so a shipping or installed archive (tests off) contains no test-only symbol or branch at all -- not even a null pointer or a never-taken null check. An UNGATED test-only symbol, present even as a null/no-op in a release build, is not allowed. A gated seam must be null/no-op by default and driven only by a test that sets it before starting the participating threads and clears it after they join. **That publication rule is frozen and binds every exit path, not just the passing one.** The threads read these objects without synchronization, so replacing one under a live loop destroys a callable mid-call, and returning from a scope a callback captured by reference destroys its payload underneath it -- either turns an intended red diagnostic into a native access violation or a hang, which reports as a different failure than the one the proof states. A raw host therefore owns the order structurally rather than repeating it at each `return`: unblock parked callback work, run down and join, then clear. `tests/lifecycle/input_seam_cleanup.hpp` is that owner for the input hosts. Two traps: a callback parked on another callback's flag never returns, so a join without the unblock wedges instead of failing; and `Input::shutdown()` reached from a binding callback hands its rundown to the process reaper and returns before it has been delivered, so "the engine reads as stopped" is not evidence that a callback cannot still run. Each affected host carries a bounded negative control that abandons a premise on purpose and asserts released, still-installed, stopped, then cleared -- reading the seam from inside the parked callback, which is the only vantage point that can observe the order rather than the outcome. Prefer no seam when a concurrency-stress test, a `tests/fault` / `tests/lifecycle` proof, or a real-`LoadLibrary`/subprocess host can reach the behavior. (The seams in `config.cpp`, `input_intercept.*`, and `session.cpp` are all gated; `scripts/check_no_test_seams.py` scans the shipped MinGW and MSVC archives in the release workflow and fails the release if a `*_for_test`, `*_test_hook`, `g_*_override` or `g_*_probe` symbol survives. An injection point named outside those shapes is caught by review, not by that gate, so prefer one of them when you must add a seam.)

### A must-fault test holds a committed PAGE_NOACCESS page

**A "must fault" test needs a committed `PAGE_NOACCESS` page held until teardown, never a `MEM_RELEASE`d region:** a released VA can be recycled and remapped by allocations the spawning threads trigger (stacks / TEBs, more so under ASan), so the read lands on live memory and flakes. See `AsyncMode_ConcurrentLogAndDisable` in `test_logger.cpp` for the concurrent-test pattern. The reusable `tests/fixtures/fault_injection.hpp` provides `dmk_test::NoAccessPage` (a leaked-on-purpose committed no-access page) and `ProtectedPage` (a page pinned to a chosen protection, for asserting a fault path restored it).

### Fault-injection fixtures live in tests/fault/

**Fault-injection fixtures do NOT go in the `tests/test_*.cpp` glob.** Adding a source there forces a `CONFIGURE_DEPENDS` reconfigure that rebuilds the main C++23 test target. Put them in `tests/fault/test_*.cpp`; `tests/fault/CMakeLists.txt` compiles them into the `fault_tests` proof target linked against the archive, and `gtest_discover_tests` registers each case as its own ctest test under the `fault-proof` label with a real execution timeout. `CONFIGURE_DEPENDS` picks up a new fault TU without adding it to the monolithic target. Build and run the complete target set with `bash scripts/run_fault_tests.sh` (any configured tests-ON tree, MinGW or MSVC), or build `fault_tests` plus `fault_scanner_escape_probe` and run `ctest -L fault-proof` directly. `tests/fault/CMakeLists.txt` carries no toolchain gate: MSVC contains a fault in a frame-based `__try`/`__except` and MinGW x64 in the process-wide vectored handler, and a gate around the directory leaves whichever mechanism it excludes unproven. Give the case a per-compiler arm instead, and state the expectation each arm proves -- MSVC's frame nesting is a structural property of SEH, MinGW's is the thread-local guard slot being restored rather than cleared, and a shared body with one expectation silently asserts only the MinGW mechanism. A proof whose subject is an escaping fault (one the guard must NOT claim) cannot live in the shared GoogleTest process at all: put it in a `tests/fault/` raw host whose exit status is the oracle, as `fault_scanner_escape_probe.cpp` does for the two scanner spans.

### Lifecycle standalone fixtures live in tests/lifecycle/

**Lifecycle standalone fixtures do NOT go in the `tests/test_*.cpp` glob either.** A fixture that needs a real loader transition (`LoadLibrary`/`FreeLibrary` reference-count behavior, `DLL_PROCESS_DETACH`) or a controlled static-teardown ordering (one replaces global `operator new`/`delete` for the whole process) cannot run inside the monolithic GoogleTest process. Put it in `tests/lifecycle/`; `tests/lifecycle/CMakeLists.txt` builds the CMake-owned targets (the mod-shaped probe DLL links the archive; the loader host and the profiler use-after-free driver link no library, and that driver compiles `src/profiler.cpp` directly so its poisoning allocator governs the ring buffer) and registers each as a `lifecycle-proof`-labelled ctest whose verdict is the process exit code. Build and run with `bash scripts/run_lifecycle_proofs.sh`, or build the lifecycle targets and run `ctest -L lifecycle-proof` directly. A fixture proving language, allocation, or OS behavior runs on both toolchains: static-destruction order, first-use OOM, and the `LoadLibrary`/`FreeLibrary` reference-count and `DLL_PROCESS_DETACH` proofs, since loader reference counting is an OS property and the archive links into a SHARED target under both toolchains. `tests/lifecycle/CMakeLists.txt` therefore has no toolchain gate at all, and neither does `tests/fault/CMakeLists.txt`; a fixture whose subject is genuinely toolchain-specific (MinGW emulated-TLS behavior, for example) needs its own per-compiler arm or a separate counterpart, never a gate that removes the case from the other toolchain.

### Proxy-sensitive OOM contracts route around MSVC debug iterators

**Proxy-sensitive out-of-memory contracts route around MSVC debug iterators.** MSVC's debug STL (`_ITERATOR_DEBUG_LEVEL >= 1`, the `/MDd` default) allocates a hidden `_Container_proxy` inside noexcept container constructors, which derails exact-budget OOM injection; the library never overrides `_ITERATOR_DEBUG_LEVEL` (see `[B-93]`), so a gtest that arms `dmk_test::AllocFailScope` calls `DMK_REQUIRE_PROXY_FREE_STL()` (from `tests/test_alloc_probe.hpp`) as its first statement, and a lifecycle first-use-OOM host returns 77 (`SKIP_RETURN_CODE`) for its OOM modes under those conditions. Allocation-free steady-state tests remain active because they do not arm the injector. The injected contracts stay proven on libstdc++ in every configuration and on the naturally proxy-free MSVC release STL, which the release pipeline's Release-with-tests ctest lane runs.

### Proof wrappers select the configured MinGW runtime

**Proof wrappers select the configured MinGW runtime.** All three run `scripts/resolve_runtime_dir.py`, which reads the absolute compiler path CMake recorded in `CMakeFiles/<version>/CMakeCXXCompiler.cmake` and prints the directory to prepend before launching CTest, or nothing for an MSVC tree. A working Python interpreter is a hard dependency of every wrapper; the shell wrappers take it from the tree's `DMK_PYTHON_EXECUTABLE` and fall back to a `python3` or `python` that has been shown to execute. Do not read `CMAKE_CXX_COMPILER` out of `CMakeCache.txt`: a preset leaves that entry as the bare string `g++` or `cl`, so every basename or dirname test against it answers a question the cache cannot answer. Do not replace the prepend with a first-`g++` check: another MinGW distribution can appear earlier on `PATH` and supply an ABI-incompatible `libwinpthread-1.dll` to a probe DLL. Do not extend the prepend to an MSVC tree either: `cl.exe`'s directory carries private `msvcp140` / `vcruntime140` copies that would shadow the system CRT for every proof process.

### A scripts/ self-test is Windows-on-Windows

**A `scripts/` self-test is a Windows-on-Windows script, not a portable one.** The build is Win64 only (every library translation unit includes `<windows.h>`, the link list carries `psapi` / `dbghelp` / `ntdll` / `xinput`, and no lane configures on another OS), so a CTest registration only ever exists in a Windows tree. A self-test may import `winreg` or any other Windows-only module at module scope with no platform guard and no gated registration. Inside an `except` block these suites raise a bare `AssertionError`: implicit `__context__` chaining already prints the caught exception, and `raise ... from err` would label a wrong-exception mismatch as the direct cause of the assertion, which is the opposite of what happened.

### A proof label needs an inventory gate

**A proof label needs an inventory gate, registered outside the directory it gates.** `ctest -L <label>` exits zero on an empty selection, so a toolchain gate, a renamed case, or a host that was never registered removes the coverage and still reports green. Declare the label's cases to `scripts/check_test_label_inventory.py` (`--require` per name, `--minimum`, `--expect-target` for a `gtest_discover_tests` target whose `_NOT_BUILT` placeholder means it was never built) and register that check as a ctest carrying the same label -- from `tests/CMakeLists.txt`, never from the subdirectory it covers, because a gate the skipped subdirectory also skips proves nothing. `FaultProof.LabelInventoryIsComplete` is the worked example. Related: `dmk_add_raw_proof` declares no build dependency, so a workflow that builds targets by name must list every raw host or the ctest is registered and never built.

### CTest execution timeouts

`CTestTimeoutControl` is the proof pointer. [The test coverage guide](../tests/README.md) owns the CTest timeout contract.

### Most regression guards belong in regular test_*.cpp cases

**Most regression guards belong in regular `test_*.cpp` cases.** When a fix needs an empirical reproduction or regression guard that can share the main test process, add it as an ordinary GoogleTest case in the matching `test_<module>.cpp` -- a low-address `VirtualAlloc` fixture, a `PAGE_GUARD` page, an `is_lock_free()` probe, and the like all run fine in the monolithic suite (see `ScannerRipTest.find_and_resolve_skips_implausible_decoy_and_finds_genuine_site` and `EventDispatcherTest.AtomicSharedPtrIsNotLockFree`). Do NOT add a separate regression-test directory or a dedicated executable for in-process checks. Reach for the `tests/fault/` or `tests/lifecycle/` proof targets ONLY when the fixture genuinely needs a leaked `PAGE_NOACCESS` page, a global `operator new`/`delete` override, or a real loader / teardown event that cannot share the test process.

### Inject faults into the foreign target the guard arms

**Inject a fault into the FOREIGN target the guard arms, not a write's source.** Both guards confine their claim to the range an operation explicitly touches -- the target of a read / walk / in-place write -- and let a fault outside it reach the host, so a genuine out-of-range bug is not swallowed. A guarded write's SOURCE span is caller-owned and trusted: a faulting source is a caller-contract violation and is uncontained on either toolchain, so a source-fault test crashes rather than failing closed. This is also why the escalating write slow-path copy-fault arm is not deterministic single-threaded -- once the slow path has made the target writable, only a concurrent reprotect can fault the copy.

### VmtHook declaration order

**A `VmtHook` restores the object's vptr in its destructor,** so declare the handle AFTER the target it clones (`auto target = ...; VmtHook vh = ...`) so reverse-order destruction restores the vptr first, and clear any global the detour reaches (for example a live `VmtHook*`) before the handle drops.

### Poll-loop probe seams install stopped, clear after join

**A poll-loop `std::function` seam is installed only while the poller is stopped and cleared only after it is joined.** `g_input_key_state_probe`, `g_input_post_stage_probe`, and `g_input_pre_dispatch_probe` are plain globals the poll loop reads and calls every cycle with no synchronization. Assign them before `poller.start()`, arm whatever phase the probe parks on through a separate atomic afterwards, and clear them only once the poll thread is joined. The probe's captures are the case's barrier atomics, so declare those BEFORE the poller and the cleanup owner AFTER it, so every exit path -- a fatal `ASSERT_`, a premise failure, or the end of the case -- opens any parked dispatch, joins, and only then destroys the probe. Getting this wrong writes over a `std::function` the poll loop is executing and frees a parked frame's barriers: it surfaces as an intermittent native access violation, not as a failed expectation, and the GoogleTest launcher renders it as a CMake diagnostic that must never be normalized as a CMake-only failure. `tests/test_input.cpp`'s `StagedProbeCleanup` is the shared owner and `InputLifecycleProof.StagedProbeCleanupJoinsBeforeDestroyingProbeCaptures` is its control.

### No fatal GoogleTest assertion off the main thread

**A test thread never carries a fatal GoogleTest assertion, and a cross-thread barrier always has a deadline.** `ASSERT_*` and `FAIL()` off the main thread return from the enclosing lambda instead of failing the case, so the work after them is skipped and whatever the main thread is waiting for never happens. Report the worker's outcome through an atomic and assert it on the main thread, and give every wait on a worker-set flag a `steady_clock` deadline that opens any barrier the worker could be parked on, joins, and fails with the premise it could not establish. An unbounded spin here wedges the whole shared unit binary with no diagnostic. `BindingGateTest.UnrelatedThreadStillWaitsOutAnotherThreadsTeardownSpan` is the local pattern.

### White-box internal suites

**White-box internal suites** (`test_x86_decode` over `src/x86_decode.hpp`, `test_input_intercept` over `src/internal/input_intercept.hpp`) add `src/` to their include path and call `DetourModKit::detail::` directly. `test_gate_race_probe` is a concurrency-stress white-box suite over the two header-only synchronization primitives (`src/internal/hook_ledger.hpp` and `src/internal/input_binding_gate.hpp`): it drives real cross-thread contention on the install/teardown ledger and the input hold/press gates. It runs in the main suite (per the in-process rule above) but stays independent of the library's compiled surface so the same source remains usable by standalone race-instrumented builds that cannot link the Windows-only library.
