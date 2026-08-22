# Test architecture design

This note explains test architecture. The related rulebook entries live in the [AGENTS.md Testing section](../../AGENTS.md#testing).

Rules owned here: none. This note owns the test-architecture conventions that the rulebook points at.

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
- `RttiTest.FindInTable_WarmCacheRevalidatesGenerationTwicePerCall` pins the two generation probes on the `PointerTableCache` warm path.
- `RttiReverseProof.TypeIdentityWarmMatchesRevalidatesGenerationEachCall` pins the one generation probe for each warm `TypeIdentity::matches`.
- `RttiReverseProof.TypeIdentityWarmMatchesReadsPeHeaders` pins the guarded PE-header reads that probe costs.

Code review compares every other hot-path change against this inventory.

## Lock-order proof locations

Class headers own each multi-lock order. These headers state the current orders:

- [`logger.hpp`](../../include/DetourModKit/logger.hpp) states the logger order.
- [`input_intercept.hpp`](../../src/internal/input_intercept.hpp) states the intercept order.
- [`hook.hpp`](../../include/DetourModKit/hook.hpp) states the hook toggle order.

The subsystem notes describe the related concurrency models.

## Rules

### Test seams compile out of shipping builds

A `src/` translation unit can carry a test-only seam ONLY when its definition AND every fire site sit inside `#if defined(DMK_ENABLE_TEST_SEAMS)`. A seam is a null `*_test_hook` function pointer, a `*_for_test` / `seed_*_for_test` helper, or an internal injection point. That macro is a PRIVATE compile definition (see the root and `tests/` CMakeLists). It is set on the `DetourModKit` library and the test targets only when `DMK_BUILD_TESTS` is ON. A shipping or installed archive (tests off) therefore contains no test-only symbol or branch at all. Not even a null pointer or a never-taken null check survives. An UNGATED test-only symbol, present even as a null/no-op in a release build, is not allowed.

A gated seam must be null/no-op by default. Only a test drives it: the test sets it before the participating threads start and clears it after they join. That publication rule is frozen and binds every exit path, not only the passing one. The threads read these objects without synchronization. A replacement under a live loop destroys a callable mid-call. A return from a scope that a callback captured by reference destroys its payload underneath it. Either turns an intended red diagnostic into a native access violation or a hang. That reports as a different failure than the one the proof states.

A raw host therefore owns the order structurally rather than repeats it at each `return`: unblock parked callback work, run down and join, then clear. `tests/lifecycle/input_seam_cleanup.hpp` is that owner for the input hosts. Two traps:

- A callback parked on another callback's flag never returns, so a join without the unblock wedges instead of fails.
- `Input::shutdown()` reached from a binding callback hands its rundown to the process reaper and returns before the rundown is delivered. "The engine reads as stopped" is therefore not evidence that a callback cannot still run.

Each affected host carries a bounded negative control that abandons a premise on purpose and asserts released, still-installed, stopped, then cleared. The control reads the seam from inside the parked callback, the only vantage point that observes the order rather than the outcome.

Prefer no seam when a concurrency-stress test, a `tests/fault` / `tests/lifecycle` proof, or a real- `LoadLibrary` /subprocess host can reach the behavior. The seams in `config.cpp`, `input_intercept.*`, and `session.cpp` are all gated. `scripts/check_no_test_seams.py` scans the shipped MinGW and MSVC archives in the release workflow and fails the release if a `*_for_test`, `*_test_hook`, `g_*_override`, or `g_*_probe` symbol survives. Review, not that gate, catches an injection point named outside those shapes, so prefer one of those shapes when you must add a seam.

### A must-fault test holds a committed PAGE_NOACCESS page

A "must fault" test needs a committed `PAGE_NOACCESS` page held until teardown, never a region released with `MEM_RELEASE`. The spawned threads' own allocations (stacks and TEBs, more so under ASan) can recycle and remap a released VA. The read then lands on live memory and flakes. See `AsyncMode_ConcurrentLogAndDisable` in `test_logger.cpp` for the concurrent-test pattern. The reusable `tests/fixtures/fault_injection.hpp` provides `dmk_test::NoAccessPage`, a leaked-on-purpose committed no-access page. It also provides `ProtectedPage`, a page pinned to a chosen protection, for an assertion that a fault path restored it.

### Fault-injection fixtures live in tests/fault/

Fault-injection fixtures do NOT go in the `tests/test_*.cpp` glob. A source added there forces a `CONFIGURE_DEPENDS` reconfigure that rebuilds the main C++23 test target. Put them in `tests/fault/test_*.cpp`. `tests/fault/CMakeLists.txt` compiles them into the `fault_tests` proof target linked against the archive. `gtest_discover_tests` registers each case as its own ctest test under the `fault-proof` label with a real execution timeout. `CONFIGURE_DEPENDS` picks up a new fault TU without an entry in the monolithic target.

Build and run the complete target set with `bash scripts/run_fault_tests.sh` (any configured tests-ON tree, MinGW or MSVC), or build `fault_tests` plus `fault_scanner_escape_probe` and run `ctest -L fault-proof` directly.

`tests/fault/CMakeLists.txt` carries no toolchain gate. MSVC contains a fault in a frame-based `__try` / `__except` and MinGW x64 in the process-wide vectored handler. A gate around the directory leaves whichever mechanism it excludes unproven. Give the case a per-compiler arm instead, and state the expectation that each arm proves. MSVC's frame nesting is a structural property of SEH. MinGW's is the thread-local guard slot restored rather than cleared. A shared body with one expectation silently asserts only the MinGW mechanism.

A proof whose subject is an escaping fault (one the guard must NOT claim) cannot live in the shared GoogleTest process at all. Put it in a `tests/fault/` raw host whose exit status is the oracle, as `fault_scanner_escape_probe.cpp` does for the two scanner spans.

### Lifecycle standalone fixtures live in tests/lifecycle/

Lifecycle standalone fixtures do NOT go in the `tests/test_*.cpp` glob either. A fixture that needs a real loader transition (`LoadLibrary` / `FreeLibrary` reference-count behavior, `DLL_PROCESS_DETACH`) cannot run inside the monolithic GoogleTest process. Neither can a controlled static-teardown ordering, where one fixture replaces global `operator new` / `delete` for the whole process. Put it in `tests/lifecycle/`. `tests/lifecycle/CMakeLists.txt` builds the CMake-owned targets and registers each as a `lifecycle-proof` -labeled ctest whose verdict is the process exit code. The mod-shaped probe DLL links the archive. The loader host and the profiler use-after-free driver link no library, and that driver compiles `src/profiler.cpp` directly so its poisoning allocator governs the ring buffer. Build and run with `bash scripts/run_lifecycle_proofs.sh`, or build the lifecycle targets and run `ctest -L lifecycle-proof` directly.

A fixture that proves language, allocation, or OS behavior runs on both toolchains: static-destruction order, first-use OOM, and the `LoadLibrary` / `FreeLibrary` reference-count and `DLL_PROCESS_DETACH` proofs. Loader reference counting is an OS property, and the archive links into a SHARED target under both toolchains. `tests/lifecycle/CMakeLists.txt` therefore has no toolchain gate at all, and neither does `tests/fault/CMakeLists.txt`. A fixture whose subject is genuinely toolchain-specific (MinGW emulated-TLS behavior, for example) needs its own per-compiler arm or a separate counterpart. It never gets a gate that removes the case from the other toolchain.

### A case that mutates a process-wide singleton restores it or owns a host

A proof case gets a private process under ctest, and no gate states that. `cmake/DMKTesting.cmake` registers the unit binary through `gtest_discover_tests`, so each of its ctest entries runs alone. A green `ctest` therefore proves nothing about the binary run whole. Run `DetourModKit_tests.exe` directly as well, on both toolchains, and report the count.

A case that mutates a process-wide singleton must restore that singleton in teardown. When the mutation is terminal, the case must move to its own `tests/lifecycle/` proof host instead. Three singletons carry this rule today:

- The `StringPool` free list (`src/internal/async_logger_queue.hpp`) is never destroyed, and a recycled slot keeps its `std::string` capacity. An allocation-failure injection therefore must use a size above `MAX_POOLED_STRING_SIZE` , which no earlier case can pre-satisfy.
- The lifecycle reaper counters behind `diagnostics::lifecycle_counters` are monotonic. A case asserts a delta, or a process-lifetime absolute, never a zero start value.
- `bootstrap_detach` moves the bootstrap slot to a terminal `Detached` state that nothing reverses. `Lifecycle.DetachAfterDrainRevokesBlockingAuthorization` therefore owns its own host.

### Proxy-sensitive OOM contracts route around MSVC debug iterators

MSVC's debug STL (`_ITERATOR_DEBUG_LEVEL >= 1`, the `/MDd` default) allocates a hidden `_Container_proxy` inside noexcept container constructors, which derails exact-budget OOM injection. The library never overrides `_ITERATOR_DEBUG_LEVEL` (see `[B-93]`). A gtest that arms `dmk_test::AllocFailScope` therefore calls `DMK_REQUIRE_PROXY_FREE_STL()` (from `tests/test_alloc_probe.hpp`) as its first statement. A lifecycle first-use-OOM host returns 77 (`SKIP_RETURN_CODE`) for its OOM modes under those conditions. Allocation-free steady-state tests remain active because they do not arm the injector. The injected contracts stay proven on libstdc++ in every configuration and on the proxy-free MSVC release STL. The release pipeline's Release-with-tests ctest lane runs the latter.

### Proof wrappers select the configured MinGW runtime

All three proof wrappers run `scripts/resolve_runtime_dir.py`. It reads the absolute compiler path that CMake recorded in `CMakeFiles/<version>/CMakeCXXCompiler.cmake`. It prints the directory to prepend before CTest launches, or nothing for an MSVC tree. A working Python interpreter is a hard dependency of every wrapper. The shell wrappers take it from the tree's `DMK_PYTHON_EXECUTABLE` and fall back to a `python3` or `python` that demonstrably executes.

- Do not read `CMAKE_CXX_COMPILER` out of `CMakeCache.txt`. A preset leaves that entry as the bare string `g++` or `cl`. Every basename or dirname test against it answers a question the cache cannot answer.
- Do not replace the prepend with a first- `g++` check. Another MinGW distribution can appear earlier on `PATH` and supply an ABI-incompatible `libwinpthread-1.dll` to a probe DLL.
- Do not extend the prepend to an MSVC tree either. `cl.exe`'s directory carries private `msvcp140` / `vcruntime140` copies that shadow the system CRT for every proof process.

### A scripts/ self-test is Windows-on-Windows

The build is Win64 only. Every library translation unit includes `<windows.h>`, the link list carries `psapi` / `dbghelp` / `ntdll` / `xinput`, and no lane configures on another OS. A CTest registration therefore only ever exists in a Windows tree. A self-test can import `winreg` or any other Windows-only module at module scope, with no platform guard and no gated registration. Inside an `except` block these suites raise a bare `AssertionError`. Implicit `__context__` chaining already prints the caught exception. `raise ... from err` labels a wrong-exception mismatch as the direct cause of the assertion, which is the opposite of what happened.

### A proof label needs an inventory gate

`ctest -L <label>` exits zero on an empty selection. A toolchain gate, a renamed case, or a host that was never registered therefore removes the coverage and still reports green. Declare the label's cases to `scripts/check_test_label_inventory.py` (`--require` per name, `--minimum`, `--expect-target` for a `gtest_discover_tests` target whose `_NOT_BUILT` placeholder means it was never built). Register that check as a ctest that carries the same label, from `tests/CMakeLists.txt`, never from the subdirectory it covers. A gate that the skipped subdirectory also skips proves nothing. `FaultProof.LabelInventoryIsComplete` is the worked example. Related: `dmk_add_raw_proof` declares no build dependency. A workflow that builds targets by name must therefore list every raw host, or the ctest is registered and never built.

### CTest execution timeouts

`CTestTimeoutControl` is the proof pointer. [The test coverage guide](../tests/README.md) owns the CTest timeout contract.

### Most regression guards belong in regular test_*.cpp cases

When a fix needs a reproduction or regression guard that can share the main test process, add an ordinary GoogleTest case in the matching `test_<module>.cpp`. A low-address `VirtualAlloc` fixture, a `PAGE_GUARD` page, an `is_lock_free()` probe, and the like all run fine in the monolithic suite (see `ScannerRipTest.find_and_resolve_skips_implausible_decoy_and_finds_genuine_site` and `EventDispatcherTest.AtomicSharedPtrIsNotLockFree`). Do NOT add a separate regression-test directory or a dedicated executable for in-process checks. Reach for the `tests/fault/` or `tests/lifecycle/` proof targets ONLY when the fixture genuinely needs more. That means a leaked `PAGE_NOACCESS` page, a global `operator new` / `delete` override, or a real loader or teardown event that cannot share the test process.

### Inject faults into the foreign target the guard arms

Inject a fault into the FOREIGN target that the guard arms, not a write's source. Both guards confine their claim to the range an operation explicitly touches: the target of a read, walk, or in-place write. A fault outside it reaches the host, so a genuine out-of-range bug is not swallowed. A guarded write's SOURCE span is caller-owned and trusted. A faulting source is a caller-contract violation and is uncontained on either toolchain, so a source-fault test crashes rather than fails closed. This is also why the escalating write slow-path copy-fault arm is not deterministic single-threaded. Once the slow path makes the target writable, only a concurrent reprotect can fault the copy.

### VmtHook declaration order

A `VmtHook` restores the object's vptr in its destructor. Declare the handle AFTER the target it clones, `auto target` first and `VmtHook vh` second, so reverse-order destruction restores the vptr first. Clear any global that the detour reaches (for example a live `VmtHook*`) before the handle drops.

### Poll-loop probe seams install stopped, clear after join

A poll-loop `std::function` seam is installed only while the poller is stopped and cleared only after it is joined. `g_input_key_state_probe`, `g_input_post_stage_probe`, and `g_input_pre_dispatch_probe` are plain globals that the poll loop reads and calls every cycle with no synchronization. Assign them before `poller.start()`, and arm whatever phase the probe parks on through a separate atomic afterwards. Clear them only once the poll thread is joined.

The probe's captures are the case's barrier atomics. Declare those BEFORE the poller and the cleanup owner AFTER it. Every exit path then opens any parked dispatch, joins, and only then destroys the probe. Exit paths include a fatal `ASSERT_`, a premise failure, and the end of the case. A mistake here writes over a `std::function` that the poll loop is executing and frees a parked frame's barriers. That surfaces as an intermittent native access violation, not as a failed expectation. The GoogleTest launcher renders it as a CMake diagnostic that must never be normalized as a CMake-only failure. `tests/test_input.cpp`'s `StagedProbeCleanup` is the shared owner and `InputLifecycleProof.StagedProbeCleanupJoinsBeforeDestroyingProbeCaptures` is its control.

### No fatal GoogleTest assertion off the main thread

A test thread never carries a fatal GoogleTest assertion, and a cross-thread barrier always has a deadline. `ASSERT_*` and `FAIL()` off the main thread return from the enclosing lambda instead of a failed case. The work after them is skipped, and the main thread's wait target never arrives. Report the worker's outcome through an atomic and assert it on the main thread. Give every wait on a worker-set flag a `steady_clock` deadline. On expiry it opens any barrier where the worker can park, joins, and fails with the premise it failed to establish. An unbounded spin here wedges the whole shared unit binary with no diagnostic. `BindingGateTest.UnrelatedThreadStillWaitsOutAnotherThreadsTeardownSpan` is the local pattern.

### White-box internal suites

White-box internal suites (`test_x86_decode` over `src/x86_decode.hpp`, `test_input_intercept` over `src/internal/input_intercept.hpp`) add `src/` to their include path and call `DetourModKit::detail::` directly. `test_gate_race_probe` is a concurrency-stress white-box suite over the two header-only synchronization primitives ( `src/internal/hook_ledger.hpp` and `src/internal/input_binding_gate.hpp`). It drives real cross-thread contention on the install/teardown ledger and the input hold/press gates. It runs in the main suite (per the in-process rule above) but stays independent of the library's compiled surface. The same source therefore remains usable by standalone race-instrumented builds that cannot link the Windows-only library.
