# Test coverage guide

## Overview

This guide documents the DetourModKit test strategy: how to build with coverage, run tests, interpret reports, and handle common obstacles. [docs/design/testing.md](../design/testing.md) owns the test-architecture rules. This guide owns the per-suite coverage inventory and the tooling commands.

## Quick commands

### Build with coverage

```bash
# Using CMake presets (recommended)
PATH="/c/msys64/mingw64/bin:$PATH"
cmake --preset mingw-debug -DDMK_ENABLE_COVERAGE=ON
cmake --build build/mingw-debug --parallel
```

### Run tests

`ctest` is the canonical runner. `gtest_discover_tests` registers each test case as its own ctest test, so ctest runs each case in a separate process. Some suites drive process-global state (the `ConfigTest` log-capture cases reconfigure the one `log()` sink). They can interleave when many cases share one monolithic process, so prefer `ctest`. The standalone `DetourModKit_tests.exe` serves fast local iteration and `--gtest_filter` work, not the canonical green/red signal.

```bash
PATH="/c/msys64/mingw64/bin:$PATH"

# Canonical: per-case process isolation
ctest --preset mingw-debug --output-on-failure

# Fast local iteration (single process; log-capture cases can interleave)
./build/mingw-debug/tests/DetourModKit_tests.exe
./build/mingw-debug/tests/DetourModKit_tests.exe --gtest_filter="LoggerTest.*"
```

### Generate a coverage report

```bash
# Summary report
python -m gcovr --root . --filter "src/" --filter "include/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --gcov-ignore-parse-errors negative_hits.warn \
    --print-summary

# HTML report (output to docs/tests/coverage/, gitignored)
python -m gcovr --root . --filter "src/" --filter "include/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --gcov-ignore-parse-errors negative_hits.warn \
    --html-details docs/tests/coverage/index.html
```

## Coverage analysis workflow

### 1. Identify low-coverage files

Run the full coverage report and look for files below the 80% gate:

```bash
python -m gcovr --root . --filter "src/" --filter "include/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --gcov-ignore-parse-errors negative_hits.warn \
    --print-summary
```

### 2. Check specific file coverage

```bash
python -m gcovr --root . --filter "src/hook.cpp" --txt
```

### 3. Analyze uncovered lines

Look at the "Missing" column for specific line numbers, then categorize by reason:

| Reason | Examples | Solution |
| ------ | -------- | -------- |
| **Invalid memory addresses** | Hook functions that require valid function pointers | Use real function addresses with `DMK_TEST_NOINLINE` |
| **Error paths** | Exception handlers, error returns | Test with invalid inputs that trigger errors |
| **Windows API errors** | `GetModuleHandleExA`, `VirtualQuery` failures | Accept the limitation or mock |
| **Template instantiation** | Template methods instantiated only with specific types | Add tests that call with those types |
| **Threading race conditions** | Lock-free CAS retry loops | Difficult to cover deterministically |
| **Cross-module paths** | DLL hooks, module scans | Use integration tests with `hook_target_lib.dll` |

CI gates line coverage at 80%.

## Test architecture

### Unit tests

Each module has a corresponding test file that tests the module in isolation:

```text
src/<module>.cpp  →  tests/test_<module>.cpp
```

Unit tests use `DMK_TEST_NOINLINE` static functions as hook targets within the test binary itself. This checks the hook mechanics without cross-module complexity.

### Integration tests

`tests/test_hook_integration.cpp` tests the real-world DLL hook workflow against `tests/fixtures/hook_target_lib.cpp`, built as a shared library:

1. `LoadLibrary` the fixture DLL.
2. `GetProcAddress` to resolve exports.
3. Hook exported functions through `hook::inline_at`, by address and by AOB scan.
4. Verify behavioral changes (altered return values).
5. Drop the `Hook` handles and verify that original behavior is restored.

The fixture DLL exports `extern "C"` functions with volatile magic constants for stable AOB patterns across builds.

## Hook testing

Five test files exercise the hook surface:

- `tests/test_hook.cpp` covers the free-function / RAII surface (`hook::inline_at`, `hook::mid_at`, `hook::vmt_for` , `hook::install_all`). That includes inline / mid / vmt installs, `Hook` lifecycle (enable, disable, release, destructor unhook), duplicate detection, prologue policy, and `Hook::call`. It also includes `install_all` batch outcomes and `install_all`'s `noexcept` out-of-memory degradation through the `dmk_test::AllocFailScope` injector.
- `tests/test_mid_hook_context.cpp` covers the `hook::MidContext` accessors (`gpr`, `stack_pointer`, `resume_stack_pointer`, `instruction_pointer`, `flags`, `xmm`).
- `tests/test_hook_backend.cpp` covers the managed hook/backend transaction boundary. It covers post-commit reported failures, contained throws before and after inline/mid enable, and disable and rollback mutation. It covers conservative Foreign/Indeterminate recovery after a committed restore. It also covers safe teardown with a stale backend flag, allocation-failure-safe pin diagnostics, persistent emitted-patch provenance, zero-filled first-enable refusal, and preservation of Foreign bytes. Test-only address-scoped seams run transaction cleanup before they return an error or rethrow, so each discovered GoogleTest is an isolated host-survival and state-reconciliation proof.
- `tests/test_hook_integration.cpp` covers real-DLL cross-module hooks against the `hook_target_lib.dll` fixture.
- `tests/test_diagnostics.cpp` covers hook-lifecycle events. `ModulePins.*` covers reason isolation, direct totals, Snapshot derivation, and Worker. `DiagnosticsSnapshotTest.CountsLiveHookPopulation` covers Hook. Input tests cover InputPoller and MessageHookKeepalive. XInput lifecycle proofs cover XInputKeepalive and XInputTarget. `Lifecycle.FullLifecycleCycles` covers Bootstrap, AsyncLogger, and MemoryCache. The StoppableWorker self-shutdown case covers LifecycleReaper and deferred Worker release.

### Using real function addresses

```cpp
#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

// Test-local functions marked noinline to prevent the compiler
// from optimizing away the function body.
DMK_TEST_NOINLINE static int real_hook_target_add(int a, int b)
{
    return a + b;
}

DMK_TEST_NOINLINE static int real_hook_detour_add(int a, int b)
{
    return a + b + 100;
}

// Create a hook on a real, callable function. The returned Hook is a
// move-only RAII handle, DISABLED; call enable() to arm it. Its destructor unhooks.
auto result = DetourModKit::hook::inline_at(
    {.name = "TestHook",
     .target = DetourModKit::Address{reinterpret_cast<uintptr_t>(&real_hook_target_add)}},
    &real_hook_detour_add);
ASSERT_TRUE(result.has_value());
DetourModKit::hook::Hook hook = std::move(*result);
ASSERT_TRUE(hook.enable().has_value());
```

### Cross-module hooks (integration tests)

```cpp
// Load the fixture DLL and hook its exports
HMODULE dll = LoadLibraryA("hook_target_lib.dll");
auto fn = reinterpret_cast<ComputeDamageFn>(GetProcAddress(dll, "compute_damage"));

auto result = DetourModKit::hook::inline_at(
    {.name = "DamageHook",
     .target = DetourModKit::Address{reinterpret_cast<uintptr_t>(fn)}},
    &detour_compute_damage);
ASSERT_TRUE(result.has_value());
DetourModKit::hook::Hook hook = std::move(*result);
ASSERT_TRUE(hook.enable().has_value());
```

### AOB scan + hook pipeline

```cpp
// Build a signature from the export's first 16 bytes
auto *bytes = reinterpret_cast<const unsigned char *>(fn);
std::string aob = build_aob_from_bytes(bytes, 16);

// Scan the DLL's memory region for the pattern
auto pattern_result = DetourModKit::scan::Pattern::compile(aob);
const auto found = DetourModKit::scan::scan(
    *pattern_result,
    DetourModKit::Region::module_named(module_name),
    1, DetourModKit::scan::Pages::Executable);

// Verify it found the exact export address, then hook it
EXPECT_EQ(found->raw(), reinterpret_cast<uintptr_t>(fn));
```

### What the suite covers

- Pre-flight validation: invalid addresses, null pointers, duplicate names, unsafe prologues.
- Hook lifecycle: install, enable, disable, release, RAII destructor unhook, re-enable.
- Original invocation: `Hook::original<Fn>()` (typed trampoline) and `Hook::call<Ret>(Args...)` (guarded by the per-hook mutex).
- Batch install: `hook::install_all` Mandatory / BestEffort severities and per-row `InstallOutcome`.
- noexcept-batch degradation: `scan::resolve_batch` and `hook::install_all` degrade rather than terminate under injected out-of-memory (the thread-local `dmk_test::AllocFailScope` injector). A `resolve_batch` container-allocation failure is signalled by the outer `Result<...>` as `Error{OutOfMemory}`. A per-request `bad_alloc` degrades only that slot, with no throw past the `noexcept` boundary.
- Concurrent access: multi-threaded hook creation stress tests.
- Cross-module hooks: DLL exports hooked and verified through integration tests.
- AOB scan pipeline: `scan::scan` / `scan::resolve` finds patterns in loaded DLLs, then `hook::inline_at(InlineRequest{.target = scan::OwnedScanRequest{...}})` hooks the result.
- Mid hooks: argument inspection and modification through the `hook::MidContext` accessors (`gpr()`, `stack_pointer()`, `instruction_pointer()`, `xmm()`).

### Platform-specific tests

Mid hook tests that modify registers (`gpr(ctx, Gpr::Rcx)`, `gpr(ctx, Gpr::Rdx)`) are x86-64 specific. Guard with:

```cpp
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "Requires x86-64 calling convention";
#endif
```

### Fault-injection tests (tests/fault/, CMake-owned proof target)

A test that must observe a guarded primitive contain a real hardware fault needs a committed `PAGE_NOACCESS` page held until process teardown. [The must-fault page rule](../design/testing.md#a-must-fault-test-holds-a-committed-page_noaccess-page) owns the lifetime rationale. These fixtures do NOT join the `tests/test_*.cpp` glob. [docs/design/testing.md](../design/testing.md) owns the placement rule and the no-toolchain-gate rule.

- Reusable fixtures live in [`tests/fixtures/fault_injection.hpp`](../../tests/fixtures/fault_injection.hpp): `dmk_test::NoAccessPage`, `dmk_test::ProtectedPage`, and `dmk_test::ExecutablePage`, a zero-filled RWX page usable as a synthetic module image, with helpers to plant a literal and a RIP-relative `lea`. The must-fault page rule describes the first two.
- Fault TUs live in `tests/fault/test_*.cpp`. [`tests/fault/CMakeLists.txt`](../../tests/fault/CMakeLists.txt) compiles them into the `fault_tests` proof target. Build and run the complete set with `bash scripts/run_fault_tests.sh` (any configured tests-ON tree), or build `fault_tests` plus `fault_scanner_escape_probe` and run `ctest -L fault-proof` directly.
- Inject the fault into the FOREIGN target that a guard arms, not a write's caller-owned source. The [inject-faults rule](../design/testing.md#inject-faults-into-the-foreign-target-the-guard-arms) owns the rationale.

`tests/fault/test_fault_containment.cpp` proves that guarded read, pointer-chain walk, and `write_in_place` all fail closed against a no-access page. It also proves the deterministic escalating write slow-path protection restore and containment of a RIP snapshot tail that crosses into `PAGE_NOACCESS`. It proves that an enclosing guard still holds after a nested guarded read returns.

`tests/fault/test_faststring_straddle.cpp` pins the classification the guarded store hinges on. A destination whose first byte sits on a blocked page must report `NotWritten` and must leave every writable byte of the span untouched, across three blocked-prefix widths, both blocking protections, and fourteen span widths. A span that faults past a writable prefix must report `MayBePartial` with that whole prefix committed. `rep movsb` is allowed to retire its stores out of order, so a committed tail byte under a first-byte fault makes the `WriteFaulted` a caller acts on a lie. This is one microarchitecture's evidence, not an architectural guarantee: a red here means re-derive the classification on that host before reading it as a defect.

`tests/fault/fault_scanner_escape_probe.cpp` proves both sides of that contract. Both scanner sweeps declare an exact span: the region sweep declares `[region_start, capture_limit)`, and the string-xref narrow sweep declares the gated window. A fault outside the span is an unrelated defect the host has to see, not the concurrent unmap the guard absorbs. Neither outcome is observable from outside the guard, because both report "the sweep was incomplete", and an escaping access violation cannot share the GoogleTest process. This is therefore a raw host with an exit-status oracle.

- The `region` and `xref` modes drive real scans and use the `DMK_ENABLE_TEST_SEAMS` -gated slot in `src/internal/scan_fault_seam.hpp` to read one outside address from inside the guarded body.
- The paired `xref-in-span` mode reprotects its accepted window only after phase 1 reaches the narrow body. It then requires that call site's filter to contain the injected in-span fault.
- On MSVC, an escaping exception unwinds to the host's own `__except`, whose filter accepts only the exact injected address. On MinGW nothing claims it, and the host's top-level filter proves that it got out.
- A still-armed slot after the scan is a setup failure rather than either verdict.

`ctest -L fault-proof` exits zero on an empty selection, so [`tests/CMakeLists.txt`](../../tests/CMakeLists.txt) registers `FaultProof.LabelInventoryIsComplete` outside `tests/fault/`, where a skipped subdirectory cannot skip its own gate. It runs [`scripts/check_test_label_inventory.py`](../../scripts/check_test_label_inventory.py) against the tree's own CTest inventory. It fails when a named case is absent or duplicated, or when the label carries fewer cases than declared. It also fails when `fault_tests` was never built (GoogleTest's `_NOT_BUILT` placeholder). `scripts/test_check_test_label_inventory.py` pins those rejections and is registered as the `TestLabelInventoryGateSelfTest` script-lint ctest.

### Lifecycle proofs (tests/lifecycle/, CMake-owned targets)

A proof that needs a real loader transition or a controlled static-teardown ordering runs in its own process under `tests/lifecycle/`. [docs/design/testing.md](../design/testing.md) owns the placement rule. Several of these proofs replace the global allocation operators for their whole process. `diagnostics_first_use_oom.cpp` is the only one whose poison is armed by constant initialization. It therefore covers the loader's own initializer pass rather than a window opened from `main`.

[`tests/lifecycle/CMakeLists.txt`](../../tests/lifecycle/CMakeLists.txt) builds each proof as a CMake-owned target and registers it as a `lifecycle-proof` -labeled ctest whose verdict is the process exit code. Zero is a pass. Any other code is a proof or setup failure, identified by the returned code and a message on stderr. A proof whose subject is not present on every host must declare `SKIP_RETURN_CODE` on its `dmk_add_raw_proof` call and return that code from its unavailable branch. ctest then reports Skipped. The XInput rundown proofs use skip code 77.

Build and run with `bash scripts/run_lifecycle_proofs.sh`, or build the lifecycle targets and run `ctest -L lifecycle-proof` directly.

The proof hosts:

- `bootstrap_probe_dll.cpp` / `test_bootstrap_module_ref.cpp` is the raw T-BOOTSTRAP lifecycle proof.
- `input_loader_detach_dll.cpp` / `test_input_loader_detach.cpp` is the raw T-INPUT-LOADER proof. It covers two sole-owner shapes across a bare `FreeLibrary`: a staged entry and a parked `input::scope()` guard. The capture destructor signals a witness event. An armed control verifies that event.
- `input_reshape_retirement.cpp` is the T-INPUT-RESHAPE host. Each mode runs in a separate process.
  - `pending-remove` covers staged name removal under `m_mutex`.
  - `pending-clear` covers staged clear under `m_mutex`.
  - `pending-shutdown` covers staged shutdown under `m_mutex`.
  - `pending-cardinality` covers staged cardinality rebuild under `m_mutex`.
  - `live-remove` covers live name removal under `m_bindings_rw_mutex`.
  - `live-clear` covers live clear under `m_bindings_rw_mutex`.
  - `live-rebind` covers live cardinality rebuild under `m_bindings_rw_mutex`.
  - The unknown-token case is the `WILL_FAIL` control.

  Each mode leaves the reshape entry as the final callable owner. Its capture destructor calls `Input::binding_count`. Lock-held destruction deadlocks, so CTest `TIMEOUT` detects it. Exit status rejects absent or late destruction.
- `test_full_lifecycle.cpp` is the long-lived host (the `full_lifecycle` target): one binary, four separately registered scenarios selected by `argv[1]`. Their terminal states are mutually exclusive in one process. `cycles` runs six bootstrap/use-every-subsystem/drain generations and asserts that a clean drain retains nothing. `concurrent` has two control threads drain one generation. Exactly one owns it, and the other gets `SessionShutdownInProgress`. `misuse` proves that a bare-FreeLibrary `DLL_PROCESS_DETACH` against a live worker abandons, pins, and records the leak. It refuses a later drain with `SessionShutdownUnavailable` and still lets the pinned worker finish its own teardown. `exit` reaches process exit with every subsystem still live, so the CRT teardown path neither hangs nor faults.
- `xinput_detour_rundown.cpp` is the fresh-process host for XInput hook lifetime and pair integrity. Each CLI mode maps to one `Lifecycle.XInput*` CTest case. The `process-exit-storage` mode proves the B-100 XInput exit boundary. The suite covers install failure, byte reconciliation, pair recovery, teardown, and module reference balance. It also proves route unwind metadata and capacity limits. Host-dependent modes return skip code 77 when no subject exists. This test target names the backend because its route proofs inspect generated regions. The deterministic `newer-layer-ex` mode also runs maintenance while the managed primary patch is Foreign. It requires suppression to fail open and the distinct Ex member to remain exactly covered. Teardown must retain both callable chains, and hand-back must recover through the same primary trampoline before both exact patches are republished.
- `xinput_forwarding_guard.cpp` is the ordinal-100 membership host. Four checked-in proxy DLLs give the branch its own deterministic export shape. The shapes are ordinal 100 local to the patched module, forwarded into another module, absent, and aliased onto `XInputGetState`. `forwarded` and `same-module` are distinct members and require their own hook. The forwarded one additionally requires the third target-module keepalive and a pass-through call that reaches the resolved target. `absent-ex` and `alias-ex` are the only exemptions and require complete coverage from the primary hook alone. The install reports success, no second chain is published, and two keepalives are held. A published mask clears the bound controller's bits, and the single patched prologue still forwards exactly once. An absent ordinal treated as a distinct member fails `absent-ex` and no other mode. A dropped alias exemption fails `alias-ex` and no other, which guards against a second inline hook that captures the first hook's jump as its original.
- `input_tls_exhaustion.cpp` is the delivery-marker admission host, and the only place where the marker's failure mode is reachable. A taken TLS index set is process-wide, and the marker latches its unavailability. Neither half can be undone inside the shared unit process. `exhausted` consumes every index before DetourModKit reserves its slot, makes two threads race the serialized first reservation, and requires both to report failure. It then requires hold true, hold false, and press delivery refusal to run no consumer code and to restore the gate state each edge found. One thread's unrecordable frame must leave another thread readable as not callback-entrant. Balancing-edge and retired-callable self-reentry must complete on both an ordinary C++ thread and a foreign `CreateThread` host thread, with the exact allocation-free Win32 identity. A regression there hangs, so the ctest timeout is the oracle. It then hands the indices back and drives the real facade, and requires zero delivered edges. `available` is the positive control over the same drive. A binding that never matched also produces zero edges, so the refusal case means nothing without it. A third registration is the `WILL_FAIL` unknown-token control. `store-failure` covers the branch that index exhaustion cannot reach: the reservation succeeds and only the per-thread depth store fails. A reserved index past the TEB's inline slots does that when its lazily heap-allocated expansion array cannot grow. It requires the frame to report itself unrecorded and the thread to keep its not-callback-entrant answer. Hold and press deliveries must run no consumer code and must restore the gate state they found. Then, with the store in service again, an ordinary delivery, its balancing edge, and a real facade drive must all succeed. A permanently broken store therefore cannot pass as a refusal proof. The same scenario also covers the half that must not be refused. A mandatory teardown span opened while the store fails must report no recorded depth, yet still make its own thread read as callback-entrant. It must leave a freshly started thread with a false answer and stop the entrant answer the instant the span ends. Those four together separate an exact fallback from a process-wide marker, which satisfies the first two and fails the third.
- `test_input_gate_abba.cpp` is the re-entrant teardown host, isolated because every regression here is a mutual wait rather than a failed assertion. The ctest timeout is the oracle, and a deadlock must not wedge the shared unit binary. The no-argument scenario drives 200 iterations of two Hold bindings whose cancellation callbacks release each other's guards through the real facade. It requires exactly one true and one false edge per binding per iteration. `press-retire-disposal` and `hold-retire-disposal` cover the other re-entry shape: a retired callable whose captured destructor releases the gate that disposes of it. `hold-store-failure-abba`, `hold-retire-store-failure-abba`, and `press-store-failure-abba` separately cover Hold release, Hold retirement plus capture disposal, and Press capture disposal. Each runs with the exact TLS depth store refused on both threads at once. That is the composition the depth marker alone cannot answer. Each thread's teardown span reads as depth-zero control plane, so each waits on the other's claim. A rendezvous inside consumer code makes the crossing deterministic. The scenarios additionally require that both refusals armed. A seam that silently ran out of registration slots therefore cannot pass as a proof of the crossing. A separate `WILL_FAIL` registration is the unknown-token control.
- `test_dispatch_cow.cpp` is an isolated host that checks re-entry into the dispatcher writer path. Each target calls `clear()` from its copy constructor or destructor. A regression deadlocks on the non-recursive mutex, and the CTest timeout detects it. Four modes cover subscribe copy, compact copy, clear destruction, and reset destruction. `DispatchCow.*` supplies the count checks. A separate `WILL_FAIL` case rejects an unknown token.
- `test_profiler_late_uaf.cpp` compiles `src/profiler.cpp` directly and replaces global `operator new` / `delete` with a size-targeted poisoning allocator. A `ScopedProfile` record that outlives ordinary static teardown then faults deterministically if the profiler singleton were ever destroyed early. It links no library and is not instrumented for coverage, so gcov's `atexit` `.gcda` flush cannot allocate into the poisoned path.
- `diagnostics_first_use_oom.cpp` is one source built twice. With `DMK_DIAGNOSTICS_OOM_PROBE_DLL` it is the `diagnostics_oom_probe` DLL. It links the archive and replaces every global allocation operator, plain and over-aligned, with a poison that is constant-initialized to armed. Every C++ allocation attempted while the loader runs that module's initializers therefore fails. The aligned family is included deliberately and is backed by `_aligned_malloc` / `_aligned_free`, so the two families never cross. DMK already allocates an over-aligned block through the nothrow aligned operator new (`src/internal/async_logger.cpp`). That family left at its default keeps a channel that serves a load-time allocation instead of a refusal. The positive control below exercises both families for that reason. Without the macro, the same file is the host. The host must not link the archive, or its own copy of DMK initializes outside the poisoned window. The window is otherwise unreachable: DMK's static initializers run inside `LoadLibrary`, before any user bootstrap gets control, and an allocation failure there has no handler. Three things must hold together for a pass, and each kills a different fake. `LoadLibrary` succeeds: an allocating initializer that propagates fails the load outright. The probe's own deliberate allocation is refused. Without this positive control, a module whose `operator new` replacement never took effect is indistinguishable from one that needed no memory. The load-time refusal count is exactly zero: an initializer that allocates but swallows the failure stays loadable, and only this counter catches it. An eager `hook_lifecycle().subscribe(...)` initializer makes `LoadLibrary` fail with `ERROR_DLL_INIT_FAILED` (1114). The proof covers the probe's link closure, not the archive. DMK links statically, so only referenced object files are present to initialize. The probe deliberately references the hook surface as well as diagnostics, so `hook.cpp`, which owns the population tally, initializes inside the poisoned window.
- `logic_callback_dll.cpp` / `logic_dll_protocol.hpp` / `test_logic_dll_unload.cpp` is the callback-only Logic-DLL topology. The host (`logic_dll_unload`) links the archive and owns every `Hook`, every binding, and every config registration. The companion DLL links no DetourModKit archive and contributes only callables. That excludes a second library instance and any install-time self-reference in the unmap verdict. The DLL is deliberately given no path to the library's headers. The one DetourModKit type a mid detour names is forward-declared in the protocol header. Unmap is asserted with `GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT)` over an exported marker. The callable target has an observable nontrivial destructor, and its erased invoker and manager are instantiated inside the DLL. The construct/destroy tallies therefore remain valid whether the standard library stores the target inline or on the heap. Every process first injects one callable-factory failure and requires the `noexcept` C ABI to return an empty result. Nine scenarios then run in separate processes. `input-drained` proves that a completed drain destroys every input callable. `guard-retained` pins the destruction half of the documented retained-guard hazard. `guard-retained-hold` pins the worse half. A guard on a still-held binding synthesizes its balancing `on_state_change(false)` after `SafeToUnload`. The release is therefore a call into the provider, not only a destructor. `input-parked`, `config-setter-parked`, and `config-parked` prove that a parked input body, config setter, and reload callback each force refusal. Both config cases then release the body, retry to `SafeToUnload`, verify that every callable was destroyed, and unmap. `mid-parked` proves that ordinary teardown waits. `mid-pinned` proves that a still-patched tombstoned stub stays inert after unmap. `inline-quiesced` first proves that the armed detour really chains to its trampoline. The unchained path returns a value the target cannot produce, so a detour that recomputed the result instead of a chain fails. It then parks a caller in the detour before it applies the caller-owned stop, release, join, destroy, unmap order. A removed mid-adapter tombstone store fails `mid-pinned`. `mid-parked` and `input-parked` pin composite end-to-end properties, because lower layers still enforce their result when either named DMK wait is removed.
- `diagnostics_late_emitter.cpp` has two arms that are strict ordering proofs only because the library subscribes to neither dispatcher during static initialization. An implementation that established a permanent subscription at load touches `hook_lifecycle()` before this TU can order itself against it. That silently weakens the arm from an ordering proof to a delivery assertion, without a failure.
- `logger_generation_log.cpp` is the staged-generation log-survival host. Each scenario uses `Session::start` in the first child and `bootstrap` in the second child over one file. `append-preserves` selects `LogOpenMode::Append` and requires the second file to retain the first file as an exact prefix. That prefix includes teardown records, and the second marker follows it. `truncate-default` omits the mode and requires removal of the first marker. A separate `WILL_FAIL` case rejects an unknown token.
- `staged_generation_dll.cpp` / `staged_generation_protocol.hpp` / `staged_generation_soak.cpp` pin the staged-generation reload pattern from the hot-reload guide. The generation DLL links a private DetourModKit archive and uses a test seam for XInput selection and an explicit wheel target thread. The host stages unique-name copies, rewrites each tag, loads each generation, and reads its instance-local status. The eight cases are:

  - `Lifecycle.StagedGenerationSoakReloadsWithFreshBytes` verifies 100 fresh logic images against one resident wheel host. Each live generation owns the sole lease. Shutdown releases it and reports zero logic pins and leaks. The loader probes the free lease, calls `FreeLibrary`, and requires address unmap before the successor load. The host snapshot stays at one hook, one thread handle, zero leases, and one mount generation.
  - `Lifecycle.StagedGenerationLocalWheelRetentionStaysMapped` verifies the local `MessageHook` negative-unload contract. Each of two generations mounts the wheel hook, books exactly one permanent `MessageHookKeepalive`, retains it across Shutdown, and stays mapped after `FreeLibrary`.
  - `Lifecycle.StagedGenerationReloadNeverUninstallsInterception` combines the configure gate with a live engine proof. The gate requires exactly one `uninstall(m_intercept_owner)` call. `clear_bindings` leaves the layer installed, and poller shutdown removes it.
  - `Lifecycle.StagedGenerationForeignXInputRetainsThePair` uses a host hook as the rival XInput owner. Calls before teardown, after revocation, after `FreeLibrary`, and after hand-back prove inert forwarding and image retention.
  - `Lifecycle.StagedGenerationParkedCallbackRefusesReload` parks a callback and requires Shutdown to refuse the reload. Cleanup releases the callback, retries teardown, and requires the image to unmap.
  - `Lifecycle.StagedGenerationReleasedCallbackAllowsReload` requires the refused generation to accept a retry after callback release and then unmap.
  - `Lifecycle.StagedGenerationPartialInitRollsBackAndUnmaps` first verifies that an `AfterHook` failure rolls back and unmaps. It then places a host hook above the generation hook and requires the HookManager delta to refuse Shutdown. The refused generation preserves its target module and remains callable.
  - `Lifecycle.StagedGenerationProofRejectsAnUnknownScenario` uses `WILL_FAIL` to reject an unknown token.

  Only the soak, local-wheel-retention, and uninstall-call-site cases use `SKIP_RETURN_CODE 77`. They require a window station. If the synthetic XInput fixture is absent, the foreign XInput case fails. A cleanup fixture removes staged DLL and log files after all seven positive processes exit.
- `logger_writer_batch_oom.cpp` is the async writer's forward-progress floor. The regression it owns is a HANG, not a wrong value, so the ctest `TIMEOUT` is the oracle. The writer reserves headroom for a whole batch before it pops. A reservation it can never secure used to pop nothing and skip both idle gates, because the queue was not empty. It then spun until `shutdown()`'s join blocked forever. `persistent-batch-oom` replaces the global allocation operators with a poison keyed on allocation SIZE rather than on the calling thread. A thread-local key needs emulated TLS on MinGW, which allocates on first touch and recurses straight back into the hook. It arms the poison before the writer's first successful pop, which is the point of the ordering. `std::vector` keeps its capacity across the writer's `clear()`, so a batch that reserved once never reserves again, and the failure is unreachable afterwards. A neutralized one-record floor makes the case time out. `oversize-batch` covers the same permanent zero-progress state reached with no memory pressure at all, from a `batch_size` larger than `std::vector`'s `max_size`. Liveness alone cannot distinguish the clamp there, because the floor rescues that configuration too. What separates them is that the clamp keeps the writer in BATCHES instead of a degrade to one record per cycle behind a thrown `length_error`. Both cases therefore assert on `g_async_logger_batch_floor_counter`. The persistent case requires every record to go through the floor. Without that, it passes vacuously on a reservation that quietly succeeded. The oversize case requires none to go through.

#### Join before clear: raw-proof seam ownership

A raw proof's failure exits are as load-bearing as its success path, and they are where the poll thread is still live. The [test-seam rule](../design/testing.md#test-seams-compile-out-of-shipping-builds) owns the ordering rationale. The order is: unblock parked callback work, run the engine down and join, and only then clear the seams.

[`tests/lifecycle/input_seam_cleanup.hpp`](../../tests/lifecycle/input_seam_cleanup.hpp) owns that order as `dmk_lifecycle::InputSeamOwner`. Declare it immediately after the engine starts and after every local that a callback captures. Reverse destruction order then makes the sequence structural rather than a burden on each exit path. A host that can self-shutdown must supply a completion predicate. `Input::shutdown()` reached from a binding callback hands its rundown to the process reaper and returns before delivery. `dismiss()` exists for the one shape that genuinely wants the engine left in service: a loop iteration that re-registers against a still-started manager. It is valid only where the callbacks completed and nothing is parked.

Three bounded negative controls drive that path on purpose: `InputLifecycleProof.AbandonedParkedCallbackRunsDownBeforeClearing`, `AbandonedFacadeDrivePremiseRunsDownBeforeClearing`, and `AbandonedSelfShutdownPremiseRunsDownBeforeClearing`. Each starts the real engine, parks a callback inside the poll thread, abandons its premise, and then asserts what the rundown did with it. The ordering oracle is read from inside the parked callback. The callback waits out a window that a correct rundown cannot use, because a correct rundown is blocked in a join on that same body. It then records whether its seam is still installed. A rundown that cleared before the join loses that race and is named for it. One that never unblocked hangs into the case's `TEST_TIMEOUT`. One that did not run at all leaves the engine started. Exit zero requires released, still-installed, stopped, then cleared, in that order.

### CTest execution-timeout control (tests/lifecycle/timeout_probe.cpp)

`CTestTimeoutControl` is a passing meta-proof that CTest enforces a test's execution `TIMEOUT`, the property that fails and kills a hung case. That property is distinct from GoogleTest's `DISCOVERY_TIMEOUT`, which only bounds case enumeration. [`scripts/verify_ctest_timeout.cmake`](../../scripts/verify_ctest_timeout.cmake) writes a throwaway inner testfile that registers an intentionally-hung probe (`dmk_timeout_probe`) under a two-second `TIMEOUT`. It runs `ctest` against it and asserts that the timeout diagnostic failed the probe. The hung probe is never registered in the top-level suite, so an ordinary `ctest` run never blocks on it. This proof is toolchain-agnostic and runs on both MinGW and MSVC. A companion `CTestTimeoutControlNegative` (`WILL_FAIL`) drives the verifier against a fast-failing probe under a scratch path that itself contains the word "timeout". It passes only when the verifier rejects a non-timeout failure, which pins the `***Timeout` -token match against a regression to a bare-word match.

On a MinGW build tree, the fault, lifecycle, and soak wrappers prepend the directory of the tree's configured C++ compiler before they launch CTest. This prevents a probe DLL from a bind to an incompatible `libwinpthread-1.dll` supplied by another MinGW distribution earlier on the caller's `PATH`. All three skip the prepend on an MSVC tree. That tree's compiler directory carries private `msvcp140` / `vcruntime140` copies that shadow the system CRT for every proof process.

That directory is not readable from `CMakeCache.txt`. The [proof-wrapper rule](../design/testing.md#proof-wrappers-select-the-configured-mingw-runtime) explains why. [`scripts/resolve_runtime_dir.py`](../../scripts/resolve_runtime_dir.py) reads the absolute path CMake recorded in `CMakeFiles/<version>/CMakeCXXCompiler.cmake` and prints it, or prints nothing for MSVC. The two shell wrappers cannot share code with each other, and Python is already a hard gate dependency. The parse therefore lives in that one script. The shell wrappers run it as a subprocess, and the Python soak imports its `resolve` directly. It emits forward slashes on every interpreter, because a native Windows Python renders the path with backslashes and an MSYS one with forward slashes.

The shell wrappers take the interpreter from the tree's own `DMK_PYTHON_EXECUTABLE`, with a fallback to a `python3` or `python` that demonstrably executes. A bare `command -v python3` is not sufficient on Windows. The App Execution Alias of that name precedes any real interpreter on a default `PATH` and exits nonzero without a run of the script. Under `set -euo pipefail`, that aborts the wrapper before it builds anything.

### Release negative controls and lifecycle soak

The blocking sanitizer workflow has one dispatch-only negative control. `dmk_asan_failure_probe` is an `EXCLUDE_FROM_ALL` MSVC-ASan target, never registered with CTest, and performs one deliberate heap-buffer-overflow only when the workflow explicitly builds and runs it. A capability dispatch is valid evidence only under three conditions. The ordinary full suite passes first, the probe prints a real AddressSanitizer diagnostic, and the workflow concludes Failure. A normal dispatch at the same exact SHA must then conclude Success. A faulting index made in-range turns the capability dispatch green, which is the negative control's mutation oracle.

[`scripts/run_lifecycle_soak.py`](../../scripts/run_lifecycle_soak.py) is the final-candidate lifecycle gate used by both Release jobs. It inventories CTest first, so a missing label or named regression cannot pass vacuously: every entry of `REQUIRED_SOAK_PROOFS` must appear exactly once. That set covers:

- the three staged-release harness cases whose subject is the repetition, the exact in-place-rebind case included,
- the forced-cleanup control,
- five CMake-owned input raw proofs,
- the three bounded cleanup controls described above,
- four exact XInput pair-health raw proofs.

An omitted registration otherwise disappears from the inventory rather than fails. `scripts/test_run_lifecycle_soak.py` carries an independently spelled expected tuple and rejects drift from the production tuple. It then drops each required name in turn and requires the gate to fail and name the dropped proof. The list therefore cannot rot into a group count with a hole in it.

The soak temporarily arms per-executable WER LocalDumps only for the proof processes. It drives `fast_fail_probe wer-crash` through a bounded wait and requires a complete `MDMP` control before it trusts capture. The assertion is that the control terminated with `STATUS_FAIL_FAST_EXCEPTION` (`0xC0000602`), not merely nonzero. Only that status proves that the control exercised the path WER is asked to capture. Python makes that assertion expressible: it reports the raw process exit status. A POSIX shell on Windows maps a fatal status onto a signal number and loses the distinction. `winreg` arms and restores the machine-wide WER values. The completed-dump check opens with no sharing through `CreateFileW`. A dump WER still writes therefore reads as incomplete rather than trusted for its first four bytes. The control dump is deleted.

The script then repeats every `InputLifecycleProof` 200 times serially and runs `Lifecycle.FullLifecycleExit` 100 times serially through `run_lifecycle_proofs.sh`. It then runs all `lifecycle-proof` cases 20 times at parallelism four, with a stop on the first failure.

A restoration guard covers arming and every proof. Each newly created key is ledgered before another registry operation can fail. Every captured value and key is isolated, so one failure does not abandon later work. An otherwise successful soak exits nonzero unless the registry returns to its pre-run state. A key that was absent before the run is deleted only when it is empty. Unowned content is left intact and reported as restoration residue. An earlier soak or unexpected failure stays primary while every cleanup failure prints beside it, and the success message appears only after restoration passes. `scripts/test_run_lifecycle_soak.py` drives those paths against a stateful stub registry, so the failure modes are provable without a broken real machine. It is registered as the `LifecycleSoakRestorationSelfTest` script-lint ctest.

A real crash minidump remains for the workflow's short-retention diagnostic artifact. WER captures unhandled crashes, not hangs, CTest timeouts, cancellations, or ordinary nonzero exits, so CTest's per-case timeouts and `LastTest.log` remain the evidence for those failures. Minidumps can still contain sensitive process memory and must never become release assets. WER policy is machine-wide, so do not overlap two soak-script invocations on one host. The checked-in Release jobs use separate hosted VMs.

### Script self-tests (scripts/, Python)

The `script-lint` label carries twelve standalone Python self-tests: `HeaderHygieneStripperSelfTest`, `EmitTlsCheckerSelfTest`, `ExportEqualityGateSelfTest`, `MechanicalStyleCheckerSelfTest`, `NoTestSeamsCheckerSelfTest`, `TestLabelInventoryGateSelfTest`, `LifecycleSoakRestorationSelfTest`, `RuntimeDirResolverSelfTest`, `BenchmarkResultsCheckerSelfTest`, `WorkflowTopologyCheckerSelfTest`, `ReleaseIdentityCheckerSelfTest`, and `GTestExecutionCheckerSelfTest`. Two positive/negative controls sit on the workflow boundary. `WorkflowTopologyIsBlocking` runs the topology gate against this repository's own workflows. `ReleaseIdentityRefusesAMismatchedCandidate` runs the real identity command line on a mismatched pair and requires a nonzero exit. `SameBaseReplacementExecutionEvidence` is described below. Python is a tests-ON configure prerequisite because the RTTI generation fixture needs it, so every configured test tree registers all of them. MinGW also registers the `EmitPathHasNoEmulatedTls` archive gate, which rejects winpthreads thread identity from the input binding teardown owner path.

#### The canonical workflow contract

[docs/design/build-ci.md](../design/build-ci.md) owns the workflow-contract rules. Those are comparison against a canonical contract rather than fragment presence, quoted-data identity contexts, unconditional required steps, exit-status propagation, and the shell allowlist. This section records only the test evidence.

[`scripts/test_check_workflow_topology.py`](../../scripts/test_check_workflow_topology.py) has 126 tests, and [`scripts/test_check_release_identity.py`](../../scripts/test_check_release_identity.py) has 22. The matrix challenges the structured diagnostics and the exact source boundary. It inserts into, deletes from, reorders, and respells pinned programs. The mutations include:

- shadowing, `export`, and `unset`,
- the tag step's single success exit relocated to the front,
- dropped checkout/ref controls,
- direct context interpolation,
- unquoted or retargeted environment values,
- a comment spliced between a continued line and its continuation,
- a reintroduced retry,
- one unreviewed line inserted into each of the twenty-eight named pinned steps. The pinned steps are held equal to the set of contract steps that carry a program, so neither side can drift. Focused status mutations must still be refused by their unsafe construct. Exact-source mutations cover:

- every workflow, action replacements, trigger values, and flow mappings,
- deleted matrix legs and job defaults,
- unlisted program replacement or last-command masking,
- nested substitutions and shell-startup redirects,
- credential references in every workflow rather than only the release route,
- line-ending portability and invalid UTF-8. Around those sit deleted, renamed, added, and reordered jobs and steps, plus retargeted conditions, unreviewed shells, and path-filtered contexts. Dispatch-input, dependency, publish-mode, credential, clang-tidy, and SIMD controls complete the matrix. The identity self-test drives the real command line in a subprocess. It covers malformed or newline-tainted SHA values, wrong event/ref/checkout, hostile `GIT_DIR`, Git failure, and exact positive identity, the publish checkout included. Every negative asserts the refusal message, not only the exit code, and process-boundary controls prove both CLI exit statuses.

Two policy details carry their own pins. The three exact `TEST_MAJOR` / `TEST_MINOR` / `TEST_PATCH` captures can end in `|| true`. Their failure becomes an empty value that the following validation rejects with a useful diagnostic. Other captured or bare success fallbacks are refused. A zero exit is allowed only in the exact reviewed tag step, after the existing annotated tag proves to resolve to the candidate. An early success anywhere else is refused.

[`scripts/test_resolve_runtime_dir.py`](../../scripts/test_resolve_runtime_dir.py) pins the compiler-runtime resolution the three proof wrappers share:

- a preset tree's bare `g++` cache entry still resolves to the real MinGW `bin` directory,
- an MSVC tree resolves to nothing,
- a bare compiler name is refused rather than a silent resolve to `.`, the bug that made the shell wrappers prepend the repository root,
- the separator is forward slashes on every interpreter.

### Executed-case evidence (scripts/check_gtest_execution.py)

A failing case is red and a case that never ran is green, so a host-conditional proof cannot be read out of a pass/fail count. `MemoryTest.ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent` calls `GTEST_SKIP()` when the loader will not place both fixture variants at the reserved base. That is honest on a developer machine and unacceptable in a release candidate. The case therefore publishes `RecordProperty("dmk_same_base_replacement", "executed")` as its last statement, after both mapping steps and the replacement-extent observation succeed. Every earlier exit is a skip or a fatal assertion, and both leave the property absent.

`tests/CMakeLists.txt` registers two tests around that. `SameBaseReplacementExecutionRecord` runs the exact case with `--gtest_output=xml:` into the build tree (a CTest fixture, so ordering is not a guess). `SameBaseReplacementExecutionEvidence` reads the record back through [`scripts/check_gtest_execution.py`](../../scripts/check_gtest_execution.py). Locally the checker is given `--skip-exit-code 77`, so an unqualified host reports Skipped rather than a false pass. Both Release producers in `release.yml` run the same checker over their own tree's record WITHOUT it. There, an unavailable exact-base mapping is a red candidate host. The checker refuses a missing, unreadable, or unparsable report, an absent or duplicated case, and a case that states neither a status nor a result. It also refuses a not-run/suppressed/skipped case, a failed case, a missing property, and a wrong property value. `--skip-exit-code` never launders anything but a genuine skip. A case that records a failure or an error is not a skip, whatever else the report claims. [`scripts/test_check_gtest_execution.py`](../../scripts/test_check_gtest_execution.py) (20 tests) feeds it each of those shapes. It adds a foreign suite that carries the same case name, a name that differs only in letter case, and the real CLI exit codes.

### Backend equality (scripts/check_backend_patch.py)

[docs/design/hooking.md](../design/hooking.md) `[B-01]` owns the backend patch model and the byte-equality verdict. The test evidence: `scripts/test_check_backend_patch.py` has 36 cases. They include:

- direct positive and contaminated-fixture executions of the production CMake entry point,
- a same-target drift whose fixture is deliberately large enough that the smuggled bytes fall outside every hunk. A one-line fixture cannot express the defect, because any added byte lands in the patch's own context and the reverse-apply catches it first.
- alternate committed-base and replacement-object refusals in both models,
- an agreement matrix that asserts the two implementations accept and refuse the same states,
- the `CMP0057` declaration that `cmake -P` needs, because script mode carries no project policy state.

### Build-tree consumer evidence

`tests/package_build_tree` is the `add_subdirectory` half of the packaging contract, as `tests/package_smoke` is the `find_package` half. Both Release producers in `release.yml` configure, build, and run it at the Release configuration they package, and `scripts/check_workflow_topology.py` refuses a producer that stops. A producer without it still uploads an archive. The missing proof is then visible only as an absent log line in a job that reported success.

### Header-hygiene stripper self-test (scripts/, Python)

`scripts/check_header_hygiene.py`'s legacy-token and backend-confinement gates only inspect real code, because the script blanks comments before it scans. A regression in that comment stripper can fail a PR on a legacy spelling that appears only in prose. One example: a C++14 digit separator such as `1'000'000'000ULL` mistracked as a char literal. That leaves the scanner stuck in char state and passes later comments through unstripped. [`scripts/test_check_header_hygiene.py`](../../scripts/test_check_header_hygiene.py) pins the stripper behavior and is registered as the `HeaderHygieneStripperSelfTest` ctest (label `script-lint`), so `ctest` runs it alongside the C++ suite on both toolchains.

## Test naming conventions

```cpp
// Pattern: Subject_ConditionOrScenario
TEST_F(ClassName, Method_ExpectedBehavior)
TEST_F(HookTest, InlineAt_InvalidAddress)
TEST_F(HookIntegrationTest, AOBScan_InlineAt_EndToEnd)
```

## Adding new tests

### For error paths

```cpp
TEST_F(SomeTest, Method_ErrorCondition)
{
    auto result = object->method(invalid_input);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ExpectedError::Value);
}
```

### For template methods

```cpp
// Template methods only get coverage when instantiated with specific types.
// Hook::original<Fn>() and Hook::call<Ret>(Args...) are templates, so a test
// that instantiates them with the target signature drives that coverage.
auto result = DetourModKit::hook::inline_at(
    {.name = "HookName",
     .target = DetourModKit::Address{reinterpret_cast<uintptr_t>(&target)}},
    &detour);
ASSERT_TRUE(result.has_value());
DetourModKit::hook::Hook hook = std::move(*result);
ASSERT_TRUE(hook.enable().has_value()); // install returns disabled; arm before driving the detour

auto orig = hook.original<int (*)(int, int)>();
EXPECT_NE(orig, nullptr);
EXPECT_EQ(hook.call<int>(2, 3), /* original result */ 5);
```

### For config parsing

```cpp
// Comments are stripped per-token, not per-line
ini_file << "Keys=0x10, 0x20 ; comment at end\n";
```

## Common issues and fixes

### Duplicate test name

```text
error: 'TestName' is defined twice
```

Fix: use distinct, descriptive names. Never append numeric suffixes.

### std::byte array initialization

```text
error: cannot initialize 'std::byte' with 'int'
```

Fix: use explicit casts:

```cpp
std::byte data[] = {static_cast<std::byte>(0x48), static_cast<std::byte>(0x8B)};
```

### g++ coverage tool bug

```text
Got negative hit value in: ...
```

Fix: add `--gcov-ignore-parse-errors negative_hits.warn` to the gcovr command.

### GetProcAddress cast warning

```text
warning: cast between incompatible function types [-Wcast-function-type]
```

This is expected for a `FARPROC` from `GetProcAddress` cast to a typed function pointer. The warning is harmless for integration tests.

## Testing internal and hard-to-reach code

Most suites are ordinary black-box unit tests over a public header. A few need special techniques. Each entry states the contract and the proof source. The individual cases live in the named files.

- Lock-free structures, verified through a test-only accessor. `test_event_dispatcher.cpp` proves the copy-on-write dispatcher's snapshot invariants through `debug_snapshot_use_count()`, gated behind `#define DMK_EVENT_DISPATCHER_INTERNAL_TESTING 1`. That accessor is not public API and must not be defined in consumer code.
- Non-installed internal headers, driven white-box. `test_x86_decode.cpp` (`src/x86_decode.hpp`) and `test_input_intercept.cpp` (`src/internal/input_intercept.hpp`) add `src/` to their include path and call `DetourModKit::detail::` directly. The decoders and the two interception state machines are pure, so hand-crafted byte buffers and hand-supplied state drive each branch.
- Header-only synchronization primitives, stressed under contention. `test_gate_race_probe.cpp` drives concurrent install, commit, teardown, edge-delivery, and release operations against `src/internal/hook_ledger.hpp` and `src/internal/input_binding_gate.hpp`, with no compiled DetourModKit surface included.
- Poll-loop hot-path helpers, tested in isolation. `test_input.cpp` covers the per-cycle `KeyStateCache` and the reshape-generation `BindingToken`.
- Poll-loop `std::function` seams carry a lifetime rule. [docs/design/testing.md](../design/testing.md#poll-loop-probe-seams-install-stopped-clear-after-join) owns the rule. `tests/test_input.cpp`'s `StagedProbeCleanup` is the shared owner, and `InputLifecycleProof.StagedProbeCleanupJoinsBeforeDestroyingProbeCaptures` is the bounded forced-cleanup control.
- Self-referential lifetimes, observed through a live-instance counter. A detached `AsyncLogger` is kept alive by a retention root it holds on itself, so a retained writer is reachable only from itself. `test_logger.cpp` reads `DetourModKit::detail::g_async_logger_live_count_for_test` instead. The proofs are `DetachedWriterRetentionHasNoAllocationAndNoFiniteCeiling`, `CleanJoinBreaksTheRetentionRootAndLeaksNothing`, and `PrePublicationFailureBreaksTheRetentionRoot`.
- Completed same-base module replacement, driven through the fixed-base fixture. `test_memory.cpp` maps `dmk_rtti_gen_a.dll`, lets `dmk_rtti_gen_b.dll` claim the same base, and gives the replacement a different `OptionalHeader.SizeOfImage` through the `ImageSizeOverride` helper. The two variants publish equal sizes by construction. `memory::module_of` and the named-region consumers must both report the replacement's extent inside one lifecycle generation, which a span memoized per module handle cannot do. The case skips where the loader will not honor the reserved base, so it publishes an XML property once it observes the replacement. See the executed-case evidence section above.
- Live OS hooks, exercised against a throwaway window and skipped when headless. The `WH_GETMESSAGE` wheel hook and the `XInputGetState` inline hook cases in `test_input_intercept.cpp` stand up a top-level window and load an `xinput` runtime. Each case skips itself on a host with no window station or XInput runtime. `InterceptMessageHookTest.*` posts wheel records to a window on the pumping thread and reads the outcome from the retrieved message, and `InterceptMessageHookTest.MigrationRemovesOldHookBeforeNewMountAndBumpsGeneration` plus `TargetThreadExitRetiresRouteToRetryable` pin route migration and health. Two paths keep no automated coverage: a clear of a live controller's `wButtons`, which needs a physically connected pad, and the physical wheel routes in the real game. The `GamepadSuppressTest` state-machine cases plus manual play-testing cover the gamepad path indirectly.

## Benchmark harness

`DMK_BUILD_BENCHMARKS=ON` builds four standalone microbenchmark executables. None is a gtest binary, so each runs under any build configuration (release, release+PGO, ASan) without the gtest runtime. Each prints its results as a table on stdout:

- `DetourModKit_bench` (`bench_event_dispatcher.cpp`) measures EventDispatcher emit / subscribe throughput.
- `DetourModKit_bench_scanner` (`bench_scanner.cpp`) measures `detail::find_pattern` over six pattern shapes on a shared 8 MiB code-like buffer. It also measures rare-byte anchor versus a naive first-byte anchor, prefilter and verify isolation rows, and serial cascade resolution versus `scan::resolve_batch`.
- `DetourModKit_bench_memory` (`bench_memory.cpp`) measures the cost of each way to read game memory from a hot path. The compared ways are the validation predicate (warm hit / cold miss), the direct SEH-guarded read, and the pointer-chain primitives. It adds per-probe tail-latency and per-frame budget studies.
- `DetourModKit_bench_logger` (`bench_logger.cpp`) measures async-logger producer enqueue latency while the writer actively drains. Timed `enqueue` calls run against an 8192-slot queue with `DropOldest` overflow, reported as p50 / p99 / p999 / max nanoseconds plus the dropped-record count.

The option is independent of `DMK_BUILD_TESTS`, so the benches build alone:

```bash
PATH="/c/msys64/mingw64/bin:$PATH"
cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON
cmake --build build/mingw-release --parallel
./build/mingw-release/tests/DetourModKit_bench.exe > bench.tsv
```

`DetourModKit_bench` output has columns `scenario, subscribers, iterations, median_ns_per_op, total_ms`. The covered scenarios:

- `emit` / `emit_safe` at 0, 1, 8, 64 subscribers (the 0-subscriber rows measure the fast path).
- `subscribe_unsub_roundtrip` (single-thread RAII churn).
- `emit_concurrent_4_threads` (contention stress on the copy-on-write read path).
- `reentrancy_rejection` (cost of the guard's reject-during-handler path).

`DetourModKit_bench_memory` is documented in [../guides/memory/hot-path-memory.md](../guides/memory/hot-path-memory.md). Read the `probe_gated_over_direct` metric for the gated-versus-direct multiplier on your machine.

### Benchmark gate records

Every executable also emits the record set defined in [`tests/bench_gate.hpp`](../../tests/bench_gate.hpp) and exits nonzero when a deterministic gate fails. Before this existed, a broken benchmark printed a shorter table and returned success. The breakage was a pattern that failed to compile, a backing page never committed, or a pointer chain resolved to the wrong cell. That made every number above it decoration.

- `#GATE suite name kind status observed relation threshold` is one record per checked property. `deterministic` gates are correctness facts and block on any host. `timing` gates carry a declared wall-clock ratio.
- `#METRIC suite name value` is a measurement whose policy needs more than one run, such as the AVX-512-versus-AVX2 verify throughput ratio.
- `#HOST identity`, `#BUILD role`, and `#TIER name` are stable-comparison provenance. The scanner reads the nonempty host identity from `DMK_BENCH_HOST_ID`. Build role and selected tier are intrinsic.
- `#GATE-END suite count` is the terminal sentinel. It is the only thing that separates "nothing failed" from "the process died before it got there".

[docs/design/build-ci.md](../design/build-ci.md) owns the record-identity and stable-host policy. The test evidence: `tests/bench_gate.hpp` enforces the identity shape, rejects a ledger that emits no gate, and makes close terminal. The standalone `dmk_bench_gate_probe` compiles that header as its own producer and exercises valid, refused, failed, zero-count, duplicate-close, and post-close modes. `scripts/test_check_benchmark_results.py` has 57 parser, policy, provenance, CLI, and compiled-producer cases and requires the probe path from CTest or the release workflow. It resolves that path to an absolute one before it executes it. Windows refuses a relative program path spelled with forward slashes and no leading `./`, which is exactly what the release workflow's `find` hands it. CTest's generator expression hands it an absolute one. One case pins that spelling so the two callers cannot diverge again.

`release.yml`'s `benchmark-evidence` job builds and runs all four on every dispatch, preflight included, then checks the captures without `--stable-host` and uploads them as an artifact.

## Installed package smoke test

`tests/package_smoke` is a minimal consumer project that validates installed release packages. It uses `find_package(DetourModKit REQUIRED)`, links `DetourModKit::DetourModKit`, and touches `hook::is_target_hooked`, so the final link requires the static dependency archives.

```bash
cmake -S tests/package_smoke -B build/package-smoke-mingw -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DDetourModKit_DIR="$PWD/install_package/mingw/lib/cmake/DetourModKit" \
    -DCMAKE_CXX_COMPILER=g++
cmake --build build/package-smoke-mingw --parallel
ctest --test-dir build/package-smoke-mingw --output-on-failure
```

The release workflow runs this smoke project for both MinGW and MSVC after it installs the package and before it uploads release artifacts.

## Project structure

Test files are named by the surface they verify and live under `tests/`. That directory is the authoritative list. Most modules have one `test_<module>.cpp`, while large modules split by API surface, fault-frame state, or integration boundary. These files deserve a callout, because their role is not obvious from the name:

- Deliberate same-module splits: `test_memory_chain.cpp` (pointer-chain and plausibility primitives) is split from `test_memory.cpp`, and `test_string.cpp` (the `string::trim` cases) shares `format.hpp` with `test_format.cpp`. Scanner and RTTI have several focused suites for string xrefs, resolver tiers, parallel scans, reverse dissection, and heal scheduling.
- Compile-time proofs: `test_memory_representation.cpp` carries the typed-read participation matrix as `static_assert` s, so rejected types are asserted false instead of written as calls that cannot compile. Its runtime case instantiates accepted function bodies and verifies their decoded values. The matrix-reporting case gives ctest a named route for the compile-time portion.
- Internal white-box tests: `test_input_intercept.cpp`, `test_x86_decode.cpp`, and `test_gate_race_probe.cpp` add `src/` to their include path to drive non-installed headers directly. The gate race probe is isolated from the compiled library, so it exercises only the hook-ledger and input-gate synchronization primitives.
- Integration and lifecycle: `test_hook_integration.cpp` (cross-module hooks against the fixture DLL), `test_session.cpp` (`Session` / bootstrap / ordered `~Session` teardown), and `test_mid_hook_context.cpp` ( `hook::MidContext` accessors).
- Non- `test_*` support: `main.cpp` (GoogleTest entry point), `CMakeLists.txt` (test discovery, fixture DLL build, bench wiring), and `fixtures/hook_target_lib.cpp` (the exported-function fixture DLL). `package_smoke/` is the installed-package consumer, and the `bench_*.cpp` microbenches build under `DMK_BUILD_BENCHMARKS`.

The `docs/tests/` directory holds this guide plus the coverage tooling:

```text
docs/tests/
├── README.md          # This guide
├── parse_coverage.py  # Coverage JSON parser script
├── test_compile.cpp   # Minimal toolchain verification stub
└── coverage/          # Generated HTML reports (gitignored)
    └── index.html     # Entry point for HTML coverage report
```

## Helper scripts

### parse_coverage.py

Parses `coverage.json` to display per-file coverage statistics:

```bash
# Generate coverage.json into the coverage subdirectory
python -m gcovr --root . --filter "src/" --filter "include/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --gcov-ignore-parse-errors negative_hits.warn \
    --json docs/tests/coverage/coverage.json

# Run the parser
python docs/tests/parse_coverage.py docs/tests/coverage/coverage.json
```

### test_compile.cpp

A minimal stub (`int main() { return 0; }`) that verifies the toolchain works:

```bash
g++ -o test_compile.exe docs/tests/test_compile.cpp
```

## Best practices

1. Start with error paths: test invalid inputs first, for easy coverage gains.
2. Use real addresses: for hook tests, use `DMK_TEST_NOINLINE` functions or DLL exports.
3. Use `ASSERT_*` for preconditions: stop the test immediately if setup fails.
4. Use `EXPECT_*` for verifications: continue the test even if one check fails.
5. Guard platform-specific tests: use `GTEST_SKIP()` for architecture-dependent logic.
6. Rebuild clean for coverage: after major changes, delete `.gcda` files or rebuild from scratch.
7. Follow naming conventions: `s_` for file-scope statics, `m_` for members, `snake_case` for functions.
