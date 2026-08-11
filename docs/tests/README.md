# Test Coverage Guide

## Overview

This guide documents the testing strategy for DetourModKit, including how to build with coverage, run tests, interpret reports, and address common obstacles.

## Quick Commands

### Build with Coverage

```bash
# Using CMake presets (recommended)
PATH="/c/msys64/mingw64/bin:$PATH"
cmake --preset mingw-debug -DDMK_ENABLE_COVERAGE=ON
cmake --build build/mingw-debug --parallel
```

### Run Tests

`ctest` is the canonical runner. `gtest_discover_tests` registers each test case as its own ctest test, so ctest runs each case in a separate process. Prefer it -- some suites drive process-global state (the `ConfigTest` log-capture cases reconfigure the one `log()` sink) and can interleave when many cases share a single monolithic process. The standalone `DetourModKit_tests.exe` is for fast local iteration and `--gtest_filter` debugging, not the canonical green/red signal.

```bash
PATH="/c/msys64/mingw64/bin:$PATH"

# Canonical: per-case process isolation
ctest --preset mingw-debug --output-on-failure

# Fast local iteration (single process -- log-capture cases may interleave)
./build/mingw-debug/tests/DetourModKit_tests.exe
./build/mingw-debug/tests/DetourModKit_tests.exe --gtest_filter="LoggerTest.*"
```

### Generate Coverage Report

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

## Coverage Analysis Workflow

### 1. Identify Low-Coverage Files

Run the full coverage report and look for files below the 80% gate:

```bash
python -m gcovr --root . --filter "src/" --filter "include/" \
    --exclude "external/" --exclude "build/" --exclude "tests/" \
    --gcov-ignore-parse-errors negative_hits.warn \
    --print-summary
```

### 2. Check Specific File Coverage

```bash
python -m gcovr --root . --filter "src/hook.cpp" --txt
```

### 3. Analyze Uncovered Lines

Look at the "Missing" column for specific line numbers, then categorize by reason:

| Reason | Examples | Solution |
| ------ | -------- | -------- |
| **Invalid memory addresses** | Hook functions requiring valid function pointers | Use real function addresses with `DMK_TEST_NOINLINE` |
| **Error paths** | Exception handlers, error returns | Test with invalid inputs that trigger errors |
| **Windows API errors** | `GetModuleHandleExA`, `VirtualQuery` failures | Accept limitation or mock |
| **Template instantiation** | Template methods only instantiated with specific types | Add tests calling with those types |
| **Threading race conditions** | Lock-free CAS retry loops | Difficult to cover deterministically |
| **Cross-module paths** | DLL hooking, module scanning | Use integration tests with `hook_target_lib.dll` |

## Test Architecture

### Unit Tests

Each module has a corresponding test file that tests the module in isolation:

```text
src/<module>.cpp  →  tests/test_<module>.cpp
```

Unit tests use `DMK_TEST_NOINLINE` static functions as hook targets within the test binary itself. This validates the hooking mechanics without cross-module complexity.

### Integration Tests

`tests/test_hook_integration.cpp` tests the real-world DLL hooking workflow against `tests/fixtures/hook_target_lib.cpp` (built as a shared library):

1. `LoadLibrary` the fixture DLL
2. `GetProcAddress` to resolve exports
3. Hook exported functions via `hook::inline_at` (by address and AOB scan)
4. Verify behavioral changes (altered return values)
5. Drop the `Hook` handles and verify original behavior is restored

The fixture DLL exports `extern "C"` functions with volatile magic constants for stable AOB patterns across builds.

## Hook Testing

The hook surface is exercised by five test files:

- `tests/test_hook.cpp` -- the free-function / RAII surface (`hook::inline_at`, `hook::mid_at`, `hook::vmt_for`, `hook::install_all`): inline / mid / vmt installs, `Hook` lifecycle (enable / disable / release / destructor unhook), duplicate detection, prologue policy, `Hook::call`, `install_all` batch outcomes, and `install_all`'s `noexcept` out-of-memory degradation (via the `dmk_test::AllocFailScope` injector).
- `tests/test_mid_hook_context.cpp` -- `hook::MidContext` accessors (`gpr` / `stack_pointer` / `resume_stack_pointer` / `instruction_pointer` / `flags` / `xmm`).
- `tests/test_hook_backend.cpp` -- the managed hook/backend transaction boundary: post-commit reported failures, contained throws before and after inline/mid enable, disable and rollback mutation, conservative Foreign/Indeterminate recovery after a committed restore, safe teardown with a stale backend flag, allocation-failure-safe pin diagnostics, persistent emitted-patch provenance, zero-filled first-enable refusal, and preservation of Foreign bytes. Test-only address-scoped seams run transaction cleanup before returning an error or rethrowing, so each discovered GoogleTest is an isolated host-survival and state-reconciliation proof.
- `tests/test_hook_integration.cpp` -- real-DLL cross-module hooking against the `hook_target_lib.dll` fixture.
- `tests/test_diagnostics.cpp` -- covers hook-lifecycle diagnostic events (install / enable / disable / teardown) emitted through the diagnostics surface.

### Using Real Function Addresses

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

### Cross-Module Hooking (Integration Tests)

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

### AOB Scan + Hook Pipeline

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

### What Can Be Tested

- **Pre-flight validation**: Invalid addresses, null pointers, duplicate names, unsafe prologues
- **Hook lifecycle**: Install, enable, disable, release, RAII destructor unhook, re-enable
- **Original invocation**: `Hook::original<Fn>()` (typed trampoline) and `Hook::call<Ret>(Args...)` (guarded by the per-hook mutex)
- **Batch install**: `hook::install_all` Mandatory / BestEffort severities and per-row `InstallOutcome`
- **noexcept-batch degradation**: `scan::resolve_batch` and `hook::install_all` degrade rather than terminate under injected out-of-memory (the thread-local `dmk_test::AllocFailScope` injector): a `resolve_batch` container-allocation failure is signalled by the outer `Result<...>` as `Error{OutOfMemory}`, and a per-request `bad_alloc` degrades only that slot, with no throw escaping the `noexcept` boundary
- **Concurrent access**: Multi-threaded hook creation stress tests
- **Cross-module hooking**: DLL exports hooked and verified via integration tests
- **AOB scan pipeline**: `scan::scan` / `scan::resolve` finds patterns in loaded DLLs, hooks the result via `hook::inline_at(InlineRequest{.target = scan::OwnedScanRequest{...}})`
- **Mid hooks**: Argument inspection and modification via `hook::MidContext` (the DMK accessors `gpr()` / `stack_pointer()` / `instruction_pointer()` / `xmm()`)

### Platform-Specific Tests

Mid hook tests that modify registers (`gpr(ctx, Gpr::Rcx)`, `gpr(ctx, Gpr::Rdx)`) are x86-64 specific. Guard with:

```cpp
#if !defined(__x86_64__) && !defined(_M_X64)
    GTEST_SKIP() << "Requires x86-64 calling convention";
#endif
```

### Fault-injection tests (`tests/fault/`, CMake-owned proof target)

A test that must observe a guarded primitive contain a real hardware fault needs a committed `PAGE_NOACCESS` page held until process teardown (never `MEM_RELEASE`d, so a recycled virtual address cannot flake the fault onto live memory). These fixtures do **not** join the `tests/test_*.cpp` glob: adding a file there forces a `CONFIGURE_DEPENDS` reconfigure that rebuilds the main C++23 test target. Instead:

- Reusable fixtures live in [`tests/fixtures/fault_injection.hpp`](../../tests/fixtures/fault_injection.hpp): `dmk_test::NoAccessPage` (a leaked-on-purpose committed no-access page), `dmk_test::ProtectedPage` (a page pinned to a chosen protection, with `current_protection()` for asserting a fault path restored it), and `dmk_test::ExecutablePage` (a zero-filled RWX page usable as a synthetic module image, with helpers to plant a literal and a RIP-relative `lea`).
- Fault TUs live in `tests/fault/test_*.cpp`. [`tests/fault/CMakeLists.txt`](../../tests/fault/CMakeLists.txt) compiles them into the `fault_tests` proof target linked against the archive, and `gtest_discover_tests` registers each case as its own ctest test under the `fault-proof` label with a real execution timeout, so `ctest` drives them in the normal flow. `CONFIGURE_DEPENDS` picks up a new fault TU without adding it to the monolithic test target. Build and run the complete fault-proof target set with `bash scripts/run_fault_tests.sh` (any configured tests-ON tree), or build `fault_tests` plus `fault_scanner_escape_probe` and run `ctest -L fault-proof` directly.
- **Both toolchains run every case.** The directory carries no toolchain gate: MSVC contains a fault in a frame-based `__try`/`__except` and MinGW x64 in a process-wide vectored handler with a thread-local armed range, and gating the directory leaves whichever mechanism it excludes unproven. A case that reaches a fault frame directly carries a per-compiler arm and states what each arm proves; a case whose subject is a public `memory::` contract needs no arm.
- Inject the fault into the **foreign target** a guard actually arms (the target of a read / walk / in-place write), not a write's caller-owned source: both guards confine their claim to the declared range and let a fault outside it reach the host, so a faulting source is a caller-contract violation that crashes rather than failing closed. This is also why the escalating write slow-path copy-fault arm is not deterministic single-threaded -- once the slow path has made the target writable, only a concurrent reprotect can fault the copy.

`tests/fault/test_fault_containment.cpp` proves guarded read, pointer-chain walk, and `write_in_place` all fail closed against a no-access page, the deterministic escalating write slow-path protection restore, containment of a RIP snapshot tail that crosses into `PAGE_NOACCESS`, and that an enclosing guard still holds after a nested guarded read returns.

`tests/fault/fault_scanner_escape_probe.cpp` proves both sides of that contract. Both scanner sweeps declare an exact span -- the region sweep `[region_start, capture_limit)`, the string-xref narrow sweep the gated window -- and a fault outside it is an unrelated defect the host has to see, not the concurrent unmap the guard absorbs. Neither outcome is observable from outside the guard (both report "the sweep was incomplete"), and an escaping access violation cannot share the GoogleTest process, so this is a raw host with an exit-status oracle. The `region` and `xref` modes drive real scans and use the `DMK_ENABLE_TEST_SEAMS`-gated slot in `src/internal/scan_fault_seam.hpp` to read one outside address from inside the guarded body. The paired `xref-in-span` mode reprotects its accepted window only after phase 1 reaches the narrow body, then requires that call site's filter to contain the injected in-span fault. On MSVC an escaping exception unwinds to the host's own `__except`, whose filter accepts only the exact injected address; on MinGW nothing claims it and the host's top-level filter proves it got out. A still-armed slot after the scan is a setup failure rather than either verdict.

Because `ctest -L fault-proof` exits zero on an empty selection, [`tests/CMakeLists.txt`](../../tests/CMakeLists.txt) registers `FaultProof.LabelInventoryIsComplete` -- outside `tests/fault/`, so a skipped subdirectory cannot skip its own gate. It runs [`scripts/check_test_label_inventory.py`](../../scripts/check_test_label_inventory.py) against the tree's own CTest inventory and fails when a named case is absent or duplicated, when the label carries fewer cases than declared, or when `fault_tests` was never built (GoogleTest's `_NOT_BUILT` placeholder). `scripts/test_check_test_label_inventory.py` pins those rejections and is registered as the `TestLabelInventoryGateSelfTest` script-lint ctest.

### Lifecycle proofs (`tests/lifecycle/`, CMake-owned targets)

A proof that needs a real loader transition (`LoadLibrary`/`FreeLibrary` reference-count behavior, `DLL_PROCESS_DETACH`) or a controlled static-teardown ordering cannot run inside the monolithic GoogleTest process, and several of them replace the global allocation operators for their whole process -- `diagnostics_first_use_oom.cpp` is the only one whose poison is armed by constant initialization, so it covers the loader's own initializer pass rather than a window opened from `main`. These live in `tests/lifecycle/`. [`tests/lifecycle/CMakeLists.txt`](../../tests/lifecycle/CMakeLists.txt) builds each as a CMake-owned target and registers it as a `lifecycle-proof`-labelled ctest whose verdict is the process exit code (0 = pass, any other code a proof or setup failure, with the failing check identified by the code it returns and a message on stderr). A proof whose subject is not present on every host must declare `SKIP_RETURN_CODE` on its `dmk_add_raw_proof` call and return that code from its unavailable branch, so ctest reports Skipped rather than counting a run that asserted nothing as a pass; the XInput rundown proofs use 77. Build and run with `bash scripts/run_lifecycle_proofs.sh`, or build the lifecycle targets and run `ctest -L lifecycle-proof` directly. `tests/lifecycle/CMakeLists.txt` carries no toolchain gate: language, allocation, threading, and OS behavior all run on both toolchains, and that includes the `LoadLibrary`/`FreeLibrary` reference-count and `DLL_PROCESS_DETACH` proofs, since loader reference counting is an OS property and the archive links into a SHARED target under both toolchains. A proof whose subject is genuinely toolchain-specific (MinGW emulated-TLS behavior, for example) needs its own per-compiler arm or a separate counterpart rather than a gate that removes it from the other toolchain, exactly as `tests/fault/` does for the SEH-versus-VEH fault frames.

- `bootstrap_probe_dll.cpp` -- a minimal mod-shaped DLL whose `DllMain` forwards attach/detach into `bootstrap()`/`bootstrap_detach()`, linked against the archive (the `bootstrap_probe` target). It is the only lifecycle target loaded through a real loader transition rather than launched as a host process. Any target that links the archive also links `dmk_coverage`, because it performs the final link of the instrumented library.
- `test_bootstrap_module_ref.cpp` -- the loader host. Proves the bootstrap worker's counted module reference in both directions: the module stays mapped across a balanced `FreeLibrary` ("mapped"), and the probe's exported synchronous drain (`dmk_probe_shutdown_and_wait`, forwarding to `DetourModKit::shutdown_and_wait()`) returns only after the worker's ordered teardown and module-reference release, so a following `FreeLibrary` genuinely unloads it ("unload"). The "leaf" scenario counts attach-thread allocations and requires zero; "bare" pauses the worker callback, drops the host reference, then lets the worker self-drain through a real `DLL_PROCESS_DETACH` without destroying its callback capture under the loader lock; and "exit" leaves the loaded DLL and worker live so process termination delivers the real process-exit detach notification.
- `test_full_lifecycle.cpp` -- the long-lived host (the `full_lifecycle` target). One binary, four separately registered scenarios selected by `argv[1]`, because their terminal states are mutually exclusive in one process: `cycles` (six bootstrap/use-every-subsystem/drain generations, asserting a clean drain retains nothing), `concurrent` (two control threads drain one generation; exactly one owns it and the other gets `SessionShutdownInProgress`), `misuse` (a bare-FreeLibrary `DLL_PROCESS_DETACH` against a live worker must abandon, pin, record the leak, refuse a later drain with `SessionShutdownUnavailable`, and still let the pinned worker finish its own teardown), and `exit` (process exit reached with every subsystem still live, so the CRT teardown path neither hangs nor faults).
- `xinput_detour_rundown.cpp` -- the fresh-process XInput transaction and teardown host. `timeout` and `reference-balance` prove allocation-free retention of an in-flight detour and balanced keepalives after a witnessed clean restore. `first-install-oom` poisons caller-thread allocation across the whole first install and requires a clean disabled state, a callable target, a successful retry, and balanced keepalives. `first-install-oom-create` fires a test-only probe after the hook's isolated route allocator exists and poisons the first allocation inside `InlineHook::create`; narrowing `create_disabled_xinput_hook`'s catch fails that mode independently. `enable-before` / `enable-after` and `disable-before` / `disable-after` use an address-scoped backend seam to throw on either side of the primary byte mutation, then require the containment counter, logical state, target callability, retry or retained-chain state, and keepalive ownership to agree with the witnessed bytes. `disable-ex-before` uses the checked-in same-module proxy to prove an optional Ex restore refusal retains the still-armed primary and leaves it rearmable. `newer-layer` installs a managed hook above the raw XInput detour, tears down the raw owner, and requires both the newer patch and its saved original chain to remain callable. `newer-layer-ex` puts that managed layer over the proxy's primary only and requires the ordinal-100 trampoline to survive teardown, which is the pre-restore pair classification: removing it restores the Ex prologue alone and fails this case and no other. `disable-primary-before` covers the opposite asymmetry, which is the one no pre-restore classification can see: the ordinal-100 restore commits and the primary restore then refuses. Retaining there without putting the Ex member back publishes a primary-only chain and loses an entry point that was masked on entry, permanently, because a later install accepts the retained primary without ever reaching Ex creation. The case requires the ordinal-100 trampoline to survive the retention and the following install. `pair-compensation-inverted` beats that compensation with an arm-window writer, requires a refused ordinal-100 recovery to leave the retained primary fail-open and marked degraded, requires a 64-cycle retry burst to run no further backend transaction, and then requires exactly one transaction to recover the retained Ex member once the delay expires instead of latching primary-only coverage; skipping the recovery, or letting the retries run at poll cadence, fails this mode and no other. `arm-inversion` drives an arm-boundary seam that restores the original prologue between the committed backend toggle and the witness read, then requires the install to keep both keepalives and move the hook into permanent storage instead of destroying a trampoline the patched prologue already published; destroying the candidate or taking the ordinary failure exit each fails this mode and no other. `ex-arm-inversion` inverts the ordinal-100 arm instead, so the pair keeps an armed primary beside an inactive hook that still names an export it no longer patches. That is degraded coverage, not success: the mode requires the install to report incomplete, both detours to pass through a published suppression mask, the primary trampoline to stay readable by the owning poller, and a 64-cycle retry burst to reach the backend at most once. A foreign writer then takes that export and the drained teardown must still restore and release the primary. Publishing coverage over an unarmed distinct ordinal-100 member, removing the recovery deadline, hiding the degraded trampoline from its owner, or reading the inactive hook's target bytes for its restore verdict each fail this mode and no other. CMake registers every mode as a separate `Lifecycle.XInput*` ctest with a 60-second timeout; host-dependent modes use skip code 77, so retained process-global hook state never crosses scenarios and an unavailable subject cannot false-pass. This host is also the one test target that names the backend directly, because the routed-unwind scenarios assert against the generated regions themselves. `wrapper-unwind` requires all three generated regions to resolve through `RtlLookupFunctionEntry`, virtually unwinds synthetic gateway and exit contexts at the live-body and `popfq` boundaries, then walks out of a live detour and requires the wrapper frame to reach the hooked caller. `wrapper-native-exception` throws from the detour and requires the caller's handler, with the entrant still counted because an unwound call never returns to decrement. `unwind-registration-refused` drives registration refusal, proves an untouched target and unchanged accounting, then destroys a successful never-published route and requires all three records to disappear. `route-metadata-retained` destroys a published hook and requires gateway, wrapper, and exit records to survive; `unwind-unregistration-refused` drives deletion refusal and requires the same records and their complete arena charge to remain. `route-capacity-refusal` independently removes logical and committed headroom, then proves dual reservation before publication and exact conversion to actual charged backing blocks afterwards. `route-capacity-overflow` refuses an overflowing credit count without changing any totals. `route-allocator-reclamation` keeps an allocator alive, frees its only allocation, and requires `VirtualQuery` to report the whole block as `MEM_FREE`. `mid-route-accounting` pollutes the caller allocator with an oversized block, requires MidHook to isolate its route anyway, and includes the generated 404-byte stub and its allocator block in the published charge. `xinput-pair-capacity` leaves room for one slot and requires the explicit two-slot transaction to refuse both entries. The post-mutation enable-exception and restore-error cases each require a committed route to leave no reservation and enter both charged totals. Mutating registration, unregistration, either flag-frame unwind code, MID-stub inclusion, reservation conversion, or checked credit arithmetic therefore fails its focused mode.
- `xinput_forwarding_guard.cpp` -- the ordinal-100 membership host. Four checked-in proxy DLLs give the branch its own deterministic export shape instead of leaving it to whichever xinput runtime the machine happens to load: ordinal 100 local to the patched module, forwarded into another module, absent, and aliased onto `XInputGetState`. `forwarded` and `same-module` are distinct members and require their own hook; the forwarded one additionally requires the third target-module keepalive and a pass-through call that reaches the resolved target. `absent-ex` and `alias-ex` are the only exemptions and require complete coverage from the primary hook alone: the install reports success, no second chain is published, two keepalives are held, a published mask actually clears the bound controller's bits, and the single patched prologue still forwards exactly once. Treating an absent ordinal as a distinct member fails `absent-ex` and no other mode; dropping the alias exemption fails `alias-ex` and no other, which is the guard against a second inline hook capturing the first hook's jump as its original.
- `input_tls_exhaustion.cpp` -- the delivery-marker admission host, and the only place the marker's failure mode is reachable: taking every TLS index is process-wide and the marker latches its unavailability, so neither half can be undone inside the shared unit process. `exhausted` consumes every index before DetourModKit reserves its slot, makes two threads race the serialized first reservation and requires both to report failure, then requires hold true, hold false, and press delivery refusal to run no consumer code and to restore the gate state each edge found. One thread's unrecordable frame must leave another thread reading as not callback-entrant (any answer wider than "this thread" lets an unrelated control-plane release skip the rundown its public contract promises), while balancing-edge and retired-callable self-reentry must complete on both an ordinary C++ thread and a foreign `CreateThread` host thread using the exact allocation-free Win32 identity -- a regression there hangs, so the ctest timeout is the oracle. It then hands the indices back and drives the real facade, requiring zero delivered edges. `available` is the positive control over the same drive: a binding that never matched would also produce zero edges, so the refusal case means nothing without it. A third registration is the `WILL_FAIL` unknown-token control. `store-failure` covers the branch index exhaustion cannot reach: the reservation succeeds and only the per-thread depth store fails, which is what a reserved index past the TEB's inline slots does when its lazily heap-allocated expansion array cannot be grown. It requires the frame to report itself unrecorded, the thread to keep reading as not callback-entrant, hold and press deliveries to run no consumer code and restore the gate state they found, and then -- with the store working again -- an ordinary delivery, its balancing edge, and a real facade drive to all succeed, so a permanently broken store cannot pass as a refusal proof.
- `test_profiler_late_uaf.cpp` -- compiles `src/profiler.cpp` directly and replaces global `operator new`/`delete` with a size-targeted poisoning allocator, so a `ScopedProfile` record that outlives ordinary static teardown faults deterministically if the profiler singleton were ever destroyed early. It links no library and is not instrumented for coverage, so gcov's `atexit` `.gcda` flush cannot allocate into the poisoned path.
- `diagnostics_first_use_oom.cpp` -- one source built twice. With `DMK_DIAGNOSTICS_OOM_PROBE_DLL` it is the `diagnostics_oom_probe` DLL: it links the archive and replaces every global allocation operator, plain and over-aligned, with a poison that is *constant-initialized to armed*, so every C++ allocation attempted while the loader runs that module's initializers fails. The aligned family is included deliberately and is backed by `_aligned_malloc` / `_aligned_free` so the two families never cross: DMK already allocates an over-aligned block through the nothrow aligned operator new (`src/internal/async_logger.cpp`), so leaving that family at its default would leave a channel that serves a load-time allocation instead of refusing it. The positive control below exercises both families for that reason. Without the macro the same file is the host, which must not link the archive or its own copy of DMK would initialize outside the poisoned window. The window is otherwise unreachable: DMK's static initializers run inside `LoadLibrary`, before any user bootstrap gets control, and an allocation failure there has no handler. Three things have to hold together for a pass, and each kills a different way of faking one: `LoadLibrary` succeeds (an allocating initializer that propagates fails the load outright), the probe's own deliberate allocation is *refused* (without this positive control, a module whose `operator new` replacement never took effect is indistinguishable from one that needed no memory), and the load-time refusal count is exactly zero (an initializer that allocates but swallows the failure stays loadable, and only this counter catches it). An eager `hook_lifecycle().subscribe(...)` initializer makes `LoadLibrary` fail with `ERROR_DLL_INIT_FAILED` (1114). What the proof covers is the probe's link closure, not the archive: DMK links statically, so only referenced object files are present to initialize, and the probe deliberately references the hook surface as well as diagnostics so `hook.cpp` (which owns the population tally) initializes inside the poisoned window.
- `logic_callback_dll.cpp` / `logic_dll_protocol.hpp` / `test_logic_dll_unload.cpp` -- the callback-only Logic-DLL topology. The host (`logic_dll_unload`) links the archive and owns every `Hook`, binding, and config registration; the companion DLL links no DetourModKit archive and contributes only callables. This excludes a second library instance and any install-time self-reference it could add to the unmap verdict. The DLL is deliberately given no path to the library's headers; the one DetourModKit type a mid detour names is forward-declared in the protocol header. Unmap is asserted with `GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT)` over an exported marker. The callable target has an observable nontrivial destructor, and its erased invoker and manager are instantiated inside the DLL, so the construct/destroy tallies remain valid whether the standard library stores the target inline or on the heap. Every process first injects one callable-factory failure and requires the `noexcept` C ABI to return an empty result. Nine scenarios then run in separate processes: `input-drained` proves a completed drain destroys every input callable; `guard-retained` pins the destruction half of the documented retained-guard hazard, and `guard-retained-hold` pins the worse half, that a guard on a still-held binding synthesizes its balancing `on_state_change(false)` after `SafeToUnload`, so the release is a call into the provider and not only a destructor; `input-parked`, `config-setter-parked`, and `config-parked` prove a parked input body, config setter, and reload callback each force refusal; both config cases then release the body, retry to `SafeToUnload`, verify every callable was destroyed, and unmap; `mid-parked` proves ordinary teardown waits; `mid-pinned` proves a still-patched tombstoned stub stays inert after unmap; and `inline-quiesced` first proves the armed detour really chains to its trampoline (the unchained path returns a value the target cannot produce, so a detour that recomputed the result instead of chaining fails), then parks a caller in the detour before applying the caller-owned stop, release, join, destroy, unmap order. Removing the mid-adapter tombstone store fails `mid-pinned`. `mid-parked` and `input-parked` pin composite end-to-end properties because lower layers still enforce their result when either named DMK wait is removed.
- `diagnostics_late_emitter.cpp` -- both arms are strict ordering proofs only because the library subscribes to neither dispatcher during static initialization. An implementation that established a permanent subscription at load would touch `hook_lifecycle()` before this TU could order itself against it, silently weakening that arm from an ordering proof to a delivery assertion without failing.
- `logger_writer_batch_oom.cpp` -- the async writer's forward-progress floor. The regression it owns is a HANG, not a wrong value, so the ctest `TIMEOUT` is the oracle: the writer reserves headroom for a whole batch before popping, and a reservation it can never secure used to pop nothing, skip both idle gates because the queue was not empty, and spin until `shutdown()`'s join blocked forever. `persistent-batch-oom` replaces the global allocation operators with a poison keyed on allocation SIZE rather than on the calling thread -- a thread-local key would need emulated TLS on MinGW, which allocates on first touch and would recurse straight back into the hook -- and arms it before the writer's first successful pop, which is the whole point of the ordering: `std::vector` keeps its capacity across the writer's `clear()`, so a batch that reserved once never reserves again and the failure would be unreachable afterwards. Neutralizing the one-record floor makes the case time out. `oversize-batch` covers the same permanent zero-progress state reached with no memory pressure at all, from a `batch_size` larger than `std::vector`'s `max_size`. Liveness alone cannot distinguish the clamp there, because the floor rescues that configuration too; what separates them is that the clamp keeps the writer BATCHING instead of degrading to one record per cycle behind a thrown `length_error`. Both cases therefore assert on `g_async_logger_batch_floor_counter`: the persistent case requires every record to have gone through the floor (without which it could pass vacuously on a reservation that quietly succeeded), and the oversize case requires none to have.

### CTest execution-timeout control (`tests/lifecycle/timeout_probe.cpp`)

`CTestTimeoutControl` is a passing meta-proof that CTest enforces a test's execution `TIMEOUT` -- the property that fails and kills a hung case -- which is distinct from GoogleTest's `DISCOVERY_TIMEOUT` that only bounds case enumeration. [`scripts/verify_ctest_timeout.cmake`](../../scripts/verify_ctest_timeout.cmake) writes a throwaway inner testfile that registers an intentionally-hung probe (`dmk_timeout_probe`) under a two-second `TIMEOUT`, runs `ctest` against it, and asserts the probe was failed by the timeout diagnostic. The hung probe is never registered in the top-level suite, so an ordinary `ctest` run never blocks on it. This proof is toolchain-agnostic and runs on both MinGW and MSVC. A companion `CTestTimeoutControlNegative` (`WILL_FAIL`) drives the verifier against a fast-failing probe under a scratch path that itself contains the word "timeout", so it passes only when the verifier rejects a non-timeout failure -- pinning the `***Timeout`-token match against a regression to a bare-word match.

On a MinGW build tree the fault, lifecycle and soak wrappers prepend the directory of the tree's configured C++ compiler before launching CTest. This prevents a probe DLL from binding an incompatible `libwinpthread-1.dll` supplied by another MinGW distribution earlier on the caller's `PATH`. All three skip the prepend on an MSVC tree, whose compiler directory carries private `msvcp140` / `vcruntime140` copies that would shadow the system CRT for every proof process.

That directory is not readable from `CMakeCache.txt`. A preset passing `CMAKE_CXX_COMPILER=g++` leaves the cache entry as the bare string `g++`, and an MSVC tree holds bare `cl`, so every basename or dirname test against the cache is answering a question the cache cannot answer. [`scripts/resolve_runtime_dir.py`](../../scripts/resolve_runtime_dir.py) reads the absolute path CMake recorded in `CMakeFiles/<version>/CMakeCXXCompiler.cmake` and prints it, or prints nothing for MSVC. The two shell wrappers cannot share code with each other and Python is already a hard gate dependency, so the parse lives in that one script rather than in three copies: the shell wrappers run it as a subprocess and the Python soak imports its `resolve` directly. It emits forward slashes on every interpreter, because a native Windows Python renders the path with backslashes and an MSYS one with forward slashes.

The shell wrappers take the interpreter that runs it from the tree's own `DMK_PYTHON_EXECUTABLE`, falling back to a `python3` or `python` that has been shown to execute. A bare `command -v python3` is not sufficient on Windows: the App Execution Alias of that name precedes any real interpreter on a default `PATH` and exits nonzero without running the script, which under `set -euo pipefail` aborts the wrapper before it builds anything.

### Release negative controls and lifecycle soak

The blocking sanitizer workflow has one dispatch-only negative control. `dmk_asan_failure_probe` is an `EXCLUDE_FROM_ALL` MSVC-ASan target, is never registered with CTest, and performs one deliberate heap-buffer-overflow only when the workflow explicitly builds and runs it. A capability dispatch is valid evidence only when the ordinary full suite passes first, the probe prints a real AddressSanitizer diagnostic, and the workflow concludes Failure. A normal dispatch at the same exact SHA must then conclude Success. Making the faulting index in-range turns the capability dispatch green, which is the negative control's mutation oracle.

[`scripts/run_lifecycle_soak.py`](../../scripts/run_lifecycle_soak.py) is the final-candidate lifecycle gate used by both Release jobs. It inventories CTest first so a missing label or named regression cannot vacuously pass -- `InputLifecycleProof.CardinalityRebindReleasesDroppedNonPrototypeHold` and `InputLifecycleProof.TlsExhaustionRefusesUntrackedDelivery` are each required to appear exactly once, the second named explicitly because an omitted raw-proof registration would otherwise disappear from the prefix inventory -- temporarily arms per-executable WER LocalDumps minidumps only for the proof processes, and drives `fast_fail_probe wer-crash` through a bounded wait to require a complete `MDMP` control before trusting capture. The assertion is that the control terminated with `STATUS_FAIL_FAST_EXCEPTION` (`0xC0000602`), not merely that it was nonzero, because only that status proves the control exercised the path WER is being asked to capture. Python is what makes that assertion expressible: it reports the raw process exit status, whereas a POSIX shell on Windows maps a fatal status onto a signal number and loses the distinction. `winreg` arms and restores the machine-wide WER values, and the completed-dump check opens with no sharing through `CreateFileW`, so a dump WER is still writing reads as incomplete rather than being trusted for its first four bytes. The control dump is deleted. The script then repeats every `InputLifecycleProof` 200 times serially, runs `Lifecycle.FullLifecycleExit` 100 times serially through `run_lifecycle_proofs.sh`, and runs all `lifecycle-proof` cases 20 times at parallelism four, stopping on the first failure. A restoration guard covers arming and every proof: each newly created key is ledgered before another registry operation can fail, every captured value and key is isolated so one failure does not abandon later work, and an otherwise successful soak exits nonzero unless the registry returns to its pre-run state. A key that was absent before the run is deleted only when it is empty; unowned content is left intact and reported as restoration residue. An earlier soak or unexpected failure stays primary while every cleanup failure is printed alongside it, and the success message is emitted only after restoration passes. `scripts/test_run_lifecycle_soak.py` drives those paths against a stateful stub registry -- so the failure modes are provable without breaking a real machine -- and is registered as the `LifecycleSoakRestorationSelfTest` script-lint ctest. A real crash minidump remains for the workflow's short-retention diagnostic artifact. WER captures unhandled crashes, not hangs, CTest timeouts, cancellations, or ordinary nonzero exits, so CTest's per-case timeouts and `LastTest.log` remain the evidence for those failures. Minidumps can still contain sensitive process memory and must never become release assets. Because WER policy is machine-wide, do not overlap two soak-script invocations on one host; the checked-in Release jobs use separate hosted VMs.

### Script self-tests (`scripts/`, Python)

The `script-lint` label carries nine standalone Python self-tests: `HeaderHygieneStripperSelfTest`, `EmitTlsCheckerSelfTest`, `ExportEqualityGateSelfTest`, `MechanicalStyleCheckerSelfTest`, `TestLabelInventoryGateSelfTest`, `LifecycleSoakRestorationSelfTest`, `RuntimeDirResolverSelfTest`, `BenchmarkResultsCheckerSelfTest`, and `WorkflowTopologyCheckerSelfTest`, plus `WorkflowTopologyIsBlocking`, which runs the topology gate against this repository's own workflows. Python is a tests-ON configure prerequisite because the RTTI generation fixture needs it, so every configured test tree registers all of them; MinGW also registers the `EmitPathHasNoEmulatedTls` archive gate, which rejects winpthreads thread identity from the input binding teardown owner path.

[`scripts/test_check_workflow_topology.py`](../../scripts/test_check_workflow_topology.py) has 28 tests: one positive repository control, 26 negative mutations, and one process-boundary case proving both actual CLI exit codes. The negatives reintroduce advisory/skip markers, weaken compiler/tidy failure policy, invert the publish condition, disable the main-ref or exact-SHA comparison, remove each producer's validation dependency, bypass benchmark checking, or expose `RELEASE_TOKEN` outside the publish job; every mutation must be refused. A topology checker that never refuses anything reports green over exactly the shape it exists to forbid. [`scripts/test_resolve_runtime_dir.py`](../../scripts/test_resolve_runtime_dir.py) pins the compiler-runtime resolution the three proof wrappers share: that a preset tree's bare `g++` cache entry still resolves to the real MinGW `bin` directory, that an MSVC tree resolves to nothing, that a bare compiler name is refused rather than silently resolving to `.` (which is what made the shell wrappers prepend the repository root), and that the separator is forward slashes on every interpreter.

### Header-hygiene stripper self-test (`scripts/`, Python)

`scripts/check_header_hygiene.py`'s legacy-token and backend-confinement gates only inspect real code because the script blanks comments before scanning. A regression in that comment stripper -- for example mistracking a C++14 digit separator such as `1'000'000'000ULL` as a char literal, which would leave the scanner stuck in char state and pass later comments through unstripped -- could fail a PR on a legacy spelling that appears only in prose. [`scripts/test_check_header_hygiene.py`](../../scripts/test_check_header_hygiene.py) pins the stripper behavior and is registered as the `HeaderHygieneStripperSelfTest` ctest (label `script-lint`), so `ctest` runs it alongside the C++ suite on both toolchains.

## Test Naming Conventions

```cpp
// Pattern: Subject_ConditionOrScenario
TEST_F(ClassName, Method_ExpectedBehavior)
TEST_F(HookTest, InlineAt_InvalidAddress)
TEST_F(HookIntegrationTest, AOBScan_InlineAt_EndToEnd)
```

## Adding New Tests

### For Error Paths

```cpp
TEST_F(SomeTest, Method_ErrorCondition)
{
    auto result = object->method(invalid_input);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ExpectedError::Value);
}
```

### For Template Methods

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

### For Config Parsing

```cpp
// Comments are stripped per-token, not per-line
ini_file << "Keys=0x10, 0x20 ; comment at end\n";
```

## Common Issues and Fixes

### Duplicate Test Name

```text
error: 'TestName' is defined twice
```

**Fix**: Use distinct, descriptive names. Never append numeric suffixes.

### std::byte Array Initialization

```text
error: cannot initialize 'std::byte' with 'int'
```

**Fix**: Use explicit casts:

```cpp
std::byte data[] = {static_cast<std::byte>(0x48), static_cast<std::byte>(0x8B)};
```

### g++ Coverage Tool Bug

```text
Got negative hit value in: ...
```

**Fix**: Add `--gcov-ignore-parse-errors negative_hits.warn` to the gcovr command.

### GetProcAddress Cast Warning

```text
warning: cast between incompatible function types [-Wcast-function-type]
```

This is expected when casting `FARPROC` from `GetProcAddress` to a typed function pointer. The warning is harmless for integration tests.

## Coverage Targets

| Target | Difficulty | Notes |
| ------ | ---------- | ----- |
| 80% | Baseline | Error path testing, basic happy paths. CI gate. |
| 85% | Medium | Template instantiation, more error paths |
| 90% | Hard | Integration tests, edge cases in threading |
| 95%+ | Very Hard | Requires mocking Windows API or refactoring |

## Testing Internal and Hard-to-Reach Code

Most suites are ordinary black-box unit tests over a public header. A few need techniques worth documenting; the individual cases live in the named files.

- **Lock-free structures, verified through a test-only accessor.** `test_event_dispatcher.cpp` proves the copy-on-write dispatcher's snapshot invariants (the zero-subscriber fast path never loads the snapshot, an in-flight `emit()` iterates its own snapshot while a concurrent `subscribe()` publishes a new one via CAS, and subscribe/unsubscribe churn leaks no snapshot references) through `debug_snapshot_use_count()`, gated behind `#define DMK_EVENT_DISPATCHER_INTERNAL_TESTING 1`. That accessor is not public API and must not be defined in consumer code.
- **Non-installed internal headers, driven white-box.** `test_x86_decode.cpp` (`src/x86_decode.hpp`, the RIP-relative jump/call decoders the scan engine uses) and `test_input_intercept.cpp` (`src/internal/input_intercept.hpp`, the active-input layer) add `src/` to their include path and call `DetourModKit::detail::` directly. The decoders and the two interception state machines (the wheel-pulse stepper and the gamepad consume-until-release latch) are pure, so each branch is driven by a hand-crafted byte buffer or hand-supplied state rather than real input.
- **Header-only synchronization primitives, stressed under contention.** `test_gate_race_probe.cpp` drives concurrent install, commit, teardown, edge-delivery, and release operations against `src/internal/hook_ledger.hpp` and `src/internal/input_binding_gate.hpp`. It includes no compiled DetourModKit surface, keeping the synchronization checks independent of Windows runtime components while still running in the main test suite.
- **Poll-loop hot-path helpers, tested in isolation.** `test_input.cpp` covers the pieces the live poll loop would otherwise hide behind real process input state: the per-cycle `KeyStateCache` (one probe per distinct VK per cycle, re-armed on `reset()`, failing closed on an out-of-range VK) and the reshape-generation `BindingToken` (a stale token fails closed after a `consume` toggle).
- **Self-referential lifetimes, observed through a live-instance counter.** A detached `AsyncLogger` is kept alive by a retention root it holds on itself, so "was this writer retained or destroyed?" is unreachable from outside: a retained writer is reachable only from itself. `test_logger.cpp` reads `DetourModKit::detail::g_async_logger_live_count_for_test` instead. `DetachedWriterRetentionHasNoAllocationAndNoFiniteCeiling` drives 24 forced loader-lock detaches with caller-thread allocation poisoned across each `shutdown()` and requires every writer to survive with no allocation charged; `CleanJoinBreaksTheRetentionRootAndLeaksNothing` requires the counter to return to its baseline on the joined path; `PrePublicationFailureBreaksTheRetentionRoot` throws from `g_logger_publication_probe` inside the arm-then-publish window and requires the unpublished writer to be destroyed rather than stranded.
- **Completed same-base module replacement, driven through the fixed-base fixture.** `test_memory.cpp` maps `dmk_rtti_gen_a.dll`, lets `dmk_rtti_gen_b.dll` claim the same base, and gives the replacement a different `OptionalHeader.SizeOfImage` through the `ImageSizeOverride` helper, because the two variants publish equal sizes by construction. `memory::module_of` and the named-region consumers must both report the replacement's extent inside one lifecycle generation, which is what a span memoized per module handle could not do.
- **Live OS hooks, exercised against a throwaway window and skipped when headless.** The window-procedure subclass and the `XInputGetState` inline hook in `test_input_intercept.cpp` stand up a top-level window the test process owns and load an `xinput` runtime; each case skips itself when the host has no window station or XInput runtime, so a headless CI runner stays green. `InterceptWndProcTest.UninstallPreservesForeignSubclassInterposedBeforeExchange` inserts a forwarding foreign subclass after uninstall observes DMK at the top and requires the exchange result to restore it. `InterceptWndProcTest.UninstallPreservesLatestSubclassInterposedBeforeCompensation` adds a second writer after that exchange and requires reconciliation to leave the latest returned writer on top. Both cases keep DMK conservatively installed until the test restores it to the top, then exercise the ordinary teardown. The one path with no automated coverage is clearing a live controller's `wButtons` (it needs a physically connected pad), covered indirectly by the `GamepadSuppressTest` state-machine cases plus manual play-testing.

## Benchmark Harness

`DMK_BUILD_BENCHMARKS=ON` builds four standalone microbenchmark executables. Each is deliberately not a gtest binary, so it runs under any build configuration (release, release+PGO, ASan, etc.) without dragging in the gtest runtime, and each prints its results as a table on stdout:

- `DetourModKit_bench` (`bench_event_dispatcher.cpp`) -- EventDispatcher emit / subscribe throughput.
- `DetourModKit_bench_scanner` (`bench_scanner.cpp`) -- `detail::find_pattern` over six pattern shapes on a shared 8 MiB code-like buffer, rare-byte anchor vs a naive first-byte anchor, prefilter and verify isolation rows, and serial cascade resolution vs `scan::resolve_batch`.
- `DetourModKit_bench_memory` (`bench_memory.cpp`) -- the cost of each way to read game memory from a hot path: validation predicate (warm hit / cold miss) vs direct SEH-guarded read vs the pointer-chain primitives, plus per-probe tail-latency and per-frame budget studies.
- `DetourModKit_bench_logger` (`bench_logger.cpp`) -- async-logger producer enqueue latency while the writer is actively draining: timed `enqueue` calls against an 8192-slot queue with `DropOldest` overflow, reported as p50 / p99 / p999 / max nanoseconds plus the dropped-record count.

The option is independent of `DMK_BUILD_TESTS`, so the benches build alone:

```bash
PATH="/c/msys64/mingw64/bin:$PATH"
cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON
cmake --build build/mingw-release --parallel
./build/mingw-release/tests/DetourModKit_bench.exe > bench.tsv
```

`DetourModKit_bench` output has columns `scenario, subscribers, iterations, median_ns_per_op, total_ms`. Covered scenarios:

- `emit` / `emit_safe` at 0, 1, 8, 64 subscribers (the 0-subscriber rows measure the fast path).
- `subscribe_unsub_roundtrip` (single-thread RAII churn).
- `emit_concurrent_4_threads` (contention stress on the copy-on-write read path).
- `reentrancy_rejection` (cost of the guard's reject-during-handler path).

`DetourModKit_bench_memory` is documented in [../guides/memory/hot-path-memory.md](../guides/memory/hot-path-memory.md); read the `probe_gated_over_direct` metric for the gated-vs-direct multiplier on your machine.

### Benchmark gate records

Every executable also emits the record set defined in [`tests/bench_gate.hpp`](../../tests/bench_gate.hpp) and exits nonzero when a deterministic gate fails. Before this existed a benchmark whose pattern failed to compile, whose backing page was never committed, or whose pointer chain resolved to the wrong cell printed a shorter table and returned success, which made every number above it decoration.

- `#GATE  suite  name  kind  status  observed  relation  threshold` -- one per checked property. `deterministic` gates are correctness facts and block on any host; `timing` gates carry a declared wall-clock ratio.
- `#METRIC  suite  name  value` -- a measurement whose policy needs more than one run, such as the AVX-512-versus-AVX2 verify throughput ratio.
- `#HOST  identity`, `#BUILD  role`, and `#TIER  name` -- stable-comparison provenance. The scanner reads the nonempty host identity from `DMK_BENCH_HOST_ID`; build role and selected tier are intrinsic.
- `#GATE-END  suite  count` -- the terminal sentinel. It is the only thing separating "nothing failed" from "the process died before it got there".

[`scripts/check_benchmark_results.py`](../../scripts/check_benchmark_results.py) consumes the captures and refuses missing, malformed, non-finite, duplicated, spliced, unclosed, or internally contradictory evidence; failed deterministic gates in either current or baseline captures; mismatched deterministic scenarios; missing/wrong build or tier roles; and missing/mismatched stable-host identity. Any `--require`d gate must remain present. Timing gates and valid `--metric-ratio` comparisons are reported everywhere and enforced only under `--stable-host`, because a shared runner cannot tell a regression from a noisy neighbour. `scripts/test_check_benchmark_results.py` pins parser, policy, provenance, and actual process-exit refusals and is registered as the `BenchmarkResultsCheckerSelfTest` script-lint ctest.

`release.yml`'s `benchmark-evidence` job builds and runs all four on every dispatch, including preflight, then checks the captures without `--stable-host` and uploads them as an artifact.

## Installed Package Smoke Test

`tests/package_smoke` is a minimal consumer project for validating installed release packages. It uses `find_package(DetourModKit REQUIRED)`, links `DetourModKit::DetourModKit`, and touches `hook::is_target_hooked` so the static dependency archives are required by the final link.

```bash
cmake -S tests/package_smoke -B build/package-smoke-mingw -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DDetourModKit_DIR="$PWD/install_package/mingw/lib/cmake/DetourModKit" \
    -DCMAKE_CXX_COMPILER=g++
cmake --build build/package-smoke-mingw --parallel
ctest --test-dir build/package-smoke-mingw --output-on-failure
```

The release workflow runs this smoke project for both MinGW and MSVC after installing the package and before uploading release artifacts.

## Project Structure

Test files are named by the surface they verify and live under `tests/`; that directory is the authoritative list. Most modules have one `test_<module>.cpp`, while large modules split by API surface, fault-frame state, or integration boundary. The files worth calling out, because their role is not obvious from the name:

- **Deliberate same-module splits** -- `test_memory_chain.cpp` (pointer-chain and plausibility primitives) is split from `test_memory.cpp`, and `test_string.cpp` (the `string::trim` cases) shares `format.hpp` with `test_format.cpp`; scanner and RTTI have several focused suites for resolver tiers, string xrefs, parallel scanning, reverse dissection, and heal scheduling.
- **Compile-time proofs** -- `test_memory_representation.cpp` carries the typed-read participation matrix as `static_assert`s, so rejected types are asserted false instead of being written as calls that cannot compile. Its runtime case instantiates accepted function bodies and verifies their decoded values; the matrix-reporting case gives ctest a named route for the compile-time portion.
- **Internal white-box tests** -- `test_input_intercept.cpp`, `test_x86_decode.cpp`, and `test_gate_race_probe.cpp` add `src/` to their include path to drive non-installed headers directly. The gate race probe is isolated from the compiled library so it exercises only the hook-ledger and input-gate synchronization primitives.
- **Integration and lifecycle** -- `test_hook_integration.cpp` (cross-module hooking against the fixture DLL), `test_session.cpp` (`Session` / bootstrap / ordered `~Session` teardown), and `test_mid_hook_context.cpp` (`hook::MidContext` accessors).
- **Non-`test_*` support** -- `main.cpp` (GoogleTest entry point), `CMakeLists.txt` (test discovery, fixture DLL build, bench wiring), `fixtures/hook_target_lib.cpp` (the exported-function fixture DLL), `package_smoke/` (the installed-package consumer), and the `bench_*.cpp` microbenches (built under `DMK_BUILD_BENCHMARKS`).

The `docs/tests/` directory holds this guide plus the coverage tooling:

```text
docs/tests/
├── README.md          # This guide
├── parse_coverage.py  # Coverage JSON parser script
├── test_compile.cpp   # Minimal toolchain verification stub
└── coverage/          # Generated HTML reports (gitignored)
    └── index.html     # Entry point for HTML coverage report
```

## Helper Scripts

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

A minimal stub (`int main() { return 0; }`) for verifying the toolchain works:

```bash
g++ -o test_compile.exe docs/tests/test_compile.cpp
```

## Best Practices

1. **Start with error paths**: Test invalid inputs first (easy coverage gains).
2. **Use real addresses**: For hook tests, use `DMK_TEST_NOINLINE` functions or DLL exports.
3. **Use `ASSERT_*` for preconditions**: Stop the test immediately if setup fails.
4. **Use `EXPECT_*` for verifications**: Continue testing even if one check fails.
5. **Guard platform-specific tests**: Use `GTEST_SKIP()` for architecture-dependent logic.
6. **Clean rebuild for coverage**: After major changes, delete `.gcda` files or rebuild from scratch.
7. **Follow naming conventions**: `s_` for file-scope statics, `m_` for members, `snake_case` for functions.
