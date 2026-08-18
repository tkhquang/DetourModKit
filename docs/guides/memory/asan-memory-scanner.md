# AddressSanitizer and the memory scanner

## Summary

DetourModKit's AOB scanner and SEH-guarded probe read deliberately read arbitrary mapped process memory. Under MSVC AddressSanitizer (the `msvc-debug-asan` preset) those reads land on memory ASan poisoned for its own bookkeeping and are reported as buffer overflows. Yet every read is in bounds of a committed, readable page and never faults in a release build. They are false positives intrinsic to a whole-process memory scanner run inside an ASan-instrumented process.

The fix excludes only the deliberate foreign-memory readers from ASan. The AOB byte-search prefilter routes through a self-provided `dmk_memchr` in every build, so it is immune to libc interceptors by construction. Only the `no_sanitize_address` attribute and the `__movsb` copy path remain ASan-conditional under `#if defined(__SANITIZE_ADDRESS__)`. The guarded copy lives in the memory engine TU, and the public `memory.hpp` header is Win32-free. The full test suite still runs, and passes, under ASan with the scanner exercised.

## What ASan reports

A build of the suite under `msvc-debug-asan` without the fix produces reports like:

- `stack-buffer-underflow` / `global-buffer-overflow` in `find_pattern_raw` (`src/internal/scan_engine.cpp`), reached via `scan_readable_regions` -> `scan_regions_filtered`. ASan attributes the address to `find_pattern_raw`'s own stack frame, or to an instrumented global.
- `global-buffer-overflow` in `guarded_read_bytes` (`src/internal/memory_guarded.cpp`), reached via the RTTI host-module section walk.

## Root cause

`scan_readable_regions` enumerates every committed, readable region in the current process with `VirtualQuery` and scans each one for the pattern. Among those regions are the running thread's own stack and the module's data segments. Both carry poisoned shadow under ASan, because ASan surrounds stack locals and instrumented globals with redzones.

The scanner's reads stay strictly in bounds of the regions `VirtualQuery` reported as readable. The arithmetic in `find_pattern_raw` keeps every access inside `[start, start + region_size)`, and the SIMD verify never reads past `pattern_start + pattern.size()`. The reads therefore never fault in a release build. They only "fail" because ASan's shadow marks sub-ranges of that mapped, readable memory as off-limits to ordinary code. `guarded_read_bytes` is the same: its `__try`-guarded copy reads a mapped data section that happens to contain an instrumented global's redzone.

This is the well-known conflict between AddressSanitizer and code that intentionally reads memory it does not own (memory scanners, conservative garbage collectors, stack walkers). ASan cannot model a process that reads its own shadow. It never arises in production. DetourModKit runs inside a target (game) process where neither the game nor the mod DLL is built with ASan, so the address space it scans carries no poisoned shadow.

## Two ASan mechanisms, two fixes

A function that reads foreign memory trips ASan two different ways, and each needs its own treatment:

1. **Compiler load instrumentation.** ASan rewrites the function's own loads to check the shadow first. `__declspec(no_sanitize_address)` removes that instrumentation. On MSVC the attribute is compile-time only and must sit on the function's first declaration.
2. **libc interceptors.** ASan hot-patches `memchr`, `memcpy`, `memmove`, and peers at runtime, so a call to one checks its range against the shadow regardless of the caller's attributes. `no_sanitize_address` does **not** disable this. The only portable way to avoid it is to not call the intercepted function on foreign memory.

## The fix

The byte-search prefilter is unconditional. Every build routes it through a self-provided `dmk_memchr` that performs its own byte comparisons and never calls into libc, so the interceptor has nothing to hot-patch. Only the `DMK_NO_SANITIZE_ADDRESS` attribute and the `__movsb` copies in `guarded_read_bytes` and `guarded_write_bytes` are guarded by `#if defined(__SANITIZE_ADDRESS__)`.

`src/internal/scan_engine.cpp`:

- A translation-unit-local `DMK_NO_SANITIZE_ADDRESS` macro (empty off ASan).
- `no_sanitize_address` on the pattern matchers and SIMD helpers whose instrumented loads read the scanned region. The set is `find_pattern_flat_start` and the segmented matchers (`segment_run_matches` / `extend_segments` / `find_pattern_segmented`), `verify_pattern_avx2` / `verify_pattern_avx512`, the `dmk_memchr` family (`dmk_memchr` / `dmk_memchr_sse2` / `dmk_memchr_avx2`), and `scan_for_byte`. `find_pattern_raw` itself stays instrumented. It is a dispatcher that performs no region loads of its own and delegates them to these.
- `scan_for_byte` replaces the inner-loop `memchr` and routes through the self-provided `dmk_memchr` in all builds, so the interceptor never sees the scan in any configuration. `dmk_memchr` runs a 16-byte SSE2 body with a scalar tail on x86-64, plus a 32-byte AVX2 body when the CPU and OS support it. A scalar loop runs only where neither SSE2 nor AVX2 is available.

`src/internal/memory_guarded.cpp`:

- `guarded_read_bytes` copies with the `__movsb` (`rep movsb`) intrinsic under ASan, which emits the copy inline with no interceptable call, and with `std::memcpy` otherwise. No `no_sanitize_address` is applied here. The copy is the function's only foreign read, and `__movsb` is neither instrumented nor intercepted, so the attribute suppresses nothing and is dead.

What this costs: ASan no longer validates the scanner's own reads of arbitrary process memory. That is unavoidable, because those reads are the false-positive source, and it is acceptable. The scanner's bounds logic is still exercised under ASan by the tests that scan small, heap-allocated buffers. Their match and no-match assertions catch a bounds regression that alters results, though ASan itself can no longer flag any of the scanner's reads. The attribute is function-scoped, so it exempts reads of the tests' own heap buffers exactly as it exempts reads of foreign memory. The full non-ASan suite also exercises the same logic on every read.

## Alternatives considered and rejected

- **Skip the offending tests under ASan.** Removes coverage and is widely treated as an anti-pattern. The convention is to exclude the *function* that legitimately bypasses ASan, not the test.
- **`no_sanitize_address` alone.** Insufficient: it does not stop the `memchr` / `memcpy` interceptors (see above).
- **Sanitizer ignorelist / special-case-list file.** Unsupported by MSVC AddressSanitizer.
- **`__asan_unpoison_memory_region`.** Intended only for memory ASan owns. Unpoison of another subsystem's redzones corrupts ASan's bookkeeping and masks real bugs.
- **A global disable of the intrinsic interceptors** (an `ASAN_OPTIONS` knob). Weakens `memcpy` / `memchr` overflow detection across the entire suite.

## Adding a new foreign-memory primitive

If a new function deliberately reads memory the process does not own:

1. Mark it `DMK_NO_SANITIZE_ADDRESS`, with the attribute on its first declaration (on MSVC, the header prototype for an out-of-line function).
2. Route any `memchr` / `memcpy` / `memmove` / `memset` it performs on that memory around the interceptor under `#if defined(__SANITIZE_ADDRESS__)`, with an inline loop, or `__movsb` / `__stosb` for bulk copies and fills.
3. Decide whether the replacement is unconditional or ASan-only. A primitive on a scan path that must behave identically in every build gets a self-provided unconditional replacement (the AOB prefilter's `dmk_memchr`). A primitive whose libc form is fine outside ASan can keep the libc call under the `#else` branch (the `__movsb` copy in `guarded_read_bytes`).

## References

- [MSVC AddressSanitizer language, build, and debugging reference](https://learn.microsoft.com/en-us/cpp/sanitizers/asan-building?view=msvc-170). The `__SANITIZE_ADDRESS__` macro, and that `__declspec(no_sanitize_address)` "affects compiler behavior, not runtime behavior", so it cannot disable the runtime interceptors.
- [MSVC AddressSanitizer known issues and limitations](https://learn.microsoft.com/en-us/cpp/sanitizers/asan-known-issues?view=msvc-170). Special-case-list (ignorelist) files are unsupported on MSVC.
- [Clang AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html). `__attribute__((no_sanitize("address")))`, and the stronger `disable_sanitizer_instrumentation`, for exclusion of a function that legitimately bypasses ASan.
- [MaskRay - All about sanitizer interceptors](https://maskray.me/blog/2023-01-08-all-about-sanitizer-interceptors). On Windows, ASan installs its `memchr` / `memcpy` / ... interceptors by a hot-patch of the function entry at run time, which is why a compile-time attribute on the caller cannot suppress them.
- [google/sanitizers - AddressSanitizerManualPoisoning](https://github.com/google/sanitizers/wiki/AddressSanitizerManualPoisoning). `__asan_poison_memory_region` / `__asan_unpoison_memory_region` apply only to memory ASan owns. They are not a tool for reads of foreign memory.
- [`__movsb` intrinsic](https://learn.microsoft.com/en-us/cpp/intrinsics/movsb?view=msvc-170). Emits `rep movsb` inline with no interceptable call, and declared in `<intrin.h>`.
