# AddressSanitizer and the memory scanner

## Summary

DetourModKit's AOB scanner and SEH-guarded probe read deliberately read arbitrary mapped process memory. Under MSVC AddressSanitizer (the `msvc-debug-asan` preset) those reads land on memory ASan has poisoned for its own bookkeeping and are reported as buffer overflows -- even though every read is in bounds of a committed, readable page and never faults in a release build. They are false positives intrinsic to running a whole-process memory scanner inside an ASan-instrumented process.

The fix excludes only the deliberate foreign-memory readers from ASan, entirely under `#if defined(__SANITIZE_ADDRESS__)`, so release and non-ASan builds are byte-for-byte unchanged and the full test suite still runs -- and passes -- under ASan with the scanner exercised.

## What ASan reports

Building the suite under `msvc-debug-asan` without the fix produces reports like:

- `stack-buffer-underflow` / `global-buffer-overflow` in `find_pattern_raw` (`src/scanner.cpp`), reached via `scan_readable_regions` -> `scan_regions_filtered`. ASan attributes the address to `find_pattern_raw`'s own stack frame, or to an instrumented global.
- `global-buffer-overflow` in `seh_read_bytes` (`src/memory.cpp`), reached via the RTTI host-module section walk.

## Root cause

`scan_readable_regions` enumerates every committed, readable region in the current process with `VirtualQuery` and scans each one for the pattern. Among those regions are the running thread's own stack and the module's data segments -- both of which, under ASan, carry poisoned shadow, because ASan surrounds stack locals and instrumented globals with redzones.

The scanner's reads stay strictly in bounds of the regions `VirtualQuery` reported as readable: the arithmetic in `find_pattern_raw` keeps every access inside `[start, start + region_size)`, and the SIMD verify never reads past `pattern_start + pattern.size()`. So the reads never fault in a release build. They only "fail" because ASan's shadow marks sub-ranges of that mapped, readable memory as off-limits to ordinary code. `seh_read_bytes` is the same: its `__try`-guarded copy reads a mapped data section that happens to contain an instrumented global's redzone.

This is the well-known conflict between AddressSanitizer and code that intentionally reads memory it does not own (memory scanners, conservative garbage collectors, stack walkers). ASan cannot model a process reading its own shadow. It never arises in production: DetourModKit scans a separate target process that is not built with ASan.

## Two ASan mechanisms, two fixes

A function that reads foreign memory trips ASan two different ways, and each needs its own treatment:

1. **Compiler load instrumentation.** ASan rewrites the function's own loads to check the shadow first. `__declspec(no_sanitize_address)` removes that instrumentation. On MSVC the attribute is compile-time only and must sit on the function's first declaration.
2. **libc interceptors.** ASan hot-patches `memchr`, `memcpy`, `memmove`, etc. at runtime, so a call to one checks its range against the shadow regardless of the caller's attributes. `no_sanitize_address` does **not** disable this. The only portable way to avoid it is to not call the intercepted function on foreign memory.

## The fix

Every change is guarded by `#if defined(__SANITIZE_ADDRESS__)`; release and non-ASan builds keep the original `memchr`/`memcpy` and emit identical code.

`src/scanner.cpp`:

- A translation-unit-local `DMK_NO_SANITIZE_ADDRESS` macro (empty off ASan).
- `no_sanitize_address` on `find_pattern_raw`, `verify_pattern_avx2`, and the `scan_for_byte` helper -- the functions whose instrumented SIMD/scalar loads read the scanned region.
- `scan_for_byte` replaces the inner-loop `memchr`. Under ASan it scans inline (no interceptor); otherwise it forwards to `memchr`, so release keeps the optimized path.

`src/memory.cpp`:

- `seh_read_bytes` copies with the `__movsb` (`rep movsb`) intrinsic under ASan -- it emits the copy inline with no interceptable call -- and with `std::memcpy` otherwise. No `no_sanitize_address` is applied here: the copy is the function's only foreign read, and `__movsb` is neither instrumented nor intercepted, so the attribute would suppress nothing and would be dead.

What this costs: ASan no longer validates the scanner's own reads of arbitrary process memory. That is unavoidable -- those reads are the false-positive source -- and acceptable: the scanner's bounds logic is still exercised under ASan by the tests that scan small, heap-allocated (ASan-tracked) buffers, where a genuine over-read would still be caught, and by the full non-ASan suite.

## Alternatives considered and rejected

- **Skip the offending tests under ASan.** Removes coverage and is widely considered an anti-pattern; the convention is to exclude the *function* that legitimately bypasses ASan, not the test.
- **`no_sanitize_address` alone.** Insufficient: it does not stop the `memchr`/`memcpy` interceptors (see above).
- **Sanitizer ignorelist / special-case-list file.** Unsupported by MSVC AddressSanitizer.
- **`__asan_unpoison_memory_region`.** Intended only for memory ASan owns; unpoisoning another subsystem's redzones would corrupt ASan's bookkeeping and mask real bugs.
- **Disabling the intrinsic interceptors globally** (an `ASAN_OPTIONS` knob). Weakens `memcpy`/`memchr` overflow detection across the entire suite.

## Adding a new foreign-memory primitive

If a new function deliberately reads memory the process does not own:

1. Mark it `DMK_NO_SANITIZE_ADDRESS`, with the attribute on its first declaration (on MSVC, the header prototype for an out-of-line function).
2. Route any `memchr`/`memcpy`/`memmove`/`memset` it performs on that memory around the interceptor under `#if defined(__SANITIZE_ADDRESS__)` -- an inline loop, or `__movsb`/`__stosb` for bulk copies/fills.
3. Keep the release path on the original libc call so shipped code is unchanged.

## References

- [MSVC AddressSanitizer language, build, and debugging reference](https://learn.microsoft.com/en-us/cpp/sanitizers/asan-building?view=msvc-170) -- the `__SANITIZE_ADDRESS__` macro, and that `__declspec(no_sanitize_address)` "affects compiler behavior, not runtime behavior" (so it cannot disable the runtime interceptors).
- [MSVC AddressSanitizer known issues and limitations](https://learn.microsoft.com/en-us/cpp/sanitizers/asan-known-issues?view=msvc-170) -- special-case-list (ignorelist) files are unsupported on MSVC.
- [Clang AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) -- `__attribute__((no_sanitize("address")))`, and the stronger `disable_sanitizer_instrumentation`, for excluding a function that legitimately bypasses ASan.
- [MaskRay -- All about sanitizer interceptors](https://maskray.me/blog/2023-01-08-all-about-sanitizer-interceptors) -- on Windows, ASan installs its `memchr`/`memcpy`/... interceptors by hot-patching the function entry at run time, which is why a compile-time attribute on the caller cannot suppress them.
- [google/sanitizers -- AddressSanitizerManualPoisoning](https://github.com/google/sanitizers/wiki/AddressSanitizerManualPoisoning) -- `__asan_poison_memory_region` / `__asan_unpoison_memory_region` apply only to memory ASan owns; they are not a tool for reads of foreign memory.
- [`__movsb` intrinsic](https://learn.microsoft.com/en-us/cpp/intrinsics/movsb?view=msvc-170) -- emits `rep movsb` inline with no interceptable call; declared in `<intrin.h>`.
