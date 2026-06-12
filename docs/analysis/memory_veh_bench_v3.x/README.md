# Memory microbenchmark: MinGW vectored-handler fault guard

This directory captures a run of `tests/bench_memory.cpp` against the `Memory` read primitives on **MinGW**, where the `seh_read` family is guarded by a process-wide vectored exception handler (VEH) rather than a per-call `VirtualQuery`. It is the MinGW companion to the MSVC numbers in [../memory_bench_v3.x](../memory_bench_v3.x): the same harness, run once per toolchain, so the two columns below are directly comparable.

The question is "does the VEH actually buy anything on MinGW?" The VirtualQuery-validated baseline issues a `VirtualQuery` syscall on every terminal read (and one per link on a chain walk) because GCC has no zero-cost frame-based SEH. The VEH path removes that syscall entirely: the success path is a single `rep movsb` under a thread-local guard, and a read fault is recovered with a non-unwinding `__builtin_setjmp` / `__builtin_longjmp` (the GCC equivalent of Frida's `_setjmp(env, NULL)`). The per-thread guard is published through a Win32 TLS slot read with `TlsGetValue`, which is allocation-free and safe to touch from the exception-dispatch context (a `thread_local` / `__thread` would lower to `__emutls_get_address`, which allocates and locks on first access -- forbidden in a handler).

The benchmark measures the per-call cost of each read primitive. The two numbers that matter are:

- **`seh_read<u64>`** -- a single terminal guarded read. The MinGW VirtualQuery baseline pays one query (the `raw VirtualQuery` row) plus a copy; the VEH path pays neither.
- **`seh_resolve_chain` / `seh_read_chain<u64>`** -- a six-link pointer-chain walk. The VirtualQuery-validated baseline pays one query per link.

## Hardware / configuration

- Build: `cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON` (MinGW column); MSVC Release `/O2` with `-DDMK_BUILD_BENCHMARKS=ON` (MSVC column)
- Toolchains: GCC 15.1 (MSYS2 MinGW-w64), `-O3` + LTO, `seh_*` use the vectored-handler fault guard; MSVC 2022, `seh_*` use real `__try` / `__except` (table-driven on x64, free on the no-fault path)
- Iterations: 200,000 per sample (20,000 for `write_bytes`); 15 samples; median reported
- Pointer chain: six links, warm cache
- `DEFAULT_CACHE_EXPIRY_MS = 50`

## Results

```text
primitive                 MinGW (VEH)    MSVC (__try)    MinGW VirtualQuery baseline
raw VirtualQuery            224.28 ns      213.76 ns      -- (this row is the per-read baseline)
direct volatile load          6.47 ns        ~4 ns        --
read_ptr_unchecked          191.82 ns        5.34 ns      -- (range-guarded, no fault guard; debug-assert build)
seh_read<u64>                62.34 ns        7.26 ns      ~224 ns  (a VirtualQuery + copy)
seh_resolve_chain (6)       250.15 ns        9.92 ns      ~1345 ns (6 x VirtualQuery)
seh_read_chain<u64> (6)     299.26 ns        8.94 ns      ~1345 ns (6 x VirtualQuery + terminal read)
```

The "MinGW VirtualQuery baseline" column is derived, not separately benchmarked: `virtualquery_validated_copy` is the install-failure fallback, so its cost is the `raw VirtualQuery` row (224 ns) times the number of regions a read spans -- one for a terminal read, one per link for a chain.

## How to read this

| Primitive | MinGW VEH | vs VirtualQuery baseline | vs MSVC `__try` |
|-----------|-----------|-------------------|-----------------|
| `seh_read<u64>` | 62 ns | **~3.6x faster** (no VirtualQuery) | ~8.6x slower |
| `seh_resolve_chain` (6 links) | 250 ns | **~5.4x faster** (no per-link syscall) | ~25x slower |
| `seh_read_chain<u64>` (6 links) | 299 ns | **~4.5x faster** | ~33x slower |

A few takeaways:

1. **The VEH eliminates the syscall, which is the whole point.** A guarded terminal read dropped from a `VirtualQuery` (224 ns) to 62 ns, and a six-link chain from roughly 1.3 microseconds of syscalls to 250 ns. The remaining MinGW cost is the `__builtin_setjmp` snapshot, two `TlsSetValue` writes, the drain-epoch atomics, and a `rep movsb` -- all userspace, no kernel transition. The 62 ns being far below a single `raw VirtualQuery` is also the proof that the VEH is actually active rather than silently falling back.
2. **The MinGW-to-MSVC gap is inherent and not closable.** MSVC `__try` is table-driven SEH described by `.pdata`/`.xdata` emitted at compile time, so the no-fault path costs nothing beyond the read itself (7-10 ns). GCC on Windows has no equivalent; any runtime fault guard -- VEH, signal handler, or otherwise -- must do per-read setup. So the realistic goal was "stop paying a syscall per read," which is met, not "match MSVC."
3. **The hardened TLS path keeps the handler allocation-free.** Publishing the guard through a Win32 TLS slot (`TlsSetValue` / `TlsGetValue`, a TEB-array access) avoids the `__emutls_get_address` call a mingw `thread_local` lowers to, and that matters because allocation and locking are forbidden in the exception-dispatch context.
4. **`read_ptr_unchecked` stays the floor for known-live pointers.** It applies only range guards and no fault guard; in this debug-assert benchmark build its MinGW number is inflated by the `is_readable` assert, but in a release consumer it is a single guarded `memcpy`. Use it only when the caller can prove the pointer is live this frame; otherwise `seh_read` / `seh_read_chain` is the safe choice and, on MinGW, now cheap enough to use freely.

## Reproducing locally

```bash
# MinGW (vectored-handler path)
PATH="/c/msys64/mingw64/bin:$PATH" \
  cmake -S . -B build/mingw-release -DDMK_BUILD_BENCHMARKS=ON
PATH="/c/msys64/mingw64/bin:$PATH" \
  cmake --build build/mingw-release --target DetourModKit_bench_memory -j 3
./build/mingw-release/tests/DetourModKit_bench_memory.exe
```

The program prints the human-readable tables shown above plus a `#TSV` block on stdout for scripted comparison. The toolchain banner on the first line confirms which fault-guard path is in effect (`vectored-handler fault guard` on MinGW, `__try/__except` on MSVC).
