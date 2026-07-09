#!/usr/bin/env bash
#
# Standalone-link runner for DetourModKit's lifecycle host-safety proofs under tests/lifecycle/.
#
# These proofs need real process or DLL teardown events that the in-tree tests/test_*.cpp glob cannot host. The
# bootstrap-worker proof builds a minimal mod-shaped DLL and a loader host so the worker's module reference is tested
# against real LoadLibrary/FreeLibrary reference-count transitions. The profiler proof forces a static-teardown ordering
# where a late ScopedProfile records after ordinary static destruction and uses a poisoning allocator to make a destroyed
# ring buffer fault deterministically.
#
# Neither proof belongs in the monolithic test target: the profiler proof overrides global operator new/delete, and both
# use the process exit code as the verdict. Like scripts/run_fault_tests.sh, this compiles the proofs as one-off
# artifacts and links the DLL against the already-built library archive, so adding a proof never triggers a CMake
# reconfigure of the main suite.
#
# The library archive must already be current. Build it once (or after any src/ change) with:
#   PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-debug --target DetourModKit
#
#   bash scripts/run_lifecycle_proofs.sh [build-dir]
# build-dir defaults to build/mingw-debug and must contain a configured DMK_BUILD_TESTS=ON tree (for the prebuilt
# Zydis/SafetyHook archives under _deps/ and external/ that the probe DLL links).

set -euo pipefail

# Local dev shells do not always carry the MSYS2 MinGW bin on PATH, so add it when g++ is not already resolvable. CI
# prepends its own pinned MinGW to PATH before invoking this script, so g++ resolves there and this no-ops -- the
# pinned toolchain is used unchanged rather than being shadowed by a runner-image MSYS2 install.
if ! command -v g++ >/dev/null 2>&1; then
  export PATH="/c/msys64/mingw64/bin:$PATH"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="${1:-build/mingw-debug}"
# A Debug build tree carries DEBUG_POSTFIX ("d"), so its archive is libDetourModKitd.a; a Release tree keeps
# libDetourModKit.a. Prefer the suffixed Debug archive when it exists so an old unsuffixed archive left by a prior
# Debug build cannot be linked by mistake.
ARCHIVE="$BUILD_DIR/libDetourModKitd.a"
if [[ ! -f "$ARCHIVE" ]]; then
  ARCHIVE="$BUILD_DIR/libDetourModKit.a"
fi
CXX="${CXX:-g++}"

if [[ ! -f "$ARCHIVE" ]]; then
  echo "error: prebuilt library archive not found at '$ARCHIVE'." >&2
  echo "       build it first: PATH=\"/c/msys64/mingw64/bin:\$PATH\" cmake --build $BUILD_DIR --target DetourModKit" >&2
  exit 1
fi

SAFETYHOOK_A="$BUILD_DIR/external/safetyhook/libsafetyhook.a"
ZYDIS_A="$BUILD_DIR/_deps/zydis-build/libZydis.a"
ZYCORE_A="$BUILD_DIR/_deps/zydis-build/zycore/libZycore.a"
for required_archive in "$SAFETYHOOK_A" "$ZYDIS_A" "$ZYCORE_A"; do
  if [[ ! -f "$required_archive" ]]; then
    echo "error: required archive not found at '$required_archive'." >&2
    echo "       configure/build a MinGW debug tree with DMK_BUILD_TESTS=ON before running the lifecycle proofs." >&2
    exit 1
  fi
done

# Mirror the archive's coverage instrumentation onto the probe DLL link. Only the probe DLL links the DetourModKit
# archive; when the tree was configured with DMK_ENABLE_COVERAGE those objects carry --coverage and reference the gcov
# runtime (__gcov_*), which a bare g++ link leaves undefined. Read the tree's own setting from CMakeCache and pass
# --coverage through on that one link, exactly as the library's own build links it. The host driver links no library,
# and the profiler driver compiles src/profiler.cpp fresh under a size-targeted poisoning operator new/delete -- both
# stay uninstrumented, so gcov's atexit .gcda flush cannot allocate into the poisoned path. A non-coverage tree leaves
# the array empty and every link stays plain.
COVERAGE_FLAGS=()
if [[ -f "$BUILD_DIR/CMakeCache.txt" ]] && grep -q '^DMK_ENABLE_COVERAGE:BOOL=ON' "$BUILD_DIR/CMakeCache.txt"; then
  COVERAGE_FLAGS+=(--coverage)
fi

PROBE_DLL="$BUILD_DIR/bootstrap_probe.dll"
MODULE_REF_EXE="$BUILD_DIR/test_bootstrap_module_ref.exe"
UAF_EXE="$BUILD_DIR/test_profiler_late_uaf.exe"

WARN_FLAGS=(-std=c++23 -g -O0 -Wall -Wextra -Wpedantic -Wshadow)
RUNTIME_FLAGS=(-static-libgcc -static-libstdc++)

# The probe DLL includes the umbrella header, so it needs the library's full define/include set (matching the archive's
# own build) plus the external SYSTEM include dirs, and it links the archive group exactly as the monolithic suite does.
DEFINES=(-DNOMINMAX -DSAFETYHOOK_NO_DLL -DWINVER=0x0A00 -DZYCORE_STATIC_BUILD -DZYDIS_STATIC_BUILD -D_WIN32_WINNT=0x0A00)
INCLUDES=(-I include -I "$BUILD_DIR/generated" -I src)
SYS_INCLUDES=(
  -isystem external/DirectXMath/Inc -isystem external/simpleini -isystem external/safetyhook/include
  -isystem "$BUILD_DIR/_deps/zydis-src/include" -isystem "$BUILD_DIR/_deps/zydis-build"
  -isystem "$BUILD_DIR/_deps/zydis-src/dependencies/zycore/include" -isystem "$BUILD_DIR/_deps/zydis-build/zycore"
)
WIN_LIBS=(-luser32 -lxinput1_4 -lpsapi -ldbghelp -lntdll)

echo "== [1/3] building bootstrap_probe.dll (bootstrap worker probe, linked against $ARCHIVE) =="
"$CXX" "${WARN_FLAGS[@]}" -shared \
  "${DEFINES[@]}" "${INCLUDES[@]}" "${SYS_INCLUDES[@]}" \
  tests/lifecycle/bootstrap_probe_dll.cpp \
  -Wl,--start-group "$ARCHIVE" "$SAFETYHOOK_A" "$ZYDIS_A" "$ZYCORE_A" -Wl,--end-group \
  "${RUNTIME_FLAGS[@]}" "${WIN_LIBS[@]}" \
  "${COVERAGE_FLAGS[@]}" \
  -o "$PROBE_DLL"

echo "== [2/3] building test_bootstrap_module_ref.exe (bootstrap worker host) =="
# The host uses only the Win32 loader API; it does not link the library.
"$CXX" "${WARN_FLAGS[@]}" tests/lifecycle/test_bootstrap_module_ref.cpp "${RUNTIME_FLAGS[@]}" -o "$MODULE_REF_EXE"

echo "== [3/3] building test_profiler_late_uaf.exe (profiler teardown driver, compiling src/profiler.cpp directly) =="
# The profiler depends only on <windows.h> and the standard library, so the driver compiles it fresh and links nothing
# else. The driver's replacement operator new/delete then govern the profiler's ring-buffer allocation.
"$CXX" "${WARN_FLAGS[@]}" -I include \
  tests/lifecycle/test_profiler_late_uaf.cpp src/profiler.cpp "${RUNTIME_FLAGS[@]}" -o "$UAF_EXE"

failures=0

run_proof() {
  local label="$1"
  local exe="$2"
  shift 2
  local basename_exe
  basename_exe="$(basename "$exe")"
  echo
  echo "== running $label ($basename_exe $*) =="
  # Run from the build directory so the host resolves the companion DLL from its own directory and any log files the
  # probe writes stay out of the source tree.
  if (cd "$BUILD_DIR" && "./$basename_exe" "$@"); then
    echo "-> $label: PASS"
  else
    local code=$?
    echo "-> $label: FAIL (exit $code)" >&2
    failures=$((failures + 1))
  fi
}

# The bootstrap worker's counted-reference behavior is proved in two directions: its reference keeps the module mapped
# across a bare FreeLibrary, and a drained shutdown releases that reference so a following FreeLibrary actually unloads.
run_proof "BootstrapWorker StaysMapped" "$MODULE_REF_EXE" mapped
run_proof "BootstrapWorker DrainedUnloads" "$MODULE_REF_EXE" unload
run_proof "ProfilerLateScopedProfileNoUAF" "$UAF_EXE"

echo
if [[ $failures -eq 0 ]]; then
  echo "== all lifecycle proofs PASSED =="
else
  echo "== $failures lifecycle proof(s) FAILED ==" >&2
fi
exit "$failures"
