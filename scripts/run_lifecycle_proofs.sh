#!/usr/bin/env bash
#
# Builds and runs the CMake-owned lifecycle host-safety proofs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="${1:-build/mingw-debug}"

if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]]; then
  echo "error: '$BUILD_DIR' is not a configured build tree." >&2
  echo "       configure a Debug tree first, e.g. cmake --preset mingw-debug or cmake --preset msvc-debug" >&2
  exit 1
fi

# MinGW lane only: the probe DLL imports libwinpthread, so use the runtime beside the CONFIGURED compiler rather than
# an unrelated MinGW DLL that happens to appear earlier on the caller's PATH. Skipped for MSVC, whose compiler
# directory carries private msvcp140 / vcruntime140 copies that would shadow the system CRT for every proof process.
CXX_COMPILER="$(sed -n 's/^CMAKE_CXX_COMPILER:[^=]*=//p' "$BUILD_DIR/CMakeCache.txt" | head -n 1)"
if [[ -n "$CXX_COMPILER" && "$(basename "$CXX_COMPILER")" != cl.exe ]]; then
  if command -v cygpath >/dev/null 2>&1; then
    CXX_COMPILER="$(cygpath -u "$CXX_COMPILER")"
  fi
  export PATH="$(dirname "$CXX_COMPILER"):$PATH"
fi

# Every executable behind a lifecycle-proof ctest must be named here: dmk_add_raw_proof registers a bare add_test with
# no build dependency, so an unbuilt host fails the run with "Unable to find executable" rather than being skipped. Only
# the top-level hosts are listed; their companion DLLs come in through add_dependencies.
cmake --build "$BUILD_DIR" \
  --target bootstrap_module_ref full_lifecycle profiler_late_uaf hook_static_order hook_instance_scope \
           logger_first_use_oom input_gate_abba config_servicer_self_retire \
           input_self_shutdown input_first_use_oom xinput_detour_rundown xinput_forwarding_guard \
           profiler_first_use_oom diagnostics_late_emitter --parallel 4
ctest --test-dir "$BUILD_DIR" -L lifecycle-proof --output-on-failure "${@:2}"
