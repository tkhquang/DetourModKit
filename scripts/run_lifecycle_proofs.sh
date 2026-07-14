#!/usr/bin/env bash
#
# Builds and runs the CMake-owned lifecycle host-safety proofs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="${1:-build/mingw-debug}"

if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]]; then
  echo "error: '$BUILD_DIR' is not a configured build tree." >&2
  echo "       configure a MinGW Debug tree first: cmake --preset mingw-debug" >&2
  exit 1
fi

# The probe DLL imports libwinpthread. Use the runtime beside the configured compiler, not an unrelated MinGW DLL that
# happens to appear earlier on the caller's PATH.
CXX_COMPILER="$(sed -n 's/^CMAKE_CXX_COMPILER:[^=]*=//p' "$BUILD_DIR/CMakeCache.txt" | head -n 1)"
if [[ -n "$CXX_COMPILER" ]]; then
  if command -v cygpath >/dev/null 2>&1; then
    CXX_COMPILER="$(cygpath -u "$CXX_COMPILER")"
  fi
  export PATH="$(dirname "$CXX_COMPILER"):$PATH"
fi

cmake --build "$BUILD_DIR" --target bootstrap_module_ref profiler_late_uaf --parallel 4
ctest --test-dir "$BUILD_DIR" -L lifecycle-proof --output-on-failure "${@:2}"
