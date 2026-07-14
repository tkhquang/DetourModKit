#!/usr/bin/env bash
#
# Builds and runs the CMake-owned fault-containment proofs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="${1:-build/mingw-debug}"

if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]]; then
  echo "error: '$BUILD_DIR' is not a configured build tree." >&2
  echo "       configure a MinGW Debug tree first: cmake --preset mingw-debug" >&2
  exit 1
fi

# The proof may load libwinpthread at runtime. Prepend the configured compiler directory so an earlier Git/MinGW DLL
# on the caller's PATH cannot satisfy that import with an incompatible runtime.
CXX_COMPILER="$(sed -n 's/^CMAKE_CXX_COMPILER:[^=]*=//p' "$BUILD_DIR/CMakeCache.txt" | head -n 1)"
if [[ -n "$CXX_COMPILER" ]]; then
  if command -v cygpath >/dev/null 2>&1; then
    CXX_COMPILER="$(cygpath -u "$CXX_COMPILER")"
  fi
  export PATH="$(dirname "$CXX_COMPILER"):$PATH"
fi

cmake --build "$BUILD_DIR" --target fault_tests --parallel 4
ctest --test-dir "$BUILD_DIR" -L fault-proof --output-on-failure "${@:2}"
