#!/usr/bin/env bash
#
# Builds and runs the CMake-owned fault-containment proofs. Every case runs on both toolchains, so any configured
# tests-ON tree works; pass build/msvc-debug (or an ASan tree) to drive the MSVC SEH arms.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="${1:-build/mingw-debug}"

if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]]; then
  echo "error: '$BUILD_DIR' is not a configured build tree." >&2
  echo "       configure one first, for example: cmake --preset mingw-debug (or --preset msvc-debug)" >&2
  exit 1
fi

# The proof may load libwinpthread at runtime. Prepend the configured compiler directory so an earlier Git/MinGW DLL
# on the caller's PATH cannot satisfy that import with an incompatible runtime. The resolver returns nothing for MSVC,
# whose compiler directory would shadow the system CRT with its private msvcp140 / vcruntime140 copies.
# Prefer the interpreter CMake configured for this tree, which is also the one its registered self-tests run under.
# A bare `command -v python3` is not enough: Windows ships an App Execution Alias of that name that sits ahead of any
# real interpreter on a default PATH and exits nonzero without running the script, which would abort this wrapper
# under `set -e` before it builds anything. A candidate is therefore accepted only once it has executed.
PYTHON="$(sed -n 's/^DMK_PYTHON_EXECUTABLE:[^=]*=//p' "$BUILD_DIR/CMakeCache.txt" | head -n 1)"
if [[ -n "$PYTHON" ]] && command -v cygpath >/dev/null 2>&1; then
  PYTHON="$(cygpath -u "$PYTHON")"
fi
if [[ -z "$PYTHON" || ! -x "$PYTHON" ]]; then
  PYTHON=""
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "" >/dev/null 2>&1; then
      PYTHON="$candidate"
      break
    fi
  done
fi
if [[ -z "$PYTHON" ]]; then
  echo "error: a working python3 (or python) is required to resolve the compiler runtime directory." >&2
  exit 1
fi
RUNTIME_DIR="$("$PYTHON" scripts/resolve_runtime_dir.py "$BUILD_DIR")"
if [[ -n "$RUNTIME_DIR" ]]; then
  if command -v cygpath >/dev/null 2>&1; then
    RUNTIME_DIR="$(cygpath -u "$RUNTIME_DIR")"
  fi
  export PATH="$RUNTIME_DIR:$PATH"
fi

# The aggregate in tests/fault/CMakeLists.txt owns the host inventory beside each declaration. The label's own
# inventory gate is registered under fault-proof too, so the run below refuses a selection that lost a case rather
# than reporting an empty success.
cmake --build "$BUILD_DIR" --target dmk_fault_proof_hosts --parallel 4
ctest --test-dir "$BUILD_DIR" -L fault-proof --output-on-failure "${@:2}"
