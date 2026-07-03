#!/usr/bin/env bash
#
# Standalone-link runner for DetourModKit's fault-injection tests (tests/fault/*.cpp).
#
# WHY THIS EXISTS
# --------------
# The main test suite globs tests/test_*.cpp with CONFIGURE_DEPENDS into one monolithic executable, so dropping a new
# source there forces a reconfigure and rebuild of the main C++23 test target. Fault fixtures need a committed
# PAGE_NOACCESS page held until teardown, so they must be authored somewhere the "must fault" page can live without
# paying that rebuild. This script is that path: it
# compiles the fault TUs as a single one-off executable and links them against the ALREADY-BUILT library archive, so
# adding a fault fixture never touches the main glob.
#
# PRECONDITION
# ------------
# The library archive must already be current. Build it once (or after any src/ change) with:
#   PATH="/c/msys64/mingw64/bin:$PATH" cmake --build build/mingw-debug --target DetourModKit
# Rebuilding just that target compiles only the changed TUs and re-archives; it does not trigger the whole-suite build.
#
# USAGE
# -----
#   bash scripts/run_fault_tests.sh [build-dir]
# build-dir defaults to build/mingw-debug and must contain a configured DMK_BUILD_TESTS=ON tree (for the prebuilt
# gtest archives under lib/ and the fetched Zydis/SafetyHook archives under _deps/ and external/).

set -euo pipefail

export PATH="/c/msys64/mingw64/bin:$PATH"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="${1:-build/mingw-debug}"
ARCHIVE="$BUILD_DIR/libDetourModKit.a"
CXX="${CXX:-g++}"

if [[ ! -f "$ARCHIVE" ]]; then
  echo "error: prebuilt library archive not found at '$ARCHIVE'." >&2
  echo "       build it first: PATH=\"/c/msys64/mingw64/bin:\$PATH\" cmake --build $BUILD_DIR --target DetourModKit" >&2
  exit 1
fi

REQUIRED_ARCHIVES=(
  "$BUILD_DIR/lib/libgtest_main.a"
  "$BUILD_DIR/lib/libgtest.a"
  "$BUILD_DIR/external/safetyhook/libsafetyhook.a"
  "$BUILD_DIR/_deps/zydis-build/libZydis.a"
  "$BUILD_DIR/_deps/zydis-build/zycore/libZycore.a"
)

for required_archive in "${REQUIRED_ARCHIVES[@]}"; do
  if [[ ! -f "$required_archive" ]]; then
    echo "error: required archive not found at '$required_archive'." >&2
    echo "       configure/build a MinGW debug tree with DMK_BUILD_TESTS=ON before running fault tests." >&2
    exit 1
  fi
done

# Collect every fault TU. A new tests/fault/test_*.cpp is picked up automatically -- no CMake reconfigure.
mapfile -t FAULT_SOURCES < <(find tests/fault -name 'test_*.cpp' | sort)
if [[ ${#FAULT_SOURCES[@]} -eq 0 ]]; then
  echo "error: no tests/fault/test_*.cpp sources found." >&2
  exit 1
fi

OUT_EXE="$BUILD_DIR/fault_tests.exe"

echo "== compiling ${#FAULT_SOURCES[@]} fault TU(s) against $ARCHIVE =="
for src in "${FAULT_SOURCES[@]}"; do
  echo "   - $src"
done

# The include/link flags mirror the library's own build (defines, external SYSTEM include dirs, and the archive group
# ordering) so the one-off TU sees the exact same headers and resolves the same symbols the monolithic suite would.
"$CXX" -std=c++23 -g -O0 -Wall -Wextra -Wpedantic -Wshadow \
  -DNOMINMAX -DSAFETYHOOK_NO_DLL -DWINVER=0x0A00 -DZYCORE_STATIC_BUILD -DZYDIS_STATIC_BUILD -D_WIN32_WINNT=0x0A00 \
  -I include -I "$BUILD_DIR/generated" -I src -I tests/fixtures \
  -isystem "$BUILD_DIR/_deps/googletest-src/googletest/include" \
  -isystem external/DirectXMath/Inc -isystem external/simpleini -isystem external/safetyhook/include \
  -isystem "$BUILD_DIR/_deps/zydis-src/include" -isystem "$BUILD_DIR/_deps/zydis-build" \
  -isystem "$BUILD_DIR/_deps/zydis-src/dependencies/zycore/include" -isystem "$BUILD_DIR/_deps/zydis-build/zycore" \
  "${FAULT_SOURCES[@]}" \
  "$BUILD_DIR/lib/libgtest_main.a" "$BUILD_DIR/lib/libgtest.a" \
  -Wl,--start-group \
    "$ARCHIVE" \
    "$BUILD_DIR/external/safetyhook/libsafetyhook.a" \
    "$BUILD_DIR/_deps/zydis-build/libZydis.a" \
    "$BUILD_DIR/_deps/zydis-build/zycore/libZycore.a" \
  -Wl,--end-group \
  -static -static-libgcc -static-libstdc++ \
  -luser32 -lxinput1_4 -lpsapi -ldbghelp -lntdll \
  -o "$OUT_EXE"

echo "== running $OUT_EXE =="
"$OUT_EXE" "${@:2}"
