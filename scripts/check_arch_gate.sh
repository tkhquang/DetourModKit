#!/usr/bin/env bash
#
# check_arch_gate.sh -- prove the native x86-64 Windows platform gate.
#
# Macro probes cover these unsupported targets:
#
# - A non-x64 target.
# - An ARM64EC target.
# - A non-Windows target.
#
# Native compiles are positive controls.
# The full-header probes also prove the platform diagnostic precedes later representation checks.
# A target-system CMake probe covers the root configure gate.

set -u

CXX="${CXX:-g++}"
COMMON=(-std=c++23 -Iinclude -fsyntax-only -x c++)
# This text is common to the header and configure diagnostics.
GATE_MSG="x86-64 Windows"
GATE_HEADER="include/DetourModKit/defines.hpp"
SURFACE_HEADER="include/DetourModKit/hook.hpp"
status=0

# Report an absent compiler as an environment error.
if ! command -v "$CXX" >/dev/null 2>&1; then
    echo "FAIL: C++ compiler '$CXX' not found on PATH (set CXX or add the toolchain to PATH)." >&2
    exit 2
fi

if [ ! -f "$GATE_HEADER" ]; then
    echo "FAIL: run this from the repository root ($GATE_HEADER not found)." >&2
    exit 2
fi

# The compiler uses an optional unsupported-target macro set for HEADER.
# The function writes combined diagnostics to stdout and returns the compiler exit code.
compile() {
    local mode="$1" header="$2"
    if [ "$mode" = "non-x64" ]; then
        "$CXX" "${COMMON[@]}" -U__x86_64__ "$header" 2>&1
    elif [ "$mode" = "arm64ec" ]; then
        "$CXX" "${COMMON[@]}" -D_M_X64=100 -D_M_ARM64EC=1 "$header" 2>&1
    elif [ "$mode" = "non-windows" ]; then
        "$CXX" "${COMMON[@]}" -U_WIN32 "$header" 2>&1
    else
        "$CXX" "${COMMON[@]}" "$header" 2>&1
    fi
}

# A target-system override must reach the root configure guard.
expect_root_config_gated() {
    local probe_dir out rc
    probe_dir="$(mktemp -d)"
    out="$(cmake -S . -B "$probe_dir" -G Ninja \
        -DCMAKE_SYSTEM_NAME=Linux \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_CXX_COMPILER_WORKS=TRUE \
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY 2>&1)"
    rc=$?
    cmake -E remove_directory "$probe_dir"
    if [ "$rc" -eq 0 ]; then
        echo "FAIL [CMakeLists.txt] a non-Windows configure succeeded."
        status=1
        return
    fi
    if ! grep -q "$GATE_MSG" <<<"$out"; then
        echo "FAIL [CMakeLists.txt] the non-Windows configure missed the platform diagnostic:"
        printf '%s\n' "$out" | head -20
        status=1
        return
    fi
    echo "PASS [CMakeLists.txt] a non-Windows configure reaches the platform gate."
}

# This check asserts the platform error. Optional modes also require the sole or first diagnostic.
expect_gated() {
    local mode="$1" header="$2" want="${3:-}" out rc
    out="$(compile "$mode" "$header")"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "FAIL [$header] a simulated $mode compile SUCCEEDED. The platform gate did not fire."
        status=1
        return
    fi
    if ! grep -q "$GATE_MSG" <<<"$out"; then
        echo "FAIL [$header] the $mode compile failed WITHOUT the gate #error (wrong reason):"
        printf '%s\n' "$out" | head -20
        status=1
        return
    fi
    echo "PASS [$header] a simulated $mode compile halts at the platform #error."
    if [ "$want" = "sole-diagnostic" ]; then
        local diagnostic_count
        diagnostic_count="$(grep -Eci '(^|: )(fatal error|error|warning|note):' <<<"$out")"
        if [ "$diagnostic_count" -ne 1 ]; then
            echo "FAIL [$header] expected exactly one compiler diagnostic, saw $diagnostic_count:"
            printf '%s\n' "$out" | head -20
            status=1
            return
        fi
        if grep -Eqi 'static[ _-]?assert|static assertion' <<<"$out"; then
            echo "FAIL [$header] a static_assert diagnostic accompanies the #error; the gate is not the sole message."
            status=1
            return
        fi
        echo "PASS [$header] the #error stands alone through the full public surface (no accompanying static_assert)."
    elif [ "$want" = "first-diagnostic" ]; then
        local first_error
        first_error="$(grep -Ei '(^|: )(fatal error|error):' <<<"$out" | head -1)"
        if ! grep -q "$GATE_MSG" <<<"$first_error"; then
            echo "FAIL [$header] the gate #error is not the first error under the $mode simulation:"
            printf '%s\n' "$out" | head -20
            status=1
            return
        fi
        echo "PASS [$header] the gate #error is the first error a consumer sees under the $mode simulation."
    fi
}

# A native x64 compile is the positive control.
expect_clean() {
    local header="$1" out rc
    out="$(compile x64 "$header")"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "FAIL [$header] the native x64 syntax check failed (the positive control is broken):"
        printf '%s\n' "$out" | head -20
        status=1
        return
    fi
    echo "PASS [$header] the native x64 syntax check is clean."
}

echo "== Platform gate: x86-64 Windows (Win64) only =="
expect_gated non-x64 "$GATE_HEADER"
expect_gated arm64ec "$GATE_HEADER"
expect_gated non-windows "$GATE_HEADER"
expect_clean "$GATE_HEADER"
expect_gated non-x64 "$SURFACE_HEADER" sole-diagnostic
expect_gated arm64ec "$SURFACE_HEADER" sole-diagnostic
expect_gated non-windows "$SURFACE_HEADER" first-diagnostic
expect_clean "$SURFACE_HEADER"
expect_root_config_gated

if [ "$status" -ne 0 ]; then
    echo "== Platform gate FAILED =="
else
    echo "== Platform gate passed =="
fi
exit $status
