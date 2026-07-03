#!/usr/bin/env bash
#
# check_arch_gate.sh -- prove the single deliberate x86-64 architecture gate holds.
#
# DetourModKit is an x86-64 (Win64) library by design: an Address is exactly a machine pointer, and
# the scan / hook engines assume the x86-64 register file and instruction encodings. The whole
# library therefore routes a non-x86-64 target into one clear diagnostic -- the `#error` in
# include/DetourModKit/defines.hpp -- which halts translation before the scattered pointer-width /
# ABI-layout `static_assert`s in the engine (the x86 decoder, the RTTI ColHead layout, the mid-hook
# register set) would otherwise fire as a confusing cascade. This check locks that contract in.
#
# Why simulate rather than cross-compile: there is no 32-bit toolchain on the standard Windows CI
# image, and the pinned MinGW is not multilib, so a real `-m32` / `i686-w64-mingw32` build is not
# available (and `-m32` on a non-multilib GCC fails with its own diagnostic, which would not exercise
# our gate). The gate keys on `defined(_M_X64) || defined(__x86_64__)`, so undefining the compiler's
# `__x86_64__` predefine (GCC never defines `_M_X64`) drives that condition false exactly as a real
# 32-bit / non-x86 configure would. `-fsyntax-only` keeps the probe configure-only: it parses the
# headers with no code generation, no link step, and no target libraries.
#
# What the simulation does and does not do: clearing `__x86_64__` flips only the macro, not the host
# pointer width, so `sizeof(void*)` stays 8 under the probe. The scattered pointer-width asserts
# (`sizeof(void*) == 8`) therefore do not themselves fail here -- they fail only on a genuine 32-bit
# target, which CI cannot host. What this check verifies is the property that makes that real-target
# cascade unreachable in the first place: the gate is present, is positioned early enough in the
# include graph that a consumer hits it before anything else, and is the single clear diagnostic.
# That is the whole contract -- one deliberate message instead of a wall of engine asserts.
#
# The probe compiles two headers, each with a native-x64 positive control so that a "gated" failure
# is attributable to the gate and never to a broken environment or include path:
#   * defines.hpp  -- the gate header itself: the canonical minimal proof that the `#error` fires.
#   * hook.hpp     -- a full public header (its include graph pulls defines.hpp early via address.hpp)
#                     that also carries its own `static_assert(sizeof(void*) == 8)`. A non-x64 compile
#                     that halts at the single `#error` with no other diagnostic proves the gate is
#                     reached first through a real consumer surface and is the sole message emitted.

set -u

CXX="${CXX:-g++}"
COMMON=(-std=c++23 -Iinclude -fsyntax-only -x c++)
GATE_MSG="targets x86-64" # substring of the defines.hpp #error message
GATE_HEADER="include/DetourModKit/defines.hpp"
SURFACE_HEADER="include/DetourModKit/hook.hpp"
status=0

# Pre-flight the compiler so a missing toolchain fails with a clear, actionable message instead of
# surfacing as a spurious gate mismatch: a non-zero compile that emits no #error would otherwise be
# reported by expect_gated as "failed WITHOUT the gate #error (wrong reason)", which reads like a gate
# regression rather than an environment problem.
if ! command -v "$CXX" >/dev/null 2>&1; then
    echo "FAIL: C++ compiler '$CXX' not found on PATH (set CXX or add the toolchain to PATH)." >&2
    exit 2
fi

if [ ! -f "$GATE_HEADER" ]; then
    echo "FAIL: run this from the repository root ($GATE_HEADER not found)." >&2
    exit 2
fi

# Compile HEADER, optionally simulating a non-x64 target by clearing the __x86_64__ predefine.
# Echoes the combined diagnostics on stdout and returns the compiler's exit code.
compile() {
    local mode="$1" header="$2"
    if [ "$mode" = "non-x64" ]; then
        "$CXX" "${COMMON[@]}" -U__x86_64__ "$header" 2>&1
    else
        "$CXX" "${COMMON[@]}" "$header" 2>&1
    fi
}

# A non-x64 compile of HEADER must FAIL, and must fail specifically at the architecture #error.
# Pass "sole-diagnostic" as the second argument to also assert that the #error stands alone: no
# warning, note, fatal error, or static_assert diagnostic accompanies it, so the gate is the single clear message a
# consumer sees rather than one line among many.
expect_gated() {
    local header="$1" want_sole="${2:-}" out rc
    out="$(compile non-x64 "$header")"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "FAIL [$header] a simulated non-x64 compile SUCCEEDED; the architecture gate did not fire."
        status=1
        return
    fi
    if ! grep -q "$GATE_MSG" <<<"$out"; then
        echo "FAIL [$header] the non-x64 compile failed WITHOUT the gate #error (wrong reason):"
        printf '%s\n' "$out" | head -20
        status=1
        return
    fi
    echo "PASS [$header] a simulated non-x64 compile halts at the single architecture #error."
    if [ "$want_sole" = "sole-diagnostic" ]; then
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
    fi
}

# A native x64 compile of HEADER must SUCCEED. This is the positive control: it proves the compiler,
# flags, and include path are sound, so the gated failure above is the gate and nothing else.
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

echo "== Architecture gate: x86-64 (Win64) only =="
expect_gated "$GATE_HEADER"
expect_clean "$GATE_HEADER"
expect_gated "$SURFACE_HEADER" sole-diagnostic
expect_clean "$SURFACE_HEADER"

if [ "$status" -ne 0 ]; then
    echo "== Architecture gate FAILED =="
else
    echo "== Architecture gate passed =="
fi
exit $status
