#!/usr/bin/env python3
"""Shipping-archive test-seam hygiene gate.

A test-only seam in a `src/` TU (a `*_for_test` helper, a `*_test_hook` function pointer, a `g_*_override`
injection pointer, a `g_*_probe` point) is permitted ONLY when its definition and every reference are gated
behind DMK_ENABLE_TEST_SEAMS, so a tests-OFF (DMK_BUILD_TESTS=OFF) build compiles none of it. An unguarded
seam silently exports a mutable hook or a private entry point into every shipped archive; the export-equality
gate cannot see it, because a tests-ON tree legitimately carries seams.

This gate scans a shipped (tests-OFF) static archive and fails if any defined external symbol names a test
seam. It reads `.a` archives with `nm` and `.lib` archives with `dumpbin` (falling back to `llvm-nm` for
either); a pre-captured symbol dump can be passed with --symbols-file so the policy is toolchain-agnostic
and unit-testable. Exit status is 1 with the offending symbols printed when a seam leaks, else 0.
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path


# A shipped archive must contain none of these. `_for_test` is the naming convention for test-only entry
# points; `_test_hook` is the null-function-pointer seam a TU fires through; `g_*_override` / `g_*_probe` /
# `g_*_failure*` are injection globals. The latter forms are anchored to the `g_` global prefix so ordinary
# internal helpers such as `resolve_candidate_by_probe` are not false positives. The trailing \b keeps
# unrelated spellings such as `resolve_test_hookup` out.
SEAM_PATTERNS = (
    re.compile(r"_for_test\b"),
    re.compile(r"_test_hook\b"),
    re.compile(r"\bg_[A-Za-z0-9_]*_override\b"),
    re.compile(r"\bg_[A-Za-z0-9_]*_probe\b"),
    re.compile(r"\bg_[A-Za-z0-9_]*_failure(?:_[A-Za-z0-9_]+)*\b"),
    re.compile(r"\b(?:route_retention_stats|set_route_retention_capacity|route_chain_worst_case)\b"),
)


def find_seam_symbols(symbol_names):
    """Returns the sorted, de-duplicated subset of @p symbol_names that names a test seam."""
    hits = set()
    for name in symbol_names:
        if any(pattern.search(name) for pattern in SEAM_PATTERNS):
            hits.add(name.strip())
    return sorted(hits)


def _run(tool_args):
    return subprocess.run(tool_args, capture_output=True, text=True, check=False)


def defined_symbols_from_nm(archive, nm_tool):
    """Defined external symbols of @p archive via nm, demangled. Raises on tool failure."""
    result = _run([nm_tool, "-C", "--defined-only", "--extern-only", str(archive)])
    if result.returncode != 0:
        raise RuntimeError(f"{nm_tool} failed on {archive}: {result.stderr.strip()}")
    names = []
    for line in result.stdout.splitlines():
        # `<addr> <type> <name>`; with --defined-only --extern-only every remaining line is a defined global.
        parts = line.split(" ", 2)
        if len(parts) == 3:
            names.append(parts[2])
    return names


def defined_symbols_from_dumpbin(archive):
    """Defined external symbols of a .lib via dumpbin /SYMBOLS. Undecorated names carry the seam token."""
    result = _run(["dumpbin", "/SYMBOLS", str(archive)])
    if result.returncode != 0:
        raise RuntimeError(f"dumpbin failed on {archive}: {result.stderr.strip()}")
    names = []
    for line in result.stdout.splitlines():
        if "External" not in line or "UNDEF" in line:
            continue
        # `... External     | ?seed_wheel_notches_for_test@detail@... (public: ...)`; the decorated name
        # after `|` still contains the literal seam token, which is all the patterns need to match.
        marker = line.find("|")
        if marker != -1:
            names.append(line[marker + 1:].strip())
    return names


def archive_symbols(archive):
    suffix = archive.suffix.lower()
    if suffix == ".a":
        for tool in ("nm", "llvm-nm"):
            if shutil.which(tool):
                return defined_symbols_from_nm(archive, tool)
        raise RuntimeError("no nm/llvm-nm on PATH to read a .a archive")
    if suffix == ".lib":
        if shutil.which("dumpbin"):
            return defined_symbols_from_dumpbin(archive)
        if shutil.which("llvm-nm"):
            return defined_symbols_from_nm(archive, "llvm-nm")
        raise RuntimeError("no dumpbin/llvm-nm on PATH to read a .lib archive")
    raise RuntimeError(f"unsupported archive type: {archive}")


def main(argv):
    args = argv[1:]
    symbols_file = None
    positional = []
    i = 0
    while i < len(args):
        if args[i] == "--symbols-file":
            symbols_file = args[i + 1]
            i += 2
        else:
            positional.append(args[i])
            i += 1

    if symbols_file is not None:
        names = Path(symbols_file).read_text(encoding="utf-8", errors="replace").splitlines()
    elif len(positional) == 1:
        archive = Path(positional[0]).resolve()
        if not archive.is_file():
            print(f"test-seam gate FAILED: archive '{archive}' does not exist")
            return 1
        try:
            names = archive_symbols(archive)
        except RuntimeError as error:
            print(f"test-seam gate could not read the archive: {error}")
            return 2
    else:
        print("usage: check_no_test_seams.py <shipped-archive.a|.lib> | --symbols-file <dump>")
        return 2

    seams = find_seam_symbols(names)
    if seams:
        print("Test-seam hygiene gate FAILED: the shipped (tests-OFF) archive exports test seams:\n")
        for seam in seams:
            print("  " + seam)
        print(f"\n{len(seams)} leaked seam(s): gate each behind #if defined(DMK_ENABLE_TEST_SEAMS).")
        return 1
    print("Test-seam hygiene gate passed: the shipped archive exports no test seam.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
