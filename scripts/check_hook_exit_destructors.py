#!/usr/bin/env python3
"""Reject exit-time destructor registration in hook translation units.

A namespace-scope Hook or VmtHook can outlive hook state initialized after its owner. The VMT object gate, hook
ledger, allocator hold, and mid adapter table use never-destroyed storage (`[B-47]`). Source spelling does not prove
this property. Current MSVC treats ``std::mutex`` as trivially destructible. MinGW registers
``atexit(pthread_mutex_destroy)``. This checker reads archive symbols. Other archive objects can own valid exit-time
destructors, so the checker limits its object set.
"""

import argparse
import re
import shutil
import subprocess
import sys

# GCC routes every exit-time destructor of a function-local or namespace-scope object through one of these.
EXIT_REGISTRATION = re.compile(r"\bU\s+(?:__imp_)?(?:__cxa_)?atexit\b")
# The objects whose statics a late namespace-scope hook owner can outlive.
HOOK_OBJECT = re.compile(
    r":(?P<object>(?:mid_)?hook(?:_toggle|_mid_context|_ledger|_fault_boundary|_adapter)?\.cpp\.(?:obj|o)):",
    re.IGNORECASE,
)
REQUIRED_OBJECTS = {
    "hook.cpp",
    "hook_toggle.cpp",
    "hook_mid_context.cpp",
    "hook_ledger.cpp",
    "hook_fault_boundary.cpp",
    "mid_hook_adapter.cpp",
}


def find_offenders(output: str):
    """Return exit-registration records emitted by an in-scope hook object."""
    return sorted(
        {line.strip() for line in output.splitlines() if HOOK_OBJECT.search(line) and EXIT_REGISTRATION.search(line)}
    )


def find_covered_objects(output: str):
    """Return the in-scope object names the archive actually contains."""
    covered = set()
    for line in output.splitlines():
        match = HOOK_OBJECT.search(line)
        if match is not None:
            covered.add(match.group("object").rsplit(".cpp.", 1)[0] + ".cpp")
    return covered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", help="built DetourModKit static archive")
    parser.add_argument("--nm", default="nm", help="nm executable to read the archive with")
    args = parser.parse_args()

    nm = shutil.which(args.nm)
    if nm is None:
        print(f"check_hook_exit_destructors: nm not found ({args.nm}). Cannot inspect the archives", file=sys.stderr)
        return 2

    outputs = []
    for archive in args.archives:
        try:
            result = subprocess.run(
                [nm, "-A", "-C", archive], capture_output=True, text=True, errors="replace", check=True
            )
        except (subprocess.CalledProcessError, OSError) as exc:
            print(f"check_hook_exit_destructors: failed to read {archive}: {exc}", file=sys.stderr)
            return 2
        outputs.append(result.stdout)

    combined = "\n".join(outputs)
    missing = sorted(REQUIRED_OBJECTS - find_covered_objects(combined))
    if missing:
        print(
            "check_hook_exit_destructors: the archives omit these in-scope objects: "
            + ", ".join(missing),
            file=sys.stderr,
        )
        return 1

    offenders = find_offenders(combined)
    if offenders:
        print(
            "check_hook_exit_destructors: a hook translation unit registers an exit-time destructor.\n"
            "A namespace-scope Hook or VmtHook owner tears down after that destructor runs, so the state it\n"
            "reaches must live in never-destroyed storage. AGENTS [B-47].\n"
            "Exit registration records:",
            file=sys.stderr,
        )
        for record in offenders:
            print(f"  {record}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
