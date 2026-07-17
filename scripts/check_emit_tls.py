#!/usr/bin/env python3
"""Fail if the built library reaches emulated TLS from an EventDispatcher path.

MinGW's GCC lowers every C++ and GNU TLS spelling to ``__emutls_get_address``, which allocates on each thread's first
touch and calls ``abort()`` when that allocation fails. ``abort()`` raises SIGABRT, which no catch frame intercepts,
so ``emit_safe()``'s noexcept containment would not survive it. Hook callbacks can reach ``emit_safe()`` on arbitrary
host threads, so the emit chain uses a reserved Win32 TLS index instead.

That rule governs a mechanism, not a spelling, so it cannot be checked by reading the source: ``thread_local``,
namespace-scope ``thread_local`` and ``__thread`` all lower to emutls here, while ``__declspec(thread)`` is silently
ignored with only a warning and degrades to a plain shared global. Only the emitted symbols say which one happened,
which is what this script reads.

The check covers EventDispatcher template symbols and the event_dispatcher implementation object, including an
``__emutls_get_address`` import reached through an out-of-line helper. The scope is deliberately the dispatcher and its
implementation object rather than a repo-wide emulated-TLS ban: the archive legitimately carries unrelated ``__emutls``
references from other subsystems, so a blanket rule would false-positive. A repo-wide per-symbol emulated-TLS checker is
a separate, more general tool.
"""

import argparse
import re
import shutil
import subprocess
import sys

# GCC emits one control symbol per emulated-TLS variable and imports __emutls_get_address at each use site.
EMUTLS_SYMBOL = re.compile(r"__emutls_(?:get_address|[vt]\.)")
DISPATCHER_SCOPE = re.compile(r"(?:EventDispatcher|event_dispatcher(?:\.cpp)?\.(?:obj|o))", re.IGNORECASE)


def find_offenders(output: str):
    """Return emulated-TLS records owned by a dispatcher template or implementation object."""
    return sorted(
        {
            line.strip()
            for line in output.splitlines()
            if EMUTLS_SYMBOL.search(line) and DISPATCHER_SCOPE.search(line)
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="path to the built DetourModKit static library")
    parser.add_argument("--nm", default="nm", help="nm executable to read the archive with")
    args = parser.parse_args()

    nm = shutil.which(args.nm)
    if nm is None:
        print(f"check_emit_tls: nm not found ({args.nm}); cannot inspect {args.archive}", file=sys.stderr)
        return 2

    try:
        result = subprocess.run([nm, "-A", args.archive], capture_output=True, text=True, errors="replace", check=True)
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"check_emit_tls: could not read {args.archive}: {exc}", file=sys.stderr)
        return 2

    offenders = find_offenders(result.stdout)

    if offenders:
        print(
            "check_emit_tls: EventDispatcher reaches emulated TLS. On MinGW that allocates on a thread's first touch\n"
            "and abort()s if it fails, inside a path hook callbacks reach on arbitrary host threads. Use a reserved\n"
            "Win32 TLS index (see detail::ensure_emit_frame_tls) rather than any thread_local spelling. "
            "AGENTS [B-86].\n"
            f"Offending records in {args.archive}:",
            file=sys.stderr,
        )
        for record in offenders:
            print(f"  {record}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
