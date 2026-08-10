#!/usr/bin/env python3
"""Fail if callback paths use allocation-capable implicit thread identity on MinGW.

MinGW's GCC lowers every C++ and GNU TLS spelling to ``__emutls_get_address``, which allocates on each thread's first
touch and calls ``abort()`` when that allocation fails. ``abort()`` raises SIGABRT, which no catch frame intercepts,
so a noexcept callback path would not survive it. Hook callbacks can reach the dispatcher, input-delivery marker, and
routed backend on arbitrary host threads, so none may rely on emulated TLS.

That rule governs a mechanism, not a spelling, so it cannot be checked by reading the source: ``thread_local``,
namespace-scope ``thread_local`` and ``__thread`` all lower to emutls here, while ``__declspec(thread)`` is silently
ignored with only a warning and degrades to a plain shared global. Only the emitted symbols say which one happened,
which is what this script reads.

The check covers EventDispatcher, the reserved input-delivery marker, and SafetyHook's routed-retention control path,
including an ``__emutls_get_address`` import reached through an out-of-line helper. It also rejects ``pthread_self``
from input.cpp, where the binding teardown gate needs exact allocation-free identity. The scope is deliberately narrow
because the archives legitimately carry these symbols in control-plane-only subsystems.
"""

import argparse
import re
import shutil
import subprocess
import sys

# GCC emits one control symbol per emulated-TLS variable and imports __emutls_get_address at each use site.
EMUTLS_SYMBOL = re.compile(r"__emutls_(?:get_address|[vt]\.)")
CALLBACK_TLS_SCOPE = re.compile(
    r"(?:EventDispatcher|event_dispatcher(?:\.cpp)?\.(?:obj|o)|input_delivery_scope\.cpp\.(?:obj|o)|"
    r"inline_hook\.cpp\.(?:obj|o))",
    re.IGNORECASE,
)
PTHREAD_SELF_SYMBOL = re.compile(r"(?:__imp_)?pthread_self\b")
INPUT_GATE_SCOPE = re.compile(r"(?:^|:)input\.cpp\.(?:obj|o):", re.IGNORECASE)


def find_offenders(output: str):
    """Return allocation-capable identity records from callback-path objects."""
    return sorted(
        {
            line.strip()
            for line in output.splitlines()
            if (EMUTLS_SYMBOL.search(line) and CALLBACK_TLS_SCOPE.search(line))
            or (PTHREAD_SELF_SYMBOL.search(line) and INPUT_GATE_SCOPE.search(line))
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", help="built DetourModKit and/or SafetyHook static archives")
    parser.add_argument("--nm", default="nm", help="nm executable to read the archive with")
    args = parser.parse_args()

    nm = shutil.which(args.nm)
    if nm is None:
        print(f"check_emit_tls: nm not found ({args.nm}); cannot inspect the archives", file=sys.stderr)
        return 2

    offenders = []
    for archive in args.archives:
        try:
            result = subprocess.run([nm, "-A", archive], capture_output=True, text=True, errors="replace", check=True)
        except (subprocess.CalledProcessError, OSError) as exc:
            print(f"check_emit_tls: could not read {archive}: {exc}", file=sys.stderr)
            return 2
        offenders.extend(find_offenders(result.stdout))
    offenders = sorted(set(offenders))

    if offenders:
        print(
            "check_emit_tls: a callback path reaches allocation-capable implicit thread identity on MinGW.\n"
            "EventDispatcher and input delivery must use reserved Win32 TLS/native thread identity, SafetyHook's\n"
            "route credit must be explicit, and input teardown must avoid winpthreads pthread_self. AGENTS [B-86].\n"
            "Offending records:",
            file=sys.stderr,
        )
        for record in offenders:
            print(f"  {record}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
