#!/usr/bin/env python3
"""Fail if MinGW callback code adds implicit TLS or mid-adapter accessor calls.

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

The mid-hook adapter table must share one object with its slot and TLS accessors. This preserves direct access in the
callback path.
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
OBJECT_RECORD = re.compile(r"^(?P<object>.*\.(?:obj|o)):(?P<record>.*)$", re.IGNORECASE)
MID_ADAPTER_DEFINITION = re.compile(
    r"\b[TtWw]\s+void DetourModKit::detail::mid_adapter<\d+(?:ull|ul)>\("
)
MID_ADAPTER_ACCESSOR_REFERENCE = re.compile(
    r"\bU\s+DetourModKit::detail::(?:mid_adapter_slots|mid_entry_tls_index)\(\)"
)
MID_ADAPTER_COUNT = 64


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


def find_mid_adapter_indirection(output: str):
    """Return adapter ownership errors and out-of-line accessor records."""
    owner_counts = {}
    accessor_references = {}
    for raw_line in output.splitlines():
        match = OBJECT_RECORD.match(raw_line)
        if match is None:
            continue
        owner = match.group("object")
        record = match.group("record")
        if MID_ADAPTER_DEFINITION.search(record):
            owner_counts[owner] = owner_counts.get(owner, 0) + 1
        if MID_ADAPTER_ACCESSOR_REFERENCE.search(record):
            accessor_references.setdefault(owner, []).append(raw_line.strip())

    if not owner_counts:
        # The archive set always includes the DetourModKit archive, which defines every adapter. Zero matches
        # means symbol rot in the archive or in MID_ADAPTER_DEFINITION, so the check fails closed.
        return ["no mid-hook adapter definitions were found; the adapter symbol pattern no longer matches"]

    errors = []
    definition_count = sum(owner_counts.values())
    if definition_count != MID_ADAPTER_COUNT:
        errors.append(f"mid-hook adapter definition count is {definition_count}, expected {MID_ADAPTER_COUNT}")
    if len(owner_counts) != 1:
        errors.append(f"mid-hook adapters span {len(owner_counts)} objects, expected one")
    for owner in owner_counts:
        errors.extend(accessor_references.get(owner, []))
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", help="built DetourModKit and SafetyHook static archives")
    parser.add_argument("--nm", default="nm", help="nm executable to read the archive with")
    args = parser.parse_args()

    nm = shutil.which(args.nm)
    if nm is None:
        print(f"check_emit_tls: nm not found ({args.nm}); cannot inspect the archives", file=sys.stderr)
        return 2

    outputs = []
    offenders = []
    for archive in args.archives:
        try:
            result = subprocess.run(
                [nm, "-A", "-C", archive], capture_output=True, text=True, errors="replace", check=True
            )
        except (subprocess.CalledProcessError, OSError) as exc:
            print(f"check_emit_tls: could not read {archive}: {exc}", file=sys.stderr)
            return 2
        outputs.append(result.stdout)
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

    adapter_offenders = find_mid_adapter_indirection("\n".join(outputs))
    if adapter_offenders:
        print(
            "check_emit_tls: a mid-hook adapter reaches an out-of-line storage accessor on MinGW.\n"
            "The adapter table and storage must share one object so Release code uses direct slot and TLS access.\n"
            "Offending records:",
            file=sys.stderr,
        )
        for record in adapter_offenders:
            print(f"  {record}", file=sys.stderr)

    return 1 if offenders or adapter_offenders else 0


if __name__ == "__main__":
    sys.exit(main())
