#!/usr/bin/env python3
"""CTest label-inventory gate.

A label-selected run reports success when it runs nothing. `ctest -L fault-proof` on a tree where the proof
subdirectory registered no target is indistinguishable from a tree where every case passed, so a toolchain gate, a
renamed case, or a proof host that was never added silently removes coverage while CI stays green.

This gate reads the inventory rather than the results: it fails when a named case is absent from a label, when it is
registered more than once, when the label carries fewer cases than declared, or when GoogleTest discovery left a
`_NOT_BUILT` placeholder because the proof executable does not exist. Exit status is 0 when the inventory matches and
1 with the exact drift printed otherwise.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

# gtest_discover_tests(DISCOVERY_MODE PRE_TEST) registers this placeholder instead of the real cases when the target
# binary is missing at run time, which is exactly the "the proof was never built" state a label run must not pass.
NOT_BUILT_MARKER = "_NOT_BUILT"


def load_inventory(build_directory: Path | None, inventory_file: Path | None) -> dict:
    """Returns the parsed `ctest --show-only=json-v1` document."""
    if inventory_file is not None:
        return json.loads(inventory_file.read_text(encoding="utf-8"))

    completed = subprocess.run(
        ["ctest", "--test-dir", str(build_directory), "--show-only=json-v1"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"CTest inventory exited with code {completed.returncode}.\n{completed.stderr}")
    return json.loads(completed.stdout)


def labels_of(test: dict) -> list[str]:
    for prop in test.get("properties") or []:
        if prop.get("name") == "LABELS":
            return [str(value) for value in (prop.get("value") or [])]
    return []


def find_drift(inventory: dict, label: str, required: list[str], minimum: int,
               expect_targets: list[str]) -> list[str]:
    """Returns one message per inventory defect, empty when the label matches its declaration."""
    tests = inventory.get("tests")
    if not isinstance(tests, list):
        return ["The CTest inventory carries no 'tests' array."]

    drift: list[str] = []

    # The placeholder carries no LABELS property, so it has to be matched by name. Only the declared targets are
    # checked: an unbuilt target this label does not own is not this gate's business.
    names_present = {str(test.get("name", "")) for test in tests}
    for target in expect_targets:
        if f"{target}{NOT_BUILT_MARKER}" in names_present:
            drift.append(f"'{target}' was not built, so GoogleTest registered a placeholder instead of its cases.")

    selected = [t for t in tests if label in labels_of(t)]
    names = [str(t.get("name", "")) for t in selected]

    for name in required:
        occurrences = names.count(name)
        if occurrences == 0:
            drift.append(f"'{name}' is not registered under label '{label}'.")
        elif occurrences > 1:
            drift.append(f"'{name}' is registered {occurrences} times under label '{label}'; expected exactly one.")

    if len(selected) < minimum:
        drift.append(f"Label '{label}' carries {len(selected)} cases; at least {minimum} were declared.")

    return drift


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--build-directory", type=Path, help="Configured CMake tree to inventory through CTest.")
    source.add_argument("--inventory-file", type=Path, help="A captured json-v1 document, for the self-test.")
    parser.add_argument("--label", required=True, help="The CTest label whose registration is being gated.")
    parser.add_argument("--require", action="append", default=[], metavar="NAME",
                        help="A case that must be registered exactly once under the label. Repeatable.")
    parser.add_argument("--minimum", type=int, default=0, help="Least number of cases the label must carry.")
    parser.add_argument("--expect-target", action="append", default=[], metavar="TARGET",
                        help="A GoogleTest proof target whose discovery placeholder is a failure. Repeatable.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_arguments(argv)
    try:
        inventory = load_inventory(args.build_directory, args.inventory_file)
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    drift = find_drift(inventory, args.label, args.require, args.minimum, args.expect_target)
    if drift:
        print(f"error: the '{args.label}' inventory does not match its declaration:", file=sys.stderr)
        for message in drift:
            print(f"  {message}", file=sys.stderr)
        return 1

    print(f"Label '{args.label}' inventory matches: {len(args.require)} named cases, minimum {args.minimum}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
