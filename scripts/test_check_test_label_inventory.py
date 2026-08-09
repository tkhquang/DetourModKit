#!/usr/bin/env python3
"""Regression tests for the CTest label-inventory gate.

The gate's whole value is failing on an inventory that a label-selected ctest run would report as green, so each case
below feeds a document that such a run would accept and asserts the gate rejects it anyway.
"""

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "check_test_label_inventory.py"
SPEC = importlib.util.spec_from_file_location("check_test_label_inventory", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

LABEL = "fault-proof"


def entry(name: str, labels: list[str] | None = None) -> dict:
    properties = []
    if labels is not None:
        properties.append({"name": "LABELS", "value": labels})
    return {"name": name, "command": [f"C:/build/{name}.exe"], "properties": properties}


def inventory(*tests: dict) -> dict:
    return {"kind": "ctestInfo", "version": {"major": 1, "minor": 0}, "tests": list(tests)}


def expect_drift(document: dict, required: list[str], minimum: int, expected: int,
                 expect_targets: list[str] | None = None) -> None:
    drift = MODULE.find_drift(document, LABEL, required, minimum, expect_targets or [])
    if len(drift) != expected:
        raise AssertionError(f"expected {expected} drift message(s), got {drift}")


def test_complete_inventory_is_accepted() -> None:
    document = inventory(entry("A", [LABEL]), entry("B", [LABEL]), entry("Other", ["unit"]))
    expect_drift(document, ["A", "B"], 2, 0)


def test_missing_required_case_is_rejected() -> None:
    expect_drift(inventory(entry("A", [LABEL])), ["A", "B"], 0, 1)


def test_unlabelled_registration_does_not_satisfy_the_requirement() -> None:
    # The case exists, so a name-only search would pass; it carries no label, so `ctest -L` would never run it.
    expect_drift(inventory(entry("A", [LABEL]), entry("B", ["unit"])), ["A", "B"], 0, 1)


def test_duplicate_registration_is_rejected() -> None:
    expect_drift(inventory(entry("A", [LABEL]), entry("A", [LABEL])), ["A"], 0, 1)


def test_short_label_set_is_rejected() -> None:
    expect_drift(inventory(entry("A", [LABEL])), ["A"], 3, 1)


def test_empty_label_set_is_rejected() -> None:
    # The state a toolchain gate around the whole proof subdirectory produces, and the one `ctest -L` calls success.
    expect_drift(inventory(entry("Other", ["unit"])), ["A"], 1, 2)


def test_unbuilt_discovery_placeholder_is_rejected() -> None:
    # gtest_discover_tests leaves this instead of the real cases when the proof executable is absent, and it carries
    # no LABELS property, so it is matched by name against the declared targets.
    document = inventory(entry("fault_tests" + MODULE.NOT_BUILT_MARKER))
    expect_drift(document, [], 0, 1, ["fault_tests"])


def test_an_undeclared_targets_placeholder_is_out_of_scope() -> None:
    # Another label's target being unbuilt says nothing about this label; the fault wrapper builds only its own.
    document = inventory(entry("other_tests" + MODULE.NOT_BUILT_MARKER), entry("A", [LABEL]))
    expect_drift(document, ["A"], 1, 0, ["fault_tests"])


def test_missing_tests_array_is_rejected() -> None:
    expect_drift({"kind": "ctestInfo"}, ["A"], 1, 1)


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"label-inventory gate self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
