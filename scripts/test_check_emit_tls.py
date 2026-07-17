#!/usr/bin/env python3
"""Regression tests for the EventDispatcher emulated-TLS symbol filter."""

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "check_emit_tls.py"
SPEC = importlib.util.spec_from_file_location("check_emit_tls", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def expect_offenders(output: str, expected: int) -> None:
    offenders = MODULE.find_offenders(output)
    if len(offenders) != expected:
        raise AssertionError(f"expected {expected} offender(s), got {offenders}")


def test_template_control_symbol_is_rejected() -> None:
    expect_offenders(
        "lib.a:diagnostics.cpp.obj:0000 D __emutls_v._ZN12DetourModKit15EventDispatcherIiE5depthE\n",
        1,
    )


def test_out_of_line_helper_import_is_rejected() -> None:
    expect_offenders("lib.a:event_dispatcher.cpp.obj:         U __emutls_get_address\n", 1)


def test_unrelated_tls_is_out_of_scope() -> None:
    expect_offenders("lib.a:worker.cpp.obj:0000 D __emutls_v._ZN6worker5depthE\n", 0)


def test_unrelated_import_is_out_of_scope() -> None:
    expect_offenders("lib.a:worker.cpp.obj:         U __emutls_get_address\n", 0)


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"emit-TLS checker self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
