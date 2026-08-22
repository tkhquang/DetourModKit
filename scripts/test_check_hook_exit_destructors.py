#!/usr/bin/env python3
"""Regression tests for the hook exit-destructor symbol filter."""

import importlib.util
import io
import sys
from contextlib import redirect_stderr
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "check_hook_exit_destructors.py"
SPEC = importlib.util.spec_from_file_location("check_hook_exit_destructors", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


CLEAN_ARCHIVE = "\n".join(f"lib.a:{name}.obj:0000 T DetourModKit::hook::probe()" for name in MODULE.REQUIRED_OBJECTS)


def expect_offenders(output: str, expected: int) -> None:
    offenders = MODULE.find_offenders(output)
    if len(offenders) != expected:
        raise AssertionError(f"expected {expected} offender(s), got {offenders}")


def test_vmt_gate_registration_is_rejected() -> None:
    expect_offenders("lib.a:hook.cpp.obj:                 U atexit\n", 1)


def test_toggle_registration_is_rejected() -> None:
    expect_offenders("lib.a:hook_toggle.cpp.obj:          U __cxa_atexit\n", 1)


def test_mid_context_registration_is_rejected() -> None:
    expect_offenders("lib.a:hook_mid_context.cpp.obj:     U atexit\n", 1)


def test_ledger_registration_is_rejected() -> None:
    expect_offenders("lib.a:hook_ledger.cpp.obj:          U __imp_atexit\n", 1)


def test_mid_adapter_registration_is_rejected() -> None:
    expect_offenders("lib.a:mid_hook_adapter.cpp.obj:     U atexit\n", 1)


def test_unrelated_object_is_out_of_scope() -> None:
    expect_offenders("lib.a:logger.cpp.obj:               U atexit\n", 0)


def test_defined_symbol_named_atexit_is_not_a_registration() -> None:
    expect_offenders("lib.a:hook.cpp.obj:0000 T DetourModKit::detail::atexit_probe()\n", 0)


def test_clean_archive_covers_every_required_object() -> None:
    if MODULE.REQUIRED_OBJECTS - MODULE.find_covered_objects(CLEAN_ARCHIVE):
        raise AssertionError("the clean fixture does not cover every required object")
    expect_offenders(CLEAN_ARCHIVE, 0)


def test_missing_object_fails_closed() -> None:
    trimmed = "\n".join(line for line in CLEAN_ARCHIVE.splitlines() if "hook_ledger" not in line)
    missing = MODULE.REQUIRED_OBJECTS - MODULE.find_covered_objects(trimmed)
    if missing != {"hook_ledger.cpp"}:
        raise AssertionError(f"the checker must report a dropped object, got {missing}")


def run_main(nm_output: str) -> tuple[int, str]:
    original_argv = sys.argv
    original_run = MODULE.subprocess.run
    original_which = MODULE.shutil.which

    class Completed:
        def __init__(self, stdout: str):
            self.stdout = stdout

    errors = io.StringIO()
    try:
        sys.argv = ["check_hook_exit_destructors.py", "library.a"]
        MODULE.shutil.which = lambda name: name
        MODULE.subprocess.run = lambda *args, **kwargs: Completed(nm_output)
        with redirect_stderr(errors):
            code = MODULE.main()
    finally:
        sys.argv = original_argv
        MODULE.subprocess.run = original_run
        MODULE.shutil.which = original_which

    return code, errors.getvalue()


def test_main_reports_a_missing_object() -> None:
    code, errors = run_main("lib.a:hook.cpp.obj:0000 T DetourModKit::hook::probe()\n")

    if code != 1 or "hook_ledger.cpp" not in errors:
        raise AssertionError(f"the checker did not reject a vacuous archive: code={code}, errors={errors}")


def test_main_rejects_an_exit_registration() -> None:
    output = CLEAN_ARCHIVE + "\nlib.a:hook.cpp.obj:                 U atexit\n"
    code, errors = run_main(output)
    if code != 1 or "Exit registration records:" not in errors or "hook.cpp.obj" not in errors:
        raise AssertionError(f"the checker accepted an exit registration: code={code}, errors={errors}")


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"hook exit-destructor checker self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
