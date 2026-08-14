#!/usr/bin/env python3
"""Regression tests for the callback-path symbol filters."""

import importlib.util
import io
import subprocess
import sys
from contextlib import redirect_stderr
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "check_emit_tls.py"
SPEC = importlib.util.spec_from_file_location("check_emit_tls", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def expect_offenders(output: str, expected: int) -> None:
    offenders = MODULE.find_offenders(output)
    if len(offenders) != expected:
        raise AssertionError(f"expected {expected} offender(s), got {offenders}")


def mid_adapter_symbols(owner: str) -> str:
    return "\n".join(
        f"lib.a:{owner}:0000 T void DetourModKit::detail::mid_adapter<{index}ull>(safetyhook::Context64&)"
        for index in range(MODULE.MID_ADAPTER_COUNT)
    )


def test_template_control_symbol_is_rejected() -> None:
    expect_offenders(
        "lib.a:diagnostics.cpp.obj:0000 D __emutls_v._ZN12DetourModKit15EventDispatcherIiE5depthE\n",
        1,
    )


def test_out_of_line_helper_import_is_rejected() -> None:
    expect_offenders("lib.a:event_dispatcher.cpp.obj:         U __emutls_get_address\n", 1)


def test_input_delivery_tls_import_is_rejected() -> None:
    expect_offenders("lib.a:input_delivery_scope.cpp.obj:     U __emutls_get_address\n", 1)


def test_backend_retention_tls_import_is_rejected() -> None:
    expect_offenders("libsafetyhook.a:inline_hook.cpp.obj:    U __emutls_get_address\n", 1)


def test_unrelated_tls_is_out_of_scope() -> None:
    expect_offenders("lib.a:worker.cpp.obj:0000 D __emutls_v._ZN6worker5depthE\n", 0)


def test_unrelated_import_is_out_of_scope() -> None:
    expect_offenders("lib.a:worker.cpp.obj:         U __emutls_get_address\n", 0)


def test_input_gate_pthread_identity_is_rejected() -> None:
    expect_offenders("lib.a:input.cpp.obj:                 U pthread_self\n", 1)


def test_unrelated_pthread_identity_is_out_of_scope() -> None:
    expect_offenders("lib.a:worker.cpp.obj:                 U pthread_self\n", 0)


def test_mid_adapter_accessor_indirection_is_rejected() -> None:
    output = mid_adapter_symbols("hook.cpp.obj")
    output += "\nlib.a:hook.cpp.obj: U DetourModKit::detail::mid_adapter_slots()\n"
    offenders = MODULE.find_mid_adapter_indirection(output)
    if offenders != ["lib.a:hook.cpp.obj: U DetourModKit::detail::mid_adapter_slots()"]:
        raise AssertionError(f"mid-adapter accessor call was not rejected: {offenders}")


def test_mid_adapter_owner_with_direct_access_is_accepted() -> None:
    output = mid_adapter_symbols("mid_hook_adapter.cpp.obj")
    offenders = MODULE.find_mid_adapter_indirection(output)
    if offenders:
        raise AssertionError(f"direct mid-adapter access was rejected: {offenders}")


def test_main_scans_every_archive() -> None:
    calls = []
    original_argv = sys.argv
    original_run = MODULE.subprocess.run
    original_which = MODULE.shutil.which

    def fake_run(args, **_kwargs):
        archive = args[-1]
        calls.append(archive)
        output = ""
        if archive == "backend.a":
            output = "backend.a:inline_hook.cpp.obj: U __emutls_get_address\n"
        return subprocess.CompletedProcess(args, 0, output, "")

    try:
        sys.argv = ["check_emit_tls.py", "library.a", "backend.a", "--nm", "fake-nm"]
        MODULE.shutil.which = lambda _tool: "fake-nm"
        MODULE.subprocess.run = fake_run
        errors = io.StringIO()
        with redirect_stderr(errors):
            code = MODULE.main()
    finally:
        sys.argv = original_argv
        MODULE.subprocess.run = original_run
        MODULE.shutil.which = original_which

    if code != 1 or calls != ["library.a", "backend.a"] or "inline_hook.cpp.obj" not in errors.getvalue():
        raise AssertionError(f"second archive was not enforced: code={code}, calls={calls}, errors={errors.getvalue()}")


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"emit-TLS checker self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
