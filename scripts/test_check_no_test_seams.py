#!/usr/bin/env python3
"""Self-test for check_no_test_seams.py: the gate must flag every seam-naming shape and pass clean archives.

Covers the policy core (find_seam_symbols) for the *_for_test convention, the *_test_hook function pointer,
g_*_override / g_*_probe / g_*_failure injection globals, explicit retention-test APIs, the MSVC-decorated form of a
seam, and the two non-seams that must NOT trip an anchor (resolve_candidate_by_probe against g_*_probe,
resolve_test_hookup against the *_test_hook word boundary); plus the end-to-end --symbols-file path for both a
leaking and a clean dump.
"""
import importlib.util
import io
import pathlib
import sys
import tempfile
from contextlib import redirect_stdout

_SCRIPT = pathlib.Path(__file__).with_name("check_no_test_seams.py")
_spec = importlib.util.spec_from_file_location("check_no_test_seams", _SCRIPT)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)


def _expect(condition, message):
    if not condition:
        raise AssertionError(message)


def _run_symbols_file(lines):
    with tempfile.TemporaryDirectory() as tmp:
        dump = pathlib.Path(tmp) / "syms.txt"
        dump.write_text("\n".join(lines), encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            code = _module.main(["check_no_test_seams.py", "--symbols-file", str(dump)])
        return code, out.getvalue()


def _test_policy_core():
    seams = _module.find_seam_symbols([
        "DetourModKit::detail::seed_wheel_notches_for_test(std::array<int, 4ull> const&)",
        "DetourModKit::detail::request_servicer_reload_for_test()",
        "g_rtti_resolve_clock_override",
        "g_mid_adapter_precommit_probe",
        "DetourModKit::detail::g_mid_entry_store_failure_thread",
        "DetourModKit::detail::g_mid_entry_store_failure_hits",
        "safetyhook::g_unwind_registration_failure",
        "safetyhook::g_unwind_unregistration_failure",
        "safetyhook::route_retention_stats()",
        "DetourModKit::detail::g_config_repoint_window_test_hook",  # null function-pointer seam
        "?bootstrap_shutdown_event_for_test@detail@DetourModKit@@YAPEAX_test@@XZ",  # MSVC-decorated
    ])
    _expect(len(seams) == 11, f"expected all 11 seams flagged, got {seams}")

    clean = _module.find_seam_symbols([
        "DetourModKit::detail::take_wheel_counts()",
        "DetourModKit::detail::publish_wheel_consume(unsigned char)",
        "DetourModKit::scan::(anonymous namespace)::resolve_candidate_by_probe(...)",  # not a g_* probe
        "DetourModKit::detail::resolve_test_hookup(...)",  # _test_hook without the word boundary
        "DetourModKit::hook::install(...)",
    ])
    _expect(clean == [], f"non-seam symbols must not trip the gate, got {clean}")


def _test_symbols_file():
    code, out = _run_symbols_file([
        "0000000000000000 T DetourModKit::detail::seed_wheel_notches_for_test(std::array<int, 4ull> const&)",
        "0000000000000000 T DetourModKit::hook::install(void*)",
    ])
    _expect(code == 1, "a dump containing a seam must exit 1")
    _expect("seed_wheel_notches_for_test" in out, "the offending seam must be printed")

    code, out = _run_symbols_file([
        "0000000000000000 T DetourModKit::detail::take_wheel_counts()",
        "0000000000000000 T DetourModKit::detail::publish_wheel_consume(unsigned char)",
    ])
    _expect(code == 0, "a clean dump must exit 0")
    _expect("passed" in out, "a clean dump must report a pass")


def main():
    failures = []
    for test in (_test_policy_core, _test_symbols_file):
        try:
            test()
        except AssertionError as error:
            failures.append(f"{test.__name__}: {error}")
    if failures:
        print("check_no_test_seams self-test FAILED:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("check_no_test_seams self-test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
