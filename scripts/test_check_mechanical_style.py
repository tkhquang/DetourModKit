#!/usr/bin/env python3
"""Regression fixtures for the mechanical naming/namespace-comment/dash probe.

Each case pins one rule with a positive fixture (a crafted violation the probe
must flag) and negative controls that must stay silent.
"""

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "check_mechanical_style.py"
SPEC = importlib.util.spec_from_file_location("check_mechanical_style", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def expect(text: str, expected: int) -> None:
    problems = MODULE.scan_text(text, "<fixture>")
    if len(problems) != expected:
        raise AssertionError(f"expected {expected} violation(s), got {problems}")


def expect_wheel(text: str, expected: int) -> None:
    problems = MODULE.scan_text(text, MODULE.WHEEL_HOST_HEADER)
    if len(problems) != expected:
        raise AssertionError(f"expected {expected} wheel violation(s), got {problems}")


def test_em_dash_is_rejected() -> None:
    # chr() so the fixture carries the banned codepoint without this file spelling it literally.
    expect("// a wide " + chr(0x2014) + " gap", 1)


def test_en_dash_is_rejected() -> None:
    expect("// range 1" + chr(0x2013) + "5 inclusive", 1)


def test_ascii_double_dash_is_accepted() -> None:
    expect("// the house replacement -- stays legal", 0)


def test_lowercase_object_macro_is_rejected() -> None:
    expect("#define bufferBytes 4096", 1)


def test_mixedcase_function_macro_is_rejected() -> None:
    expect("  #  define Foo_Bar(x) ((x) + 1)", 1)


def test_upper_snake_macro_is_accepted() -> None:
    expect("#define DETOURMODKIT_ADDRESS_HPP", 0)


def test_upper_snake_function_macro_is_accepted() -> None:
    expect("#define DMK_TRY(expr) do { } while (0)", 0)


def test_named_closer_is_accepted() -> None:
    expect("} // namespace DetourModKit::scan", 0)


def test_anonymous_bare_closer_is_accepted() -> None:
    expect("    } // namespace", 0)


def test_anonymous_explicit_closer_is_accepted() -> None:
    expect("    } // anonymous namespace", 0)


def test_double_close_is_accepted() -> None:
    expect("}} // namespace DetourModKit", 0)


def test_non_house_keyword_is_rejected() -> None:
    expect("} // end namespace", 1)


def test_trailing_token_after_name_is_rejected() -> None:
    expect("} // namespace DetourModKit extra", 1)


def test_malformed_namespace_spacing_or_case_is_rejected() -> None:
    fixture = "\n".join(["}// namespace DetourModKit", "} //namespace", "} // Namespace DetourModKit"])
    expect(fixture, 3)


def test_non_namespace_closer_is_ignored() -> None:
    expect("} // end of the retry loop", 0)


def test_multiple_violations_are_all_reported() -> None:
    fixture = "\n".join(
        [
            "#define lowerName 1",
            "int x = 0; // plain -- ascii",
            "} // namespace ok::name",
            "// stray " + chr(0x2014) + " dash",
            "} // closes namespace wrongly",
        ]
    )
    expect(fixture, 3)


def test_clean_snippet_has_no_violations() -> None:
    fixture = "\n".join(
        [
            "#define DETOURMODKIT_EXAMPLE_HPP",
            "namespace DetourModKit",
            "{",
            "    namespace",
            "    {",
            "        constexpr int retry_budget = 3; // local snake_case constant",
            "    } // namespace",
            "} // namespace DetourModKit",
        ]
    )
    expect(fixture, 0)


def test_wheel_partition_accepts_the_settled_vocabulary() -> None:
    fixture = "\n".join(
        [
            "#define DETOURMODKIT_WHEEL_HOST_H",
            "#define DMK_WHEELHOST_CALL __stdcall",
            "#define DMK_WHEELHOST_ABI_VERSION 2u",
            "#define DMK_WHEELHOST_ERR_ABI (-1)",
            "#define DMK_WHEEL_UP 0",
            "#define DMK_WHEEL_DIRECTIONS 4",
            "#define DMK_WHEEL_CONSUME_UP (1u << DMK_WHEEL_UP)",
            "#define DMK_WHEEL_CAPTURE_ENABLED 1u",
        ]
    )
    expect_wheel(fixture, 0)


def test_wheel_partition_rejects_a_mechanic_on_the_data_stem() -> None:
    # A status or mechanic macro on DMK_WHEEL_ violates the partition.
    expect_wheel("#define DMK_WHEEL_ERR_BUSY (-3)", 1)


def test_wheel_partition_rejects_a_foreign_stem() -> None:
    expect_wheel("#define DMK_HOST_STATUS_OK 0", 1)


def test_wheel_partition_is_scoped_to_the_wheel_host_header() -> None:
    # The same define in any other file answers only to the generic UPPER_SNAKE_CASE rule.
    expect("#define DMK_WHEEL_ERR_BUSY (-3)", 0)


def test_tracked_sources_requests_c_sources() -> None:
    original = MODULE.subprocess.check_output
    arguments = []

    def fake_check_output(command, text):
        arguments.append(command)
        return "probe.c\n"

    MODULE.subprocess.check_output = fake_check_output
    try:
        paths = MODULE.tracked_sources()
    finally:
        MODULE.subprocess.check_output = original

    if paths != ["probe.c"] or "*.c" not in arguments[0]:
        raise AssertionError(f"C sources are absent from the tracked path set: {arguments}")


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"mechanical-style checker self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
