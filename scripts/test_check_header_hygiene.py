#!/usr/bin/env python3
"""Regression tests for check_header_hygiene.py's comment stripper.

The legacy-token and backend-confinement gates only inspect real code because strip_comments blanks // and /* */
comments before the token scans run. That contract silently breaks if the stripper mis-tracks a char literal: a C++14
numeric digit separator (1'000'000, 0xFF'FF) is NOT a char-literal delimiter, and an odd number of separators in one
literal must not leave the scanner stuck in char state -- which would pass every following comment through unstripped
and let a legacy spelling that appears only in prose trip the gate. These tests pin that behavior so a later edit to
the stripper cannot reintroduce the desync unnoticed, and confirm the guard does not over-suppress real code.
"""
import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent / "check_header_hygiene.py"
_spec = importlib.util.spec_from_file_location("check_header_hygiene", _SCRIPT)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
strip_comments = _module.strip_comments


def _expect(condition, message):
    if not condition:
        raise AssertionError(message)


def test_odd_count_digit_separator_does_not_desync():
    # Three separators (an odd count) previously left the scanner in char state, so the trailing // comment was
    # never blanked and its legacy token survived into the scanned text.
    stripped = strip_comments("auto x = 1'000'000'000ULL;  // Config:: in prose\n")
    _expect("Config::" not in stripped, "odd-count digit separator desynced the stripper; comment survived")


def test_even_count_digit_separator_still_strips():
    stripped = strip_comments("auto x = 1'000'000ULL;  // Config:: in prose\n")
    _expect("Config::" not in stripped, "even-count digit separator broke comment stripping")


def test_hex_digit_separator_does_not_desync():
    stripped = strip_comments("auto m = 0xFF'FF'FFu;  // Memory:: in prose\n")
    _expect("Memory::" not in stripped, "hex digit separator desynced the stripper; comment survived")


def test_separator_desync_does_not_leak_across_lines():
    # A desync must not leak past the literal's own line: a legacy token in a comment two lines below an odd-count
    # literal must still be stripped.
    src = "auto x = 1'000'000'000ULL;\nint y = 0;\n// safetyhook:: in prose\n"
    stripped = strip_comments(src)
    _expect("safetyhook::" not in stripped, "digit-separator desync leaked into a later comment line")


def test_real_char_literal_still_tracked():
    # A genuine char literal must still open char state so a following comment is stripped. Use a char literal that
    # holds a double quote to prove the stripper does not misread it as the start of a string literal.
    stripped = strip_comments("char q = '\"';  // Memory:: in prose\n")
    _expect("Memory::" not in stripped, "a real char literal broke comment stripping")


def test_legacy_token_in_real_code_is_not_suppressed():
    # The guard must not over-suppress: a legacy spelling in actual code after a separated literal is still visible
    # to the scans (the gate then flags it), so the digit-separator exemption is confined to numeric context.
    stripped = strip_comments("int n = 1'000; auto p = Memory::thing();\n")
    _expect("Memory::" in stripped, "the fix wrongly blanked a legacy token that appears in real code")


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"check_header_hygiene stripper self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
