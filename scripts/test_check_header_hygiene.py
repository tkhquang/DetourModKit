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
WINDOWS_INCLUDE = _module.WINDOWS_INCLUDE
UNPARENTHESIZED_LIMITS = _module.UNPARENTHESIZED_LIMITS
ASYNC_INTERNAL_HEADER = _module.ASYNC_INTERNAL_HEADER
string_pool_destructor_violations = _module.string_pool_destructor_violations
unguarded_libc_memory_calls = _module.unguarded_libc_memory_calls
installed_test_macro_violations = _module.installed_test_macro_violations


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


def test_windows_include_rule_recognizes_both_include_spellings():
    _expect(WINDOWS_INCLUDE.search("#include <windows.h>"), "angle-bracket windows.h include was not recognized")
    _expect(WINDOWS_INCLUDE.search('#include "Windows.h"'), "quoted Windows.h include was not recognized")
    _expect(WINDOWS_INCLUDE.search("#include <WINDOWS.H>"), "uppercase windows.h include was not recognized")
    _expect(not WINDOWS_INCLUDE.search("#include <windows.hpp>"), "a different header was misidentified as windows.h")


def test_numeric_limits_rule_requires_macro_safe_parentheses():
    unparenthesized = "auto value = std::numeric_limits<std::size_t>::max();"
    argument_position = "return static_cast<int>(std::numeric_limits<int>::max());"
    parenthesized = "auto value = (std::numeric_limits<std::size_t>::max)();"
    parenthesized_argument = "f((std::numeric_limits<int>::max)());"
    _expect(UNPARENTHESIZED_LIMITS.search(unparenthesized), "macro-fragile numeric_limits call was not recognized")
    _expect(UNPARENTHESIZED_LIMITS.search(argument_position),
            "argument-position macro-fragile numeric_limits call was not recognized")
    _expect(not UNPARENTHESIZED_LIMITS.search(parenthesized), "macro-safe numeric_limits call was rejected")
    _expect(not UNPARENTHESIZED_LIMITS.search(parenthesized_argument),
            "macro-safe numeric_limits call in argument position was rejected")


def test_string_pool_destructor_rule_accepts_only_the_deleted_sentinel():
    source = "class StringPool { ~StringPool() = delete; };\n"
    _expect(string_pool_destructor_violations(ASYNC_INTERNAL_HEADER, source) == [],
            "canonical deleted StringPool destructor sentinel was rejected")


def test_string_pool_destructor_rule_rejects_a_missing_sentinel():
    violations = string_pool_destructor_violations(ASYNC_INTERNAL_HEADER, "class StringPool {};\n")
    _expect(len(violations) == 1 and "exactly one" in violations[0][1],
            "missing StringPool destructor sentinel was not rejected")


def test_string_pool_destructor_rule_rejects_teardown_declarations_and_definitions():
    declaration = "class StringPool { ~StringPool() noexcept; };\n"
    definition = "StringPool::~StringPool() noexcept {}\n"
    declared = string_pool_destructor_violations(ASYNC_INTERNAL_HEADER, declaration)
    defined = string_pool_destructor_violations("src/internal/async_logger.cpp", definition)
    _expect(len(declared) == 1 and "'= delete'" in declared[0][1],
            "StringPool destructor declaration was not rejected")
    _expect(len(defined) == 1 and "forbidden outside" in defined[0][1],
            "StringPool destructor definition was not rejected")


def test_string_pool_destructor_rule_rejects_the_void_parameter_spelling():
    # `(void)` and `()` declare the same empty parameter list, so a teardown spelled either way must be rejected.
    # An out-of-line definition is the arm that matters: a pattern anchored on `()` alone reports this file clean.
    definition = string_pool_destructor_violations("src/internal/async_logger.cpp",
                                                   "StringPool::~StringPool(void) noexcept {}\n")
    beside_sentinel = string_pool_destructor_violations(
        ASYNC_INTERNAL_HEADER,
        "class StringPool { ~StringPool() = delete; };\nStringPool::~StringPool(void) {}\n")
    _expect(len(definition) == 1 and "forbidden outside" in definition[0][1],
            "StringPool destructor defined with a (void) parameter list was not rejected")
    _expect(beside_sentinel == [(2, "StringPool must declare exactly one deleted destructor sentinel")],
            "a (void) StringPool destructor beside the sentinel was not rejected at its own line")


def test_string_pool_destructor_rule_accepts_the_void_spelled_sentinel():
    source = "class StringPool { ~StringPool(void) = delete; };\n"
    _expect(string_pool_destructor_violations(ASYNC_INTERNAL_HEADER, source) == [],
            "the deleted StringPool sentinel spelled with (void) was rejected")


def test_string_pool_destructor_rule_rejects_an_inline_body():
    source = "class StringPool { ~StringPool() {} };\n"
    violations = string_pool_destructor_violations(ASYNC_INTERNAL_HEADER, source)
    _expect(len(violations) == 1 and "'= delete'" in violations[0][1],
            "inline StringPool destructor body was not rejected")


def test_string_pool_destructor_rule_rejects_a_second_declaration_beside_the_sentinel():
    # The sentinel itself is well formed, so only the duplicate arm can reject this. Reporting exactly one violation,
    # anchored at the second occurrence, also pins that the '= delete' check inspects the first match and not the last.
    source = "class StringPool { ~StringPool() = delete; };\nvoid f(StringPool *p) { p->~StringPool(); }\n"
    violations = string_pool_destructor_violations(ASYNC_INTERNAL_HEADER, source)
    _expect(violations == [(2, "StringPool must declare exactly one deleted destructor sentinel")],
            "a second StringPool destructor beside the sentinel was not rejected at its own line")


def test_string_pool_destructor_rule_ignores_documentation():
    source = "// ~StringPool() is forbidden in prose\nclass StringPool { ~StringPool() = delete; };\n"
    _expect(string_pool_destructor_violations(ASYNC_INTERNAL_HEADER, source) == [],
            "StringPool destructor rule inspected a comment instead of code")


def test_scanner_libc_copy_outside_an_asan_branch_is_flagged():
    # The shape the rule exists to catch: a bare libc copy of swept memory, which ASan's hot-patched interceptor
    # inspects against poisoned shadow no attribute on the caller can suppress.
    source = "void f()\n{\n    std::memcpy(out, in, n);\n}\n"
    _expect(unguarded_libc_memory_calls(source) == [3], "a bare libc copy on the scanner path was not flagged")


def test_scanner_libc_copy_inside_an_asan_branch_is_allowed():
    source = ("#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)\n"
              "    __movsb(out, in, n);\n"
              "#else\n"
              "    std::memcpy(out, in, n);\n"
              "#endif\n")
    _expect(unguarded_libc_memory_calls(source) == [], "the ASan-guarded fallback copy was rejected")


def test_scanner_libc_copy_after_the_asan_chain_closes_is_flagged():
    # The chain must not arm the rest of the file: a second copy added below the branch is unguarded again.
    source = ("#if defined(__SANITIZE_ADDRESS__)\n"
              "    __movsb(out, in, n);\n"
              "#else\n"
              "    std::memcpy(out, in, n);\n"
              "#endif\n"
              "    std::memcmp(other, in, n);\n")
    _expect(unguarded_libc_memory_calls(source) == [6], "a libc call after the guarded chain closed was not flagged")


def test_scanner_libc_copy_inside_the_asan_arm_itself_is_flagged():
    # The arm taken when ASan is ON is the one that must not reach libc, so this is the defect rather than a fallback.
    # Chain-level tracking would accept it, which is why the arm in effect is what decides.
    source = ("#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)\n"
              "    std::memcpy(out, in, n);\n"
              "#else\n"
              "    std::memcpy(out, in, n);\n"
              "#endif\n")
    _expect(unguarded_libc_memory_calls(source) == [2], "a libc copy in the ASan-ON arm was not flagged")


def test_scanner_gate_flags_a_conditional_nested_inside_the_asan_arm():
    # Nesting an unrelated conditional inside the ASan-ON arm does not leave it: the call still runs under ASan.
    source = ("#if defined(__SANITIZE_ADDRESS__)\n"
              "#if defined(_MSC_VER)\n"
              "    std::memcpy(out, in, n);\n"
              "#endif\n"
              "#endif\n")
    _expect(unguarded_libc_memory_calls(source) == [3], "a call nested inside the ASan-ON arm was not flagged")


def test_scanner_gate_accepts_a_conditional_nested_inside_the_fallback_arm():
    source = ("#if defined(__SANITIZE_ADDRESS__)\n"
              "    __movsb(out, in, n);\n"
              "#else\n"
              "#if defined(_MSC_VER)\n"
              "    std::memcpy(out, in, n);\n"
              "#endif\n"
              "#endif\n")
    _expect(unguarded_libc_memory_calls(source) == [], "a call nested inside the ASan-OFF arm was rejected")


def test_scanner_gate_reads_a_negated_mention_as_the_fallback_arm():
    # #ifndef and !defined put the ASan-OFF side first, so the libc call belongs in the opening arm and the #else is
    # the side that must stay non-interceptable.
    negated_if = ("#if !defined(__SANITIZE_ADDRESS__)\n"
                  "    std::memcpy(out, in, n);\n"
                  "#else\n"
                  "    __movsb(out, in, n);\n"
                  "#endif\n")
    _expect(unguarded_libc_memory_calls(negated_if) == [], "a copy under !defined(ASan) was rejected")
    ifndef_form = ("#ifndef __SANITIZE_ADDRESS__\n"
                   "    std::memcpy(out, in, n);\n"
                   "#else\n"
                   "    std::memcpy(out, in, n);\n"
                   "#endif\n")
    _expect(unguarded_libc_memory_calls(ifndef_form) == [4], "#ifndef did not hand the ASan-ON side to the #else")


def test_scanner_gate_does_not_match_the_engines_own_memchr():
    # dmk_memchr is the self-provided search the engine routes the prefilter through precisely to avoid libc; the
    # rule must not read it as the thing it bans.
    source = "    const unsigned char *p = dmk_memchr(hay, needle, n);\n"
    _expect(unguarded_libc_memory_calls(source) == [], "the engine's self-provided memchr was misread as libc")


def test_token_stability_rule_flags_a_macro_gated_class_member():
    # The defect shape the rule exists for: a member of an installed class definition that exists only when a private
    # test macro is defined, so translation units with and without the macro disagree on the class tokens.
    source = strip_comments(
        "class Input\n{\n#ifdef DMK_ENABLE_TEST_SEAMS\n    static void probe_for_test() noexcept;\n#endif\n};\n")
    _expect(installed_test_macro_violations(source) == [(3, "DMK_ENABLE_TEST_SEAMS")],
            "a DMK_ENABLE_TEST_SEAMS-gated class member was not flagged")


def test_token_stability_rule_flags_the_compound_dispatcher_shape():
    # Both macros in one condition report the first mention. A second gated line reports again.
    source = strip_comments(
        "#if defined(DMK_EVENT_DISPATCHER_INTERNAL_TESTING) && defined(DMK_ENABLE_TEST_SEAMS)\n"
        "long debug_snapshot_use_count() const noexcept;\n"
        "#endif\n")
    violations = installed_test_macro_violations(source)
    _expect(violations == [(1, "DMK_EVENT_DISPATCHER_INTERNAL_TESTING")],
            "the compound two-macro conditional was not flagged at its condition line")


def test_token_stability_rule_accepts_a_macro_free_definition_as_identical_on_and_off():
    # The fixed shape: an unconditional friend keeps the definition's token stream identical with the macro defined
    # and undefined, so the rule stays silent.
    source = strip_comments(
        "class Input\n{\nprivate:\n    friend struct detail::InputTestSeams;\n};\n")
    _expect(installed_test_macro_violations(source) == [],
            "a token-stable installed definition was wrongly flagged")


def test_token_stability_rule_ignores_comment_mentions():
    # The scan runs on stripped text, so prose that names the macro (a doc pointer, a rationale) is not dependence.
    source = strip_comments("// Compiled only when DMK_ENABLE_TEST_SEAMS is defined.\nclass Logger\n{\n};\n")
    _expect(installed_test_macro_violations(source) == [],
            "a comment mention of the private test macro was misread as macro dependence")


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"check_header_hygiene stripper self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
