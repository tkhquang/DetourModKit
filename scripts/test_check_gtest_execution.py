#!/usr/bin/env python3
"""Self-test for check_gtest_execution.py.

The checker exists because a skipped case and a proved case look identical in a
pass/fail count. A checker that accepted a skip, an absent case, or a green case
with no marker would reproduce exactly that blindness one layer up, so every
case below feeds it one of those shapes and expects a refusal that names it.

Run standalone; exits 0 when every shape behaves.
"""
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_gtest_execution as checker

# A subprocess that never returns would hang the whole ctest run rather than fail it.
CLI_TIMEOUT_SECONDS = 120

CASE = "MemoryTest.ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent"
MARKER = "dmk_same_base_replacement"
VALUE = "executed"

# The shape GoogleTest 1.17 actually writes: the property is a <properties> child of <testcase>, not an attribute.
PROPERTIES = (
    "      <properties>\n"
    '        <property name="{marker}" value="{value}"/>\n'
    "      </properties>\n"
).format(marker=MARKER, value=VALUE)

SELECTED = (
    '    <testcase name="ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent" status="run"'
    ' result="completed" time="0.014" classname="MemoryTest">\n'
    "{properties}"
    "    </testcase>\n"
).format(properties=PROPERTIES)

EXECUTED = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<testsuites tests="2" failures="0" name="AllTests">\n'
    '  <testsuite name="MemoryTest" tests="2" failures="0">\n'
    '    <testcase name="ModuleRangeFor_RepeatedLookupIsConsistent" status="run" result="completed"'
    ' time="0.001" classname="MemoryTest" />\n'
    "{selected}"
    "  </testsuite>\n"
    "</testsuites>\n"
).format(selected=SELECTED)

MARKER_LESS = SELECTED.replace(PROPERTIES, "")


class EvidenceRefusals(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="dmk_gtest_evidence_")
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)

    def write(self, name, text):
        path = os.path.join(self.directory, name)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        return path

    def run_checker(self, path, *extra):
        """Return (exit status, printed output) for one checker run."""
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            verdict = checker.main(
                [path, "--case", CASE, "--property", "{0}={1}".format(MARKER, VALUE), *extra]
            )
        return verdict, buffer.getvalue()

    def refuses(self, text, expected, *extra):
        """Assert the checker refuses the report AND names the expected problem."""
        path = self.write("report.xml", text)
        verdict, output = self.run_checker(path, *extra)
        self.assertEqual(verdict, 1, "expected a refusal, got acceptance:\n{0}".format(output))
        self.assertIn(expected, output, "refused, but not for the expected reason:\n{0}".format(output))

    def test_an_executed_marked_case_is_accepted(self):
        path = self.write("report.xml", EXECUTED)
        verdict, output = self.run_checker(path)
        self.assertEqual(verdict, 0, output)

    def test_a_missing_report_is_refused(self):
        verdict, output = self.run_checker(os.path.join(self.directory, "absent.xml"))
        self.assertEqual(verdict, 1)
        self.assertIn("report is missing", output)

    def test_a_malformed_report_is_refused(self):
        self.refuses(EXECUTED.replace("</testsuites>", ""), "not parsable XML")

    def test_an_absent_case_is_refused(self):
        self.refuses(EXECUTED.replace(SELECTED, ""), "is absent from the report")

    def test_a_duplicated_case_is_refused(self):
        self.refuses(EXECUTED.replace(SELECTED, SELECTED + SELECTED), "appears 2 times")

    def test_a_skipped_case_is_refused(self):
        self.refuses(
            EXECUTED.replace(
                SELECTED,
                '    <testcase name="ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent"'
                ' status="run" result="skipped" classname="MemoryTest">\n'
                '      <skipped message="variant B did not claim variant A\'s base" />\n'
                "    </testcase>\n",
            ),
            "was skipped, so this host proved nothing",
        )

    def test_a_not_run_case_is_refused(self):
        self.refuses(EXECUTED.replace('status="run" result="completed" time="0.014"', 'status="notrun"'), "never executed")

    def test_a_suppressed_case_is_refused(self):
        self.refuses(EXECUTED.replace('result="completed" time="0.014"', 'result="suppressed"'), "did not run to completion")

    def test_a_failed_case_is_refused(self):
        self.refuses(
            EXECUTED.replace(
                SELECTED,
                SELECTED.replace(
                    "    </testcase>\n", '      <failure message="Expected equality" type="" />\n    </testcase>\n'
                ),
            ),
            "records a failure",
        )

    def test_a_case_stating_neither_status_nor_result_is_refused(self):
        # A report that never says the case ran is not evidence that it did, however complete it otherwise looks.
        self.refuses(
            EXECUTED.replace(' status="run" result="completed" time="0.014" classname="MemoryTest">', ' classname="MemoryTest">'),
            "records neither a status nor a result",
        )

    def test_a_recorded_failure_is_never_laundered_as_a_skip(self):
        # `--skip-exit-code` may only excuse a host that could not run the case; a recorded outcome says it ran.
        failing_skip = SELECTED.replace(
            ' status="run" result="completed" time="0.014"', ' status="run" result="skipped"'
        ).replace("    </testcase>\n", '      <failure message="Expected equality" type="" />\n    </testcase>\n')
        for extra in ([], ["--skip-exit-code", "77"]):
            with self.subTest(skip_code=bool(extra)):
                self.refuses(EXECUTED.replace(SELECTED, failing_skip), "did not run to completion", *extra)

    def test_a_marker_less_case_is_refused(self):
        # The case ran and reported green, but took an exit before the observation that publishes the marker.
        self.refuses(EXECUTED.replace(SELECTED, MARKER_LESS), "published no '{0}' property".format(MARKER))

    def test_a_wrong_property_value_is_refused(self):
        self.refuses(EXECUTED.replace('value="{0}"'.format(VALUE), 'value="skipped"'), "expected 'executed'")

    def test_a_property_written_as_a_testcase_attribute_is_read(self):
        # Older GoogleTest writers put test properties on the testcase element itself.
        attribute_form = MARKER_LESS.replace(
            'classname="MemoryTest">\n    </testcase>\n',
            'classname="MemoryTest" {0}="{1}" />\n'.format(MARKER, VALUE),
        )
        path = self.write("attribute.xml", EXECUTED.replace(SELECTED, attribute_form))
        verdict, output = self.run_checker(path)
        self.assertEqual(verdict, 0, output)

    def test_a_wrong_case_cannot_stand_in(self):
        # Same suite, neighbouring case, and a case whose name differs only in letter case.
        self.refuses(EXECUTED.replace(SELECTED, ""), "is absent from the report")
        self.refuses(
            EXECUTED.replace(
                "ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent",
                "modulerangefor_completedsamebasereplacementreportsthereplacementextent",
            ),
            "is absent from the report",
        )

    def test_a_foreign_suite_carrying_the_same_case_name_is_refused(self):
        self.refuses(EXECUTED.replace('classname="MemoryTest"', 'classname="ForeignTest"'), "is absent from the report")

    def test_a_skip_reports_the_skip_code_only_where_it_is_offered(self):
        skipped = EXECUTED.replace(
            SELECTED,
            '    <testcase name="ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent"'
            ' status="run" result="skipped" classname="MemoryTest" />\n',
        )
        path = self.write("skipped.xml", skipped)
        self.assertEqual(self.run_checker(path)[0], 1)
        self.assertEqual(self.run_checker(path, "--skip-exit-code", "77")[0], 77)

    def test_the_skip_code_does_not_absolve_a_real_failure(self):
        # A skip is a host limit; a failure or an absent marker is not, so --skip-exit-code must not launder either.
        for label, text in (
            ("marker-less", EXECUTED.replace(SELECTED, MARKER_LESS)),
            ("absent", EXECUTED.replace(SELECTED, "")),
        ):
            with self.subTest(label=label):
                path = self.write(label + ".xml", text)
                self.assertEqual(self.run_checker(path, "--skip-exit-code", "77")[0], 1)

    def test_actual_cli_propagates_success_and_refusal_exit_codes(self):
        clean = self.write("clean.xml", EXECUTED)
        marker_less = self.write("marker-less.xml", EXECUTED.replace(SELECTED, MARKER_LESS))
        command = ["--case", CASE, "--property", "{0}={1}".format(MARKER, VALUE)]
        self.assertEqual(
            subprocess.run(
                [sys.executable, checker.__file__, clean, *command],
                capture_output=True,
                timeout=CLI_TIMEOUT_SECONDS,
            ).returncode,
            0,
        )
        self.assertEqual(
            subprocess.run(
                [sys.executable, checker.__file__, marker_less, *command],
                capture_output=True,
                timeout=CLI_TIMEOUT_SECONDS,
            ).returncode,
            1,
        )
        self.assertEqual(
            subprocess.run(
                [
                    sys.executable,
                    checker.__file__,
                    self.write("cli-skipped.xml", EXECUTED.replace('result="completed"', 'result="skipped"')),
                    *command,
                    "--skip-exit-code",
                    "77",
                ],
                capture_output=True,
                timeout=CLI_TIMEOUT_SECONDS,
            ).returncode,
            77,
        )

    def test_a_malformed_requirement_is_rejected_at_the_command_line(self):
        clean = self.write("clean.xml", EXECUTED)
        for command in (
            [clean, "--case", "NoSuiteSeparator", "--property", "{0}={1}".format(MARKER, VALUE)],
            [clean, "--case", CASE, "--property", "no_equals_sign"],
            [clean, "--case", CASE],
        ):
            with self.subTest(command=command[1:]):
                with self.assertRaises(SystemExit) as caught:
                    with contextlib.redirect_stderr(io.StringIO()):
                        checker.main(command)
                self.assertNotEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
