#!/usr/bin/env python3
"""Self-test for check_workflow_topology.py.

A topology checker that never refuses anything is worse than none: it reports
green over exactly the shape it exists to forbid. One positive control checks
the repository; every other case mutates a required route and expects refusal.

Run standalone; exits 0 when every mutation is caught.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_workflow_topology as checker

REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Workspace:
    """A throwaway copy of .github/workflows that a case may mutate."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="dmk_workflow_topology_")
        destination = os.path.join(self.root, ".github", "workflows")
        shutil.copytree(os.path.join(REPOSITORY, ".github", "workflows"), destination)

    def read(self, relative):
        with open(os.path.join(self.root, relative), encoding="utf-8") as handle:
            return handle.read()

    def write(self, relative, text):
        with open(os.path.join(self.root, relative), "w", encoding="utf-8", newline="") as handle:
            handle.write(text)

    def mutate(self, relative, original, replacement):
        text = self.read(relative)
        assert text.count(original) >= 1, "mutation anchor not found in {0}: {1}".format(relative, original)
        self.write(relative, text.replace(original, replacement, 1))

    def verdict(self):
        return checker.main(["--repository-root", self.root])


class TopologyRefusals(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace()

    def test_the_repository_topology_holds(self):
        self.assertEqual(self.workspace.verdict(), 0)

    def test_actual_cli_propagates_success_and_refusal_exit_codes(self):
        self.assertEqual(
            subprocess.run(
                [sys.executable, checker.__file__, "--repository-root", self.workspace.root], capture_output=True
            ).returncode,
            0,
        )
        self.workspace.mutate(checker.RELEASE, "inputs.mode == 'publish'", "inputs.mode != 'publish'")
        self.assertNotEqual(
            subprocess.run(
                [sys.executable, checker.__file__, "--repository-root", self.workspace.root], capture_output=True
            ).returncode,
            0,
        )

    def test_a_missing_workflow_is_refused(self):
        os.remove(os.path.join(self.workspace.root, checker.QUALITY))
        self.assertEqual(self.workspace.verdict(), 1)

    def test_an_advisory_quality_job_is_refused(self):
        self.workspace.mutate(
            checker.QUALITY,
            "  clang-tidy:\n    name: clang-tidy (blocking)\n",
            "  clang-tidy:\n    name: clang-tidy (blocking)\n    continue-on-error: true\n",
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_swallowed_quality_exit_status_is_refused(self):
        self.workspace.mutate(checker.QUALITY, "python scripts/check_comment_style.py", "python scripts/check_comment_style.py || true")
        self.assertEqual(self.workspace.verdict(), 1)

    def test_tidy_without_the_warnings_as_errors_override_is_refused(self):
        self.workspace.mutate(checker.QUALITY, "--warnings-as-errors='*'", "--quiet")
        self.assertEqual(self.workspace.verdict(), 1)

    def test_tidy_without_compiler_werror_is_refused(self):
        self.workspace.mutate(checker.QUALITY, "--extra-arg=-Werror", "--extra-arg=-Wno-error")
        self.assertEqual(self.workspace.verdict(), 1)

    def test_tidy_database_with_the_gcc_only_warning_is_refused(self):
        self.workspace.mutate(checker.QUALITY, " -DDMK_HAS_WDANGLING_REFERENCE=OFF", "")
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_deleted_quality_job_is_refused(self):
        text = self.workspace.read(checker.QUALITY)
        self.workspace.write(checker.QUALITY, text.replace("  mechanical-style:", "  mechanical_style_renamed:", 1))
        self.assertEqual(self.workspace.verdict(), 1)

    def test_an_advisory_simd_leg_is_refused(self):
        self.workspace.mutate(
            checker.SIMD,
            "    runs-on: windows-latest\n",
            "    runs-on: windows-latest\n    continue-on-error: true\n",
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_skipping_simd_leg_is_refused(self):
        self.workspace.mutate(
            checker.SIMD,
            'throw "Intel SDE not found under SDE_PATH; the ${{ matrix.tier }} tier was never executed"',
            "exit 0",
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_fail_open_tier_assertion_is_refused(self):
        self.workspace.mutate(
            checker.SIMD,
            'if (-not $level)\n          {\n              throw "No',
            'if ($false)\n          {\n              throw "No',
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_release_without_a_mode_input_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "      mode:\n", "      unused_mode:\n")
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_mode_defaulting_to_publish_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "default: preflight", "default: publish")
        self.assertEqual(self.workspace.verdict(), 1)

    def test_an_ungated_create_release_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "    if: ${{ inputs.mode == 'publish' }}\n", "")
        self.assertEqual(self.workspace.verdict(), 1)

    def test_an_inverted_publish_mode_gate_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "inputs.mode == 'publish'", "inputs.mode != 'publish'")
        self.assertEqual(self.workspace.verdict(), 1)

    def test_publishing_from_a_non_main_ref_is_refused(self):
        self.workspace.mutate(checker.RELEASE, 'RELEASE_REF="refs/heads/main"', 'RELEASE_REF="${DISPATCH_REF}"')
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_disabled_main_ref_guard_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            'if [ "${DISPATCH_REF}" != "${RELEASE_REF}" ]; then',
            "if false; then",
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def test_dropping_the_exact_candidate_check_is_refused(self):
        text = self.workspace.read(checker.RELEASE)
        head, marker, tail = text.partition("  build-mingw:")
        self.workspace.write(checker.RELEASE, head.replace("expected_sha", "any_sha") + marker + tail)
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_disabled_exact_candidate_guard_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            'if [ "${EXPECTED_SHA,,}" != "${EVENT_SHA,,}" ] || \\\n             [ "${EXPECTED_SHA,,}" != "${CHECKED_OUT_SHA,,}" ]; then',
            "if false; then",
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_credential_outside_the_publish_job_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            "      - name: Add MinGW to PATH",
            "      - name: Leak\n        run: echo ${{ secrets.RELEASE_TOKEN }}\n      - name: Add MinGW to PATH",
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_workflow_level_release_credential_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            "  actions: read\n",
            "  actions: read\n\nenv:\n  LEAKED_RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n",
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def refuse_without_producer_dependency(self, anchor, occurrence=1):
        text = self.workspace.read(checker.RELEASE)
        position = -1
        start = 0
        for _ in range(occurrence):
            position = text.find(anchor, start)
            self.assertGreaterEqual(position, 0)
            start = position + len(anchor)
        replacement = anchor.replace("    needs: validate-version\n", "")
        self.workspace.write(checker.RELEASE, text[:position] + replacement + text[position + len(anchor) :])
        self.assertEqual(self.workspace.verdict(), 1)

    def test_mingw_producer_must_depend_on_candidate_validation(self):
        self.refuse_without_producer_dependency(
            "    timeout-minutes: 120\n    needs: validate-version\n    outputs:\n"
        )

    def test_msvc_producer_must_depend_on_candidate_validation(self):
        self.refuse_without_producer_dependency(
            "    timeout-minutes: 120\n    needs: validate-version\n    outputs:\n", occurrence=2
        )

    def test_benchmark_producer_must_depend_on_candidate_validation(self):
        self.refuse_without_producer_dependency(
            "    runs-on: windows-latest\n    needs: validate-version\n    # Deterministic benchmark"
        )

    def test_publishing_without_the_benchmark_evidence_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            "    needs: [build-mingw, build-msvc, benchmark-evidence]",
            "    needs: [build-mingw, build-msvc]",
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def test_an_advisory_benchmark_job_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            "  benchmark-evidence:\n    name: Benchmark evidence\n",
            "  benchmark-evidence:\n    name: Benchmark evidence\n    continue-on-error: true\n",
        )
        self.assertEqual(self.workspace.verdict(), 1)

    def test_a_benchmark_job_that_never_checks_its_output_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "python scripts/check_benchmark_results.py", "echo skipped #")
        self.assertEqual(self.workspace.verdict(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
