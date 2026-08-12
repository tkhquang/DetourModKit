#!/usr/bin/env python3
"""Self-test for check_workflow_topology.py.

A topology checker that never refuses anything is worse than none: it reports
green over exactly the shape it exists to forbid. One positive control checks
the repository; every other case mutates a required route and expects refusal.

Each refusal case asserts the message, not only the exit code. A mutation that
trips some unrelated problem would otherwise pass as coverage for the guard it
was written to remove.

Run standalone; exits 0 when every mutation is caught.
"""
import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_workflow_topology as checker

REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A subprocess that never returns would hang the whole ctest run rather than fail it.
CLI_TIMEOUT_SECONDS = 120


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

    def job_span(self, relative, name):
        """Return (text, body start, body end) for one job block, so a case can replace or empty it wholesale."""
        text = self.read(relative)
        header = "\n  {0}:\n".format(name)
        assert header in text, "job '{0}' not found in {1}".format(name, relative)
        start = text.index(header) + len(header)
        # Only a job header sits at two spaces: a job's own keys are at four and a step's at six or more.
        following = re.compile(r"^  [A-Za-z0-9_-]+:\s*$", re.MULTILINE).search(text, start)
        return text, start, following.start() if following else len(text)

    def add_job_key(self, relative, name, line):
        """Insert a job-level key immediately after the job header."""
        text, start, _ = self.job_span(relative, name)
        self.write(relative, text[:start] + line + text[start:])

    def empty_job(self, relative, name):
        """Replace a job's whole body with a comment, leaving the job present and depended on."""
        text, start, end = self.job_span(relative, name)
        self.write(relative, text[:start] + "    # body removed\n" + text[end:])

    def add_step(self, relative, name, step):
        """Insert a step at the head of one job's step list."""
        text, start, end = self.job_span(relative, name)
        body = text[start:end]
        anchor = "    steps:\n"
        assert anchor in body, "job '{0}' has no step list".format(name)
        position = start + body.index(anchor) + len(anchor)
        self.write(relative, text[:position] + step + text[position:])

    def swallow_a_step(self, relative, name):
        """Add a step to the job whose real exit status is discarded."""
        self.add_step(
            relative,
            name,
            "      - name: Swallowed check\n"
            '        run: python -c "raise SystemExit(1)" || true\n'
            "        shell: bash\n",
        )

    def skip_the_job(self, relative, name):
        """Add a step that returns success before anything after it can run."""
        self.add_step(
            relative,
            name,
            "      - name: Early success\n        run: |\n          exit 0\n        shell: bash\n",
        )

    def verdict(self):
        return checker.main(["--repository-root", self.root])


class TopologyRefusals(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace()
        self.addCleanup(shutil.rmtree, self.workspace.root, ignore_errors=True)

    def run_checker(self):
        """Return (exit status, printed output) for one checker run over the workspace."""
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            verdict = self.workspace.verdict()
        return verdict, buffer.getvalue()

    def refuses(self, expected):
        """Assert the checker refuses AND names the expected problem."""
        verdict, output = self.run_checker()
        self.assertEqual(verdict, 1, "expected a refusal, got acceptance:\n{0}".format(output))
        self.assertIn(expected, output, "refused, but not for the expected reason:\n{0}".format(output))

    def holds(self):
        """Assert the checker accepts the workspace."""
        verdict, output = self.run_checker()
        self.assertEqual(verdict, 0, "expected acceptance, got a refusal:\n{0}".format(output))

    def test_the_repository_topology_holds(self):
        self.holds()

    def test_actual_cli_propagates_success_and_refusal_exit_codes(self):
        self.assertEqual(
            subprocess.run(
                [sys.executable, checker.__file__, "--repository-root", self.workspace.root],
                capture_output=True,
                timeout=CLI_TIMEOUT_SECONDS,
            ).returncode,
            0,
        )
        self.workspace.mutate(checker.RELEASE, "inputs.mode == 'publish'", "inputs.mode != 'publish'")
        self.assertNotEqual(
            subprocess.run(
                [sys.executable, checker.__file__, "--repository-root", self.workspace.root],
                capture_output=True,
                timeout=CLI_TIMEOUT_SECONDS,
            ).returncode,
            0,
        )

    def test_a_missing_workflow_is_refused(self):
        os.remove(os.path.join(self.workspace.root, checker.QUALITY))
        self.refuses("workflow is missing")

    def test_an_advisory_quality_job_is_refused(self):
        self.workspace.mutate(
            checker.QUALITY,
            "  clang-tidy:\n    name: clang-tidy (blocking)\n",
            "  clang-tidy:\n    name: clang-tidy (blocking)\n    continue-on-error: true\n",
        )
        self.refuses("carries a continue-on-error marker")

    # One mutation per required release job, per shape that leaves the job in the graph while it stops deciding
    # anything. A shape covered for four of the five jobs is a shape the fifth can regress through.
    def test_every_required_release_job_refuses_an_advisory_marker(self):
        for job in checker.REQUIRED_RELEASE_JOBS:
            with self.subTest(job=job):
                self.setUp()
                self.workspace.add_job_key(checker.RELEASE, job, "    continue-on-error: true\n")
                self.refuses("job '{0}' carries a continue-on-error marker".format(job))

    def test_every_required_release_job_refuses_an_emptied_body(self):
        for job in checker.REQUIRED_RELEASE_JOBS:
            with self.subTest(job=job):
                self.setUp()
                self.workspace.empty_job(checker.RELEASE, job)
                self.refuses("job '{0}' has no readable body".format(job))

    def test_every_required_release_job_refuses_a_swallowed_exit_status(self):
        for job in checker.REQUIRED_RELEASE_JOBS:
            with self.subTest(job=job):
                self.setUp()
                self.workspace.swallow_a_step(checker.RELEASE, job)
                self.refuses("job '{0}' discards a step's exit status".format(job))

    def test_every_gate_running_release_job_refuses_an_early_success(self):
        # create-release is excluded on purpose: its reviewed body returns success when the annotated tag already
        # resolves to the exact candidate, and the repository positive control keeps that from being refused.
        for job in checker.REQUIRED_RELEASE_JOBS:
            if job == "create-release":
                continue
            with self.subTest(job=job):
                self.setUp()
                self.workspace.skip_the_job(checker.RELEASE, job)
                self.refuses("job '{0}' has a bare 'exit 0' skip".format(job))

    def test_every_required_release_job_refuses_an_unexpected_gate(self):
        for job in checker.REQUIRED_RELEASE_JOBS:
            with self.subTest(job=job):
                self.setUp()
                if job == "create-release":
                    # It already carries the one allowed gate, so the mutation narrows that gate instead of adding one.
                    self.workspace.mutate(
                        checker.RELEASE,
                        "    if: ${{ inputs.mode == 'publish' }}\n",
                        "    if: ${{ inputs.mode == 'publish' && github.actor == 'release-bot' }}\n",
                    )
                else:
                    self.workspace.add_job_key(
                        checker.RELEASE, job, "    if: ${{ github.event_name == 'push' }}\n"
                    )
                self.refuses("job '{0}' is gated on".format(job))

    def test_a_captured_command_substitution_is_not_a_swallowed_exit_status(self):
        # validate-version reads three optional literals this way on purpose: the empty VALUE is what its own guard
        # decides on. Refusing this shape would force the correct construct out of the workflow.
        self.holds()
        self.workspace.mutate(
            checker.RELEASE,
            '          TEST_MAJOR="$(grep -m1 -oP \'DMK_VERSION_MAJOR,\\s*\\K[0-9]+\' tests/test_version.cpp || true)"',
            '          TEST_MAJOR="$(grep -m1 -oP \'DMK_VERSION_MAJOR,\\s*\\K[0-9]+\' tests/test_version.cpp)" || true',
        )
        self.refuses("job 'validate-version' discards a step's exit status")

    def test_a_spaced_yaml_if_key_cannot_hide_a_job_gate(self):
        # Whitespace before the colon is valid YAML. The structural reader must still recognize this as the direct
        # job-level `if` key rather than accepting a release producer that never runs.
        self.workspace.add_job_key(checker.RELEASE, "build-mingw", "    if : ${{ false }}\n")
        self.refuses("job 'build-mingw' is gated on")

    def test_release_proof_steps_are_exact_unconditional_commands(self):
        mutations = (
            (
                "disabled step",
                "      - name: Assert the same-base replacement case executed (MinGW Release)\n",
                "      - name: Assert the same-base replacement case executed (MinGW Release)\n"
                "        if: ${{ false }}\n",
            ),
            (
                "skip escape",
                "              --property dmk_same_base_replacement=executed\n",
                "              --property dmk_same_base_replacement=executed --skip-exit-code 0\n",
            ),
            (
                "unused captured result",
                "          python scripts/check_gtest_execution.py "
                "build/mingw-release/dmk_same_base_replacement.xml \\\n"
                "              --case MemoryTest."
                "ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent \\\n"
                "              --property dmk_same_base_replacement=executed\n",
                "          PROOF=\"$(python scripts/check_gtest_execution.py "
                "build/mingw-release/dmk_same_base_replacement.xml --case "
                "MemoryTest.ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent "
                "--property dmk_same_base_replacement=executed || true)\"\n",
            ),
            (
                "early success",
                "        run: |\n"
                "          python scripts/check_gtest_execution.py "
                "build/mingw-release/dmk_same_base_replacement.xml \\\n",
                "        run: |\n"
                "          exit 0;\n"
                "          python scripts/check_gtest_execution.py "
                "build/mingw-release/dmk_same_base_replacement.xml \\\n",
            ),
            (
                "colon swallow",
                "              --property dmk_same_base_replacement=executed\n",
                "              --property dmk_same_base_replacement=executed || :\n",
            ),
        )
        for label, original, replacement in mutations:
            with self.subTest(mutation=label):
                self.setUp()
                self.workspace.mutate(checker.RELEASE, original, replacement)
                self.refuses("job 'build-mingw'")

    def test_build_tree_proof_requires_configure_build_and_execution(self):
        mutations = (
            (
                "MinGW build and execution",
                "          cmake --build build/package-build-tree-mingw --parallel 4\n"
                "          ctest --test-dir build/package-build-tree-mingw --output-on-failure\n",
                '          echo "build and execution removed"\n',
                "build-mingw",
            ),
            (
                "MSVC execution",
                "          ctest --test-dir build/package-build-tree-msvc --output-on-failure\n",
                '          echo "execution removed"\n',
                "build-msvc",
            ),
            (
                "MSVC status guard",
                "          cmake --build build/package-build-tree-msvc --parallel 2\n"
                "          if errorlevel 1 exit /b 1\n"
                "          ctest --test-dir build/package-build-tree-msvc --output-on-failure\n",
                "          cmake --build build/package-build-tree-msvc --parallel 2\n"
                "          ctest --test-dir build/package-build-tree-msvc --output-on-failure\n",
                "build-msvc",
            ),
        )
        for label, original, replacement, job in mutations:
            with self.subTest(mutation=label):
                self.setUp()
                self.workspace.mutate(checker.RELEASE, original, replacement)
                self.refuses("job '{0}' does not run the build-tree consumer proof".format(job))

    def test_harmless_policy_words_inside_quoted_shell_data_are_accepted(self):
        self.workspace.add_step(
            checker.RELEASE,
            "validate-version",
            "      - name: Harmless policy prose\n"
            '        run: echo "continue-on-error; avoid || true and exit 0"\n'
            "        shell: bash\n",
        )
        self.holds()

    def test_each_producer_must_run_the_build_tree_consumer(self):
        for job, anchor in (
            ("build-mingw", "cmake -S tests/package_build_tree -B build/package-build-tree-mingw"),
            ("build-msvc", "cmake -S tests/package_build_tree -B build/package-build-tree-msvc"),
        ):
            with self.subTest(job=job):
                self.setUp()
                self.workspace.mutate(checker.RELEASE, anchor, "cmake -S tests/package_smoke -B build/removed-proof")
                self.refuses("job '{0}' does not run the build-tree consumer proof".format(job))

    def test_each_producer_must_run_the_same_base_execution_check(self):
        for job, anchor in (
            ("build-mingw", "python scripts/check_gtest_execution.py build/mingw-release"),
            ("build-msvc", "python scripts/check_gtest_execution.py build/msvc-release"),
        ):
            with self.subTest(job=job):
                self.setUp()
                self.workspace.mutate(checker.RELEASE, anchor, "echo skipped # build/removed")
                self.refuses("job '{0}' does not run the exact same-base execution check".format(job))

    def test_a_producer_running_only_the_checkers_self_test_is_refused(self):
        # Running test_check_gtest_execution.py proves the parser works, not that this candidate's case executed.
        self.workspace.mutate(
            checker.RELEASE,
            "python scripts/check_gtest_execution.py build/mingw-release",
            "python scripts/test_check_gtest_execution.py # build/mingw-release",
        )
        self.refuses("job 'build-mingw' does not run the exact same-base execution check")

    def test_a_swallowed_quality_exit_status_is_refused(self):
        self.workspace.mutate(
            checker.QUALITY, "python scripts/check_comment_style.py", "python scripts/check_comment_style.py || true"
        )
        self.refuses("discards a step's exit status with '|| true'")

    def test_a_quality_job_hiding_a_swallowed_status_behind_a_quoted_hash_is_refused(self):
        # A `#` inside a quoted string is data. Cutting the line at the first `#` regardless of quoting would delete
        # the `|| true` that follows it, and this evasion would read as a clean job.
        self.workspace.mutate(
            checker.QUALITY,
            "python scripts/check_comment_style.py",
            'echo "### marker" && python scripts/check_comment_style.py || true',
        )
        self.refuses("discards a step's exit status with '|| true'")

    def test_a_quality_job_with_no_readable_body_is_refused(self):
        text = self.workspace.read(checker.QUALITY)
        head, marker, rest = text.partition("  header-hygiene:\n")
        self.assertTrue(marker, "anchor job not found")
        _, _, tail = rest.partition("\n  mechanical-style:\n")
        self.workspace.write(checker.QUALITY, head + marker + "    # body removed\n  mechanical-style:\n" + tail)
        self.refuses("job 'header-hygiene' has no readable body")

    def test_tidy_without_the_warnings_as_errors_override_is_refused(self):
        self.workspace.mutate(checker.QUALITY, "--warnings-as-errors='*'", "--quiet")
        self.refuses("must pass a command-line --warnings-as-errors override")

    def test_tidy_without_compiler_werror_is_refused(self):
        self.workspace.mutate(checker.QUALITY, "--extra-arg=-Werror", "--extra-arg=-Wno-error")
        self.refuses("clang compiler diagnostics are not promoted with --extra-arg=-Werror")

    def test_tidy_database_with_the_gcc_only_warning_is_refused(self):
        self.workspace.mutate(checker.QUALITY, " -DDMK_HAS_WDANGLING_REFERENCE=OFF", "")
        self.refuses("does not suppress GCC-only -Wdangling-reference")

    def test_a_deleted_quality_job_is_refused(self):
        text = self.workspace.read(checker.QUALITY)
        self.workspace.write(checker.QUALITY, text.replace("  mechanical-style:", "  mechanical_style_renamed:", 1))
        self.refuses("job 'mechanical-style' is missing")

    def test_an_advisory_simd_leg_is_refused(self):
        self.workspace.mutate(
            checker.SIMD,
            "    runs-on: windows-latest\n",
            "    runs-on: windows-latest\n    continue-on-error: true\n",
        )
        self.refuses("a continue-on-error marker makes the tier legs advisory")

    def test_a_skipping_simd_leg_is_refused(self):
        self.workspace.mutate(
            checker.SIMD,
            'throw "Intel SDE not found under SDE_PATH; the ${{ matrix.tier }} tier was never executed"',
            "exit 0",
        )
        self.refuses("an 'exit 0' skip lets a leg pass without running the tier it covers")

    def test_a_fail_open_tier_assertion_is_refused(self):
        self.workspace.mutate(
            checker.SIMD,
            'if (-not $level)\n          {\n              throw "No',
            'if ($false)\n          {\n              throw "No',
        )
        self.refuses("no '-not $level' guard")

    def test_a_release_without_a_mode_input_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "      mode:\n", "      unused_mode:\n")
        self.refuses("no 'mode' dispatch input")

    def test_a_mode_defaulting_to_publish_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "default: preflight", "default: publish")
        self.refuses("must default to preflight")

    def test_a_fake_mode_default_literal_elsewhere_cannot_mask_publish_default(self):
        self.workspace.mutate(checker.RELEASE, "        default: preflight\n", "        default: publish\n")
        self.workspace.mutate(
            checker.RELEASE,
            '        description: "Title for the release',
            '        description: "default: preflight; title for the release',
        )
        self.refuses("must default to preflight")

    def test_an_ungated_create_release_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "    if: ${{ inputs.mode == 'publish' }}\n", "")
        self.refuses("is not gated on the publish mode")

    def test_an_inverted_publish_mode_gate_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "inputs.mode == 'publish'", "inputs.mode != 'publish'")
        self.refuses("is not gated on the publish mode")

    def test_a_create_release_with_no_readable_body_is_refused(self):
        text = self.workspace.read(checker.RELEASE)
        head, marker, _ = text.partition("  create-release:\n")
        self.assertTrue(marker, "anchor job not found")
        self.workspace.write(checker.RELEASE, head + marker + "    # body removed\n")
        self.refuses("job 'create-release' has no readable body")

    def test_publishing_from_a_non_main_ref_is_refused(self):
        self.workspace.mutate(checker.RELEASE, 'RELEASE_REF="refs/heads/main"', 'RELEASE_REF="${DISPATCH_REF}"')
        self.refuses("no longer restricts publishing to refs/heads/main")

    def test_a_disabled_main_ref_guard_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            'if [ "${DISPATCH_REF}" != "${RELEASE_REF}" ]; then',
            "if false; then",
        )
        self.refuses("no longer refuses a non-main dispatch ref")

    def test_a_non_main_guard_that_returns_success_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            '            exit 1\n          fi\n          echo "Dispatch ref check passed."',
            '            exit 0\n          fi\n          echo "Dispatch ref check passed."',
        )
        self.refuses("no longer refuses a non-main dispatch ref")

    def test_dropping_the_exact_candidate_check_is_refused(self):
        text = self.workspace.read(checker.RELEASE)
        head, marker, tail = text.partition("  build-mingw:")
        self.workspace.write(checker.RELEASE, head.replace("expected_sha", "any_sha") + marker + tail)
        self.refuses("validate-version no longer proves the exact candidate SHA")

    def test_a_disabled_exact_candidate_guard_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            'if [ "${EXPECTED_SHA,,}" != "${EVENT_SHA,,}" ] || \\\n'
            '             [ "${EXPECTED_SHA,,}" != "${CHECKED_OUT_SHA,,}" ]; then',
            "if false; then",
        )
        self.refuses("validate-version no longer proves the exact candidate SHA")

    def test_an_exact_candidate_guard_without_a_failing_outcome_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            '            echo "::error::The dispatch ref did not resolve to expected candidate ${EXPECTED_SHA}."\n'
            "            exit 1\n",
            '            echo "candidate mismatch ignored"\n',
        )
        self.refuses("validate-version no longer proves the exact candidate SHA")

    def test_tag_creation_must_target_the_exact_dispatched_sha(self):
        self.workspace.mutate(
            checker.RELEASE,
            '          git tag -a "$VERSION" -m "$TAG_MESSAGE" "${EXPECTED_SHA}"\n',
            '          git tag -a "$VERSION" -m "$TAG_MESSAGE" "HEAD~1"\n',
        )
        self.refuses("no longer tags the exact dispatched candidate SHA")

    def test_a_validate_version_with_no_readable_body_is_refused(self):
        text = self.workspace.read(checker.RELEASE)
        head, marker, rest = text.partition("  validate-version:\n")
        self.assertTrue(marker, "anchor job not found")
        _, _, tail = rest.partition("\n  build-mingw:\n")
        self.workspace.write(checker.RELEASE, head + marker + "    # body removed\n  build-mingw:\n" + tail)
        self.refuses("job 'validate-version' has no readable body")

    def test_a_credential_outside_the_publish_job_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            "      - name: Checkout code\n",
            "      - name: Leak\n        run: echo ${{ secrets.RELEASE_TOKEN }}\n      - name: Checkout code\n",
        )
        self.refuses("only the audited publish job may")

    def test_a_workflow_level_release_credential_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            "  actions: read\n",
            "  actions: read\n\nenv:\n  LEAKED_RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n",
        )
        self.refuses("workflow-level configuration exposes RELEASE_TOKEN outside create-release")

    def test_a_workflow_level_credential_after_jobs_is_refused(self):
        self.workspace.write(
            checker.RELEASE,
            self.workspace.read(checker.RELEASE)
            + "\nenv:\n  LEAKED_RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n",
        )
        self.refuses("workflow-level configuration exposes RELEASE_TOKEN outside create-release")

    def test_bracket_secret_syntax_outside_publish_is_refused(self):
        self.workspace.add_step(
            checker.RELEASE,
            "validate-version",
            "      - name: Leak\n"
            "        run: echo ${{ secrets['RELEASE_TOKEN'] }}\n"
            "        shell: bash\n",
        )
        self.refuses("only the audited publish job may")

    def test_release_credentials_must_remain_on_the_two_reviewed_action_inputs(self):
        self.workspace.mutate(
            checker.RELEASE,
            "          token: ${{ secrets.RELEASE_TOKEN }}\n",
            "          unused: ${{ secrets.RELEASE_TOKEN }}\n",
        )
        self.refuses("exactly the two reviewed RELEASE_TOKEN uses")

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
        self.refuses("does not need validate-version")

    def test_mingw_producer_must_depend_on_candidate_validation(self):
        self.refuse_without_producer_dependency(
            "    timeout-minutes: 120\n    needs: validate-version\n    outputs:\n"
        )

    def test_nested_needs_data_cannot_stand_in_for_the_job_dependency(self):
        self.workspace.mutate(
            checker.RELEASE,
            "    needs: validate-version\n    outputs:\n",
            "    env:\n      needs: validate-version\n    outputs:\n",
        )
        self.refuses("job 'build-mingw' does not need validate-version")

    def test_msvc_producer_must_depend_on_candidate_validation(self):
        self.refuse_without_producer_dependency(
            "    timeout-minutes: 120\n    needs: validate-version\n    outputs:\n", occurrence=2
        )

    def test_benchmark_producer_must_depend_on_candidate_validation(self):
        self.refuse_without_producer_dependency(
            "    needs: validate-version\n    # Deterministic benchmark"
        )

    def test_publishing_without_the_benchmark_evidence_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            "    needs: [build-mingw, build-msvc, benchmark-evidence]",
            "    needs: [build-mingw, build-msvc]",
        )
        self.refuses("does not need 'benchmark-evidence'")

    def test_a_block_sequence_needs_list_is_read_as_the_same_dependencies(self):
        # The inline and block forms are the same YAML. Reading only the inline one would refuse a correct workflow.
        self.workspace.mutate(
            checker.RELEASE,
            "    needs: [build-mingw, build-msvc, benchmark-evidence]\n",
            "    needs:\n      - build-mingw\n      - build-msvc\n      - benchmark-evidence\n",
        )
        self.holds()

    def test_a_block_sequence_needs_list_missing_a_producer_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            "    needs: [build-mingw, build-msvc, benchmark-evidence]\n",
            "    needs:\n      - build-mingw\n      - build-msvc\n",
        )
        self.refuses("does not need 'benchmark-evidence'")

    def test_an_advisory_benchmark_job_is_refused(self):
        self.workspace.mutate(
            checker.RELEASE,
            "  benchmark-evidence:\n    name: Benchmark evidence\n",
            "  benchmark-evidence:\n    name: Benchmark evidence\n    continue-on-error: true\n",
        )
        self.refuses("job 'benchmark-evidence' carries a continue-on-error marker")

    def test_benchmark_route_must_build_the_compiled_ledger_probe(self):
        self.workspace.mutate(
            checker.RELEASE,
            "                     DetourModKit_bench_memory DetourModKit_bench_logger dmk_bench_gate_probe\n",
            "                     DetourModKit_bench_memory DetourModKit_bench_logger\n",
        )
        self.refuses("does not build all four benchmarks and the compiled ledger probe")

    def test_benchmark_route_must_run_the_compiled_ledger_self_test(self):
        self.workspace.mutate(
            checker.RELEASE,
            '          python scripts/test_check_benchmark_results.py --ledger-probe "${LEDGER_PROBE}"\n',
            '          echo "compiled ledger self-test removed"\n',
        )
        self.refuses("does not run the exact capture checker and compiled ledger self-test")

    def test_a_benchmark_job_that_never_checks_its_output_is_refused(self):
        self.workspace.mutate(checker.RELEASE, "python scripts/check_benchmark_results.py", "echo skipped #")
        self.refuses("does not run the result checker")


if __name__ == "__main__":
    unittest.main(verbosity=2)
