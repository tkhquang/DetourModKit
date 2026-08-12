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

# Every step whose skipping would let the run stay green while the thing it proves never happened. Named individually
# rather than derived from the workflow, so deleting a step from the workflow fails this list instead of shrinking the
# mutation matrix with it. Steps that legitimately carry a reviewed condition are covered by the retarget case instead:
# gating them again would collide on a duplicate step key and refuse for an unrelated reason.
LOAD_BEARING_STEPS = tuple(
    (checker.RELEASE, step)
    for step in (
        "Assert the dispatch resolved to the exact candidate",
        "Compare release input against project(VERSION) in CMakeLists.txt",
        "Assert the dispatch ref may publish a tag",
        "Create or verify annotated tag",
        "Run dump-capturing lifecycle soak (MinGW Release)",
        "Run dump-capturing lifecycle soak (MSVC Release)",
        "Assert the same-base replacement case executed (MinGW Release)",
        "Assert the same-base replacement case executed (MSVC Release)",
        "Run DetourModKit Tests (MinGW Release)",
        "Run DetourModKit Tests (MSVC Release)",
        "Assert Export Equality (MinGW)",
        "Assert Export Equality (MSVC)",
        "Assert Install-Prefix Hygiene (MinGW)",
        "Assert Install-Prefix Hygiene (MSVC)",
        "Assert No Test Seams (MinGW)",
        "Assert No Test Seams (MSVC)",
        "Assert Emit Path Has No Emulated TLS (MinGW)",
        "Smoke Test Installed Package (MinGW)",
        "Smoke Test Installed Package (MSVC)",
        "Build-Tree Consumer Proof (MinGW)",
        "Build-Tree Consumer Proof (MSVC)",
        "Dual-Config Package Matrix (MinGW)",
        "Dual-Config Package Matrix (MSVC)",
        "Run the benchmarks",
        "Check the recorded evidence",
    )
) + tuple(
    (checker.QUALITY, step)
    for step in (
        "Check formatting (dry run, project sources only)",
        "Check header-encapsulation hygiene",
        "Check mechanical naming/namespace/dash rules",
        "Self-test the backend-patch checker",
        "Analyse library sources (warnings are errors)",
    )
)

# One nonliteral successful fallback per critical command. None of these spells `true`: a checker that recognized only
# the literal would accept every one of them while the command's failure reached nothing.
CRITICAL_COMMAND_FALLBACKS = (
    ('              --dump-directory "$RUNNER_TEMP/dmk-lifecycle-dumps-mingw"', "|| echo ignored"),
    ('              --dump-directory "$RUNNER_TEMP/dmk-lifecycle-dumps-msvc"', "|| printf skipped"),
    ('          python scripts/check_install_prefix.py "${{ github.workspace }}/install_package/mingw"', "|| :"),
    ('          python scripts/check_emit_tls.py "$archive" "$backend"', "|| echo tolerated"),
    ('          python scripts/check_no_test_seams.py "$archive"', "|| cat /dev/null"),
    ("          ctest --test-dir build/package-build-tree-mingw --output-on-failure", "|| echo ignored"),
    ("            --require dispatcher.reentrant_subscribe_rejected", "|| echo ignored"),
)


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

    def gate_step(self, relative, step_name, condition="${{ false }}"):
        """Put a step-level condition on one named step, so it is present but never runs."""
        self.mutate(
            relative,
            "      - name: {0}\n".format(step_name),
            "      - name: {0}\n        if: {1}\n".format(step_name, condition),
        )

    def step_span(self, relative, job, step_name):
        """Return (text, job start, job end, offset of the step's name line within the job body).

        Scoped to the job because a step name is unique only inside one: `Install MinGW (if not cached)` exists in two
        release jobs, and a first-match mutation would silently test the wrong one.
        """
        text, start, end = self.job_span(relative, job)
        body = text[start:end]
        anchor = "      - name: {0}\n".format(step_name)
        assert anchor in body, "step '{0}' not found in job '{1}' of {2}".format(step_name, job, relative)
        return text, start, end, body.index(anchor)

    def retarget_step_condition(self, relative, job, step_name, reviewed, replacement="${{ false }}"):
        """Replace one named step's reviewed condition with another, without touching a like-conditioned neighbour."""
        text, start, end, position = self.step_span(relative, job, step_name)
        body = text[start:end]
        original = "        if: {0}\n".format(reviewed)
        assert original in body[position:], "step '{0}' does not carry '{1}'".format(step_name, reviewed)
        offset = position + body[position:].index(original)
        mutated = body[:offset] + "        if: {0}\n".format(replacement) + body[offset + len(original) :]
        self.write(relative, text[:start] + mutated + text[end:])

    def step_carries_condition(self, relative, job, step_name, reviewed):
        """Whether the named step in the named job is the one carrying `reviewed`."""
        text, start, end, position = self.step_span(relative, job, step_name)
        body = text[start:end]
        following = body.index("      - name: ", position + 1) if "      - name: " in body[position + 1 :] else len(body)
        return "        if: {0}\n".format(reviewed) in body[position:following]

    def append_fallback(self, relative, command, fallback):
        """Append a successful fallback to one command, so its failure is normalized to green."""
        self.mutate(relative, command, command + " " + fallback)

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

    def test_every_required_release_job_refuses_an_early_success(self):
        # The tag-step exemption is scoped to one reviewed step name, not to the whole job, so create-release belongs
        # here too: an early success in any OTHER step of it is refused exactly as it is in the four gate-running jobs.
        for job in checker.REQUIRED_RELEASE_JOBS:
            with self.subTest(job=job):
                self.setUp()
                self.workspace.skip_the_job(checker.RELEASE, job)
                self.refuses("job '{0}' has a bare 'exit 0' skip".format(job))

    def test_a_step_level_advisory_marker_names_the_step_it_is_on(self):
        # The job-level and step-level refusals are different defects, so they may not read identically: a reader who
        # cannot tell which one fired has to re-derive it from the workflow.
        self.workspace.add_step(
            checker.RELEASE,
            "build-mingw",
            "      - name: Advisory probe\n        run: echo probe\n        shell: bash\n        continue-on-error: true\n",
        )
        self.refuses("step 'Advisory probe' in job 'build-mingw' carries a continue-on-error marker")

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

    def test_every_load_bearing_step_refuses_a_false_condition(self):
        # A step that does not run cannot fail. Each of these is the sole proof of what it names, so a false condition
        # on any one of them skips a refusal or a gate while the job, and the credentialed publish after it, stay green.
        for relative, step in LOAD_BEARING_STEPS:
            with self.subTest(step=step):
                self.setUp()
                self.workspace.gate_step(relative, step)
                self.refuses("step '{0}'".format(step))
                self.refuses("never runs the guard it reports green for")

    def test_every_reviewed_step_condition_refuses_being_retargeted(self):
        # The reviewed conditions strengthen their steps rather than skip them. Accepting the KEY rather than the exact
        # VALUE would let a reviewed step keep its name and take a false condition instead.
        for (relative, job, step), reviewed in checker.REVIEWED_STEP_CONDITIONS.items():
            with self.subTest(step=step):
                self.setUp()
                self.workspace.retarget_step_condition(relative, job, step, reviewed)
                self.refuses("step '{0}' in job '{1}' is gated on '${{{{ false }}}}'".format(step, job))

    def test_reviewed_step_conditions_all_describe_a_step_that_exists(self):
        # The table is an allowlist, so a stale entry is a standing permission for a step name nobody reviewed to
        # arrive later already carrying a condition.
        for (relative, job, step), reviewed in checker.REVIEWED_STEP_CONDITIONS.items():
            with self.subTest(step=step):
                self.assertTrue(
                    self.workspace.step_carries_condition(relative, job, step, reviewed),
                    "reviewed entry {0} names no step that carries '{1}'".format((relative, job, step), reviewed),
                )

    def test_every_critical_command_refuses_a_nonliteral_successful_fallback(self):
        # `|| true` was never the only way to normalize a failure: any fallback that exits zero does it. These are
        # spelled without the word `true` on purpose, so a checker that pattern-matched the literal fails here.
        for command, fallback in CRITICAL_COMMAND_FALLBACKS:
            with self.subTest(command=command.strip()[:60], fallback=fallback):
                self.setUp()
                self.workspace.append_fallback(checker.RELEASE, command, fallback)
                self.refuses("discards a step's exit status")

    def test_a_detected_failure_that_only_warns_is_refused(self):
        # Both producers verify their install prefix is non-empty. Reporting that with Write-Warning leaves the step
        # green and the job goes on to archive an empty prefix, so the check would exist without deciding anything.
        self.workspace.mutate(
            checker.RELEASE,
            '            Write-Error "Install directory \'${installDir}\' is empty after cmake --install!"\n'
            "            exit 1\n",
            "            Write-Warning \"Install directory '${installDir}' is empty!\"\n",
        )
        self.refuses("contains fail-open shell construct 'Write-Warning'")

    def test_a_nested_powershell_warning_is_refused(self):
        # Write-Warning remains fail-open when nested in a conditional or subexpression, and an omitted shell on a
        # Windows job still means PowerShell. Looking only at the line's first command or explicit shell misses these.
        for body, shell in (
            ('if ($true) { Write-Warning "empty install" }', "        shell: pwsh\n"),
            ('if ($true) { $(Write-Warning "empty install") }', "        shell: pwsh\n"),
            ('Write-Warning "empty install"', ""),
            ('Microsoft.PowerShell.Utility\\Write-Warning "empty install"', "        shell: pwsh\n"),
            ('. Write-Warning "empty install"', "        shell: pwsh\n"),
            ('. Microsoft.PowerShell.Utility\\Write-Warning "empty install"', "        shell: pwsh\n"),
            ('Write-`Warning "empty install"', "        shell: pwsh\n"),
            ('Microsoft.PowerShell.Utility\\Write-`Warning "empty install"', "        shell: pwsh\n"),
        ):
            with self.subTest(body=body, shell=shell.strip() or "default"):
                self.setUp()
                self.workspace.add_step(
                    checker.RELEASE,
                    "build-mingw",
                    "      - name: Nested warning\n" + "        run: {0}\n".format(body) + shell,
                )
                self.refuses("contains fail-open shell construct 'Write-Warning'")

    def test_a_backtick_split_powershell_warning_is_refused(self):
        # PowerShell's line continuation is a backtick-newline, and it joins without inserting whitespace, so a command
        # name can be split across two physical lines. Reading a PowerShell step with bash's backslash marker leaves
        # `Write-` and `Warning` as separate logical lines and neither matches. build-mingw and build-msvc run on
        # Windows, where an omitted shell is PowerShell too, so the split must be rejected with and without the key.
        for job, shell in (
            ("build-mingw", "        shell: pwsh\n"),
            ("build-msvc", "        shell: powershell\n"),
            ("build-mingw", ""),
        ):
            with self.subTest(job=job, shell=shell.strip() or "omitted"):
                self.setUp()
                self.workspace.add_step(
                    checker.RELEASE,
                    job,
                    "      - name: Split warning\n"
                    "        run: |\n"
                    "          Write-`\n"
                    "          Warning \"empty install\"\n" + shell,
                )
                self.refuses("contains fail-open shell construct 'Write-Warning'")

    def test_a_conditional_head_carve_out_needs_a_bash_step(self):
        # The carve-out reads `[ test ] || [ test ]` under bash status semantics. validate-version runs on Linux, where
        # an omitted shell is bash, so the shape stays accepted there; the same line on a Windows job is PowerShell,
        # where a bracket compound is not a test at all and the `||` must still be refused.
        self.workspace.add_step(
            checker.RELEASE,
            "validate-version",
            "      - name: Linux default shell test compound\n"
            '        run: if [ -n "$GITHUB_SHA" ] || [ 1 = 1 ]; then echo checked; fi\n',
        )
        self.holds()
        self.setUp()
        self.workspace.add_step(
            checker.RELEASE,
            "build-mingw",
            "      - name: Windows default shell test compound\n"
            '        run: if [ -n "$GITHUB_SHA" ] || [ 1 = 1 ]; then echo checked; fi\n',
        )
        self.refuses("discards a step's exit status")

    def test_a_required_command_cannot_hide_before_a_bracket_test(self):
        # The conditional-head carve-out is for `[ test ] || [ test ]`, not for any line whose fallback happens to be
        # a bracket test. In both mutants the required command can fail while the condition and step still succeed.
        for body in (
            "if python -c \"raise SystemExit(1)\" || [ 1 = 1 ]; then echo ignored; fi",
            "if [ 1 = 1 ] && python -c \"raise SystemExit(1)\" || [ 1 = 1 ]; then echo ignored; fi",
            "if [ \"$(python -c 'raise SystemExit(1)')\" = \"\" ] || [ 1 = 1 ]; then echo ignored; fi",
        ):
            with self.subTest(body=body):
                self.setUp()
                self.workspace.add_step(
                    checker.RELEASE,
                    "build-mingw",
                    "      - name: Conditional status swallow\n"
                    + "        run: {0}\n".format(body)
                    + "        shell: bash\n",
                )
                self.refuses("discards a step's exit status")

        # Keep this mutation aligned as a YAML block continuation. Bash removes the backslash-newline without adding
        # whitespace, so it reconstructs `$(false)` even though the source-level `$(` spelling spans two lines.
        self.setUp()
        self.workspace.add_step(
            checker.RELEASE,
            "build-mingw",
            "      - name: Split substitution swallow\n"
            "        run: |\n"
            "          if [ \"$\\\n"
            "          (false)\" = \"\" ] || [ 1 = 1 ]; then echo ignored; fi\n"
            "        shell: bash\n",
        )
        self.refuses("discards a step's exit status")

    def test_both_lifecycle_soaks_are_exact_required_commands(self):
        # The soak is the only route that runs the dump-capturing lifecycle inventory. Redirecting it at another build
        # tree would package a candidate whose lifecycle proofs ran somewhere else, or nowhere.
        for step, original, replacement in (
            (checker.MINGW_SOAK_STEP, '"build/mingw-release"', '"build/mingw-debug"'),
            (checker.MSVC_SOAK_STEP, '"build/msvc-release"', '"build/msvc-debug"'),
        ):
            with self.subTest(step=step):
                self.setUp()
                self.workspace.mutate(checker.RELEASE, original, replacement)
                self.refuses("does not run the exact dump-capturing lifecycle soak")

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

    def test_a_quoted_capture_cannot_normalize_a_failure_with_a_nonliteral_fallback(self):
        # `|| true` is not the only spelling that discards a status: `|| echo ignored` is exactly as green. Inside a
        # QUOTED capture the whole assignment lexes as one shell word, so the `||` token scan never sees the operator
        # and only the capture rule can refuse it. Without this case the rule can be narrowed back to `true`/`:` with
        # every other case still passing, which is how the hole would reopen.
        self.holds()
        self.workspace.mutate(
            checker.RELEASE,
            '          TEST_MAJOR="$(grep -m1 -oP \'DMK_VERSION_MAJOR,\\s*\\K[0-9]+\' tests/test_version.cpp || true)"',
            '          TEST_MAJOR="$(grep -m1 -oP \'DMK_VERSION_MAJOR,\\s*\\K[0-9]+\' tests/test_version.cpp '
            '|| echo ignored)"',
        )
        self.refuses("job 'validate-version' discards a step's exit status")

    def test_a_spaced_yaml_if_key_cannot_hide_a_job_gate(self):
        # Whitespace before the colon is valid YAML. The structural reader must still recognize this as the direct
        # job-level `if` key rather than accepting a release producer that never runs.
        self.workspace.add_job_key(checker.RELEASE, "build-mingw", "    if : ${{ false }}\n")
        self.refuses("job 'build-mingw' is gated on")

    def test_release_proof_steps_are_exact_unconditional_commands(self):
        # Each mutation names the refusal it must provoke. Asserting only the job name would let a mutation pass as
        # coverage by tripping some unrelated problem in the same job.
        exact_check = "job 'build-mingw' does not run the exact same-base execution check"
        discarded = "job 'build-mingw' discards a step's exit status"
        early_success = "job 'build-mingw' has a bare 'exit 0' skip"
        mutations = (
            (
                "disabled step",
                "      - name: Assert the same-base replacement case executed (MinGW Release)\n",
                "      - name: Assert the same-base replacement case executed (MinGW Release)\n"
                "        if: ${{ false }}\n",
                exact_check,
            ),
            (
                "skip escape",
                "              --property dmk_same_base_replacement=executed\n",
                "              --property dmk_same_base_replacement=executed --skip-exit-code 0\n",
                exact_check,
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
                discarded,
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
                early_success,
            ),
            (
                "colon swallow",
                "              --property dmk_same_base_replacement=executed\n",
                "              --property dmk_same_base_replacement=executed || :\n",
                discarded,
            ),
        )
        for label, original, replacement, expected in mutations:
            with self.subTest(mutation=label):
                self.setUp()
                self.workspace.mutate(checker.RELEASE, original, replacement)
                self.refuses(expected)

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
        for replacement in (
            "python scripts/check_comment_style.py || true",
            "! python scripts/check_comment_style.py",
            "if python scripts/check_comment_style.py; then echo checked; fi",
        ):
            with self.subTest(replacement=replacement):
                self.setUp()
                self.workspace.mutate(checker.QUALITY, "python scripts/check_comment_style.py", replacement)
                self.refuses("discards a step's exit status")

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
