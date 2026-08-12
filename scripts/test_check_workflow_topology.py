#!/usr/bin/env python3
"""Self-test for check_workflow_topology.py.

A topology checker that never refuses anything is worse than none: it reports green over exactly the
shape it exists to forbid. One positive control checks the repository; every other case mutates a
reviewed route and expects refusal.

Each refusal case asserts the message, not only the exit code. A mutation that trips some unrelated
problem would otherwise pass as coverage for the guard it was written to remove.

The matrix exercises both diagnostic layers. Reviewed load-bearing programs are mutated by
insertion, deletion, reordering and respelling, while the normalized-source identity is challenged
with changes outside the structural reader: action inputs, trigger values, matrices, defaults, and
otherwise-unlisted run bodies. Focused status mutations still require the checker to name the unsafe
construct rather than relying only on the source-identity mismatch.

Run standalone; exits 0 when every mutation is caught.
"""
import contextlib
import hashlib
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
import workflow_contract as contract

REPOSITORY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A subprocess that never returns would hang the whole ctest run rather than fail it.
CLI_TIMEOUT_SECONDS = 120

RELEASE = contract.RELEASE
QUALITY = contract.QUALITY
SIMD = contract.SIMD
PR_CHECK = contract.PR_CHECK
ARCH_GATE = contract.ARCH_GATE
SANITIZERS = contract.SANITIZERS
COVERAGE_PAGES = contract.COVERAGE_PAGES

# Steps whose complete ordered program the contract pins. Named individually rather than derived from the
# contract, so a pin that is quietly dropped fails this list instead of shrinking the matrix with it.
PINNED_STEPS = (
    (RELEASE, "validate-version", contract.IDENTITY_STEP),
    (RELEASE, "create-release", contract.REF_GUARD_STEP),
    (RELEASE, "create-release", contract.TAG_STEP),
    (RELEASE, "build-mingw", "Run dump-capturing lifecycle soak (MinGW Release)"),
    (RELEASE, "build-msvc", "Run dump-capturing lifecycle soak (MSVC Release)"),
    (RELEASE, "build-mingw", "Assert the same-base replacement case executed (MinGW Release)"),
    (RELEASE, "build-msvc", "Assert the same-base replacement case executed (MSVC Release)"),
    (RELEASE, "build-mingw", "Build-Tree Consumer Proof (MinGW)"),
    (RELEASE, "build-msvc", "Build-Tree Consumer Proof (MSVC)"),
    (RELEASE, "benchmark-evidence", "Configure and build the benchmarks (MinGW Release)"),
    (RELEASE, "benchmark-evidence", "Check the recorded evidence"),
    (QUALITY, "workflow-contract", "Check this repository against the canonical workflow contract"),
    (ARCH_GATE, "arch-gate", contract.DISPATCH_IDENTITY_STEP),
    (ARCH_GATE, "arch-gate", "Run x86-64 architecture-gate check"),
    (SANITIZERS, "sanitizers", contract.DISPATCH_IDENTITY_STEP),
    (SIMD, "tier-correctness-sde", contract.DISPATCH_IDENTITY_STEP),
    (COVERAGE_PAGES, "mingw-coverage", contract.DISPATCH_IDENTITY_STEP),
    (PR_CHECK, "msvc-build-test", "Run Tests"),
)

# Every step whose skipping would let a run stay green while the thing it proves never happened.
LOAD_BEARING_STEPS = tuple(
    (RELEASE, step)
    for step in (
        contract.IDENTITY_STEP,
        "Compare release input against project(VERSION) in CMakeLists.txt",
        contract.REF_GUARD_STEP,
        contract.TAG_STEP,
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
    (QUALITY, step)
    for step in (
        "Check formatting (dry run, project sources only)",
        "Check header-encapsulation hygiene",
        "Check mechanical naming/namespace/dash rules",
        "Self-test the backend-patch checker",
        "Analyse library sources (warnings are errors)",
        "Self-test the workflow topology checker",
    )
) + (
    (ARCH_GATE, "Run x86-64 architecture-gate check"),
    (SANITIZERS, "Run tests under ASan"),
    (PR_CHECK, "Run proof cases (fault, lifecycle, timeout control)"),
)

# One nonliteral successful fallback per unpinned critical command. None of these spells `true`: a checker
# that recognized only the literal would accept every one of them while the command's failure reached nothing.
CRITICAL_COMMAND_FALLBACKS = (
    (RELEASE, '          python scripts/check_install_prefix.py "${{ github.workspace }}/install_package/mingw"', "|| :"),
    (RELEASE, '          python scripts/check_emit_tls.py "$archive" "$backend"', "|| echo tolerated"),
    (RELEASE, '          python scripts/check_no_test_seams.py "$archive"', "|| cat /dev/null"),
    (RELEASE, "          ctest --test-dir build/package-dual-config-mingw -C Release --output-on-failure", "|| echo ignored"),
    (RELEASE, '          "${BIN}/DetourModKit_bench" | tee bench-results/dispatcher.txt', "|| printf skipped"),
    (QUALITY, "        run: python scripts/check_header_hygiene.py", "|| echo ignored"),
    (QUALITY, "        run: python scripts/check_mechanical_style.py", "|| :"),
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

        Scoped to the job because a step name is unique only inside one: `Install MinGW (if not cached)` exists in
        several jobs, and a first-match mutation would silently test the wrong one.
        """
        text, start, end = self.job_span(relative, job)
        body = text[start:end]
        anchor = "      - name: {0}\n".format(step_name)
        assert anchor in body, "step '{0}' not found in job '{1}' of {2}".format(step_name, job, relative)
        return text, start, end, body.index(anchor)

    def step_bounds(self, relative, job, step_name):
        """Return (text, absolute start, absolute end) of one step block."""
        text, start, end, position = self.step_span(relative, job, step_name)
        body = text[start:end]
        following = body.find("      - name: ", position + 1)
        return text, start + position, start + (following if following >= 0 else len(body))

    def delete_step(self, relative, job, step_name):
        text, begin, finish = self.step_bounds(relative, job, step_name)
        self.write(relative, text[:begin] + text[finish:])

    def rename_step(self, relative, job, step_name, replacement):
        text, begin, _ = self.step_bounds(relative, job, step_name)
        self.write(
            relative,
            text[:begin] + text[begin:].replace(step_name, replacement, 1),
        )

    def retarget_step_condition(self, relative, job, step_name, reviewed, replacement="${{ false }}"):
        """Replace one named step's reviewed condition with another, without touching a like-conditioned neighbour."""
        text, start, end, position = self.step_span(relative, job, step_name)
        body = text[start:end]
        original = "        if: {0}\n".format(reviewed)
        assert original in body[position:], "step '{0}' does not carry '{1}'".format(step_name, reviewed)
        offset = position + body[position:].index(original)
        mutated = body[:offset] + "        if: {0}\n".format(replacement) + body[offset + len(original) :]
        self.write(relative, text[:start] + mutated + text[end:])

    def prepend_unreviewed_line(self, relative, job, step_name, line="echo unreviewed"):
        """Insert one unreviewed command at the head of a step's program, whatever form its run takes."""
        text, begin, finish = self.step_bounds(relative, job, step_name)
        block = text[begin:finish]
        block_marker = "        run: |\n"
        if block_marker in block:
            mutated = block.replace(block_marker, block_marker + "          {0}\n".format(line), 1)
        else:
            match = re.search(r"^        run: (?P<body>.+)$", block, re.MULTILINE)
            assert match, "step '{0}' has no run body to extend".format(step_name)
            mutated = block.replace(
                match.group(0),
                "        run: |\n          {0}\n          {1}".format(line, match.group("body")),
                1,
            )
        self.write(relative, text[:begin] + mutated + text[finish:])

    def mutate_step(self, relative, job, step_name, original, replacement):
        """Replace text only inside one named step, even when another step carries the same spelling."""
        text, begin, finish = self.step_bounds(relative, job, step_name)
        block = text[begin:finish]
        assert original in block, "mutation anchor not found in step '{0}': {1}".format(step_name, original)
        self.write(relative, text[:begin] + block.replace(original, replacement, 1) + text[finish:])

    def append_fallback(self, relative, command, fallback):
        """Append a successful fallback to one command, so its failure is normalized to green."""
        self.mutate(relative, command, command + " " + fallback)

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

    # -- positive controls -------------------------------------------------------------------------

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
        self.workspace.mutate(RELEASE, "inputs.mode == 'publish'", "inputs.mode != 'publish'")
        self.assertNotEqual(
            subprocess.run(
                [sys.executable, checker.__file__, "--repository-root", self.workspace.root],
                capture_output=True,
                timeout=CLI_TIMEOUT_SECONDS,
            ).returncode,
            0,
        )

    def test_every_contract_workflow_exists_in_the_repository(self):
        for relative in contract.WORKFLOWS:
            self.assertTrue(
                os.path.isfile(os.path.join(REPOSITORY, relative)),
                "the contract names {0}, which is not in the repository".format(relative),
            )

    def test_every_contract_workflow_has_one_exact_source_identity(self):
        self.assertEqual(set(contract.WORKFLOW_SOURCE_SHA256), set(contract.WORKFLOWS))
        for relative, digest in contract.WORKFLOW_SOURCE_SHA256.items():
            self.assertRegex(digest, r"^[0-9a-f]{64}$", relative)

    def test_source_identity_normalizes_lf_crlf_and_bare_cr(self):
        relative = next(iter(contract.WORKFLOWS))
        original = contract.WORKFLOW_SOURCE_SHA256[relative]
        try:
            contract.WORKFLOW_SOURCE_SHA256[relative] = hashlib.sha256(b"first\nsecond\n").hexdigest()
            for spelling in (b"first\nsecond\n", b"first\r\nsecond\r\n", b"first\rsecond\r"):
                path = os.path.join(self.workspace.root, relative)
                with open(path, "wb") as handle:
                    handle.write(spelling)
                problems = []
                text = checker.read(self.workspace.root, relative, problems)
                checker.check_canonical_source(relative, text, problems)
                self.assertEqual(problems, [], spelling)
        finally:
            contract.WORKFLOW_SOURCE_SHA256[relative] = original

    def test_invalid_utf8_workflow_source_is_refused(self):
        path = os.path.join(self.workspace.root, QUALITY)
        with open(path, "ab") as handle:
            handle.write(b"\xff")
        self.refuses("workflow is not valid UTF-8")

    def test_the_contract_names_no_step_twice_within_one_job(self):
        # Step lookups are by name within a job, so a duplicate would make one entry unreachable and silently
        # stop being enforced.
        for relative, shape in contract.WORKFLOWS.items():
            for name, job in shape.jobs:
                names = [step.name for step in job.steps]
                self.assertEqual(
                    len(names), len(set(names)), "{0}: job '{1}' names a step twice".format(relative, name)
                )

    def test_harmless_policy_words_inside_quoted_shell_data_are_accepted(self):
        self.assertIsNone(
            checker.status_loss_reason(
                'python scripts/check_header_hygiene.py --note "continue-on-error is not set here"',
                "bash",
                False,
            )
        )
        self.holds()

    def test_a_captured_command_substitution_is_not_a_swallowed_exit_status(self):
        # `X="$(cmd || true)"` yields an empty VALUE the next guard still decides on, so the three reviewed
        # version captures must stay accepted while a bare swallow does not.
        self.holds()

    # -- unreviewed and missing routes -------------------------------------------------------------

    def test_a_missing_workflow_is_refused(self):
        os.remove(os.path.join(self.workspace.root, QUALITY))
        self.refuses("workflow is missing")

    def test_an_unreviewed_workflow_file_is_refused(self):
        self.workspace.write(
            ".github/workflows/shadow.yml",
            "name: Shadow\non:\n  pull_request:\njobs:\n  shadow:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - name: Do something\n        run: echo hi\n        shell: bash\n",
        )
        self.refuses("shadow.yml: workflow is not named by the canonical contract")

    def test_every_workflow_refuses_source_drift_outside_the_structural_reader(self):
        for relative in contract.WORKFLOWS:
            with self.subTest(relative=relative):
                self.setUp()
                self.workspace.mutate(relative, "jobs:\n", "x-unreviewed-policy: true\n\njobs:\n")
                self.refuses("normalized source does not match the reviewed canonical identity")

    def test_replacing_an_action_under_its_reviewed_name_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "uses: softprops/action-gh-release@3d0d9888cb7fd7b750713d6e236d1fcb99157228",
            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        )
        self.refuses("normalized source does not match the reviewed canonical identity")

    def test_a_renamed_job_is_refused(self):
        self.workspace.mutate(RELEASE, "\n  benchmark-evidence:\n", "\n  benchmark-evidence-renamed:\n")
        self.refuses("declares jobs")

    def test_a_deleted_quality_job_is_refused(self):
        text, start, end = self.workspace.job_span(QUALITY, "mechanical-style")
        header = "\n  mechanical-style:\n"
        self.workspace.write(QUALITY, text[: text.index(header)] + text[end:])
        self.refuses("declares jobs")

    def test_an_added_job_is_refused(self):
        self.workspace.mutate(
            QUALITY,
            "  clang-tidy:\n",
            "  extra-job:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Nothing\n"
            "        run: echo nothing\n        shell: bash\n\n  clang-tidy:\n",
        )
        self.refuses("declares jobs")

    # -- triggers and required contexts ------------------------------------------------------------

    def test_a_path_filtered_pull_request_context_is_refused(self):
        for relative in (PR_CHECK, ARCH_GATE, QUALITY):
            with self.subTest(relative=relative):
                self.setUp()
                self.workspace.mutate(
                    relative,
                    "  pull_request:\n    branches: [main, 'release/**']\n",
                    "  pull_request:\n    branches: [main, 'release/**']\n    paths:\n      - 'src/**'\n",
                )
                self.refuses("carries a 'paths' filter")

    def test_a_paths_ignore_filter_on_a_required_context_is_refused(self):
        self.workspace.mutate(
            PR_CHECK,
            "  pull_request:\n    branches: [main, 'release/**']\n",
            "  pull_request:\n    branches: [main, 'release/**']\n    paths-ignore:\n      - 'docs/**'\n",
        )
        self.refuses("carries a 'paths-ignore' filter")

    def test_required_trigger_values_and_flow_mappings_are_canonical(self):
        mutations = (
            ("    branches: [main, 'release/**']", "    branches: [dead-branch]"),
            (
                "  pull_request:\n    branches: [main, 'release/**']",
                "  pull_request: {branches: [main], paths: ['src/**']}",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(replacement=replacement):
                self.setUp()
                self.workspace.mutate(ARCH_GATE, original, replacement)
                self.refuses("normalized source does not match the reviewed canonical identity")

    def test_the_reviewed_coverage_paths_filter_stays_accepted(self):
        # The push route republishes what main already is, so its filter is a cost control, not a skipped context.
        self.holds()

    def test_a_removed_trigger_is_refused(self):
        self.workspace.mutate(SANITIZERS, "  push:\n    branches: [main, 'release/v4.0.0-*']\n", "")
        self.refuses("triggers are")

    def test_an_added_trigger_is_refused(self):
        self.workspace.mutate(ARCH_GATE, "on:\n  pull_request:", "on:\n  schedule:\n    - cron: '0 0 * * *'\n  pull_request:")
        self.refuses("triggers are")

    def test_a_dispatch_candidate_input_that_stops_being_required_is_refused(self):
        self.workspace.mutate(
            SIMD,
            '      expected_sha:\n        description: "Exact 40-character commit SHA to test"\n        required: true\n',
            '      expected_sha:\n        description: "Exact 40-character commit SHA to test"\n        required: false\n',
        )
        self.refuses("must be a required string input")

    def test_a_deleted_dispatch_candidate_input_is_refused(self):
        self.workspace.mutate(
            ARCH_GATE,
            '  workflow_dispatch:\n    inputs:\n      expected_sha:\n'
            '        description: "Exact 40-character commit SHA to gate"\n        required: true\n        type: string\n',
            "  workflow_dispatch:\n",
        )
        self.refuses("has no 'expected_sha' input")

    # -- job-level policy --------------------------------------------------------------------------

    def test_an_advisory_quality_job_is_refused(self):
        self.workspace.add_job_key(QUALITY, "format-check", "    continue-on-error: true\n")
        self.refuses("carries a continue-on-error marker")

    def test_a_job_that_calls_itself_advisory_is_refused(self):
        self.workspace.mutate(QUALITY, "    name: clang-format (blocking)", "    name: clang-format (advisory)")
        self.refuses("still calls itself advisory")

    def test_every_required_release_job_refuses_an_advisory_marker(self):
        for name in contract.REQUIRED_RELEASE_JOBS:
            with self.subTest(job=name):
                self.setUp()
                self.workspace.add_job_key(RELEASE, name, "    continue-on-error: true\n")
                self.refuses("job '{0}' carries a continue-on-error marker".format(name))

    def test_every_required_release_job_refuses_an_emptied_body(self):
        for name in contract.REQUIRED_RELEASE_JOBS:
            with self.subTest(job=name):
                self.setUp()
                self.workspace.empty_job(RELEASE, name)
                self.refuses("job '{0}' has no readable body".format(name))

    def test_every_required_release_job_refuses_an_unexpected_gate(self):
        for name in contract.REQUIRED_RELEASE_JOBS:
            with self.subTest(job=name):
                self.setUp()
                self.workspace.add_job_key(RELEASE, name, "    if: ${{ false }}\n")
                if name == "create-release":
                    self.refuses("is not gated on the publish mode")
                else:
                    self.refuses("job '{0}' is gated on".format(name))

    def test_every_blocking_quality_job_refuses_an_advisory_marker(self):
        for name in contract.BLOCKING_QUALITY_JOBS:
            with self.subTest(job=name):
                self.setUp()
                self.workspace.add_job_key(QUALITY, name, "    continue-on-error: true\n")
                self.refuses("job '{0}' carries a continue-on-error marker".format(name))

    def test_a_quality_job_with_no_readable_body_is_refused(self):
        self.workspace.empty_job(QUALITY, "header-hygiene")
        self.refuses("job 'header-hygiene' has no readable body")

    def test_a_relocated_job_runner_is_refused(self):
        self.workspace.mutate(RELEASE, "  build-mingw:\n    name: Build for MinGW (g++)\n    runs-on: windows-latest", "  build-mingw:\n    name: Build for MinGW (g++)\n    runs-on: ubuntu-latest")
        self.refuses("runs on 'ubuntu-latest', not its reviewed 'windows-latest'")

    def test_a_deleted_matrix_leg_is_refused(self):
        self.workspace.mutate(SIMD, "          - tier: AVX-512\n            chip: spr\n", "")
        self.refuses("normalized source does not match the reviewed canonical identity")

    def test_job_defaults_that_relocate_every_run_step_are_refused(self):
        self.workspace.mutate(
            SANITIZERS,
            "    runs-on: windows-latest\n",
            "    runs-on: windows-latest\n    defaults:\n      run:\n        working-directory: elsewhere\n",
        )
        self.refuses("normalized source does not match the reviewed canonical identity")

    def test_a_spaced_yaml_if_key_cannot_hide_a_job_gate(self):
        self.workspace.add_job_key(RELEASE, "build-mingw", "    if : ${{ false }}\n")
        self.refuses("job 'build-mingw' is gated on")

    # -- step inventory: deletion, replacement, reordering -----------------------------------------

    def test_every_load_bearing_step_refuses_being_deleted(self):
        for relative, step in LOAD_BEARING_STEPS:
            with self.subTest(step=step):
                self.setUp()
                job = self.job_of(relative, step)
                self.workspace.delete_step(relative, job, step)
                self.refuses("runs steps")

    def test_every_load_bearing_step_refuses_being_renamed(self):
        for relative, step in LOAD_BEARING_STEPS:
            with self.subTest(step=step):
                self.setUp()
                job = self.job_of(relative, step)
                self.workspace.rename_step(relative, job, step, "Something else entirely")
                self.refuses("runs steps")

    def test_an_inserted_step_is_refused(self):
        self.workspace.add_step(
            RELEASE,
            "build-mingw",
            "      - name: Swallowed check\n"
            '        run: python -c "raise SystemExit(1)" || true\n'
            "        shell: bash\n",
        )
        self.refuses("runs steps")

    def test_a_reordered_step_list_is_refused(self):
        # Moving the exact-candidate guard after the version comparison keeps every reviewed step present.
        text, begin, finish = self.workspace.step_bounds(RELEASE, "validate-version", contract.IDENTITY_STEP)
        block = text[begin:finish]
        remainder = text[:begin] + text[finish:]
        self.workspace.write(RELEASE, remainder + block)
        self.refuses("runs steps")

    def test_a_replaced_step_body_under_the_reviewed_name_is_refused(self):
        self.workspace.mutate_step(
            RELEASE,
            "validate-version",
            contract.IDENTITY_STEP,
            'python scripts/check_release_identity.py --expected-sha "$EXPECTED_SHA" '
            '--event-sha "$EVENT_SHA" --verify-checkout',
            "echo skipping the identity check",
        )
        self.refuses("is not the reviewed program")

    # -- step conditions ---------------------------------------------------------------------------

    def test_every_load_bearing_step_refuses_a_false_condition(self):
        for relative, step in LOAD_BEARING_STEPS:
            with self.subTest(step=step):
                self.setUp()
                self.workspace.gate_step(relative, step)
                self.refuses("never runs the guard it reports green for")

    def test_every_reviewed_step_condition_refuses_being_retargeted(self):
        reviewed = [
            (relative, name, step)
            for relative, shape in contract.WORKFLOWS.items()
            for name, job in shape.jobs
            for step in job.steps
            if step.condition is not None
        ]
        self.assertTrue(reviewed, "the contract reviews no step condition, so this matrix proves nothing")
        for relative, name, step in reviewed:
            with self.subTest(step=step.name):
                self.setUp()
                self.workspace.retarget_step_condition(relative, name, step.name, step.condition)
                self.refuses("not its reviewed condition")

    def test_a_step_level_advisory_marker_names_the_step_it_is_on(self):
        self.workspace.mutate(
            RELEASE,
            "      - name: Assert Export Equality (MinGW)\n",
            "      - name: Assert Export Equality (MinGW)\n        continue-on-error: true\n",
        )
        self.refuses("step 'Assert Export Equality (MinGW)' in job 'build-mingw' carries a continue-on-error marker")

    def test_a_deliberate_red_probe_cannot_be_widened_to_every_event(self):
        self.workspace.retarget_step_condition(
            SANITIZERS,
            "sanitizers",
            "Run deliberate ASan failure probe (expected red)",
            "${{ github.event_name == 'workflow_dispatch' && inputs.deliberate_asan_red }}",
            "${{ always() }}",
        )
        self.refuses("not its reviewed condition")

    # -- publication programs: shadowing, relocation, reduction ------------------------------------

    def test_a_shadowing_assignment_in_the_tag_program_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            '          TITLE="${RELEASE_TITLE}"\n',
            '          TITLE="${RELEASE_TITLE}"\n          EXPECTED_SHA="$(git rev-parse HEAD)"\n',
        )
        self.refuses("is not the reviewed program")

    def test_an_exported_alias_in_the_tag_program_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            '          VERSION="v${RELEASE_VERSION}"\n',
            '          VERSION="v${RELEASE_VERSION}"\n          export EXPECTED_SHA="${REMOTE_TARGET}"\n',
        )
        self.refuses("is not the reviewed program")

    def test_an_unset_of_an_identity_variable_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            '          TAG_MESSAGE="${TITLE:-DetourModKit ${VERSION}}"\n',
            '          TAG_MESSAGE="${TITLE:-DetourModKit ${VERSION}}"\n          unset EXPECTED_SHA\n',
        )
        self.refuses("is not the reviewed program")

    def test_moving_the_single_success_exit_to_the_front_is_refused(self):
        # The reviewed program returns success only after the remote tag was observed to resolve to the
        # candidate. The same lines in a different order are an unconditional early success.
        self.workspace.mutate(
            RELEASE,
            '          TITLE="${RELEASE_TITLE}"\n',
            "          exit 0\n          TITLE=\"${RELEASE_TITLE}\"\n",
        )
        self.refuses("is not the reviewed program")

    def test_dropping_the_tag_target_comparison_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            '            if [ "${REMOTE_TARGET}" != "${EXPECTED_SHA}" ]; then',
            '            if [ "${REMOTE_TARGET}" = "${REMOTE_TARGET}" ]; then',
        )
        self.refuses("is not the reviewed program")

    def test_tag_creation_must_target_the_exact_dispatched_sha(self):
        self.workspace.mutate(
            RELEASE,
            'git tag -a "$VERSION" -m "$TAG_MESSAGE" "${EXPECTED_SHA}"',
            'git tag -a "$VERSION" -m "$TAG_MESSAGE"',
        )
        self.refuses("is not the reviewed program")

    def test_a_retargeted_tag_environment_is_refused(self):
        self.workspace.mutate(RELEASE, "          EXPECTED_SHA: ${{ github.sha }}", "          EXPECTED_SHA: ${{ github.ref }}")
        self.refuses("declares environment")

    def test_a_moved_tag_working_directory_is_refused(self):
        self.workspace.mutate(RELEASE, "        working-directory: release-source\n", "")
        self.refuses("runs in working directory")

    def test_dropping_the_checkout_verification_from_the_candidate_guard_is_refused(self):
        self.workspace.mutate_step(
            RELEASE,
            "validate-version",
            contract.IDENTITY_STEP,
            '--event-sha "$EVENT_SHA" --verify-checkout',
            '--event-sha "$EVENT_SHA"',
        )
        self.refuses("is not the reviewed program")

    def test_publishing_from_a_non_main_ref_guard_that_lost_its_ref_is_refused(self):
        self.workspace.mutate_step(
            RELEASE,
            "create-release",
            contract.REF_GUARD_STEP,
            '--required-ref refs/heads/main --actual-ref "$ACTUAL_REF"',
            "",
        )
        self.refuses("is not the reviewed program")

    def test_a_relaxed_publish_ref_is_refused(self):
        self.workspace.mutate(RELEASE, "--required-ref refs/heads/main", "--required-ref refs/heads/release")
        self.refuses("is not the reviewed program")

    def test_an_identity_guard_interpolating_untrusted_context_into_bash_is_refused(self):
        self.workspace.mutate_step(
            RELEASE,
            "validate-version",
            contract.IDENTITY_STEP,
            '--expected-sha "$EXPECTED_SHA"',
            '--expected-sha "${{ github.event.inputs.expected_sha }}"',
        )
        self.refuses("is not the reviewed program")

    def test_a_retargeted_identity_environment_is_refused(self):
        self.workspace.mutate_step(
            RELEASE,
            "validate-version",
            contract.IDENTITY_STEP,
            "          EXPECTED_SHA: ${{ github.event.inputs.expected_sha }}",
            "          EXPECTED_SHA: ${{ github.ref }}",
        )
        self.refuses("declares environment")

    def test_an_unquoted_identity_environment_expansion_is_refused(self):
        self.workspace.mutate_step(
            RELEASE,
            "validate-version",
            contract.IDENTITY_STEP,
            '--expected-sha "$EXPECTED_SHA"',
            "--expected-sha $EXPECTED_SHA",
        )
        self.refuses("is not the reviewed program")

    def test_a_workflow_level_shell_startup_redirect_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "jobs:\n",
            "env:\n  BASH_ENV: unreviewed-startup.sh\n\njobs:\n",
        )
        self.refuses("normalized source does not match the reviewed canonical identity")

    def test_the_publish_guard_must_verify_its_own_checkout(self):
        self.workspace.mutate_step(
            RELEASE,
            "create-release",
            contract.REF_GUARD_STEP,
            ' --verify-checkout --required-ref refs/heads/main',
            ' --required-ref refs/heads/main',
        )
        self.refuses("is not the reviewed program")

    def test_every_pinned_step_refuses_an_inserted_line(self):
        # One unreviewed command inserted into a pinned program. Every reviewed line is still present and in
        # its reviewed order, which is exactly the shape a presence check reports green for.
        for relative, job, step in PINNED_STEPS:
            with self.subTest(step=step):
                self.setUp()
                self.workspace.prepend_unreviewed_line(relative, job, step)
                self.refuses("is not the reviewed program")

    def test_a_continued_comment_cannot_hide_a_pinned_program(self):
        # Bash removes the backslash-newline before recognizing the comment, so the next physical line would
        # become comment text and the required command would never execute.
        text, begin, finish = self.workspace.step_bounds(RELEASE, "validate-version", contract.IDENTITY_STEP)
        block = text[begin:finish]
        run_line = next(line for line in block.splitlines() if line.startswith("        run: "))
        command = run_line[len("        run: ") :]
        replacement = "        run: |\n          # hide the guard \\\n          {0}".format(command)
        self.workspace.write(RELEASE, text[:begin] + block.replace(run_line, replacement, 1) + text[finish:])
        self.refuses("is not the reviewed program")

    # -- focused status-loss diagnostics ------------------------------------------------------------

    def test_every_critical_command_refuses_a_nonliteral_successful_fallback(self):
        for relative, command, fallback in CRITICAL_COMMAND_FALLBACKS:
            with self.subTest(command=command, fallback=fallback):
                self.setUp()
                self.workspace.append_fallback(relative, command, fallback)
                self.refuses("discards a step's exit status")

    def test_a_capture_that_normalizes_a_failure_with_a_nonliteral_fallback_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            '          archive=$(ls "${{ github.workspace }}"/install_package/mingw/lib*/libDetourModKit.a)',
            '          archive=$(ls "${{ github.workspace }}"/install_package/mingw/lib*/libDetourModKit.a || echo none)',
        )
        self.refuses("discards a step's exit status")

    def test_a_disjunction_hidden_inside_a_quoted_program_is_refused(self):
        # The shell still evaluates it; a token scan sees one opaque word. This is the shape that made the
        # previous blacklist bypassable, so it is refused on the raw line rather than on the token stream.
        self.workspace.mutate(
            RELEASE,
            '          python scripts/check_no_test_seams.py "$archive"\n',
            "          bash -c 'python scripts/check_no_test_seams.py \"$archive\" || true'\n",
        )
        self.refuses("hidden inside quoting or a command substitution")

    def test_disabling_errexit_with_the_long_option_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "          archive=$(ls",
            "          set +o errexit\n          archive=$(ls",
        )
        self.refuses("'set +o errexit'")

    def test_disabling_pipefail_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            '          SCANNER="$(find build/mingw-release',
            '          set +o pipefail\n          SCANNER="$(find build/mingw-release',
        )
        self.refuses("'set +o pipefail'")

    def test_disabling_errexit_with_the_short_option_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "          archive=$(ls",
            "          set +e\n          archive=$(ls",
        )
        self.refuses("'set +e'")

    def test_an_eval_that_hides_the_checked_program_is_refused(self):
        self.workspace.mutate(
            QUALITY,
            "        run: python scripts/check_mechanical_style.py",
            "        run: eval python scripts/check_mechanical_style.py",
        )
        self.refuses("'eval'")

    def test_a_cmd_ampersand_chain_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "          cmake --install build/msvc-release-package\n",
            "          cmake --install build/msvc-release-package & echo ignored\n",
        )
        self.refuses("CMD '&'")

    def test_a_cmd_pipeline_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "          cmake --install build/msvc-release-package\n",
            "          cmake --install build/msvc-release-package | more\n",
        )
        self.refuses("CMD '|'")

    def test_a_negated_required_command_is_refused(self):
        self.workspace.mutate(
            QUALITY,
            "        run: python scripts/check_header_hygiene.py",
            "        run: ! python scripts/check_header_hygiene.py",
        )
        self.refuses("negated with '!'")

    def test_a_bare_success_exit_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "          cmake --install build/mingw-release-package\n",
            "          exit 0\n          cmake --install build/mingw-release-package\n",
        )
        self.refuses("bare 'exit 0' skip")

    def test_a_cmd_success_exit_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "          cmake --install build/msvc-release-package\n",
            "          exit /b 0\n          cmake --install build/msvc-release-package\n",
        )
        self.refuses("'exit /b 0'")

    def test_a_required_command_cannot_hide_before_a_bracket_test(self):
        # The carve-out is for compounds whose every operand is a bracket test. A real command on the left of
        # `||` inside a conditional head is work whose status the test then normalizes.
        self.workspace.mutate(
            RELEASE,
            '          if [ -z "${SCANNER}" ]; then',
            '          if python scripts/check_install_prefix.py x || [ -z "${SCANNER}" ]; then',
        )
        self.refuses("discards a step's exit status")

    def test_a_conditional_head_that_runs_work_is_refused(self):
        self.workspace.mutate(
            QUALITY,
            "        run: python scripts/check_mechanical_style.py",
            "        run: if python scripts/check_mechanical_style.py; then echo ok; fi",
        )
        self.refuses("conditional head executes a required command")

    def test_replacing_an_unpinned_required_program_is_refused(self):
        self.workspace.mutate(
            QUALITY,
            "        run: python scripts/check_header_hygiene.py",
            "        run: echo skipped",
        )
        self.refuses("normalized source does not match the reviewed canonical identity")

    def test_a_later_success_command_cannot_mask_an_unpinned_required_command(self):
        mutations = (
            (
                QUALITY,
                "        run: python scripts/check_header_hygiene.py",
                "        run: |\n          python scripts/check_header_hygiene.py\n          echo masked",
            ),
            (
                RELEASE,
                "        run: cmake --build --preset msvc-release --parallel 2",
                "        run: |\n          cmake --build --preset msvc-release --parallel 2\n          echo masked",
            ),
            (
                SANITIZERS,
                "        run: cmake --build --preset msvc-debug-asan --parallel 2",
                "        run: |\n          cmake --build --preset msvc-debug-asan --parallel 2\n          Write-Output masked",
            ),
        )
        for relative, original, replacement in mutations:
            with self.subTest(relative=relative):
                self.setUp()
                self.workspace.mutate(relative, original, replacement)
                self.refuses("normalized source does not match the reviewed canonical identity")

    def test_a_nested_command_substitution_cannot_hide_a_required_program(self):
        self.workspace.mutate(
            QUALITY,
            "        run: python scripts/check_header_hygiene.py",
            '        run: echo "$(python scripts/check_header_hygiene.py)"',
        )
        self.refuses("normalized source does not match the reviewed canonical identity")

    def test_a_detected_failure_that_only_warns_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            '            Write-Error "Install directory \'$installDir\' does not exist after cmake --install!"',
            '            Write-Warning "Install directory \'$installDir\' does not exist after cmake --install!"',
        )
        self.refuses("'Write-Warning'")

    def test_a_nested_powershell_warning_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            '            Write-Error "Install directory \'$installDir\' does not exist after cmake --install!"',
            "            if ($true) { Write-Warning \"broken\" }",
        )
        self.refuses("'Write-Warning'")

    def test_a_backtick_split_powershell_warning_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            '            Write-Error "Install directory \'$installDir\' does not exist after cmake --install!"',
            '            Write-`\n            Warning "broken"',
        )
        self.refuses("'Write-Warning'")

    # -- shells ------------------------------------------------------------------------------------

    def test_a_custom_shell_template_is_refused(self):
        for template in ("bash {0} || true", "bash --noprofile {0}", "bash -c {0}"):
            with self.subTest(template=template):
                self.setUp()
                self.workspace.mutate(
                    RELEASE,
                    "      - name: Assert Export Equality (MinGW)\n"
                    '        # DMK_BUILD_TESTS must not change the installed contract: package config, ABI record, '
                    "targets files, and\n",
                    "      - name: Assert Export Equality (MinGW)\n        shell: {0}\n"
                    '        # DMK_BUILD_TESTS must not change the installed contract: package config, ABI record, '
                    "targets files, and\n".format(template),
                )
                self.refuses("declares unreviewed shell")

    def test_switching_a_reviewed_step_to_another_reviewed_shell_is_refused(self):
        self.workspace.mutate(
            QUALITY,
            "        run: python scripts/check_header_hygiene.py\n        shell: bash\n",
            "        run: python scripts/check_header_hygiene.py\n        shell: pwsh\n",
        )
        self.refuses("not its reviewed 'bash'")

    def test_dropping_an_explicit_shell_is_refused(self):
        self.workspace.mutate(
            QUALITY,
            "        run: python scripts/check_header_hygiene.py\n        shell: bash\n",
            "        run: python scripts/check_header_hygiene.py\n",
        )
        self.refuses("runs under shell 'None'")

    def test_an_action_step_that_gains_a_run_body_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "      - name: Upload MinGW Artifact for Release\n",
            "      - name: Upload MinGW Artifact for Release\n        run: echo surprise\n",
        )
        self.refuses("reviewed as an action step but carries a run body")

    # -- dependency graph --------------------------------------------------------------------------

    def test_each_producer_must_depend_on_candidate_validation(self):
        for name in ("build-mingw", "build-msvc", "benchmark-evidence"):
            with self.subTest(job=name):
                self.setUp()
                self.workspace.mutate(
                    RELEASE, "  {0}:\n".format(name), "  {0}:\n".format(name)
                )
                text, start, end = self.workspace.job_span(RELEASE, name)
                body = text[start:end].replace("    needs: validate-version\n", "", 1)
                self.workspace.write(RELEASE, text[:start] + body + text[end:])
                self.refuses("job '{0}' needs [], not the reviewed ['validate-version']".format(name))

    def test_publishing_without_a_producer_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "    needs: [build-mingw, build-msvc, benchmark-evidence]",
            "    needs: [build-mingw, build-msvc]",
        )
        self.refuses("job 'create-release' needs")

    def test_an_unreviewed_dependency_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "    needs: [build-mingw, build-msvc, benchmark-evidence]",
            "    needs: [build-mingw, build-msvc, benchmark-evidence, validate-version]",
        )
        self.refuses("job 'create-release' needs")

    def test_a_semantically_equivalent_dependency_rewrite_is_not_the_reviewed_source(self):
        self.workspace.mutate(
            RELEASE,
            "    needs: [build-mingw, build-msvc, benchmark-evidence]",
            "    needs:\n      - build-mingw\n      - build-msvc\n      - benchmark-evidence",
        )
        self.refuses("normalized source does not match the reviewed canonical identity")

    def test_a_block_sequence_needs_list_missing_a_producer_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "    needs: [build-mingw, build-msvc, benchmark-evidence]",
            "    needs:\n      - build-mingw\n      - build-msvc",
        )
        self.refuses("job 'create-release' needs")

    def test_nested_needs_data_cannot_stand_in_for_the_job_dependency(self):
        text, start, end = self.workspace.job_span(RELEASE, "build-mingw")
        body = text[start:end].replace(
            "    needs: validate-version\n", "    env:\n      NOTE: needs validate-version\n", 1
        )
        self.workspace.write(RELEASE, text[:start] + body + text[end:])
        self.refuses("job 'build-mingw' needs []")

    # -- release mode and credentials --------------------------------------------------------------

    def test_a_release_without_a_mode_input_is_refused(self):
        self.workspace.mutate(RELEASE, "      mode:\n", "      mode_disabled:\n")
        self.refuses("no 'mode' dispatch input")

    def test_a_mode_defaulting_to_publish_is_refused(self):
        self.workspace.mutate(RELEASE, "        default: preflight", "        default: publish")
        self.refuses("must default to preflight")

    def test_a_mode_offering_an_unreviewed_option_is_refused(self):
        self.workspace.mutate(RELEASE, "          - publish\n", "          - publish\n          - force\n")
        self.refuses("offers an unreviewed mode")

    def test_an_ungated_create_release_is_refused(self):
        self.workspace.mutate(RELEASE, "    if: ${{ inputs.mode == 'publish' }}\n", "")
        self.refuses("is not gated on the publish mode")

    def test_an_inverted_publish_mode_gate_is_refused(self):
        self.workspace.mutate(RELEASE, "inputs.mode == 'publish'", "inputs.mode != 'publish'")
        self.refuses("is not gated on the publish mode")

    def test_a_credential_outside_the_publish_job_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "      - name: Verify Tools (MinGW context)\n",
            "      - name: Verify Tools (MinGW context)\n        env:\n"
            "          TOKEN: ${{ secrets.RELEASE_TOKEN }}\n",
        )
        self.refuses("holds a release credential")

    def test_a_workflow_level_release_credential_is_refused(self):
        self.workspace.mutate(
            RELEASE, "jobs:\n", "env:\n  TOKEN: ${{ secrets.RELEASE_TOKEN }}\n\njobs:\n"
        )
        self.refuses("exposes RELEASE_TOKEN outside create-release")

    def test_a_secret_context_reference_outside_release_is_refused(self):
        self.workspace.mutate(
            QUALITY,
            "        run: python scripts/check_header_hygiene.py",
            '        run: echo "${{ toJSON(secrets) }}"',
        )
        self.refuses("normalized source does not match the reviewed canonical identity")

    def test_bracket_secret_syntax_outside_publish_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "      - name: Verify Tools (MinGW context)\n",
            "      - name: Verify Tools (MinGW context)\n        env:\n"
            "          TOKEN: ${{ secrets['RELEASE_TOKEN'] }}\n",
        )
        self.refuses("holds a release credential")

    def test_release_credentials_must_remain_on_the_two_reviewed_action_inputs(self):
        self.workspace.mutate(
            RELEASE,
            "          token: ${{ secrets.RELEASE_TOKEN }}\n          path: release-source\n",
            "          path: release-source\n",
        )
        self.refuses("exactly the two reviewed RELEASE_TOKEN uses")

    # -- content pins that survive from the previous boundary ---------------------------------------

    def test_tidy_without_the_warnings_as_errors_override_is_refused(self):
        self.workspace.mutate(QUALITY, "--warnings-as-errors='*'", "--checks='*'")
        self.refuses("--warnings-as-errors override")

    def test_tidy_without_compiler_werror_is_refused(self):
        self.workspace.mutate(QUALITY, "--extra-arg=-Werror", "--extra-arg=-Wall")
        self.refuses("--extra-arg=-Werror")

    def test_tidy_database_with_the_gcc_only_warning_is_refused(self):
        self.workspace.mutate(QUALITY, "-DDMK_HAS_WDANGLING_REFERENCE=OFF", "-DDMK_HAS_WDANGLING_REFERENCE=ON")
        self.refuses("-Wdangling-reference")

    def test_tidy_without_the_mingw_triple_is_refused(self):
        self.workspace.mutate(QUALITY, "--target=x86_64-w64-windows-gnu", "--target=x86_64-pc-windows-msvc")
        self.refuses("MinGW target triple")

    def test_a_removed_tier_banner_guard_is_refused(self):
        self.workspace.mutate(SIMD, "if (-not $level)", "if ($false)")
        self.refuses("no '-not $level' guard")

    def test_a_missing_sde_guard_is_refused(self):
        self.workspace.mutate(SIMD, "if (-not $sdeExe)", "if ($false)")
        self.refuses("no '-not $sdeExe' guard")

    def test_a_tier_guard_that_only_reports_is_refused(self):
        self.workspace.mutate(
            SIMD,
            '          {\n              throw "Intel SDE not found under SDE_PATH; '
            'the ${{ matrix.tier }} tier was never executed"\n          }',
            '          {\n              Write-Host "Intel SDE not found"\n          }',
        )
        self.refuses("guard does not throw")

    def test_a_skipping_simd_leg_is_refused(self):
        self.workspace.mutate(
            SIMD,
            "          $exe = (Get-ChildItem -Recurse -Path build/msvc-debug",
            "          exit 0\n          $exe = (Get-ChildItem -Recurse -Path build/msvc-debug",
        )
        self.refuses("bare 'exit 0' skip")

    def test_a_benchmark_job_that_never_checks_its_output_is_refused(self):
        self.workspace.mutate(RELEASE, "python scripts/check_benchmark_results.py", "python scripts/noop.py")
        self.refuses("does not run the result checker")

    def test_benchmark_route_must_build_the_compiled_ledger_probe(self):
        self.workspace.mutate(RELEASE, " dmk_bench_gate_probe\n", "\n")
        self.refuses("is not the reviewed program")

    def test_benchmark_route_must_run_the_compiled_ledger_self_test(self):
        self.workspace.mutate(
            RELEASE,
            '          python scripts/test_check_benchmark_results.py --ledger-probe "${LEDGER_PROBE}"\n',
            "",
        )
        self.refuses("is not the reviewed program")

    def test_a_producer_running_only_the_checkers_self_test_is_refused(self):
        self.workspace.mutate(
            RELEASE,
            "python scripts/check_benchmark_results.py bench-results/*.txt",
            "python scripts/test_check_benchmark_results.py bench-results/*.txt",
        )
        self.refuses("does not run the result checker")

    def test_each_producer_must_run_the_same_base_execution_check(self):
        for job, directory in (("build-mingw", "mingw"), ("build-msvc", "msvc")):
            with self.subTest(job=job):
                self.setUp()
                self.workspace.mutate(
                    RELEASE,
                    "build/{0}-release/dmk_same_base_replacement.xml".format(directory),
                    "build/{0}-release/some_other_report.xml".format(directory),
                )
                self.refuses("is not the reviewed program")

    def test_each_producer_must_run_the_build_tree_consumer(self):
        for job, suffix in (("build-mingw", "mingw"), ("build-msvc", "msvc")):
            with self.subTest(job=job):
                self.setUp()
                self.workspace.mutate(
                    RELEASE,
                    "          ctest --test-dir build/package-build-tree-{0} --output-on-failure".format(suffix),
                    "          echo skipping the consumer",
                )
                self.refuses("is not the reviewed program")

    def test_both_lifecycle_soaks_are_exact_required_commands(self):
        for suffix in ("mingw", "msvc"):
            with self.subTest(soak=suffix):
                self.setUp()
                self.workspace.mutate(
                    RELEASE,
                    '--dump-directory "$RUNNER_TEMP/dmk-lifecycle-dumps-{0}"'.format(suffix),
                    '--dump-directory "$RUNNER_TEMP/elsewhere-{0}"'.format(suffix),
                )
                self.refuses("is not the reviewed program")

    def test_the_pr_check_retry_policy_cannot_come_back(self):
        self.workspace.mutate(
            PR_CHECK,
            "        run: ctest --preset msvc-debug\n",
            "        run: ctest --preset msvc-debug --repeat until-pass:2\n",
        )
        self.refuses("is not the reviewed program")

    def test_the_architecture_gate_command_cannot_be_reduced(self):
        self.workspace.mutate(ARCH_GATE, "        run: bash scripts/check_arch_gate.sh", "        run: echo skipped")
        self.refuses("is not the reviewed program")

    def test_the_repository_positive_contract_run_cannot_be_reduced(self):
        self.workspace.mutate(
            QUALITY,
            "        run: python scripts/check_workflow_topology.py --repository-root .",
            "        run: echo contract ok",
        )
        self.refuses("is not the reviewed program")

    # -- helpers -----------------------------------------------------------------------------------

    def job_of(self, relative, step_name):
        """Return the job that owns one reviewed step name."""
        for name, job in contract.WORKFLOWS[relative].jobs:
            if any(step.name == step_name for step in job.steps):
                return name
        raise AssertionError("no reviewed job owns step '{0}' in {1}".format(step_name, relative))


if __name__ == "__main__":
    unittest.main(verbosity=2)
