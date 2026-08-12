#!/usr/bin/env python3
"""Self-test for check_release_identity.py.

The helper is the only thing standing between a dispatch and a publish that operates on a different
commit, so every refusal it owes is exercised here, and the positive case is exercised too: a guard
that refused everything would be just as useless as one that refused nothing.

Every case runs the real command line in a subprocess. The workflow invokes it that way, and an
in-process call would not prove that the exit status the job reads is the one the checker decided.
The topology self-test separately proves the exact environment bindings and quoted shell command.

Run standalone; exits 0 when every case behaves.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_release_identity as checker

CLI_TIMEOUT_SECONDS = 120

ONE = "1" * 40
TWO = "2" * 40


class Repository:
    """A throwaway git repository whose HEAD a case can compare against."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="dmk_release_identity_")
        self.git("init", "--quiet")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        with open(os.path.join(self.root, "candidate.txt"), "w", encoding="utf-8") as handle:
            handle.write("candidate\n")
        self.git("add", "candidate.txt")
        self.git("commit", "--quiet", "-m", "candidate")
        self.head = self.git("rev-parse", "HEAD").strip()

    def git(self, *arguments):
        completed = subprocess.run(
            ["git"] + list(arguments),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=CLI_TIMEOUT_SECONDS,
            check=True,
        )
        return completed.stdout


class ReleaseIdentity(unittest.TestCase):
    def setUp(self):
        self.repository = Repository()
        self.addCleanup(shutil.rmtree, self.repository.root, ignore_errors=True)

    def invoke(self, *arguments, environment=None):
        """Run the real CLI and return (exit status, combined output)."""
        completed = subprocess.run(
            [sys.executable, checker.__file__] + list(arguments),
            capture_output=True,
            env=environment,
            text=True,
            timeout=CLI_TIMEOUT_SECONDS,
        )
        return completed.returncode, completed.stdout + completed.stderr

    def refuses(self, arguments, expected, environment=None):
        status, output = self.invoke(*arguments, environment=environment)
        self.assertEqual(status, 1, "expected a refusal, got acceptance:\n{0}".format(output))
        self.assertIn(expected, output, "refused, but not for the expected reason:\n{0}".format(output))

    def accepts(self, arguments):
        status, output = self.invoke(*arguments)
        self.assertEqual(status, 0, "expected acceptance, got a refusal:\n{0}".format(output))

    def test_the_exact_candidate_is_accepted(self):
        self.accepts(
            [
                "--expected-sha",
                self.repository.head,
                "--event-sha",
                self.repository.head,
                "--verify-checkout",
                "--repository-root",
                self.repository.root,
            ]
        )

    def test_the_exact_candidate_on_the_required_ref_is_accepted(self):
        self.accepts(
            [
                "--expected-sha",
                self.repository.head,
                "--event-sha",
                self.repository.head,
                "--required-ref",
                "refs/heads/main",
                "--actual-ref",
                "refs/heads/main",
                "--verify-checkout",
                "--repository-root",
                self.repository.root,
            ]
        )

    def test_a_malformed_expected_sha_is_refused(self):
        self.refuses(
            ["--expected-sha", "abc123", "--event-sha", ONE],
            "must be one full 40-character commit SHA",
        )

    def test_an_empty_expected_sha_is_refused(self):
        self.refuses(
            ["--expected-sha", "", "--event-sha", ONE],
            "must be one full 40-character commit SHA",
        )

    def test_an_abbreviated_expected_sha_is_refused(self):
        self.refuses(
            ["--expected-sha", self.repository.head[:12], "--event-sha", self.repository.head],
            "must be one full 40-character commit SHA",
        )

    def test_an_expected_sha_with_a_terminal_newline_is_refused(self):
        self.refuses(
            ["--expected-sha", ONE + "\n", "--event-sha", ONE + "\n"],
            "must be one full 40-character commit SHA",
        )

    def test_a_malformed_event_sha_is_refused(self):
        self.refuses(
            ["--expected-sha", ONE, "--event-sha", "not-a-sha"],
            "is not one full 40-character commit SHA",
        )

    def test_an_empty_event_sha_is_refused(self):
        self.refuses(["--expected-sha", ONE, "--event-sha", ""], "is not one full 40-character commit SHA")

    def test_an_event_sha_with_a_terminal_newline_is_refused(self):
        self.refuses(
            ["--expected-sha", ONE, "--event-sha", ONE + "\n"],
            "is not one full 40-character commit SHA",
        )

    def test_a_wrong_event_sha_is_refused(self):
        self.refuses(
            ["--expected-sha", ONE, "--event-sha", TWO],
            "not the expected candidate",
        )

    def test_case_differences_alone_do_not_refuse(self):
        self.accepts(["--expected-sha", "A" * 40, "--event-sha", "a" * 40])

    def test_a_wrong_ref_is_refused(self):
        self.refuses(
            [
                "--expected-sha",
                ONE,
                "--event-sha",
                ONE,
                "--required-ref",
                "refs/heads/main",
                "--actual-ref",
                "refs/heads/release/v4.0.0-v5",
            ],
            "Only 'refs/heads/main' may proceed",
        )

    def test_a_tag_ref_that_ends_in_the_required_name_is_refused(self):
        self.refuses(
            [
                "--expected-sha",
                ONE,
                "--event-sha",
                ONE,
                "--required-ref",
                "refs/heads/main",
                "--actual-ref",
                "refs/tags/main",
            ],
            "Only 'refs/heads/main' may proceed",
        )

    def test_an_empty_ref_is_refused(self):
        self.refuses(
            ["--expected-sha", ONE, "--event-sha", ONE, "--required-ref", "refs/heads/main", "--actual-ref", ""],
            "Only 'refs/heads/main' may proceed",
        )

    def test_a_required_ref_without_an_actual_ref_is_refused(self):
        self.refuses(
            ["--expected-sha", ONE, "--event-sha", ONE, "--required-ref", "refs/heads/main"],
            "only meaningful together",
        )

    def test_an_actual_ref_without_a_required_ref_is_refused(self):
        self.refuses(
            ["--expected-sha", ONE, "--event-sha", ONE, "--actual-ref", "refs/heads/main"],
            "only meaningful together",
        )

    def test_a_wrong_checkout_is_refused(self):
        self.refuses(
            [
                "--expected-sha",
                ONE,
                "--event-sha",
                ONE,
                "--verify-checkout",
                "--repository-root",
                self.repository.root,
            ],
            "not the expected candidate",
        )

    def test_a_checkout_that_cannot_be_resolved_is_refused(self):
        outside = tempfile.mkdtemp(prefix="dmk_release_identity_bare_")
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        self.refuses(
            [
                "--expected-sha",
                self.repository.head,
                "--event-sha",
                self.repository.head,
                "--verify-checkout",
                "--repository-root",
                outside,
            ],
            "git rev-parse HEAD failed",
        )

    def test_git_environment_cannot_redirect_checkout_verification(self):
        redirected = Repository()
        self.addCleanup(shutil.rmtree, redirected.root, ignore_errors=True)
        with open(os.path.join(redirected.root, "redirect.txt"), "w", encoding="utf-8") as handle:
            handle.write("redirect\n")
        redirected.git("add", "redirect.txt")
        redirected.git("commit", "--quiet", "-m", "redirect")
        redirected.head = redirected.git("rev-parse", "HEAD").strip()
        self.assertNotEqual(redirected.head, self.repository.head)

        environment = os.environ.copy()
        environment["GIT_DIR"] = os.path.join(redirected.root, ".git")
        self.refuses(
            [
                "--expected-sha",
                redirected.head,
                "--event-sha",
                redirected.head,
                "--verify-checkout",
                "--repository-root",
                self.repository.root,
            ],
            "not the expected candidate",
            environment=environment,
        )

    def test_a_missing_working_tree_is_refused(self):
        self.refuses(
            [
                "--expected-sha",
                self.repository.head,
                "--event-sha",
                self.repository.head,
                "--verify-checkout",
                "--repository-root",
                os.path.join(self.repository.root, "no-such-directory"),
            ],
            "could not be run",
        )

    def test_the_checkout_is_only_resolved_when_asked(self):
        # Without --verify-checkout the helper must not consult git at all, so a run in a directory that has no
        # repository still decides on the values it was handed.
        outside = tempfile.mkdtemp(prefix="dmk_release_identity_plain_")
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        self.accepts(["--expected-sha", ONE, "--event-sha", ONE, "--repository-root", outside])

    def test_a_missing_required_argument_is_refused(self):
        status, output = self.invoke("--expected-sha", ONE)
        self.assertNotEqual(status, 0, "a missing --event-sha must not be acceptance:\n{0}".format(output))


if __name__ == "__main__":
    unittest.main(verbosity=2)
