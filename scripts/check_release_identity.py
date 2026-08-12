#!/usr/bin/env python3
"""Decide, at workflow runtime, whether a run is operating on the dispatched candidate.

The workflow transports context values through an exact step environment and passes them as quoted
arguments, so shell-significant input remains data. The checked-out commit is resolved by this process
with Git's repository-selection environment disabled. The topology contract pins both the environment
and the one command that consumes it.

Exit status is 0 when the identity holds, else 1.
"""
import argparse
import os
import re
import subprocess
import sys


FULL_SHA = re.compile(r"[0-9a-fA-F]{40}")

GIT_TIMEOUT_SECONDS = 60


def refuse(problems, message):
    problems.append(message)


def resolve_head(repository_root, problems):
    """Return the checked-out commit, or None when git could not decide it."""
    # A runner or caller may carry Git's repository-selection variables. GIT_DIR, GIT_WORK_TREE, and
    # their relatives must not redirect this proof away from repository_root.
    git_environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            capture_output=True,
            env=git_environment,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except OSError as error:
        refuse(problems, "git rev-parse HEAD could not be run in '{0}' ({1}).".format(repository_root, error))
        return None
    except subprocess.TimeoutExpired:
        refuse(problems, "git rev-parse HEAD timed out in '{0}'.".format(repository_root))
        return None
    if completed.returncode != 0:
        refuse(
            problems,
            "git rev-parse HEAD failed in '{0}' with status {1}: {2}".format(
                repository_root, completed.returncode, completed.stderr.strip() or "<no diagnostic>"
            ),
        )
        return None
    head = completed.stdout.strip()
    if not FULL_SHA.fullmatch(head):
        refuse(problems, "git rev-parse HEAD returned '{0}', which is not one full commit SHA.".format(head))
        return None
    return head


def check(expected_sha, event_sha, required_ref, actual_ref, verify_checkout, repository_root):
    """Return the list of identity problems; empty means the run is on the dispatched candidate."""
    problems = []
    if not FULL_SHA.fullmatch(expected_sha):
        refuse(problems, "expected_sha '{0}' must be one full 40-character commit SHA.".format(expected_sha))
    if not FULL_SHA.fullmatch(event_sha):
        refuse(problems, "The event SHA '{0}' is not one full 40-character commit SHA.".format(event_sha))
    if problems:
        return problems

    if expected_sha.lower() != event_sha.lower():
        refuse(
            problems,
            "The dispatch resolved to event SHA {0}, not the expected candidate {1}.".format(event_sha, expected_sha),
        )

    if (required_ref is None) != (actual_ref is None):
        refuse(problems, "--required-ref and --actual-ref are only meaningful together.")
    elif required_ref is not None and actual_ref != required_ref:
        refuse(
            problems,
            "This run is on ref '{0}'. Only '{1}' may proceed.".format(actual_ref, required_ref),
        )

    if verify_checkout:
        head = resolve_head(repository_root, problems)
        if head is not None and head.lower() != expected_sha.lower():
            refuse(
                problems,
                "The working tree is checked out at {0}, not the expected candidate {1}.".format(head, expected_sha),
            )
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Assert a workflow run is operating on the exact dispatched candidate."
    )
    parser.add_argument("--expected-sha", required=True, help="the 40-character candidate SHA the dispatch named")
    parser.add_argument("--event-sha", required=True, help="the commit the event itself resolved to")
    parser.add_argument("--required-ref", help="the only ref permitted to proceed, e.g. refs/heads/main")
    parser.add_argument("--actual-ref", help="the ref this run is on")
    parser.add_argument(
        "--verify-checkout",
        action="store_true",
        help="also resolve HEAD in the working tree and require it to be the candidate",
    )
    parser.add_argument("--repository-root", default=".", help="working tree to resolve HEAD in")
    args = parser.parse_args(argv)

    problems = check(
        args.expected_sha,
        args.event_sha,
        args.required_ref,
        args.actual_ref,
        args.verify_checkout,
        args.repository_root,
    )
    if problems:
        for problem in problems:
            print("::error::{0}".format(problem))
        return 1
    print("Release identity OK: this run is on candidate {0}.".format(args.expected_sha))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
