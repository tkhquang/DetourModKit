#!/usr/bin/env python3
"""Gate the workflow topology that makes the required routes actually required.

A gate is only a gate while nothing above it can swallow its result. Three
shapes have historically turned one into decoration, and all three are one line
to reintroduce:

  - ``continue-on-error: true`` on the job, so a red step reports green
  - ``|| true`` (or a bare ``exit 0`` skip) on the step, so the command's status
    never reaches the runner
  - a conditional that only asserts when the expected output happens to be
    present, so an absent tool or an absent marker passes as coverage

The fourth shape is a release workflow that can publish from a run nobody
audited. The preflight/publish split only means something while the publishing
job is gated on the mode, restricted to ``refs/heads/main``, bound to the exact
dispatched SHA, and the sole holder of the release credential.

This checker reads the tracked workflow files and refuses any of that. It parses
no YAML: it splits the ``jobs:`` mapping by indentation and asserts on the raw
block text, which is what a reviewer reads anyway and what a regression would
show up in. ``scripts/test_check_workflow_topology.py`` pins each refusal by
mutating a workflow back to the advisory shape.

Exit status is 0 when the topology holds, else 1.
"""
import argparse
import os
import re
import sys

QUALITY = ".github/workflows/quality.yml"
SIMD = ".github/workflows/simd-tier-correctness.yml"
RELEASE = ".github/workflows/release.yml"

# Every quality job below is a correctness gate. None of them may be advisory.
BLOCKING_QUALITY_JOBS = ("format-check", "clang-tidy", "header-hygiene", "mechanical-style", "backend-patch")

JOB_HEADER = re.compile(r"^  (?P<name>[A-Za-z0-9_-]+):\s*$")


def job_blocks(text):
    """Return {job name: raw block text} for the top-level `jobs:` mapping."""
    lines = text.splitlines()
    try:
        start = next(index for index, line in enumerate(lines) if line.rstrip() == "jobs:")
    except StopIteration:
        return {}

    blocks = {}
    name = None
    body = []
    for line in lines[start + 1 :]:
        if line and not line[0].isspace():
            break
        header = JOB_HEADER.match(line)
        if header:
            if name is not None:
                blocks[name] = "\n".join(body)
            name = header.group("name")
            body = []
            continue
        if name is not None:
            body.append(line)
    if name is not None:
        blocks[name] = "\n".join(body)
    return blocks


def preamble(text):
    """Return everything above the top-level `jobs:` key."""
    head, separator, _ = text.partition("\njobs:")
    return head if separator else text


def read(root, relative, problems):
    path = os.path.join(root, relative)
    if not os.path.isfile(path):
        problems.append("{0}: workflow is missing".format(relative))
        return None
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def uncommented(block):
    """The block's lines with whole-line and trailing comments removed."""
    kept = []
    for line in block.splitlines():
        stripped = line.split("#", 1)[0]
        if stripped.strip():
            kept.append(stripped)
    return "\n".join(kept)


def dependencies(block):
    """Return one job's single-line `needs` dependencies, or an empty set."""
    match = re.search(r"^\s*needs:\s*(?P<value>[^\n]+?)\s*$", uncommented(block), re.MULTILINE)
    if not match:
        return set()
    value = match.group("value").strip()
    if value.startswith("[") and value.endswith("]"):
        return {item.strip() for item in value[1:-1].split(",") if item.strip()}
    return {value}


def check_quality(text, problems):
    blocks = job_blocks(text)
    for name in BLOCKING_QUALITY_JOBS:
        if name not in blocks:
            problems.append("{0}: job '{1}' is missing".format(QUALITY, name))
            continue
        block = uncommented(blocks[name])
        if "continue-on-error: true" in block:
            problems.append("{0}: job '{1}' is continue-on-error, so its result cannot fail a PR".format(QUALITY, name))
        if "|| true" in block:
            problems.append("{0}: job '{1}' discards a step's exit status with '|| true'".format(QUALITY, name))
        label = re.search(r"^\s*name:\s*(?P<label>.+)$", block, re.MULTILINE)
        if label and "advisory" in label.group("label").lower():
            problems.append("{0}: job '{1}' still calls itself advisory".format(QUALITY, name))

    tidy = uncommented(blocks.get("clang-tidy", ""))
    if tidy and "--warnings-as-errors" not in tidy:
        problems.append(
            "{0}: the clang-tidy job must pass a command-line --warnings-as-errors override, because the "
            "curated .clang-tidy deliberately leaves WarningsAsErrors empty".format(QUALITY)
        )
    if tidy and not re.search(r"--extra-arg(?:-before)?=-Werror(?:\s|$)", tidy):
        problems.append("{0}: clang compiler diagnostics are not promoted with --extra-arg=-Werror".format(QUALITY))
    if tidy and "DMK_HAS_WDANGLING_REFERENCE=OFF" not in tidy:
        problems.append(
            "{0}: the clang-tooling database does not suppress GCC-only -Wdangling-reference".format(QUALITY)
        )
    if tidy and "--target=x86_64-w64-windows-gnu" not in tidy:
        problems.append("{0}: clang-tidy no longer pins the MinGW target triple".format(QUALITY))


def check_simd(text, problems):
    body = uncommented(text)
    if "continue-on-error" in body:
        problems.append("{0}: a continue-on-error marker makes the tier legs advisory".format(SIMD))
    if re.search(r"^\s*exit 0\s*$", body, re.MULTILINE):
        problems.append("{0}: an 'exit 0' skip lets a leg pass without running the tier it covers".format(SIMD))
    for guard, why in (
        ("-not $sdeExe", "a missing Intel SDE must fail the leg, not skip it"),
        ("-not $level", "an absent tier marker must fail the leg, not pass unverified"),
    ):
        index = body.find(guard)
        if index < 0:
            problems.append("{0}: no '{1}' guard; {2}".format(SIMD, guard, why))
            continue
        if "throw" not in body[index : index + 400]:
            problems.append("{0}: the '{1}' guard does not throw; {2}".format(SIMD, guard, why))


def check_release(text, problems):
    head = uncommented(preamble(text))
    if not re.search(r"^\s+mode:\s*$", head, re.MULTILINE):
        problems.append("{0}: no 'mode' dispatch input; preflight and publish cannot be separated".format(RELEASE))
    else:
        if "default: preflight" not in head:
            problems.append("{0}: the 'mode' input must default to preflight, so publishing is opt-in".format(RELEASE))
        for option in ("preflight", "publish"):
            if "- {0}".format(option) not in head:
                problems.append("{0}: the 'mode' input does not offer '{1}'".format(RELEASE, option))

    blocks = job_blocks(text)
    for name in ("validate-version", "build-mingw", "build-msvc", "benchmark-evidence", "create-release"):
        if name not in blocks:
            problems.append("{0}: job '{1}' is missing".format(RELEASE, name))

    publish = uncommented(blocks.get("create-release", ""))
    if publish:
        if not re.search(
            r"^\s*if:\s*\$\{\{\s*inputs\.mode\s*==\s*'publish'\s*\}\}\s*$", publish, re.MULTILINE
        ):
            problems.append(
                "{0}: create-release is not gated on the publish mode, so a preflight run could tag".format(RELEASE)
            )
        if not re.search(r'^\s*DISPATCH_REF:\s*\$\{\{\s*github\.ref\s*\}\}\s*$', publish, re.MULTILINE):
            problems.append("{0}: create-release does not read the exact dispatch ref".format(RELEASE))
        if not re.search(r'^\s*RELEASE_REF="refs/heads/main"\s*$', publish, re.MULTILINE):
            problems.append("{0}: create-release no longer restricts publishing to refs/heads/main".format(RELEASE))
        if not re.search(
            r'if\s+\[\s*"\$\{DISPATCH_REF\}"\s*!=\s*"\$\{RELEASE_REF\}"\s*\]\s*;\s*then', publish
        ):
            problems.append("{0}: create-release no longer refuses a non-main dispatch ref".format(RELEASE))
        if "continue-on-error" in publish:
            problems.append("{0}: create-release is continue-on-error".format(RELEASE))
        publish_needs = dependencies(blocks.get("create-release", ""))
        for required in ("build-mingw", "build-msvc", "benchmark-evidence"):
            if required not in publish_needs:
                problems.append(
                    "{0}: create-release does not need '{1}', so publish could run without it".format(
                        RELEASE, required
                    )
                )
        if "secrets.RELEASE_TOKEN" not in publish:
            problems.append("{0}: create-release has no release credential, so publish cannot complete".format(RELEASE))

    for producer in ("build-mingw", "build-msvc", "benchmark-evidence"):
        if producer in blocks and "validate-version" not in dependencies(blocks[producer]):
            problems.append(
                "{0}: job '{1}' does not need validate-version, so it can build an unvalidated candidate".format(
                    RELEASE, producer
                )
            )

    validate = uncommented(blocks.get("validate-version", ""))
    if validate:
        exact_sha_anchors = (
            r"^\s*EXPECTED_SHA:\s*\$\{\{\s*github\.event\.inputs\.expected_sha\s*\}\}\s*$",
            r"^\s*EVENT_SHA:\s*\$\{\{\s*github\.sha\s*\}\}\s*$",
            r'^\s*CHECKED_OUT_SHA="\$\(git rev-parse HEAD\)"\s*$',
            r'if\s+\[\[\s*!\s*"\$\{EXPECTED_SHA\}"\s*=~\s*\^\[0-9a-fA-F\]\{40\}\$\s*\]\]\s*;\s*then',
            r'if\s+\[\s*"\$\{EXPECTED_SHA,,\}"\s*!=\s*"\$\{EVENT_SHA,,\}"\s*\]\s*\|\|\s*\\?\s*'
            r'\[\s*"\$\{EXPECTED_SHA,,\}"\s*!=\s*"\$\{CHECKED_OUT_SHA,,\}"\s*\]\s*;\s*then',
        )
        if not all(re.search(anchor, validate, re.MULTILINE) for anchor in exact_sha_anchors):
            problems.append("{0}: validate-version no longer proves the exact candidate SHA".format(RELEASE))

    evidence = uncommented(blocks.get("benchmark-evidence", ""))
    if evidence:
        if "continue-on-error" in evidence:
            problems.append("{0}: the benchmark evidence job is advisory".format(RELEASE))
        if "|| true" in evidence:
            problems.append("{0}: the benchmark evidence job discards an exit status with '|| true'".format(RELEASE))
        # The lookbehind keeps the checker's own self-test from standing in for the checker: running
        # test_check_benchmark_results.py proves the parser works, not that this run's output was ever read.
        if not re.search(r"(?<!test_)check_benchmark_results\.py", evidence):
            problems.append(
                "{0}: the benchmark evidence job does not run the result checker, so a benchmark that printed "
                "nothing would pass".format(RELEASE)
            )

    if "secrets.RELEASE_TOKEN" in head:
        problems.append("{0}: workflow-level configuration exposes RELEASE_TOKEN outside create-release".format(RELEASE))

    for name, block in blocks.items():
        if name == "create-release":
            continue
        if "secrets.RELEASE_TOKEN" in uncommented(block):
            problems.append(
                "{0}: job '{1}' holds RELEASE_TOKEN; only the audited publish job may".format(RELEASE, name)
            )


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gate the blocking-route and release-publication workflow topology.")
    parser.add_argument("--repository-root", default=".", help="repository root holding .github/workflows")
    args = parser.parse_args(argv)

    problems = []
    for relative, check in ((QUALITY, check_quality), (SIMD, check_simd), (RELEASE, check_release)):
        text = read(args.repository_root, relative, problems)
        if text is not None:
            check(text, problems)

    if problems:
        print("Workflow topology rejected:")
        for problem in problems:
            print("  {0}".format(problem))
        return 1
    print("Workflow topology OK: required routes are blocking and publishing stays main/exact-SHA/publish-mode only.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
