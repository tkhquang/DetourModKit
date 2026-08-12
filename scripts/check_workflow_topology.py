#!/usr/bin/env python3
"""Gate the workflow topology that makes the required routes actually required.

This is a deliberately small, fail-closed reader for the canonical workflow
shape used by this repository. It scopes mapping keys and steps by indentation
instead of treating their spelling anywhere in a job as evidence. Release-
critical shell fragments are then pinned as exact commands or exact guards.

It does not claim to interpret arbitrary shell programs. It rejects the known
fail-open constructs that have permanent controls here, while exact command
checks protect the producer proofs and publication boundary.

Exit status is 0 when the topology holds, else 1.
"""
import argparse
import os
import re
import shlex
import sys
from dataclasses import dataclass


QUALITY = ".github/workflows/quality.yml"
SIMD = ".github/workflows/simd-tier-correctness.yml"
RELEASE = ".github/workflows/release.yml"

BLOCKING_QUALITY_JOBS = ("format-check", "clang-tidy", "header-hygiene", "mechanical-style", "backend-patch")
REQUIRED_RELEASE_JOBS = ("validate-version", "build-mingw", "build-msvc", "benchmark-evidence", "create-release")
PUBLISH_MODE_CONDITION = "${{ inputs.mode == 'publish' }}"

EXACT_SHA_STEP = "Assert the dispatch resolved to the exact candidate"
REF_GUARD_STEP = "Assert the dispatch ref may publish a tag"
TAG_STEP = "Create or verify annotated tag"

SAME_BASE_CASE = "MemoryTest.ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent"
SAME_BASE_PROPERTY = "dmk_same_base_replacement=executed"

MAPPING_LINE = re.compile(
    r"^(?P<spaces> *)(?P<key>[A-Za-z0-9_-]+|'[^']+'|\"[^\"]+\")\s*:\s*(?P<value>.*?)\s*$"
)
STEP_LINE = re.compile(r"^ {6}-\s+(?P<body>.+?)\s*$")
SECRET_EXPRESSION = re.compile(r"\$\{\{[^}\n]*\bsecrets\s*(?:\.|\[)", re.IGNORECASE)
CANONICAL_RELEASE_TOKEN = re.compile(r"\$\{\{\s*secrets\.RELEASE_TOKEN\s*\}\}")
CAPTURED_SUBSTITUTION = re.compile(
    r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)=\"?\$\((?P<body>.*)\)\"?\s*$"
)

ALLOWED_FAILURE_CAPTURES = {
    r'''TEST_MAJOR="$(grep -m1 -oP 'DMK_VERSION_MAJOR,\s*\K[0-9]+' tests/test_version.cpp || true)"''',
    r'''TEST_MINOR="$(grep -m1 -oP 'DMK_VERSION_MINOR,\s*\K[0-9]+' tests/test_version.cpp || true)"''',
    r'''TEST_PATCH="$(grep -m1 -oP 'DMK_VERSION_PATCH,\s*\K[0-9]+' tests/test_version.cpp || true)"''',
}


@dataclass(frozen=True)
class Entry:
    """One direct mapping entry in a workflow block."""

    key: str
    value: str
    line: int
    indent: int


@dataclass
class StepBlock:
    """One parsed step and its direct keys."""

    start: int
    end: int
    entries: dict
    run: str = ""

    @property
    def name(self):
        entry = self.entries.get("name")
        return scalar(entry) if entry else None


@dataclass
class JobBlock:
    """One parsed job and its direct keys and steps."""

    name: str
    start: int
    end: int
    entries: dict
    steps: list


@dataclass
class Workflow:
    """The structurally relevant parts of one workflow."""

    relative: str
    lines: list
    entries: dict
    jobs: dict
    jobs_start: int
    jobs_end: int


def read(root, relative, problems):
    path = os.path.join(root, relative)
    if not os.path.isfile(path):
        problems.append("{0}: workflow is missing".format(relative))
        return None
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def strip_comment(line):
    """Return the line up to its first unquoted comment marker."""
    quote = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
        elif character in "'\"":
            quote = character
        elif character == "#":
            return line[:index]
    return line


def uncommented(block):
    """Return nonempty lines with YAML comments removed."""
    kept = []
    for line in block.splitlines():
        stripped = strip_comment(line)
        if stripped.strip():
            kept.append(stripped)
    return "\n".join(kept)


def leading_spaces(line):
    return len(line) - len(line.lstrip(" "))


def normalized_key(token):
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "'\"":
        return token[1:-1]
    return token


def parse_mapping_line(line, indent):
    text = strip_comment(line)
    match = MAPPING_LINE.match(text)
    if not match or len(match.group("spaces")) != indent:
        return None
    return Entry(normalized_key(match.group("key")), match.group("value"), -1, indent)


def block_end(lines, line, parent_end, indent):
    """Return the first later non-comment line outside an entry's child block."""
    for index in range(line + 1, parent_end):
        text = strip_comment(lines[index])
        if not text.strip():
            continue
        if leading_spaces(text) <= indent:
            return index
    return parent_end


def direct_entries(lines, start, end, indent, relative, context, problems):
    """Parse mapping entries at exactly one indentation level."""
    entries = {}
    for index in range(start, end):
        text = strip_comment(lines[index])
        if not text.strip() or leading_spaces(text) != indent:
            continue
        parsed = parse_mapping_line(text, indent)
        if parsed is None:
            problems.append(
                "{0}:{1}: unreadable direct key in {2}; the topology cannot be checked".format(
                    relative, index + 1, context
                )
            )
            continue
        entry = Entry(parsed.key, parsed.value, index, indent)
        if entry.key in entries:
            problems.append(
                "{0}:{1}: duplicate direct key '{2}' in {3}".format(relative, index + 1, entry.key, context)
            )
            continue
        entries[entry.key] = entry
    return entries


def parse_step(lines, start, end, relative, problems):
    match = STEP_LINE.match(strip_comment(lines[start]))
    entries = {}
    if not match:
        problems.append("{0}:{1}: unreadable workflow step".format(relative, start + 1))
        return StepBlock(start, end, entries)

    first = parse_mapping_line(match.group("body"), 0)
    if first is None:
        problems.append("{0}:{1}: a workflow step must begin with a mapping key".format(relative, start + 1))
    else:
        entries[first.key] = Entry(first.key, first.value, start, 6)

    following = direct_entries(lines, start + 1, end, 8, relative, "workflow step", problems)
    for key, entry in following.items():
        if key in entries:
            problems.append("{0}:{1}: duplicate step key '{2}'".format(relative, entry.line + 1, key))
        else:
            entries[key] = entry

    step = StepBlock(start, end, entries)
    run_entry = entries.get("run")
    if run_entry is not None:
        value = run_entry.value.strip()
        if value.startswith("|") or value.startswith(">"):
            run_end = block_end(lines, run_entry.line, end, run_entry.indent)
            content_indent = run_entry.indent + 2
            content = []
            for line in lines[run_entry.line + 1 : run_end]:
                if line.strip():
                    content.append(line[content_indent:] if len(line) >= content_indent else line.lstrip())
                else:
                    content.append("")
            step.run = "\n".join(content).strip("\n")
        else:
            step.run = scalar(run_entry)
    return step


def parse_steps(lines, entry, job_end, relative, problems):
    if entry.value.strip():
        problems.append("{0}:{1}: steps must use the canonical block sequence form".format(relative, entry.line + 1))
        return []
    end = block_end(lines, entry.line, job_end, entry.indent)
    starts = []
    for index in range(entry.line + 1, end):
        text = strip_comment(lines[index])
        if not text.strip() or leading_spaces(text) != 6:
            continue
        if not STEP_LINE.match(text):
            problems.append("{0}:{1}: unreadable workflow step".format(relative, index + 1))
            continue
        starts.append(index)
    return [
        parse_step(lines, start, starts[offset + 1] if offset + 1 < len(starts) else end, relative, problems)
        for offset, start in enumerate(starts)
    ]


def parse_workflow(text, relative, problems):
    """Parse direct workflow, job, and step keys without a third-party YAML dependency."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        prefix = line[: len(line) - len(line.lstrip())]
        if "\t" in prefix:
            problems.append("{0}:{1}: tabs make workflow indentation ambiguous".format(relative, index + 1))

    entries = direct_entries(lines, 0, len(lines), 0, relative, "workflow", problems)
    jobs_entry = entries.get("jobs")
    if jobs_entry is None or jobs_entry.value.strip():
        return Workflow(relative, lines, entries, {}, len(lines), len(lines))

    jobs_end = block_end(lines, jobs_entry.line, len(lines), 0)
    headers = direct_entries(lines, jobs_entry.line + 1, jobs_end, 2, relative, "jobs mapping", problems)
    jobs = {}
    ordered = sorted(headers.values(), key=lambda item: item.line)
    for offset, header in enumerate(ordered):
        end = ordered[offset + 1].line if offset + 1 < len(ordered) else jobs_end
        if header.value.strip():
            problems.append(
                "{0}:{1}: job '{2}' must use the canonical block mapping form".format(
                    relative, header.line + 1, header.key
                )
            )
        job_entries = direct_entries(
            lines, header.line + 1, end, 4, relative, "job '{0}'".format(header.key), problems
        )
        steps_entry = job_entries.get("steps")
        steps = parse_steps(lines, steps_entry, end, relative, problems) if steps_entry else []
        jobs[header.key] = JobBlock(header.key, header.line, end, job_entries, steps)
    return Workflow(relative, lines, entries, jobs, jobs_entry.line, jobs_end)


def scalar(entry):
    if entry is None:
        return None
    value = entry.value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def child_entries(workflow, entry, parent_end, indent, context, problems):
    if entry is None or entry.value.strip():
        return {}
    end = block_end(workflow.lines, entry.line, parent_end, entry.indent)
    return direct_entries(workflow.lines, entry.line + 1, end, indent, workflow.relative, context, problems)


def sequence_values(workflow, entry, parent_end, indent, problems):
    if entry is None or entry.value.strip():
        return []
    end = block_end(workflow.lines, entry.line, parent_end, entry.indent)
    values = []
    for index in range(entry.line + 1, end):
        text = strip_comment(workflow.lines[index])
        if not text.strip() or leading_spaces(text) != indent:
            continue
        match = re.match(r"^ {%d}-\s*(?P<value>\S.*?)\s*$" % indent, text)
        if not match:
            problems.append("{0}:{1}: unreadable sequence item".format(workflow.relative, index + 1))
            continue
        value = match.group("value")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values.append(value)
    return values


def job_text(workflow, job):
    return uncommented("\n".join(workflow.lines[job.start + 1 : job.end]))


def step_text(workflow, step):
    return uncommented("\n".join(workflow.lines[step.start : step.end]))


def step_by_name(relative, job, name, problems, missing_message):
    matches = [step for step in job.steps if step.name == name]
    if len(matches) != 1:
        problems.append(
            missing_message
            if not matches
            else "{0}: job '{1}' has {2} steps named '{3}'; one proof is required".format(
                relative, job.name, len(matches), name
            )
        )
        return None
    return matches[0]


def logical_lines(script, continuation):
    """Join one workflow shell's explicit physical-line continuations."""
    result = []
    pending = ""
    for raw in script.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = (pending + " " + line).strip() if pending else line
        if pending.endswith(continuation):
            pending = pending[: -len(continuation)].rstrip()
            continue
        result.append(" ".join(pending.split()))
        pending = ""
    if pending:
        result.append(" ".join(pending.split()))
    return result


def shell_tokens(line):
    lexer = shlex.shlex(line, posix=True, punctuation_chars="|;&()")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)


def bash_commands(script, relative, job, what, problems):
    commands = []
    try:
        for line in logical_lines(script, "\\"):
            commands.append(tuple(shell_tokens(line)))
    except ValueError as error:
        problems.append("{0}: job '{1}' has an unreadable {2} command ({3})".format(relative, job, what, error))
        return []
    return commands


def run_fail_open_reason(step, allow_success_exit=False):
    """Return one known fail-open spelling, without interpreting arbitrary shell."""
    shell = (scalar(step.entries.get("shell")) or "bash").lower()
    continuation = "^" if shell == "cmd" else "\\"
    for line in logical_lines(step.run, continuation):
        capture = CAPTURED_SUBSTITUTION.match(line)
        if capture and re.search(r"\|\|\s*(?:true|:)(?:\s|$)", capture.group("body")):
            if line not in ALLOWED_FAILURE_CAPTURES:
                return "captured command substitution ending in success"
        try:
            tokens = shell_tokens(line)
        except ValueError:
            return "unreadable shell quoting"
        for index, token in enumerate(tokens):
            if token == "||" and index + 1 < len(tokens) and tokens[index + 1] in ("true", ":"):
                return "'{0} {1}'".format(token, tokens[index + 1])
            if token in ("exit", "return") and index + 1 < len(tokens) and tokens[index + 1].isdigit():
                if int(tokens[index + 1]) == 0 and not allow_success_exit:
                    return "bare 'exit 0'"
            if (
                token.lower() == "exit"
                and index + 2 < len(tokens)
                and tokens[index + 1].lower() == "/b"
                and tokens[index + 2].isdigit()
                and int(tokens[index + 2]) == 0
            ):
                return "'exit /b 0'"
        if len(tokens) >= 2 and tokens[0].lower() == "set" and tokens[1] == "+e":
            return "'set +e'"
    return None


def dependencies(workflow, job, problems):
    entry = job.entries.get("needs")
    if entry is None:
        return set()
    value = scalar(entry)
    if value.startswith("[") and value.endswith("]"):
        return {item.strip().strip("'\"") for item in value[1:-1].split(",") if item.strip()}
    if value:
        return {value.strip("'\"")}
    return set(sequence_values(workflow, entry, job.end, 6, problems))


def check_required_job(relative, workflow, name, problems, condition=None, allowed_success_step=None):
    """Apply the policy shared by every required job."""
    job = workflow.jobs.get(name)
    if job is None:
        problems.append("{0}: job '{1}' is missing".format(relative, name))
        return None
    if not job.entries or not job.steps:
        problems.append(
            "{0}: job '{1}' has no readable body, so none of its required guards could be checked".format(
                relative, name
            )
        )
        return job

    if "continue-on-error" in job.entries:
        problems.append(
            "{0}: job '{1}' carries a continue-on-error marker, so a red step reports green".format(relative, name)
        )
    observed = scalar(job.entries.get("if"))
    if observed != condition:
        if name == "create-release":
            problems.append(
                "{0}: job 'create-release' is gated on '{1}' and is not gated on the publish mode, so a "
                "preflight run could tag".format(relative, observed)
            )
        else:
            problems.append(
                "{0}: job '{1}' is gated on '{2}', expected {3}".format(
                    relative, name, observed, "'{0}'".format(condition) if condition else "no job-level condition"
                )
            )
    label = scalar(job.entries.get("name")) or ""
    if "advisory" in label.lower():
        problems.append("{0}: job '{1}' still calls itself advisory".format(relative, name))

    for step in job.steps:
        if "continue-on-error" in step.entries:
            problems.append(
                "{0}: step '{1}' in job '{2}' carries a continue-on-error marker, so a red step reports green".format(
                    relative, step.name or "<unnamed>", name
                )
            )
        if not step.run:
            continue
        reason = run_fail_open_reason(step, allow_success_exit=step.name == allowed_success_step)
        if reason is None:
            continue
        if reason == "bare 'exit 0'":
            problems.append(
                "{0}: job '{1}' has a bare 'exit 0' skip, which passes without running what it covers".format(
                    relative, name
                )
            )
        elif "||" in reason or "captured" in reason:
            problems.append(
                "{0}: job '{1}' discards a step's exit status with {2}".format(relative, name, reason)
            )
        else:
            problems.append("{0}: job '{1}' contains fail-open shell construct {2}".format(relative, name, reason))
    return job


def check_quality(text, problems):
    workflow = parse_workflow(text, QUALITY, problems)
    for name in BLOCKING_QUALITY_JOBS:
        check_required_job(QUALITY, workflow, name, problems)

    tidy = workflow.jobs.get("clang-tidy")
    body = job_text(workflow, tidy) if tidy else ""
    if body and "--warnings-as-errors" not in body:
        problems.append(
            "{0}: the clang-tidy job must pass a command-line --warnings-as-errors override, because the "
            "curated .clang-tidy deliberately leaves WarningsAsErrors empty".format(QUALITY)
        )
    if body and not re.search(r"--extra-arg(?:-before)?=-Werror(?:\s|$)", body):
        problems.append("{0}: clang compiler diagnostics are not promoted with --extra-arg=-Werror".format(QUALITY))
    if body and "DMK_HAS_WDANGLING_REFERENCE=OFF" not in body:
        problems.append(
            "{0}: the clang-tooling database does not suppress GCC-only -Wdangling-reference".format(QUALITY)
        )
    if body and "--target=x86_64-w64-windows-gnu" not in body:
        problems.append("{0}: clang-tidy no longer pins the MinGW target triple".format(QUALITY))


def check_simd(text, problems):
    workflow = parse_workflow(text, SIMD, problems)
    for job in workflow.jobs.values():
        if "continue-on-error" in job.entries or any("continue-on-error" in step.entries for step in job.steps):
            problems.append("{0}: a continue-on-error marker makes the tier legs advisory".format(SIMD))
        if any(step.run and run_fail_open_reason(step) == "bare 'exit 0'" for step in job.steps):
            problems.append("{0}: an 'exit 0' skip lets a leg pass without running the tier it covers".format(SIMD))

    body = uncommented(text)
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


def check_mode(workflow, problems):
    on_entry = workflow.entries.get("on")
    on_entries = child_entries(workflow, on_entry, workflow.jobs_start, 2, "on mapping", problems)
    dispatch = on_entries.get("workflow_dispatch")
    dispatch_end = block_end(workflow.lines, dispatch.line, workflow.jobs_start, 2) if dispatch else 0
    dispatch_entries = child_entries(workflow, dispatch, dispatch_end, 4, "workflow_dispatch mapping", problems)
    inputs = dispatch_entries.get("inputs")
    inputs_end = block_end(workflow.lines, inputs.line, dispatch_end, 4) if inputs else 0
    input_entries = child_entries(workflow, inputs, inputs_end, 6, "workflow_dispatch inputs", problems)
    mode = input_entries.get("mode")
    if mode is None:
        problems.append("{0}: no 'mode' dispatch input; preflight and publish cannot be separated".format(RELEASE))
        return
    mode_end = block_end(workflow.lines, mode.line, inputs_end, 6)
    fields = child_entries(workflow, mode, mode_end, 8, "mode input", problems)
    if scalar(fields.get("default")) != "preflight":
        problems.append("{0}: the 'mode' input must default to preflight, so publishing is opt-in".format(RELEASE))
    if scalar(fields.get("required")) != "true" or scalar(fields.get("type")) != "choice":
        problems.append("{0}: the 'mode' input must be a required choice".format(RELEASE))
    options = sequence_values(workflow, fields.get("options"), mode_end, 10, problems)
    for option in ("preflight", "publish"):
        if option not in options:
            problems.append("{0}: the 'mode' input does not offer '{1}'".format(RELEASE, option))
    if set(options) != {"preflight", "publish"} or len(options) != 2:
        problems.append("{0}: the 'mode' input offers an unreviewed mode".format(RELEASE))


def step_env(workflow, step, problems):
    entry = step.entries.get("env")
    return child_entries(workflow, entry, step.end, 10, "step environment", problems)


def exact_environment(workflow, step, expected, problems):
    observed = step_env(workflow, step, problems)
    return all(scalar(observed.get(key)) == value for key, value in expected.items())


def guard_exits_nonzero(lines, condition):
    positions = [index for index, line in enumerate(lines) if line == condition]
    if len(positions) != 1:
        return False
    start = positions[0]
    for index in range(start + 1, len(lines)):
        if lines[index] == "fi":
            return "exit 1" in lines[start + 1 : index] and "exit 0" not in lines[start + 1 : index]
    return False


def check_exact_sha(workflow, job, problems):
    message = "{0}: validate-version no longer proves the exact candidate SHA".format(RELEASE)
    step = step_by_name(RELEASE, job, EXACT_SHA_STEP, problems, message)
    if step is None:
        return
    lines = logical_lines(step.run, "\\")
    correct = scalar(step.entries.get("shell")) == "bash"
    correct = correct and "if" not in step.entries and "continue-on-error" not in step.entries
    correct = correct and exact_environment(
        workflow,
        step,
        {"EXPECTED_SHA": "${{ github.event.inputs.expected_sha }}", "EVENT_SHA": "${{ github.sha }}"},
        problems,
    )
    correct = correct and 'CHECKED_OUT_SHA="$(git rev-parse HEAD)"' in lines
    correct = correct and guard_exits_nonzero(
        lines, 'if [[ ! "${EXPECTED_SHA}" =~ ^[0-9a-fA-F]{40}$ ]]; then'
    )
    correct = correct and guard_exits_nonzero(
        lines,
        'if [ "${EXPECTED_SHA,,}" != "${EVENT_SHA,,}" ] || '
        '[ "${EXPECTED_SHA,,}" != "${CHECKED_OUT_SHA,,}" ]; then',
    )
    if not correct:
        problems.append(message)


def check_ref_guard(workflow, job, problems):
    missing = "{0}: create-release no longer refuses a non-main dispatch ref".format(RELEASE)
    step = step_by_name(RELEASE, job, REF_GUARD_STEP, problems, missing)
    if step is None:
        return
    env = exact_environment(
        workflow,
        step,
        {"DISPATCH_REF": "${{ github.ref }}", "DISPATCH_SHA": "${{ github.sha }}"},
        problems,
    )
    if not env:
        problems.append("{0}: create-release does not read the exact dispatch ref".format(RELEASE))
    lines = logical_lines(step.run, "\\")
    if 'RELEASE_REF="refs/heads/main"' not in lines:
        problems.append("{0}: create-release no longer restricts publishing to refs/heads/main".format(RELEASE))
    if not guard_exits_nonzero(lines, 'if [ "${DISPATCH_REF}" != "${RELEASE_REF}" ]; then'):
        problems.append(missing)


def check_tag_target(workflow, job, problems):
    message = "{0}: create-release no longer tags the exact dispatched candidate SHA".format(RELEASE)
    step = step_by_name(RELEASE, job, TAG_STEP, problems, message)
    if step is None:
        return
    lines = logical_lines(step.run, "\\")
    correct = scalar(step.entries.get("shell")) in (None, "bash")
    correct = correct and "if" not in step.entries and "continue-on-error" not in step.entries
    correct = correct and exact_environment(workflow, step, {"EXPECTED_SHA": "${{ github.sha }}"}, problems)
    correct = correct and guard_exits_nonzero(
        lines, 'if [ "${REMOTE_TARGET}" != "${EXPECTED_SHA}" ]; then'
    )
    correct = correct and lines.count("exit 0") == 1
    correct = correct and 'git tag -a "$VERSION" -m "$TAG_MESSAGE" "${EXPECTED_SHA}"' in lines
    correct = correct and 'git push origin "refs/tags/${VERSION}"' in lines
    if not correct:
        problems.append(message)


def check_exact_bash_step(workflow, job, name, expected, what, problems):
    message = (
        "{0}: job '{1}' does not run {2}, so the candidate it packages was never held to it".format(
            RELEASE, job.name, what
        )
    )
    step = step_by_name(RELEASE, job, name, problems, message)
    if step is None:
        return
    commands = bash_commands(step.run, RELEASE, job.name, what, problems)
    if (
        scalar(step.entries.get("shell")) != "bash"
        or "if" in step.entries
        or "continue-on-error" in step.entries
        or commands != expected
    ):
        problems.append(message)


def check_exact_cmd_step(job, name, expected, what, problems):
    message = (
        "{0}: job '{1}' does not run {2}, so the candidate it packages was never held to it".format(
            RELEASE, job.name, what
        )
    )
    step = step_by_name(RELEASE, job, name, problems, message)
    if step is None:
        return
    commands = logical_lines(step.run, "^")
    if (
        scalar(step.entries.get("shell")) != "cmd"
        or "if" in step.entries
        or "continue-on-error" in step.entries
        or commands != expected
    ):
        problems.append(message)


def check_producer_proofs(workflow, problems):
    case_args = ("--case", SAME_BASE_CASE, "--property", SAME_BASE_PROPERTY)
    mingw = workflow.jobs.get("build-mingw")
    if mingw:
        check_exact_bash_step(
            workflow,
            mingw,
            "Assert the same-base replacement case executed (MinGW Release)",
            [
                (
                    "python",
                    "scripts/check_gtest_execution.py",
                    "build/mingw-release/dmk_same_base_replacement.xml",
                )
                + case_args
            ],
            "the exact same-base execution check",
            problems,
        )
        check_exact_bash_step(
            workflow,
            mingw,
            "Build-Tree Consumer Proof (MinGW)",
            [
                (
                    "cmake",
                    "-S",
                    "tests/package_build_tree",
                    "-B",
                    "build/package-build-tree-mingw",
                    "-G",
                    "Ninja",
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DCMAKE_C_COMPILER=gcc",
                    "-DCMAKE_CXX_COMPILER=g++",
                    "-DDMK_WARNINGS_AS_ERRORS=ON",
                ),
                ("cmake", "--build", "build/package-build-tree-mingw", "--parallel", "4"),
                ("ctest", "--test-dir", "build/package-build-tree-mingw", "--output-on-failure"),
            ],
            "the build-tree consumer proof",
            problems,
        )

    msvc = workflow.jobs.get("build-msvc")
    if msvc:
        check_exact_bash_step(
            workflow,
            msvc,
            "Assert the same-base replacement case executed (MSVC Release)",
            [
                (
                    "python",
                    "scripts/check_gtest_execution.py",
                    "build/msvc-release/dmk_same_base_replacement.xml",
                )
                + case_args
            ],
            "the exact same-base execution check",
            problems,
        )
        check_exact_cmd_step(
            msvc,
            "Build-Tree Consumer Proof (MSVC)",
            [
                "cmake -S tests/package_build_tree -B build/package-build-tree-msvc -G Ninja "
                "-DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl "
                "-DDMK_WARNINGS_AS_ERRORS=ON",
                "if errorlevel 1 exit /b 1",
                "cmake --build build/package-build-tree-msvc --parallel 2",
                "if errorlevel 1 exit /b 1",
                "ctest --test-dir build/package-build-tree-msvc --output-on-failure",
            ],
            "the build-tree consumer proof",
            problems,
        )


def check_benchmark_route(workflow, job, problems):
    """Pin the release capture checker and the compiled ledger boundary it depends on."""
    build_message = (
        "{0}: benchmark-evidence does not build all four benchmarks and the compiled ledger probe".format(RELEASE)
    )
    build = step_by_name(
        RELEASE,
        job,
        "Configure and build the benchmarks (MinGW Release)",
        problems,
        build_message,
    )
    if build is not None:
        commands = bash_commands(build.run, RELEASE, job.name, "benchmark producer build", problems)
        expected = [
            ("cmake", "--preset", "mingw-release", "-DDMK_BUILD_BENCHMARKS=ON"),
            (
                "cmake",
                "--build",
                "build/mingw-release",
                "--parallel",
                "--target",
                "DetourModKit_bench",
                "DetourModKit_bench_scanner",
                "DetourModKit_bench_memory",
                "DetourModKit_bench_logger",
                "dmk_bench_gate_probe",
            ),
        ]
        if scalar(build.entries.get("shell")) != "bash" or "if" in build.entries or commands != expected:
            problems.append(build_message)

    check_message = (
        "{0}: benchmark-evidence does not run the exact capture checker and compiled ledger self-test".format(
            RELEASE
        )
    )
    check = step_by_name(RELEASE, job, "Check the recorded evidence", problems, check_message)
    if check is None:
        return
    commands = bash_commands(check.run, RELEASE, job.name, "benchmark evidence check", problems)
    expected = [
        ("LEDGER_PROBE=$(find build/mingw-release -name 'dmk_bench_gate_probe.exe' -type f | head -n 1)",),
        ("if", "[", "-z", "${LEDGER_PROBE}", "]", ";", "then"),
        (
            "echo",
            "::error::No dmk_bench_gate_probe.exe under build/mingw-release; the producer boundary was not built.",
        ),
        ("exit", "1"),
        ("fi",),
        ("python", "scripts/test_check_benchmark_results.py", "--ledger-probe", "${LEDGER_PROBE}"),
        (
            "python",
            "scripts/check_benchmark_results.py",
            "bench-results/*.txt",
            "--require",
            "scanner.scenario_anchor_agreement",
            "--require",
            "scanner.verify_workload_no_match",
            "--require",
            "scanner.resolver_batch_matches_serial",
            "--require",
            "memory.chain_walk_resolves_leaf",
            "--require",
            "logger.enqueue_reached_the_queue",
            "--require",
            "dispatcher.reentrant_subscribe_rejected",
        ),
    ]
    if scalar(check.entries.get("shell")) != "bash" or "if" in check.entries or commands != expected:
        problems.append(check_message)


def check_credentials(workflow, publish, problems):
    outside = []
    for index, line in enumerate(workflow.lines):
        if publish and publish.start <= index < publish.end:
            continue
        if SECRET_EXPRESSION.search(strip_comment(line)):
            outside.append(index)
    for index in outside:
        owner = next(
            (job.name for job in workflow.jobs.values() if job.start <= index < job.end),
            None,
        )
        if owner:
            problems.append(
                "{0}: job '{1}' holds a release credential; only the audited publish job may".format(RELEASE, owner)
            )
        else:
            problems.append(
                "{0}: workflow-level configuration exposes RELEASE_TOKEN outside create-release".format(RELEASE)
            )

    if publish is None:
        return
    body = job_text(workflow, publish)
    canonical = list(CANONICAL_RELEASE_TOKEN.finditer(body))
    remainder = CANONICAL_RELEASE_TOKEN.sub("", body)
    locations_hold = True
    for name in ("Checkout code for annotated tag", "Create GitHub Release"):
        matches = [step for step in publish.steps if step.name == name]
        if len(matches) != 1:
            locations_hold = False
            continue
        fields = child_entries(
            workflow,
            matches[0].entries.get("with"),
            matches[0].end,
            10,
            "credentialed step inputs",
            problems,
        )
        if scalar(fields.get("token")) != "${{ secrets.RELEASE_TOKEN }}":
            locations_hold = False
    if len(canonical) != 2 or SECRET_EXPRESSION.search(remainder) or not locations_hold:
        problems.append(
            "{0}: create-release must hold exactly the two reviewed RELEASE_TOKEN uses".format(RELEASE)
        )


def check_release(text, problems):
    workflow = parse_workflow(text, RELEASE, problems)
    check_mode(workflow, problems)

    jobs = {}
    for name in REQUIRED_RELEASE_JOBS:
        jobs[name] = check_required_job(
            RELEASE,
            workflow,
            name,
            problems,
            condition=PUBLISH_MODE_CONDITION if name == "create-release" else None,
            allowed_success_step=TAG_STEP if name == "create-release" else None,
        )

    expected_dependencies = {
        "validate-version": set(),
        "build-mingw": {"validate-version"},
        "build-msvc": {"validate-version"},
        "benchmark-evidence": {"validate-version"},
        "create-release": {"build-mingw", "build-msvc", "benchmark-evidence"},
    }
    for name, expected in expected_dependencies.items():
        job = jobs.get(name)
        if job is None:
            continue
        observed = dependencies(workflow, job, problems)
        for required in sorted(expected - observed):
            if name == "create-release":
                problems.append(
                    "{0}: create-release does not need '{1}', so publish could run without it".format(
                        RELEASE, required
                    )
                )
            elif required == "validate-version":
                problems.append(
                    "{0}: job '{1}' does not need validate-version, so it can build an unvalidated candidate".format(
                        RELEASE, name
                    )
                )
            else:
                # Every reviewed dependency is refused by name. Without this the map could gain an edge that no
                # branch reports, which is a dependency the checker silently stops requiring.
                problems.append(
                    "{0}: job '{1}' does not need '{2}'".format(RELEASE, name, required)
                )
        if observed - expected:
            problems.append("{0}: job '{1}' has unreviewed dependencies".format(RELEASE, name))

    validate = jobs.get("validate-version")
    publish = jobs.get("create-release")
    if validate:
        check_exact_sha(workflow, validate, problems)
    if publish:
        check_ref_guard(workflow, publish, problems)
        check_tag_target(workflow, publish, problems)

    check_producer_proofs(workflow, problems)

    evidence = jobs.get("benchmark-evidence")
    if evidence:
        check_benchmark_route(workflow, evidence, problems)
        if not re.search(r"(?<!test_)check_benchmark_results\.py", job_text(workflow, evidence)):
            problems.append(
                "{0}: the benchmark evidence job does not run the result checker, so a benchmark that printed "
                "nothing would pass".format(RELEASE)
            )
    check_credentials(workflow, publish, problems)


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
