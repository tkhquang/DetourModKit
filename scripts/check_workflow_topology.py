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
MINGW_SOAK_STEP = "Run dump-capturing lifecycle soak (MinGW Release)"
MSVC_SOAK_STEP = "Run dump-capturing lifecycle soak (MSVC Release)"

# A step that does not run cannot fail, so a step-level condition on a required command is a guard reporting green
# without having run. Only these exact tuples are reviewed; every other step in a required job must be unconditional.
# Each reviewed condition either strengthens the step (`!cancelled()` keeps a later gate reporting after an earlier
# failure, so the report is complete) or guards a diagnostics upload, and none of them can skip a guard on a run that
# is otherwise passing. Keyed by step name, so a load-bearing step cannot borrow a reviewed entry without also
# colliding with the exact-name lookups that pin the reviewed step.
REVIEWED_STEP_CONDITIONS = {
    (QUALITY, "format-check", "Check comment-marker conventions"): "${{ !cancelled() }}",
    (QUALITY, "backend-patch", "Check the pristine pinned backend input"): "${{ !cancelled() }}",
    (QUALITY, "backend-patch", "Apply the vendored patch the way a configure does"): "${{ !cancelled() }}",
    (QUALITY, "backend-patch", "Re-run the configure boundary on the configured backend"): "${{ !cancelled() }}",
    (QUALITY, "backend-patch", "Check the configured backend equals the reviewed patch output"): "${{ !cancelled() }}",
    (RELEASE, "build-mingw", "Install MinGW (if not cached)"): "steps.cache-mingw.outputs.cache-hit != 'true'",
    (RELEASE, "build-mingw", "Upload MinGW lifecycle failure diagnostics"): "failure()",
    (RELEASE, "build-msvc", "Upload MSVC lifecycle failure diagnostics"): "failure()",
    (RELEASE, "benchmark-evidence", "Install MinGW (if not cached)"): "steps.cache-mingw.outputs.cache-hit != 'true'",
    (RELEASE, "benchmark-evidence", "Upload benchmark evidence"): "${{ !cancelled() }}",
}

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

# GitHub's default shell is PowerShell on a Windows runner and bash elsewhere, so a step that omits `shell` is read
# under the shell its job would really run it with. Reading a PowerShell step as bash picks the wrong continuation
# marker, which is enough to hide a command name split across a backtick-newline.
POWERSHELL_SHELLS = ("pwsh", "powershell")
LEXICAL_CONTINUATIONS = ("\\", "`")

# The only place `||` joins operands without deciding a required command's exit status: a shell test compound in a
# conditional head, where both sides are `[`/`[[` tests rather than the work the step exists to run.
CONDITIONAL_HEADS = ("if", "elif", "while", "until")
SHELL_TEST_OPENERS = ("[", "[[")
SHELL_TEST_CLOSERS = {"[": "]", "[[": "]]"}

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
    join_without_space = False
    for raw in script.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if pending:
            pending += ("" if join_without_space else " ") + line
            join_without_space = False
        else:
            pending = line
        # Bash removes a backslash-newline without inserting whitespace, and PowerShell removes a backtick-newline the
        # same way; preserving that lexical join matters for a command substitution such as `$\` + `(cmd)` and for a
        # command name split as `Write-` + `Warning`. cmd's caret separates ordinary tokens instead.
        if pending.endswith(continuation):
            pending = pending[: -len(continuation)]
            if continuation not in LEXICAL_CONTINUATIONS:
                pending = pending.rstrip()
            join_without_space = continuation in LEXICAL_CONTINUATIONS
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


def shell_test_condition_boundary(tokens, line):
    """Return the conditional-head boundary when every operand is one bracket test, otherwise -1."""
    if not tokens or tokens[0] not in CONDITIONAL_HEADS:
        return -1
    # A bracket test can execute work through command or process substitution. Such a command's status becomes data
    # inside the test, and a true test on the right can still normalize the failure, so it is not the inert carve-out.
    if any(spelling in line for spelling in ("$(", "`", "<(", ">(")):
        return -1
    expected_tail = "then" if tokens[0] in ("if", "elif") else "do"
    try:
        boundary = tokens.index(";")
    except ValueError:
        return -1
    if boundary + 1 >= len(tokens) or tokens[boundary + 1] != expected_tail:
        return -1

    clauses = []
    clause = []
    for token in tokens[1:boundary]:
        if token in ("&&", "||"):
            clauses.append(clause)
            clause = []
        else:
            clause.append(token)
    clauses.append(clause)
    if not all(
        len(candidate) >= 2
        and candidate[0] in SHELL_TEST_OPENERS
        and candidate[-1] == SHELL_TEST_CLOSERS[candidate[0]]
        and not any(token in ("&&", "|", "&", "(", ")") for token in candidate[1:-1])
        for candidate in clauses
    ):
        return -1
    return boundary


def contains_powershell_warning_command(tokens, line):
    """Whether a PowerShell token stream invokes Write-Warning at a command boundary."""
    # POSIX shlex treats a PowerShell module separator as an escape and removes it, so preserve the source spelling.
    powershell_line = line.replace("`", "")
    if re.search(r"(?i)(?:^|[;{(&|.]\s*)[A-Za-z0-9_.-]+\\Write-Warning\b", powershell_line):
        return True
    if re.search(r"(?i)(?:^|[;{(&|.]\s*)Write-Warning\b", powershell_line):
        return True
    boundaries = {";", "{", "(", ".", "&", "&&", "||", "|"}
    for index, token in enumerate(tokens):
        normalized = token.lower()
        command = normalized.lstrip("{").replace("\\", "/").rsplit("/", 1)[-1]
        if command != "write-warning":
            continue
        if normalized.startswith("{") or index == 0 or tokens[index - 1] in boundaries:
            return True
    return False


def bash_commands(script, relative, job, what, problems):
    commands = []
    try:
        for line in logical_lines(script, "\\"):
            commands.append(tuple(shell_tokens(line)))
    except ValueError as error:
        problems.append("{0}: job '{1}' has an unreadable {2} command ({3})".format(relative, job, what, error))
        return []
    return commands


def run_fail_open_reason(step, allow_success_exit=False, default_shell="bash"):
    """Return one known fail-open spelling, without interpreting arbitrary shell."""
    shell = (scalar(step.entries.get("shell")) or default_shell).lower()
    bash_status_semantics = shell in ("bash", "sh")
    if shell == "cmd":
        continuation = "^"
    elif shell in POWERSHELL_SHELLS:
        continuation = "`"
    else:
        continuation = "\\"
    for line in logical_lines(step.run, continuation):
        capture = CAPTURED_SUBSTITUTION.match(line)
        if capture and "||" in capture.group("body") and line not in ALLOWED_FAILURE_CAPTURES:
            return "captured command substitution whose failure is discarded"
        try:
            tokens = shell_tokens(line)
        except ValueError:
            return "unreadable shell quoting"
        test_boundary = shell_test_condition_boundary(tokens, line) if bash_status_semantics else -1
        if bash_status_semantics and tokens and tokens[0] == "!":
            return "required command is negated with '!', so its failure becomes success"
        if bash_status_semantics and tokens and tokens[0] in CONDITIONAL_HEADS and test_boundary < 0:
            return "conditional head executes a required command whose status does not reach the step"
        for index, token in enumerate(tokens):
            if token == "||":
                # `required-command || anything-that-succeeds` normalizes the command's failure, and the fallback does
                # not have to be `true` to do it: `|| echo ignored` is exactly as green. Refuse the operator by
                # construction and carve out only the one form that decides nothing -- test compounds joined inside a
                # conditional head -- rather than enumerating the successful commands somebody might reach for.
                following = tokens[index + 1] if index + 1 < len(tokens) else ""
                if 0 <= index < test_boundary:
                    continue
                return "'|| {0}'".format(following or "<end of line>")
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
        if contains_powershell_warning_command(tokens, line):
            # A PowerShell step that detected a broken state and only warned about it stays green, so the job goes on
            # to package whatever the broken state produced. Scan command shape even when shell is omitted because
            # GitHub's Windows default is PowerShell. Report it with Write-Error and a nonzero exit instead.
            return "'Write-Warning' on a condition nothing else fails"
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


def job_default_shell(job):
    """The shell GitHub runs a step that omits `shell`: PowerShell on a Windows runner, bash elsewhere."""
    runner = (scalar(job.entries.get("runs-on")) or "").lower()
    return "pwsh" if "windows" in runner else "bash"


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

    default_shell = job_default_shell(job)
    for step in job.steps:
        if "continue-on-error" in step.entries:
            problems.append(
                "{0}: step '{1}' in job '{2}' carries a continue-on-error marker, so a red step reports green".format(
                    relative, step.name or "<unnamed>", name
                )
            )
        step_condition = step.entries.get("if")
        if step_condition is not None:
            observed_condition = scalar(step_condition)
            reviewed = REVIEWED_STEP_CONDITIONS.get((relative, name, step.name))
            if reviewed is None:
                problems.append(
                    "{0}: step '{1}' in job '{2}' is gated on '{3}'; a required step that can be skipped never runs "
                    "the guard it reports green for".format(relative, step.name or "<unnamed>", name, observed_condition)
                )
            elif observed_condition != reviewed:
                problems.append(
                    "{0}: step '{1}' in job '{2}' is gated on '{3}', not its reviewed condition '{4}'".format(
                        relative, step.name or "<unnamed>", name, observed_condition, reviewed
                    )
                )
        if not step.run:
            continue
        reason = run_fail_open_reason(
            step, allow_success_exit=step.name == allowed_success_step, default_shell=default_shell
        )
        if reason is None:
            continue
        if reason == "bare 'exit 0'":
            problems.append(
                "{0}: job '{1}' has a bare 'exit 0' skip, which passes without running what it covers".format(
                    relative, name
                )
            )
        elif "||" in reason or "captured" in reason or "required command" in reason:
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
        simd_shell = job_default_shell(job)
        if any(
            step.run and run_fail_open_reason(step, default_shell=simd_shell) == "bare 'exit 0'"
            for step in job.steps
        ):
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


def soak_command(build_directory, dump_directory):
    return [
        (
            "python",
            "scripts/run_lifecycle_soak.py",
            "--build-directory",
            build_directory,
            "--dump-directory",
            dump_directory,
        )
    ]


def check_producer_proofs(workflow, problems):
    case_args = ("--case", SAME_BASE_CASE, "--property", SAME_BASE_PROPERTY)
    mingw = workflow.jobs.get("build-mingw")
    if mingw:
        # Pinned as an exact command for the same reason as the execution and consumer proofs above: the soak is the
        # only route that runs the dump-capturing lifecycle inventory, and a respelled or redirected invocation would
        # package a candidate that never faced it.
        check_exact_bash_step(
            workflow,
            mingw,
            MINGW_SOAK_STEP,
            soak_command("build/mingw-release", "$RUNNER_TEMP/dmk-lifecycle-dumps-mingw"),
            "the exact dump-capturing lifecycle soak",
            problems,
        )
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
            MSVC_SOAK_STEP,
            soak_command("build/msvc-release", "$RUNNER_TEMP/dmk-lifecycle-dumps-msvc"),
            "the exact dump-capturing lifecycle soak",
            problems,
        )
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
