#!/usr/bin/env python3
"""Hold this repository's workflows to the canonical contract in workflow_contract.py.

The reader is a deliberately small, fail-closed YAML subset parser: it scopes mapping keys and steps
by indentation rather than treating a spelling found anywhere in a job as evidence. That structure
is compared against the contract for focused diagnostics, while a normalized-source digest holds
everything the subset parser does not interpret.

That distinction is the whole point. A presence check answers "is the reviewed line still here?",
which stays "yes" after an inserted assignment shadows the value that line reads, after a relocated
success exit turns a guard into an unconditional pass, and after a wrapper shell normalizes the
status the guard was computing. A comparison answers "is this the reviewed program?", which those
mutations cannot answer "yes" to, because each of them adds or moves something.

Exit status is 0 when the contract holds, else 1.
"""
import argparse
import hashlib
import os
import re
import shlex
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import workflow_contract as contract

# The three workflows that carry a content check beyond the shared contract comparison.
QUALITY = contract.QUALITY
SIMD = contract.SIMD
RELEASE = contract.RELEASE

MAPPING_LINE = re.compile(
    r"^(?P<spaces> *)(?P<key>[A-Za-z0-9_-]+|'[^']+'|\"[^\"]+\")\s*:\s*(?P<value>.*?)\s*$"
)
STEP_LINE = re.compile(r"^ {6}-\s+(?P<body>.+?)\s*$")
# Any use of the secrets context, not only `secrets.NAME` and `secrets['NAME']`. `toJSON(secrets)` names no
# single secret and expands to all of them, so requiring a member accessor would miss the widest spelling.
SECRET_EXPRESSION = re.compile(r"\$\{\{[^}\n]*\bsecrets\b", re.IGNORECASE)
CANONICAL_RELEASE_TOKEN = re.compile(r"\$\{\{\s*secrets\.RELEASE_TOKEN\s*\}\}")

POWERSHELL_SHELLS = ("pwsh", "powershell")
LEXICAL_CONTINUATIONS = ("\\", "`")
CONTINUATIONS = {"bash": "\\", "sh": "\\", "cmd": "^", "pwsh": "`", "powershell": "`"}

# The only place `||` joins operands without deciding a required command's exit status: a conditional
# head whose every operand is a bracket test rather than the work the step exists to run.
CONDITIONAL_HEADS = ("if", "elif", "while", "until")
SHELL_TEST_OPENERS = ("[", "[[")
SHELL_TEST_CLOSERS = {"[": "]", "[[": "]]"}

# Disabling either of these makes a later failure stop reaching the step's exit status. GitHub runs
# `shell: bash` as `bash --noprofile --norc -eo pipefail {0}`, so both are on until something turns
# them off, and turning one off is the mutation.
ERREXIT_DISABLED_OPTIONS = (("+o", "errexit"), ("+o", "pipefail"))

# `set` takes its short options as a cluster, so errexit is disabled by `+eo pipefail`, `+ex` and `+xe`
# just as much as by `+e`. Matching only the bare spelling would leave every clustered form unrecognized.
ERREXIT_SHORT_CLUSTER = re.compile(r"^\+[a-z]*e[a-z]*$")


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
    try:
        with open(path, "rb") as handle:
            source = handle.read()
    except OSError as error:
        problems.append("{0}: workflow could not be read ({1})".format(relative, error))
        return None
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        problems.append("{0}: workflow is not valid UTF-8 ({1})".format(relative, error))
        return None
    return text.replace("\r\n", "\n").replace("\r", "\n")


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


def logical_lines(script, continuation):
    """Join one workflow shell's explicit physical-line continuations."""
    result = []
    pending = ""
    join_without_space = False
    for raw in script.splitlines():
        line = raw.strip()
        if not line:
            continue
        # A `#` only opens a comment where a word can start. After a continuation it is mid-command: the shell
        # joins the physical lines first, so the marker truncates THAT logical line and the following physical
        # line becomes a separate command. Splicing across it would reconstruct one command the shell never runs,
        # and could reconstruct exactly a reviewed continued line while the shell executed a truncated one.
        # Keep the text in the pending command so the comparison sees the real logical line and refuses.
        if line.startswith("#") and not pending:
            # A standalone comment is ignored by every shell here, including one that ends in a continuation
            # marker: a marker inside a comment is comment text, not a join. Such a line is still retained so
            # the exact-program comparison refuses a comment shaped like a continuation rather than reading past it.
            if continuation in LEXICAL_CONTINUATIONS and line.endswith(continuation):
                result.append(" ".join(line.split()))
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


def errexit_disabled_by(operands):
    """Return the `set` operand that turns errexit or pipefail off, or None.

    Only the leading option run is read. `--` ends it, and so does the first non-option word, because
    everything after either is a positional parameter rather than an option.
    """
    index = 0
    while index < len(operands):
        operand = operands[index]
        if operand == "--" or not operand.startswith(("+", "-")):
            return None
        if ERREXIT_SHORT_CLUSTER.match(operand):
            return "'set {0}'".format(operand)
        for name, option in ERREXIT_DISABLED_OPTIONS:
            if operand == name and index + 1 < len(operands) and operands[index + 1] == option:
                return "'set {0} {1}'".format(name, option)
        index += 1
    return None


def status_loss_reason(script, shell, allow_success_exit):
    """Return one way this script's failure could stop reaching the job, or None.

    This decides shape, not meaning: it never claims to interpret an arbitrary shell program. It is
    the second line of defence behind the exact program pins, and it covers the constructs that turn
    a real failure into a green step.
    """
    bash_status_semantics = shell in ("bash", "sh")
    continuation = CONTINUATIONS.get(shell, "\\")
    for line in logical_lines(script, continuation):
        try:
            tokens = shell_tokens(line)
        except ValueError:
            return "unreadable shell quoting"

        test_boundary = shell_test_condition_boundary(tokens, line) if bash_status_semantics else -1
        token_disjunctions = [index for index, token in enumerate(tokens) if token == "||"]
        if "||" in line and line not in contract.ALLOWED_FAILURE_CAPTURES:
            if not token_disjunctions:
                # The operator survived tokenization inside quoting or a command substitution, so it joins
                # operands the shell will still evaluate while a token scan sees one opaque word.
                return "'||' hidden inside quoting or a command substitution"
            for index in token_disjunctions:
                if 0 <= index < test_boundary:
                    continue
                following = tokens[index + 1] if index + 1 < len(tokens) else ""
                # `required-command || anything-that-succeeds` normalizes the command's failure, and the fallback
                # does not have to be `true` to do it: `|| echo ignored` is exactly as green. Refuse the operator
                # by construction and carve out only the form that decides nothing.
                return "'|| {0}'".format(following or "<end of line>")

        if bash_status_semantics and tokens and tokens[0] == "!":
            return "required command is negated with '!', so its failure becomes success"
        if bash_status_semantics and tokens and tokens[0] in CONDITIONAL_HEADS and test_boundary < 0:
            return "conditional head executes a required command whose status does not reach the step"

        for index, token in enumerate(tokens):
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
            if bash_status_semantics and token == "eval":
                return "'eval', which hides the program whose status is being checked"
            # cmd runs `A & B` unconditionally and reports only B, and a pipeline reports only its tail.
            # `&&` is the conditional form and keeps the left side deciding, so it is not swept up.
            if shell == "cmd" and token in ("&", "|"):
                return "CMD '{0}', which reports the last command instead of the failing one".format(token)

        lowered = [token.lower() for token in tokens]
        if bash_status_semantics and lowered and lowered[0] == "set":
            reason = errexit_disabled_by(lowered[1:])
            if reason is not None:
                return reason

        if shell in POWERSHELL_SHELLS and contains_powershell_warning_command(tokens, line):
            # A step that detected a broken state and only warned about it stays green, so the job goes on to
            # package whatever the broken state produced. Report it with Write-Error and a nonzero exit instead.
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


def step_env(workflow, step, problems):
    entry = step.entries.get("env")
    return child_entries(workflow, entry, step.end, 10, "step environment", problems)


def check_triggers(workflow, shape, problems):
    """Every reviewed trigger present, no unreviewed one, and no paths filter where it would skip a context."""
    relative = workflow.relative
    on_entry = workflow.entries.get("on")
    if on_entry is None:
        problems.append("{0}: no 'on' block, so the contract cannot say when this workflow runs".format(relative))
        return
    on_entries = child_entries(workflow, on_entry, workflow.jobs_start, 2, "on mapping", problems)
    observed = tuple(sorted(on_entries))
    expected = tuple(sorted(shape.triggers))
    if observed != expected:
        problems.append(
            "{0}: triggers are {1}, not the reviewed {2}".format(relative, list(observed), list(expected))
        )
    for name, entry in on_entries.items():
        if name in shape.path_filtered_triggers:
            continue
        end = block_end(workflow.lines, entry.line, workflow.jobs_start, 2)
        fields = child_entries(workflow, entry, end, 4, "'{0}' trigger".format(name), problems)
        for filter_key in ("paths", "paths-ignore"):
            if filter_key in fields:
                problems.append(
                    "{0}: the '{1}' trigger carries a '{2}' filter, so a run that changes nothing under it never "
                    "creates this context and a required check waits forever".format(relative, name, filter_key)
                )


def check_dispatch_candidate_input(workflow, shape, problems):
    """A workflow that binds a manual run to a candidate must accept that candidate as a required input."""
    relative = workflow.relative
    names = [step.name for _, job in shape.jobs for step in job.steps]
    if contract.DISPATCH_IDENTITY_STEP not in names:
        return
    on_entry = workflow.entries.get("on")
    on_entries = child_entries(workflow, on_entry, workflow.jobs_start, 2, "on mapping", problems)
    dispatch = on_entries.get("workflow_dispatch")
    if dispatch is None:
        problems.append("{0}: the candidate guard has no workflow_dispatch trigger to guard".format(relative))
        return
    dispatch_end = block_end(workflow.lines, dispatch.line, workflow.jobs_start, 2)
    dispatch_entries = child_entries(workflow, dispatch, dispatch_end, 4, "workflow_dispatch mapping", problems)
    inputs = dispatch_entries.get("inputs")
    inputs_end = block_end(workflow.lines, inputs.line, dispatch_end, 4) if inputs else 0
    input_entries = child_entries(workflow, inputs, inputs_end, 6, "workflow_dispatch inputs", problems)
    expected_sha = input_entries.get("expected_sha")
    if expected_sha is None:
        problems.append(
            "{0}: the candidate guard has no 'expected_sha' input, so a manual run names no candidate".format(
                relative
            )
        )
        return
    fields = child_entries(
        workflow, expected_sha, block_end(workflow.lines, expected_sha.line, inputs_end, 6), 8, "expected_sha", problems
    )
    if scalar(fields.get("required")) != "true" or scalar(fields.get("type")) != "string":
        problems.append("{0}: 'expected_sha' must be a required string input".format(relative))


def check_program(relative, job_name, step, reviewed, observed_shell, problems):
    """Compare a step's complete ordered program against the reviewed one."""
    observed = tuple(logical_lines(step.run, CONTINUATIONS.get(observed_shell, "\\")))
    if observed == tuple(reviewed):
        return
    extra = [line for line in observed if line not in reviewed]
    missing = [line for line in reviewed if line not in observed]
    if extra:
        detail = "it runs unreviewed line {0!r}".format(extra[0])
    elif missing:
        detail = "reviewed line {0!r} is gone".format(missing[0])
    else:
        detail = "its reviewed lines are in a different order"
    problems.append(
        "{0}: step '{1}' in job '{2}' is not the reviewed program: {3}".format(relative, step.name, job_name, detail)
    )


def check_environment(workflow, relative, job_name, step, reviewed, problems):
    observed = step_env(workflow, step, problems)
    observed_pairs = tuple((key, scalar(entry)) for key, entry in observed.items())
    if tuple(sorted(observed_pairs)) != tuple(sorted(reviewed)):
        problems.append(
            "{0}: step '{1}' in job '{2}' declares environment {3}, not the reviewed {4}".format(
                relative, step.name, job_name, sorted(observed_pairs), sorted(reviewed)
            )
        )


def check_step(workflow, job_name, step, reviewed, problems):
    """Hold one step to its reviewed shell, condition, environment, program, and status semantics.

    Nothing here consults the job's runner default, because the contract records an explicit shell for
    every run step: a step that dropped its `shell` key mismatches the reviewed value and is refused.
    """
    relative = workflow.relative
    label = "step '{0}' in job '{1}'".format(step.name, job_name)

    if "continue-on-error" in step.entries:
        problems.append(
            "{0}: {1} carries a continue-on-error marker, so a red step reports green".format(relative, label)
        )

    observed_condition = scalar(step.entries.get("if")) if "if" in step.entries else None
    if observed_condition != reviewed.condition:
        if reviewed.condition is None:
            problems.append(
                "{0}: {1} is gated on '{2}'; a required step that can be skipped never runs the guard it reports "
                "green for".format(relative, label, observed_condition)
            )
        else:
            problems.append(
                "{0}: {1} is gated on '{2}', not its reviewed condition '{3}'".format(
                    relative, label, observed_condition, reviewed.condition
                )
            )

    declared_shell = scalar(step.entries.get("shell")) if "shell" in step.entries else None
    if declared_shell is not None and declared_shell not in contract.REVIEWED_SHELLS:
        # A custom shell template is not a shell choice. `bash {0} || true` and its relatives rewrite the
        # status the step reports without touching a single line of the program the reviewer read.
        problems.append(
            "{0}: {1} declares unreviewed shell '{2}'; only {3} are reviewed, and a custom template can "
            "normalize the status of every command in the step".format(
                relative, label, declared_shell, list(contract.REVIEWED_SHELLS)
            )
        )
        return
    if declared_shell != reviewed.shell:
        problems.append(
            "{0}: {1} runs under shell '{2}', not its reviewed '{3}'".format(
                relative, label, declared_shell, reviewed.shell
            )
        )
        return

    observed_directory = scalar(step.entries.get("working-directory")) if "working-directory" in step.entries else None
    if observed_directory != reviewed.working_directory:
        problems.append(
            "{0}: {1} runs in working directory '{2}', not its reviewed '{3}'".format(
                relative, label, observed_directory, reviewed.working_directory
            )
        )

    if reviewed.environment is not None:
        check_environment(workflow, relative, job_name, step, reviewed.environment, problems)

    if reviewed.shell is None:
        if step.run:
            problems.append(
                "{0}: {1} is reviewed as an action step but carries a run body".format(relative, label)
            )
        return

    if not step.run:
        problems.append("{0}: {1} is reviewed as a run step but has no run body".format(relative, label))
        return

    if reviewed.program is not None:
        check_program(relative, job_name, step, reviewed.program, reviewed.shell, problems)
        return

    allow_success_exit = (relative, job_name, step.name) in contract.ALLOWED_SUCCESS_EXIT_STEPS
    reason = status_loss_reason(step.run, reviewed.shell, allow_success_exit)
    if reason is None:
        return
    if reason == "bare 'exit 0'":
        problems.append(
            "{0}: job '{1}' has a bare 'exit 0' skip, which passes without running what it covers".format(
                relative, job_name
            )
        )
    elif "||" in reason or "required command" in reason:
        problems.append("{0}: job '{1}' discards a step's exit status with {2}".format(relative, job_name, reason))
    else:
        problems.append("{0}: job '{1}' contains fail-open shell construct {2}".format(relative, job_name, reason))


def check_job(workflow, job_name, reviewed, problems):
    """Hold one job to its reviewed condition, dependencies, and complete ordered step list."""
    relative = workflow.relative
    job = workflow.jobs.get(job_name)
    if job is None:
        problems.append("{0}: job '{1}' is missing".format(relative, job_name))
        return
    if not job.entries or not job.steps:
        problems.append(
            "{0}: job '{1}' has no readable body, so none of its required guards could be checked".format(
                relative, job_name
            )
        )
        return

    if "continue-on-error" in job.entries:
        problems.append(
            "{0}: job '{1}' carries a continue-on-error marker, so a red step reports green".format(
                relative, job_name
            )
        )
    observed_condition = scalar(job.entries.get("if"))
    if observed_condition != reviewed.condition:
        if job_name == "create-release":
            problems.append(
                "{0}: job 'create-release' is gated on '{1}' and is not gated on the publish mode, so a "
                "preflight run could tag".format(relative, observed_condition)
            )
        else:
            problems.append(
                "{0}: job '{1}' is gated on '{2}', expected {3}".format(
                    relative,
                    job_name,
                    observed_condition,
                    "'{0}'".format(reviewed.condition) if reviewed.condition else "no job-level condition",
                )
            )
    label = scalar(job.entries.get("name")) or ""
    if "advisory" in label.lower():
        problems.append("{0}: job '{1}' still calls itself advisory".format(relative, job_name))

    observed_runner = scalar(job.entries.get("runs-on"))
    if observed_runner != reviewed.runner:
        problems.append(
            "{0}: job '{1}' runs on '{2}', not its reviewed '{3}'".format(
                relative, job_name, observed_runner, reviewed.runner
            )
        )

    observed_needs = dependencies(workflow, job, problems)
    if observed_needs != set(reviewed.needs):
        problems.append(
            "{0}: job '{1}' needs {2}, not the reviewed {3}".format(
                relative, job_name, sorted(observed_needs), sorted(reviewed.needs)
            )
        )

    observed_steps = [step.name for step in job.steps]
    reviewed_steps = [step.name for step in reviewed.steps]
    if observed_steps != reviewed_steps:
        problems.append(
            "{0}: job '{1}' runs steps {2}, not the reviewed {3}".format(
                relative, job_name, observed_steps, reviewed_steps
            )
        )
        return

    for step, reviewed_step in zip(job.steps, reviewed.steps):
        check_step(workflow, job_name, step, reviewed_step, problems)


def check_shape(workflow, shape, problems):
    """Compare one whole workflow against its reviewed shape, in both directions."""
    relative = workflow.relative
    check_triggers(workflow, shape, problems)
    check_dispatch_candidate_input(workflow, shape, problems)

    reviewed_names = [name for name, _ in shape.jobs]
    observed_names = list(workflow.jobs)
    if sorted(observed_names) != sorted(reviewed_names):
        problems.append(
            "{0}: declares jobs {1}, not the reviewed {2}".format(relative, sorted(observed_names), sorted(reviewed_names))
        )
    for name, reviewed in shape.jobs:
        check_job(workflow, name, reviewed, problems)


def check_quality_content(workflow, problems):
    """The clang-tidy route's decisive flags, which live on the command line rather than in .clang-tidy."""
    tidy = workflow.jobs.get("clang-tidy")
    body = job_text(workflow, tidy) if tidy else ""
    if not body:
        return
    if "--warnings-as-errors" not in body:
        problems.append(
            "{0}: the clang-tidy job must pass a command-line --warnings-as-errors override, because the "
            "curated .clang-tidy deliberately leaves WarningsAsErrors empty".format(QUALITY)
        )
    if not re.search(r"--extra-arg(?:-before)?=-Werror(?:\s|$)", body):
        problems.append("{0}: clang compiler diagnostics are not promoted with --extra-arg=-Werror".format(QUALITY))
    if "DMK_HAS_WDANGLING_REFERENCE=OFF" not in body:
        problems.append(
            "{0}: the clang-tooling database does not suppress GCC-only -Wdangling-reference".format(QUALITY)
        )
    if "--target=x86_64-w64-windows-gnu" not in body:
        problems.append("{0}: clang-tidy no longer pins the MinGW target triple".format(QUALITY))


def guarded_block(body, index):
    """Return the braced block that opens after `index`, or None when it is unbalanced or absent."""
    start = body.find("{", index)
    if start < 0:
        return None
    depth = 0
    for position in range(start, len(body)):
        if body[position] == "{":
            depth += 1
        elif body[position] == "}":
            depth -= 1
            if depth == 0:
                return body[start : position + 1]
    return None


def check_simd_content(text, problems):
    """The two guards that make an unavailable emulator or an absent tier banner a red leg."""
    body = uncommented(text)
    for guard, why in (
        ("-not $sdeExe", "a missing Intel SDE must fail the leg, not skip it"),
        ("-not $level", "an absent tier marker must fail the leg, not pass unverified"),
    ):
        index = body.find(guard)
        if index < 0:
            problems.append("{0}: no '{1}' guard; {2}".format(SIMD, guard, why))
            continue
        # The throw has to be inside this guard's own block. A neighbouring guard's throw a few lines away
        # satisfies a proximity window while this guard reports nothing and the leg continues.
        block = guarded_block(body, index)
        if block is None or "throw" not in block:
            problems.append("{0}: the '{1}' guard does not throw; {2}".format(SIMD, guard, why))


def check_release_mode(workflow, problems):
    """The dispatch input that separates preflight from publish."""
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


def check_credentials(workflow, problems):
    """A secret reaches exactly the two reviewed action inputs of release.yml's publish job and nowhere else.

    Every workflow is scanned, not only release.yml: a credential in a pull-request-triggered route is the
    more dangerous placement, because that route runs on a contributor's head rather than on a dispatch an
    owner performed. Only release.yml has an audited publish job, so only there is a secret ever in place.
    """
    relative = workflow.relative
    publish = workflow.jobs.get("create-release") if relative == RELEASE else None
    outside = []
    for index, line in enumerate(workflow.lines):
        if publish and publish.start <= index < publish.end:
            continue
        if SECRET_EXPRESSION.search(strip_comment(line)):
            outside.append(index)
    for index in outside:
        owner = next((job.name for job in workflow.jobs.values() if job.start <= index < job.end), None)
        if owner:
            problems.append(
                "{0}: job '{1}' holds a release credential; only the audited publish job may".format(relative, owner)
            )
        else:
            problems.append(
                "{0}: workflow-level configuration exposes RELEASE_TOKEN outside create-release".format(relative)
            )

    if publish is None:
        return
    body = job_text(workflow, publish)
    canonical = list(CANONICAL_RELEASE_TOKEN.finditer(body))
    remainder = CANONICAL_RELEASE_TOKEN.sub("", body)
    locations_hold = True
    for name in contract.RELEASE_TOKEN_STEPS:
        matches = [step for step in publish.steps if step.name == name]
        if len(matches) != 1:
            locations_hold = False
            continue
        fields = child_entries(
            workflow, matches[0].entries.get("with"), matches[0].end, 10, "credentialed step inputs", problems
        )
        if scalar(fields.get("token")) != contract.RELEASE_TOKEN_VALUE:
            locations_hold = False
    if len(canonical) != 2 or SECRET_EXPRESSION.search(remainder) or not locations_hold:
        problems.append("{0}: create-release must hold exactly the two reviewed RELEASE_TOKEN uses".format(RELEASE))


def check_benchmark_checker_is_not_its_own_self_test(workflow, problems):
    evidence = workflow.jobs.get("benchmark-evidence")
    if evidence is None:
        return
    if not re.search(r"(?<!test_)check_benchmark_results\.py", job_text(workflow, evidence)):
        problems.append(
            "{0}: the benchmark evidence job does not run the result checker, so a benchmark that printed "
            "nothing would pass".format(RELEASE)
        )


def check_contract_covers_the_repository(root, problems):
    """A workflow file that no contract entry names is an unreviewed route into this repository."""
    directory = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(directory):
        problems.append(".github/workflows: directory is missing")
        return
    present = {
        ".github/workflows/{0}".format(name)
        for name in sorted(os.listdir(directory))
        if name.endswith((".yml", ".yaml"))
    }
    for relative in sorted(present - set(contract.WORKFLOWS)):
        problems.append("{0}: workflow is not named by the canonical contract".format(relative))


def source_identity(text):
    """The reviewed identity of one normalized workflow source."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_canonical_source(relative, text, problems):
    """Require the whole normalized workflow source, including keys the subset parser does not interpret."""
    expected = contract.WORKFLOW_SOURCE_SHA256.get(relative)
    if expected is None:
        problems.append("{0}: canonical contract has no normalized-source identity".format(relative))
        return
    observed = source_identity(text)
    if observed != expected:
        # The observed digest is reported so a reviewed workflow change can be completed without recomputing
        # the normalization by hand. It is the replacement value, never a reason to accept the diff that
        # produced it: the workflow diff is what a reviewer reads before the identity is allowed to move.
        problems.append(
            "{0}: normalized source does not match the reviewed canonical identity; observed {1}, "
            "reviewed {2}".format(relative, observed, expected)
        )


def print_source_identities(root):
    """Print the current normalized-source identity of every contract workflow, in contract form."""
    problems = []
    for relative in contract.WORKFLOWS:
        text = read(root, relative, problems)
        print("    {0}: \"{1}\",".format(contract_constant(relative), source_identity(text) if text else "<unreadable>"))
    for problem in problems:
        print("  {0}".format(problem))
    return 1 if problems else 0


def contract_constant(relative):
    """The contract's own name for one workflow path, so printed identities can be pasted as they stand."""
    for name in ("QUALITY", "SIMD", "RELEASE", "PR_CHECK", "ARCH_GATE", "SANITIZERS", "COVERAGE_PAGES"):
        if getattr(contract, name) == relative:
            return name
    return relative


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gate the workflows against the canonical contract.")
    parser.add_argument("--repository-root", default=".", help="repository root holding .github/workflows")
    parser.add_argument(
        "--print-source-identities",
        action="store_true",
        help="print each workflow's current normalized-source identity for WORKFLOW_SOURCE_SHA256 and exit",
    )
    args = parser.parse_args(argv)

    if args.print_source_identities:
        return print_source_identities(args.repository_root)

    problems = []
    check_contract_covers_the_repository(args.repository_root, problems)

    parsed = {}
    for relative, shape in contract.WORKFLOWS.items():
        text = read(args.repository_root, relative, problems)
        if text is None:
            continue
        check_canonical_source(relative, text, problems)
        workflow = parse_workflow(text, relative, problems)
        parsed[relative] = (workflow, text)
        check_shape(workflow, shape, problems)

    for workflow, _ in parsed.values():
        check_credentials(workflow, problems)

    if QUALITY in parsed:
        check_quality_content(parsed[QUALITY][0], problems)
    if SIMD in parsed:
        check_simd_content(parsed[SIMD][1], problems)
    if RELEASE in parsed:
        release = parsed[RELEASE][0]
        check_release_mode(release, problems)
        check_benchmark_checker_is_not_its_own_self_test(release, problems)

    if problems:
        print("Workflow topology rejected:")
        for problem in problems:
            print("  {0}".format(problem))
        return 1
    print(
        "Workflow topology OK: every reviewed source, context, job, step, shell, condition, environment "
        "and publication program matches the canonical contract."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
