#!/usr/bin/env python3
"""Gate the mechanically decidable naming, namespace-comment, and dash rules.

The rules live in AGENTS.md ("Code style"). This probe covers only the subset a
machine can decide by reading a line, with no brace matching, ownership
inference, or aesthetic judgement:

  - No em dash (U+2014) or en dash (U+2013). AGENTS.md ("Formatting and tooling")
    mandates ``--`` in their place; the ASCII replacement stays legal.
  - Object- and function-like macro names are ``UPPER_SNAKE_CASE``. AGENTS.md
    ("Naming") keeps macros and namespace/class protocol constants in that case;
    the macro half is decidable from the ``#define`` line alone. Local
    ``const`` / ``constexpr`` naming and protocol-constant scope are not decided
    here (they need scope analysis) and stay a review/cleanup concern.
  - A namespace-closer comment uses a house form: a named close reads
    ``} // namespace <Qualified::Name>``, an anonymous close reads the
    clang-format bare ``} // namespace`` or the explicit ``} // anonymous
    namespace``. A closer whose comment names a namespace but matches no house
    form (``// end namespace``, ``//namespace``, a stray trailing token) is
    flagged.

The scope is every C/C++ file this repository tracks (``git ls-files`` never
lists submodule contents, so ``external/`` is excluded without a filter). Pass
explicit paths to narrow the run. Exit status is 1 with the offenders printed
when any rule is violated, else 0.
"""
import os
import re
import subprocess
import sys

# A unicode em dash (U+2014) or en dash (U+2013). The house replacement is `--`.
# Built from chr() codepoints so this detector never itself carries the character it bans.
UNICODE_DASH = re.compile("[" + chr(0x2013) + chr(0x2014) + "]")
# An object- or function-like macro definition: capture the defined identifier.
MACRO_DEFINE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)")
# UPPER_SNAKE_CASE: capitals, digits, and underscores, opening on a letter or `_`.
UPPER_SNAKE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
# A candidate line starts with closing braces and has a trailing // fragment.
# Only fragments that mention "namespace" are treated as self-declared closers.
NAMESPACE_CLOSER = re.compile(r"^\s*\}+\s*//\s*(?P<body>.*?)\s*$")
# The accepted house forms, requiring whitespace around the line-comment marker.
NAMESPACE_HOUSE_FORM = re.compile(
    r"^\s*\}+[ \t]+//[ \t]+"
    r"(?:namespace(?:\s+[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)?|anonymous namespace)"
    r"[ \t\r]*$"
)


def scan_text(text: str, path: str):
    """Return the list of rule violations in one file's text, most specific first."""
    problems = []
    for number, line in enumerate(text.split("\n"), 1):
        if UNICODE_DASH.search(line):
            problems.append(f"{path}:{number}: unicode em/en dash (use -- instead)")

        macro = MACRO_DEFINE.match(line)
        if macro and not UPPER_SNAKE.match(macro.group(1)):
            problems.append(f"{path}:{number}: macro {macro.group(1)} is not UPPER_SNAKE_CASE")

        closer = NAMESPACE_CLOSER.match(line)
        if closer:
            body = closer.group("body").strip()
            if "namespace" in body.casefold() and not NAMESPACE_HOUSE_FORM.match(line):
                problems.append(
                    f"{path}:{number}: namespace-closer comment '// {body}' is not a house form "
                    "(} // namespace <name>, } // namespace, or } // anonymous namespace)"
                )
    return problems


def scan_file(path: str):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return scan_text(handle.read(), path)


def tracked_sources():
    output = subprocess.check_output(["git", "ls-files", "*.cpp", "*.hpp", "*.h"], text=True)
    return output.split()


def main(argv=None) -> int:
    paths = list(argv) if argv else tracked_sources()
    problems = []
    for path in paths:
        # Deleted files have no content to scan.
        if not os.path.isfile(path):
            continue
        problems.extend(scan_file(path))

    if problems:
        print('Mechanical-style violations (see AGENTS.md, "Code style"):')
        print("\n".join(problems))
        return 1
    print("Mechanical style OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
