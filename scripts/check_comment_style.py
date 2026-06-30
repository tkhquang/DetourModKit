#!/usr/bin/env python3
"""Advisory lint for DetourModKit's comment-marker conventions.

The rules it guards are defined in AGENTS.md, "Comment conventions". Across the
repo's own tracked C++ sources (submodules under external/ are excluded because
git ls-files lists only this repo's files) it flags:

  - a trailing ``///<`` member doc (documentation belongs on the line above the
    member, as ``///`` or a ``/** */`` block);
  - a multi-line ``///`` doc (two or more consecutive ``///`` lines -- that is a
    multi-line documentation comment and belongs in a ``/** */`` block);
  - a structural/block Doxygen tag on a ``///`` line (``@brief``, ``@param``,
    ``@return``, ``@note``, ``@name`` and the like -- the moment one is needed,
    switch to ``/** */``). Inline link markup (``@ref``, ``@c``, ``@p``, ``@a``)
    is allowed on a ``///`` line and is not flagged.

Exit status is 1 with the offenders printed when any rule is violated, else 0.
"""
import os
import re
import subprocess
import sys

# Structural/block tags that imply a /** */ block; inline link tags are omitted.
BLOCK_TAG = re.compile(
    r"^\s*///.*@(brief|param|tparam|return|retval|note|warning|details|throws|pre|post|name|\{|\})"
)
# A /// documentation line, excluding the trailing-doc ///< form and ////
# banner/separator lines (four or more slashes are not documentation).
DOC_LINE = re.compile(r"^\s*///(?![</])")


def main() -> int:
    files = subprocess.check_output(["git", "ls-files", "*.cpp", "*.hpp"], text=True).split()
    problems = []
    for path in files:
        # git ls-files still lists a file that has been deleted but not yet staged; skip it rather than crash on the
        # missing path (a removed file has no comments to lint).
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().split("\n")
        prev_is_doc = False
        for number, line in enumerate(lines, 1):
            if "///<" in line:
                problems.append(f"{path}:{number}: trailing ///< (move the doc above the member)")
            if BLOCK_TAG.match(line):
                problems.append(f"{path}:{number}: block Doxygen tag on a /// line (use /** */)")
            is_doc = bool(DOC_LINE.match(line))
            if is_doc and prev_is_doc:
                problems.append(f"{path}:{number}: multi-line /// doc (use /** */)")
            prev_is_doc = is_doc

    if problems:
        print('Comment-style violations (see AGENTS.md, "Comment conventions"):')
        print("\n".join(problems))
        return 1
    print("Comment style OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
