#!/usr/bin/env python3
"""Print the compiler directory a proof wrapper must prepend to PATH, or nothing when it must not.

The proof hosts and their companion DLLs load their compiler's runtime (libwinpthread, libstdc++) at run time, so a
wrapper has to put the CONFIGURED compiler's directory ahead of whatever unrelated MinGW happens to sit on the
caller's PATH. The directory is not readable from ``CMakeCache.txt``: a preset that passes ``CMAKE_CXX_COMPILER=g++``
leaves the cache entry as the bare string ``g++`` (MSVC trees hold bare ``cl``), so every basename or dirname test
against that value is answering a question the cache cannot answer. ``CMakeFiles/<version>/CMakeCXXCompiler.cmake``
holds the absolute path CMake actually resolved, which is what this reads.

MSVC returns the empty string on purpose. That compiler directory carries private ``msvcp140`` / ``vcruntime140``
copies, and prepending it would shadow the system CRT for every proof process the wrapper then launches.

Three wrappers share this. Two are shell scripts that cannot share code with each other, and Python is already a hard
gate dependency, so the resolution lives here: the shell wrappers run it as a script and the Python soak imports
``resolve`` directly.
"""

import argparse
import re
import sys
from pathlib import Path, PureWindowsPath

# CMake writes this with forward slashes and always quoted, on one line.
COMPILER_SETTING = re.compile(r'^\s*set\(CMAKE_CXX_COMPILER\s+"([^"]+)"', re.MULTILINE)

# Matched against the stem so both `cl` and `cl.exe` are recognised.
MSVC_STEMS = frozenset({"cl"})


class ResolveError(Exception):
    """A build tree that cannot answer the question at all, as opposed to one that answers 'nothing to prepend'."""


def version_order(description: Path) -> tuple[int, tuple[int, ...]]:
    """Order CMakeFiles/<version> directories numerically.

    String order gets this backwards on the very pair it exists to separate: '3.9.0' sorts above '3.28.0', so a tree
    reconfigured from an older CMake would answer with the stale description. A name that is not a dotted number
    sorts below every real version rather than winning on its spelling.
    """
    parts = description.parent.name.split(".")
    if not all(part.isdigit() for part in parts):
        return (0, ())
    return (1, tuple(int(part) for part in parts))


def find_compiler_description(build_dir: Path) -> Path:
    """Return the CMakeCXXCompiler.cmake of a configured tree."""
    candidates = sorted(build_dir.glob("CMakeFiles/*/CMakeCXXCompiler.cmake"), key=version_order)
    if not candidates:
        raise ResolveError(f"'{build_dir}' has no CMakeFiles/<version>/CMakeCXXCompiler.cmake; configure it first")
    # A tree reconfigured across CMake versions keeps both; the highest version directory is the live one.
    return candidates[-1]


def compiler_path_from(description: Path) -> str:
    match = COMPILER_SETTING.search(description.read_text(encoding="utf-8", errors="replace"))
    if match is None:
        raise ResolveError(f"'{description}' does not set CMAKE_CXX_COMPILER")
    return match.group(1)


def runtime_dir_for(compiler_path: str) -> str:
    """Return the directory to prepend, or '' when prepending would do harm rather than nothing."""
    # PureWindowsPath, not Path: under an MSYS2 or Cygwin interpreter Path is a PosixPath that treats a backslash as
    # an ordinary filename character, and this tool only ever parses a Windows compiler path.
    compiler = PureWindowsPath(compiler_path)
    if compiler.stem.lower() in MSVC_STEMS:
        return ""
    parent = compiler.parent
    # A bare name has no directory to offer. Returning '.' here is what made the shell wrappers prepend the
    # repository root, so refuse instead of inventing a directory.
    if str(parent) in ("", "."):
        raise ResolveError(f"compiler '{compiler_path}' carries no directory")
    # Forward slashes regardless of interpreter: a native Windows Python renders this path with backslashes and an
    # MSYS one with forward slashes, so the answer would otherwise differ per lane. Every consumer accepts forward
    # slashes on Windows, including the ``cygpath -u`` the shell wrappers pass it through.
    return parent.as_posix()


def resolve(build_dir: Path) -> str:
    return runtime_dir_for(compiler_path_from(find_compiler_description(build_dir)))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("build_dir", type=Path, help="configured CMake build tree")
    args = parser.parse_args(argv)

    try:
        runtime_dir = resolve(args.build_dir)
    except ResolveError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    # An empty line is a real answer ("prepend nothing"), distinct from the failure exit above.
    print(runtime_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
