#!/usr/bin/env python3
"""Regression tests for the shared proof-wrapper runtime-directory resolver.

Each case builds a synthetic tree holding the exact cache and description bytes a real preset produces, because the
defect this resolver replaces was that the bare cache string ``g++`` reads as a plausible path to every naive
basename or dirname test.
"""

import importlib.util
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "resolve_runtime_dir.py"
SPEC = importlib.util.spec_from_file_location("resolve_runtime_dir", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def make_tree(root: Path, compiler: str, cache_value: str, version: str = "3.31.6") -> Path:
    build = root / "tree"
    description = build / "CMakeFiles" / version
    description.mkdir(parents=True, exist_ok=True)
    (build / "CMakeCache.txt").write_text(
        f"CMAKE_CXX_COMPILER:UNINITIALIZED={cache_value}\n", encoding="utf-8"
    )
    (description / "CMakeCXXCompiler.cmake").write_text(
        f'set(CMAKE_CXX_COMPILER "{compiler}")\nset(CMAKE_CXX_COMPILER_ID "GNU")\n', encoding="utf-8"
    )
    return build


def test_mingw_preset_tree_resolves_the_real_compiler_directory() -> None:
    with tempfile.TemporaryDirectory() as raw:
        # The cache holds the bare string the preset passed; only the description carries the resolved path.
        build = make_tree(Path(raw), "C:/msys64/mingw64/bin/g++.exe", "g++")
        resolved = MODULE.resolve(build)
    if resolved != "C:/msys64/mingw64/bin":
        raise AssertionError(f"expected the MinGW bin directory, got '{resolved}'")


def test_msvc_preset_tree_prepends_nothing() -> None:
    with tempfile.TemporaryDirectory() as raw:
        build = make_tree(
            Path(raw),
            "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.43.34808/bin/Hostx64/x64/cl.exe",
            "cl",
        )
        resolved = MODULE.resolve(build)
    if resolved != "":
        raise AssertionError(f"expected no prepend for MSVC, got '{resolved}'")


def test_msvc_without_the_exe_suffix_still_skips() -> None:
    if MODULE.runtime_dir_for("C:/vs/bin/cl") != "":
        raise AssertionError("a cl compiler recorded without .exe must still skip the prepend")


def test_separator_is_forward_slash_on_every_interpreter() -> None:
    # A native Windows Python renders parents with backslashes and an MSYS one with forward slashes, so the
    # wrappers would otherwise get a different answer per lane.
    resolved = MODULE.runtime_dir_for("C:\\msys64\\mingw64\\bin\\g++.exe")
    if "\\" in resolved:
        raise AssertionError(f"expected forward slashes, got '{resolved}'")


def test_bare_compiler_name_is_refused_rather_than_resolved_to_dot() -> None:
    # dirname('g++') is '.', which is what made the shell wrappers prepend the repository root.
    try:
        MODULE.runtime_dir_for("g++")
    except MODULE.ResolveError:
        return
    raise AssertionError("a bare compiler name must raise rather than resolve to '.'")


def test_unconfigured_tree_is_an_error_not_an_empty_answer() -> None:
    with tempfile.TemporaryDirectory() as raw:
        build = Path(raw) / "empty"
        build.mkdir()
        try:
            MODULE.resolve(build)
        except MODULE.ResolveError:
            return
    raise AssertionError("a tree with no CMakeCXXCompiler.cmake must raise")


def test_reconfigured_tree_picks_the_highest_version_directory() -> None:
    # 3.9.0 against 3.28.0 on purpose: string order puts 3.9.0 last, so a sort that is not numeric answers with the
    # stale description here while still passing a 3.28.0-against-3.31.6 pair.
    with tempfile.TemporaryDirectory() as raw:
        build = make_tree(Path(raw), "C:/old/bin/g++.exe", "g++", version="3.9.0")
        newer = build / "CMakeFiles" / "3.28.0"
        newer.mkdir(parents=True)
        (newer / "CMakeCXXCompiler.cmake").write_text(
            'set(CMAKE_CXX_COMPILER "C:/msys64/mingw64/bin/g++.exe")\n', encoding="utf-8"
        )
        resolved = MODULE.resolve(build)
    if resolved != "C:/msys64/mingw64/bin":
        raise AssertionError(f"expected the newer description to win, got '{resolved}'")


def test_non_numeric_description_directory_never_outranks_a_version() -> None:
    # CMake writes only dotted numbers here, but a stray directory matching the glob must not win on its spelling.
    with tempfile.TemporaryDirectory() as raw:
        build = make_tree(Path(raw), "C:/msys64/mingw64/bin/g++.exe", "g++", version="3.31.6")
        stray = build / "CMakeFiles" / "zz-scratch"
        stray.mkdir(parents=True)
        (stray / "CMakeCXXCompiler.cmake").write_text('set(CMAKE_CXX_COMPILER "C:/stray/bin/g++.exe")\n', encoding="utf-8")
        resolved = MODULE.resolve(build)
    if resolved != "C:/msys64/mingw64/bin":
        raise AssertionError(f"expected the versioned description to win, got '{resolved}'")


def test_description_without_the_setting_is_an_error() -> None:
    with tempfile.TemporaryDirectory() as raw:
        build = Path(raw) / "tree"
        description = build / "CMakeFiles" / "3.31.6"
        description.mkdir(parents=True)
        (description / "CMakeCXXCompiler.cmake").write_text('set(CMAKE_CXX_COMPILER_ID "GNU")\n', encoding="utf-8")
        try:
            MODULE.resolve(build)
        except MODULE.ResolveError:
            return
    raise AssertionError("a description that never sets CMAKE_CXX_COMPILER must raise")


def main() -> int:
    failures = 0
    for name, case in sorted(globals().items()):
        if not name.startswith("test_") or not callable(case):
            continue
        try:
            case()
        except AssertionError as error:
            print(f"FAILED {name}: {error}", file=sys.stderr)
            failures += 1
    if failures:
        print(f"{failures} test(s) failed", file=sys.stderr)
        return 1
    print("all resolve_runtime_dir tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
