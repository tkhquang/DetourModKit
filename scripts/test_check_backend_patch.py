#!/usr/bin/env python3
"""Regression fixtures for the vendored backend-patch model probe.

Exercises the pure helpers -- patch discovery/order, added-line extraction, fix-marker detection,
patch-set hashing, and .gitmodules URL matching -- and the working-tree state rule over a real
throwaway git checkout, because that rule's whole job is to refuse states a repository can be in.
The configure-time CMake entry point is also exercised against both accepted and contaminated trees.

Every fixture writes into a TemporaryDirectory context so nothing is left on disk, even when
an assertion fails.
"""

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_backend_patch.py"
CMAKE_MODULE = ROOT / "cmake" / "DMKBackendPatch.cmake"
SPEC = importlib.util.spec_from_file_location("check_backend_patch", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# A minimal patch body carrying every fix marker on an added line. The checker freezes the real patch hash as the
# semantic backstop; this fixture isolates the marker-extraction and mutation behavior.
GOOD_PATCH = "\n".join(
    ["--- a/src/backend.cpp", "+++ b/src/backend.cpp", "@@ -1 +1 @@"]
    + [f"+{sentinel}" for sentinel in MODULE.REQUIRED_SENTINELS]
    + [" unchanged context line"]
)


def _added(text: str) -> str:
    """Write `text` as a lone patch in a temp dir and return its extracted added lines."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "0001.patch"
        p.write_text(text, encoding="utf-8")
        return MODULE.combined_added_lines([p])


def test_all_sentinels_present_passes() -> None:
    assert MODULE.missing_sentinels(_added(GOOD_PATCH)) == [], "a complete patch must report no missing markers"


def test_each_fix_marker_is_mutation_discriminating() -> None:
    # Every marker, not just the PR-43 additions: dropping any one of them must be reported, and must be reported
    # alone. The "alone" half is what catches a marker that is a substring of another marker's line, where removing it
    # would still be satisfied by the survivor and the gate would silently stop covering that obligation.
    for sentinel in MODULE.REQUIRED_SENTINELS:
        gutted = GOOD_PATCH.replace(f"+{sentinel}\n", "+fix removed\n")
        missing = MODULE.missing_sentinels(_added(gutted))
        assert missing == [sentinel], (
            f"dropping marker {sentinel!r} must fail the checker on that marker alone, got {missing!r}"
        )


def test_sentinels_in_context_or_removed_lines_do_not_count() -> None:
    # Same tokens, but as context (' ') and removal ('-') lines, never added ('+').
    sneaky = "\n".join(
        [
            "--- a/x",
            "+++ b/x",
            "@@ -1,3 +1,1 @@",
            " " + " ".join(MODULE.REQUIRED_SENTINELS),
            "-trap_armed removed",
            "+plain added line",
        ]
    )
    assert len(MODULE.missing_sentinels(_added(sneaky))) == len(MODULE.REQUIRED_SENTINELS), (
        "markers that only appear as context or removed lines must not satisfy the check"
    )


def test_plusplusplus_header_excluded() -> None:
    # A '+++' file header must not be mistaken for an added content line.
    assert "std::expected<void, OsError>" not in _added("+++ b/std::expected<void, OsError>\n"), (
        "the +++ header is not added content"
    )


def test_patch_files_sorted_order() -> None:
    with tempfile.TemporaryDirectory() as d:
        dp = Path(d)
        (dp / "0002-second.patch").write_text("x", encoding="utf-8")
        (dp / "0001-first.patch").write_text("x", encoding="utf-8")
        (dp / "notes.txt").write_text("x", encoding="utf-8")  # non-patch ignored
        names = [p.name for p in MODULE.patch_files(dp)]
        assert names == ["0001-first.patch", "0002-second.patch"], names


def test_apply_check_accepts_relative_paths() -> None:
    # `git init` plus `git apply --check` writes no object, pack or index, so the tree this cleans up holds no
    # read-only Git content and needs no Windows-specific rmtree handling.
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        submodule = root / "submodule"
        submodule.mkdir()
        subprocess.run(["git", "init", "--quiet"], cwd=submodule, check=True)
        (submodule / "value.txt").write_text("before\n", encoding="utf-8")
        patch = root / "change.patch"
        patch.write_text(
            "--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-before\n+after\n",
            encoding="utf-8",
        )
        previous = Path.cwd()
        try:
            os.chdir(root)
            assert MODULE.patch_applies_or_present(Path("submodule"), Path("change.patch"))
        finally:
            os.chdir(previous)


def test_patchset_sha256_stable_and_order_independent_input() -> None:
    with tempfile.TemporaryDirectory() as d:
        dp = Path(d)
        (dp / "0001.patch").write_text("alpha", encoding="utf-8")
        (dp / "0002.patch").write_text("beta", encoding="utf-8")
        first = MODULE.patchset_sha256(MODULE.patch_files(dp))
        # Recomputing over the same sorted set is deterministic.
        assert first == MODULE.patchset_sha256(MODULE.patch_files(dp))
        # Content change moves the hash.
        (dp / "0002.patch").write_text("BETA", encoding="utf-8")
        assert MODULE.patchset_sha256(MODULE.patch_files(dp)) != first


def test_patchset_sha256_is_line_ending_agnostic() -> None:
    # A git checkout may store the patch CRLF (Windows autocrlf) or LF; the frozen hash must not change.
    with tempfile.TemporaryDirectory() as d:
        lf = Path(d) / "lf"
        lf.mkdir()
        (lf / "0001.patch").write_bytes(b"line one\nline two\n")
        crlf = Path(d) / "crlf"
        crlf.mkdir()
        (crlf / "0001.patch").write_bytes(b"line one\r\nline two\r\n")
        assert MODULE.patchset_sha256(MODULE.patch_files(lf)) == MODULE.patchset_sha256(MODULE.patch_files(crlf))


def test_submodule_url_parsed_and_fork_detected() -> None:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        gm = root / ".gitmodules"
        gm.write_text(
            '[submodule "external/safetyhook"]\n\tpath = external/safetyhook\n'
            "\turl = https://github.com/cursey/safetyhook.git\n",
            encoding="utf-8",
        )
        url = MODULE.submodule_url(root)
        assert url is not None and MODULE.UPSTREAM_URL_RE.search(url.lower()), url
        gm.write_text(
            '[submodule "external/safetyhook"]\n\turl = https://github.com/someuser/safetyhook.git\n',
            encoding="utf-8",
        )
        fork = MODULE.submodule_url(root)
        assert fork is not None and not MODULE.UPSTREAM_URL_RE.search(fork.lower()), fork


def test_upstream_url_regex_forms() -> None:
    ok = [
        "https://github.com/cursey/safetyhook.git",
        "git@github.com:cursey/safetyhook.git",  # SSH scp form (colon, no scheme)
        "ssh://git@github.com/cursey/safetyhook.git",  # ssh:// url form
        "https://github.com/cursey/safetyhook",  # no .git suffix
    ]
    bad = [
        "https://github.com/someuser/safetyhook.git",  # different owner
        "https://github.com/cursey/safetyhook-fork.git",  # look-alike suffix
        "https://evilgithub.com/cursey/safetyhook.git",  # hostile prefixed host
        "https://notgithub.com/cursey/safetyhook.git",  # hostile prefixed host
        "https://github.com.evil.com/cursey/safetyhook.git",  # hostile suffixed host
    ]
    for u in ok:
        assert MODULE.UPSTREAM_URL_RE.search(u.strip().lower()), f"should accept {u}"
    for u in bad:
        assert not MODULE.UPSTREAM_URL_RE.search(u.strip().lower()), f"should reject {u}"


FIXTURE_PATCH = (
    "diff --git a/src/backend.cpp b/src/backend.cpp\n"
    "--- a/src/backend.cpp\n"
    "+++ b/src/backend.cpp\n"
    "@@ -1 +1,2 @@\n"
    "-int base();\n"
    "+int reviewed();\n"
    "+int also_reviewed();\n"
    "diff --git a/include/backend.hpp b/include/backend.hpp\n"
    "--- a/include/backend.hpp\n"
    "+++ b/include/backend.hpp\n"
    "@@ -1 +1 @@\n"
    "-int declared();\n"
    "+int reviewed_declaration();\n"
)


def _git(cwd: Path, *arguments) -> None:
    subprocess.run(
        ["git", "-c", "user.name=dmk", "-c", "user.email=dmk@example.invalid", "-C", str(cwd), *arguments],
        check=True,
        capture_output=True,
    )


def _fixture_checkout(directory: str):
    """Return (submodule path, [patch]) for a pristine mini checkout the patch reconstructs."""
    root = Path(directory)
    submodule = root / "submodule"
    (submodule / "src").mkdir(parents=True)
    (submodule / "include").mkdir(parents=True)
    (submodule / "src" / "backend.cpp").write_bytes(b"int base();\n")
    (submodule / "src" / "untouched.cpp").write_bytes(b"int untouched();\n")
    (submodule / "include" / "backend.hpp").write_bytes(b"int declared();\n")
    _git(submodule, "init", "--quiet")
    _git(submodule, "add", ".")
    _git(submodule, "commit", "--quiet", "-m", "base")
    patch = root / "0001-fixture.patch"
    patch.write_bytes(FIXTURE_PATCH.encode("utf-8"))
    return submodule, [patch]


def _apply(submodule: Path, patch: Path) -> None:
    subprocess.run(["git", "-C", str(submodule), "apply", "--", str(patch)], check=True, capture_output=True)


def _problems(submodule: Path, patches, expect: str = "any"):
    return MODULE.backend_state_problems(submodule, patches, expect)


def _ignore(submodule: Path, pattern: str) -> None:
    """Append one fixture-only ignore pattern without changing a tracked worktree file."""
    exclude = submodule / ".git" / "info" / "exclude"
    exclude.write_bytes(exclude.read_bytes() + pattern.encode("utf-8") + b"\n")


def _run_cmake(submodule: Path, patches):
    """Run the production script-mode patch module against a throwaway checkout."""
    cmake = shutil.which("cmake")
    assert cmake is not None, "cmake must be on PATH for the production-module fixtures"
    return subprocess.run(
        [
            cmake,
            f"-DDMK_SUBMODULE_DIR={submodule}",
            f"-DDMK_PATCH_DIR={patches[0].parent}",
            "-P",
            str(CMAKE_MODULE),
        ],
        capture_output=True,
        text=True,
    )


def test_patch_targets_read_only_file_headers() -> None:
    with tempfile.TemporaryDirectory() as d:
        patch = Path(d) / "0001.patch"
        # The removed line renders as '--- gone', which a header-agnostic reader would take for a file header.
        patch.write_text(
            "diff --git a/src/backend.cpp b/src/backend.cpp\n"
            "--- a/src/backend.cpp\n"
            "+++ b/src/backend.cpp\n"
            "@@ -1,2 +1 @@\n"
            "--- gone\n"
            "+kept\n",
            encoding="utf-8",
        )
        assert MODULE.patch_targets([patch]) == {"src/backend.cpp"}


def test_pristine_and_patched_states_are_the_only_accepted_ones() -> None:
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        assert _problems(submodule, patches) == [], "a pristine pinned base is a legitimate pre-configure state"
        assert _problems(submodule, patches, "pristine") == []
        assert _problems(submodule, patches, "patched"), "a pristine tree must not satisfy the patched requirement"

        _apply(submodule, patches[0])
        assert _problems(submodule, patches) == [], "the exact reviewed patch output must be accepted"
        assert _problems(submodule, patches, "patched") == []
        assert _problems(submodule, patches, "pristine"), "a patched tree must not satisfy the pristine requirement"


def test_an_extra_tracked_edit_is_refused() -> None:
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        _apply(submodule, patches[0])
        (submodule / "src" / "untouched.cpp").write_bytes(b"int untouched();\nint smuggled();\n")
        problems = _problems(submodule, patches)
        assert any("outside the vendored patch" in problem for problem in problems), problems


def test_an_edit_inside_a_patched_file_is_refused() -> None:
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        _apply(submodule, patches[0])
        # The patch still reverse-applies cleanly here, so only byte equality against the reconstruction catches it.
        target = submodule / "src" / "backend.cpp"
        target.write_bytes(target.read_bytes() + b"int smuggled();\n")
        problems = _problems(submodule, patches)
        assert any("not byte-equal to the reviewed patch output" in problem for problem in problems), problems


def test_a_patch_that_removes_a_file_agrees_with_a_tree_that_removed_it() -> None:
    # Absent on both sides is the patch's own outcome, not a difference; a file the patch removes but the tree kept is.
    removal = (
        "diff --git a/src/untouched.cpp b/src/untouched.cpp\n"
        "deleted file mode 100644\n"
        "--- a/src/untouched.cpp\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-int untouched();\n"
    )
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        patches[0].write_bytes((FIXTURE_PATCH + removal).encode("utf-8"))
        _apply(submodule, patches[0])
        assert _problems(submodule, patches) == []
        # Re-created with different content, so git still reports it changed and the reconstruction is what decides.
        (submodule / "src" / "untouched.cpp").write_bytes(b"int smuggled();\n")
        problems = _problems(submodule, patches)
        assert any("should have been removed" in problem for problem in problems), problems


def test_an_incompletely_applied_patch_is_refused() -> None:
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        _apply(submodule, patches[0])
        _git(submodule, "checkout", "--", "include/backend.hpp")
        problems = _problems(submodule, patches)
        assert any("applied delta is incomplete" in problem for problem in problems), problems


def test_an_untracked_source_is_refused_but_the_lock_marker_is_not() -> None:
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        _apply(submodule, patches[0])
        (submodule / MODULE.LOCK_MARKER).write_bytes(b"")
        assert _problems(submodule, patches) == [], "the configure-time lock marker is the one allowed exception"
        (submodule / "src" / "smuggled.cpp").write_bytes(b"int smuggled();\n")
        problems = _problems(submodule, patches)
        assert any("untracked content" in problem for problem in problems), problems


def test_staged_content_is_refused() -> None:
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        _apply(submodule, patches[0])
        _git(submodule, "add", "src/backend.cpp")
        problems = _problems(submodule, patches)
        assert any("staged content" in problem for problem in problems), problems


def test_reviewed_ignored_outputs_are_allowed_but_other_ignored_content_is_refused() -> None:
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        _apply(submodule, patches[0])
        _ignore(submodule, "build/")
        (submodule / "build").mkdir()
        (submodule / "build" / "CMakeCache.txt").write_bytes(b"generated\n")
        assert _problems(submodule, patches) == [], "a reviewed non-source output root must remain usable"

    refused = (("src/ignored.cpp", "src/ignored.cpp"), ("generated-private/", "generated-private/data.bin"))
    for pattern, relative in refused:
        with tempfile.TemporaryDirectory() as d:
            submodule, patches = _fixture_checkout(d)
            _apply(submodule, patches[0])
            _ignore(submodule, pattern)
            ignored = submodule / relative
            ignored.parent.mkdir(parents=True, exist_ok=True)
            ignored.write_bytes(b"unreviewed\n")
            problems = _problems(submodule, patches)
            assert any("ignored content outside reviewed generated-output roots" in problem for problem in problems), (
                pattern,
                problems,
            )


def test_assume_unchanged_and_skip_worktree_are_refused() -> None:
    for option in ("--assume-unchanged", "--skip-worktree"):
        with tempfile.TemporaryDirectory() as d:
            submodule, patches = _fixture_checkout(d)
            _apply(submodule, patches[0])
            _git(submodule, "update-index", option, "src/untouched.cpp")
            (submodule / "src" / "untouched.cpp").write_bytes(b"int untouched();\nint hidden();\n")
            problems = _problems(submodule, patches)
            assert any("visibility flags" in problem for problem in problems), (option, problems)


def test_untracked_query_failure_is_refused() -> None:
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        _apply(submodule, patches[0])
        original = MODULE.git_paths

        def fail_ordinary_untracked(cwd: Path, *arguments):
            if arguments[:2] == ("ls-files", "--others") and "--ignored" not in arguments:
                return None
            return original(cwd, *arguments)

        MODULE.git_paths = fail_ordinary_untracked
        try:
            problems = _problems(submodule, patches, "patched")
        finally:
            MODULE.git_paths = original
        assert any("could not enumerate untracked content" in problem for problem in problems), problems


def test_cmake_module_declares_the_membership_policy_before_its_functions() -> None:
    """The `-P` entry point has no project policy state, so the module must set CMP0057 itself.

    A function captures the policy state where it is defined, so the declaration has to precede the first function.
    Pinned as source rather than behavior because CMake 4 forces this policy NEW and cannot reproduce the failure;
    on CMake 3.x every `IN_LIST` below aborts the backend check with "Unknown arguments specified".
    """
    text = CMAKE_MODULE.read_text(encoding="utf-8")
    policy = text.find("cmake_policy(SET CMP0057 NEW)")
    assert policy >= 0, "cmake/DMKBackendPatch.cmake must set CMP0057 for its IN_LIST membership tests"
    assert policy < text.index("function("), "CMP0057 must be set before the functions that rely on it"
    assert "IN_LIST" in text, "the policy exists for the IN_LIST tests; drop it only with them"


def test_cmake_script_mode_requires_both_directories() -> None:
    cmake = shutil.which("cmake")
    assert cmake is not None, "cmake must be on PATH for the production-module fixtures"
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        definitions = (
            (),
            (f"-DDMK_SUBMODULE_DIR={root}",),
            (f"-DDMK_PATCH_DIR={root}",),
            # One case per operand of the guard's OR, so dropping either half leaves a case failing.
            (f"-DDMK_SUBMODULE_DIR={root}", "-DDMK_PATCH_DIR="),
            ("-DDMK_SUBMODULE_DIR=", f"-DDMK_PATCH_DIR={root}"),
        )
        for arguments in definitions:
            result = subprocess.run(
                [cmake, *arguments, "-P", str(CMAKE_MODULE)],
                capture_output=True,
                text=True,
            )
            output = result.stdout + result.stderr
            assert result.returncode != 0 and "requires nonempty DMK_SUBMODULE_DIR and DMK_PATCH_DIR" in output, (
                arguments,
                result.returncode,
                output,
            )


def test_cmake_module_discriminates_contaminated_backend_states() -> None:
    # Each fixture starts at the exact applied patch, so removing the production verifier makes every case return zero.
    cases = (
        "extra-tracked",
        "staged",
        "untracked",
        "ignored-source",
        "assume-unchanged",
        "skip-worktree",
    )
    for case in cases:
        with tempfile.TemporaryDirectory() as d:
            submodule, patches = _fixture_checkout(d)
            _apply(submodule, patches[0])
            if case == "extra-tracked":
                (submodule / "src" / "untouched.cpp").write_bytes(b"int untouched();\nint smuggled();\n")
            elif case == "staged":
                _git(submodule, "add", "src/backend.cpp")
            elif case == "untracked":
                (submodule / "src" / "smuggled.cpp").write_bytes(b"int smuggled();\n")
            elif case == "ignored-source":
                _ignore(submodule, "src/ignored.cpp")
                (submodule / "src" / "ignored.cpp").write_bytes(b"int ignored();\n")
            else:
                option = "--assume-unchanged" if case == "assume-unchanged" else "--skip-worktree"
                _git(submodule, "update-index", option, "src/untouched.cpp")
                (submodule / "src" / "untouched.cpp").write_bytes(b"int untouched();\nint hidden();\n")

            result = _run_cmake(submodule, patches)
            output = result.stdout + result.stderr
            assert result.returncode != 0 and "not exactly the reviewed patch output" in output, (
                case,
                result.returncode,
                output,
            )


def test_cmake_module_accepts_reviewed_ignored_output() -> None:
    with tempfile.TemporaryDirectory() as d:
        submodule, patches = _fixture_checkout(d)
        _apply(submodule, patches[0])
        _ignore(submodule, "build/")
        (submodule / "build").mkdir()
        (submodule / "build" / "CMakeCache.txt").write_bytes(b"generated\n")
        result = _run_cmake(submodule, patches)
        output = result.stdout + result.stderr
        assert result.returncode == 0, output
        assert _problems(submodule, patches, "patched") == []


def test_line_ending_policy_does_not_decide_equality() -> None:
    # core.autocrlf decides whether a checkout stores the patched files LF or CRLF, and it can differ between the
    # tree under test and the scratch reconstruction. Both spellings are the same reviewed content.
    for ending in (b"\n", b"\r\n"):
        with tempfile.TemporaryDirectory() as d:
            submodule, patches = _fixture_checkout(d)
            _apply(submodule, patches[0])
            for relative in ("src/backend.cpp", "include/backend.hpp"):
                path = submodule / relative
                path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", ending))
            assert _problems(submodule, patches) == [], ending


def test_shipped_patchset_matches_pinned_hash() -> None:
    # The real vendored patch set must equal the pinned SHA-256, or the freeze is broken.
    root = Path(__file__).resolve().parent.parent
    paths = MODULE.patch_files(root / MODULE.PATCH_DIR)
    assert paths, "the shipped patch directory must not be empty"
    assert MODULE.patchset_sha256(paths) == MODULE.EXPECTED_PATCH_SHA256, (
        "shipped patch set != EXPECTED_PATCH_SHA256; regenerate the patch or update the constant"
    )


def test_base_commit_is_full_sha() -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", MODULE.EXPECTED_BASE_COMMIT), MODULE.EXPECTED_BASE_COMMIT


def test_shipped_gitlink_matches_pinned_base() -> None:
    # The committed submodule gitlink must equal the documented base, or the checker's base guard is stale.
    root = Path(__file__).resolve().parent.parent
    gitlink = MODULE.git_rev(root, f"HEAD:{MODULE.SUBMODULE}")
    if gitlink is None:
        return  # not a git checkout (e.g. a source tarball); nothing to assert
    assert gitlink == MODULE.EXPECTED_BASE_COMMIT, f"gitlink {gitlink} != EXPECTED_BASE_COMMIT {MODULE.EXPECTED_BASE_COMMIT}"


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"backend-patch checker self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
