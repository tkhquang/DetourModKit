#!/usr/bin/env python3
"""Regression fixtures for the vendored backend-patch model probe.

Exercises the pure helpers: patch discovery/order, added-line extraction, fix-marker
detection, patch-set hashing, and .gitmodules URL matching. The git-apply reconstruction
runs against the live submodule in CI and at configure time; it is not re-simulated here.

Every fixture writes into a TemporaryDirectory context so nothing is left on disk, even when
an assertion fails.
"""

import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check_backend_patch.py"
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
