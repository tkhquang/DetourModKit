#!/usr/bin/env python3
"""Regression fixtures for the vendored backend-patch model probe.

Exercises the pure helpers: patch discovery/order, added-line extraction, fix-marker
detection, patch-set hashing, and .gitmodules URL matching. The git-apply reconstruction
runs against the live submodule in CI and at configure time; it is not re-simulated here.

Every fixture writes into a TemporaryDirectory context so nothing is left on disk, even when
an assertion fails.
"""

import importlib.util
import re
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check_backend_patch.py"
SPEC = importlib.util.spec_from_file_location("check_backend_patch", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# A minimal well-formed patch body carrying both fixes across its added lines.
GOOD_PATCH = "\n".join(
    [
        "--- a/src/os.windows.cpp",
        "+++ b/src/os.windows.cpp",
        "@@ -1,2 +1,4 @@",
        "+std::expected<void, OsError> trap_threads() {",
        "+    if (!TrapManager::is_destructed) { trap_armed = true; }",
        "+    return std::unexpected{Error::failed_to_unprotect(m_target)};",
        " unchanged context line",
    ]
)


def _added(text: str) -> str:
    """Write `text` as a lone patch in a temp dir and return its extracted added lines."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "0001.patch"
        p.write_text(text, encoding="utf-8")
        return MODULE.combined_added_lines([p])


def test_all_sentinels_present_passes() -> None:
    assert MODULE.missing_sentinels(_added(GOOD_PATCH)) == [], "a complete patch must report no missing markers"


def test_missing_one_fix_is_reported() -> None:
    gutted = GOOD_PATCH.replace("trap_armed = true;", "/* fix removed */")
    assert "trap_armed" in MODULE.missing_sentinels(_added(gutted)), "dropping a fix marker must be flagged"


def test_sentinels_in_context_or_removed_lines_do_not_count() -> None:
    # Same tokens, but as context (' ') and removal ('-') lines, never added ('+').
    sneaky = "\n".join(
        [
            "--- a/x",
            "+++ b/x",
            "@@ -1,3 +1,1 @@",
            " std::expected<void, OsError> is_destructed trap_armed Error::failed_to_unprotect",
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
