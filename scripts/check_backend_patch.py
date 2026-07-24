#!/usr/bin/env python3
"""Fail if the vendored SafetyHook backend-patch model is broken.

``external/safetyhook`` is pinned to a commit the configured upstream remote (``cursey/safetyhook``)
actually serves, so a fresh ``git submodule update --init`` resolves it. DMK's two backend fixes --
trap-transaction status reporting and post-static-destruction teardown -- exist on no upstream ref,
so they are carried in-tree under ``cmake/safetyhook_patches/`` and re-applied to the submodule at
configure time by ``cmake/DMKBackendPatch.cmake``. That arrangement has three ways to rot silently,
each of which would ship an un-patched or fork-dependent backend, and this check fails closed on all:

1. ``.gitmodules`` gets repointed at a personal fork. The model is "upstream pin + vendored patches",
   not a fork dependency; a fork URL means the patch directory is now dead weight and the release no
   longer builds from an upstream-served ref.
2. The patch directory is emptied or the patches drift off the pinned base, so ``git apply`` can no
   longer reconstruct the reviewed backend tree.
3. A patch is edited so a fix is dropped or its logic inverted. The patch set is frozen by a pinned
   SHA-256, so any content change fails the gate until ``EXPECTED_PATCH_SHA256`` is deliberately updated.

The check is offline and portable: it inspects ``.gitmodules`` and the patch files, confirms the patch
set matches the pinned hash and carries every fix marker, that the parent gitlink and (when initialized)
the submodule HEAD are the documented base commit, and that each patch applies cleanly to that base or
is already present. No network or built archive is needed. See AGENTS.md [B-01].
"""

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

SUBMODULE = "external/safetyhook"
PATCH_DIR = "cmake/safetyhook_patches"
# The model depends on the UPSTREAM remote serving the pinned base. A fork URL defeats the point. Anchored at BOTH
# ends and restricted to the accepted GitHub HTTPS/SSH forms, so a valid SSH url (git@github.com:cursey/safetyhook.git)
# matches while a look-alike (cursey/safetyhook-fork) and a hostile prefixed host (evilgithub.com, notgithub.com) are
# rejected rather than matched on an unanchored substring.
UPSTREAM_URL_RE = re.compile(r"^(?:https?://|ssh://git@|git://|git@)github\.com[:/]cursey/safetyhook(?:\.git)?/?$")
# SHA-256 over the patch set (each file's name, a NUL, then its bytes, in sorted order). This freezes the vendored
# delta to the exact reviewed content: an edit that keeps a fix marker but inverts the logic still changes this hash
# and fails the gate. Regenerate ONLY alongside a deliberate backend re-pin, then update this value:
#   python -c "import hashlib,pathlib; h=hashlib.sha256(); [ (h.update(p.name.encode()),h.update(b'\0'),h.update(p.read_bytes())) for p in sorted(pathlib.Path('cmake/safetyhook_patches').glob('*.patch')) ]; print(h.hexdigest())"
EXPECTED_PATCH_SHA256 = "21d124c525a75393d152e072e97d8285787a958611812f5be02ba576f6d2995b"
# The documented upstream base the patch reconstructs. Both the parent gitlink and the checked-out submodule HEAD
# must equal this, so a silent re-pin is rejected even when the patch still reverse-applies against the drifted
# commit (the former pin 99e6888 is exactly such a commit). Update alongside EXPECTED_PATCH_SHA256 on a re-pin.
EXPECTED_BASE_COMMIT = "f44cc070a8340f2f26649553c49533475417304d"
# Substrings that MUST survive in the combined added lines of the patch set, one pair per fix, so an
# edit that guts a fix is caught. Chosen from the added ('+') hunks, not the surrounding context.
REQUIRED_SENTINELS = [
    "Error::failed_to_unprotect",  # fix 1: trap_threads reports a failed transaction ...
    "std::expected<void, OsError>",  # ... by returning an error instead of void
    "is_destructed",  # fix 2: teardown proceeds once TrapManager's static dtor ran ...
    "trap_armed",  # ... skipping the net rather than refusing the unhook
]


def patch_files(patch_dir: Path):
    """Return the *.patch files in application order (filename-sorted, as CMake globs them)."""
    return sorted(patch_dir.glob("*.patch"))


def patchset_sha256(paths) -> str:
    """SHA-256 over the patch set: each file's name, a NUL, then its bytes, in sorted order."""
    h = hashlib.sha256()
    for p in paths:
        h.update(p.name.encode("utf-8"))
        h.update(b"\0")
        h.update(p.read_bytes())
    return h.hexdigest()


def combined_added_lines(paths) -> str:
    """Concatenate the added ('+', excluding the '+++' file header) lines across every patch."""
    out = []
    for p in paths:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                out.append(line[1:])
    return "\n".join(out)


def missing_sentinels(added_text: str, sentinels=REQUIRED_SENTINELS):
    """Return the required sentinels absent from the patch set's added lines."""
    return [s for s in sentinels if s not in added_text]


def submodule_url(repo_root: Path, name: str = SUBMODULE):
    """Read the submodule's configured URL from .gitmodules, or None if unset/missing."""
    result = subprocess.run(
        ["git", "config", "-f", str(repo_root / ".gitmodules"), "--get", f"submodule.{name}.url"],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def patch_applies_or_present(submodule_dir: Path, patch: Path) -> bool:
    """True if `patch` cleanly applies to, or is already present in, the submodule checkout."""

    def check(*extra):
        return subprocess.run(
            ["git", "apply", *extra, "--check", "--", str(patch)],
            cwd=str(submodule_dir),
            capture_output=True,
            text=True,
        ).returncode == 0

    return check("--reverse") or check()


def git_rev(cwd: Path, ref: str):
    """Return the full SHA `ref` resolves to in the repo at `cwd`, or None if it does not resolve."""
    result = subprocess.run(
        ["git", "-C", str(cwd), "rev-parse", ref],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args()
    root: Path = args.repo_root
    failures = []

    # 0. git is needed to fetch the submodule on a fresh clone and to run the apply check below.
    if shutil.which("git") is None:
        print("FAIL: git is not on PATH; the vendored backend-patch model needs git to fetch and apply.")
        return 1

    # 1. Upstream URL, not a fork.
    url = submodule_url(root)
    if url is None:
        failures.append(f".gitmodules has no url for submodule '{SUBMODULE}'.")
    elif not UPSTREAM_URL_RE.search(url.strip().lower()):
        failures.append(
            f"submodule '{SUBMODULE}' url is '{url}', not the upstream cursey/safetyhook. "
            "The vendored-patch model requires an upstream-served pin; a fork url is not that model."
        )

    # 2. Patch directory is non-empty, byte-frozen to the reviewed delta, and carries every fix.
    paths = patch_files(root / PATCH_DIR)
    if not paths:
        failures.append(f"no *.patch files in '{PATCH_DIR}'; the backend fixes would be dropped.")
    else:
        actual = patchset_sha256(paths)
        if actual != EXPECTED_PATCH_SHA256:
            failures.append(
                f"the patch set in '{PATCH_DIR}' does not match the reviewed content "
                f"(sha256 {actual[:12]}... vs expected {EXPECTED_PATCH_SHA256[:12]}...). If this is a deliberate "
                "backend re-pin, regenerate the patch and update EXPECTED_PATCH_SHA256."
            )
        absent = missing_sentinels(combined_added_lines(paths))
        if absent:
            failures.append(
                f"the patch set in '{PATCH_DIR}' is missing required fix markers: {absent}. "
                "A backend fix was edited out of its patch."
            )

    # 3. Patches reconstruct the reviewed tree (only checkable with the submodule initialized).
    submodule_dir = root / SUBMODULE
    if paths and (submodule_dir / ".git").exists():
        for patch in paths:
            if not patch_applies_or_present(submodule_dir, patch):
                failures.append(
                    f"patch '{patch.name}' neither applies to nor is present in '{SUBMODULE}'. "
                    "The submodule is at an unexpected commit; re-init it to the pinned base."
                )
    elif paths:
        print(f"note: '{SUBMODULE}' is not initialized; skipping the apply check (URL and marker checks still ran).")

    # 4. The pin is the documented base commit, in both the parent gitlink and the checked-out submodule, so a
    # silent re-pin is rejected even when the patch still reverse-applies against the drifted commit. Unreadable
    # values (not a git repo, submodule uninitialized) are skipped rather than failed.
    gitlink = git_rev(root, f"HEAD:{SUBMODULE}")
    if gitlink is not None and gitlink != EXPECTED_BASE_COMMIT:
        failures.append(
            f"parent gitlink for '{SUBMODULE}' is {gitlink[:12]}..., not the documented base "
            f"{EXPECTED_BASE_COMMIT[:12]}...; move the pin back or update EXPECTED_BASE_COMMIT on a deliberate re-pin."
        )
    if (submodule_dir / ".git").exists():
        head = git_rev(submodule_dir, "HEAD")
        if head is not None and head != EXPECTED_BASE_COMMIT:
            failures.append(
                f"'{SUBMODULE}' HEAD is {head[:12]}..., not the documented base {EXPECTED_BASE_COMMIT[:12]}...; "
                "re-init it to the pinned base (git submodule update --init --force external/safetyhook)."
            )

    if failures:
        print("FAIL: backend-patch model check found problems:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"OK: {SUBMODULE} pinned upstream and {len(paths)} vendored patch(es) carry every backend fix.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
