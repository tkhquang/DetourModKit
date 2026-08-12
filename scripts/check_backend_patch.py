#!/usr/bin/env python3
"""Fail if the vendored SafetyHook backend-patch model is broken.

``external/safetyhook`` is pinned to a commit the configured upstream remote (``cursey/safetyhook``)
actually serves, so a fresh ``git submodule update --init`` resolves it. DMK's backend fixes --
trap-transaction status reporting, commit-truthful state, executable-route rundown, allocation-free release,
late-static handler retirement, and closed-window execute-fault retry -- exist on no upstream ref, so they are
carried in-tree under ``cmake/safetyhook_patches/`` and re-applied to the submodule at configure time by
``cmake/DMKBackendPatch.cmake``. That arrangement has three ways to rot silently,
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

A fourth way to ship an un-reviewed backend has nothing to do with the patch files: the submodule working
tree is where the patch is applied, so source-capable content left in it can enter the build too. Only two states are
legitimate -- the pristine pinned base before any configure, and exactly the reviewed patch output after
one -- and this check refuses everything between and beyond them: an extra tracked edit, staged content,
an untracked source, or a patched file whose bytes are not the reconstruction of base plus patch. The
configure-time lock marker and frozen non-source output roots that SafetyHook deliberately ignores are
the only exceptions. ``--expect-state`` pins which state a caller requires, so the quality workflow can
prove the checkout is pristine BEFORE configure and exactly the reviewed output AFTER it.

``cmake/DMKBackendPatch.cmake`` decides the same question at configure time, over the same model:
``patch_targets`` names the owned paths, and each one is compared against base-plus-patch rebuilt in a
scratch tree that is never the live checkout. The two implementations spell the canonical normalization
differently -- ``lf()`` here, ``git diff --ignore-cr-at-eol`` there -- because one has Python and the
other has only git, so ``test_check_backend_patch.py`` asserts they accept and refuse the same states
rather than trusting the two spellings to stay equivalent. Neither may rule on the changed-path SET
alone: an edit inside a target the patch already owns leaves that set identical and keeps the
idempotence reverse-apply clean, so only byte equality decides it.
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SUBMODULE = "external/safetyhook"
PATCH_DIR = "cmake/safetyhook_patches"
# Left in the submodule working tree by cmake/DMKBackendPatch.cmake's file(LOCK). It is the only ordinary untracked
# path the backend state may carry; ignored output is separately restricted to reviewed non-source roots.
LOCK_MARKER = ".dmk_patch.lock"
# SafetyHook explicitly ignores these generated output roots. None participates in the DMK add_subdirectory source
# graph: the library sources are named explicitly under src/, while the optional amalgamation globs only src/ and
# include/. Keep this frozen rather than trusting .gitignore or .git/info/exclude, either of which can hide source.
GENERATED_IGNORED_ROOTS = frozenset(
    {
        ".idea",
        ".vscode",
        ".vs",
        "__build",
        "amalgamated-dist",
        "build",
        "build32",
    }
)
# The model depends on the UPSTREAM remote serving the pinned base. A fork URL defeats the point. Anchored at BOTH
# ends and restricted to the accepted GitHub HTTPS/SSH forms, so a valid SSH url (git@github.com:cursey/safetyhook.git)
# matches while a look-alike (cursey/safetyhook-fork) and a hostile prefixed host (evilgithub.com, notgithub.com) are
# rejected rather than matched on an unanchored substring.
UPSTREAM_URL_RE = re.compile(r"^(?:https?://|ssh://git@|git://|git@)github\.com[:/]cursey/safetyhook(?:\.git)?/?$")
# SHA-256 over the patch set (each file's name, a NUL, then its bytes, in sorted order). This freezes the vendored
# delta to the exact reviewed content: an edit that keeps a fix marker but inverts the logic still changes this hash
# and fails the gate. Regenerate only alongside a reviewed backend-delta update or re-pin, then update this value:
#   python -c "import hashlib,pathlib; h=hashlib.sha256(); [ (h.update(p.name.encode()),h.update(b'\0'),h.update(p.read_bytes().replace(b'\r\n',b'\n'))) for p in sorted(pathlib.Path('cmake/safetyhook_patches').glob('*.patch')) ]; print(h.hexdigest())"
EXPECTED_PATCH_SHA256 = "a34cf7bc071d88f53db0be6331549ede5ff309d5022aad8433cf6f151e4f3c8e"
# The documented upstream base the patch reconstructs. Both the parent gitlink and the checked-out submodule HEAD
# must equal this, so a silent re-pin is rejected even when the patch still reverse-applies against the drifted
# commit (the former pin 99e6888 is exactly such a commit). Update alongside EXPECTED_PATCH_SHA256 on a re-pin.
EXPECTED_BASE_COMMIT = "f44cc070a8340f2f26649553c49533475417304d"
# Substrings that MUST survive in the combined added lines of the patch set, one pair per fix, so an
# edit that guts a fix is caught. Chosen from the added ('+') hunks, not the surrounding context.
REQUIRED_SENTINELS = [
    "Error::failed_to_unprotect",  # fix 1: trap_threads reports a failed transaction ...
    "std::expected<void, OsError>",  # ... by returning an error instead of void
    "patch_bytes_valid",  # fix 3: retained bytes carry explicit provenance ...
    "m_enabled = true;",  # ... enabled state changes at the patch mutation ...
    "m_enabled = false;",  # ... and disabled state at the restore mutation ...
    "reconcile_enabled",  # ... while a caller's exact byte witness can reconcile retained reachability ...
    "m_patch_bytes",  # ... while the emitted encoding is retained for ownership comparison ...
    "g_trap_restore_failure_override",  # ... with an address-scoped post-commit failure seam ...
    "g_trap_exception_target_override",  # ... plus an address-scoped exception target ...
    "g_trap_exception_stage_override",  # ... and independently published transaction stage ...
    "TrapExceptionStage::BEFORE_MUTATION",  # ... before the byte mutation ...
    "TrapExceptionStage::AFTER_MUTATION",  # ... or after it commits ...
    "throw std::bad_alloc{};",  # ... to prove the caller contains a real C++ exception
    "is_closed_window_execute_fault",  # fix 4: a DEP fault whose window already closed is retried ...
    "mbi.State == MEM_COMMIT",  # ... recognised by the page being committed and executable at fault time ...
    "ExceptionInformation[0] != 8",  # ... and restricted to execute faults so other violations still propagate
]

# PR-43 additions. Keep these separate so the checker self-test can mutation-test every new backend obligation rather
# than proving only that one representative marker is detected.
PR43_SENTINELS = [
    "struct AllocatorFreeNode",  # release metadata is provisioned on the throwing allocation path
    "AllocatorFreeNodeDeleter",  # the private node remains safely destructible from MSVC-facing headers
    "void Allocation::free() noexcept",  # destruction and move-release cannot propagate allocation failure
    "std::move(free_node)",  # each live allocation carries its own return node
    "void Allocation::abandon() noexcept",  # refused executable teardown can retain without allocator mutation
    "RoutedExternal",  # raw redirected entry opts into the stable executable route
    "struct InlineHook::RouteControl",  # never-reclaimed state cell owns route admission and allocator lifetime
    # Every marker below names code, never comment prose: a reworded comment must not be able to fail this gate, and
    # rewriting logic while leaving its comment intact must not be able to pass it.
    "ROUTE_WRAPPER_OFFSET",  # the gateway's fixed region layout that admission and rundown are emitted into
    "region_fits",  # emitted-code growth fails the create instead of splicing the next region or RouteControl
    "static_assert(asm_data.size() == 391)",  # the mid-stub layout is pinned to asm_data at compile time
    "offsetof(EXCEPTION_RECORD, NumberParameters)",  # the raw displacements the closed VEH branch walks are pinned
    "m_enabled ? cancel_route_rundown() : finish_route_rundown();",  # post-commit errors resolve from mutation truth
    "RouteParkStage::BEFORE_DESTINATION",  # deterministic proof reaches the pre-C++ interval
    "route_entries() const noexcept",  # callers can drain the full executable route
    "constexpr size_t routed_stub_size = 404",  # mid stub carries a stable exit pointer
    "m_hook.set_mid_route();",  # mid entry stays admitted across the generated stub
    "m_stub.abandon();",  # self/unwaitable route retains rather than recycles live bytes
    "struct TrapGatewayData",  # selected-before-entry VEH callbacks land in permanent storage
    "std::atomic<uint64_t> admission",  # high-bit close and low-bit entry count share one ordered cell
    "transactions_closed",  # late transactions refuse before their first protection change
    "AddVectoredExceptionHandler(1, gateway)",  # Windows dispatch names the stable gateway, not module C++
    "fetch_or(closed_bit",  # retirement closes admission before unregistering the handler
    "RemoveVectoredExceptionHandler",  # the registered gateway is retired under transaction serialization
    "g_trap_transaction_hold",  # deterministic live-transaction retirement proof
    "g_trap_protect_calls",  # refusal oracle proves no VirtualProtect occurred
]

REQUIRED_SENTINELS += PR43_SENTINELS

# PR-47 checkpoint B additions: routed-frame unwind metadata and retained-chain capacity accounting. Kept separate for
# the same reason as PR43_SENTINELS, and drawn from code rather than comment prose.
PR47B_SENTINELS = [
    "vm_register_unwind_table",  # generated frames publish platform unwind metadata ...
    "RtlAddFunctionTable",  # ... through the platform's dynamic function table ...
    "vm_unregister_unwind_table",  # ... which is withdrawn only for storage nothing ever reached ...
    "g_unwind_registration_failure",  # ... and whose refusal is drivable, so the rollback branch is proved
    "g_unwind_unregistration_failure",  # failed removal is also drivable and retains all referenced storage
    "struct RouteUnwindTable",  # the records live inside the gateway allocation, sharing the code's lifetime
    "Error::failed_to_register_unwind",  # a refused registration fails creation instead of publishing blind frames
    "emit_flag_frame",  # each routed flag frame saves a nonvolatile register before capturing RFLAGS ...
    "emit_flag_restore",  # ... then restores RFLAGS before the flag-transparent pop/jump epilogue
    "push_rbx_at_1",  # the unwind record describes the saved nonvolatile stack word
    "alloc_8_at_2",  # and separately describes pushfq's eight-byte stack effect
    "route_retention_stats",  # the permanently retained chain is accounted ...
    "logical_high_water",  # ... on a monotonic logical high-water ...
    "committed_reserved",  # ... through an independently bounded committed reservation ...
    "committed_high_water",  # ... and a backing-block committed high-water ...
    "Error::route_retention_exhausted",  # ... with refusal before anything is published ...
    "class SAFETYHOOK_API RouteRetentionCredit",  # ... and a transaction-wide pre-reservation for multi-hook installs
    "credit->consume",  # the explicit object-owned credit transfers one complete slot without ambient TLS
    "m_route_gateway.backing_size()",  # retained commitment is derived from the actual allocator backing blocks
    "whole->start == allocation.address",  # wholly free route blocks are released instead of becoming collateral
    "charge_publication",  # every post-publication return or exception converts its reservation exactly once
    "m_route_retention_charged",  # repeated enable/destroy paths cannot double-charge the route
    "add_route_retention",  # the mid stub is folded into the route's chain rather than escaping the ceiling
]

REQUIRED_SENTINELS += PR47B_SENTINELS


def patch_files(patch_dir: Path):
    """Return the *.patch files in application order (filename-sorted, as CMake globs them)."""
    return sorted(patch_dir.glob("*.patch"))


def patchset_sha256(paths) -> str:
    """SHA-256 over the patch set: each file's name, a NUL, then its bytes, in sorted order."""
    h = hashlib.sha256()
    for p in paths:
        h.update(p.name.encode("utf-8"))
        h.update(b"\0")
        # Normalize CRLF to LF so the hash is stable across checkouts that re-encode line endings: a Windows
        # autocrlf checkout stores the patch as CRLF, which would otherwise hash differently in CI than the
        # LF value pinned here.
        h.update(p.read_bytes().replace(b"\r\n", b"\n"))
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

    submodule_dir = submodule_dir.resolve()
    patch = patch.resolve()

    def check(*extra):
        return subprocess.run(
            ["git", "apply", *extra, "--check", "--", str(patch)],
            cwd=str(submodule_dir),
            capture_output=True,
            text=True,
        ).returncode == 0

    return check("--reverse") or check()


GIT_DIFF_HEADER = re.compile(r"^diff --git a/(?P<old>.+) b/(?P<new>.+)$")


def patch_targets(paths):
    """Return the submodule-relative paths the patch set writes.

    Read from the `diff --git` headers rather than the `---`/`+++` lines: a removed line whose own text begins with
    `-- ` renders as `--- ...` inside a hunk, and taking that for a file header would invent a target.
    """
    targets = set()
    for path in paths:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            header = GIT_DIFF_HEADER.match(line)
            if header:
                targets.add(header.group("new"))
    return targets


def git_output(cwd: Path, *arguments):
    """Return git's stdout for `arguments` run in `cwd`, or None when the command failed."""
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = subprocess.run(
        ["git", "-C", str(cwd), *arguments], capture_output=True, text=True, env=environment
    )
    return result.stdout if result.returncode == 0 else None


def git_paths(cwd: Path, *arguments):
    """Return the nonempty lines of a git command that prints one path per line, or None on failure."""
    output = git_output(cwd, *arguments)
    if output is None:
        return None
    return [line.strip() for line in output.splitlines() if line.strip()]


def replacement_object_problems(cwd: Path):
    """Return local replacement-object state that can redirect the reviewed commit's object reads."""
    problems = []
    replacement_base = os.environ.get("GIT_REPLACE_REF_BASE", "")
    if replacement_base:
        problems.append(
            "GIT_REPLACE_REF_BASE is set for the SafetyHook backend; the pinned commit's bytes cannot be trusted"
        )
    replacement_refs = git_paths(cwd, "for-each-ref", "--format=%(refname)", "refs/replace")
    if replacement_refs is None:
        problems.append("could not inspect SafetyHook replacement refs; the backend state cannot be decided")
    elif replacement_refs:
        problems.append(
            "replacement refs redirect the SafetyHook backend's pinned objects: {0}".format(replacement_refs)
        )
    return problems


def lf(data: bytes) -> bytes:
    """The bytes with CRLF folded to LF, so a checkout's line-ending policy cannot decide equality."""
    return data.replace(b"\r\n", b"\n")


def ignored_backend_output_allowed(path: str) -> bool:
    """Return whether an ignored path is confined to a reviewed generated-output root."""
    normalized = path.replace("\\", "/").rstrip("/")
    if not normalized or normalized.startswith("/"):
        return False
    first, _, remainder = normalized.partition("/")
    if first in GENERATED_IGNORED_ROOTS or first.startswith("cmake-build"):
        return True
    if first != "docs":
        return False
    return remainder == "Doxyfile" or remainder == "html" or remainder.startswith("html/") or (
        remainder == "latex" or remainder.startswith("latex/")
    )


def reconstruction_differences(submodule_dir: Path, paths, targets):
    """Return why the live patched files are not exactly base-plus-patch, or an empty list when they are."""
    problems = []
    with tempfile.TemporaryDirectory(prefix="dmk_backend_state_") as scratch:
        scratch_root = Path(scratch)
        tree = scratch_root / "tree"
        tree.mkdir()
        for target in sorted(targets):
            blob = subprocess.run(
                ["git", "-C", str(submodule_dir), "show", "HEAD:{0}".format(target)],
                capture_output=True,
                env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
            )
            destination = tree / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            if blob.returncode == 0:
                destination.write_bytes(lf(blob.stdout))

        for patch in paths:
            # Applied to base blobs in a scratch tree, never to the live checkout: this reconstructs what the reviewed
            # delta produces so the live bytes can be compared against it without mutating anything.
            normalized = scratch_root / patch.name
            normalized.write_bytes(lf(patch.read_bytes()))
            applied = subprocess.run(
                ["git", "apply", "--whitespace=nowarn", "--", str(normalized)],
                cwd=str(tree),
                capture_output=True,
                text=True,
            )
            if applied.returncode != 0:
                problems.append(
                    "patch '{0}' does not apply to the pinned base blobs: {1}".format(
                        patch.name, applied.stderr.strip() or "no diagnostic"
                    )
                )
                return problems

        for target in sorted(targets):
            expected = tree / target
            live = submodule_dir / target
            if not expected.is_file():
                # The patch removes this path. Absent on both sides is agreement, not a difference.
                if live.is_file():
                    problems.append("'{0}' should have been removed by the patch but is still present".format(target))
                continue
            if not live.is_file():
                problems.append("'{0}' is absent from the submodule working tree".format(target))
                continue
            if lf(live.read_bytes()) != lf(expected.read_bytes()):
                problems.append(
                    "'{0}' is not byte-equal to the reviewed patch output; the configured backend carries an edit "
                    "nobody reviewed".format(target)
                )
    return problems


def backend_state_problems(submodule_dir: Path, paths, expect):
    """Return why the submodule working tree is neither the pristine base nor the exact reviewed patch output."""
    problems = replacement_object_problems(submodule_dir)
    staged = git_paths(submodule_dir, "diff", "--cached", "--name-only")
    if staged is None:
        return ["could not read the submodule index; the backend state cannot be decided"]
    if staged:
        problems.append(
            "staged content in '{0}': {1}. The backend delta is carried by the vendored patch, never by the "
            "submodule index.".format(SUBMODULE, sorted(staged))
        )

    visibility = git_paths(submodule_dir, "ls-files", "-v")
    if visibility is None:
        return problems + ["could not read tracked-path visibility flags; the backend state cannot be decided"]
    hidden = sorted(
        entry[2:]
        for entry in visibility
        if entry and (entry[0].islower() or entry[0] == "S")
    )
    if hidden:
        problems.append(
            "tracked paths in '{0}' carry assume-unchanged or skip-worktree visibility flags: {1}. "
            "Those flags can hide backend edits from the state check.".format(SUBMODULE, hidden)
        )

    untracked = git_paths(submodule_dir, "ls-files", "--others", "--exclude-standard", "--directory")
    if untracked is None:
        return problems + ["could not enumerate untracked content; the backend state cannot be decided"]
    unexpected = sorted(set(untracked) - {LOCK_MARKER})
    if unexpected:
        problems.append(
            "untracked content in '{0}': {1}. Only '{2}' may be present.".format(SUBMODULE, unexpected, LOCK_MARKER)
        )

    ignored = git_paths(
        submodule_dir,
        "ls-files",
        "--others",
        "--ignored",
        "--exclude-standard",
        "--directory",
    )
    if ignored is None:
        return problems + ["could not enumerate ignored content; the backend state cannot be decided"]
    unexpected_ignored = sorted(
        path for path in set(ignored) if path != LOCK_MARKER and not ignored_backend_output_allowed(path)
    )
    if unexpected_ignored:
        problems.append(
            "ignored content outside reviewed generated-output roots in '{0}': {1}".format(
                SUBMODULE, unexpected_ignored
            )
        )

    changed = git_paths(submodule_dir, "diff", "HEAD", "--name-only")
    if changed is None:
        return problems + ["could not read the submodule working tree; the backend state cannot be decided"]

    targets = patch_targets(paths)
    if not changed:
        if expect == "patched":
            problems.append(
                "'{0}' is at the pristine pinned base, but the reviewed patch output was required. Configure a "
                "build tree (or run cmake/DMKBackendPatch.cmake) first.".format(SUBMODULE)
            )
        return problems

    if expect == "pristine":
        problems.append(
            "'{0}' is already patched, but the pristine pinned base was required. This phase must observe the "
            "checkout as a fresh clone leaves it.".format(SUBMODULE)
        )
        return problems

    extra = sorted(set(changed) - targets)
    if extra:
        problems.append(
            "tracked edits outside the vendored patch in '{0}': {1}".format(SUBMODULE, extra)
        )
    missing = sorted(targets - set(changed))
    if missing:
        problems.append(
            "the vendored patch changes {0} but the working tree does not; the applied delta is incomplete".format(
                missing
            )
        )
    if not extra and not missing:
        problems.extend(reconstruction_differences(submodule_dir, paths, targets))
    return problems


def git_rev(cwd: Path, ref: str):
    """Return the full SHA `ref` resolves to in the repo at `cwd`, or None if it does not resolve."""
    result = subprocess.run(
        ["git", "-C", str(cwd), "rev-parse", ref],
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
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
    parser.add_argument(
        "--expect-state",
        choices=("any", "pristine", "patched"),
        default="any",
        help="require the submodule working tree to be the pristine pinned base, the exact reviewed patch output, "
        "or (the default) whichever of the two it is",
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
                "reviewed backend-delta update or re-pin, regenerate the patch and update EXPECTED_PATCH_SHA256."
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

    # 5. The working tree is either the pristine pinned base or exactly the reviewed patch output, with nothing else
    # in it. This is what makes the CONFIGURED backend, rather than only the patch files, the reviewed one.
    if paths and (submodule_dir / ".git").exists():
        failures.extend(backend_state_problems(submodule_dir, paths, args.expect_state))
    elif args.expect_state != "any":
        failures.append(
            f"'{SUBMODULE}' is not initialized, so the {args.expect_state} backend state cannot be proved."
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
