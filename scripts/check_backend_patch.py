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

    if failures:
        print("FAIL: backend-patch model check found problems:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"OK: {SUBMODULE} pinned upstream and {len(paths)} vendored patch(es) carry every backend fix.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
