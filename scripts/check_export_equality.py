#!/usr/bin/env python3
"""Installed-contract equality gate between two DetourModKit install prefixes.

DMK_BUILD_TESTS must not change what a consumer receives: the exported usage requirements, package config,
ABI record, and every installed header have to be identical whether or not the producing tree built tests.
This gate takes two install prefixes (one from a tests-ON configure, one from tests-OFF, same toolchain and
configuration) and byte-compares their consumer-visible contract:

  * every file under lib*/cmake/DetourModKit/ (Config, ConfigVersion, Targets and per-config Targets files,
    and the DetourModKitAbi.cmake record)
  * every file under include/

Archives are compared by PRESENCE only: a tests-ON tree legitimately compiles test seams into the archive
(that build is never what ships), so object-code equality is not part of the contract this gate holds; the
release pipeline installs the shipped prefix from a tests-OFF producer instead.

Exit status is 1 with the differing paths printed when the contracts diverge, else 0.
"""
import filecmp
import sys
from pathlib import Path


LIB_DIR_CANDIDATES = ("lib", "lib64")
ARCHIVE_SUFFIXES = (".a", ".lib")
REQUIRED_ARCHIVE_NAMES = ("DetourModKit", "safetyhook", "Zydis", "Zycore")


def lib_dir(prefix):
    for name in LIB_DIR_CANDIDATES:
        candidate = prefix / name / "cmake" / "DetourModKit"
        if candidate.is_dir():
            return prefix / name
    for name in LIB_DIR_CANDIDATES:
        candidate = prefix / name
        if candidate.is_dir():
            return candidate
    return prefix / LIB_DIR_CANDIDATES[0]


def lib_cmake_dir(prefix):
    return lib_dir(prefix) / "cmake" / "DetourModKit"


def rel_files(root):
    """Every regular file under root, as sorted prefix-relative POSIX paths (empty when root is absent)."""
    if not root.is_dir():
        return []
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def compare_tree(root_a, root_b, label, violations):
    for side, root in (("A", root_a), ("B", root_b)):
        if not root.is_dir():
            violations.append(f"{label}: prefix {side} has no such directory")
    if not root_a.is_dir() or not root_b.is_dir():
        return

    files_a = rel_files(root_a)
    files_b = rel_files(root_b)
    if not files_a:
        violations.append(f"{label}: prefix A contains no files")
    if not files_b:
        violations.append(f"{label}: prefix B contains no files")
    for only_a in sorted(set(files_a) - set(files_b)):
        violations.append(f"{label}/{only_a}: present only in prefix A")
    for only_b in sorted(set(files_b) - set(files_a)):
        violations.append(f"{label}/{only_b}: present only in prefix B")
    for common in sorted(set(files_a) & set(files_b)):
        if not filecmp.cmp(root_a / common, root_b / common, shallow=False):
            violations.append(f"{label}/{common}: contents differ between the two prefixes")


def archive_names(prefix):
    root = lib_dir(prefix)
    if not root.is_dir():
        return []
    return sorted(
        path.name for path in root.iterdir() if path.is_file() and path.suffix.lower() in ARCHIVE_SUFFIXES)


def archive_set_provides(archives, required):
    accepted_stems = {required.casefold(), f"lib{required}".casefold()}
    return any(Path(archive).stem.casefold() in accepted_stems for archive in archives)


def compare_archive_presence(prefix_a, prefix_b, violations):
    archives_a = archive_names(prefix_a)
    archives_b = archive_names(prefix_b)
    for required in REQUIRED_ARCHIVE_NAMES:
        if not archive_set_provides(archives_a, required):
            violations.append(f"archives: prefix A has no {required} archive")
        if not archive_set_provides(archives_b, required):
            violations.append(f"archives: prefix B has no {required} archive")
    for only_a in sorted(set(archives_a) - set(archives_b)):
        violations.append(f"archives/{only_a}: present only in prefix A")
    for only_b in sorted(set(archives_b) - set(archives_a)):
        violations.append(f"archives/{only_b}: present only in prefix B")


def main():
    if len(sys.argv) != 3:
        print("usage: check_export_equality.py <install-prefix-a> <install-prefix-b>")
        return 2

    prefix_a = Path(sys.argv[1]).resolve()
    prefix_b = Path(sys.argv[2]).resolve()
    for prefix in (prefix_a, prefix_b):
        if not prefix.is_dir():
            print(f"export-equality gate FAILED: prefix '{prefix}' does not exist or is not a directory")
            return 1

    violations = []
    compare_tree(lib_cmake_dir(prefix_a), lib_cmake_dir(prefix_b), "cmake/DetourModKit", violations)
    compare_tree(prefix_a / "include", prefix_b / "include", "include", violations)
    compare_archive_presence(prefix_a, prefix_b, violations)

    if violations:
        print(f"Export-equality gate FAILED between '{prefix_a}' (A) and '{prefix_b}' (B):\n")
        for violation in violations:
            print("  " + violation)
        print(f"\n{len(violations)} difference(s): the installed contract depends on the producing tree's options.")
        return 1
    print("Export-equality gate passed: both prefixes ship an identical consumer contract.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
