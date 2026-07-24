#!/usr/bin/env python3
"""Dual-configuration package-matrix gate for an installed DetourModKit prefix.

check_install_prefix.py proves one installed prefix upholds the v4 encapsulation contract and is complete enough for a
single-configuration find_package consumer. This gate proves the configuration-specific packaging contract: a prefix
produced by one multi-config tree that installed several configurations must ship each configuration's DetourModKit and
dependency archives under distinct names, so Debug and Release coexist in one lib/ without overwrite or cross-link. It
also requires that the configuration-invariant package files (Config, ConfigVersion, Abi, Targets) exist exactly once
and that a per-configuration DetourModKitTargets-<config>.cmake fragment exists for every installed configuration.

The debug postfix ("d") applies to the Debug configuration only, matching the DetourModKit target's DEBUG_POSTFIX and
the per-config dependency install rules in CMakeLists.txt. Every other configuration ships unpostfixed archives.

Usage: check_package_matrix.py <install-prefix> [--configs Debug Release ...] [--debug-postfix d]
                               [--reference-prefix <single-config-prefix>]
Exit status is 1 with offenders printed when any invariant is violated, else 0.
"""
import argparse
import re
import sys
from pathlib import Path


LIB_DIR_CANDIDATES = ("lib", "lib64")
DEPENDENCIES = ("safetyhook", "Zydis", "Zycore")
# Configuration-invariant package files: one copy regardless of how many configurations were installed.
INVARIANT_CONFIG_FILES = (
    "DetourModKitConfig.cmake",
    "DetourModKitConfigVersion.cmake",
    "DetourModKitTargets.cmake",
    "DetourModKitAbi.cmake",
)


def lib_dir(prefix: Path) -> Path:
    """First existing lib directory under the prefix, else the primary candidate so a missing check reports a path."""
    for name in LIB_DIR_CANDIDATES:
        candidate = prefix / name
        if candidate.is_dir():
            return candidate
    return prefix / LIB_DIR_CANDIDATES[0]


def postfix_for(config: str, debug_postfix: str) -> str:
    """The archive name postfix DMK applies to a configuration. Only Debug carries the debug postfix."""
    return debug_postfix if config == "Debug" else ""


def archive_name(stem: str, postfix: str, archive_format: str, *, main_library: bool) -> str:
    """Return the exact installed archive name for one producer toolchain."""
    if archive_format == "mingw":
        return f"lib{stem}{postfix}.a"
    prefix = "lib" if main_library else ""
    return f"{prefix}{stem}{postfix}.lib"


def producer_archive_format(abi_path: Path) -> tuple[str | None, str | None]:
    """Read the package ABI record and return its supported archive naming convention or an error."""
    try:
        text = abi_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return None, f"cannot read {abi_path.name}: {error}"

    compiler_match = re.search(r'set\(DetourModKit_ABI_COMPILER_ID "([^"]*)"\)', text)
    simulate_match = re.search(r'set\(DetourModKit_ABI_SIMULATE_ID "([^"]*)"\)', text)
    if compiler_match is None or simulate_match is None:
        return None, f"{abi_path.name} omits compiler or simulation identity"

    compiler_id = compiler_match.group(1)
    simulate_id = simulate_match.group(1)
    if compiler_id == "GNU":
        return "mingw", None
    if compiler_id == "MSVC" or simulate_id == "MSVC":
        return "msvc", None
    return None, f"unsupported archive-producing compiler '{compiler_id}' (simulate '{simulate_id}')"


def compare_invariant_files(cmake_dir: Path, reference_cmake_dir: Path, violations: list[str]) -> None:
    """Require the combined prefix's shared package files to match a single-configuration reference byte for byte."""
    for config_file in INVARIANT_CONFIG_FILES:
        combined_path = cmake_dir / config_file
        reference_path = reference_cmake_dir / config_file
        if not reference_path.is_file():
            violations.append(f"reference prefix is missing configuration-invariant {config_file}")
            continue
        if not combined_path.is_file():
            continue
        try:
            if combined_path.read_bytes() != reference_path.read_bytes():
                violations.append(f"configuration-invariant {config_file} changed across configuration installs")
        except OSError as error:
            violations.append(f"cannot compare configuration-invariant {config_file}: {error}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dual-configuration package-matrix gate for a DetourModKit prefix.")
    parser.add_argument("prefix", help="installed package prefix to inspect")
    parser.add_argument("--configs", nargs="+", default=["Debug", "Release"],
                        help="configurations the prefix is expected to carry (default: Debug Release)")
    parser.add_argument("--debug-postfix", default="d", help="archive name postfix for the Debug configuration")
    parser.add_argument(
        "--reference-prefix",
        help="single-configuration prefix whose shared package files must byte-match the combined prefix",
    )
    args = parser.parse_args(argv)

    prefix = Path(args.prefix).resolve()
    if not prefix.is_dir():
        print(f"package-matrix gate FAILED: prefix '{prefix}' does not exist or is not a directory")
        return 1

    libdir = lib_dir(prefix)
    cmake_dir = libdir / "cmake" / "DetourModKit"
    violations = []

    for config_file in INVARIANT_CONFIG_FILES:
        if not (cmake_dir / config_file).is_file():
            violations.append(f"missing configuration-invariant {libdir.name}/cmake/DetourModKit/{config_file}")

    if args.reference_prefix:
        reference_prefix = Path(args.reference_prefix).resolve()
        reference_cmake_dir = lib_dir(reference_prefix) / "cmake" / "DetourModKit"
        compare_invariant_files(cmake_dir, reference_cmake_dir, violations)

    archive_format, format_error = producer_archive_format(cmake_dir / "DetourModKitAbi.cmake")
    if format_error is not None:
        violations.append(format_error)

    # Two configurations that map to the same postfix (e.g. Release and RelWithDebInfo) would share one archive name
    # and could not be distinguished in a shared prefix; the matrix is only meaningful for distinctly-named configs.
    seen_postfix: dict[str, str] = {}
    for config in args.configs:
        postfix = postfix_for(config, args.debug_postfix)
        if postfix in seen_postfix:
            violations.append(
                f"configurations '{seen_postfix[postfix]}' and '{config}' share archive postfix "
                f"'{postfix or '<none>'}'; "
                "they cannot coexist in one prefix")
        seen_postfix[postfix] = config

    if archive_format is not None:
        for config in args.configs:
            postfix = postfix_for(config, args.debug_postfix)
            main_archive = archive_name("DetourModKit", postfix, archive_format, main_library=True)
            if not (libdir / main_archive).is_file():
                violations.append(
                    f"[{config}] missing {libdir.name}/{main_archive}; "
                    "Debug and Release must coexist under distinct names")
            for dependency in DEPENDENCIES:
                dependency_archive = archive_name(dependency, postfix, archive_format, main_library=False)
                if not (libdir / dependency_archive).is_file():
                    violations.append(
                        f"[{config}] missing {libdir.name}/{dependency_archive}; "
                        f"the {config} DetourModKit::deps entry links it")

    for config in args.configs:
        target_fragment = cmake_dir / f"DetourModKitTargets-{config.lower()}.cmake"
        if not target_fragment.is_file():
            violations.append(
                f"[{config}] missing {libdir.name}/cmake/DetourModKit/"
                f"DetourModKitTargets-{config.lower()}.cmake "
                "(install(EXPORT) emits one per installed configuration)")

    if violations:
        print(f"package-matrix gate FAILED for '{prefix}' (configs: {', '.join(args.configs)}):\n")
        for v in sorted(violations):
            print("  " + v)
        print(f"\n{len(violations)} violation(s).")
        return 1
    print(f"package-matrix gate passed: configurations {', '.join(args.configs)} coexist without overwrite ({prefix}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
