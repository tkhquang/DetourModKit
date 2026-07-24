#!/usr/bin/env python3
"""ABI-tuple rejection gate for an installed DetourModKit package.

DetourModKitConfig.cmake fails find_package early when the consuming toolchain does not match the recorded producer
ABI (compiler family, standard library, pointer size, or architecture), because a C++23 static archive with no
extern "C" boundary cannot be linked across those axes. This gate proves each check independently against a copy of a
real installed prefix, then proves architecture-alias normalization, the explicit override, and the matching-toolchain
control.

Usage: check_abi_reject.py <install-prefix> [--cxx g++] [--generator Ninja]
Exit status is 1 with the failing case printed when an expectation is violated, else 0.
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

CONSUMER_CMAKE = """cmake_minimum_required(VERSION 3.28)
project(dmk_abi_reject_probe LANGUAGES CXX)
find_package(DetourModKit REQUIRED)
message(STATUS "abi_reject_probe: find_package succeeded")
"""
ABI_SET_PATTERN = re.compile(r'set\((DetourModKit_ABI_[A-Z_]+) "([^"]*)"\)')


def config_dir(prefix: Path) -> Path | None:
    for lib in ("lib", "lib64"):
        candidate = prefix / lib / "cmake" / "DetourModKit"
        if candidate.is_dir():
            return candidate
    return None


def read_abi_axes(text: str) -> dict[str, str]:
    """Return every ABI variable recorded by the generated package."""
    return dict(ABI_SET_PATTERN.findall(text))


def tamper_abi(abi_path: Path, original: str, replacements: Mapping[str, str]) -> None:
    """Rewrite exactly the requested ABI axes, failing if the generated record changed shape."""
    text = original
    for variable, value in replacements.items():
        pattern = re.compile(rf'(set\({re.escape(variable)} ")[^"]*("\))')
        text, replacement_count = pattern.subn(
            lambda match: f"{match.group(1)}{value}{match.group(2)}",
            text,
        )
        if replacement_count != 1:
            raise ValueError(f"expected one {variable} record, found {replacement_count}")
    abi_path.write_text(text, encoding="utf-8")


def configure(
    consumer_src: Path,
    build_dir: Path,
    cfg_dir: Path,
    generator: str,
    cxx: str,
    *,
    allow_override: bool,
) -> tuple[int, str]:
    cmd = [
        "cmake", "-S", str(consumer_src), "-B", str(build_dir), "-G", generator,
        f"-DDetourModKit_DIR={cfg_dir.as_posix()}",
        f"-DCMAKE_CXX_COMPILER={cxx}",
    ]
    if allow_override:
        cmd.append("-DDetourModKit_ALLOW_INCOMPATIBLE_ABI=ON")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ABI-tuple rejection gate for a DetourModKit prefix.")
    parser.add_argument("prefix")
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--generator", default="Ninja")
    args = parser.parse_args(argv)

    prefix = Path(args.prefix).resolve()
    src_cfg = config_dir(prefix)
    if src_cfg is None:
        print(f"ABI-reject gate FAILED: no lib*/cmake/DetourModKit under '{prefix}'")
        return 1

    source_abi_path = src_cfg / "DetourModKitAbi.cmake"
    try:
        original_abi = source_abi_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(f"ABI-reject gate FAILED: cannot read '{source_abi_path}': {error}")
        return 1

    axes = read_abi_axes(original_abi)
    required_axes = (
        "DetourModKit_ABI_COMPILER_ID",
        "DetourModKit_ABI_SIMULATE_ID",
        "DetourModKit_ABI_STL",
        "DetourModKit_ABI_ARCHITECTURE",
        "DetourModKit_ABI_POINTER_SIZE",
    )
    missing_axes = [axis for axis in required_axes if axis not in axes]
    if missing_axes:
        print(f"ABI-reject gate FAILED: ABI record omits {', '.join(missing_axes)}")
        return 1

    producer_is_gnu = axes["DetourModKit_ABI_COMPILER_ID"] == "GNU"
    foreign_compiler = "MSVC" if producer_is_gnu else "GNU"
    foreign_stl = "msvc-stl" if axes["DetourModKit_ABI_STL"] == "libstdc++" else "libstdc++"
    normalized_architecture = axes["DetourModKit_ABI_ARCHITECTURE"].lower()
    producer_is_x64 = normalized_architecture in {"amd64", "x86_64", "x64"}
    producer_is_arm64 = normalized_architecture in {"arm64", "aarch64"}
    foreign_architecture = "ARM64" if producer_is_x64 else "AMD64"
    if producer_is_x64:
        equivalent_architecture = next(
            spelling for spelling in ("AMD64", "x86_64", "x64")
            if spelling.lower() != normalized_architecture
        )
    elif producer_is_arm64:
        equivalent_architecture = next(
            spelling for spelling in ("ARM64", "aarch64")
            if spelling.lower() != normalized_architecture
        )
    else:
        equivalent_architecture = axes["DetourModKit_ABI_ARCHITECTURE"]
    foreign_pointer_size = "4" if axes["DetourModKit_ABI_POINTER_SIZE"] == "8" else "8"
    mismatch_cases = (
        (
            "compiler",
            {
                "DetourModKit_ABI_COMPILER_ID": foreign_compiler,
                "DetourModKit_ABI_SIMULATE_ID": "",
            },
            "compiler ABI family",
        ),
        ("stl", {"DetourModKit_ABI_STL": foreign_stl}, "standard library"),
        ("architecture", {"DetourModKit_ABI_ARCHITECTURE": foreign_architecture}, "target architecture"),
        ("pointer", {"DetourModKit_ABI_POINTER_SIZE": foreign_pointer_size}, "pointer size"),
    )

    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        consumer = tmp / "consumer"
        consumer.mkdir()
        (consumer / "CMakeLists.txt").write_text(CONSUMER_CMAKE, encoding="utf-8")

        tampered = tmp / "tampered"
        shutil.copytree(prefix, tampered)
        tampered_cfg = config_dir(tampered)
        if tampered_cfg is None:
            failures.append("copied prefix lost its DetourModKit package directory")
        else:
            tampered_abi_path = tampered_cfg / "DetourModKitAbi.cmake"
            for label, replacements, expected_diagnostic in mismatch_cases:
                try:
                    tamper_abi(tampered_abi_path, original_abi, replacements)
                except (OSError, UnicodeError, ValueError) as error:
                    failures.append(f"{label} mismatch fixture could not be prepared: {error}")
                    continue

                rc, out = configure(
                    consumer,
                    tmp / f"b_reject_{label}",
                    tampered_cfg,
                    args.generator,
                    args.cxx,
                    allow_override=False,
                )
                if rc == 0:
                    failures.append(f"{label} mismatch was ACCEPTED (find_package should have failed)")
                elif "incompatible toolchain" not in out or expected_diagnostic not in out:
                    failures.append(f"{label} mismatch was rejected without its ABI diagnostic")

            combined_mismatch = {
                "DetourModKit_ABI_COMPILER_ID": foreign_compiler,
                "DetourModKit_ABI_SIMULATE_ID": "",
                "DetourModKit_ABI_STL": foreign_stl,
                "DetourModKit_ABI_ARCHITECTURE": foreign_architecture,
                "DetourModKit_ABI_POINTER_SIZE": foreign_pointer_size,
            }
            try:
                tamper_abi(
                    tampered_abi_path,
                    original_abi,
                    {"DetourModKit_ABI_ARCHITECTURE": equivalent_architecture},
                )
            except (OSError, UnicodeError, ValueError) as error:
                failures.append(f"architecture alias fixture could not be prepared: {error}")
            else:
                rc, out = configure(
                    consumer,
                    tmp / "b_architecture_alias",
                    tampered_cfg,
                    args.generator,
                    args.cxx,
                    allow_override=False,
                )
                if rc != 0:
                    failures.append(f"equivalent architecture spelling was falsely rejected:\n{out[-800:]}")

            try:
                tamper_abi(tampered_abi_path, original_abi, combined_mismatch)
            except (OSError, UnicodeError, ValueError) as error:
                failures.append(f"override fixture could not be restored: {error}")

        rc, out = configure(
            consumer,
            tmp / "b_override",
            tampered_cfg if tampered_cfg is not None else src_cfg,
            args.generator,
            args.cxx,
            allow_override=True,
        )
        if rc != 0:
            failures.append(
                "DetourModKit_ALLOW_INCOMPATIBLE_ABI=ON did not permit the mismatched consume:\n"
                f"{out[-800:]}"
            )

        rc, out = configure(
            consumer,
            tmp / "b_native",
            src_cfg,
            args.generator,
            args.cxx,
            allow_override=False,
        )
        if rc != 0:
            failures.append(f"matching-toolchain consume was falsely rejected:\n{out[-800:]}")

    if failures:
        print(f"ABI-reject gate FAILED for '{prefix}':\n")
        for f in failures:
            print("  " + f)
        return 1
    print(
        "ABI-reject gate passed: compiler/STL/architecture/pointer mismatches rejected independently, "
        f"architecture alias accepted, override honored, matching toolchain accepted ({prefix})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
