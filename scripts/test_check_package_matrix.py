#!/usr/bin/env python3
"""Self-test for check_package_matrix.py: positive and negative fixtures over synthetic install prefixes."""
import io
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_package_matrix as matrix  # noqa: E402


def run(prefix: Path, *extra: str) -> int:
    """Invoke the gate over `prefix`, swallowing its report, and return the exit code."""
    with redirect_stdout(io.StringIO()):
        return matrix.main([str(prefix), *extra])


def make_prefix(
    root: Path,
    *,
    mingw: bool = True,
    configs: tuple[str, ...] = ("Debug", "Release"),
    skip_archive: str | None = None,
    skip_dep: tuple[str, str] | None = None,
    skip_fragment: str | None = None,
    skip_invariant: str | None = None,
) -> None:
    """Build a synthetic prefix. skip_* selectively omit one file to model a defect."""
    lib = root / "lib"
    cmake = lib / "cmake" / "DetourModKit"
    cmake.mkdir(parents=True, exist_ok=True)

    def touch(name: str) -> None:
        (lib / name).write_text("", encoding="ascii")

    suffix = ".a" if mingw else ".lib"
    for config in configs:
        pfx = matrix.postfix_for(config, "d")
        if skip_archive != config:
            touch(f"libDetourModKit{pfx}{suffix}")
        for dep in matrix.DEPENDENCIES:
            if skip_dep == (config, dep):
                continue
            # MinGW keeps the lib prefix on deps; MSVC does not.
            touch(f"lib{dep}{pfx}.a" if mingw else f"{dep}{pfx}.lib")
        if skip_fragment != config:
            (cmake / f"DetourModKitTargets-{config.lower()}.cmake").write_text("", encoding="ascii")

    for config_file in matrix.INVARIANT_CONFIG_FILES:
        if skip_invariant == config_file:
            continue
        content = ""
        if config_file == "DetourModKitAbi.cmake":
            compiler_id = "GNU" if mingw else "MSVC"
            content = (
                f'set(DetourModKit_ABI_COMPILER_ID "{compiler_id}")\n'
                'set(DetourModKit_ABI_SIMULATE_ID "")\n'
            )
        (cmake / config_file).write_text(content, encoding="ascii")


def main() -> int:
    failures = []

    def expect(label: str, code: int, want: int) -> None:
        if code != want:
            failures.append(f"{label}: expected exit {want}, got {code}")

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        good = base / "good"
        make_prefix(good)
        expect("dual-config MinGW prefix passes", run(good), 0)

        reference = base / "reference"
        make_prefix(reference, configs=("Debug",))
        expect("invariant files match a single-config reference",
               run(good, "--reference-prefix", str(reference)), 0)

        drifted = base / "drifted"
        make_prefix(drifted)
        drifted_config = drifted / "lib" / "cmake" / "DetourModKit" / "DetourModKitConfig.cmake"
        drifted_config.write_text("configuration-specific content", encoding="ascii")
        expect("configuration-invariant content drift fails",
               run(drifted, "--reference-prefix", str(reference)), 1)

        good_msvc = base / "good_msvc"
        make_prefix(good_msvc, mingw=False)
        expect("dual-config MSVC prefix passes", run(good_msvc), 0)

        no_debug_lib = base / "no_debug_lib"
        make_prefix(no_debug_lib, skip_archive="Debug")
        expect("missing Debug DetourModKit archive fails", run(no_debug_lib), 1)

        no_release_dep = base / "no_release_dep"
        make_prefix(no_release_dep, skip_dep=("Release", "Zydis"))
        expect("missing Release dependency archive fails", run(no_release_dep), 1)

        no_fragment = base / "no_fragment"
        make_prefix(no_fragment, skip_fragment="Debug")
        expect("missing per-config targets fragment fails", run(no_fragment), 1)

        no_invariant = base / "no_invariant"
        make_prefix(no_invariant, skip_invariant="DetourModKitConfig.cmake")
        expect("missing invariant Config.cmake fails", run(no_invariant), 1)

        wrong_format = base / "wrong_format"
        make_prefix(wrong_format)
        (wrong_format / "lib" / "libZydisd.a").rename(wrong_format / "lib" / "Zydisd.lib")
        expect("wrong-toolchain dependency spelling fails", run(wrong_format), 1)

        # A single-config prefix must NOT satisfy a Debug+Release matrix (the overwrite defect this gate guards).
        single = base / "single"
        make_prefix(single, configs=("Release",))
        expect("single-config prefix fails the dual matrix", run(single), 1)
        expect("single-config prefix passes when only its config is required",
               run(single, "--configs", "Release"), 0)

        # Two configurations mapping to the same (empty) postfix cannot coexist and must be rejected as ambiguous. Build
        # the prefix with BOTH configurations so their archives and Targets fragments all exist; the shared "" postfix
        # is then the sole violation, isolating the ambiguity check (a prefix missing one config would fail for that
        # reason regardless of the ambiguity logic).
        ambiguous = base / "ambiguous"
        make_prefix(ambiguous, configs=("Release", "RelWithDebInfo"))
        expect("same-postfix configs are ambiguous",
               run(ambiguous, "--configs", "Release", "RelWithDebInfo"), 1)

    if failures:
        print("check_package_matrix self-test FAILED:")
        for f in failures:
            print("  " + f)
        return 1
    print("check_package_matrix self-test passed (12 cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
