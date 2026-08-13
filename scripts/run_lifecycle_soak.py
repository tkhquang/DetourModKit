#!/usr/bin/env python3
"""Final-candidate lifecycle soak: the gate both Release jobs run before producing a package.

It inventories CTest first so a missing label or a renamed regression cannot vacuously pass, temporarily arms
per-executable WER LocalDumps for the proof processes only, proves capture with a native fail-fast control, then
repeats the lifecycle proofs. Pre-existing WER values are restored however the run ends, and an otherwise successful
run that cannot restore every captured value fails: a green soak must not leave machine-wide policy behind.

WER captures unhandled crashes, not hangs, CTest timeouts, cancellations or ordinary nonzero exits, so CTest's
per-case timeouts and LastTest.log remain the evidence for those. Minidumps can contain sensitive process memory and
must never become release assets. WER policy is machine-wide: do not overlap two invocations on one host.
"""

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
import winreg
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resolve_runtime_dir  # noqa: E402

# The status RaiseFailFastException terminates with, and the only status that proves the control exercised the
# fail-fast path WER is being asked to capture.
STATUS_FAIL_FAST_EXCEPTION = 0xC0000602

WER_ROOT = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
AEDEBUG_PATHS = (
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug",
)
VALUE_NAMES = ("DumpFolder", "DumpType", "DumpCount")

# Every proof this soak's repetition count or release claim depends on, named one by one. CTest exits zero on an empty
# or shrunken selection, so a case that was renamed, gated out, or never registered would otherwise leave the soak green
# having repeated nothing. The three staged-release harness cases are here because their subject is the repetition; the
# cleanup control and raw hosts are here because a deleted CMake-owned proof vanishes rather than failing.
REQUIRED_INPUT_PROOFS = (
    "InputLifecycleProof.CardinalityRebindReleasesDroppedNonPrototypeHold",
    "InputLifecycleProof.InPlaceRebindStillDeliversStagedReleaseEdge",
    "InputLifecycleProof.RemoveDeliversBalancingReleaseWhenKeyReleasesConcurrently",
    "InputLifecycleProof.StagedProbeCleanupJoinsBeforeDestroyingProbeCaptures",
    "InputLifecycleProof.TlsExhaustionRefusesUntrackedDelivery",
    "InputLifecycleProof.TlsStoreFailureRefusesUntrackedDelivery",
    "InputLifecycleProof.CrossGateHoldRetirementSurvivesSimultaneousStoreFailure",
    "InputLifecycleProof.CrossGateHoldTeardownSurvivesSimultaneousStoreFailure",
    "InputLifecycleProof.CrossGatePressDisposalSurvivesSimultaneousStoreFailure",
    # The bounded cleanup controls. Each drives a raw host's early-failure exit while a callback is parked, so the
    # repetition below covers the abandonment path as well as the passing one. Repeating only the quiescent scenarios
    # would soak the shape that was never in doubt.
    "InputLifecycleProof.AbandonedParkedCallbackRunsDownBeforeClearing",
    "InputLifecycleProof.AbandonedFacadeDrivePremiseRunsDownBeforeClearing",
    "InputLifecycleProof.AbandonedSelfShutdownPremiseRunsDownBeforeClearing",
)
REQUIRED_LOADER_PROOFS = (
    "Lifecycle.InputLoaderDetachRetainsCompleteOwner",
)
REQUIRED_XINPUT_PROOFS = (
    "Lifecycle.XInputActivePairSurvivesProcessExitStaticDestruction",
    "Lifecycle.XInputPrimaryLostDuringExArmDegradesThePair",
    "Lifecycle.XInputInstalledPairMaintenanceRecoversALostPrimary",
    "Lifecycle.XInputRetainedPairRecoversALostPrimary",
    "Lifecycle.XInputPollLoopMaintainsAPublishedPair",
)
REQUIRED_SOAK_PROOFS = REQUIRED_INPUT_PROOFS + REQUIRED_LOADER_PROOFS + REQUIRED_XINPUT_PROOFS

# Explicit 64-bit view so a 32-bit interpreter cannot silently arm the WOW6432Node redirection instead.
REG_VIEW = winreg.KEY_WOW64_64KEY


class SoakError(Exception):
    """A gate failure. Distinct from an unexpected crash so the teardown still runs and the message stays the cause."""


def require_input_proofs(tests: list[dict]) -> list[dict]:
    """Returns the repeated input inventory after validating every exact proof the soak requires."""
    input_tests = [t for t in tests if str(t.get("name", "")).startswith("InputLifecycleProof.")]
    if not input_tests:
        raise SoakError("CTest inventory contains no InputLifecycleProof tests.")
    for required in REQUIRED_SOAK_PROOFS:
        matches = [t for t in tests if t.get("name") == required]
        if len(matches) != 1:
            raise SoakError(f"CTest inventory does not contain exactly one {required} proof.")
        if required.startswith("Lifecycle.") and not any(
            prop.get("name") == "LABELS" and "lifecycle-proof" in (prop.get("value") or [])
            for prop in (matches[0].get("properties") or [])
        ):
            raise SoakError(f"CTest proof {required} is not labeled lifecycle-proof.")
    return input_tests


def run_checked(command: list[str], cwd: Path | None = None, env: dict | None = None) -> None:
    completed = subprocess.run(command, cwd=cwd, env=env)
    if completed.returncode != 0:
        raise SoakError(f"Command '{command[0]}' exited with code {completed.returncode}.")


def run_ctest(arguments: list[str], runtime_directory: str) -> None:
    env = None
    if runtime_directory:
        env = dict(os.environ)
        env["PATH"] = runtime_directory + os.pathsep + env.get("PATH", "")
    run_checked(["ctest", *arguments], env=env)


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def is_complete_minidump(path: Path) -> bool:
    """True only for a finished dump.

    Opened with no sharing, so a dump WER is still writing raises a sharing violation and reads as incomplete rather
    than being trusted for its first four bytes.
    """
    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    # ctypes defaults a foreign return to int, which truncates a 64-bit HANDLE and makes the failure value compare
    # unequal to INVALID_HANDLE_VALUE, so the guard below would never fire. Declare the type instead.
    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.restype = ctypes.c_void_p

    handle = create_file(ctypes.c_wchar_p(str(path)), GENERIC_READ, 0, None, OPEN_EXISTING, 0, None)
    if handle is None or handle == INVALID_HANDLE_VALUE:
        return False
    try:
        size = ctypes.c_longlong(0)
        if not ctypes.windll.kernel32.GetFileSizeEx(ctypes.c_void_p(handle), ctypes.byref(size)):
            return False
        if size.value < 32:
            return False
        buffer = ctypes.create_string_buffer(4)
        read = ctypes.c_ulong(0)
        if not ctypes.windll.kernel32.ReadFile(
            ctypes.c_void_p(handle), buffer, 4, ctypes.byref(read), None
        ):
            return False
        return read.value == 4 and buffer.raw == b"MDMP"
    finally:
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))


def snapshot_value(key: winreg.HKEYType, name: str):
    """Return (exists, data, type) for one value, without expanding REG_EXPAND_SZ."""
    try:
        data, kind = winreg.QueryValueEx(key, name)
    except FileNotFoundError:
        return (False, None, None)
    return (True, data, kind)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    def bounded(low: int, high: int):
        def check(raw: str) -> int:
            value = int(raw)
            if value < low or value > high:
                raise argparse.ArgumentTypeError(f"expected {low}..{high}, got {value}")
            return value

        return check

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--build-directory", required=True)
    parser.add_argument("--dump-directory", required=True)
    parser.add_argument("--exit-repetitions", type=bounded(1, 1000), default=100)
    parser.add_argument("--input-repetitions", type=bounded(1, 1000), default=200)
    parser.add_argument("--label-repetitions", type=bounded(1, 1000), default=20)
    parser.add_argument("--label-parallelism", type=bounded(1, 64), default=4)
    return parser.parse_args(argv)


def inventory_tests(build: Path) -> dict:
    completed = subprocess.run(
        ["ctest", "--test-dir", str(build), "--show-only=json-v1"],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise SoakError(f"CTest inventory exited with code {completed.returncode}.\n{completed.stderr}")
    return json.loads(completed.stdout)


def executable_name(test: dict) -> str:
    command = test.get("command") or []
    if not command:
        raise SoakError(f"CTest inventory entry '{test.get('name')}' has no command.")
    return Path(str(command[0])).name


def arm_wer_key(path: str, dump_dir: Path, key_states: list[dict]) -> None:
    """Snapshots and arms one executable key, ledgering a newly created key before another operation can fail."""
    existed = True
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | REG_VIEW))
    except FileNotFoundError:
        existed = False

    state = {
        "path": path,
        "existed": existed,
        "snapshots": {name: (False, None, None) for name in VALUE_NAMES},
    }
    # Once CreateKeyEx returns, the machine-wide mutation has already happened. Allocate and publish the provisional
    # ledger first so neither Python allocation nor a failed QueryValueEx can strand an untracked key.
    if not existed:
        key_states.append(state)

    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WRITE | REG_VIEW
    ) as key:
        for name in VALUE_NAMES:
            state["snapshots"][name] = snapshot_value(key, name)

        if existed:
            key_states.append(state)

        winreg.SetValueEx(key, "DumpFolder", 0, winreg.REG_EXPAND_SZ, str(dump_dir))
        winreg.SetValueEx(key, "DumpType", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "DumpCount", 0, winreg.REG_DWORD, 10)


def collect_restoration_failures(restoration: Callable[[], list[str]]) -> list[str]:
    """Runs cleanup without allowing an unexpected cleanup exception to replace the proof's own failure."""
    try:
        return restoration()
    except Exception as error:
        return [f"{WER_ROOT}: restoration aborted unexpectedly: {error}"]


@contextmanager
def restoration_guard(restoration: Callable[[], list[str]]) -> Iterator[None]:
    """Runs restoration on every exit and promotes residue only when the guarded work otherwise succeeded."""
    try:
        yield
    except BaseException:
        failures = collect_restoration_failures(restoration)
        if failures:
            print(
                "warning: WER LocalDumps restoration was also incomplete; repair these entries by hand:\n"
                + "\n".join(failures),
                file=sys.stderr,
            )
        raise

    failures = collect_restoration_failures(restoration)
    reported = incomplete_restoration_error(failures)
    if reported is not None:
        raise reported


def arm_and_run(args: argparse.Namespace, repo_root: Path, build: Path, relative_build: str,
                dump_dir: Path, runtime_directory: str) -> None:
    # Checked before any inventory or build work: arming WER is the whole point of this gate, so a host that cannot
    # do it has nothing to gain from the minutes that would otherwise run first.
    if not is_elevated():
        raise SoakError("WER LocalDumps requires an elevated Windows runner.")

    inventory = inventory_tests(build)
    tests = inventory.get("tests", [])

    lifecycle_tests = [
        test
        for test in tests
        if any(
            prop.get("name") == "LABELS" and "lifecycle-proof" in (prop.get("value") or [])
            for prop in (test.get("properties") or [])
        )
    ]
    if not lifecycle_tests:
        raise SoakError("CTest inventory contains no lifecycle-proof tests.")
    if len([t for t in lifecycle_tests if t.get("name") == "Lifecycle.FullLifecycleExit"]) != 1:
        raise SoakError("CTest inventory does not contain exactly one Lifecycle.FullLifecycleExit proof.")

    input_tests = require_input_proofs(tests)

    run_checked(["cmake", "--build", str(build), "--target", "fast_fail_probe", "--parallel", "2"])
    control_probes = sorted(build.rglob("fast_fail_probe.exe"))
    if len(control_probes) != 1:
        raise SoakError(f"Expected one fast_fail_probe.exe below '{build}', found {len(control_probes)}.")
    control_probe = control_probes[0]

    for aedebug_path in AEDEBUG_PATHS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, aedebug_path, 0, winreg.KEY_READ | REG_VIEW) as key:
                auto, _ = winreg.QueryValueEx(key, "Auto")
                if str(auto) == "1":
                    raise SoakError(
                        f"Automatic postmortem debugging is active at '{aedebug_path}'; "
                        "WER would not collect LocalDumps."
                    )
        except FileNotFoundError:
            continue

    wer_executables = sorted({executable_name(t) for t in lifecycle_tests + input_tests} | {control_probe.name})
    if not wer_executables or any(not name.endswith(".exe") for name in wer_executables):
        raise SoakError("CTest inventory contains an invalid lifecycle executable name.")

    wer_root_existed = True
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WER_ROOT, 0, winreg.KEY_READ | REG_VIEW))
    except FileNotFoundError:
        wer_root_existed = False

    key_states: list[dict] = []
    with restoration_guard(lambda: restore_wer(key_states, wer_root_existed)):
        if not wer_root_existed:
            winreg.CloseKey(winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, WER_ROOT, 0, winreg.KEY_WRITE | REG_VIEW))

        for name in wer_executables:
            path = f"{WER_ROOT}\\{name}"
            arm_wer_key(path, dump_dir, key_states)

        # The control's promise is a fail-fast termination, not merely a nonzero status: a control that exited any
        # other way did not exercise the path WER is being asked to capture. Python reports the raw process exit
        # status, so the exact NTSTATUS is comparable here.
        # No runtime_directory prepend here, unlike run_ctest: fast_fail_probe is a dmk_static_runtime target whose
        # only imports are KERNEL32 and the system CRT, so it binds no compiler runtime to get wrong.
        control = subprocess.Popen([str(control_probe), "wer-crash"])
        try:
            control.wait(timeout=30)
        except subprocess.TimeoutExpired:
            control.kill()
            raise SoakError("The WER control process did not terminate within 30 seconds.")
        control_status = control.returncode & 0xFFFFFFFF
        if control_status != STATUS_FAIL_FAST_EXCEPTION:
            raise SoakError(
                f"The WER control process terminated with 0x{control_status:08X} instead of "
                f"STATUS_FAIL_FAST_EXCEPTION 0x{STATUS_FAIL_FAST_EXCEPTION:08X}."
            )

        deadline = time.monotonic() + 30.0
        control_dumps: list[Path] = []
        while True:
            control_dumps = sorted(dump_dir.glob("fast_fail_probe*.dmp"))
            if len(control_dumps) == 1 and is_complete_minidump(control_dumps[0]):
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.25)

        if len(control_dumps) != 1 or not is_complete_minidump(control_dumps[0]):
            raise SoakError(
                "WER did not capture exactly one complete native fail-fast control dump within 30 seconds."
            )
        control_dumps[0].unlink()

        run_ctest(
            [
                "--test-dir", str(build),
                "-R", "^InputLifecycleProof[.]",
                "--repeat", f"until-fail:{args.input_repetitions}",
                "--parallel", "1",
                "--stop-on-failure",
                "--output-on-failure",
            ],
            runtime_directory,
        )

        bash = shutil.which("bash")
        if bash is None:
            raise SoakError("bash is required to drive scripts/run_lifecycle_proofs.sh.")
        run_checked(
            [
                bash,
                "scripts/run_lifecycle_proofs.sh",
                relative_build,
                "-R", "^Lifecycle[.]FullLifecycleExit$",
                "--repeat", f"until-fail:{args.exit_repetitions}",
                "--parallel", "1",
                "--stop-on-failure",
            ],
            cwd=repo_root,
        )

        run_ctest(
            [
                "--test-dir", str(build),
                "-L", "lifecycle-proof",
                "--repeat", f"until-fail:{args.label_repetitions}",
                "--parallel", str(args.label_parallelism),
                "--stop-on-failure",
                "--output-on-failure",
            ],
            runtime_directory,
        )

    print(
        f"Lifecycle soak passed: {args.input_repetitions} serial InputLifecycleProof repetitions, "
        f"{args.exit_repetitions} serial FullLifecycleExit repetitions, and {args.label_repetitions} "
        f"full-label repetitions at parallelism {args.label_parallelism}."
    )


def restore_one_key(state: dict) -> list[str]:
    """Restores every snapshotted value of one key, and returns one message per value it could not restore."""
    failures: list[str] = []
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, state["path"], 0, winreg.KEY_READ | winreg.KEY_WRITE | REG_VIEW
        )
    except FileNotFoundError:
        if not state["existed"]:
            return []
        return [f"{state['path']}: key existed before the run but is now missing"]
    except OSError as error:
        return [f"{state['path']}: {error}"]

    with key:
        # Each value is isolated: one that cannot be written must not skip the values after it, or a single failure
        # would leave the rest of the key armed at a dump folder that is about to disappear.
        for name, (existed, data, kind) in state["snapshots"].items():
            try:
                if existed:
                    winreg.SetValueEx(key, name, 0, kind, data)
                else:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
            except Exception as error:
                failures.append(f"{state['path']}\\{name}: {error}")

    # A key this run created stays while an owned value could not be undone. If owned cleanup succeeded, the separate
    # removal helper distinguishes an already-missing key from unowned residue that makes deletion unsafe.
    if not failures and not state["existed"]:
        failures.extend(remove_created_key(state["path"]))
    return failures


def remove_created_key(path: str) -> list[str]:
    """Removes one key that was absent before the run, without deleting concurrent or otherwise unowned content."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | REG_VIEW) as key:
            subkeys, values, _ = winreg.QueryInfoKey(key)
    except FileNotFoundError:
        return []
    except OSError as error:
        return [f"{path}: could not inspect the created key after restoration: {error}"]

    if subkeys != 0 or values != 0:
        return [f"{path}: key did not exist before the run but remains nonempty after restoration; left intact"]

    try:
        winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, path, REG_VIEW, 0)
    except FileNotFoundError:
        return []
    except OSError as error:
        return [f"{path}: {error}"]
    return []


def restore_wer(key_states: list[dict], wer_root_existed: bool) -> list[str]:
    """Undoes machine-wide policy and returns one message per entry that could not be restored.

    Failures are returned rather than raised: the caller ranks them against a soak error that already happened, and
    raising here would replace the cause of the gate failure.
    """
    failures: list[str] = []
    for state in key_states:
        try:
            failures.extend(restore_one_key(state))
        except Exception as error:
            # Cleanup is a best-effort ledger walk: a defect or unexpected registry result in one entry must still let
            # every later executable key restore, and the caller must receive the unexpected residue as data.
            failures.append(f"{state.get('path', WER_ROOT)}: restoration aborted unexpectedly: {error}")

    if not wer_root_existed and not failures:
        failures.extend(remove_created_key(WER_ROOT))

    return failures


def incomplete_restoration_error(failures: list[str]) -> SoakError | None:
    """Returns the gate error for restoration residue, or None when cleanup reproduced the pre-run state."""
    if failures:
        return SoakError(
            "WER LocalDumps restoration was incomplete, so this host is not in its pre-run state; "
            "repair these entries by hand:\n" + "\n".join(failures)
        )
    return None


def main(argv: list[str]) -> int:
    args = parse_arguments(argv)
    repo_root = Path(__file__).resolve().parent.parent

    build_candidate = Path(args.build_directory)
    if not build_candidate.is_absolute():
        build_candidate = repo_root / build_candidate
    try:
        build = build_candidate.resolve(strict=True)
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    try:
        relative_build = build.relative_to(repo_root).as_posix()
    except ValueError:
        print(f"error: Build directory '{build}' is outside the repository.", file=sys.stderr)
        return 1
    if not (build / "CMakeCache.txt").is_file():
        print(f"error: Build directory '{build}' is not a configured CMake tree.", file=sys.stderr)
        return 1

    try:
        runtime_directory = resolve_runtime_dir.resolve(build)
    except resolve_runtime_dir.ResolveError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    dump_candidate = Path(args.dump_directory)
    if not dump_candidate.is_absolute():
        dump_candidate = repo_root / dump_candidate
    dump_candidate.mkdir(parents=True, exist_ok=True)
    dump_dir = dump_candidate.resolve()
    if any(dump_dir.glob("*.dmp")):
        print(
            f"error: Dump directory '{dump_dir}' already contains dumps; "
            "refusing to confuse old evidence with this run.",
            file=sys.stderr,
        )
        return 1

    try:
        arm_and_run(args, repo_root, build, relative_build, dump_dir, runtime_directory)
    except SoakError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
