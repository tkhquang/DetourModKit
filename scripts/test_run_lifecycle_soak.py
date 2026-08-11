#!/usr/bin/env python3
"""Regression tests for the lifecycle soak's WER LocalDumps restoration.

The production code writes machine-wide HKLM policy, so a stateful winreg stub drives failure paths without changing
the developer machine. The final key map is compared with the pre-run map whenever restoration can complete.
"""

import copy
import importlib.util
import io
import sys
from contextlib import redirect_stderr
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "run_lifecycle_soak.py"
SPEC = importlib.util.spec_from_file_location("run_lifecycle_soak", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

KEY = rf"{MODULE.WER_ROOT}\proof.exe"
OTHER_KEY = rf"{MODULE.WER_ROOT}\other.exe"
OLD_VALUES = {
    "DumpFolder": (r"C:\old", 2),
    "DumpType": (2, 4),
    "DumpCount": (5, 4),
}
ARMED_VALUES = {
    "DumpFolder": (str(Path(r"C:\new")), 2),
    "DumpType": (1, 4),
    "DumpCount": (10, 4),
}


class FakeKey:
    def __init__(self, path: str):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeRegistry:
    """The winreg surface used by the WER ledger, with per-operation failure injection."""

    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x1
    KEY_WRITE = 0x2
    REG_EXPAND_SZ = 2
    REG_DWORD = 4

    def __init__(self, keys=None):
        self.keys = copy.deepcopy(keys or {})
        self.unopenable: set[str] = set()
        self.uncreatable: set[str] = set()
        self.unqueryable_keys: set[str] = set()
        self.unqueryable_values: set[tuple[str, str]] = set()
        self.unwritable: set[tuple[str, str]] = set()
        self.unexpected_write_failures: set[tuple[str, str]] = set()
        self.undeletable_values: set[tuple[str, str]] = set()
        self.undeletable_keys: set[str] = set()
        self.written: list[tuple[str, str, object, int]] = []
        self.deleted_values: list[tuple[str, str]] = []
        self.deleted_keys: list[str] = []

    def OpenKey(self, _root, path, _reserved, _access):
        if path in self.unopenable:
            raise OSError(5, "Access is denied")
        if path not in self.keys:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return FakeKey(path)

    def CreateKeyEx(self, _root, path, _reserved, _access):
        if path in self.uncreatable:
            raise OSError(5, "Access is denied")
        self.keys.setdefault(path, {})
        return FakeKey(path)

    def CloseKey(self, _key):
        return None

    def QueryValueEx(self, key, name):
        if (key.path, name) in self.unqueryable_values:
            raise OSError(5, "Access is denied")
        try:
            return self.keys[key.path][name]
        except KeyError as error:
            raise FileNotFoundError(2, "The system cannot find the file specified") from error

    def QueryInfoKey(self, key):
        if key.path in self.unqueryable_keys:
            raise OSError(5, "Access is denied")
        prefix = key.path + "\\"
        subkeys = {
            candidate[len(prefix):].split("\\", 1)[0]
            for candidate in self.keys
            if candidate.startswith(prefix) and candidate != key.path
        }
        return (len(subkeys), len(self.keys[key.path]), 0)

    def SetValueEx(self, key, name, _reserved, kind, data):
        if (key.path, name) in self.unexpected_write_failures:
            raise RuntimeError("injected registry wrapper defect")
        if (key.path, name) in self.unwritable:
            raise OSError(5, "Access is denied")
        self.keys[key.path][name] = (data, kind)
        self.written.append((key.path, name, data, kind))

    def DeleteValue(self, key, name):
        if (key.path, name) in self.undeletable_values:
            raise OSError(5, "Access is denied")
        if name not in self.keys[key.path]:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        del self.keys[key.path][name]
        self.deleted_values.append((key.path, name))

    def DeleteKeyEx(self, _root, path, _view, _reserved):
        if path in self.undeletable_keys:
            raise OSError(5, "Access is denied")
        if path not in self.keys:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        prefix = path + "\\"
        if self.keys[path] or any(candidate.startswith(prefix) for candidate in self.keys):
            raise OSError(145, "The directory is not empty")
        del self.keys[path]
        self.deleted_keys.append(path)


def state(path: str = KEY, existed: bool = True) -> dict:
    snapshots = {
        name: (True, data, kind) if existed else (False, None, None)
        for name, (data, kind) in OLD_VALUES.items()
    }
    return {"path": path, "existed": existed, "snapshots": snapshots}


def registry_after_arming(states: list[dict], root_existed: bool = True) -> tuple[FakeRegistry, dict]:
    initial = {MODULE.WER_ROOT: {}} if root_existed else {}
    current = {MODULE.WER_ROOT: {}}
    for item in states:
        current[item["path"]] = copy.deepcopy(ARMED_VALUES)
        if item["existed"]:
            initial[item["path"]] = copy.deepcopy(OLD_VALUES)
    return FakeRegistry(current), initial


def call_with_registry(registry: FakeRegistry, callback):
    original_registry = MODULE.winreg
    MODULE.winreg = registry
    try:
        return callback()
    finally:
        MODULE.winreg = original_registry


def restore(registry: FakeRegistry, states: list[dict], root_existed: bool = True) -> list[str]:
    return call_with_registry(registry, lambda: MODULE.restore_wer(states, root_existed))


def assert_failure_names(failures: list[str], *names: str) -> None:
    for name in names:
        if not any(name in failure for failure in failures):
            raise AssertionError(f"expected a failure naming '{name}', got {failures}")


def test_arm_created_key_is_ledgered_before_a_snapshot_failure() -> None:
    registry = FakeRegistry({MODULE.WER_ROOT: {}})
    registry.unqueryable_values.add((KEY, "DumpType"))
    states: list[dict] = []
    try:
        call_with_registry(registry, lambda: MODULE.arm_wer_key(KEY, Path(r"C:\dumps"), states))
    except OSError:
        pass
    else:
        raise AssertionError("the injected snapshot failure did not fire")

    if states != [state(existed=False)]:
        raise AssertionError(f"the created key must be ledgered provisionally, got {states}")
    registry.unqueryable_values.clear()
    failures = restore(registry, states)
    if failures or registry.keys != {MODULE.WER_ROOT: {}}:
        raise AssertionError(f"the provisionally-ledgered key did not clean up: {failures} / {registry.keys}")


def test_arm_created_key_is_ledgered_before_create_returns() -> None:
    registry = FakeRegistry({MODULE.WER_ROOT: {}})
    registry.uncreatable.add(KEY)
    states: list[dict] = []
    try:
        call_with_registry(registry, lambda: MODULE.arm_wer_key(KEY, Path(r"C:\dumps"), states))
    except OSError:
        pass
    else:
        raise AssertionError("the injected CreateKeyEx failure did not fire")

    if states != [state(existed=False)]:
        raise AssertionError(f"the absent key must be ledgered before CreateKeyEx, got {states}")
    failures = restore(registry, states)
    if failures or registry.keys != {MODULE.WER_ROOT: {}}:
        raise AssertionError(f"a failed create did not reconcile cleanly: {failures} / {registry.keys}")


def test_arm_existing_key_preserves_exact_data_and_types() -> None:
    initial = {MODULE.WER_ROOT: {}, KEY: copy.deepcopy(OLD_VALUES)}
    registry = FakeRegistry(initial)
    states: list[dict] = []
    call_with_registry(registry, lambda: MODULE.arm_wer_key(KEY, Path(r"C:\new"), states))
    if registry.keys[KEY] != ARMED_VALUES:
        raise AssertionError(f"arming wrote the wrong values or types: {registry.keys[KEY]}")
    failures = restore(registry, states)
    if failures or registry.keys != initial:
        raise AssertionError(f"exact snapshot restoration failed: {failures} / {registry.keys}")


def test_clean_existing_key_restores_exact_data_and_types() -> None:
    states = [state()]
    registry, initial = registry_after_arming(states)
    failures = restore(registry, states)
    if failures or registry.keys != initial:
        raise AssertionError(f"a clean restore must reproduce the initial registry: {failures} / {registry.keys}")


def test_created_child_delete_failure_is_reported() -> None:
    states = [state(existed=False)]
    registry, _initial = registry_after_arming(states)
    registry.undeletable_keys.add(KEY)
    failures = restore(registry, states)
    assert_failure_names(failures, KEY)
    if KEY in registry.deleted_keys:
        raise AssertionError("the failed child-key deletion was recorded as successful")


def test_created_child_inspection_failure_does_not_strand_the_next_key() -> None:
    states = [state(existed=False), state(OTHER_KEY, existed=False)]
    registry, _initial = registry_after_arming(states)
    registry.unqueryable_keys.add(KEY)
    failures = restore(registry, states)
    assert_failure_names(failures, KEY)
    if OTHER_KEY in registry.keys or OTHER_KEY not in registry.deleted_keys:
        raise AssertionError("an inspection error on the first key stranded the second key")


def test_created_child_that_is_already_missing_is_restored() -> None:
    states = [state(existed=False)]
    registry = FakeRegistry({MODULE.WER_ROOT: {}})
    failures = restore(registry, states)
    if failures or registry.keys != {MODULE.WER_ROOT: {}}:
        raise AssertionError(f"an already-absent created key should be clean, got {failures}")


def test_created_child_with_unowned_content_is_reported_and_left_intact() -> None:
    states = [state(existed=False)]
    registry, _initial = registry_after_arming(states)
    registry.keys[KEY]["ForeignValue"] = ("keep", 1)
    failures = restore(registry, states)
    assert_failure_names(failures, KEY, "nonempty")
    if registry.keys[KEY] != {"ForeignValue": ("keep", 1)} or KEY in registry.deleted_keys:
        raise AssertionError(f"unowned content was not preserved: {registry.keys}")


def test_created_key_delete_value_failure_is_reported_and_other_values_continue() -> None:
    states = [state(existed=False)]
    registry, _initial = registry_after_arming(states)
    registry.undeletable_values.add((KEY, "DumpType"))
    failures = restore(registry, states)
    assert_failure_names(failures, "DumpType")
    if set(registry.keys[KEY]) != {"DumpType"}:
        raise AssertionError(f"later owned values did not continue deleting: {registry.keys[KEY]}")
    if KEY in registry.deleted_keys:
        raise AssertionError("a key holding owned residue must not be deleted")


def test_created_key_that_fully_restores_is_deleted() -> None:
    states = [state(existed=False)]
    registry, initial = registry_after_arming(states)
    failures = restore(registry, states)
    if failures or registry.keys != initial:
        raise AssertionError(f"expected exact cleanup of the created child: {failures} / {registry.keys}")
    expected_values = {(KEY, name) for name in ARMED_VALUES}
    if set(registry.deleted_values) != expected_values or registry.deleted_keys != [KEY]:
        raise AssertionError("the created-key proof did not delete all owned values before the key")


def test_created_root_delete_failure_is_reported() -> None:
    registry = FakeRegistry({MODULE.WER_ROOT: {}})
    registry.undeletable_keys.add(MODULE.WER_ROOT)
    failures = restore(registry, [], root_existed=False)
    assert_failure_names(failures, MODULE.WER_ROOT)


def test_created_root_inspection_failure_is_reported() -> None:
    registry = FakeRegistry({MODULE.WER_ROOT: {}})
    registry.unqueryable_keys.add(MODULE.WER_ROOT)
    failures = restore(registry, [], root_existed=False)
    assert_failure_names(failures, MODULE.WER_ROOT, "inspect")


def test_created_root_that_fully_restores_is_deleted_after_its_child() -> None:
    states = [state(existed=False)]
    registry, initial = registry_after_arming(states, root_existed=False)
    failures = restore(registry, states, root_existed=False)
    if failures or registry.keys != initial or registry.deleted_keys != [KEY, MODULE.WER_ROOT]:
        raise AssertionError(f"created root cleanup was not exact and ordered: {failures} / {registry.deleted_keys}")


def test_created_root_with_unowned_content_is_reported_and_left_intact() -> None:
    registry = FakeRegistry({MODULE.WER_ROOT: {"ForeignValue": ("keep", 1)}})
    failures = restore(registry, [], root_existed=False)
    assert_failure_names(failures, MODULE.WER_ROOT, "nonempty")
    if MODULE.WER_ROOT in registry.deleted_keys:
        raise AssertionError("a created root with unowned content must not be deleted")


def test_existing_key_that_disappeared_is_reported() -> None:
    registry = FakeRegistry({MODULE.WER_ROOT: {}})
    failures = restore(registry, [state()])
    assert_failure_names(failures, KEY, "missing")


def test_every_unrestorable_value_is_named() -> None:
    states = [state()]
    registry, _initial = registry_after_arming(states)
    registry.unwritable.update({(KEY, "DumpFolder"), (KEY, "DumpCount")})
    failures = restore(registry, states)
    if len(failures) != 2:
        raise AssertionError(f"expected exactly two failures, got {failures}")
    assert_failure_names(failures, "DumpFolder", "DumpCount")


def test_one_unopenable_key_does_not_strand_the_next() -> None:
    states = [state(), state(OTHER_KEY)]
    registry, _initial = registry_after_arming(states)
    registry.unopenable.add(KEY)
    failures = restore(registry, states)
    assert_failure_names(failures, KEY)
    if registry.keys[OTHER_KEY] != OLD_VALUES:
        raise AssertionError("the second key must still restore exactly")


def test_one_unexpected_key_cleanup_exception_does_not_strand_the_next() -> None:
    original_restore_one_key = MODULE.restore_one_key
    visited: list[str] = []

    def injected_restore_one_key(item: dict) -> list[str]:
        visited.append(item["path"])
        if item["path"] == KEY:
            raise RuntimeError("injected cleanup defect")
        return []

    MODULE.restore_one_key = injected_restore_one_key
    try:
        # The stub is bound for the whole call so the isolation is enforced rather than incidental: nothing here may
        # reach HKLM even if restore_wer later grows a direct registry access of its own.
        failures = call_with_registry(
            FakeRegistry({MODULE.WER_ROOT: {}}), lambda: MODULE.restore_wer([state(), state(OTHER_KEY)], True)
        )
    finally:
        MODULE.restore_one_key = original_restore_one_key

    assert_failure_names(failures, KEY, "aborted unexpectedly")
    if visited != [KEY, OTHER_KEY]:
        raise AssertionError(f"an unexpected first-key exception stranded later cleanup: {visited}")


def test_one_unwritable_value_still_restores_the_others() -> None:
    states = [state()]
    registry, _initial = registry_after_arming(states)
    registry.unwritable.add((KEY, "DumpFolder"))
    failures = restore(registry, states)
    assert_failure_names(failures, "DumpFolder")
    if registry.keys[KEY]["DumpType"] != OLD_VALUES["DumpType"]:
        raise AssertionError("DumpType after the failed value was not restored")
    if registry.keys[KEY]["DumpCount"] != OLD_VALUES["DumpCount"]:
        raise AssertionError("DumpCount after the failed value was not restored")


def test_one_unexpected_value_exception_still_restores_the_others() -> None:
    states = [state()]
    registry, _initial = registry_after_arming(states)
    registry.unexpected_write_failures.add((KEY, "DumpFolder"))
    failures = restore(registry, states)
    assert_failure_names(failures, "DumpFolder", "injected registry wrapper defect")
    if registry.keys[KEY]["DumpType"] != OLD_VALUES["DumpType"]:
        raise AssertionError("DumpType after the unexpected value exception was not restored")
    if registry.keys[KEY]["DumpCount"] != OLD_VALUES["DumpCount"]:
        raise AssertionError("DumpCount after the unexpected value exception was not restored")


def test_restoration_exception_becomes_the_failure_of_a_clean_run() -> None:
    def abort_restoration() -> list[str]:
        raise OSError(5, "Access is denied")

    try:
        with MODULE.restoration_guard(abort_restoration):
            pass
    except MODULE.SoakError as error:
        assert_failure_names([str(error)], MODULE.WER_ROOT, "aborted unexpectedly")
    else:
        raise AssertionError("an unexpected restoration exception must fail a clean run")


def test_restoration_guard_clean_body_and_cleanup_return_success() -> None:
    with MODULE.restoration_guard(lambda: []):
        pass


def test_restoration_guard_preserves_an_unexpected_primary_and_prints_residue() -> None:
    primary = RuntimeError("proof driver crashed")
    stderr = io.StringIO()
    try:
        with redirect_stderr(stderr), MODULE.restoration_guard(lambda: [f"{KEY}: Access is denied"]):
            raise primary
    except RuntimeError as reported:
        if reported is not primary:
            raise AssertionError("restoration replaced the unexpected primary exception")
    else:
        raise AssertionError("the unexpected primary exception was swallowed")
    assert_failure_names([stderr.getvalue()], KEY, "restoration was also incomplete")


def test_restoration_guard_preserves_soak_primary_and_prints_every_residue() -> None:
    primary = MODULE.SoakError("the exit proof regressed")
    failures = [f"{KEY}: Access is denied", f"{OTHER_KEY}: The directory is not empty"]
    stderr = io.StringIO()
    try:
        with redirect_stderr(stderr), MODULE.restoration_guard(lambda: failures):
            raise primary
    except MODULE.SoakError as reported:
        if reported is not primary:
            raise AssertionError("restoration replaced the primary soak failure")
    else:
        raise AssertionError("the primary soak failure was swallowed")
    assert_failure_names([stderr.getvalue()], KEY, OTHER_KEY, "restoration was also incomplete")


def test_restoration_residue_fails_an_otherwise_successful_run() -> None:
    failures = [f"{KEY}: Access is denied", f"{OTHER_KEY}: The directory is not empty"]
    try:
        with MODULE.restoration_guard(lambda: failures):
            pass
    except MODULE.SoakError as error:
        assert_failure_names([str(error)], KEY, OTHER_KEY)
    else:
        raise AssertionError("restoration residue must fail an otherwise successful run")


EXPECTED_REQUIRED_SOAK_PROOFS = (
    "InputLifecycleProof.CardinalityRebindReleasesDroppedNonPrototypeHold",
    "InputLifecycleProof.InPlaceRebindStillDeliversStagedReleaseEdge",
    "InputLifecycleProof.RemoveDeliversBalancingReleaseWhenKeyReleasesConcurrently",
    "InputLifecycleProof.StagedProbeCleanupJoinsBeforeDestroyingProbeCaptures",
    "InputLifecycleProof.TlsExhaustionRefusesUntrackedDelivery",
    "InputLifecycleProof.TlsStoreFailureRefusesUntrackedDelivery",
    "InputLifecycleProof.CrossGateHoldRetirementSurvivesSimultaneousStoreFailure",
    "InputLifecycleProof.CrossGateHoldTeardownSurvivesSimultaneousStoreFailure",
    "InputLifecycleProof.CrossGatePressDisposalSurvivesSimultaneousStoreFailure",
    "Lifecycle.XInputPrimaryLostDuringExArmDegradesThePair",
    "Lifecycle.XInputInstalledPairMaintenanceRecoversALostPrimary",
    "Lifecycle.XInputRetainedPairRecoversALostPrimary",
    "Lifecycle.XInputPollLoopMaintainsAPublishedPair",
)


def complete_input_inventory() -> list[dict]:
    inventory = []
    for name in EXPECTED_REQUIRED_SOAK_PROOFS:
        properties = []
        if name.startswith("Lifecycle.XInput"):
            properties = [{"name": "LABELS", "value": ["lifecycle-proof"]}]
        inventory.append({"name": name, "properties": properties})
    return inventory + [{"name": "Lifecycle.FullLifecycleExit"}]


def test_the_declared_required_proofs_match_the_independent_contract() -> None:
    # This tuple is deliberately independent of the production tuple. Deriving the fixture from production would let
    # deletion of a requirement shrink both sides of the test and falsely pass every per-name mutation below.
    if MODULE.REQUIRED_SOAK_PROOFS != EXPECTED_REQUIRED_SOAK_PROOFS:
        raise AssertionError("the soak's declared required proofs no longer match the independent expected inventory")


def test_complete_input_inventory_is_accepted() -> None:
    accepted = MODULE.require_input_proofs(complete_input_inventory())
    expected_input_count = len(
        [name for name in EXPECTED_REQUIRED_SOAK_PROOFS if name.startswith("InputLifecycleProof.")]
    )
    if len(accepted) != expected_input_count:
        raise AssertionError("the inventory gate returned the wrong InputLifecycleProof set")


def test_every_required_input_proof_is_individually_load_bearing() -> None:
    # One mutation per requirement, including the exact staged-rebind case: dropping any single name has to fail the
    # gate. A tuple that is checked as a whole, or a gate that only counts the group, passes this loop with a hole in
    # it and lets the soak repeat a proof that is no longer registered.
    for dropped in EXPECTED_REQUIRED_SOAK_PROOFS:
        inventory = [t for t in complete_input_inventory() if t["name"] != dropped]
        try:
            MODULE.require_input_proofs(inventory)
        except MODULE.SoakError as error:
            if dropped not in str(error):
                raise AssertionError(f"the inventory failure did not name '{dropped}'")
        else:
            raise AssertionError(f"removing '{dropped}' from the inventory did not fail the gate")


def test_a_duplicated_required_input_proof_is_refused() -> None:
    duplicated = EXPECTED_REQUIRED_SOAK_PROOFS[0]
    try:
        MODULE.require_input_proofs(complete_input_inventory() + [{"name": duplicated}])
    except MODULE.SoakError as error:
        if duplicated not in str(error):
            raise AssertionError("the duplicate failure did not name the duplicated proof")
    else:
        raise AssertionError("a duplicated required proof did not fail the gate")


def test_a_required_xinput_proof_without_the_lifecycle_label_is_refused() -> None:
    # Two arms, because the gate has two ways to be wrong: no LABELS property at all, and a LABELS property that
    # carries some other label. A gate that only checks for the property's presence passes the first and fails the
    # second, which is how a proof drifts out of the soak's selection while still looking labeled.
    unlabeled = next(name for name in EXPECTED_REQUIRED_SOAK_PROOFS if name.startswith("Lifecycle.XInput"))
    for broken_properties in ([], [{"name": "LABELS", "value": ["not-a-lifecycle-proof"]}]):
        inventory = complete_input_inventory()
        for proof in inventory:
            if proof["name"] == unlabeled:
                proof["properties"] = broken_properties
        try:
            MODULE.require_input_proofs(inventory)
        except MODULE.SoakError as error:
            if unlabeled not in str(error) or "not labeled lifecycle-proof" not in str(error):
                raise AssertionError("the missing-label failure did not name the proof and required label")
        else:
            raise AssertionError(f"a required XInput proof with properties {broken_properties} was accepted")


def test_an_empty_input_inventory_is_refused() -> None:
    try:
        MODULE.require_input_proofs([{"name": "Lifecycle.FullLifecycleExit"}])
    except MODULE.SoakError as error:
        if "no InputLifecycleProof tests" not in str(error):
            raise AssertionError("an empty input inventory failed for the wrong reason")
    else:
        raise AssertionError("an empty InputLifecycleProof inventory did not fail the gate")


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"lifecycle soak restoration self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
