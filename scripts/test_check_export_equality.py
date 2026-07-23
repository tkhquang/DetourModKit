#!/usr/bin/env python3
"""Self-test for check_export_equality.py: the gate must fail closed on every divergence shape it guards.

Builds throwaway prefix pairs and asserts the verdict for: identical contracts (pass), a missing prefix, an
empty consumer-contract tree, a content difference, a file present on one side only, an archive-set mismatch,
a missing required archive, and a partial-stem archive name that must NOT satisfy a requirement.
"""
import importlib.util
import pathlib
import sys
import tempfile
import unittest.mock

_SCRIPT = pathlib.Path(__file__).with_name("check_export_equality.py")
_spec = importlib.util.spec_from_file_location("check_export_equality", _SCRIPT)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)


def _expect(condition, message):
    if not condition:
        raise AssertionError(message)


def _make_prefix(root, name, cmake_files, archives):
    prefix = root / name
    cmake_dir = prefix / "lib" / "cmake" / "DetourModKit"
    cmake_dir.mkdir(parents=True)
    include_dir = prefix / "include" / "DetourModKit"
    include_dir.mkdir(parents=True)
    (prefix / "include" / "DetourModKit.hpp").write_text("umbrella")
    (include_dir / "session.hpp").write_text("session")
    for file_name, content in cmake_files.items():
        (cmake_dir / file_name).write_text(content)
    for archive in archives:
        (prefix / "lib" / archive).write_text("archive")
    return prefix


_FULL_CMAKE = {"DetourModKitConfig.cmake": "config", "DetourModKitAbi.cmake": "abi"}
_FULL_ARCHIVES = ("libDetourModKit.a", "libsafetyhook.a", "libZydis.a", "libZycore.a")


def _run_gate(prefix_a, prefix_b):
    argv = ["check_export_equality.py", str(prefix_a), str(prefix_b)]
    with unittest.mock.patch.object(sys, "argv", argv):
        return _module.main()


def test_identical_prefixes_pass():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        a = _make_prefix(root, "a", _FULL_CMAKE, _FULL_ARCHIVES)
        b = _make_prefix(root, "b", _FULL_CMAKE, _FULL_ARCHIVES)
        _expect(_run_gate(a, b) == 0, "identical prefixes must pass the gate")


def test_missing_prefix_fails():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        a = _make_prefix(root, "a", _FULL_CMAKE, _FULL_ARCHIVES)
        _expect(_run_gate(a, root / "absent") == 1, "a missing prefix directory must fail the gate")


def test_empty_cmake_tree_fails():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        a = _make_prefix(root, "a", _FULL_CMAKE, _FULL_ARCHIVES)
        b = _make_prefix(root, "b", {}, _FULL_ARCHIVES)
        _expect(_run_gate(a, b) == 1, "an empty consumer-contract tree must fail the gate")


def test_content_difference_fails():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        a = _make_prefix(root, "a", _FULL_CMAKE, _FULL_ARCHIVES)
        b = _make_prefix(root, "b", dict(_FULL_CMAKE, **{"DetourModKitAbi.cmake": "abi-b"}), _FULL_ARCHIVES)
        _expect(_run_gate(a, b) == 1, "a differing installed file must fail the gate")


def test_one_sided_file_fails():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        a = _make_prefix(root, "a", dict(_FULL_CMAKE, **{"DetourModKitExtra.cmake": "extra"}), _FULL_ARCHIVES)
        b = _make_prefix(root, "b", _FULL_CMAKE, _FULL_ARCHIVES)
        _expect(_run_gate(a, b) == 1, "a file present in only one prefix must fail the gate")


def test_archive_set_mismatch_fails():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        a = _make_prefix(root, "a", _FULL_CMAKE, _FULL_ARCHIVES)
        b = _make_prefix(root, "b", _FULL_CMAKE, _FULL_ARCHIVES + ("libDetourModKitd.a",))
        _expect(_run_gate(a, b) == 1, "asymmetric archive sets must fail the gate")


def test_missing_required_archive_fails_both_sides():
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        without_zydis = tuple(name for name in _FULL_ARCHIVES if name != "libZydis.a")
        a = _make_prefix(root, "a", _FULL_CMAKE, without_zydis)
        b = _make_prefix(root, "b", _FULL_CMAKE, without_zydis)
        _expect(_run_gate(a, b) == 1, "a required dependency archive missing from both prefixes must fail the gate")


def test_partial_stem_does_not_satisfy_requirement():
    _expect(not _module.archive_set_provides(["libDetourModKitExtra.a"], "DetourModKit"),
            "a longer stem must not satisfy a required archive by prefix match")
    _expect(_module.archive_set_provides(["libDetourModKit.a"], "DetourModKit"),
            "the exact lib-prefixed stem must satisfy the requirement")
    _expect(_module.archive_set_provides(["Zydis.lib"], "Zydis"),
            "the exact MSVC-spelled stem must satisfy the requirement")


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"check_export_equality self-test passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
