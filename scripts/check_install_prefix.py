#!/usr/bin/env python3
"""Install-prefix hygiene gate for a built-and-installed DetourModKit package.

The header-hygiene gate (check_header_hygiene.py) proves the boundary invariants in the source tree. This gate proves
them in the *artifact*: it inspects an actual install prefix (the output of `cmake --install`) and asserts that what
ships matches the v4 encapsulation contract. The two are complementary. A source that names no backend symbol can still
leak the backend into the prefix if a vendored dependency runs its own install() rules, which is exactly the class of
defect this gate catches and the source gate cannot.

Invariants enforced against the prefix (argv[1]):

  FORBIDDEN (must be absent) -- the backend must stay hidden and no legacy or private surface may ship:
    * include/safetyhook.hpp and any include/safetyhook/, include/Zydis/, include/Zycore/ header tree (backend headers)
    * lib*/cmake/safetyhook, lib*/cmake/Zydis, lib*/cmake/Zycore (backend package configs; a find_package(safetyhook)
      must NOT be satisfiable from a DetourModKit prefix)
    * the deleted v4 legacy public headers under include/DetourModKit/ (scanner/anchors/profile/hook_manager/
      config_watcher/bootstrap/diagnostics_dump) and the root include/DetourModKit.hpp umbrella
    * include/DetourModKit/internal/ (the true-private engine is never installed)

  REQUIRED (must be present) -- the package must actually be usable by a find_package consumer:
    * the DetourModKit archive (lib*/libDetourModKit.a or lib*/libDetourModKit.lib)
    * the three dependency archives shipped for DetourModKit::deps (safetyhook, Zydis, Zycore), in either the MinGW
      (lib<name>.a) or MSVC (<name>.lib) spelling
    * the package config trio (DetourModKitConfig.cmake / DetourModKitConfigVersion.cmake / DetourModKitTargets.cmake)
    * the public umbrella header include/DetourModKit/dmk.hpp and the generated include/DetourModKit/version.hpp

Exit status is 1 with offenders printed when any invariant is violated, else 0. The DirectXMath re-export is deliberate
and default-on, so this gate does not treat include/DirectXMath as a leak; a prefix built with DMK_INSTALL_DIRECTXMATH
off simply omits it, which is also fine, so DirectXMath is neither required nor forbidden here.
"""
import sys
from pathlib import Path


# The library dir GNUInstallDirs picks is `lib` on Windows/MinGW, but allow `lib64` too so the gate is not tied to one
# platform's convention. The first existing candidate is used for every lib-relative check.
LIB_DIR_CANDIDATES = ("lib", "lib64")

# Legacy public headers deleted by the v4 clean break; none may ship in the installed include tree. Mirrors the
# LEGACY_HEADERS set the source-level header-hygiene gate enforces, but checked at the installed path.
LEGACY_INSTALLED_HEADERS = (
    "include/DetourModKit/scanner.hpp",
    "include/DetourModKit/anchors.hpp",
    "include/DetourModKit/profile.hpp",
    "include/DetourModKit/hook_manager.hpp",
    "include/DetourModKit/config_watcher.hpp",
    "include/DetourModKit/bootstrap.hpp",
    "include/DetourModKit/diagnostics_dump.hpp",
    "include/DetourModKit.hpp",
)


def lib_dir(prefix):
    """Return the first existing lib directory under the prefix, or the primary candidate if none exists yet (so a
    missing-archive check reports against a sensible path rather than silently passing)."""
    for name in LIB_DIR_CANDIDATES:
        candidate = prefix / name
        if candidate.is_dir():
            return candidate
    return prefix / LIB_DIR_CANDIDATES[0]


def archive_present(libdir, stem):
    """True if a static archive for `stem` exists in either the MinGW (lib<stem>.a) or MSVC (<stem>.lib) spelling."""
    return (libdir / f"lib{stem}.a").is_file() or (libdir / f"{stem}.lib").is_file()


def main():
    if len(sys.argv) != 2:
        print("usage: check_install_prefix.py <install-prefix>")
        return 2

    prefix = Path(sys.argv[1]).resolve()
    if not prefix.is_dir():
        print(f"install-prefix hygiene gate FAILED: prefix '{prefix}' does not exist or is not a directory")
        return 1

    include = prefix / "include"
    libdir = lib_dir(prefix)
    cmake_dir = libdir / "cmake" / "DetourModKit"

    violations = []

    # --- FORBIDDEN: the backend must not be advertised by the prefix, at the header tree OR the package-config level. ---
    if (include / "safetyhook.hpp").is_file():
        violations.append("include/safetyhook.hpp ships: the backend header leaked into the prefix")
    # SafetyHook and its Zydis/Zycore transitive deps each install(DIRECTORY include/ ...) their own header tree, all
    # suppressed by EXCLUDE_FROM_ALL on the safetyhook subdirectory. Guard every one symmetrically so a regression in
    # that suppression is caught whichever backend tree it leaked, not just SafetyHook's.
    for backend_headers in ("safetyhook", "Zydis", "Zycore"):
        if (include / backend_headers).is_dir():
            violations.append(f"include/{backend_headers}/ ships: a backend header tree leaked into the prefix")
    for backend_pkg in ("safetyhook", "Zydis", "Zycore"):
        if (libdir / "cmake" / backend_pkg).is_dir():
            violations.append(
                f"{libdir.name}/cmake/{backend_pkg} ships: find_package({backend_pkg}) would be satisfiable from a "
                "DetourModKit prefix, defeating backend confinement")

    # --- FORBIDDEN: deleted legacy public headers and the private engine must not ship. ---
    for legacy in LEGACY_INSTALLED_HEADERS:
        if (prefix / legacy).is_file():
            violations.append(f"{legacy} ships: a v4-deleted legacy public header is present in the prefix")
    if (include / "DetourModKit" / "internal").is_dir():
        violations.append("include/DetourModKit/internal/ ships: the true-private engine must never be installed")

    # --- REQUIRED: the package must be complete enough to consume via find_package. ---
    if not archive_present(libdir, "DetourModKit"):
        violations.append(f"missing the DetourModKit archive in {libdir.name}/ (lib*DetourModKit.a|.lib)")
    for dep in ("safetyhook", "Zydis", "Zycore"):
        if not archive_present(libdir, dep):
            violations.append(
                f"missing the {dep} dependency archive in {libdir.name}/ (DetourModKit::deps links it, so it must ship)")
    for config in ("DetourModKitConfig.cmake", "DetourModKitConfigVersion.cmake", "DetourModKitTargets.cmake"):
        if not (cmake_dir / config).is_file():
            violations.append(f"missing {libdir.name}/cmake/DetourModKit/{config}")
    for header in ("include/DetourModKit/dmk.hpp", "include/DetourModKit/version.hpp"):
        if not (prefix / header).is_file():
            violations.append(f"missing public header {header}")

    if violations:
        print(f"Install-prefix hygiene gate FAILED for '{prefix}':\n")
        for v in sorted(violations):
            print("  " + v)
        print(f"\n{len(violations)} violation(s).")
        return 1
    print(f"Install-prefix hygiene gate passed: backend hidden, no legacy/private headers, package complete ({prefix}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
