#!/usr/bin/env python3
"""Header-encapsulation hygiene gate for DetourModKit's v4 public surface.

Enforces the boundary invariants introduced when the 4.0.0 public surface was encapsulated:

  1. The SafetyHook backend is confined. No public API header may include or name the backend
     (safetyhook), pull <psapi.h>, or reference Zydis/Zycore. The single sanctioned coupling
     point is the non-installed src/internal/hook_backend.hpp, which only src/hook.cpp
     includes. A consumer that includes hook.hpp must therefore compile with SafetyHook
     off its own include path.

  2. hook::MidContext is never defined. It is an opaque, pass-through alias for the backend's
     captured register context: the Context64 <-> MidContext reinterpret_cast
     is well-defined ONLY while MidContext stays incomplete. A real definition anywhere (Allman
     brace or same-line) is forbidden; the bare forward declaration `struct MidContext;` is fine.

  3. The async-logger plumbing (StringPool / LogMessage / DynamicMPMCQueue) is defined only in
     the non-installed src/internal/async_logger_queue.hpp, never on the documented public surface
     (one-definition check).

The check enumerates this repository's own C++ sources from the filesystem (so newly added but
not-yet-committed headers are covered too) and excludes vendored trees under external/ and any
build directory. Exit status is 1 with offenders printed when any rule is violated, else 0.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The one non-installed private header allowed to see the backend; only src/hook.cpp includes it. It lives
# under src/internal/ (not a public header), so the public-surface backend check below already skips it; the constant
# is kept for documentation and to localize the sanctioned coupling point.
BACKEND_BRIDGE_HEADER = "src/internal/hook_backend.hpp"
ASYNC_INTERNAL_HEADER = "src/internal/async_logger_queue.hpp"

CPP_SUFFIXES = (".hpp", ".cpp", ".h", ".cc", ".inl")
SOURCE_DIRS = ("include", "src", "tests")

SAFETYHOOK_INCLUDE = re.compile(r'#\s*include\s*[<"]\s*safetyhook')
SAFETYHOOK_NS = re.compile(r'\bsafetyhook::')
PSAPI_INCLUDE = re.compile(r'#\s*include\s*<\s*psapi\.h\s*>')
ZYDIS_REF = re.compile(r'\bZy(?:dis|core)\b')
# Matches a MidContext DEFINITION: struct/class, an optional alignas, the name, then any final / base-class
# text up to the opening brace (so `struct MidContext final {`, `class MidContext : Base {`, and
# `struct alignas(16) MidContext {` are all caught). Allman braces are covered because the character classes
# already span newlines, and a forward declaration (which reaches ';' before any '{') is not matched.
MIDCONTEXT_DEF = re.compile(r'\b(?:struct|class)\s+(?:alignas\s*\([^)]*\)\s*)?MidContext\b[^;{]*\{')
# Matches a class/struct DECLARATION token for an async-logger internal type (decl or def alike).
ASYNC_INTERNAL_DECL = re.compile(r'\b(?:class|struct)\s+(StringPool|LogMessage|DynamicMPMCQueue)\b')

# --- v4 clean-break gates ---
# Legacy public headers deleted by a clean-break reshape; none may reappear.
LEGACY_HEADERS = (
    "include/DetourModKit/scanner.hpp",
    "include/DetourModKit/anchors.hpp",
    "include/DetourModKit/profile.hpp",
    "include/DetourModKit/hook_manager.hpp",
)
# Legacy scan symbols the v4 surface replaced. None may appear in this repo's own sources: the engine is
# DetourModKit::detail::EnginePattern / find_pattern, the resolver is scan::resolve / scan::Candidate, and
# the three per-domain scan error enums folded into the unified ErrorCode. Matched after comment stripping,
# so doc prose that merely mentions the old names does not trip the gate.
LEGACY_SCAN_TOKEN = re.compile(
    r'(\bScanner::|\bresolve_cascade|\bRipResolveError\b|\bResolveError\b|\bStringXrefError\b'
    r'|\bAddrCandidate\b|\bResolveMode\b|\bResolveHit\b|\bCascadeRequest\b|\bCompiledPattern\b)')
# --- v4 memory clean-break gate ---
# The legacy memory surface (namespace Memory, MemoryError, the seh_*/read_ptr_* primitives, the
# ModuleRange family, plausible_userspace_ptr) was reshaped into namespace memory + the unified
# ErrorCode + the src/internal/ guarded engine. None of these spellings may reappear in this repo's
# own sources. Matched after comment stripping, so the v3-migration notes in memory.hpp / error.hpp
# (which mention the old names as prose) do not trip the gate. ModuleRangeCache / module_range_cache /
# module_range_from_handle are NOT matched (no \b ModuleRange \b boundary, lowercase, or distinct name).
LEGACY_MEMORY_TOKEN = re.compile(
    r'(\bMemory::|\bMemoryError\b|\bmemory_error_to_string\b'
    r'|\bseh_read|\bseh_write|\bseh_resolve'
    r'|\bread_ptr_unsafe\b|\bread_ptr_unchecked\b|\bplausible_userspace_ptr\b'
    r'|\bModuleRange\b|\bmodule_range_for\b|\bown_module_range\b|\bhost_module_range\b)')
# --- v4 hook clean-break gate ---
# The legacy hook public surface (the HookManager singleton + name registry, HookError / HookConfig / VmtHookConfig,
# InlineProloguePolicy, HookStatus / HookType, and the create_*_hook / hook_vmt_method / with_vmt_method entry points)
# was reshaped into the free-function hook:: surface (inline_at / mid_at / install_all / Hook / VmtHook) over the
# unified ErrorCode. None of these spellings may reappear. Matched after comment stripping. HookManager:: is gated
# with the scope operator, not a bare \bHookManager\b, on purpose -- broadening to the bare token is both unnecessary
# and wrong: the HookManager class is deleted, so any standalone-type spelling (HookManager x;, HookManager *, or
# using X = HookManager) is already a hard compile error that needs no gate; and a bare token would false-positive on
# the surviving Diagnostics::LeakSubsystem::HookManager enumerator (a distinct, legitimate name that FOLLOWS '::').
# The scope-only form targets exactly the legacy static-call spelling, the one that could otherwise read as plausible.
LEGACY_HOOK_TOKEN = re.compile(
    r'(\bHookManager::|\bHookError\b|\bHookConfig\b|\bVmtHookConfig\b|\bInlineProloguePolicy\b'
    r'|\bHookStatus\b|\bHookType\b|\bcreate_inline_hook\b|\bcreate_mid_hook\b'
    r'|\bhook_vmt_method\b|\bwith_vmt_method\b)')
# A public header must never reach into the non-installed private engine under src/internal/.
INTERNAL_INCLUDE = re.compile(r'#\s*include\s*[<"]\s*internal/')
# include/DetourModKit/detail/ is allowlisted: only tiny must-ship compile-visible support headers belong
# there (templates / constexpr / public object layout, backend-/Win32-/logger-/heap-free). A new detail
# header must be justified and added here, not slipped in silently.
ALLOWED_DETAIL_HEADERS = {
    "pattern_core.hpp",  # by-value inline storage + constexpr parser of public scan::Pattern
}


def strip_comments(text):
    """Blank out // and /* */ comments while preserving newlines (so line numbers stay accurate) and
    string/char literals (so an `#include "safetyhook.hpp"` is still detectable). This keeps a doc comment
    that merely *mentions* safetyhook, Zydis, or the forbidden `class MidContext { ... }` example from
    tripping the structural checks; only real code is inspected."""
    out = []
    i, n = 0, len(text)
    state = "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 2
                continue
            if c == '"':
                state = "string"
            elif c == "'":
                state = "char"
            out.append(c)
            i += 1
        elif state == "line":
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                state = "code"
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        else:  # inside a string or char literal: copy verbatim, honour escapes
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if (state == "string" and c == '"') or (state == "char" and c == "'"):
                state = "code"
            i += 1
    return "".join(out)


def iter_sources():
    for top in SOURCE_DIRS:
        base = REPO / top
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix not in CPP_SUFFIXES or not path.is_file():
                continue
            rel = path.relative_to(REPO).as_posix()
            if "/external/" in f"/{rel}" or rel.startswith("external/") or "/build/" in f"/{rel}":
                continue
            yield rel, path


def line_of(text, index):
    return text.count("\n", 0, index) + 1


def main():
    violations = []

    # v4 gate A: the deleted legacy public headers must not reappear.
    for legacy in LEGACY_HEADERS:
        if (REPO / legacy).is_file():
            violations.append(f"{legacy}: legacy public header still present; it was replaced by the v4 surface")

    # v4 memory gate A: the relocated private fault header must not reappear at its old path.
    if (REPO / "src" / "memory_internal.hpp").is_file():
        violations.append(
            "src/memory_internal.hpp: legacy private header still present; it moved to src/internal/memory_fault.hpp")

    # v4 scan gate B: include/DetourModKit/detail/ holds only allowlisted compile-visible support headers.
    detail_dir = REPO / "include" / "DetourModKit" / "detail"
    if detail_dir.is_dir():
        for header in sorted(detail_dir.glob("*.hpp")):
            if header.name not in ALLOWED_DETAIL_HEADERS:
                rel = header.relative_to(REPO).as_posix()
                violations.append(
                    f"{rel}: detail/ header not on the allowlist; true-private implementation belongs in src/internal/")

    for rel, path in iter_sources():
        raw = path.read_text(encoding="utf-8", errors="replace")
        text = strip_comments(raw)
        lines = text.splitlines()
        is_public_header = rel.startswith("include/DetourModKit/") and rel.endswith(".hpp")

        # Rule 1: backend confinement on the public surface.
        if is_public_header and rel != BACKEND_BRIDGE_HEADER:
            for n, line in enumerate(lines, 1):
                if SAFETYHOOK_INCLUDE.search(line):
                    violations.append(f"{rel}:{n}: public header includes the SafetyHook backend")
                if SAFETYHOOK_NS.search(line):
                    violations.append(f"{rel}:{n}: public header names safetyhook:: (backend leak)")
                if PSAPI_INCLUDE.search(line):
                    violations.append(f"{rel}:{n}: public header includes <psapi.h>")
                if ZYDIS_REF.search(line):
                    violations.append(f"{rel}:{n}: public header references Zydis/Zycore")

        # Rule 2: MidContext must never be defined (anywhere in this repo's sources).
        m = MIDCONTEXT_DEF.search(text)
        if m:
            violations.append(
                f"{rel}:{line_of(text, m.start())}: MidContext is defined; it must remain an opaque forward declaration")

        # Rule 3: async-logger internals are defined ONLY in src/internal/async_logger_queue.hpp. The contract is
        # location-exclusive, so this scans every source (headers and .cpp), excluding only the one allowed header,
        # rather than the public headers alone.
        if rel != ASYNC_INTERNAL_HEADER:
            for n, line in enumerate(lines, 1):
                am = ASYNC_INTERNAL_DECL.search(line)
                if am:
                    violations.append(
                        f"{rel}:{n}: {am.group(1)} declared outside detail/async_logger_internal.hpp")

        # v4 scan gate C: no public header reaches into the non-installed private engine under src/internal/.
        if is_public_header:
            for n, line in enumerate(lines, 1):
                if INTERNAL_INCLUDE.search(line):
                    violations.append(f"{rel}:{n}: public header includes the private engine (src/internal/)")

        # v4 scan gate D: no legacy scan symbol survives in this repo's own sources (headers, sources, or tests).
        for n, line in enumerate(lines, 1):
            lm = LEGACY_SCAN_TOKEN.search(line)
            if lm:
                violations.append(
                    f"{rel}:{n}: legacy scan symbol '{lm.group(1).strip()}' (replaced by the v4 scan surface)")

        # v4 memory gate D: no legacy memory symbol survives in this repo's own sources.
        for n, line in enumerate(lines, 1):
            mm = LEGACY_MEMORY_TOKEN.search(line)
            if mm:
                violations.append(
                    f"{rel}:{n}: legacy memory symbol '{mm.group(1).strip()}' (replaced by the v4 memory surface)")

        # v4 hook gate D: no legacy hook symbol survives in this repo's own sources.
        for n, line in enumerate(lines, 1):
            hm = LEGACY_HOOK_TOKEN.search(line)
            if hm:
                violations.append(
                    f"{rel}:{n}: legacy hook symbol '{hm.group(1).strip()}' (replaced by the v4 hook surface)")

    if violations:
        print("Header-hygiene gate FAILED:\n")
        for v in sorted(violations):
            print("  " + v)
        print(f"\n{len(violations)} violation(s). See AGENTS.md (the encapsulation boundary rule).")
        return 1
    print("Header-hygiene gate passed: backend confined, MidContext opaque, async internals private.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
