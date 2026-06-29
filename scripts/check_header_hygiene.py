#!/usr/bin/env python3
"""Header-encapsulation hygiene gate for DetourModKit's v4 public surface.

Enforces the boundary invariants introduced when the 4.0.0 public surface was encapsulated:

  1. The SafetyHook backend is confined. No public API header may include or name the backend
     (safetyhook), pull <psapi.h>, or reference Zydis/Zycore. The single sanctioned coupling
     point is include/DetourModKit/detail/hook_impl.hpp, which only src/hook_manager.cpp
     includes. A consumer that includes hook_manager.hpp must therefore compile with SafetyHook
     off its own include path.

  2. hook::MidContext is never defined. It is an opaque, pass-through alias for the backend's
     captured register context: the Context64 <-> MidContext reinterpret_cast
     is well-defined ONLY while MidContext stays incomplete. A real definition anywhere (Allman
     brace or same-line) is forbidden; the bare forward declaration `struct MidContext;` is fine.

  3. The async-logger plumbing (StringPool / LogMessage / DynamicMPMCQueue) is defined only in
     detail/async_logger_internal.hpp, never on the documented public surface (one-definition
     check).

The check enumerates this repository's own C++ sources from the filesystem (so newly added but
not-yet-committed headers are covered too) and excludes vendored trees under external/ and any
build directory. Exit status is 1 with offenders printed when any rule is violated, else 0.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The one public, installed header allowed to see the backend; only src/hook_manager.cpp includes it.
BACKEND_BRIDGE_HEADER = "include/DetourModKit/detail/hook_impl.hpp"
ASYNC_INTERNAL_HEADER = "include/DetourModKit/detail/async_logger_internal.hpp"

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

        # Rule 3: async-logger internals are defined ONLY in detail/async_logger_internal.hpp. The contract is
        # location-exclusive, so this scans every source (headers and .cpp), excluding only the one allowed header,
        # rather than the public headers alone.
        if rel != ASYNC_INTERNAL_HEADER:
            for n, line in enumerate(lines, 1):
                am = ASYNC_INTERNAL_DECL.search(line)
                if am:
                    violations.append(
                        f"{rel}:{n}: {am.group(1)} declared outside detail/async_logger_internal.hpp")

    if violations:
        print("Header-hygiene gate FAILED:\n")
        for v in sorted(violations):
            print("  " + v)
        print(f"\n{len(violations)} violation(s). See AGENTS.md (the encapsulation boundary rule).")
        return 1
    print("Header-hygiene gate passed: backend confined, MidContext opaque, async internals in detail/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
