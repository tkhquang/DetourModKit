#!/usr/bin/env python3
"""Header-encapsulation hygiene gate for DetourModKit's v4 public surface.

Enforces the boundary invariants introduced when the 4.0.0 public surface was encapsulated:

  1. The SafetyHook backend is confined, at two levels.
       (a) Public surface: no public API header may include or name the backend (safetyhook), pull <psapi.h>, or
           reference Zydis/Zycore, so a consumer that includes a public header compiles with SafetyHook off its own
           include path.
       (b) Source level: within this repository's own library sources (src/), only the sanctioned backend islands may
           include the backend header or name a safetyhook:: symbol. Two islands exist: the public hook:: surface's
           pimpl (src/internal/hook_backend.hpp, whose bodies the single TU src/hook.cpp completes) and the internal
           active-input layer (src/internal/input_intercept.cpp), which owns its own XInput inline hooks directly
           because it needs the create-disabled / publish-trampoline-before-enable ordering the public hook:: surface
           does not expose. Any other src/ file that reaches the backend is drift and fails this gate.

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

# The non-installed private header that carries the public hook:: surface's pimpl bodies; only src/hook.cpp includes
# it. It lives under src/internal/ (not a public header), so the public-surface backend check below already skips it;
# the constant is kept for documentation and to localize the primary sanctioned coupling point.
BACKEND_BRIDGE_HEADER = "src/internal/hook_backend.hpp"
# The sanctioned SafetyHook backend islands: the ONLY repository sources permitted to include the backend header or
# name a safetyhook:: symbol (rule 1b). Everything else must reach hooking through the public hook:: surface, so the
# backend stays swappable and its heavy headers never spread across the tree. Enforced only within src/ (the library's
# own implementation): the parked per-method-VMT fixtures in tests/ legitimately name the backend behind an #if 0, and
# white-box tests are outside the library-confinement invariant this gate protects.
BACKEND_SOURCE_ISLANDS = {
    BACKEND_BRIDGE_HEADER,               # src/internal/hook_backend.hpp: the hook:: pimpl bodies
    "src/hook.cpp",                      # the one TU that completes those bodies over safetyhook::
    "src/internal/input_intercept.cpp",  # the XInput/window-subclass active-input layer, owning its own inline hooks
}
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
# Legacy public headers deleted by a clean-break reshape; none may reappear. The root-level DetourModKit.hpp umbrella and
# bootstrap.hpp were both folded into the v4 dmk.hpp (umbrella + Session/bootstrap/ModInfo) in the lifecycle reshape.
LEGACY_HEADERS = (
    "include/DetourModKit/scanner.hpp",
    "include/DetourModKit/anchors.hpp",
    "include/DetourModKit/profile.hpp",
    "include/DetourModKit/hook_manager.hpp",
    "include/DetourModKit/config_watcher.hpp",
    "include/DetourModKit/bootstrap.hpp",
    "include/DetourModKit.hpp",
    "include/DetourModKit/diagnostics_dump.hpp",
)
# Public headers DEMOTED (moved, not deleted): each keeps its capability but leaves
# the top-level public include set for its new home. It must not reappear at the OLD public path -- that would
# re-expand the first-class public surface the demotion trimmed. A detail/ home keeps the header installed (a public
# header or the umbrella still includes it); a src/internal/ home makes it truly private (no public includer).
DEMOTED_HEADERS = {
    "include/DetourModKit/worker.hpp": "include/DetourModKit/detail/worker.hpp",
    "include/DetourModKit/win_file_stream.hpp": "include/DetourModKit/detail/win_file_stream.hpp",
    "include/DetourModKit/event_dispatcher.hpp": "include/DetourModKit/detail/event_dispatcher.hpp",
    "include/DetourModKit/drift_manifest.hpp": "include/DetourModKit/detail/drift_manifest.hpp",
    "include/DetourModKit/srw_shared_mutex.hpp": "src/internal/srw_shared_mutex.hpp",
}
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
# --- v4 config clean-break gate ---
# The legacy config surface (namespace Config, the register_* free functions, clear_registered_items) was reshaped into
# namespace config (bind / bind_int / bind_parsed / press_combo / load / clear) and the watcher was folded into a
# src/internal/ engine. None of these spellings may reappear in this repo's own sources. Config:: is gated with the
# scope operator (PascalCase) so it targets exactly the deleted legacy namespace; the v4 surface is lowercase config::.
# Matched after comment stripping, so v3-migration prose does not trip it.
LEGACY_CONFIG_TOKEN = re.compile(
    r'(\bConfig::|\bclear_registered_items\b'
    r'|\bregister_int\b|\bregister_float\b|\bregister_bool\b|\bregister_string\b|\bregister_log_level\b'
    r'|\bregister_atomic\b|\bregister_key_combo\b|\bregister_press_combo\b|\bregister_hold_combo\b'
    r'|\bregister_consume_flag\b|\bregister_reload_hotkey\b)')
# --- v4 input clean-break gate ---
# The legacy input surface (the InputManager singleton + InputPoller as a PUBLIC class, InputMode, the InputBindingGuard
# guard, update_binding_combos, input_mode_to_string) was reshaped into the namespace input facade (Input /
# register_combo / BindingGuard / Scope / Trigger / rebind) over the private engine. None of these spellings may
# reappear. InputPoller / InputBinding are intentionally NOT gated: they survive as the internal engine types
# DetourModKit::detail::InputPoller / InputBinding, so a bare token would false-positive on legitimate v4 code; the
# deletion of the PUBLIC classes is enforced by the namespace move, not this gate. Matched after comment stripping.
LEGACY_INPUT_TOKEN = re.compile(
    r'(\bInputManager\b|\bInputMode\b|\bInputBindingGuard\b|\bupdate_binding_combos\b|\binput_mode_to_string\b'
    r'|\bregister_press\b|\bregister_hold\b)')
# --- v4 logger clean-break gate ---
# The legacy logger surface (the Logger::get_instance() singleton accessor, the log_level_to_string free function, and
# the Logger::string_to_log_level static) was reshaped into the free log() value-facade accessor, the to_string(LogLevel)
# overload, and a free string_to_log_level. None of these spellings may reappear in this repo's own sources. The Logger
# class name itself SURVIVES as the v4 value facade (class Logger, the log() return type, "construct your own"), so it is
# gated only with the scope operator on the two deleted statics -- a bare \bLogger\b would false-positive on every
# legitimate v4 site (and on AsyncLogger). log_level_to_string is a distinct deleted free-function name. Matched after
# comment stripping, so v3-migration prose does not trip the gate.
LEGACY_LOGGER_TOKEN = re.compile(
    r'(\bLogger::get_instance\b|\bLogger::string_to_log_level\b|\blog_level_to_string\b)')
# --- v4 lifecycle clean-break gate ---
# The legacy lifecycle surface (the standalone DMK_Shutdown() ordered-teardown free function, the namespace Bootstrap
# scaffolding, and its on_dll_attach / on_dll_detach entry points) was reshaped into the RAII Session (whose destructor
# runs the ordered teardown) plus the free bootstrap() / bootstrap_detach() / request_shutdown() surface in dmk.hpp.
# None of these spellings may reappear in this repo's own sources. Bootstrap:: is gated with the scope operator (not a
# bare token) on purpose: the surviving Diagnostics::LeakSubsystem::Bootstrap enumerator is a distinct, legitimate name
# that FOLLOWS '::', so a bare token would false-positive on it. Matched after comment stripping, so v3-migration prose
# does not trip the gate.
LEGACY_LIFECYCLE_TOKEN = re.compile(
    r'(\bDMK_Shutdown\b|\bBootstrap::|\bon_dll_attach\b|\bon_dll_detach\b)')
# --- v4 rtti clean-break gate ---
# The legacy rtti surface (the PascalCase namespace Rtti, the per-domain IdentifyError / HealError enums, their
# identify_error_to_string / heal_error_to_string mappers, and the lossy heal_offset wrapper) was reshaped into the
# lowercase namespace rtti over the Address / Result vocabulary; the two enums folded into the unified ErrorCode's
# ErrorCategory::Rtti block (BadSlotAddress / UnreadableSlot / NoRtti / BadDescriptor / HealNoMatch / HealAmbiguous),
# and heal_offset was dropped in favour of the Result-returning heal_landmark. None of these spellings may reappear.
# Rtti:: is gated with the scope operator (PascalCase) so it targets exactly the deleted legacy namespace-qualified
# spelling: the surviving ErrorCategory::Rtti enumerator has Rtti FOLLOWING '::' (never preceding it), so \bRtti:: does
# not match it, and the v4 surface is lowercase rtti::. heal_offset is gated as a whole token, so the surviving
# healed_offset field (a distinct name) is not matched. Matched after comment stripping, so v3-migration prose does not
# trip the gate.
LEGACY_RTTI_TOKEN = re.compile(
    r'(\bRtti::|\bIdentifyError\b|\bHealError\b'
    r'|\bidentify_error_to_string\b|\bheal_error_to_string\b|\bheal_offset\b)')
# --- v4 manifest clean-break gate ---
# The drift-manifest file-level ManifestError enum and its manifest_error_to_string mapper folded into the unified
# ErrorCode's ErrorCategory::Manifest block (MissingHeader / MalformedLine / FileOpenFailed) and the Result idiom.
# Neither spelling may reappear in this repo's own sources. ErrorCategory::Manifest and the "manifest" category label
# are legitimate v4 names (Manifest FOLLOWS '::' or is the bare category word), so only the deleted enum name and its
# mapper are gated. Matched after comment stripping, so v3-migration prose does not trip the gate.
LEGACY_MANIFEST_TOKEN = re.compile(r'(\bManifestError\b|\bmanifest_error_to_string\b)')
# A public header must never reach into the non-installed private engine under src/internal/.
INTERNAL_INCLUDE = re.compile(r'#\s*include\s*[<"]\s*internal/')
# include/DetourModKit/detail/ is allowlisted. A detail/ header is installed (it ships with the package), so it
# is reserved for compile-visible support a PUBLIC header still needs across the include boundary: either tiny
# must-ship layout/parser support (pattern_core), or a header a public header / the dmk.hpp umbrella still includes
# to keep a v3 capability reachable in clean v4 idiom. True-private implementation with no public includer belongs
# in src/internal/ (never installed), not here. A new detail header must be justified and added below, not slipped
# in silently.
ALLOWED_DETAIL_HEADERS = {
    "pattern_core.hpp",      # by-value inline storage + constexpr parser of public scan::Pattern
    "event_dispatcher.hpp",  # EventDispatcher<T> template returned by-reference from public diagnostics.hpp
    "win_file_stream.hpp",   # WinFileStream held by shared_ptr in public logger.hpp / async_logger.hpp
    "worker.hpp",            # StoppableWorker utility kept reachable via the dmk.hpp umbrella (DMKStoppableWorker)
    "drift_manifest.hpp",    # drift-report persistence kept reachable via the dmk.hpp umbrella
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

    # v4 gate A': demoted public headers must not reappear at their old top-level path (they moved, not deleted).
    for old_path, new_home in DEMOTED_HEADERS.items():
        if (REPO / old_path).is_file():
            violations.append(f"{old_path}: demoted header back at the old public path; it now lives at {new_home}")

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

        # Rule 1b: source-level backend confinement. Within the library's own sources, only the sanctioned backend
        # islands may include the backend header or name a safetyhook:: symbol; anything else is drift. Scoped to src/
        # so a white-box test (and the parked #if 0 per-method-VMT fixtures under tests/) is not swept up by this
        # library-only invariant. This is what makes the "only the sanctioned islands see the backend" claim in the
        # module docstring an enforced gate rather than an unchecked assertion.
        if rel.startswith("src/") and rel not in BACKEND_SOURCE_ISLANDS:
            for n, line in enumerate(lines, 1):
                if SAFETYHOOK_INCLUDE.search(line):
                    violations.append(f"{rel}:{n}: source includes the SafetyHook backend outside a sanctioned island")
                if SAFETYHOOK_NS.search(line):
                    violations.append(f"{rel}:{n}: source names safetyhook:: outside a sanctioned island (backend drift)")

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
                        f"{rel}:{n}: {am.group(1)} declared outside {ASYNC_INTERNAL_HEADER}")

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

        # v4 config gate D: no legacy config symbol survives in this repo's own sources.
        for n, line in enumerate(lines, 1):
            cm = LEGACY_CONFIG_TOKEN.search(line)
            if cm:
                violations.append(
                    f"{rel}:{n}: legacy config symbol '{cm.group(1).strip()}' (replaced by the v4 config surface)")

        # v4 input gate D: no legacy input symbol survives in this repo's own sources.
        for n, line in enumerate(lines, 1):
            im = LEGACY_INPUT_TOKEN.search(line)
            if im:
                violations.append(
                    f"{rel}:{n}: legacy input symbol '{im.group(1).strip()}' (replaced by the v4 input surface)")

        # v4 logger gate D: no legacy logger symbol survives in this repo's own sources.
        for n, line in enumerate(lines, 1):
            gm = LEGACY_LOGGER_TOKEN.search(line)
            if gm:
                violations.append(
                    f"{rel}:{n}: legacy logger symbol '{gm.group(1).strip()}' (replaced by the v4 logger surface)")

        # v4 lifecycle gate D: no legacy lifecycle symbol survives in this repo's own sources.
        for n, line in enumerate(lines, 1):
            fm = LEGACY_LIFECYCLE_TOKEN.search(line)
            if fm:
                violations.append(
                    f"{rel}:{n}: legacy lifecycle symbol '{fm.group(1).strip()}' (replaced by the v4 Session/dmk.hpp surface)")

        # v4 rtti gate D: no legacy rtti symbol survives in this repo's own sources.
        for n, line in enumerate(lines, 1):
            rm = LEGACY_RTTI_TOKEN.search(line)
            if rm:
                violations.append(
                    f"{rel}:{n}: legacy rtti symbol '{rm.group(1).strip()}' (replaced by the v4 rtti surface)")

        # v4 manifest gate D: no legacy drift-manifest error symbol survives in this repo's own sources.
        for n, line in enumerate(lines, 1):
            fm = LEGACY_MANIFEST_TOKEN.search(line)
            if fm:
                violations.append(
                    f"{rel}:{n}: legacy manifest symbol '{fm.group(1).strip()}' (folded into ErrorCode::Manifest)")

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
