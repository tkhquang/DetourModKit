#!/usr/bin/env python3
"""Header-encapsulation hygiene gate for DetourModKit's v4 public surface.

Enforces the boundary invariants introduced when the 4.0.0 public surface was encapsulated:

  1. The SafetyHook backend is confined, at two levels.
       (a) Public surface: no public API header may include or name the backend (safetyhook), pull <psapi.h>, or
           reference Zydis/Zycore, so a consumer that includes a public header compiles with SafetyHook off its own
           include path.
       (b) Source level: within this repository's own library sources (src/), only the sanctioned backend islands may
           include the backend header or name a safetyhook:: symbol. Two islands exist: the public hook:: implementation
           (the hook sibling TUs plus their private backend headers) and the internal active-input layer
           (src/internal/input_intercept.cpp), which owns its own XInput inline hooks directly because it needs the
           create-disabled / publish-trampoline-before-enable ordering the public hook:: surface does not expose. Any
           other src/ file that reaches the backend is drift and fails this gate.

  2. hook::MidContext is never defined. It is an opaque, pass-through alias for the backend's
     captured register context: the Context64 <-> MidContext reinterpret_cast
     is well-defined ONLY while MidContext stays incomplete. A real definition anywhere (Allman
     brace or same-line) is forbidden; the bare forward declaration `struct MidContext;` is fine.

  3. The async-logger plumbing (StringPool / LogMessage / DynamicMPMCQueue) is defined only in
     the non-installed src/internal/async_logger_queue.hpp, never on the documented public surface
     (one-definition check). StringPool is a never-destroyed singleton, so its canonical header must carry one deleted
     destructor sentinel and no teardown-only declaration or implementation may exist elsewhere.

  4. Installed definitions are token-stable under private test macros. No header under include/ may name
     DMK_ENABLE_TEST_SEAMS or DMK_EVENT_DISPATCHER_INTERNAL_TESTING, so one program cannot hold two spellings of an
     installed class definition (see installed_test_macro_violations).

The check enumerates this repository's own C++ sources from the filesystem (so newly added but
not-yet-committed headers are covered too) and excludes vendored trees under external/ and any
build directory. Exit status is 1 with offenders printed when any rule is violated, else 0.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The non-installed private header that carries the public hook:: surface's pimpl bodies; only the hook sibling TUs
# include it. It lives under src/internal/ (not a public header), so the public-surface backend check below skips it
# structurally (an src/internal/ path can never satisfy is_public_header). It is a sanctioned backend island listed in
# BACKEND_SOURCE_ISLANDS and the primary sanctioned coupling point.
BACKEND_BRIDGE_HEADER = "src/internal/hook_backend.hpp"
# The sanctioned SafetyHook backend islands: the ONLY repository sources permitted to include the backend header or
# name a safetyhook:: symbol (rule 1b). Everything else must reach hooking through the public hook:: surface, so the
# backend stays swappable and its heavy headers never spread across the tree. Enforced only within src/ (the library's
# own implementation): the parked per-method-VMT fixtures in tests/ legitimately name the backend behind an #if 0, and
# white-box tests are outside the library-confinement invariant this gate protects.
BACKEND_SOURCE_ISLANDS = {
    BACKEND_BRIDGE_HEADER,                # src/internal/hook_backend.hpp: the hook:: pimpl bodies
    "src/hook.cpp",                       # hook lifecycle: install verbs, handle teardown, VMT surface
    "src/hook_toggle.cpp",                # Hook::enable / Hook::disable over the shared toggle publication order
    "src/hook_mid_context.cpp",           # the hook::MidContext accessor bridge over the backend register frame
    "src/internal/hook_backend_visit.hpp",  # nothrow visitation/toggle primitives over the backend variant
    "src/internal/input_intercept.cpp",   # the XInput/window-subclass active-input layer, owning its own inline hooks
    # src/internal/mid_hook_adapter.hpp: the exactly typed mid-hook dispatch pool and its pool-state TU
    "src/internal/mid_hook_adapter.hpp",
    "src/internal/mid_hook_adapter.cpp",
}
ASYNC_INTERNAL_HEADER = "src/internal/async_logger_queue.hpp"

CPP_SUFFIXES = (".hpp", ".cpp", ".h", ".cc", ".inl")
SOURCE_DIRS = ("include", "src", "tests")

SAFETYHOOK_INCLUDE = re.compile(r'#\s*include\s*[<"]\s*safetyhook')
SAFETYHOOK_NS = re.compile(r'\bsafetyhook::')
PSAPI_INCLUDE = re.compile(r'#\s*include\s*<\s*psapi\.h\s*>')
ZYDIS_REF = re.compile(r'\bZy(?:dis|core)\b')
# Public headers ship without <windows.h>: the Win32 handle surface is typedef-aliased (see session.hpp) precisely so
# consumer TUs never inherit the macro soup, and the windows_macro_probe consumer TUs rely on controlling when
# windows.h is included. An include here would also defeat the NOMINMAX-free contract below.
WINDOWS_INCLUDE = re.compile(r'#\s*include\s*[<"]\s*windows\.h\s*[>"]', re.IGNORECASE)
# DetourModKit does not export NOMINMAX, so public headers must stay compilable while windows.h's function-like
# min/max macros are ACTIVE. The one spelling that breaks under an active macro is an unparenthesized
# std::numeric_limits<...>::min()/max() call. The macro-proof form (std::numeric_limits<T>::max)() cannot match
# this pattern: its protective ')' sits between the member name and the call paren, so the mandatory min/max '('
# tail never lines up. The compile-level proof is the windows_macro_probe TU in the package consumers; this
# textual gate catches the same spelling on every platform.
UNPARENTHESIZED_LIMITS = re.compile(r'\bstd::numeric_limits\s*<[^;{}()]*>\s*::\s*(?:min|max)\s*\(')
# Matches a MidContext DEFINITION: struct/class, an optional alignas, the name, then any final / base-class
# text up to the opening brace (so `struct MidContext final {`, `class MidContext : Base {`, and
# `struct alignas(16) MidContext {` are all caught). Allman braces are covered because the character classes
# already span newlines, and a forward declaration (which reaches ';' before any '{') is not matched.
MIDCONTEXT_DEF = re.compile(r'\b(?:struct|class)\s+(?:alignas\s*\([^)]*\)\s*)?MidContext\b[^;{]*\{')
# Matches a class/struct DECLARATION token for an async-logger internal type (decl or def alike).
ASYNC_INTERNAL_DECL = re.compile(r'\b(?:class|struct)\s+(StringPool|LogMessage|DynamicMPMCQueue)\b')
# StringPool lives in placement-constructed static storage for process lifetime. Its one deleted destructor sentinel
# makes accidental destruction ill-formed; any other declaration would invite unreachable cleanup/reporting state.
# The optional `void` spells the same empty parameter list in C++, so both forms must be seen: matching only `()`
# would let `~StringPool(void) {}` reintroduce a teardown body that the gate reports as clean.
STRING_POOL_DESTRUCTOR = re.compile(r'~\s*StringPool\s*\(\s*(?:void\s*)?\)')
STRING_POOL_DELETED_SENTINEL = re.compile(r'~\s*StringPool\s*\(\s*(?:void\s*)?\)\s*=\s*delete\s*;')

# --- v4 clean-break gates ---
# Legacy public headers deleted by a clean-break reshape; none may reappear. bootstrap.hpp was folded into the
# Session / bootstrap / ModInfo lifecycle surface, now declared in session.hpp and aggregated by the root-level
# DetourModKit.hpp umbrella. dmk.hpp was the interim in-directory umbrella spelling; the abbreviated in-directory name
# must not reappear.
LEGACY_HEADERS = (
    "include/DetourModKit/scanner.hpp",
    "include/DetourModKit/anchors.hpp",
    "include/DetourModKit/profile.hpp",
    "include/DetourModKit/hook_manager.hpp",
    "include/DetourModKit/config_watcher.hpp",
    "include/DetourModKit/bootstrap.hpp",
    "include/DetourModKit/dmk.hpp",
    "include/DetourModKit/diagnostics_dump.hpp",
)
# Public headers DEMOTED (moved, not deleted): each keeps its capability but leaves
# the top-level public include set for its new home. It must not reappear at the OLD public path -- that would
# re-expand the first-class public surface the demotion trimmed. A detail/ home keeps the header installed (a public
# header or the umbrella still includes it); a src/internal/ home makes it truly private (no public includer).
DEMOTED_HEADERS = {
    "include/DetourModKit/async_logger.hpp": "src/internal/async_logger.hpp",
    "include/DetourModKit/worker.hpp": "include/DetourModKit/detail/worker.hpp",
    "include/DetourModKit/win_file_stream.hpp": "src/internal/win_file_stream.hpp",
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
# own sources. Matched after comment stripping, so a comment that names an old spelling as prose does not
# trip the gate. ModuleRangeCache / module_range_cache /
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
# the surviving diagnostics::LeakSubsystem::HookManager enumerator (a distinct, legitimate name that FOLLOWS '::').
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
# runs the ordered teardown) plus the free bootstrap() / bootstrap_detach() / request_shutdown() surface in session.hpp.
# None of these spellings may reappear in this repo's own sources. Bootstrap:: is gated with the scope operator (not a
# bare token) on purpose: the surviving diagnostics::LeakSubsystem::Bootstrap enumerator is a distinct, legitimate name
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
# The installed-definition token-stability gate.
# A private test macro in an installed header lets one Debug program hold two spellings of one class definition:
# the seam-enabled archive and test binary define the macro, while examples and consumers do not. That is a formal
# ODR violation. The token ban makes every installed definition token-identical with each
# macro on and off (a token stream can only vary through a conditional that names the macro, and comment mentions are
# stripped before this scan). Test access to installed-class privates goes through the unconditional internal friend
# accessors instead (src/internal/logger_test_seams.hpp, src/internal/input_test_seams.hpp, and the dispatcher test's
# EventDispatcherTestAccess).
PRIVATE_TEST_MACRO = re.compile(r"\b(DMK_ENABLE_TEST_SEAMS|DMK_EVENT_DISPATCHER_INTERNAL_TESTING)\b")


def installed_test_macro_violations(text):
    """Return (line, macro) pairs for each private test macro named by installed-header code in @p text.

    Pass comment-stripped text. Each code mention is macro-dependence: a conditional arm, a defined() operand, or
    dead test vocabulary that must not ship either way. Zero mentions prove the header's token stream is identical
    with the macro defined and undefined, which is the token-stability invariant this gate owns.

    Translation phase 2 deletes each backslash-newline before tokenization, so the scan joins spliced physical
    lines into one logical line first; a hit reports the physical line where its logical line starts."""
    hits = []
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        first = index + 1
        logical = lines[index]
        while logical.endswith("\\") and index + 1 < len(lines):
            logical = logical[:-1] + lines[index + 1]
            index += 1
        match = PRIVATE_TEST_MACRO.search(logical)
        if match:
            hits.append((first, match.group(1)))
        index += 1
    return hits

# include/DetourModKit/detail/ is allowlisted. A detail/ header is installed (it ships with the package), so it
# is reserved for compile-visible support a PUBLIC header still needs across the include boundary: either tiny
# must-ship layout/parser support (pattern_core), or a header a public header / the DetourModKit.hpp umbrella still includes
# to keep a v3 capability reachable in clean v4 idiom. True-private implementation with no public includer belongs
# in src/internal/ (never installed), not here. A new detail header must be justified and added below, not slipped
# in silently.
ALLOWED_DETAIL_HEADERS = {
    "pattern_core.hpp",      # by-value inline storage + constexpr parser of public scan::Pattern
    "profile_ring.hpp",      # by-value ProfileRing member of public Profiler
    "event_dispatcher.hpp",  # EventDispatcher<T> template returned by-reference from public diagnostics.hpp
    "worker.hpp",            # StoppableWorker utility kept reachable via the DetourModKit.hpp umbrella
    "drift_manifest.hpp",    # drift-report persistence kept reachable via the DetourModKit.hpp umbrella
}


# The AOB scanner's own translation units are the only DMK sources that read arbitrary swept memory by pointer. Under
# AddressSanitizer that memory legitimately includes poisoned shadow (the redzones around instrumented globals and
# stack locals), and MSVC routes libc's block-memory routines through ASan's runtime interceptor, which inspects the
# range and reports a false overflow. That interceptor is hot-patched at run time, so it bypasses a
# no_sanitize_address attribute on the caller (see the comment above dmk_memchr in src/internal/scan_engine.cpp): the
# only fix is for the call itself not to reach libc. These TUs may therefore reach libc only from the arm taken when
# ASan is OFF, opposite a non-interceptable arm, the __movsb shape src/internal/memory_guarded.cpp uses. A libc call in
# the ASan-ON arm is the defect itself, not a guarded fallback.
SCANNER_FOREIGN_READ_SOURCES = ("src/internal/scan_pages.cpp", "src/internal/scan_engine.cpp")
# The interceptable block-memory routines, qualified or not. memset is excluded (it writes a DMK-owned buffer rather
# than reading swept memory), and the leading \b keeps the engine's self-provided dmk_memchr from matching.
LIBC_BLOCK_MEMORY_CALL = re.compile(r"\b(?:std::)?mem(?:cpy|move|chr|cmp)\s*\(")
# A preprocessor conditional directive, with the rest of the line captured so the arm's condition can be inspected.
PREPROCESSOR_CONDITIONAL = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(?P<rest>.*)$")
# A mention of the ASan macro under negation, which marks its arm as the ASan-OFF side. #ifndef is handled separately
# because it carries the negation in the directive rather than the condition.
NEGATED_ASAN_MENTION = re.compile(r"!\s*(?:defined\s*\(\s*)?__SANITIZE_ADDRESS__")

HEX_DIGITS = "0123456789abcdefABCDEF"


def is_cpp_digit_separator(text, i):
    """True when the apostrophe at text[i] is a C++14 numeric digit separator (1'000'000, 0xFF'FF) rather than a
    char-literal delimiter. A separator sits between two hex digits inside a numeric literal, and a char literal can
    never legally open immediately after a digit, so a hex digit on both sides is unambiguously a separator. Without
    this, an odd number of separators in one literal (1'000'000'000ULL) would leave the scanner stuck in char state
    and stop stripping comments for the rest of the file."""
    return 0 < i < len(text) - 1 and text[i - 1] in HEX_DIGITS and text[i + 1] in HEX_DIGITS


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
            elif c == "'" and not is_cpp_digit_separator(text, i):
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
            if "/external/" in f"/{rel}" or "/build/" in f"/{rel}":
                continue
            yield rel, path


def line_of(text, index):
    return text.count("\n", 0, index) + 1


def string_pool_destructor_violations(rel, raw):
    """Return source-gate violations for StringPool's never-destroyed lifetime sentinel."""
    text = strip_comments(raw)
    matches = list(STRING_POOL_DESTRUCTOR.finditer(text))
    if rel == ASYNC_INTERNAL_HEADER:
        if not matches:
            return [(1, "StringPool must declare exactly one deleted destructor sentinel")]
        violations = []
        if len(matches) != 1:
            violations.append((line_of(text, matches[1].start()),
                               "StringPool must declare exactly one deleted destructor sentinel"))
        if not STRING_POOL_DELETED_SENTINEL.match(text, matches[0].start()):
            violations.append((line_of(text, matches[0].start()),
                               "StringPool's only destructor declaration must be '= delete'"))
        return violations
    return [(line_of(text, match.start()),
             f"StringPool destructor is forbidden outside {ASYNC_INTERNAL_HEADER}")
            for match in matches]


def unguarded_libc_memory_calls(text):
    """Line numbers of libc block-memory calls the scanner's foreign-read translation units may not make.

    Two shapes are reported. A call under no __SANITIZE_ADDRESS__-bearing chain at all is simply unguarded. A call in
    the arm taken when ASan is ON is the defect the rule exists to catch, so being inside such a chain is not a licence
    on its own: only the ASan-OFF arm may reach libc. Tracking the chain rather than the arm in effect would accept the
    guarded arm's own libc call.

    Pass comment-stripped text: prose naming memcpy is not a call. A negated mention (#ifndef, !defined) marks its arm
    as the ASan-OFF side and hands the ASan-ON side to the matching #else. A chain carrying #elif arms is read the same
    way, from each arm's own condition.
    """
    offenders = []
    # One record per open conditional chain. "relevant" is True once some arm named the macro, so the chain is about
    # ASan at all; "arm_is_asan" describes only the arm currently in effect.
    chains = []
    for number, line in enumerate(text.split("\n"), 1):
        directive = PREPROCESSOR_CONDITIONAL.match(line)
        if directive:
            kind = directive.group(1)
            condition = directive.group("rest")
            mentions = "__SANITIZE_ADDRESS__" in condition
            negated = kind == "ifndef" or bool(NEGATED_ASAN_MENTION.search(condition))
            if kind in ("if", "ifdef", "ifndef"):
                chains.append({"relevant": mentions,
                               "arm_is_asan": mentions and not negated,
                               "opening_negated": mentions and negated})
            elif kind == "endif":
                if chains:
                    chains.pop()
            elif chains:
                chain = chains[-1]
                if kind == "elif":
                    chain["relevant"] = chain["relevant"] or mentions
                    chain["arm_is_asan"] = mentions and not negated
                else:
                    # #else is the ASan-ON side exactly when the opening condition excluded ASan.
                    chain["arm_is_asan"] = chain["opening_negated"]
            continue
        if not LIBC_BLOCK_MEMORY_CALL.search(line):
            continue
        if not any(chain["relevant"] for chain in chains) or any(chain["arm_is_asan"] for chain in chains):
            offenders.append(number)
    return offenders


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
        # The root-level umbrella include/DetourModKit.hpp is a public header too -- the FIRST one most consumers include
        # -- but it lives one directory above include/DetourModKit/ (the Boost.Asio umbrella-beside-the-parts shape), so a
        # bare startswith("include/DetourModKit/") prefix test misses it and would exempt it from the public-surface
        # backend-confinement rule and the private-engine-include check below. Match it explicitly so a regression that
        # made the umbrella pull in the SafetyHook backend, <psapi.h>, Zydis/Zycore, or a src/internal/ header fails the
        # gate exactly as it would for any header under include/DetourModKit/.
        is_public_header = rel.endswith(".hpp") and (
            rel.startswith("include/DetourModKit/") or rel == "include/DetourModKit.hpp"
        )

        # Rule 1: backend confinement on the public surface.
        if is_public_header:
            for n, line in enumerate(lines, 1):
                if SAFETYHOOK_INCLUDE.search(line):
                    violations.append(f"{rel}:{n}: public header includes the SafetyHook backend")
                if SAFETYHOOK_NS.search(line):
                    violations.append(f"{rel}:{n}: public header names safetyhook:: (backend leak)")
                if PSAPI_INCLUDE.search(line):
                    violations.append(f"{rel}:{n}: public header includes <psapi.h>")
                if ZYDIS_REF.search(line):
                    violations.append(f"{rel}:{n}: public header references Zydis/Zycore")
                if WINDOWS_INCLUDE.search(line):
                    violations.append(f"{rel}:{n}: public header includes <windows.h> (macro soup must not ship)")
                if UNPARENTHESIZED_LIMITS.search(line):
                    violations.append(
                        f"{rel}:{n}: public header calls std::numeric_limits min/max unparenthesized; "
                        "spell it (std::numeric_limits<T>::max)() so windows.h's macros cannot break consumers")

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

        # Rule 3b: StringPool is placement-constructed into static storage and deliberately never destroyed. Its
        # canonical deleted destructor makes destruction ill-formed; any other spelling would reopen teardown code.
        for number, message in string_pool_destructor_violations(rel, raw):
            violations.append(f"{rel}:{number}: {message}")

        # Rule 4: the AOB scanner's foreign-read TUs reach libc's block-memory routines only from an
        # __SANITIZE_ADDRESS__ branch that supplies a non-interceptable arm (see SCANNER_FOREIGN_READ_SOURCES).
        if rel in SCANNER_FOREIGN_READ_SOURCES:
            for number in unguarded_libc_memory_calls(text):
                violations.append(
                    f"{rel}:{number}: libc block-memory call on the scanner's foreign-read path outside an "
                    "__SANITIZE_ADDRESS__ branch; ASan's interceptor bypasses no_sanitize_address and reports a "
                    "false overflow on swept memory (use __movsb, as src/internal/memory_guarded.cpp does)")

        # v4 scan gate C: no public header reaches into the non-installed private engine under src/internal/.
        if is_public_header:
            for n, line in enumerate(lines, 1):
                if INTERNAL_INCLUDE.search(line):
                    violations.append(f"{rel}:{n}: public header includes the private engine (src/internal/)")

        # Rule 4: installed definitions stay token-stable under private test macros (every file under include/ is
        # installed, the C ABI headers included).
        if rel.startswith("include/"):
            for number, macro in installed_test_macro_violations(text):
                violations.append(
                    f"{rel}:{number}: installed header names the private test macro {macro}. Installed definitions "
                    "must be token-identical with the macro on and off (route test access through an internal friend "
                    "accessor)")

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
                    f"{rel}:{n}: legacy lifecycle symbol '{fm.group(1).strip()}' (replaced by the v4 Session/DetourModKit.hpp surface)")

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
