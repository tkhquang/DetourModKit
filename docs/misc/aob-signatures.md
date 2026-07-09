# AOB Signature Scanning Guide

Practical reference for building, maintaining, and resolving array-of-bytes (AOB) signatures with DetourModKit's `scan` module. Written for humans first, but structured so LLM tools can pick specific sections cleanly.

## Contents

1. [Background: what an AOB is and why](#1-background-what-an-aob-is-and-why)
2. [How to find a patch-proof signature](#2-how-to-find-a-patch-proof-signature)
3. [DMK pattern syntax reference](#3-dmk-pattern-syntax-reference)
4. [Scan API tour](#4-scan-api-tour)
5. [RIP-relative resolution](#5-rip-relative-resolution)
6. [Cascading candidates](#6-cascading-candidates)
    - 6.1 [Motivation](#61-motivation)
    - 6.2 [API shape](#62-api-shape)
    - 6.3 [Basic usage](#63-basic-usage)
    - 6.4 [Prologue fallback variant](#64-prologue-fallback-variant)
    - 6.5 [Name and string resilience tiers](#65-name-and-string-resilience-tiers)
    - 6.6 [Ordering and logging](#66-ordering-and-logging)
    - 6.7 [Host-module convenience overloads](#67-host-module-convenience-overloads)
    - 6.8 [Reading a code constant (read_code_constant)](#68-reading-a-code-constant-read_code_constant)
7. [Patch-proof patterns (cache, fallback, verify)](#7-patch-proof-patterns-cache-fallback-verify)
8. [Worked examples](#8-worked-examples)
9. [DOs and DON'Ts](#9-dos-and-donts)
10. [Troubleshooting](#10-troubleshooting)
11. [Further reading](#11-further-reading)

---

## 1. Background: what an AOB is and why

An **AOB** (array of bytes, also called a **signature** or **sigscan**) is a short byte sequence picked from the `.text` section of a target binary that uniquely identifies an assembly instruction (or small run of instructions) at runtime. Tools like DMK's `Scanner` walk memory looking for that sequence and return the matching address.

Why it matters for modding:

- Module bases change every process launch on Windows (ASLR) and absolute offsets change with every compiler build. A hard-coded RVA fails the next patch day.
- Signatures bind to the **instruction semantics**, not to the binary layout. Good signatures survive many patches; great ones survive entire major version bumps.
- Once an AOB locates the instruction, DMK's hook manager or a `Result<Address>` RIP resolver turns it into an absolute address you can hook, read, or call.

Two rules set the ceiling on signature quality:

- **Sign CODE, not DATA.** Assembly instructions move when code recompiles, but compilers reshuffle *order* much more often than they change *opcodes* for the same source line. Data tables (strings, vtables, constants) move even more aggressively and are a poor anchor.
- **Wildcard anything the compiler or linker can move.** Immediate values, RIP-relative displacements, jump targets, RVAs, vtable offsets, register indices inside VEX prefixes: all of these are the normal suspects.

## 2. How to find a patch-proof signature

A patch-proof signature is short, unique, and contains only bytes that describe **opcodes and register encodings**, with wildcards covering everything the linker or compiler is free to renumber.

### 2.1 Workflow in IDA / Ghidra / x64dbg

1. **Locate the instruction you want to hook.** Prefer a load/store whose target is the value you care about, or the first instruction of a function whose prologue is distinctive.
2. **Copy the raw bytes** of 12 to 32 bytes around it (enough to span 3 to 6 instructions).
3. **Wildcard volatile operands.** For each instruction in the window:
   - Wildcard all immediate operands (8-, 16-, 32-, 64-bit) and RIP-relative displacements (`disp32`) with `??` tokens covering each byte.
   - Replace RVAs and jmp/call targets with `??`s.
   - Keep opcodes, ModRM bytes, REX prefixes, register selectors.
4. **Shrink.** Start with the minimum that returns a single hit in the target module and grow one instruction at a time if duplicates appear.
5. **Validate against at least three game versions or builds**, ideally including one version you know was compiled differently. Signatures that only survive one build are brittle by construction.

> Platform scope: this guide assumes Windows x64 (module base resolution via the PE loader, RIP-relative `disp32` encoding, and the `PAGE_EXECUTE_*` protection flags enforced by `VirtualQuery`). On 32-bit x86 the displacement forms, prefix tables, and ABI details differ; on non-Windows targets the page-protection taxonomy and module enumeration APIs are entirely different. The Scanner API itself is pure C++23 and may work elsewhere, but the worked examples below have only been exercised on Windows x64.

### 2.2 Byte-by-byte anatomy of a good signature

Given the instruction

```text
; 7 bytes total
48 8B 05 ?? ?? ?? ??       mov rax, [rip + <player_ctx_rva>]
```

`48` is the REX.W prefix (64-bit operand), `8B` is `MOV r64, r/m64`, `05` is the ModRM byte encoding `rax, [rip + disp32]`, and the next four bytes are a `disp32` that the linker recomputes every build. Wildcarding just those four bytes gives you a 7-byte signature that works across almost every rebuild unless someone changes the target register or replaces the instruction.

If you need higher uniqueness, chain one or two adjacent instructions:

```text
48 8B 05 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ??
; mov rax, [rip+disp32]
; test rax, rax
; je   rel32
```

That chain is distinctive without committing to any of the shifting fields.

### 2.3 Anchoring rules of thumb

| Situation | What to do |
| --------- | ---------- |
| Signature returns multiple hits | Add bytes forward or backward, or add a unique neighbouring instruction; don't just make it longer with more wildcards |
| Signature uses a static address | Wildcard the disp32/imm and widen with a neighbour; never bake an address into the signature body |
| Only one copy in the file but spans padding | Watch for `CC`/`90` alignment bytes: linkers rebalance padding, so don't cross those boundaries |
| Function inlined differently between builds | Move the anchor to the callee, or pick a caller whose prologue is still unique |
| Anti-tamper or packer rewrites bytes | Use `scan::scan` with `Region::whole_process()` and `Pages::Executable` (searches anonymous executable pages) and plan on a multi-candidate fallback |

## 3. DMK pattern syntax reference

Parsed by `scan::Pattern::compile(std::string_view)` ([include/DetourModKit/scan.hpp](../../include/DetourModKit/scan.hpp)). Tokens are split on whitespace (space, tab, `\r`, `\n`, `\f`, `\v`). Leading or trailing whitespace is ignored.

| Token | Meaning |
| ----- | ------- |
| `48`, `8B`, `FF` | Literal byte. Must be exactly two hex digits. Case-insensitive. |
| `??` | Wildcard byte: any value matches at this position. |
| `?` | Same as `??`. Accepted for brevity. |
| `4?`, `?A` | Per-nibble wildcard. One hex digit paired with `?`: `4?` matches any byte whose high nibble is 4 (low nibble wildcarded); `?A` matches any byte whose low nibble is A (high nibble wildcarded). Useful for a ModRM byte where only the reg or r/m field is fixed, or any operand where a single nibble is invariant across builds. |
| `[X-Y]`, `[X]` | Bounded jump: skip a run of bytes between two fixed segments. `[2-5]` matches any 2-to-5-byte gap; `[3]` is the exact-count shorthand for `[3-3]`. Unlike a fixed run of `??`, a bounded jump tolerates a gap whose *size* shifts between builds (an intervening instruction whose encoding grows or shrinks). A jump may not lead or trail the pattern and two jumps may not be adjacent (there is always at least one fixed byte between gaps), so the pattern always splits into non-empty fixed segments. The gap span is bounded (`MAX_JUMP_SPAN`); YARA's unbounded `[X-]` form is intentionally not accepted. |
| `\|` | Offset marker: records the byte position of the next token as the "point of interest", or the position one past the last byte (`offset == size()`) if placed at the very end of the pattern. Accessible via `Pattern::offset()`. Cannot appear more than once. With a bounded jump before the marker, `scan` adds the actual gap bytes at match time so the resolved address still points at the intended run. |

`scan::Pattern::compile` returns `Result<Pattern>` (an `std::expected<Pattern, Error>`) -- a `BadPattern` error on any malformed token (e.g. `"GG"`, `"1FF"`, three-character tokens, a second `|`, or a bad / mis-placed jump such as `"[5-2]"`, `"[2-]"`, a leading / trailing / adjacent jump, or more than `MAX_PATTERN_JUMPS` gaps). Empty or whitespace-only input is treated as a parse failure. The compile-time variant `scan::Pattern::literal(dsl)` is `consteval`: a malformed literal is a build error rather than a runtime failure.

The scan prefilter anchors on a single fully-known byte (`memchr` cannot search for a partial nibble), so a per-nibble token is never chosen as the anchor: give a nibble-heavy pattern at least one full literal byte for fast scanning. A pattern made entirely of nibble tokens still resolves correctly, but falls back to a masked compare at every position (no prefilter) and is correspondingly slower. With a bounded jump, the anchor is chosen from the first fixed segment (the run before the first `[...]`): the scanner locates that segment, then extends across the gaps, so give the leading segment a distinctive literal byte.

Example with an offset marker:

```text
"48 8B 88 B8 00 00 00 | 48 89 4C 24 68"
```

The `|` sits after seven literal bytes, so `Pattern::offset() == 7`. This lets you anchor on a wide distinctive window while hooking the second instruction in the chain.

Example with a bounded jump:

```text
"48 8B 05 ?? ?? ?? ?? [2-6] E8 ?? ?? ?? ??"
```

The two known instructions (`mov rax, [rip+disp32]` and a `call rel32`) are separated by a 2-to-6-byte gap that absorbs an intervening instruction whose length varies between builds. The 12 fixed bytes (7 in the first segment, 5 in the second) frame the gap, so `Pattern::segment_count()` is 2 here and `Pattern::min_match_length()` / `max_match_length()` report the 14-to-18-byte span a match can occupy.

## 4. Scan API tour

Public namespace: `DetourModKit::scan`. Errors are returned as `Result<T>` (`std::expected<T, Error>`), never thrown.

### 4.1 Compile once, scan many

`scan::Pattern::compile()` parses the AOB DSL string and returns a `Result<Pattern>`. Compile at startup and reuse the value; compilation is cheap but not free.

```cpp
#include <DetourModKit/scan.hpp>

namespace dmk = DetourModKit;
namespace sc = DMK::scan;

const auto pattern_result = sc::Pattern::compile("48 8B 05 ?? ?? ?? ?? 48 85 C0");
if (!pattern_result)
{
    // malformed string; check pattern_result.error().message() for the reason
    return false;
}
const sc::Pattern& pattern = *pattern_result;
```

For a compile-time literal, use `sc::Pattern::literal(dsl)` -- it is `consteval`, so a malformed DSL is a build error:

```cpp
static constexpr sc::Pattern k_pattern = sc::Pattern::literal("48 8B 05 ?? ?? ?? ??");
```

### 4.2 Scanning a module range

Use `scan::scan(pattern, scope, occurrence, pages)` with a `Region` scope. `Region::module_named(L"game.exe")` limits the sweep to a single module image.

```cpp
const auto scope = DMK::Region::module_named(L"game.exe");
const auto match = sc::scan(pattern, scope, 1, sc::Pages::Executable);
if (!match)
{
    return false;
}
// match->value() is the Address of the `|`-marked byte (or the pattern start
// when no `|` marker is present). scan() applies Pattern::offset() internally;
// do NOT add it yourself.
const DMK::Address target = *match;
```

### 4.3 Nth occurrence

Pass the occurrence argument (1-based):

```cpp
const auto third = sc::scan(pattern, scope, 3, sc::Pages::Executable);
```

Passing `0` yields `ErrorCode::NoMatch` by contract.

### 4.4 Process-wide scan

When the target binary is packed, decrypted into anonymous executable pages, or you don't know which module owns the code yet, use `Region::whole_process()` as the scope with `Pages::Executable`. It walks `VirtualQuery` and scans every committed `PAGE_EXECUTE_READ*` region that isn't a guard page.

```cpp
const auto match = sc::scan(pattern, DMK::Region::whole_process(), 1, sc::Pages::Executable);
```

Pure-execute pages (`PAGE_EXECUTE` with no read bit) are skipped deliberately: such pages are not guaranteed readable. Only `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, and `PAGE_EXECUTE_WRITECOPY` regions are inspected; guard and no-access pages are skipped unconditionally.

The `scan::unchecked::find_pattern(region, pattern, occurrence)` twin performs no page filtering and uses raw SIMD loads -- use it only when you can guarantee every byte in `region` is committed and readable.

> Do not scan on the render thread. A full-module sweep can run into the tens of milliseconds; a process-wide walk can exceed an entire frame budget on a large game. Resolve signatures at startup, during a loading screen, or on a background worker, and cache the resulting addresses.

### 4.5 SIMD tier

```cpp
switch (sc::active_simd_level())
{
case sc::SimdLevel::Avx2:   /* 32 bytes per iteration */ break;
case sc::SimdLevel::Sse2:   /* 16 bytes per iteration */ break;
case sc::SimdLevel::Scalar: /* byte-by-byte fallback */  break;
}
```

Useful for logging and for deciding whether a large scan should run during boot or be deferred.

### 4.6 Anchor heuristic and why sparse bytes scan faster

Internally the scan engine does NOT scan byte-by-byte from the start of the pattern. It inspects every non-wildcard byte in the pattern, scores each against a small frequency table (`0x00`, `0xCC`, `0x90`, `0xFF`, `0x48`, `0x8B`, `0x0F`, ... in rough order of "how often this byte appears in typical x64 `.text`"), and picks the rarest one as the anchor. The anchor byte drives a `memchr` sweep; the full pattern is only verified at positions where `memchr` finds the anchor.

Implication: a pattern whose literal bytes are all REX prefixes / common opcodes (`48 8B`, `48 89`, `FF 15`, `E8 ?? ?? ?? ??`) forces the scanner to verify at almost every address. Add at least one uncommon byte (any byte outside the frequency table) and the scan typically drops from tens of milliseconds to sub-millisecond on a full-module sweep. If you have a choice between two otherwise equivalent anchors, pick the one containing a rarer byte.

### 4.7 Scanning data sections

`Pages::Executable` filters to execute-readable pages, so it cannot reach `.rdata` / `.data`. When the thing you need to locate is data rather than code, use `Pages::Readable` (the default). It accepts every committed readable region (`PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_WRITECOPY`, and the three execute-readable variants), so it reaches C++ vtables, RTTI type descriptors, localized string pools, and read-only metadata tables.

```cpp
const auto match = sc::scan(pattern, DMK::Region::whole_process(), 1, sc::Pages::Readable);
```

It applies `Pattern::offset()` exactly once, identically to `Pages::Executable`. The accepted set is a strict superset: a pattern present in `.text` is found by both. Guard pages (`PAGE_GUARD`), no-access pages (`PAGE_NOACCESS`), and uncommitted regions are skipped and never dereferenced.

Two costs come with the wider reach:

- **More bytes inspected.** A typical x64 game maps hundreds of MB of data versus tens of MB of code, so a readable sweep can run several times longer than an executable one. Resolve at startup or on a worker, never on the render thread, and cache the result.
- **Higher collision risk.** `.rdata` pointer tables and constant pools look random, so a pattern that is unique in `.text` may collide in data. Supply at least 8 literal bytes and confirm the hit (occurrence count, or a follow-up structural check).

#### Prefer an RTTI name anchor over a raw vtable header

The obvious data signature for a class is its vtable header: the RTTI Complete Object Locator pointer followed by the first few virtual-function pointers. The trap is that every one of those qwords is an *absolute, relocated* pointer: `value = image_base + RVA`. On x64 the image base is at least 64 KiB aligned, so only the low 2 bytes of each pointer are invariant across launches; the higher bytes move with the ASLR slide. A "24-byte vtable header" therefore yields only about 6 reliably stable literal bytes unless the module happens to load at its preferred base, which inflates the collision risk above.

The robust anchor is the RTTI **type-descriptor name** string itself, for example the mangled `.?AVClassName@ns@@`. It is plain ASCII baked into the binary, fully ASLR-invariant, and tens of literal bytes long, so it effectively never collides. The flow is:

1. Use `scan::scan` with `Pages::Readable` to search for the mangled name string and find the `TypeDescriptor`.
2. Walk the MSVC RTTI structures from the descriptor to the vtable (see [rtti-walker.md](../guides/rtti/rtti-walker.md), which documents the COL / TypeDescriptor / self-RVA layout the `rtti` module already encodes).

This pairs with the `rtti` walker's opposite direction (vtable to name): one finds a vtable from a known name, the other recovers a name from a known vtable.

#### Using the readable scanner inside a cascade

Set `ScanRequest::scope` to `Region::module_named(L"game.exe")` (or `Region::host()`) and leave `pages` at its default (`Pages::Readable`) to resolve a candidate whose signature lives in a data section. `Candidate::direct` with `walk_back = 0` returns the match address directly, which is exactly the data address for a data-section scan.

A non-`Off` `fallback_policy` is intentionally a code-path concern: its recovery path rebuilds a hooked near-JMP prologue, which is meaningless for a data match.

#### Module-scoped scan (single unpacked PE)

When every hook target lives inside one unpacked module (a normal game DLL/EXE), set `ScanRequest::scope` to `Region::module_named(L"game.exe")`. The resolver rejects any candidate whose resolved address falls outside that region, so a generic-shaped candidate (a stock compiler prologue, a `mov reg,[rip]; ...; ret` epilogue) that also appears in another injected module (a graphics overlay, a sibling mod) cannot shadow the correct in-module match. Because the resolver is first-match-wins, that bounds check lives inside the loop.

```cpp
const sc::ScanRequest req{
    .ladder = k_candidates,
    .label = "frustum",
    .scope = DetourModKit::Region::module_named(L"game.exe"),
};
const auto hit = sc::resolve(req);
```

One scope covers both `.text` and `.rdata` / `.data` candidates via the `Pages::Readable` default. `ErrorCode::NoMatch` is returned when no candidate resolves; the resolver never falls back to a whole-process scan (which would re-introduce the cross-module shadowing the scoped request exists to prevent). With a non-`Off` `fallback_policy`, the rewritten near-JMP must be found inside the scope, but its jump destination may still point at a sibling mod's trampoline outside the module.

For a hook target -- a signature that must land on an instruction, not data -- prefer `scan::borrow_code_target(ladder, label, scope)` over a hand-built request. It presets the code-target policy in one place: `Pages::Executable` (so an instruction signature cannot alias an identical byte run in `.rdata` / `.data`), `CandidateOrder::UniqueFirst`, and a `WarnOnly` fallback policy (pass `RequireIdentity` plus a `fallback_witness` to fail closed on a recovered near-twin), with `require_unique` kept true. `Pages::Executable` narrows only the byte tiers; a mixed ladder's RTTI and string-xref tiers still resolve through their own backends. Keep the default `Pages::Readable` (or `borrow()`) for a data / RTTI / string target.

```cpp
const auto hit = sc::resolve(
    sc::borrow_code_target(k_candidates, "frustum", DetourModKit::Region::module_named(L"game.exe")));
```

> Use a named-module scope only for a single contiguous mapped image. For packed or protected targets whose code is unpacked into separate `VirtualAlloc` regions, use `Region::whole_process()` with `Pages::Executable`.

#### Requiring a unique match (`require_unique`)

A resolver returns the first candidate that resolves uniquely, and a single scan returns the lowest-address match. A loose pattern that matches several functions therefore wins on whichever address sorts first -- usually not the intended one, and impossible to recover from after the fact (the resolver has already committed). Scoping the scan to a module removes *cross-module* collisions, but two functions inside the same module can still share a generic prologue: that is an authoring problem (write a more specific signature), not something the scan scope can fix.

By default (`ScanRequest::require_unique = true`) the resolver verifies a candidate matches exactly once in the scoped region. If a second match exists the candidate is ambiguous and the resolver falls through to the next one, turning a silent wrong hit into a clean fall-through -- and, when no candidate is provably unique, an error the caller can surface as "the binary changed, update the signatures" rather than a confidently wrong hook.

Set `require_unique = false` only for a candidate you have deliberately made non-unique and separately verified -- for example a last-resort broad net whose first in-scope match you confirm with your own post-resolution check. It is an eyes-open escape hatch for an author who takes responsibility for the ambiguity, not a way to tolerate a loose signature: prefer tightening the pattern so it is unique. The flag is per-request, so build an `OwnedScanRequest` or a per-entry request if you need different policies per candidate:

```cpp
const std::array<sc::Candidate, 3> k_frustum{{
    // Unique mid-body anchor. If a build update makes it match twice, fall through.
    sc::Candidate::rip_relative("Frustum_P1_MatrixGlobalRef",
        sc::Pattern::literal("48 8B 05 ?? ?? ?? ?? 0F 28 00 | 0F 29 41 10"),
        /*displacement_at=*/3, /*instruction_length=*/7),
    // 16-byte prologue+mid-body run, also expected singular.
    sc::Candidate::direct("Frustum_P2_PrologueMatrixRead",
        sc::Pattern::literal("40 53 48 83 EC 20 48 8B D9 0F 10 02 0F 11 41 10")),
    // Broad safety net: resolve with require_unique = false in a separate request.
    sc::Candidate::direct("Frustum_P3_GenericPrologueFirst",
        sc::Pattern::literal("40 53 48 83 EC 20")),
}};
// Prefer trying the strict candidates first; fall back to non-unique only on failure.
```

> Behavior note: the default is uniqueness-required. A signature that matches more than once is almost always one that needs tightening, not a target to guess at, so the default surfaces the ambiguity as a `ErrorCode::NoMatch` you can act on rather than hooking an arbitrary match. Only set `require_unique = false` on a candidate you have intentionally made non-unique and verified yourself.

### 4.8 Batch scanning many signatures in parallel (`scan::scan` + `resolve_batch`)

When a mod resolves dozens of signatures at startup, use `scan::resolve_batch` to run them concurrently through an opt-in fork-join worker pool, so the wall-clock cost is roughly the slowest single resolve rather than the sum.

```cpp
namespace sc = DetourModKit::scan;

// Build an OwnedScanRequest per target so the ladder outlives the call.
std::vector<sc::OwnedScanRequest> owned;
owned.push_back(sc::OwnedScanRequest{
    .ladder = {sc::Candidate::direct("player_update_v1",
                   sc::Pattern::literal("48 89 5C 24 ?? 57 48 83 EC 30")),
               sc::Candidate::direct("player_update_v2",
                   sc::Pattern::literal("40 53 48 83 EC 20 48 8B D9"))},
    .label = "player_update",
});
owned.push_back(sc::OwnedScanRequest{
    .ladder = {sc::Candidate::direct("camera_update_v1",
                   sc::Pattern::literal("48 89 6C 24 ?? 56 57 41 54"))},
    .label = "camera_update",
    .fallback_policy = sc::FallbackPolicy::WarnOnly,
});

// Build borrowed views for the call (views alias the owned storage above).
std::vector<sc::ScanRequest> views;
for (const auto& o : owned) views.push_back(o.view());

// The outer Result is the whole-batch signal; unwrap it before indexing the per-request inner vector.
const auto batch = sc::resolve_batch(views, /*max_workers=*/4);
if (!batch) { /* whole-batch OOM: batch.error().code == ErrorCode::OutOfMemory */ return; }
const auto& results = *batch;
// Index the inner vector (do not range-for over it: a bare std::expected element trips a
// GCC libstdc++ <expected> equality-constraint recursion; indexed access sidesteps it).
for (std::size_t i = 0; i < results.size(); ++i) { /* results[i] is the Result<Hit> for views[i] */ }
```

Key properties:

- **Whole-batch signal.** The outer `Result` fails with `Error{OutOfMemory}` only when the per-request result container itself cannot be allocated, so a caller cannot silently proceed on a truncated batch (the same shape as `hook::install_all`).
- **Input-order results.** Inside the unwrapped vector, `(*batch)[i]` always corresponds to `views[i]`, regardless of which worker finished first.
- **Per-request fail-closed.** A failure in one request never poisons the rest; `(*batch)[i].error()` carries the `Error` for that slot.
- **Read-only sharing, no cloning.** `Pattern` is value-semantic and immutable; workers share the caller's compiled patterns directly with no re-derive.
- **Worker count.** `0` (the default) uses `std::thread::hardware_concurrency()` clamped to the request count; the calling thread participates. A single-item batch runs inline with no thread spawn.

> Setup/control-plane only. `resolve_batch` is noexcept by contract but spawns a worker pool internally; call it at startup or on a background worker, never from a hook or input callback and never under the loader lock.

## 5. RIP-relative resolution

x86-64 code uses RIP-relative addressing heavily. The 4-byte displacement stored inside the instruction is relative to the address of the *next* instruction: `target = instruction_address + instruction_length + disp32`. DMK exposes two helpers and a set of prefix constants.

### 5.1 Two-step: find the match, then resolve

Best when the instruction is part of a wider signature, or when the disp32 is not at the end (e.g. the instruction has an immediate suffix).

```cpp
const auto scan_result = sc::scan(pattern, scope, 1, sc::Pages::Executable);
if (!scan_result)
    return false;

const DMK::Address hit = *scan_result;
// Suppose the matched instruction is `mov rax, [rip+disp32]` (7 bytes, disp32 at offset 3).
const auto resolved = sc::resolve_rip_relative(hit, /*displacement_offset=*/3, /*instruction_length=*/7);
if (!resolved)
{
    DMK::log().error(
        "RIP resolve failed: {}",
        DMK::to_string(resolved.error().code));
    return false;
}

const DMK::Address absolute = *resolved;
```

Error values (all unified under `ErrorCode`):

| ErrorCode | Meaning |
| --------- | ------- |
| `NoMatch` | (find-and-resolve) no prefix match in the search region |
| `UnreadableDisplacement` | disp32 bytes could not be read under the SEH fault guard |
| `ImplausibleTarget` | the resolved address is not a plausible user-mode pointer (a corrupt displacement that resolves to 0, a low guard-page address, or a kernel-range value) |

### 5.2 One-step: find the prefix and resolve in the same call

Best when the opcode you want to hook has its disp32 **immediately after the prefix you supply** (e.g. `E8 disp32`, `E9 disp32`, `48 8B 05 disp32`). DMK ships ready-made prefix constants in `scan.hpp` under the `scan::` namespace:

| Constant | Bytes | Encodes |
| -------- | ----- | ------- |
| `PREFIX_CALL_REL32` | `E8` | `call rel32` |
| `PREFIX_JMP_REL32` | `E9` | `jmp rel32` |
| `PREFIX_MOV_RAX_RIP` | `48 8B 05` | `mov rax, [rip+disp32]` |
| `PREFIX_MOV_RCX_RIP` | `48 8B 0D` | `mov rcx, [rip+disp32]` |
| `PREFIX_MOV_RDX_RIP` | `48 8B 15` | `mov rdx, [rip+disp32]` |
| `PREFIX_MOV_RBX_RIP` | `48 8B 1D` | `mov rbx, [rip+disp32]` |
| `PREFIX_LEA_RAX_RIP` | `48 8D 05` | `lea rax, [rip+disp32]` |
| `PREFIX_LEA_RCX_RIP` | `48 8D 0D` | `lea rcx, [rip+disp32]` |
| `PREFIX_LEA_RDX_RIP` | `48 8D 15` | `lea rdx, [rip+disp32]` |

Example:

```cpp
// search is a Region covering the short window to scan.
const auto resolved = sc::find_and_resolve_rip_relative(
    DMK::Region{hit, 64},      // short search window from the match
    sc::PREFIX_CALL_REL32,            // E8
    /*instruction_length=*/5);        // E8 + disp32
```

`find_and_resolve_rip_relative` is **first-prefix-wins**: it resolves the first location whose bytes match `opcode_prefix` and does not check whether the prefix occurs again within the window. Its prefix search reads `search` directly with no page filtering, so the caller must guarantee that region is committed and readable (use it over a region already known readable, such as a located function body); to resolve a single instruction whose address is uncertain, prefer `resolve_rip_relative`, whose displacement read is fault-guarded. When a signature may be ambiguous, anchor it through `resolve()` (the candidate ladder, which enforces per-candidate uniqueness) instead of widening the search window. The resolved target is gated by the same `ImplausibleTarget` check as `resolve_rip_relative`.

### 5.3 What these helpers will not resolve

`resolve_rip_relative` deliberately understands only the 32-bit signed displacement form. The following need manual handling:

- Short jumps (`EB rel8`, `Jcc rel8`) with 8-bit displacements.
- 16-bit displacements and legacy `EA ptr16:32` far jumps.
- Indirect calls through memory: `FF 15 disp32` and `FF 25 disp32`. The disp32 points to a **pointer**; DMK returns the pointer's address, not the final target. Dereference it yourself.
- Instructions where the disp32 is interrupted by a SIB byte combination or a VEX/EVEX prefix boundary: supply your own longer `opcode_prefix` that covers up to the disp32 start.

### 5.4 String-reference anchors

When the most stable thing about a target is the text it uses, anchor on the string instead of the code. `find_string_xref` is a two-phase, fail-closed resolve scoped to one module image:

1. Locate the literal in the image's readable pages (`.rdata` / `.data`). The linker pools identical strings, so a second occurrence is treated as ambiguous and the resolve fails closed (`StringAmbiguous`).
2. Scan the image's execute-readable pages for the single RIP-relative reference whose resolved absolute target is that string, and return it. Zero references is `NoReference`; more than one is `AmbiguousReference`.

Both phases also fail closed on incompleteness. If a page-gated window faults mid-scan under the TOCTOU guard (a concurrent decommit or reprotect skips it), the occurrence count becomes a lower bound, so a would-be-unique result is reported as `StringAmbiguous` (phase 1) or `AmbiguousReference` (phase 2) rather than a possibly-non-unique anchor. A hidden duplicate string or a second reference behind a faulted page is never returned as the unique result.

```cpp
namespace sc = DetourModKit::scan;

sc::StringRefQuery query{
    .text = "Assertion failed: m_world != nullptr",  // a long, specific, once-used literal
    .encoding = sc::StringEncoding::Utf8,             // Utf16le for L"" / wchar_t literals
    .require_terminator = true,                       // do not match a prefix of a longer string
    .return_mode = sc::XrefReturn::ReferencingInstruction,
    .broad_match = false,                             // true keeps lea/mov scan and adds cmp/push/no-REX
};

const auto site = sc::find_string_xref(query); // defaults to Region::host()
if (!site)
{
    DMK::log().error("string xref failed: {}",
                     DMK::to_string(site.error().code));
    return false;
}
// site->value() is the address of the `lea`/`mov` that loads the string. With
// XrefReturn::EnclosingFunction it is instead the entry of the function that uses
// it (authoritative .pdata bounds, with a heuristic back-scan fallback). With
// XrefReturn::StringPointerSlot it is the global data slot that caches the loaded
// pointer (see below).
```

Why anchor on a string: a game patch reshuffles code bytes (breaking AOBs) and reorders globals, but a format string or assert message almost never changes. The reference is RIP-relative and resolved against the live image, so the result is ASLR-correct with no fixed address baked in.

Recognized forms. Phase 2 has two modes, both gated by the same exact-target and single-reference uniqueness guards:

- Default (`broad_match = false`): a shape scan for the dominant 64-bit string loads, `REX.W lea`/`mov reg, [rip+disp32]` (opcodes `8D` / `8B` with a RIP-relative ModRM). These instructions are self-delimiting from their byte shape, so the scan needs no instruction alignment and cannot desync on data or jump tables embedded in `.text`. This is the fast, robust default.
- `broad_match = true`: keeps the default all-offset shape scan, then adds a Zydis-verified linear sweep that decodes the instruction stream and matches any RIP-relative memory operand resolving to the string. This additionally catches the rarer shapes the shape scan does not model -- `cmp [rip+d], imm`, `push [rip+d]`, a 32-bit (no-REX) `lea`/`mov`, and similar. The sweep restarts at the next byte on a decode failure to realign past embedded data, and any hit already found by the default scan is counted only once. Prefer broad mode only when the default reports `NoReference` for a target you know is referenced, since it does extra decode work.

A shape the active mode does not model reports an error rather than a guess. One shape is out of scope for both modes: an indirect `call`/`jmp` through a `.data` pointer that itself holds the string address (a two-level indirection rather than a direct RIP reference to the string). Choose a string that is referenced exactly once; short, common strings are pooled and shared. This backend is also exposed declaratively as `AnchorKind::StringXref` in the [anchor registry](../guides/scanning/anchors.md).

Return modes. `XrefReturn::ReferencingInstruction` (default) returns the load site; `XrefReturn::EnclosingFunction` resolves the entry of the function that uses it -- the x64 `.pdata` exception table via `RtlLookupFunctionEntry`, following `UNW_FLAG_CHAININFO` chains to the primary function so a hot/cold-split fragment resolves to the true function, with a bounded RET/INT3 prologue back-scan as the fallback for leaf functions or code with no registered exception table. `XrefReturn::StringPointerSlot` is for the common pattern where a game caches the loaded string pointer into a global: when the unique reference is a `lea reg, [rip+string]` immediately (within a bounded forward window) followed by a `mov [rip+slot], reg` that stores the same register into a global slot, it returns the effective address of that slot rather than the load site. This resolves a cached global string pointer in one call. It applies only to the `lea` shape (a `mov reg, [rip+string]` load already delivered the value to a register); a register mismatch, an out-of-window store, a broad-only reference, or no matching store reports `ErrorCode::StoreNotFound`. The store match is first-within-window (compilers emit the cache next to the load), not uniqueness-checked, and an intervening reuse of the register is not modelled.

## 6. Cascading candidates

### 6.1 Motivation

Game binaries change across patches. A single literal AOB that locked onto a specific opcode window in one build is one compiler flag flip away from matching nothing on the next update. The cascade pattern is the standard defence: register several ordered candidates per target (most-specific first, most-generic last), let the scanner try each until one matches, and record the winner so you know which build of the game is actually running. Every long-lived modding community reinvents this eventually; DMK ships it as a first-class API so you do not have to reinvent the logging, the ordering rules, or the prologue-overwrite recovery path.

### 6.2 API shape

Defined in [include/DetourModKit/scan.hpp](../../include/DetourModKit/scan.hpp) inside `namespace DetourModKit::scan`:

```cpp
// Build a Candidate for each tier:
Candidate::direct(name, pattern, walk_back = 0)
Candidate::rip_relative(name, pattern, displacement_at, instruction_length)
Candidate::rtti_vtable(name, mangled)
Candidate::string_xref(name, literal)
Candidate::string_xref(name, StringRefQuery{...})  // explicit facets

// Hooked-prologue recovery strictness, and the identity check it runs on a recovered site:
enum class FallbackPolicy { Off, WarnOnly, RequireIdentity };
using FallbackValidator = bool (*)(std::int64_t recovered_address, const void* context) noexcept;
struct FallbackWitness { FallbackValidator predicate = nullptr; const void* context = nullptr; };

// A resolution request (non-owning) and its owning twin:
struct ScanRequest
{
    std::span<const Candidate> ladder;
    std::string_view label{};
    Region scope = Region::host();
    FallbackPolicy fallback_policy = FallbackPolicy::Off;  // Off = no hooked-prologue recovery
    FallbackWitness fallback_witness{};                    // identity check for RequireIdentity / WarnOnly
    bool require_unique = true;
    CandidateOrder order = CandidateOrder::AsDeclared;
    Pages pages = Pages::Readable;  // byte tiers scan this page class; Executable narrows to code
};

struct OwnedScanRequest  // for stored / deferred resolution
{
    std::vector<Candidate> ladder;
    std::string label;
    Region scope = Region::host();
    FallbackPolicy fallback_policy = FallbackPolicy::Off;
    FallbackWitness fallback_witness{};
    bool require_unique = true;
    CandidateOrder order = CandidateOrder::AsDeclared;
    Pages pages = Pages::Readable;
    ScanRequest view() const noexcept;
};

// build a borrowed request with lifetime-bound diagnostic:
ScanRequest borrow(span<const Candidate> ladder, string_view label = {},
                   Region scope = Region::host(),
                   FallbackPolicy fallback_policy = FallbackPolicy::Off,
                   FallbackWitness fallback_witness = {}, bool require_unique = true,
                   CandidateOrder order = CandidateOrder::AsDeclared,
                   Pages pages = Pages::Readable) noexcept;

// code/hook-target preset: Pages::Executable + UniqueFirst + a WarnOnly fallback by default.
// Pass RequireIdentity + a witness to fail closed on a recovered site the witness cannot confirm.
ScanRequest borrow_code_target(span<const Candidate> ladder, string_view label = {},
                               Region scope = Region::host(),
                               FallbackPolicy fallback_policy = FallbackPolicy::WarnOnly,
                               FallbackWitness fallback_witness = {}) noexcept;

struct Hit
{
    Address address;
    std::string winning_name;
};

// Single resolve: tries candidates in order, returns first that resolves.
[[nodiscard]] Result<Hit> resolve(const ScanRequest& request);

// Fork-join batch; noexcept. The OUTER Result is the whole-batch signal (Error{OutOfMemory} when even the
// result container cannot be allocated); the inner vector holds one Result<Hit> per request, in order.
[[nodiscard]] Result<std::vector<Result<Hit>>>
resolve_batch(std::span<const ScanRequest> requests, std::size_t max_workers = 0) noexcept;
```

`resolve` takes a `ScanRequest` so you can pass a borrowed view (`borrow(...)`) or an `OwnedScanRequest::view()`. Scope the scan to a single module with `Region::module_named(L"game.exe")` or `Region::host()` for the host EXE; `Region::whole_process()` searches all committed pages. `fallback_policy` selects hooked-prologue recovery: `Off` (the default) disables it so a full-ladder miss is a hard miss, `WarnOnly` recovers structurally, and `RequireIdentity` (paired with a `fallback_witness`) additionally fails the recovery closed with `ErrorCode::PrologueIdentityRejected` when the witness cannot confirm the recovered site (see 6.4). `pages` selects which page class the byte tiers scan: `Pages::Readable` (default) covers code and data, `Pages::Executable` narrows to code so a byte signature that must land on an instruction cannot alias an identical run in a data section. `resolve_batch` dispatches each request to the resolver concurrently; unwrap the outer `Result` (a whole-batch OOM failure lands there, mirroring `hook::install_all`), then read one `Result<Hit>` per request from the inner vector in input order. `Hit::winning_name` is an owned `std::string` copied from the winning candidate, so it does not alias caller storage. `Hit::address` is the post-resolution absolute address: for `direct` candidates it equals `match + walk_back`, and for `rip_relative` candidates it is the target of the displacement already resolved, so callers can hook or call it directly. Use `scan::or_null(result)` or `scan::address_or(result, fallback)` to flatten a `Result<Hit>` to an address when error detail is not needed. Errors are unified `ErrorCode` values on `result.error().code`; call `to_string(result.error().code)` for a diagnostic string.

### 6.3 Basic usage

```cpp
#include <DetourModKit/scan.hpp>
#include <DetourModKit/logger.hpp>
#include <array>

namespace sc = DetourModKit::scan;

const std::array<sc::Candidate, 3> k_weapon_fire_candidates{{
    sc::Candidate::direct("weapon_fire_v1_8_2",
        sc::Pattern::literal("48 89 5C 24 ?? 57 48 83 EC 30 48 8B D9 48 8B FA")),
    sc::Candidate::direct("weapon_fire_v1_9_0",
        sc::Pattern::literal("40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 84 C0")),
    sc::Candidate::rip_relative("weapon_fire_callsite",
        sc::Pattern::literal("E8 ?? ?? ?? ?? 48 8B CB 48 8B 43 20"),
        /*displacement_at=*/1, /*instruction_length=*/5),
}};

const sc::ScanRequest req = sc::borrow(k_weapon_fire_candidates, "weapon_fire");
const auto hit = sc::resolve(req);
if (!hit)
{
    DetourModKit::log().error(
        "weapon_fire cascade failed: {}",
        DetourModKit::to_string(hit.error().code));
    return false;
}

DetourModKit::log().info(
    "resolved {} at {:#x}", hit->winning_name, hit->address.raw());
```

### 6.4 Prologue fallback variant

`scan::resolve` is fine when the target function still looks the way your signature remembers it. It stops working as soon as another mod, loaded earlier in the process, inline-hooks the same function: SafetyHook, MinHook, and most hand-rolled detour libraries overwrite the first five bytes with a near-JMP (`E9 ?? ?? ?? ??`) to their trampoline. Your Direct-mode candidate that matches on a prologue byte sequence now sees `E9` instead of `48 89 5C 24 ...`, and the scan misses even though the function itself is still present.

`resolve` with a non-`Off` `ScanRequest::fallback_policy` handles that exact scenario. On the happy path it is identical to a plain `resolve`. If every candidate misses, it walks the list again and, for each `direct`-tier candidate, rebuilds the pattern with the patched prologue tokens replaced by a jump prefix while preserving the literal tail, then scans with the rewritten pattern. Four inline-hook prologue shapes are tried in order: the five-byte `E9 ?? ?? ?? ??` near jump (SafetyHook / MinHook for an in-range trampoline); the six-byte `FF 25 ?? ?? ?? ??` RIP-relative indirect jump a hook emits when its trampoline is beyond rel32 reach with the absolute target in a separate slot the displacement points at (a Detours-style far jump); the 14-byte `FF 25 00 00 00 00 <abs64>` absolute form whose displacement is zero so the 8-byte target is inlined immediately after the instruction; and the 12-byte `mov rax, imm64; jmp rax` (`48 B8 <imm64> FF E0`) absolute jump some libraries emit instead. The shapes are mutually exclusive at a real hook site -- their leading opcode bytes (`E9` vs `FF 25` vs `48 B8`) differ, and a 14-byte overwrite leaves a different surviving tail than a six-byte one -- so the try order only affects which is attempted first, never correctness. Whichever shape uniquely recovers an executable target wins. Two guardrails apply before accepting a hit: the rewritten pattern must resolve to exactly one location in scope (a unique jump into the sibling mod's trampoline, not an arbitrary jump that happens to share a tail shape), and the decoded jump destination must resolve to a committed, execute-readable page. The destination is deliberately *not* required to lie inside a loaded module: SafetyHook trampolines and relay-style detours can live outside every image, so an in-module requirement would reject the precise recovery this path exists for. The recovered address honors the candidate's `|` anchor offset exactly as the direct pass would, so a `|`-anchored direct candidate resolves to the same byte whether it matched directly or through the fallback. `rip_relative` candidates are skipped in the fallback phase since they target instructions deeper than the patched prologue and are unaffected by the overwrite.

Those two guardrails prove a hooked site exists and is unique; they do not prove it is the function you meant. A game reshape can leave a different function whose surviving literal tail happens to match your candidate and which is itself inline-hooked, so the rebuilt pattern resolves uniquely to a near-twin at the wrong address. `fallback_policy` chooses how strictly the recovered site is confirmed. `WarnOnly` (the `borrow_code_target` default) returns the structural recovery and, when a `fallback_witness` is supplied, logs a Warning if the witness disagrees, an observe-before-enforce mode to surface near-twin drift in your logs without changing behavior. `RequireIdentity` runs the witness and fails the recovery closed with `ErrorCode::PrologueIdentityRejected` when it rejects the site (or when no witness was supplied to confirm it), so a caller can distinguish "a hooked near-twin was found but refused" from a plain `NoMatch`. The witness is a `FallbackValidator` (`bool(std::int64_t recovered_address, const void* context) noexcept`, signature-identical to `anchor::AnchorValidator`): corroborate the recovered address against an independently resolved landmark, or read a distinguishing byte past the overwritten prologue, and return false to reject a coincidental twin.

```cpp
// Fail closed unless the recovered site is corroborated against a landmark resolved elsewhere.
static std::uintptr_t g_expected = /* an address resolved by an independent anchor */ 0;
const auto hit = sc::resolve(sc::borrow_code_target(
    k_weapon_fire_candidates, "weapon_fire", DetourModKit::Region::module_named(L"game.exe"),
    sc::FallbackPolicy::RequireIdentity,
    sc::FallbackWitness{
        .predicate = +[](std::int64_t addr, const void* ctx) noexcept
        { return static_cast<std::uintptr_t>(addr) == *static_cast<const std::uintptr_t*>(ctx); },
        .context = &g_expected}));
// hit.error().code == ErrorCode::PrologueIdentityRejected when a near-twin was recovered but not confirmed.
```

```cpp
const sc::ScanRequest req{
    .ladder = k_weapon_fire_candidates,
    .label = "weapon_fire",
    .fallback_policy = sc::FallbackPolicy::WarnOnly,
};
const auto hit = sc::resolve(req);
```

There is one guardrail callers must be aware of. The fallback refuses to scan any candidate whose literal tail after the first five tokens contains fewer than ten literal bytes, and surfaces that refusal as `ErrorCode::PrologueFallbackNotApplicable`. Five bytes still leave the rebuilt pattern shaped like a generic near-JMP plus a short common-instruction tail, which collides with thousands of unrelated `E9` sites in a multi-megabyte `.text` section; ten literal bytes is roughly two to four real instructions of context and reduces the false-positive rate to near zero on real binaries while staying inside the 12 to 20 byte sweet spot documented for fallback signatures. If you see this error, extend the offending candidate's pattern so it carries at least ten literal bytes past the five-byte prologue window.

> **Safety note.** The fallback is a recovery path for the specific case where another inline-hooking mod loaded earlier in the process has already patched the same function's prologue. It is **not** a recovery path for game patches that remove or reshape the target function: a cascade miss followed by a fallback hit on the wrong site can produce a non-zero resolved address that points into an unrelated function, which the consumer will then hook and corrupt. The tightened guardrails (one allowed match, ten literal tail bytes) make this outcome structurally improbable on a well-formed cascade, but they do not eliminate every degenerate signature shape.
>
> If your anchor family covers a function that may have been removed or reshaped by a future patch (rather than just inline-hooked by a sibling), use `scan::resolve` with `fallback_policy = FallbackPolicy::Off` (the default) as the strict variant; it treats a full-ladder miss as a hard `ErrorCode::NoMatch` without engaging the rewritten-prologue path at all. As a defense in depth, ensure at least one `Candidate` in the ladder anchors **past** the SafetyHook 5-byte displacement window (a mid-body literal-byte landmark in the function), which lets the regular resolver match a sibling-patched site without the fallback ever being needed.

### 6.5 Name and string resilience tiers

A byte AOB is the most brittle anchor on the ladder: it breaks the moment the compiler reorders an instruction or the linker shifts a constant. Two stronger signals survive a patch because the *name* or the *literal* does not move even when the surrounding bytes and addresses do, and both can live directly in a `Candidate` ladder:

- `Candidate::rtti_vtable(name, mangled)` -- `mangled` is an MSVC mangled type name (e.g. `".?AVMyEngineActor@ns@@"`). The candidate resolves through `rtti::vtable_for_type`, returning the type's primary (`COL.offset == 0`) vtable.
- `Candidate::string_xref(name, literal)` -- `literal` is the exact string content. The candidate resolves through `scan::find_string_xref`: it anchors on the immutable literal in `.rdata`, then resolves the single RIP-relative reference to it. Use `Candidate::string_xref(name, StringRefQuery{...})` to pass explicit facets (encoding, return mode, terminator match, broad sweep).

This lets one ordered ladder express the natural "try the RTTI name, else the string xref, else the byte AOB" for a single target, resolved by the same machinery and used automatically by `resolve_batch` and the prologue-fallback path.

```cpp
const std::array<sc::Candidate, 2> k_actor_vtbl{{
    sc::Candidate::rtti_vtable("MyEngineActor", ".?AVMyEngineActor@ns@@"),
    sc::Candidate::rip_relative("MyEngineActor_byteAOB",
        sc::Pattern::literal("48 8D 05 ?? ?? ?? ??"),
        /*displacement_at=*/3, /*instruction_length=*/7),
}};
const sc::ScanRequest req = sc::borrow(k_actor_vtbl, "MyEngineActorVtbl",
                                        DetourModKit::Region::host());
const auto hit = sc::resolve(req);
```

Three properties are load-bearing:

- **Scope.** Both backends are module-scoped (an RTTI COL's RVAs are image-base-relative; an in-image string xref is image-scoped). Set `ScanRequest::scope` to `Region::host()` or `Region::module_named(...)` as appropriate; `Region::whole_process()` is not meaningful for these tiers.
- **Uniqueness is the backend's job.** `require_unique` has no effect for `rtti_vtable` or `string_xref` candidates: the backends fail closed on ambiguity by construction, mapping directly to "fall through to the next candidate" without a byte-mode uniqueness rescan.
- **Prologue fallback ignores them.** The fallback pass only rewrites `direct`-tier candidates, so a name/string tier is inherently stomp-immune: it either resolved on the happy path or is skipped unchanged.

The two backends themselves (`rtti::vtable_for_type` and `scan::find_string_xref`) are documented in full in [rtti-walker.md](../guides/rtti/rtti-walker.md) and the string-xref tour above; this section only covers expressing them inside a ladder.

### 6.6 Ordering and logging

Put the most-specific candidate first. The resolver returns on the first successful resolution, so an overly-generic pattern placed near the head will shadow tighter patterns further down the list. The `winning_name` on `Hit` tells you which candidate fired; log it or stash it in your mod's telemetry so you can correlate a running session with a specific build of the game after the fact. The resolver also emits a Debug-level log line of the form `"<label> resolved via '<name>' at 0x..."` the first time it succeeds; raise your log level to Debug to capture it for build identification even without explicit caller logging. Alternatively, set `ScanRequest::order = scan::CandidateOrder::UniqueFirst` to let the resolver automatically promote the text tiers (RTTI and string xref, which are unique-only by construction) ahead of byte patterns.

### 6.7 Host-module convenience overloads

The overwhelmingly common scope for an injected ASI is "the host EXE." `Region::host()` is the default `ScanRequest::scope`, so a host-EXE cascade needs no explicit scope:

```cpp
const sc::ScanRequest req = sc::borrow(k_candidates, "weapon_fire");
// scope defaults to Region::host()
const auto hit = sc::resolve(req);
```

Use `Region::module_named(L"engine.dll")` when the target code lives in a separate module (an engine DLL loaded by a thin launcher EXE); `Region::host()` would scan the wrong image in that case. `Region::whole_process()` searches all committed pages and is the correct choice when the binary is packed or the target module is unknown.

### 6.8 Reading a code constant (`read_code_constant`)

Sometimes the value a mod needs is not an address but a constant baked into an instruction: an array stride in an `add reg, imm`, a struct displacement in a `movzx [reg + disp]`, a bit position. Hand-reading those immediates every patch is the largest "re-RE every update" bucket. `read_code_constant` is the code-side twin of the RTTI self-heal: declare the instruction site (an AOB cascade that lands **on** the instruction) plus which operand to read, and it decodes the live instruction and returns the current value.

```cpp
const std::array<sc::Candidate, 1> k_stride_site{{
    sc::Candidate::direct("equip-stride",
        sc::Pattern::literal("48 6B C0 ?? 48 03 ??")),
}};

sc::CodeConstant cc{};
cc.site = k_stride_site;
cc.kind = sc::OperandKind::Immediate; // or MemoryDisplacement
cc.operand_index = 1;                  // index into the VISIBLE operands

const auto stride_result = sc::read_code_constant(cc); // scope defaults to Region::host()
if (stride_result)
    g_equip_stride = static_cast<std::size_t>(*stride_result);
```

Key behaviours:

- **Always decodes.** `cc.nominal` is a telemetry/baseline hint only, never a return short-circuit, so a same-shape / different-value drift (a stride that changed from 232 to 240) is reported as the new value. Set `cc.has_nominal = true` to make `nominal` meaningful (do not overload `nominal == 0` as "unset").
- **Visible-operand indexing.** `operand_index` counts the operands you see in a disassembler; implicit operands (flags, implicit registers) do not shift the index.
- **RIP-relative is resolved to an absolute.** A `[rip + disp]` memory operand returns the absolute target address, not the raw relative displacement.
- **Narrowing.** `byte_width = 0` returns the decoded value (already sign-extended); a non-zero `byte_width` narrows to that many bytes and re-sign-extends, so a deliberately narrowed negative displacement stays negative.
- **Fails closed.** A site that no longer decodes, a wrong operand kind, or an out-of-range index returns `ErrorCode::DecodeFailed` / `UnexpectedShape` / `OperandOutOfRange` rather than a guess.

The decoder (Zydis) is kept entirely inside the DetourModKit implementation; consumers never include or link Zydis themselves.

## 7. Patch-proof patterns (cache, fallback, verify)

The raw Scanner API is intentionally low-level. Anything beyond a single call-site benefits from a thin layer above it. Below are patterns battle-tested in consumer projects.

### 7.1 Cache the compiled `Pattern`

`scan::Pattern::compile()` is cheap but not free. If you scan repeatedly (hot-reload, re-scan after a level load, fallback between candidates), compile once and hold the `Pattern` in a static or a class member. For compile-time-known signatures, `scan::Pattern::literal()` is `consteval` and produces a zero-cost static value:

```cpp
// For compile-time-known signatures: consteval, no runtime cost.
static constexpr auto k_pattern =
    DetourModKit::scan::Pattern::literal("48 89 5C 24 ?? 57 48 83 EC 30");

// For runtime signatures: compile once at startup and reuse.
const auto runtime_result = DetourModKit::scan::Pattern::compile(user_supplied_string);
if (!runtime_result) { /* handle BadPattern */ }
const auto& runtime_pattern = *runtime_result;
```

### 7.2 Multi-candidate fallback

For a single logical hook, ship two or three candidates: one tight one for the current build, one wider one for the previous build, and a generic one as a safety net. Use `scan::resolve` with an ordered ladder -- the resolver stops on the first hit and records the `winning_name`.

```cpp
const std::array<sc::Candidate, 3> k_player_ctx{{
    sc::Candidate::direct("player_ctx_v2",
        sc::Pattern::literal("48 89 5C 24 ?? 57 48 83 EC 30 48 8B D9 48 8B FA")),
    sc::Candidate::direct("player_ctx_v1",
        sc::Pattern::literal("40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 84 C0")),
    sc::Candidate::rip_relative("player_ctx_callsite",
        sc::Pattern::literal("E8 ?? ?? ?? ?? 48 8B CB 48 8B 43 20"),
        /*displacement_at=*/1, /*instruction_length=*/5),
}};
const auto hit = sc::resolve(sc::borrow(k_player_ctx, "player_ctx"));
if (hit) logger.info("resolved via {}", hit->winning_name);
```

### 7.3 Verify after match

A lone signature hit is necessary but not sufficient. Two lightweight checks catch the overwhelming majority of mis-hits:

- **First-byte sanity check.** A function prologue does not start with `0x00`, `0xC2`, `0xC3`, or (usually) `0xCC`. Use `scan::is_likely_function_prologue(addr)` to reject scan poison before handing the address to SafetyHook. The helper accepts `0xE9` / `0xEB` / `0xFF 0x25` so a target already inline-hooked by another mod still passes.
- **`memory::is_readable()` guard.** Before reading more than a single byte (for example, disassembling a 5-byte trampoline or copying out an RTTI string), confirm the entire span is inside a committed page with an expected protection flag. It takes a `Region` now: `memory::is_readable(DMK::Region{addr, n})`.

```cpp
if (!DetourModKit::scan::is_likely_function_prologue(resolved_addr))
{
    return; // scan poison: zero page, alignment pad, or bare RET
}
```

### 7.4 Walk-back offsets

`Candidate::direct` accepts a `walk_back` argument (signed): a negative value walks backward from the match, for example to arrive at the function start after anchoring on a later landmark. The resolver applies it before returning the hit address, so callers receive the already-adjusted `Hit::address`.

```cpp
// walk back 16 bytes from the match to arrive at the function prologue
sc::Candidate::direct("anchor_walkback",
    sc::Pattern::literal("48 8B 88 B8 00 00 00 48 89 4C 24 68"),
    /*walk_back=*/-16)
```

### 7.5 Name every candidate

Anonymous signatures make regressions unreadable. Attach a human-friendly label to every candidate (`"player_ctx_load_v1"`, `"fire_weapon_v2_backcompat"`). Log that label when a hit is found or when all candidates fail. It pays for itself the first time a patch breaks one of thirty signatures.

## 8. Worked examples

### 8.1 Hook a direct `call rel32`

```cpp
namespace sc = DetourModKit::scan;
namespace hk = DetourModKit::hook;

const auto pat_result = sc::Pattern::compile("E8 ?? ?? ?? ?? 48 89 43 10");
if (!pat_result) return;

const auto hit = sc::scan(*pat_result, DetourModKit::Region::host(), 1, sc::Pages::Executable);
if (!hit) return;

// hit->value() points at 0xE8; the full call is 5 bytes with disp32 at offset 1.
const auto target = sc::resolve_rip_relative(*hit, /*displacement_offset=*/1, /*instruction_length=*/5);
if (!target) return;

// hook::inline_at takes the resolved Address directly and returns a move-only RAII Hook. inline_at does the single
// function-to-void* cast for you; hold the handle for the hook's lifetime (here, a function-static optional).
static std::optional<hk::Hook> g_callee_hook;
auto installed = hk::inline_at(
    hk::InlineRequest{.name = "callee_hook", .target = *target}, &Detour_Callee);
if (!installed)
{
    logger.error("callee hook failed: {}", installed.error().message());
    return;
}
g_callee_hook.emplace(std::move(*installed));
// Inside Detour_Callee, reach the original via g_callee_hook->original<CalleeFn>() (typed trampoline) or
// g_callee_hook->call<Ret>(args...) (guarded original-call). No separate "original" out-pointer is registered.
```

If your pattern embeds a `|` marker, `scan::scan` has already applied `Pattern::offset()` to the returned address: pass it directly to `resolve_rip_relative`. Adding the offset again would double-apply and advance past the opcode.

> Resolve-on-install alternative. When the target is a *function entry* found by a `direct` candidate (not a two-step RIP resolution like the one above), skip the manual scan and hand a `scan::OwnedScanRequest` straight to `inline_at` / `mid_at` as the `target`. The verb resolves the ladder at install time, so the same `OwnedScanRequest` you would pass to `scan::resolve` doubles as the hook target:
>
> ```cpp
> hk::inline_at(
>     hk::InlineRequest{
>         .name = "weapon_fire",
>         .target = sc::OwnedScanRequest{
>             .ladder = {sc::Candidate::direct("weapon_fire_v1",
>                            sc::Pattern::literal("48 89 5C 24 ?? 57 48 83 EC 30"))},
>             .label = "weapon_fire",
>             .scope = DetourModKit::Region::host(),
>         },
>     },
>     &Detour_WeaponFire);
> ```

### 8.2 Resolve a global pointer via `mov rax, [rip+disp32]`

```cpp
// Search 64 bytes from the match for the mov, then resolve.
const auto ptr_addr = sc::find_and_resolve_rip_relative(
    DetourModKit::Region{*hit, 64},
    sc::PREFIX_MOV_RAX_RIP, /*instruction_length=*/7);
if (!ptr_addr)
{
    logger.error("mov rax, [rip+disp32] not found: {}",
                 DetourModKit::to_string(ptr_addr.error().code));
    return;
}

// ptr_addr is the absolute address of the pointer slot, not the pointee.
auto global_ptr = DMK::memory::read<std::uintptr_t>(*ptr_addr).value_or(0);
```

If `hit` came from a pattern with a `|` offset marker, `scan::scan` has already applied the offset: pass `*hit` directly. Adding the offset would double-apply and start the search window past the intended opcode.

### 8.3 Scan a packed binary

```cpp
// Code decrypted into anonymous executable pages outside any loaded module.
const auto pat_result = sc::Pattern::compile("48 8B ?? ?? ?? ?? ?? 48 85 C0 74 ?? E8");
if (!pat_result) return;

// Region::whole_process() with Pages::Executable walks all committed execute-readable pages.
const auto hit = sc::scan(*pat_result, DetourModKit::Region::whole_process(), 1, sc::Pages::Executable);
if (!hit) return;

// hit->value() is the already offset-adjusted address.
```

### 8.4 Second occurrence with an offset marker

```cpp
//  "48 8B 88 B8 00 00 00 | 48 89 4C 24 68"
// Use the second hit (e.g. the one inside the actual setter, not the reader).
static constexpr auto k_pattern =
    sc::Pattern::literal("48 8B 88 B8 00 00 00 | 48 89 4C 24 68");

const auto hit = sc::scan(k_pattern, DetourModKit::Region::host(), /*occurrence=*/2, sc::Pages::Executable);
if (!hit) return;

// hit->value() already lands on the `mov [rsp+0x68], rcx` because scan() applied
// Pattern::offset(). Do not add the offset again.
const DetourModKit::Address anchor = *hit;
```

Reminder: `scan::scan` returns the offset-adjusted address when a `|` marker is present (and the match start when it is absent). `Pattern::offset()` is applied for you; adding it manually double-applies.

## 9. DOs and DON'Ts

### DO

- **Do** prefer code anchors over data anchors.
- **Do** wildcard every immediate operand (addresses, RVAs, relative offsets, jmp/call targets).
- **Do** keep signatures as short as will return a unique hit: 7 to 16 bytes is the common sweet spot.
- **Do** cache compiled `Pattern` values if you scan more than once; prefer `Pattern::literal()` for compile-time-known signatures.
- **Do** ship at least one fallback candidate per hook for long-lived projects.
- **Do** verify the match with `memory::is_readable()` and a first-byte sanity check before hooking.
- **Do** log which named candidate matched; anonymous signatures are unmaintainable at scale.
- **Do** treat the address returned by `scan::scan` as already offset-adjusted; it applies `Pattern::offset()` for you.

### DON'T

- **Don't** include a static address or RVA in the signature body: it will change next build.
- **Don't** extend a signature into the `CC`/`90` padding between functions: linkers rebalance padding freely.
- **Don't** anchor on a short `Jcc rel8` conditional jump. Compilers flip freely between the `rel8` and `rel32` encodings (from a 2-byte `74 xx` to a 6-byte `0F 84 xx xx xx xx`, or vice versa) whenever the branch distance crosses a threshold, and even trivial edits to unrelated code can push the branch into a different encoding. The opcode byte changes, so the signature stops matching.
- **Don't** assume `scan::resolve_rip_relative` hands back the call target for `FF 15 disp32` / `FF 25 disp32`. The disp32 addresses a pointer slot, and DMK returns that slot's absolute address; you must dereference it (for example with `memory::read<std::uintptr_t>`) to obtain the final destination.
- **Don't** ship a pattern with zero literal bytes (every token `??`). The scan engine will match at the region start every time, which is almost never what the caller wants.
- **Don't** call `Pattern::compile` in a hot loop on user-supplied strings; compile once at startup.
- **Don't** add `Pattern::offset()` to the address returned by `scan::scan`; it already applies the offset. Double-applying walks past the intended byte and is a common source of mysteriously-wrong resolved addresses.
- **Don't** ignore a `NoMatch` or `UnreadableDisplacement` error: they almost always mean the signature lost its context, not that the code simply moved.
- **Don't** trust a single-build signature in a long-lived mod without a fallback.

## 10. Troubleshooting

| Symptom | Likely cause | Remedy |
| ------- | ------------ | ------ |
| `Pattern::compile` returns `BadPattern` error | Malformed token, three-digit hex, stray `\|` | Check `result.error().message()`; it names the offending token |
| `scan::scan` returns `NoMatch` every time | Wildcards too broad, or the literal bytes include a byte the binary never has | Reduce wildcard count; print a few hex dumps around the expected site |
| `scan::scan` hits the wrong site | Signature not unique; `require_unique = true` should have caught it | Pick a tighter neighbour, or use the Nth-occurrence argument with a confirmed N |
| `resolve_rip_relative` returns `UnreadableDisplacement` | Match landed inside a guard page or at a region edge | Validate the `displacement_offset` and `instruction_length`; use `Region::whole_process()` with `Pages::Executable` |
| Hit address crashes on first call | Missing post-match verification; anchor drifted into padding on a new build | Gate with `scan::is_likely_function_prologue(addr)` before hooking |
| Works locally, fails on a different machine | Packer or anti-cheat transforming the module between load and scan | Use `Region::whole_process()` with `Pages::Executable`; add a later re-scan on first frame |
| Multi-GB scan is slow | Patterns whose only literal bytes are common (`48 8B`, `E8`, etc.) | Broaden the anchor to include a rarer byte; the anchor selector prefers rarer bytes |

## 11. Further reading

- [C++ Core Guidelines - in-house coding standards](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
- [omni's hackpad: Fixing Hacks When a Game Gets Patched](https://badecho.com/index.php/2021/10/05/fixing-hacks-after-patch/)
- [Reloaded II Cheat Sheet: Signature Scanning](https://reloaded-project.github.io/Reloaded-II/CheatSheet/SignatureScanning/)
- [UE4SS: Fixing missing AOBs (advanced)](https://docs.ue4ss.com/dev/guides/fixing-compatibility-problems-advanced.html)
- [Guided Hacking: C++ Signature Scan Tutorial](https://guidedhacking.com/threads/c-signature-scan-pattern-scanning-tutorial.3981/)
- [AlliedModders Wiki: Signature Scanning](https://wiki.alliedmods.net/Signature_scanning)
- DMK source of truth:
  - [include/DetourModKit/scan.hpp](../../include/DetourModKit/scan.hpp)
  - [tests/test_scan_resolve.cpp](../../tests/test_scan_resolve.cpp)
