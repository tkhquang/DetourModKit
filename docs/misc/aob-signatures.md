# AOB signature guide

This guide shows how to write, test, and maintain array-of-bytes (AOB) signatures with the DetourModKit `scan` module.

`defines.hpp` stops the build with an `#error` on any target other than native x86-64 Windows, and the page walks and fault guards are Win64-specific. The resolvers assume PE module bases, RIP-relative `disp32` encoding, and the `PAGE_EXECUTE_*` protection flags that `VirtualQuery` reports.

In the examples below, `sc` is a namespace alias for `DetourModKit::scan`. Each example is a fragment, not a complete translation unit.

## Write a signature

An AOB (also called a signature) is a short byte sequence from the `.text` section of a target binary that identifies one instruction at runtime. Module bases change on each launch (ASLR), and offsets change with each build. A signature binds to the instruction encoding instead, so it survives patches that break a hard-coded RVA.

Two rules set the ceiling on signature quality:

- **Sign code, not data.** Compilers reorder instructions more often than they change the opcodes for one source line. Data tables (strings, vtables, constants) move more often and make a poor anchor.
- **Wildcard every field that the compiler or linker can move.** These fields include immediates, RIP-relative displacements, jump and call targets, RVAs, vtable offsets, and register indices inside VEX prefixes.

### Workflow in IDA, Ghidra, or x64dbg

1. **Locate the instruction to hook.** Prefer a load or store of the target value, or the first instruction of a distinctive prologue.
2. **Copy 12 to 32 raw bytes around it.** That window spans 3 to 6 instructions.
3. **Wildcard the volatile operands.** Replace each immediate, `disp32`, RVA, and jmp or call target byte with `??`. Keep opcodes, ModRM bytes, REX prefixes, and register selectors.
4. **Shrink the signature.** Start with the minimum that returns one hit in the target module. If duplicates appear, add one instruction at a time.
5. **Test against at least three game versions or builds.** Include one build that you know the vendor compiled differently. A signature that survives only one build is brittle.

### Anatomy of a good signature

```text
; 7 bytes total
48 8B 05 ?? ?? ?? ??       mov rax, [rip + <player_ctx_rva>]
```

`48` is the REX.W prefix (64-bit operand), `8B` is `MOV r64, r/m64`, and `05` is the ModRM byte that encodes `rax, [rip + disp32]`. The next four bytes are a `disp32` that the linker recomputes on each build. A wildcard over those four bytes gives a 7-byte signature that works across almost every rebuild. It fails only when the target register changes or the instruction is replaced.

For higher uniqueness, chain one or two adjacent instructions:

```text
48 8B 05 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ??
; mov rax, [rip+disp32]
; test rax, rax
; je   rel32
```

That chain is distinctive and commits to none of the fields that move.

### Anchor rules

| Situation | Action |
| --------- | ------ |
| The signature returns more than one hit | Add bytes forward or backward, or add a unique neighbor instruction. Do not add wildcards. |
| The signature contains a static address or RVA | Wildcard the disp32 or immediate. Widen the signature with a neighbor. The address changes on the next build. |
| The signature crosses `CC` or `90` padding between functions | Stop at the padding boundary. Linkers rebalance padding freely. |
| The signature contains a short `Jcc rel8` branch | Move the anchor off the branch. Compilers switch between `74 xx` and `0F 84 xx xx xx xx` when the branch distance changes. |
| The signature has no literal bytes | Add literal bytes. An all-`??` pattern matches at the start of the scope. |
| The compiler inlines the function differently between builds | Move the anchor to the callee, or pick a caller whose prologue is still unique. |
| An anti-tamper layer or packer rewrites the bytes | Scan `Region::whole_process()` with `Pages::Executable`. Add fallback candidates. |

Keep a signature as short as a unique hit allows. For a long-lived project, ship at least one fallback candidate for each hook.

## Pattern syntax

`scan::Pattern::compile(std::string_view)` in [scan.hpp](../../include/DetourModKit/scan.hpp) parses the DSL. Tokens split on whitespace (space, tab, `\r`, `\n`, `\f`, `\v`), and the parser ignores whitespace at either end.

| Token | Meaning |
| ----- | ------- |
| `48`, `8B`, `FF` | Literal byte. Must be exactly two hex digits. Case-insensitive. |
| `??` | Wildcard byte: any value matches at this position. |
| `?` | Same as `??`. Accepted for brevity. |
| `4?`, `?A` | Per-nibble wildcard: the hex digit is fixed, the `?` nibble is free. Use it when one nibble is invariant across builds, for example a ModRM reg or r/m field. |
| `[X-Y]`, `[X]` | Bounded jump: skip `X` to `Y` bytes. `[3]` means `[3-3]`. Unlike a `??` run, it tolerates a gap whose *size* shifts between builds. The unbounded YARA `[X-]` form is rejected. |
| `\|` | Offset marker: `Pattern::offset()` records the next token's position, or one past the last byte at pattern end. At most one. A jump before it adds its actual gap size at match time. |

`compile` returns `Result<Pattern>` (`std::expected<Pattern, Error>`), with `ErrorCode::BadPattern` on any malformed token. Malformed tokens include `"GG"`, `"1FF"`, three-character tokens, and a second `|`. A jump is malformed when it is inverted or unbounded (`"[5-2]"`, `"[2-]"`), sits at either end of the pattern, or sits next to another jump. Every pattern therefore splits into non-empty fixed segments. Empty or whitespace-only input also fails. `scan::Pattern::literal(dsl)` is `consteval`, so a malformed literal is a build error.

A `Pattern` stores its bytes inline, so it holds at most `MAX_PATTERN_BYTES = 128` fixed bytes. An over-cap pattern returns `BadPattern` with a `TooLong` status. A pattern carries at most `MAX_PATTERN_JUMPS = 8` gaps, and each gap skips at most `MAX_JUMP_SPAN = 256` bytes. The bounded-jump matcher has a per-position and a per-region work budget (`[B-65]`). When a budget runs out, `scan` returns `ErrorCode::BudgetExceeded`, never a later match. `resolve` skips that candidate and reports `BudgetExceeded` when no candidate resolves.

### Anchor byte and scan speed

The scanner sweeps for one anchor byte with `memchr` and runs the full masked compare only where it finds that byte. The anchor is the rarest fully-known byte in segment 0, the run before the first `[...]`. Nibble tokens and bytes after a bounded jump never anchor. A static table ranks these bytes as common, roughly most common first: `0x00`, `0xCC`, `0x90`, `0xFF`, `0x48`, `0x8B`, `0x89`, `0x0F`, `0xE8`, `0xE9`, `0x83`, `0xC3`. Every other byte ranks as rare.

Page-gated `scan()` and byte-tier `resolve()` sample a bounded byte histogram of the scope and re-pick the rarest segment-0 byte for that image. A scope over 512 MiB is not sampled and keeps the static pick, as `unchecked::find_pattern` always does. The anchor choice changes speed only, never the result.

A pattern of only common bytes, such as `48 8B`, `48 89`, or `E8`, has no rare anchor. Add at least one byte outside the table to the first segment. A pattern of only nibble tokens still resolves, through a masked compare at every position. [signature-health.md](../guides/scanning/signature-health.md) grades anchor rarity offline with the same table.

### Examples

```text
"48 8B 88 B8 00 00 00 | 48 89 4C 24 68"
```

The `|` sits after seven literal bytes, so `Pattern::offset() == 7`. The pattern anchors on a wide distinctive window and returns the address of the second instruction.

```text
"48 8B 05 ?? ?? ?? ?? [2-6] E8 ?? ?? ?? ??"
```

A 2-to-6-byte gap separates `mov rax, [rip+disp32]` from a `call rel32` and absorbs an instruction whose length varies between builds. The 12 fixed bytes, 7 in the first segment and 5 in the second, frame the gap. `Pattern::segment_count()` is 2, and `Pattern::min_match_length()` / `max_match_length()` report the 14-to-18-byte span of a match.

## Scan one pattern

Functions in `DetourModKit::scan` return domain failures as `Result<T>` (`std::expected<T, Error>`). `scan`, `resolve_batch`, and the RIP helpers are `noexcept`. `scan` and `resolve_batch` report an allocation failure as `Error{OutOfMemory}`. `resolve`, `find_string_xref`, and `read_code_constant` can throw `std::bad_alloc`. If you need a no-throw guarantee, wrap those calls at a startup boundary.

Compile each runtime pattern once at startup and reuse the value:

```cpp
#include <DetourModKit/scan.hpp>

namespace sc = DetourModKit::scan;

const auto pattern_result = sc::Pattern::compile("48 8B 05 ?? ?? ?? ?? 48 85 C0");
if (!pattern_result)
{
    // pattern_result.error().extra holds the numeric PatternStatus
    return false;
}
const sc::Pattern& pattern = *pattern_result;

// A compile-time literal: consteval, so a malformed DSL is a build error.
static constexpr sc::Pattern k_pattern = sc::Pattern::literal("48 8B 05 ?? ?? ?? ??");
```

`scan::scan(pattern, scope, occurrence, pages)` returns the address of the Nth match in `scope`, counted from 1:

```cpp
const auto scope = DetourModKit::Region::module_named("game.exe");
const auto match = sc::scan(pattern, scope, 1, sc::Pages::Executable);
if (!match)
{
    return false;
}
const DetourModKit::Address target = *match;
```

The returned address already includes `Pattern::offset()`, or is the match start when the pattern has no `|`. Do not add the offset again. A second add walks past the intended byte. Occurrence `0` returns `ErrorCode::NoMatch`.

### Scopes and page classes

`Region::module_named("game.exe")` limits the sweep to one module image, and `Region::host()` selects the host executable. If unpacked code sits in anonymous executable pages, or its owner module is unknown, scan `Region::whole_process()` with `Pages::Executable`.

`Pages::Executable` accepts committed `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, and `PAGE_EXECUTE_WRITECOPY` regions. `Pages::Readable`, the default, also accepts `PAGE_READONLY`, `PAGE_READWRITE`, and `PAGE_WRITECOPY`, so it reaches `.rdata`, `.data`, vtables, and RTTI descriptors. Every scan skips pure `PAGE_EXECUTE`, guard, no-access, and uncommitted pages and never reads them.

A `Pages::Readable` scan follows the Readable authority rule of `scan::Pages` in [scan.hpp](../../include/DetourModKit/scan.hpp). A `Region::whole_process()` scope with no declared exclusions therefore returns `ErrorCode::NotAuthoritative`. Query bytes are data, so a `Pages::Executable` scan stays authoritative on any scope.

A data scan reads more bytes than a code scan and collides more often, because pointer tables and constant pools look random. Give a data pattern at least 8 literal bytes. Check the hit with an occurrence count or a structural check.

Do not sign a raw vtable header. Each vtable entry is a relocated absolute pointer, and only its low 16 bits stay the same across launches. To find a vtable, use `Candidate::rtti_vtable` or `rtti::vtable_for_type` with the mangled type name ([rtti-walker.md](../guides/rtti/rtti-walker.md)).

`scan::unchecked::find_pattern(region, pattern, occurrence)` applies no page filter and faults the host on an unreadable byte. [memory-scanning.md](../design/memory-scanning.md) states when to use it.

> `scan` is setup and control-plane only. Do not scan on the render thread. Resolve signatures at startup or on a worker thread. Cache each resolved address.

`sc::active_simd_level()` reports the SIMD tier (`Scalar`, `Sse2`, `Avx2`, or `Avx512`), and `sc::to_string(level)` names it. `Avx512` needs a `DMK_ENABLE_AVX512` build on an AVX-512F and AVX-512BW host.

## RIP-relative resolution

The 4-byte displacement inside the instruction is relative to the address of the *next* instruction: `target = instruction_address + instruction_length + disp32`. DetourModKit exposes two helpers and a set of prefix constants.

### Two-step: find the match, then resolve

If the instruction is part of a wider signature, or bytes follow the disp32, use this form.

```cpp
const auto hit = sc::scan(pattern, scope, 1, sc::Pages::Executable);
if (!hit) return false;
// The matched instruction is `mov rax, [rip+disp32]`: 7 bytes, disp32 at offset 3.
const auto resolved = sc::resolve_rip_relative(*hit, /*displacement_offset=*/3, /*instruction_length=*/7);
if (!resolved) return false; // resolved.error().code names the failure below
```

Error values (all unified under `ErrorCode`):

| ErrorCode | Meaning |
| --------- | ------- |
| `NullInput` | null instruction address (`resolve_rip_relative`), or a null search region / empty opcode prefix (find-and-resolve) |
| `InvalidArg` | malformed RIP-relative layout: the disp32 does not fit inside an x86-64 instruction of at most 15 bytes |
| `RegionTooSmall` | (find-and-resolve) the search region is shorter than the prefix plus its 4-byte disp32 |
| `PrefixNotFound` | (find-and-resolve) the opcode prefix never occurs in the search region (an all-decoy region instead surfaces the last decode failure below) |
| `UnreadableDisplacement` | the fault guard failed to read the disp32 bytes |
| `ImplausibleTarget` | the resolved address is not a plausible user-mode pointer (a corrupt displacement that resolves to 0, a low guard-page address, or a kernel-range value) |
| `UnreadableTarget` | (find-and-resolve) the first byte of the resolved target is not readable at scan time |

### One-step: find the prefix and resolve

If the disp32 **immediately follows the prefix that you supply**, use this form. `scan.hpp` ships these prefix constants:

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

```cpp
const auto resolved = sc::find_and_resolve_rip_relative(
    DetourModKit::Region{*hit, 64},   // short search window from the match
    sc::PREFIX_CALL_REL32,            // E8
    /*instruction_length=*/5);        // E8 + disp32
```

`find_and_resolve_rip_relative` returns the first prefix occurrence whose disp32 resolves to a plausible target with a readable first byte. It skips each earlier decoy. After it exhausts the region, it reports the last concrete failure, or `PrefixNotFound` when no prefix occurred (`[B-60]`). The prefix search reads `search` with no page filter, so the caller must guarantee that the region is committed and readable. For one instruction at an uncertain address, use `resolve_rip_relative`, whose displacement read is guarded. For an ambiguous signature, use `resolve`, which enforces per-candidate uniqueness.

### What these helpers do not resolve

The helpers understand only the 32-bit signed displacement form. These forms need manual work:

- Short jumps (`EB rel8`, `Jcc rel8`) with 8-bit displacements.
- 16-bit displacements and legacy `EA ptr16:32` far jumps.
- Indirect calls and jumps through memory (`FF 15 disp32`, `FF 25 disp32`). The disp32 addresses a **pointer slot**, and DetourModKit returns the slot address, not the final target. Read the slot with `memory::read<std::uintptr_t>` to get the destination.

## Candidate ladders

A candidate ladder lists several signatures for one target, most specific first. `scan::resolve` tries each candidate in order and returns the first that resolves. `Hit::winning_name` records the winner, so a log line identifies the game build.

Four factories build a `Candidate`:

- `Candidate::direct(name, pattern, walk_back = 0)`: the address is the `|`-adjusted match plus a signed `walk_back`. A negative `walk_back` steps back from a later landmark to the function start.
- `Candidate::rip_relative(name, pattern, displacement_at, instruction_length)`: the address is the target of a RIP-relative memory operand inside the match.
- `Candidate::rtti_vtable(name, mangled)`: the primary vtable of an MSVC mangled type name, through `rtti::vtable_for_type`.
- `Candidate::string_xref(name, literal)`: the unique RIP-relative reference to a string literal, through `scan::find_string_xref`. `Candidate::string_xref(name, StringRefQuery{...})` passes explicit facets.

A `rip_relative` candidate decodes the matched instruction. The decoded length must equal `instruction_length`, and a 32-bit displacement of a RIP-based memory operand must sit at `displacement_at`. A `call rel32` or `jmp rel32` stores a branch offset, not a memory operand, so such a candidate never resolves. Resolve a branch target with `scan` plus `resolve_rip_relative`, as the worked examples show.

`Candidate::rip_relative` throws `std::invalid_argument` on a negative `displacement_at`, a disp32 past the instruction end, or a length above 15 bytes. It also throws when the pattern suffix from its `|` marker does not cover all four disp32 bytes.

The resolver computes the target from one immutable sweep snapshot, never from a reread after the sweep. The sweep captures the whole instruction for the decode, so the pattern does not have to cover the bytes after the disp32. It must cover the four disp32 bytes, because they authorize the target.

### Request fields

`ScanRequest` in [scan.hpp](../../include/DetourModKit/scan.hpp) owns the field contracts. It borrows its ladder, label, and exclusions for one expression. For a stored request, use `OwnedScanRequest`. Pass its `view()` to `resolve`. `scan::borrow(ladder, label, ...)` builds a borrowed request with lifetime diagnostics.

- `scope` (default `Region::host()`): every tier's final address must lie inside it. The resolver never widens to a whole-process scan. A copy of a generic candidate in an overlay or a sibling mod therefore cannot shadow the real match.
- `pages` (default `Pages::Readable`): the page class for the byte tiers.
- `require_executable_result`: every final address must be on an execute-readable page, whichever tier produced it.
- `require_unique` (default true): a byte candidate must match exactly once in scope.
- `order`: `CandidateOrder::UniqueFirst` promotes the text tiers, then anchored byte patterns, ahead of the other byte patterns.
- `fallback_policy` and `fallback_witness`: hooked-prologue recovery, described below.
- `exclusions`: every live caller copy of the query bytes. A non-empty span satisfies the Readable authority rule.

Use a named-module scope only for one contiguous mapped image. For a packed target whose code lives in separate `VirtualAlloc` regions, use `Region::whole_process()` with `Pages::Executable`.

For a hook target, use `scan::borrow_code_target(ladder, label, scope)`. It presets `Pages::Executable`, `require_executable_result`, `CandidateOrder::UniqueFirst`, and a `WarnOnly` fallback policy, and keeps `require_unique` true. `borrow_code_target_strict(ladder, label, witness, scope)` is the same preset under `RequireIdentity`, with the witness as a required argument. For a data, RTTI, or string target, keep the default `Pages::Readable` through `borrow()` or a plain `ScanRequest`.

### Basic usage

```cpp
const std::array<sc::Candidate, 2> k_weapon_fire_candidates{{
    sc::Candidate::direct("weapon_fire_v1_9_0",
        sc::Pattern::literal("48 89 5C 24 08 57 48 83 EC 30 48 8B D9 48 8B FA "
                             "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 50 18 8B 43 10")),
    sc::Candidate::direct("weapon_fire_v1_8_2",
        sc::Pattern::literal("40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 84 C0")),
}};

const auto hit = sc::resolve(sc::borrow(k_weapon_fire_candidates, "weapon_fire"));
if (!hit)
{
    DetourModKit::log().error("weapon_fire failed: {}", DetourModKit::to_string(hit.error().code));
    return false;
}
DetourModKit::log().info("resolved {} at {:#x}", hit->winning_name, hit->address.raw());
```

`Hit::address` is the final absolute address. For a `rip_relative` winner, it is the resolved displacement target. `winning_name` is an owned copy of the candidate name, and `winning_mode` names its tier. `Hit::evidence` holds the matched bytes of a byte-tier winner (see `scan::WinningEvidence`). `scan::or_null(result)` and `scan::address_or(result, fallback)` flatten a `Result<Hit>` to an address.

### Unique matches (`require_unique`)

A single scan returns the lowest-address match. A loose pattern that matches several functions therefore wins on whichever address sorts first. With `require_unique = true`, the default, a candidate that matches more than once is ambiguous, and the resolver falls through to the next candidate. If no candidate is unique, `resolve` returns an error instead of a wrong address.

Set `require_unique = false` only for a candidate that you deliberately made non-unique. Check its first in-scope match yourself. The flag applies to the whole request, so put such a candidate in a separate request:

```cpp
// Strict candidate: must match exactly once in scope.
const std::array<sc::Candidate, 1> k_frustum{{
    sc::Candidate::rip_relative("Frustum_MatrixGlobalRef",
        sc::Pattern::literal("48 8B 05 ?? ?? ?? ?? 0F 28 00 0F 29 41 10"),
        /*displacement_at=*/3, /*instruction_length=*/7),
}};
// Broad net: a separate non-unique request, tried only after the strict ladder fails.
const std::array<sc::Candidate, 1> k_frustum_broad{{
    sc::Candidate::direct("Frustum_GenericPrologue", sc::Pattern::literal("40 53 48 83 EC 20")),
}};

auto hit = sc::resolve(sc::borrow(k_frustum, "frustum"));
if (!hit)
{
    sc::ScanRequest broad = sc::borrow(k_frustum_broad, "frustum_broad");
    broad.require_unique = false;
    hit = sc::resolve(broad); // check this first in-scope match before use
}
```

### Name and string tiers

A byte AOB breaks when the compiler reorders an instruction or the linker shifts a constant. A type name and a string literal survive such a patch. One ladder can therefore put a name or string tier ahead of the byte AOB for one target, for example `{Candidate::rtti_vtable("Actor", ".?AVActor@ns@@"), Candidate::rip_relative(...)}`.

Three properties apply to the text tiers:

- **Scope.** Both backends resolve within one module image. Set `scope` to `Region::host()` or `Region::module_named(...)`. A `Region::whole_process()` scope has no meaning for these tiers.
- **Uniqueness.** `require_unique` has no effect on `rtti_vtable` or `string_xref` candidates. Their backends fail closed on ambiguity, and the ladder falls through to the next candidate.
- **Recovery.** Hooked-prologue recovery rebuilds only `direct` candidates, so it skips the text tiers.

[rtti-walker.md](../guides/rtti/rtti-walker.md) documents `rtti::vtable_for_type`, and the string-reference section below documents `find_string_xref`.

### Candidate order and log lines

Put the most specific candidate first. The resolver returns on the first success, so a generic pattern near the head shadows tighter patterns below it. The resolver logs each outcome:

- A success is a **Debug** line `"scan::resolve: '<label>' resolved <addr> via candidate '<name>'."`.
- A recovery success is a **Debug** line `"scan::resolve: '<label>' recovered <addr> via hooked-prologue reconstruction of candidate '<name>'."`.
- A ladder with no winner logs a **Warning** line `"scan::resolve: '<label>' matched no candidate across <n> tried (<reason>)."`.

To capture the winner for build identification without caller code, raise the log level to Debug.

## Hooked-prologue recovery

A `direct` candidate that signs a function prologue misses when another mod already inline-hooked that function. With a non-`Off` `ScanRequest::fallback_policy`, `resolve` handles this case. After every candidate misses, it rebuilds each `direct` candidate with a jump shape in place of the prologue and scans again. It tries four shapes in this order:

- the five-byte `E9 ?? ?? ?? ??` near jump, for a trampoline within rel32 reach,
- the six-byte `FF 25 ?? ?? ?? ??` RIP-relative indirect jump through a separate pointer slot,
- the 14-byte `FF 25 00 00 00 00 <abs64>` absolute form, with the 8-byte target inline after the instruction,
- the 12-byte `mov rax, imm64; jmp rax` (`48 B8 <imm64> FF E0`) absolute jump.

The shapes are mutually exclusive at a real hook site, so the try order does not affect correctness. A recovered site must pass these gates:

- The rebuilt pattern matches exactly once in the executable pages of the scope.
- The decoded jump destination is a plausible pointer on a committed execute-readable page. It does not have to lie inside a module, because trampolines often live outside every image.
- The recovered address, after the `|` offset and `walk_back`, lies inside the scope.

A byte candidate whose sweep was truncated (`BudgetExceeded` or `IncompleteScan`) preempts recovery, because a partly read scope does not prove a miss. `ErrorCode` in [error.hpp](../../include/DetourModKit/error.hpp) defines each recovery error code.

### Rebuildable candidates

The rebuild replaces a stolen span, which is the jump length rounded up to an instruction boundary. The jump length is five bytes for `E9` and six, twelve, or fourteen bytes for the far shapes. The fallback refuses a shape when a wildcard or an undecodable instruction sits inside its stolen span. It also refuses a shape when fewer than ten fully-known bytes follow that span. A shorter tail lets the generic jump shape collide with unrelated jump sites in a large `.text` section. The fallback also refuses every candidate that contains a bounded jump (`[B-62]`).

`ErrorCode::PrologueFallbackNotApplicable` reports a ladder whose `direct` candidates no shape can rebuild. If you see this error, replace each wildcard inside the stolen span with its literal byte. Then extend the pattern to at least ten fully-known bytes past the stolen span. For a bounded-jump candidate, remove the jump or rely on its direct match.

In `k_weapon_fire_candidates` above, candidate 1 keeps whole literal instructions for 16 bytes and 12 literal bytes after them, so every shape can rebuild it. Candidate 2 keeps only six literal bytes after its `E9` and six-byte `FF 25` stolen spans. Its `E8 ??` call does not decode inside the longer spans, so the fallback refuses candidate 2.

### Identity witness

The structural gates prove that a hooked site exists and is unique. They do not prove that it is the intended function (`[B-53]`). A game patch can leave a hooked near-twin whose tail after the stolen span also matches. `WarnOnly`, the `borrow_code_target` default, returns the structural recovery and logs a Warning when the `fallback_witness` disagrees. `RequireIdentity` fails closed with `ErrorCode::PrologueIdentityRejected` when the witness rejects the site or the request has no witness.

The witness is a `FallbackValidator` with the signature of `anchor::AnchorValidator`. Compare the recovered address with an independently resolved landmark, or read a unique byte past the stolen span. Return false to reject the site.

```cpp
static std::uintptr_t g_expected = 0; // set from an independently resolved landmark
const auto hit = sc::resolve(sc::borrow_code_target_strict(
    k_weapon_fire_candidates, "weapon_fire",
    sc::FallbackWitness{
        .predicate = +[](std::int64_t addr, const void* ctx) noexcept
        { return static_cast<std::uintptr_t>(addr) == *static_cast<const std::uintptr_t*>(ctx); },
        .context = &g_expected},
    DetourModKit::Region::module_named("game.exe")));
```

> **Safety note.** Recovery serves one case: another mod loaded earlier already hooked the same prologue. It does not recover a function that a game patch removed or reshaped. A wrong recovered site gives a nonzero address in an unrelated function, and a hook there corrupts it. If a patch can remove or reshape the target, keep `fallback_policy = FallbackPolicy::Off`, the default. For defense in depth, add a `Candidate` that anchors **past** the longest stolen span, on a mid-body literal-byte landmark. The regular resolver then matches a sibling-patched site with no fallback.

## Batch resolution (`resolve_batch`)

`scan::resolve_batch` resolves many requests concurrently on a fork-join worker pool, so the startup cost is close to the slowest single resolve.

```cpp
// Owned requests keep each ladder alive. The views borrow from them.
std::vector<sc::OwnedScanRequest> owned;
owned.push_back(sc::OwnedScanRequest{
    .ladder = {sc::Candidate::direct("player_update_v1",
                   sc::Pattern::literal("48 89 5C 24 ?? 57 48 83 EC 30"))},
    .label = "player_update",
});
std::vector<sc::ScanRequest> views;
for (const auto& o : owned) views.push_back(o.view());

const auto batch = sc::resolve_batch(views, /*max_workers=*/0);
if (!batch) { /* whole-batch failure: ErrorCode::OutOfMemory or ErrorCode::Unknown */ return; }
const auto& results = *batch;
// Index the inner vector. On GCC, a range-for over bare std::expected elements
// recurses in the libstdc++ equality constraint and fails to compile.
for (std::size_t i = 0; i < results.size(); ++i) { /* results[i] is the Result<Hit> for views[i] */ }
```

- **Whole-batch signal.** The outer `Result` fails with `Error{OutOfMemory}` when the result vector cannot be allocated, or with `Error{Unknown}` for any other whole-batch exception.
- **Per-request slots.** `(*batch)[i]` always corresponds to `views[i]`. A per-request allocation failure sets that slot to `OutOfMemory`, and any other per-request exception leaves `NoMatch` in it.
- **Worker count.** `max_workers = 0` uses `std::thread::hardware_concurrency()`, or 4 when the host reports 0, clamped to the request count. The thread that calls `resolve_batch` is one of the workers.

> Call `resolve_batch` at startup or on a background worker. Do not call it from a hook or input callback, or under the loader lock (`[B-100]` in `scan.hpp`). It creates worker threads and allocates.

## String-reference anchors

When the text that a target uses is more stable than its code, anchor on the string. `find_string_xref` is a two-phase, fail-closed resolve within one module image. The [anchor registry](../guides/scanning/anchors.md) exposes the same backend as `AnchorKind::StringXref`.

1. Phase 1 finds the literal in the readable pages of the image. Zero copies return `StringNotFound`. The linker pools identical strings, so a second copy returns `StringAmbiguous`.
2. Phase 2 finds the single RIP-relative reference in the executable pages whose target is that string. Zero references return `NoReference`, and more than one returns `AmbiguousReference`.

A truncated sweep that observed no second copy or reference returns `IncompleteScan`, in either phase. An observed second copy or reference stays ambiguous even when the sweep is also truncated. Phase 2 runs both of its sweeps over one set of executable windows (`[B-61]`).

```cpp
sc::StringRefQuery query{
    .text = "Assertion failed: m_world != nullptr", // a long, specific, once-used literal
    .encoding = sc::StringEncoding::Utf8,            // Utf16le for L"" / wchar_t literals
    .require_terminator = true,                      // no match on a prefix of a longer string
    .return_mode = sc::XrefReturn::ReferencingInstruction,
    .broad_match = false,
};
const auto site = sc::find_string_xref(query); // defaults to Region::host()
if (!site)
{
    DetourModKit::log().error("string xref failed: {}", DetourModKit::to_string(site.error().code));
    return false;
}
// *site is the address of the `lea`/`mov` that loads the string.
```

Phase 2 has two modes. Both apply the same exact-target and single-reference guards:

- Default (`broad_match = false`): a shape scan for the dominant 64-bit string loads, `REX.W lea` / `mov reg, [rip+disp32]`. These shapes delimit themselves, so the scan needs no instruction alignment and does not desync on data inside `.text`.
- `broad_match = true`: keeps the default scan and adds a Zydis decode sweep. The sweep matches any RIP-relative memory operand that resolves to the string, such as `cmp [rip+d], imm`, `push [rip+d]`, or a no-REX `lea` / `mov`. A reference that both scans find counts once. If the default reports `NoReference` for a string that you know is referenced, use broad mode. It costs extra decode work.

A shape that the active mode does not model reports an error rather than a guess. Neither mode models an indirect `call` / `jmp` through a `.data` pointer that holds the string address. Choose a string that is referenced exactly once, because the linker pools short, common strings. Phase-2 uniqueness is uniqueness among the *scanned shapes*, not global uniqueness. With `broad_match = false`, the default `ReferencingInstruction` return does not see a second reference of an unmodeled shape, and its site still references the string. A derived return runs the broad sweep after one narrow hit and fails closed on that second reference (`[B-63]`).

Three return modes select the result:

- `XrefReturn::ReferencingInstruction` (default): the load site.
- `XrefReturn::EnclosingFunction`: the entry of the function that contains the load, from `.pdata` through `RtlLookupFunctionEntry`, with a bounded RET/INT3 back-scan fallback (`[B-64]`).
- `XrefReturn::StringPointerSlot`: the global slot that caches the loaded string pointer.

`StringPointerSlot` applies when the unique reference is a `lea reg, [rip+string]` that a `mov [rip+slot], reg` of the same register follows within a bounded forward window. It returns the effective address of that slot. A `mov` load, a register mismatch, a store outside the window, a broad-only reference, or no store returns `ErrorCode::StoreNotFound`. The walk accepts the first such store without a uniqueness check. It stops at a write to the loaded register, a `CALL`, a decode failure, an unreadable byte, and each boundary that `[B-76]` lists. A clobbered register therefore yields no slot rather than a wrong one.

## Code constants (`read_code_constant`)

`read_code_constant` reads a constant inside an instruction, such as an array stride or a struct displacement. Declare a candidate ladder that lands **on** the instruction, plus the operand to read. The function decodes the live instruction and returns the current value.

```cpp
const std::array<sc::Candidate, 1> k_stride_site{{
    sc::Candidate::direct("equip-stride",
        sc::Pattern::literal("48 6B C0 ?? 48 03 ??")),
}};

sc::CodeConstant cc{};
cc.site = k_stride_site;
cc.kind = sc::OperandKind::Immediate; // or MemoryDisplacement
cc.operand_index = 2;                  // index into the VISIBLE operands

const auto stride_result = sc::read_code_constant(cc); // scope defaults to Region::host()
if (stride_result)
    g_equip_stride = static_cast<std::size_t>(*stride_result);
```

- **Always decodes.** `cc.nominal` is a telemetry hint, never a return short-circuit, so a stride that changed from 88 to 96 returns 96. Set `cc.has_nominal = true` to make `nominal` meaningful.
- **Visible operands.** `operand_index` counts the operands that a disassembler shows, not implicit ones. In `imul rax, rax, imm8` above, index 2 is the immediate.
- **Byte width.** A `[rip + disp]` operand returns its absolute target at full width. For other operands, `byte_width` 1 through 8 keeps that many low-order bytes and sign-extends them, and 0 keeps the decoded value.
- **Code sites only.** The site scan uses `Pages::Executable`. A candidate whose final site is not execute-readable is skipped, so a later candidate can win. If none can, the function returns the typed `resolve` error unchanged.
- **Typed failures.** The selected site returns `DecodeFailed` when it loses executable protection before the decode, no longer decodes, or crosses into a non-executable page. A wrong operand kind returns `UnexpectedShape`, and an index out of range returns `OperandOutOfRange`.
- **Decode epoch.** The value decodes from a fresh snapshot after site resolution. A byte candidate must still match its span at that epoch, or the function returns `ErrorCode::EvidenceMismatch` (`[B-75]` in `scan.hpp`).

Zydis stays inside the DetourModKit implementation. Consumers do not include or link it.

## Worked examples

### Hook the target of a `call rel32`

```cpp
namespace hk = DetourModKit::hook;

const auto pat_result = sc::Pattern::compile("E8 ?? ?? ?? ?? 48 89 43 10");
if (!pat_result) return;

const auto hit = sc::scan(*pat_result, DetourModKit::Region::host(), 1, sc::Pages::Executable);
if (!hit) return;

// *hit points at 0xE8. The call is 5 bytes with its rel32 at offset 1.
const auto target = sc::resolve_rip_relative(*hit, /*displacement_offset=*/1, /*instruction_length=*/5);
if (!target) return;

// inline_at takes the resolved Address and returns a disabled, move-only Hook.
auto installed = hk::inline_at(hk::InlineRequest{.name = "callee_hook", .target = *target}, &Detour_Callee);
```

Publish the returned handle before you call `enable()`, as [Install one hook](../guides/minimal-core.md#install-one-hook) shows. `hook::Target` in [hook.hpp](../../include/DetourModKit/hook.hpp) also accepts an `OwnedScanRequest`. The install resolves that request through `scan::resolve`.

### Resolve a global pointer from `mov rax, [rip+disp32]`

```cpp
// Search 64 bytes from the match for the mov, then resolve.
const auto ptr_addr = sc::find_and_resolve_rip_relative(
    DetourModKit::Region{*hit, 64},
    sc::PREFIX_MOV_RAX_RIP, /*instruction_length=*/7);
if (!ptr_addr)
{
    DetourModKit::log().error("mov rax, [rip+disp32] not found: {}",
                              DetourModKit::to_string(ptr_addr.error().code));
    return;
}

// ptr_addr is the absolute address of the pointer slot, not the pointee.
auto global_ptr = DetourModKit::memory::read<std::uintptr_t>(*ptr_addr).value_or(0);
```

### Second occurrence with an offset marker

```cpp
// Use the second hit (for example the one inside the setter, not the reader).
static constexpr auto k_pattern =
    sc::Pattern::literal("48 8B 88 B8 00 00 00 | 48 89 4C 24 68");

const auto hit = sc::scan(k_pattern, DetourModKit::Region::host(), /*occurrence=*/2, sc::Pages::Executable);
if (!hit) return;

// *hit already lands on `mov [rsp+0x68], rcx`, because scan() applied Pattern::offset().
const DetourModKit::Address anchor = *hit;
```

## Check a hit before use

- `scan::is_likely_function_prologue(addr)` reads one byte under a fault guard and rejects `0x00`, `0xCC`, `0xC2`, and `0xC3`. Every other first byte passes. A prologue that another mod already hooked starts with `0xE9`, `0xEB`, or `0xFF`, so it also passes. Gate a code hit through it before you pass the address to a hook verb.
- `memory::is_readable(DetourModKit::Region{addr, n})` checks that a whole span is committed and readable. Call it at setup before a read of more than one byte.

```cpp
if (!DetourModKit::scan::is_likely_function_prologue(resolved_addr))
{
    return; // scan poison: zero page, alignment pad, or bare RET
}
```

## Common failures

- **`Pattern::compile` returns `BadPattern`.** A token is malformed, a hex token has three digits, or a `|` is stray. `result.error().extra` holds the numeric `PatternStatus` (`TooLong`, `InvalidToken`, `InvalidJump`, `DuplicateOffset`, `TooManyJumps`, `Empty`), and `message()` prints it as `extra=N`. Neither names the token.
- **`scan::scan` returns `NoMatch` every time.** A fixed byte or nibble in the pattern differs from the binary, or the scope or `Pages` class excludes the site. Print a few hex dumps around the expected site. Compare each fixed byte with the pattern.
- **`scan::scan` returns `IncompleteScan` or `BudgetExceeded` on a signature that worked before or on another machine.** A page faulted mid-scan under the TOCTOU guard (a concurrent decommit / reprotect), or a bounded-jump scan exhausted its work budget. The page-gated sweep fails closed, because the Nth match can lie in skipped or unexamined bytes. Retry or re-scope the scan. If the pattern has an excessively broad bounded jump, simplify it.
- **`resolve_rip_relative` returns `UnreadableDisplacement`.** The match landed inside a guard page or at a region edge. Check the `displacement_offset` and `instruction_length`.
- **The signature works locally but fails on another machine.** A packer or anti-cheat layer transforms the module between load and scan. Use `Region::whole_process()` with `Pages::Executable`.
- **A multi-GB scan is slow.** The only literal bytes in the pattern are common (`48 8B`, `E8`). Add a rarer byte to the first segment.

## Related

- Design and `[B-nn]` rules: [resolution.md](../design/resolution.md), [memory-scanning.md](../design/memory-scanning.md).
- Guides: [anchors.md](../guides/scanning/anchors.md), [signature-manifest.md](../guides/scanning/signature-manifest.md), [signature-health.md](../guides/scanning/signature-health.md), [rtti-walker.md](../guides/rtti/rtti-walker.md), [minimal-core.md](../guides/minimal-core.md).
- Contracts and proofs: [scan.hpp](../../include/DetourModKit/scan.hpp), [test_scan_resolve.cpp](../../tests/test_scan_resolve.cpp), [test_pattern.cpp](../../tests/test_pattern.cpp), [test_scanner.cpp](../../tests/test_scanner.cpp).

### External references

- [omni's hackpad: Fixing Hacks When a Game Gets Patched](https://badecho.com/index.php/2021/10/05/fixing-hacks-after-patch/)
- [Reloaded II Cheat Sheet: Signature Scanning](https://reloaded-project.github.io/Reloaded-II/CheatSheet/SignatureScanning/)
- [UE4SS: Fixing missing AOBs (advanced)](https://docs.ue4ss.com/dev/guides/fixing-compatibility-problems-advanced.html)
- [Guided Hacking: C++ Signature Scan Tutorial](https://guidedhacking.com/threads/c-signature-scan-pattern-scanning-tutorial.3981/)
- [AlliedModders Wiki: Signature Scanning](https://wiki.alliedmods.net/Signature_scanning)
