# AOB signature scanning guide

Practical reference: how to build, maintain, and resolve array-of-bytes (AOB) signatures with DetourModKit's `scan` module.

## Background: what an AOB is and why

An **AOB** (array of bytes, also called a **signature** or **sigscan**) is a short byte sequence picked from the `.text` section of a target binary. It uniquely identifies an assembly instruction, or a small run of instructions, at runtime. Tools like DMK's `scan` module walk memory looking for that sequence and return the matching address.

Why it matters for modding:

- Module bases change on every process launch on Windows (ASLR), and absolute offsets change with every compiler build. A hard-coded RVA fails the next patch day.
- Signatures bind to the **instruction semantics**, not to the binary layout. Good signatures survive many patches. Great ones survive entire major version bumps.
- Once an AOB locates the instruction, DMK's hook manager or a `Result<Address>` RIP resolver takes over. The result is an absolute address you can hook, read, or call.

Two rules set the ceiling on signature quality:

- **Sign CODE, not DATA.** Assembly instructions move when code recompiles, but compilers reshuffle *order* far more often than they change *opcodes* for the same source line. Data tables (strings, vtables, constants) move even more aggressively and make a poor anchor.
- **Wildcard anything the compiler or linker can move.** The normal suspects are immediate values, RIP-relative displacements, jump targets, RVAs, vtable offsets, and register indices inside VEX prefixes.

## How to find a patch-proof signature

A patch-proof signature is short and unique. It contains only bytes that describe **opcodes and register encodings**, with wildcards over everything the linker or compiler is free to renumber.

### Workflow in IDA / Ghidra / x64dbg

1. **Locate the instruction you want to hook.** Prefer a load or store whose target is the value you care about, or the first instruction of a function whose prologue is distinctive.
2. **Copy the raw bytes** of 12 to 32 bytes around it (enough to span 3 to 6 instructions).
3. **Wildcard volatile operands.** For each instruction in the window:
   - Wildcard all immediate operands (8-, 16-, 32-, 64-bit) and RIP-relative displacements (`disp32`) with one `??` token per byte.
   - Replace RVAs and jmp/call targets with `??`s.
   - Keep opcodes, ModRM bytes, REX prefixes, register selectors.
4. **Shrink.** Start with the minimum that returns a single hit in the target module. Grow one instruction at a time if duplicates appear.
5. **Validate against at least three game versions or builds**, ideally with one version you know was compiled differently. Signatures that survive only one build are brittle by construction.

> Platform scope: this guide assumes Windows x64. That means module-base resolution through the PE loader, RIP-relative `disp32` encoding, and the `PAGE_EXECUTE_*` protection flags that `VirtualQuery` enforces. On 32-bit x86, the displacement forms, prefix tables, and ABI details differ. On non-Windows targets, the page-protection taxonomy and module enumeration APIs are entirely different. The `Pattern` value type and its DSL parser are backend-free C++23, but the page-gated scanner, the RIP / string / code-constant resolvers, and prologue recovery are Windows x86-64 only. The architecture gate in `defines.hpp` (`DMK_ARCH_X64`) fails a 32-bit or non-x86 configure outright, and the page walks and fault guards are Win64-specific. Treat this guide and every resolver in it as Windows x64.

### Byte-by-byte anatomy of a good signature

Given the instruction

```text
; 7 bytes total
48 8B 05 ?? ?? ?? ??       mov rax, [rip + <player_ctx_rva>]
```

`48` is the REX.W prefix (64-bit operand), `8B` is `MOV r64, r/m64`, and `05` is the ModRM byte that encodes `rax, [rip + disp32]`. The next four bytes are a `disp32` that the linker recomputes every build. A wildcard over those four bytes gives a 7-byte signature that works across almost every rebuild. It fails only when the target register changes or the instruction is replaced.

If you need higher uniqueness, chain one or two adjacent instructions:

```text
48 8B 05 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ??
; mov rax, [rip+disp32]
; test rax, rax
; je   rel32
```

That chain is distinctive without committing to any of the shifting fields.

### Anchoring rules of thumb

| Situation | What to do |
| --------- | ---------- |
| Signature returns multiple hits | Add bytes forward or backward, or add a unique neighboring instruction. Do not pad it with more wildcards |
| Signature uses a static address | Wildcard the disp32/imm and widen with a neighbor. Never bake an address into the signature body |
| Only one copy in the file but spans padding | Watch for `CC`/`90` alignment bytes. Linkers rebalance padding, so do not cross those boundaries |
| Function inlined differently between builds | Move the anchor to the callee, or pick a caller whose prologue is still unique |
| Anti-tamper or packer rewrites bytes | Use `scan::scan` with `Region::whole_process()` and `Pages::Executable` (searches anonymous executable pages) and plan on a multi-candidate fallback |

## DMK pattern syntax reference

Parsed by `scan::Pattern::compile(std::string_view)` ([include/DetourModKit/scan.hpp](../../include/DetourModKit/scan.hpp)). Tokens split on whitespace (space, tab, `\r`, `\n`, `\f`, `\v`). Leading or trailing whitespace is ignored.

| Token | Meaning |
| ----- | ------- |
| `48`, `8B`, `FF` | Literal byte. Must be exactly two hex digits. Case-insensitive. |
| `??` | Wildcard byte: any value matches at this position. |
| `?` | Same as `??`. Accepted for brevity. |
| `4?`, `?A` | Per-nibble wildcard: the hex digit is fixed, the `?` nibble is free. Use it when one nibble is invariant across builds, for example a ModRM reg or r/m field. |
| `[X-Y]`, `[X]` | Bounded jump: skip `X` to `Y` bytes. `[3]` means `[3-3]`. Unlike a `??` run, it tolerates a gap whose *size* shifts between builds. The unbounded YARA `[X-]` form is rejected. |
| `\|` | Offset marker: `Pattern::offset()` records the next token's position, or one past the last byte at pattern end. At most one. A jump before it adds its actual gap size at match time. |

`scan::Pattern::compile` returns `Result<Pattern>` (an `std::expected<Pattern, Error>`). It returns a `BadPattern` error on any malformed token. Malformed tokens include `"GG"`, `"1FF"`, three-character tokens, and a second `|`. A jump is malformed when it is inverted or unbounded (`"[5-2]"`, `"[2-]"`). A jump that leads or trails the pattern is also malformed, as are two adjacent jumps and more than `MAX_PATTERN_JUMPS` gaps. The pattern therefore always splits into non-empty fixed segments. Empty or whitespace-only input is a parse failure. The compile-time variant `scan::Pattern::literal(dsl)` is `consteval`, so a malformed literal is a build error rather than a runtime failure.

Caps: a value `Pattern` stores its bytes inline, so `literal()` / `compile()` accept at most `MAX_PATTERN_BYTES = 128` fixed bytes. An over-cap pattern yields a `BadPattern` with a `TooLong` status. A pattern carries at most `MAX_PATTERN_JUMPS = 8` bounded gaps, and each gap skips at most `MAX_JUMP_SPAN = 256` bytes. Each start position is bounded to `SEGMENT_MATCH_STEP_BUDGET = 65536` backtracking node visits. The internal scanner also retains one total bounded-jump budget across every start and Nth-occurrence suffix continuation of a physical region. An adversarial signature therefore cannot reset its work cap by producing many matches. When another node visit exceeds that budget, the sweep is incomplete. All public scan paths then fail closed rather than return a later match with an unproven occurrence number. The internal string-xref engine parses the same grammar through a heap-backed path with no byte cap, but that is not the public `Pattern` type.

The scan prefilter anchors on a single fully-known byte, because `memchr` cannot search for a partial nibble. A per-nibble token is therefore never chosen as the anchor, so give a nibble-heavy pattern at least one full literal byte for a fast scan. A pattern made entirely of nibble tokens still resolves correctly. It falls back to a masked compare at every position, with no prefilter, and is correspondingly slower. With a bounded jump, the anchor is chosen from the first fixed segment, the run before the first `[...]`. The scanner locates that segment, then extends across the gaps, so give the leading segment a distinctive literal byte.

Example with an offset marker:

```text
"48 8B 88 B8 00 00 00 | 48 89 4C 24 68"
```

The `|` sits after seven literal bytes, so `Pattern::offset() == 7`. This lets you anchor on a wide distinctive window while hooking the second instruction in the chain.

Example with a bounded jump:

```text
"48 8B 05 ?? ?? ?? ?? [2-6] E8 ?? ?? ?? ??"
```

The two known instructions (`mov rax, [rip+disp32]` and a `call rel32`) are separated by a 2-to-6-byte gap that absorbs an intervening instruction whose length varies between builds. The 12 fixed bytes, 7 in the first segment and 5 in the second, frame the gap. `Pattern::segment_count()` is 2 here, and `Pattern::min_match_length()` / `max_match_length()` report the 14-to-18-byte span a match can occupy.

## Scan API tour

Public namespace: `DetourModKit::scan`. Domain failures return as `Result<T>` (`std::expected<T, Error>`). `scan`, `resolve_batch`, and the RIP helpers are `noexcept` and convert even allocation failure into an `Error{OutOfMemory}`. `resolve`, `find_string_xref`, and `read_code_constant` are not `noexcept` and can still throw `std::bad_alloc` on allocation failure. If you need a hard no-throw guarantee, wrap those at a startup boundary.

Throughout the examples below, `sc` abbreviates `DetourModKit::scan`, declared once per example block with `namespace sc = DetourModKit::scan;`. Every other library symbol is spelled with the full `DetourModKit::` prefix, so each block compiles against only the includes it shows.

### Compile once, scan many

`scan::Pattern::compile()` parses the AOB DSL string and returns a `Result<Pattern>`. Compile at startup and reuse the value. Compilation is cheap but not free.

```cpp
#include <DetourModKit/scan.hpp>

namespace sc = DetourModKit::scan;

const auto pattern_result = sc::Pattern::compile("48 8B 05 ?? ?? ?? ?? 48 85 C0");
if (!pattern_result)
{
    // malformed string; check pattern_result.error().message() for the reason
    return false;
}
const sc::Pattern& pattern = *pattern_result;
```

For a compile-time literal, use `sc::Pattern::literal(dsl)`. It is `consteval`, so a malformed DSL is a build error:

```cpp
static constexpr sc::Pattern k_pattern = sc::Pattern::literal("48 8B 05 ?? ?? ?? ??");
```

### Scanning a module range

Use `scan::scan(pattern, scope, occurrence, pages)` with a `Region` scope. `Region::module_named("game.exe")` limits the sweep to a single module image.

```cpp
const auto scope = DetourModKit::Region::module_named("game.exe");
const auto match = sc::scan(pattern, scope, 1, sc::Pages::Executable);
if (!match)
{
    return false;
}
// *match is the Address of the `|`-marked byte (or the pattern start
// when no `|` marker is present). scan() applies Pattern::offset() internally;
// do NOT add it yourself.
const DetourModKit::Address target = *match;
```

### Nth occurrence

Pass the occurrence argument (1-based):

```cpp
const auto third = sc::scan(pattern, scope, 3, sc::Pages::Executable);
```

Passing `0` yields `ErrorCode::NoMatch` by contract.

### Process-wide scan

Use `Region::whole_process()` as the scope with `Pages::Executable` when the target binary is packed or decrypted into anonymous executable pages. Use it too when the owning module is not yet known. It walks `VirtualQuery` and scans every committed `PAGE_EXECUTE_READ*` region that is not a guard page.

```cpp
const auto match = sc::scan(pattern, DetourModKit::Region::whole_process(), 1, sc::Pages::Executable);
```

Pure-execute pages (`PAGE_EXECUTE` with no read bit) are skipped deliberately, because such pages are not guaranteed readable. Only `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, and `PAGE_EXECUTE_WRITECOPY` regions are inspected. Guard and no-access pages are skipped unconditionally.

The `scan::unchecked::find_pattern(region, pattern, occurrence)` twin performs no page filtering and uses raw SIMD loads. Use it only when you can guarantee that every byte in `region` is committed and readable.

> Do not scan on the render thread. A full-module sweep can run into the tens of milliseconds, and a process-wide walk can exceed an entire frame budget on a large game. Resolve signatures at startup, on a loading screen, or on a background worker, and cache the resulting addresses.

### SIMD tier

```cpp
switch (sc::active_simd_level())
{
case sc::SimdLevel::Avx512: /* 64 bytes/iter -- opt-in DMK_ENABLE_AVX512 build on an AVX-512F+BW host */ break;
case sc::SimdLevel::Avx2:   /* 32 bytes per iteration */ break;
case sc::SimdLevel::Sse2:   /* 16 bytes per iteration */ break;
case sc::SimdLevel::Scalar: /* byte-by-byte fallback */  break;
}
```

`Avx512` is reported only in a `DMK_ENABLE_AVX512` build on an AVX-512F+BW host. Otherwise the highest available lower tier is reported. `sc::to_string(level)` gives the tier name, useful for logging and for a decision on whether to run a large scan at boot or defer it.

### Anchor heuristic and why sparse bytes scan faster

Internally the scan engine does NOT scan byte-by-byte from the start of the pattern. It inspects every non-wildcard byte, scores each against a small frequency table, and picks the rarest one as the anchor. The table, in rough order of frequency in typical x64 `.text`, is `0x00`, `0xCC`, `0x90`, `0xFF`, `0x48`, `0x8B`, `0x89`, `0x0F`, `0xE8`, `0xE9`, `0x83`, `0xC3`. Every other byte scores as rarest. The anchor byte drives a `memchr` sweep, and the full pattern is verified only at positions where `memchr` finds the anchor.

Implication: a pattern whose literal bytes are all REX prefixes or common opcodes (`48 8B`, `48 89`, `FF 15`, `E8 ?? ?? ?? ??`) has no rare anchor. The scanner then verifies at almost every address. Add at least one uncommon byte, any byte outside the frequency table. The scan then typically drops from tens of milliseconds to sub-millisecond on a full-module sweep. Given a choice between two otherwise equivalent anchors, pick the one with a rarer byte.

Two tiers choose the anchor. The frequency table above is the compile-time selector a `Pattern` caches, and it is exactly what `unchecked::find_pattern` uses. Page-gated `scan()` and byte-tier `resolve()` refine it. They sample a bounded byte histogram from the searched scope. When the sample is large enough, they re-pick the rarest fully-known **segment-0** byte as observed in this image, and that pick overrides the static score. The override is correctness-neutral, because a full masked compare still decides acceptance. It is what makes a rare-byte anchor pay off on a given target. Nibble tokens and bytes after a bounded jump are never anchor candidates.

### Scanning data sections

`Pages::Executable` filters to execute-readable pages, so it cannot reach `.rdata` / `.data`. When the target is data rather than code, use `Pages::Readable` (the default). It accepts every committed readable region: `PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_WRITECOPY`, and the three execute-readable variants. It therefore reaches C++ vtables, RTTI type descriptors, localized string pools, and read-only metadata tables.

```cpp
const auto match = sc::scan(pattern, DetourModKit::Region::host(), 1, sc::Pages::Readable);
```

It applies `Pattern::offset()` exactly once, identically to `Pages::Executable`. The accepted set is a strict superset, so a pattern present in `.text` is found by both. Guard pages (`PAGE_GUARD`), no-access pages ( `PAGE_NOACCESS`), and uncommitted regions are skipped and never dereferenced.

The scope must be confined. A readable sweep reads every committed readable page it covers. That includes the allocator pages that hold a caller's own copies of the query bytes. DMK cannot prove a wide readable hit is the target rather than the query finding itself. It always excludes the query representations it owns. Those are the compiled pattern's byte and mask buffers, the `scan::Pattern` object's storage, and the candidate ladder with its owned literals. A copy the caller retained is undiscoverable. A `Pages::Readable` scope confined to one mapped image or one reserved allocation is accepted. A wider one, `Region::whole_process()` or any span that crosses many allocations, fails closed with `ErrorCode::NotAuthoritative`. Narrow the scope, or declare your retained copies through the exclusion-taking `scan::scan` overload or `ScanRequest::exclusions`. A switch to `Pages::Executable` also clears the failure. Query bytes are data and never sit on a code page, so whole-process code discovery is unaffected.

Two costs come with the wider reach:

- **More bytes inspected.** A typical x64 game maps hundreds of MB of data against tens of MB of code. A readable sweep can therefore run several times longer than an executable one. Resolve at startup or on a worker, never on the render thread, and cache the result.
- **Higher collision risk.** `.rdata` pointer tables and constant pools look random, so a pattern unique in `.text` can collide in data. Supply at least 8 literal bytes and verify the hit through an occurrence count or a follow-up structural check.

#### Prefer an RTTI name anchor over a raw vtable header

The obvious data signature for a class is its vtable header: the RTTI Complete Object Locator pointer followed by the first few virtual-function pointers. The trap is that every one of those qwords is an *absolute, relocated* pointer: `value = image_base + RVA`. On x64 the image base is at least 64 KiB aligned. Only the low 2 bytes of each pointer are invariant across launches, and the higher bytes move with the ASLR slide. A "24-byte vtable header" therefore yields only about 6 reliably stable literal bytes unless the module happens to load at its preferred base. So few stable bytes inflate the collision risk above.

The robust anchor is the RTTI **type-descriptor name** string itself, for example the mangled `.?AVClassName@ns@@`. It is plain ASCII baked into the binary, fully ASLR-invariant, and tens of literal bytes long, so it effectively never collides. The flow is:

1. Use `scan::scan` with `Pages::Readable` to search for the mangled name string and find the `TypeDescriptor`.
2. Walk the MSVC RTTI structures from the descriptor to the vtable. [rtti-walker.md](../guides/rtti/rtti-walker.md) documents the COL / TypeDescriptor / self-RVA layout the `rtti` module already encodes.

This pairs with the `rtti` walker's opposite direction (vtable to name). One finds a vtable from a known name, the other recovers a name from a known vtable.

#### Using the readable scanner inside a cascade

Set `ScanRequest::scope` to `Region::module_named("game.exe")` (or `Region::host()`) and leave `pages` at its default (`Pages::Readable`) to resolve a candidate whose signature lives in a data section. `Candidate::direct` with `walk_back = 0` returns the match address directly, which is exactly the data address for a data-section scan.

A non- `Off` `fallback_policy` is intentionally a code-path concern: its recovery path rebuilds a hooked near-JMP prologue, which is meaningless for a data match.

#### Module-scoped scan (single unpacked PE)

When every hook target lives inside one unpacked module (a normal game DLL/EXE), set `ScanRequest::scope` to `Region::module_named("game.exe")`. The resolver rejects any candidate whose resolved address falls outside that region. A generic-shaped candidate (a stock compiler prologue, a `mov reg,[rip] ... ret` epilogue) can also appear in another injected module (a graphics overlay, a sibling mod). Such a candidate therefore cannot shadow the correct in-module match. The resolver is first-match-wins, so that bounds check lives inside the loop.

```cpp
const sc::ScanRequest req{
    .ladder = k_candidates,
    .label = "frustum",
    .scope = DetourModKit::Region::module_named("game.exe"),
};
const auto hit = sc::resolve(req);
```

One scope covers both `.text` and `.rdata` / `.data` candidates through the `Pages::Readable` default. `ErrorCode::NoMatch` is returned when no candidate resolves. The resolver never falls back to a whole-process scan, which re-introduces the cross-module shadowing the scoped request exists to prevent. With a non- `Off` `fallback_policy`, the rewritten near-JMP must be found inside the scope. Its jump destination can still point at a sibling mod's trampoline outside the module.

For a hook target, a signature that must land on an instruction rather than data, prefer `scan::borrow_code_target(ladder, label, scope)` over a hand-built request. It presets the code-target policy in one place:

- `Pages::Executable`, so an instruction signature cannot alias an identical byte run in `.rdata` / `.data`,
- `require_executable_result`, so every backend's final result is also code,
- `CandidateOrder::UniqueFirst`,
- a `WarnOnly` fallback policy (pass `RequireIdentity` plus a `fallback_witness` to fail closed on a recovered near-twin),
- `require_unique` kept true.

`Pages::Executable` narrows only the byte tiers. The final-result gate also rejects a RIP-relative byte match that resolves into data, plus any RTTI or string-xref result that is not executable. Keep the default `Pages::Readable` (or `borrow()`) for a data / RTTI / string target.

```cpp
const auto hit = sc::resolve(
    sc::borrow_code_target(k_candidates, "frustum", DetourModKit::Region::module_named("game.exe")));
```

> Use a named-module scope only for a single contiguous mapped image. For packed or protected targets whose code is unpacked into separate `VirtualAlloc` regions, use `Region::whole_process()` with `Pages::Executable`.

#### Requiring a unique match (`require_unique`)

A resolver returns the first candidate that resolves uniquely, and a single scan returns the lowest-address match. A loose pattern that matches several functions therefore wins on whichever address sorts first. That is usually not the intended one, and it cannot be recovered after the fact, because the resolver already committed. A module-scoped scan removes *cross-module* collisions, but two functions inside the same module can still share a generic prologue. That is an authoring problem, solved by a more specific signature, not something the scan scope can fix.

By default (`ScanRequest::require_unique = true`) the resolver verifies a candidate matches exactly once in the scoped region. If a second match exists, the candidate is ambiguous and the resolver falls through to the next one. That turns a silent wrong hit into a clean fall-through. When no candidate is provably unique, the resolver returns an error rather than a confidently wrong hook. The caller can surface it as "the binary changed, update the signatures".

Set `require_unique = false` only for a candidate you deliberately made non-unique and separately verified. An example is a last-resort broad net whose first in-scope match you verify with your own post-resolution check. It is an eyes-open escape hatch for an author who takes responsibility for the ambiguity, not a way to tolerate a loose signature. Prefer to tighten the pattern so it is unique. The flag is per-request, so build an `OwnedScanRequest` or a per-entry request if you need different policies per candidate:

```cpp
const std::array<sc::Candidate, 3> k_frustum{{
    // Unique mid-body anchor. If a build update makes it match twice, fall through.
    sc::Candidate::rip_relative("Frustum_P1_MatrixGlobalRef",
        sc::Pattern::literal("48 8B 05 ?? ?? ?? ?? 0F 28 00 0F 29 41 10"),
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

> Behavior note: the default is uniqueness-required. A signature that matches more than once almost always needs tightening rather than a guess at a target. The default therefore surfaces the ambiguity as a `ErrorCode::NoMatch` you can act on, rather than a hook on an arbitrary match. Only set `require_unique = false` on a candidate you intentionally made non-unique and verified yourself.

Construction note: `Candidate::rip_relative` throws `std::invalid_argument` on four conditions:

- a negative `displacement_at`,
- a disp32 that overruns the instruction,
- a length above x86-64's 15-byte maximum,
- a pattern suffix from its `|` result marker that does not cover all four displacement bytes.

The guarded sweep captures the full instruction privately before semantic decode, so trailing instruction bytes need not be part of the authored pattern. The target-authorizing disp32, however, must be part of its returned evidence.

### Batch scanning many signatures in parallel (`resolve_batch`)

When a mod resolves dozens of signatures at startup, use `scan::resolve_batch` to run them concurrently through an opt-in fork-join worker pool. The wall-clock cost is then roughly the slowest single resolve rather than the sum.

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

- **Whole-batch signal.** The outer `Result` fails with `Error{OutOfMemory}` only when the per-request result container itself cannot be allocated. A caller therefore cannot silently proceed on a truncated batch. This is the same shape as `hook::install_all`.
- **Input-order results.** Inside the unwrapped vector, `(*batch)[i]` always corresponds to `views[i]`, regardless of which worker finished first.
- **Per-request fail-closed.** A failure in one request never poisons the rest. `(*batch)[i].error()` carries the `Error` for that slot.
- **Read-only sharing, no cloning.** `Pattern` is value-semantic and immutable. Workers share the caller's compiled patterns directly with no re-derive.
- **Worker count.** `0` (the default) uses `std::thread::hardware_concurrency()` clamped to the request count, and the calling thread participates. A single-item batch runs inline with no thread spawn.

> Setup/control-plane only. `resolve_batch` is noexcept by contract but spawns a worker pool internally. Call it at startup or on a background worker, never from a hook or input callback, and never under the loader lock.

## RIP-relative resolution

x86-64 code uses RIP-relative addressing heavily. The 4-byte displacement stored inside the instruction is relative to the address of the *next* instruction: `target = instruction_address + instruction_length + disp32`. DMK exposes two helpers and a set of prefix constants.

### Two-step: find the match, then resolve

Best when the instruction is part of a wider signature, or when the disp32 is not at the end. An immediate suffix after the disp32 is the common example.

```cpp
const auto scan_result = sc::scan(pattern, scope, 1, sc::Pages::Executable);
if (!scan_result)
    return false;

const DetourModKit::Address hit = *scan_result;
// Suppose the matched instruction is `mov rax, [rip+disp32]` (7 bytes, disp32 at offset 3).
const auto resolved = sc::resolve_rip_relative(hit, /*displacement_offset=*/3, /*instruction_length=*/7);
if (!resolved)
{
    DetourModKit::log().error(
        "RIP resolve failed: {}",
        DetourModKit::to_string(resolved.error().code));
    return false;
}

const DetourModKit::Address absolute = *resolved;
```

Error values (all unified under `ErrorCode`):

| ErrorCode | Meaning |
| --------- | ------- |
| `NullInput` | null instruction address (`resolve_rip_relative`), or a null search region / empty opcode prefix (find-and-resolve) |
| `InvalidArg` | malformed RIP-relative layout: the disp32 does not fit inside an x86-64 instruction of at most 15 bytes |
| `RegionTooSmall` | (find-and-resolve) the search region is shorter than the prefix plus its 4-byte disp32 |
| `PrefixNotFound` | (find-and-resolve) the opcode prefix never occurs in the search region (an all-decoy region instead surfaces the last decode failure below) |
| `UnreadableDisplacement` | the SEH fault guard failed to read the disp32 bytes |
| `ImplausibleTarget` | the resolved address is not a plausible user-mode pointer (a corrupt displacement that resolves to 0, a low guard-page address, or a kernel-range value) |

### One-step: find the prefix and resolve in the same call

Best when the opcode you want to hook has its disp32 **immediately after the prefix you supply** (for example `E8 disp32`, `E9 disp32`, `48 8B 05 disp32`). DMK ships ready-made prefix constants in `scan.hpp` under the `scan::` namespace:

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
    DetourModKit::Region{hit, 64},      // short search window from the match
    sc::PREFIX_CALL_REL32,            // E8
    /*instruction_length=*/5);        // E8 + disp32
```

`find_and_resolve_rip_relative` is **first-resolvable-prefix-wins**. It resolves the first location whose bytes match `opcode_prefix` AND whose disp32 resolves to a plausible, readable target. An earlier occurrence whose displacement is unreadable or resolves to an implausible address is treated as a coincidental decoy and skipped. The scan continues to the next occurrence. It fails only after the whole region is exhausted, and surfaces the last concrete decode failure, or `PrefixNotFound` when no prefix occurred at all. Its prefix search reads `search` directly with no page filtering, so the caller must guarantee that region is committed and readable. Use it over a region already known readable, such as a located function body. To resolve a single instruction whose address is uncertain, prefer `resolve_rip_relative`, whose displacement read is fault-guarded. When a signature can be ambiguous, anchor it through `resolve()`, the candidate ladder that enforces per-candidate uniqueness, instead of a wider search window. The resolved target is gated by the same `ImplausibleTarget` check as `resolve_rip_relative`.

### What these helpers will not resolve

`resolve_rip_relative` deliberately understands only the 32-bit signed displacement form. The following need manual handling:

- Short jumps (`EB rel8`, `Jcc rel8`) with 8-bit displacements.
- 16-bit displacements and legacy `EA ptr16:32` far jumps.
- Indirect calls through memory: `FF 15 disp32` and `FF 25 disp32`. The disp32 points to a **pointer**, and DMK returns the pointer's address, not the final target. Dereference it yourself.
- Some instructions interrupt the disp32 with a SIB byte combination or a VEX/EVEX prefix boundary. For those, supply your own longer `opcode_prefix` that covers up to the disp32 start.

### String-reference anchors

When the most stable thing about a target is the text it uses, anchor on the string instead of the code. `find_string_xref` is a two-phase, fail-closed resolve scoped to one module image:

1. Locate the literal in the image's readable pages (`.rdata` / `.data`). The linker pools identical strings, so a second occurrence is treated as ambiguous and the resolve fails closed (`StringAmbiguous`).
2. Scan the image's execute-readable pages for the single RIP-relative reference whose resolved absolute target is that string, and return it. Zero references is `NoReference`. More than one is `AmbiguousReference`.

Both phases also fail closed on incompleteness. If a page-gated window faults mid-scan under the TOCTOU guard (a concurrent decommit or reprotect skips it), the occurrence count becomes a lower bound. A truncated sweep is reported as `IncompleteScan`, in either phase and whatever that phase found. A caller can therefore tell "not read" from "not there" and from "not unique". `StringAmbiguous` and `AmbiguousReference` are reserved for a second copy or a second reference observed. A hidden duplicate string, or a second reference in unread or unexamined bytes, is never returned as the unique result. Phase 2's narrow and broad sweeps run over one shared enumeration of the executable windows. A window that disappears between them faults the guarded read and counts as incompleteness, not a pass for a verification that agreed.

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
    DetourModKit::log().error("string xref failed: {}",
                     DetourModKit::to_string(site.error().code));
    return false;
}
// *site is the address of the `lea`/`mov` that loads the string. With
// XrefReturn::EnclosingFunction it is instead the entry of the function that uses
// it (authoritative .pdata bounds, with a heuristic back-scan fallback). With
// XrefReturn::StringPointerSlot it is the global data slot that caches the loaded
// pointer (see below).
```

Why anchor on a string: a game patch reshuffles code bytes, which breaks AOBs, and reorders globals. A format string or assert message almost never changes. The reference is RIP-relative and resolved against the live image, so the result is ASLR-correct with no fixed address baked in.

Recognized forms. Phase 2 has two modes, both gated by the same exact-target and single-reference uniqueness guards:

- Default (`broad_match = false`): a shape scan for the dominant 64-bit string loads, `REX.W lea` / `mov reg, [rip+disp32]` (opcodes `8D` / `8B` with a RIP-relative ModRM). These instructions are self-delimiting from their byte shape. The scan therefore needs no instruction alignment and cannot desync on data or jump tables embedded in `.text`. This is the fast default.
- `broad_match = true`: keeps the default all-offset shape scan, then adds a Zydis-verified linear sweep. The sweep decodes the instruction stream and matches any RIP-relative memory operand that resolves to the string. It catches the rarer shapes the shape scan does not model, such as `cmp [rip+d], imm`, `push [rip+d]`, and a 32-bit (no-REX) `lea` / `mov`. The sweep restarts at the next byte on a decode failure to realign past embedded data. Any hit already found by the default scan is counted only once. Prefer broad mode only when the default reports `NoReference` for a target you know is referenced, since it does extra decode work.

A shape the active mode does not model reports an error rather than a guess. One shape is out of scope for both modes: an indirect `call` / `jmp` through a `.data` pointer that itself holds the string address. That shape is a two-level indirection rather than a direct RIP reference. Choose a string that is referenced exactly once, because short, common strings are pooled and shared. Phase-2 uniqueness is uniqueness among the *scanned shapes*, not global uniqueness. With `broad_match = false` a second reference of an unmodeled shape is invisible. That is safe for the default `ReferencingInstruction` return. It can, however, make `XrefReturn::EnclosingFunction` attribute the string to the wrong function when the true sole caller uses an unmodeled shape. Set `broad_match = true` when a globally-unique reference matters. This backend is also exposed declaratively as `AnchorKind::StringXref` in the [anchor registry](../guides/scanning/anchors.md).

Return modes. `XrefReturn::ReferencingInstruction` (default) returns the load site. `XrefReturn::EnclosingFunction` resolves the entry of the function that uses it, through the x64 `.pdata` exception table via `RtlLookupFunctionEntry`. It follows `UNW_FLAG_CHAININFO` chains to the primary function, so a hot/cold-split fragment resolves to the true function. A bounded RET/INT3 prologue back-scan is the fallback for leaf functions and for code with no registered exception table. `XrefReturn::StringPointerSlot` is for the common pattern where a game caches the loaded string pointer into a global. It applies when the unique reference is a `lea reg, [rip+string]` immediately followed, within a bounded forward window, by a `mov [rip+slot], reg`. That store puts the same register into a global slot. It then returns the effective address of that slot rather than the load site. This resolves a cached global string pointer in one call. It applies only to the `lea` shape, because a `mov reg, [rip+string]` load already delivered the value to a register. A register mismatch, an out-of-window store, a broad-only reference, or no matching store reports `ErrorCode::StoreNotFound`. The store match is first-within-window, because compilers emit the cache next to the load, and it is not uniqueness-checked. The bounded forward decode stops conservatively on a write to the loaded register, a `CALL`, a decode failure, or an unreadable byte. A clobbered register therefore yields no slot rather than a wrong one. It does not attempt full dataflow analysis.

## Cascading candidates

### Motivation

Game binaries change across patches. A single literal AOB locks onto a specific opcode window in one build. One compiler flag flip later, it matches nothing on the next update. The cascade pattern is the standard defence. Register several ordered candidates per target, most-specific first and most-generic last. Let the scanner try each until one matches, and record the winner so you know which build of the game runs. Every long-lived modding community reinvents this eventually. DMK ships it as a first-class API, so you do not reinvent the logging, the ordering rules, or the prologue-overwrite recovery path.

### API shape

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
    bool require_executable_result = false; // final address must be code after any backend resolves it
    std::span<const Region> exclusions{};   // caller-owned copies of the query bytes a match may not come from
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
    bool require_executable_result = false;
    std::vector<Region> exclusions;
    ScanRequest view() const noexcept;
};

// build a borrowed request with lifetime-bound diagnostic:
ScanRequest borrow(span<const Candidate> ladder, string_view label = {},
                   Region scope = Region::host(),
                   FallbackPolicy fallback_policy = FallbackPolicy::Off,
                   FallbackWitness fallback_witness = {}, bool require_unique = true,
                   CandidateOrder order = CandidateOrder::AsDeclared,
                   Pages pages = Pages::Readable) noexcept;

// code/hook-target preset: Pages::Executable + final executable-result gate + UniqueFirst + WarnOnly fallback.
// Pass RequireIdentity + a witness to fail closed on a recovered site the witness cannot confirm.
ScanRequest borrow_code_target(span<const Candidate> ladder, string_view label = {},
                               Region scope = Region::host(),
                               FallbackPolicy fallback_policy = FallbackPolicy::WarnOnly,
                               FallbackWitness fallback_witness = {}) noexcept;

// strict code/hook-target preset: identical to borrow_code_target but pinned to RequireIdentity with a MANDATORY
// witness, so a strict code target cannot be requested without the identity check that gives RequireIdentity meaning.
ScanRequest borrow_code_target_strict(span<const Candidate> ladder, string_view label,
                                      FallbackWitness fallback_witness,
                                      Region scope = Region::host()) noexcept;

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

`resolve` takes a `ScanRequest`, so you can pass a borrowed view (`borrow(...)`) or an `OwnedScanRequest::view()`. Scope the scan to a single module with `Region::module_named("game.exe")`, or to the host EXE with `Region::host()`. `Region::whole_process()` searches all committed pages. With the default `Pages::Readable` it is accepted only when the request declares its retained query copies through `ScanRequest::exclusions` (see the readable-scanner section).

`fallback_policy` selects hooked-prologue recovery. `Off` (the default) disables it, so a full-ladder miss is a hard miss. `WarnOnly` recovers structurally. `RequireIdentity`, paired with a `fallback_witness`, additionally fails the recovery closed with `ErrorCode::PrologueIdentityRejected` when the witness cannot verify the recovered site (see the prologue-fallback section). The `borrow_code_target_strict(ladder, label, witness, scope)` preset bakes this in: it pins `RequireIdentity` and takes the witness as a mandatory argument. A strict code target therefore cannot be requested without the identity check. A `RequireIdentity` with no witness otherwise fails closed silently on every recovery.

`pages` selects which page class the byte tiers scan. `Pages::Readable` (default) covers code and data. `Pages::Executable` narrows to code, so a byte signature that must land on an instruction cannot alias an identical run in a data section. `require_executable_result` additionally verifies every backend's final address, which matters when a RIP-relative byte match points to data or a text tier returns a data location.

`resolve_batch` dispatches each request to the resolver concurrently. Unwrap the outer `Result`, where a whole-batch OOM failure lands (the same shape as `hook::install_all`). Then read one `Result<Hit>` per request from the inner vector in input order. `Hit::winning_name` is an owned `std::string` copied from the winning candidate, so it does not alias caller storage. `Hit::address` is the post-resolution absolute address. For `direct` candidates it equals `match + walk_back`. For `rip_relative` candidates it is the already-resolved target of the displacement, so callers can hook or call it directly. Use `scan::or_null(result)` or `scan::address_or(result, fallback)` to flatten a `Result<Hit>` to an address when error detail is not needed. Errors are unified `ErrorCode` values on `result.error().code`. Call `to_string(result.error().code)` for a diagnostic string.

### Basic usage

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

### Prologue fallback variant

`scan::resolve` is fine when the target function still looks the way your signature remembers it. It stops working as soon as another mod, loaded earlier in the process, inline-hooks the same function. SafetyHook, MinHook, and most hand-rolled detour libraries overwrite the first five bytes with a near-JMP (`E9 ?? ?? ?? ??`) to their trampoline. Your Direct-mode candidate that matches on a prologue byte sequence now sees `E9` instead of `48 89 5C 24 ...`. The scan misses even though the function itself is still present.

`resolve` with a non- `Off` `ScanRequest::fallback_policy` handles that exact scenario. On the happy path it is identical to a plain `resolve`. If every candidate misses, it walks the list again and rebuilds each `direct` -tier candidate. The rebuild replaces the patched prologue tokens with a jump prefix, keeps the literal tail, and scans with the rewritten pattern. Four inline-hook prologue shapes are tried in order:

- the five-byte `E9 ?? ?? ?? ??` near jump (SafetyHook / MinHook for an in-range trampoline),
- the six-byte `FF 25 ?? ?? ?? ??` RIP-relative indirect jump, a Detours-style far jump with the absolute target in a separate slot the displacement points at. A hook emits it when its trampoline is beyond rel32 reach,
- the 14-byte `FF 25 00 00 00 00 <abs64>` absolute form whose displacement is zero, so the 8-byte target is inlined immediately after the instruction,
- the 12-byte `mov rax, imm64; jmp rax` (`48 B8 <imm64> FF E0`) absolute jump some libraries emit instead.

The shapes are mutually exclusive at a real hook site. The `E9`, `FF 25`, and `48 B8` opcode groups differ, and the two `FF 25` forms share that opcode but are told apart by overwrite length. The six-byte form points its disp32 at a separate target slot, while the fourteen-byte form zeroes the disp32 and inlines the 64-bit target. The two therefore leave different surviving tails. The try order therefore only affects which shape is attempted first, never correctness. Whichever shape uniquely recovers an executable target wins.

Two guardrails apply before a hit is accepted. The rewritten pattern must resolve to exactly one location in scope. That means a unique jump into the sibling mod's trampoline, not an arbitrary jump that happens to share a tail shape. The decoded jump destination must resolve to a committed, execute-readable page. The destination is deliberately *not* required to lie inside a loaded module. SafetyHook trampolines and relay-style detours can live outside every image, so an in-module requirement rejects the precise recovery this path exists for. The recovered address honors the candidate's `|` anchor offset exactly as the direct pass does. A `|` -anchored direct candidate therefore resolves to the same byte whether it matched directly or through the fallback. `rip_relative` candidates are skipped in the fallback phase, because they target instructions deeper than the patched prologue and are unaffected by the overwrite.

Those two guardrails prove a hooked site exists and is unique. They do not prove it is the function you meant. A game reshape can leave a different, itself inline-hooked function whose surviving literal tail happens to match your candidate. The rebuilt pattern then resolves uniquely to a near-twin at the wrong address. `fallback_policy` chooses how strictly the recovered site is verified. `WarnOnly` (the `borrow_code_target` default) returns the structural recovery and, when a `fallback_witness` is supplied, logs a Warning if the witness disagrees. That is an observe-before-enforce mode, and it surfaces near-twin drift in your logs without a behavior change. `RequireIdentity` runs the witness and fails the recovery closed with `ErrorCode::PrologueIdentityRejected` when it rejects the site, or when no witness was supplied to verify it. A caller can therefore distinguish "a hooked near-twin was found but refused" from a plain `NoMatch`. The witness is a `FallbackValidator` (`bool(std::int64_t recovered_address, const void* context) noexcept`, signature-identical to `anchor::AnchorValidator`). Corroborate the recovered address against an independently resolved landmark, or read a distinguishing byte past the overwritten prologue. Return false to reject a coincidental twin.

```cpp
// Fail closed unless the recovered site is corroborated against a landmark resolved elsewhere.
static std::uintptr_t g_expected = /* an address resolved by an independent anchor */ 0;
const auto hit = sc::resolve(sc::borrow_code_target(
    k_weapon_fire_candidates, "weapon_fire", DetourModKit::Region::module_named("game.exe"),
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

There is one guardrail callers must be aware of. The fallback refuses to rebuild any candidate that does not keep at least ten fully-known (non-wildcard) tail bytes after the tried prologue shape's overwrite length. It surfaces that refusal as `ErrorCode::PrologueFallbackNotApplicable`. That overwrite length is the shape's own `patch_bytes`: five for the near `E9`, but six, twelve, or fourteen for the far shapes. A signature long enough to rebuild for the `E9` shape can therefore still be refused for a 12- or 14-byte shape. Those far shapes strip more of the prologue before the tail is counted. Wildcards in the tail do not count toward the ten. Five surviving bytes leave the rebuilt pattern shaped like a generic near-JMP plus a short common-instruction tail. That shape collides with thousands of unrelated `E9` sites in a multi-megabyte `.text` section. Ten fully-known bytes is roughly two to four real instructions of context. It reduces the false-positive rate to near zero on real binaries, and it stays inside the 12 to 20 byte sweet spot for fallback signatures. A bounded-jump (`[X-Y]`) Direct candidate is ineligible as well, because the rebuild is a flat byte/mask concatenation that cannot preserve the variable gaps. A jump-bearing signature therefore fails closed here, and is recovered, if at all, only through its normal (non-fallback) direct match. If you see this error, extend the offending candidate's pattern to carry at least ten fully-known bytes past the prologue window. As an alternative, drop the bounded jump.

> **Safety note.** The fallback is a recovery path for the specific case where another inline-hooking mod loaded earlier in the process already patched the same function's prologue. It is **not** a recovery path for game patches that remove or reshape the target function. A cascade miss followed by a fallback hit on the wrong site can produce a non-zero resolved address that points into an unrelated function, which the consumer then hooks and corrupts. The tightened guardrails (one allowed match, ten literal tail bytes) make this outcome structurally improbable on a well-formed cascade, but they do not eliminate every degenerate signature shape. If your anchor family covers a function that a future patch can remove or reshape, rather than one merely inline-hooked by a sibling, use `scan::resolve` with `fallback_policy = FallbackPolicy::Off` (the default) as the strict variant. It treats a full-ladder miss as a hard `ErrorCode::NoMatch` without any engagement of the rewritten-prologue path. As a defense in depth, make sure at least one `Candidate` in the ladder anchors **past** the SafetyHook 5-byte displacement window (a mid-body literal-byte landmark in the function), which lets the regular resolver match a sibling-patched site without the fallback ever needed.

### Name and string resilience tiers

A byte AOB is the most brittle anchor on the ladder. It breaks the moment the compiler reorders an instruction or the linker shifts a constant. Two stronger signals survive a patch: the *name* and the *literal* do not move even when the surrounding bytes and addresses do. Both can live directly in a `Candidate` ladder:

- `Candidate::rtti_vtable(name, mangled)`: `mangled` is an MSVC mangled type name (for example `".?AVMyEngineActor@ns@@"`). The candidate resolves through `rtti::vtable_for_type` and returns the type's primary (`COL.offset == 0`) vtable.
- `Candidate::string_xref(name, literal)`: `literal` is the exact string content. The candidate resolves through `scan::find_string_xref`: it anchors on the immutable literal in `.rdata`, then resolves the single RIP-relative reference to it. Use `Candidate::string_xref(name, StringRefQuery{...})` to pass explicit facets (encoding, return mode, terminator match, broad sweep).

One ordered ladder can therefore express the natural "try the RTTI name, else the string xref, else the byte AOB" for a single target. The same machinery resolves it, and `resolve_batch` and the prologue-fallback path use it automatically.

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

- **Scope.** Both backends are module-scoped. An RTTI COL's RVAs are image-base-relative, and an in-image string xref is image-scoped. Set `ScanRequest::scope` to `Region::host()` or `Region::module_named(...)` as appropriate. `Region::whole_process()` is not meaningful for these tiers.
- **Uniqueness is the backend's job.** `require_unique` has no effect for `rtti_vtable` or `string_xref` candidates. The backends fail closed on ambiguity by construction, which maps directly to "fall through to the next candidate" without a byte-mode uniqueness rescan.
- **Prologue fallback ignores them.** The fallback pass only rewrites `direct` -tier candidates, so a name/string tier is inherently stomp-immune. It either resolved on the happy path or is skipped unchanged.

The two backends themselves (`rtti::vtable_for_type` and `scan::find_string_xref`) are documented in full in [rtti-walker.md](../guides/rtti/rtti-walker.md) and the string-xref tour above. This section only covers their expression inside a ladder.

### Ordering and logging

Put the most-specific candidate first. The resolver returns on the first successful resolution, so an overly-generic pattern placed near the head will shadow tighter patterns further down the list. The `winning_name` on `Hit` tells you which candidate fired. Log it or stash it in your mod's telemetry. You can then correlate a running session with a specific build of the game after the fact. The resolver also logs each outcome. A success is a **Debug** line `"scan::resolve: '<label>' resolved <addr> via candidate '<name>'."`, and a prologue-recovery success reads `"... recovered <addr> via hooked-prologue reconstruction of candidate '<name>'."`. Every miss is a **Warning** line `"scan::resolve: '<label>' matched no candidate across <n> tried (<reason>)."`, so a no-match is visible even with Debug off. The address renders as a zero-padded hex value (for example `0x00007FF6...`) on both toolchains. Raise your log level to Debug to capture the success line for build identification even without explicit caller logging. Alternatively, set `ScanRequest::order = scan::CandidateOrder::UniqueFirst` to let the resolver automatically promote the text tiers (RTTI and string xref, which are unique-only by construction) ahead of byte patterns.

### Host-module convenience overloads

The overwhelmingly common scope for an injected ASI is "the host EXE." `Region::host()` is the default `ScanRequest::scope`, so a host-EXE cascade needs no explicit scope:

```cpp
const sc::ScanRequest req = sc::borrow(k_candidates, "weapon_fire");
// scope defaults to Region::host()
const auto hit = sc::resolve(req);
```

Use `Region::module_named("engine.dll")` when the target code lives in a separate module, such as an engine DLL loaded by a thin launcher EXE. There `Region::host()` scans the wrong image. `Region::whole_process()` searches all committed pages accepted by the selected `Pages` filter. It is the correct choice when the binary is packed or the target module is unknown. Pair it with `pages = sc::Pages::Executable`, because an unconfined `Pages::Readable` scope fails closed with `ErrorCode::NotAuthoritative` (see the readable-scanner section).

### Reading a code constant (`read_code_constant`)

Sometimes the value a mod needs is not an address but a constant baked into an instruction. Examples: an array stride in an `add reg, imm`, a struct displacement in a `movzx [reg + disp]`, or a bit position. A hand-read of those immediates every patch is the largest re-RE-every-update bucket. `read_code_constant` is the code-side twin of the RTTI self-heal. Declare the instruction site, an AOB cascade that lands **on** the instruction, plus which operand to read. It decodes the live instruction and returns the current value.

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

- **Always decodes.** `cc.nominal` is a telemetry or baseline hint only, never a return short-circuit. A same-shape different-value drift (a stride that changed from 232 to 240) is therefore reported as the new value. Set `cc.has_nominal = true` to make `nominal` meaningful. Do not overload `nominal == 0` as "unset".
- **Visible-operand indexing.** `operand_index` counts the operands you see in a disassembler. Implicit operands (flags, implicit registers) do not shift the index.
- **RIP-relative is resolved to an absolute.** A `[rip + disp]` memory operand returns the absolute target address, not the raw relative displacement.
- **Narrowing.** `byte_width = 0` preserves the decoded value. A value from 1 through 8 keeps that many low-order bytes and re-sign-extends, so a deliberately narrowed negative constant stays negative. Values above 8 are invalid and fail before the scan. RIP-relative memory operands return their absolute target without narrowing.
- **Fails closed.** A candidate that resolves to a non-executable final site is skipped, so a later ladder rung can win. If none can, the result is `NoMatch`. A selected site returns `DecodeFailed` when it loses executable protection before the decode, or when it no longer decodes. A decoded instruction that crosses into a non-executable page also returns it. A wrong operand kind or an out-of-range index returns `UnexpectedShape` or `OperandOutOfRange` rather than a guess.
- **Revalidates the selected byte rung.** See `read_code_constant` in `scan.hpp` for the contract. `CodeConstantEpochTest` supplies T-CODE-EPOCH.
- **Validates code at both stages.** The instruction-site byte scan is gated to `Pages::Executable`, so an identical byte run in `.rdata` / `.data` cannot be mistaken for a code constant. A non-Direct candidate can still match code and resolve to data. The final resolved site is therefore also required to be execute-readable before Zydis decodes it. A code constant is by definition in executable code, so this narrows without a dropped real site. It is the same instruction-site rule `borrow_code_target` applies to hook targets.

The decoder (Zydis) is kept entirely inside the DetourModKit implementation. Consumers never include or link Zydis themselves.

## Patch-proof patterns (cache, fallback, verify)

The raw `scan` API is intentionally low-level. Anything beyond a single call-site benefits from a thin layer above it. Below are patterns battle-tested in consumer projects.

### Cache the compiled `Pattern`

`scan::Pattern::compile()` is cheap but not free. If you scan repeatedly (hot-reload, re-scan after a level load, fallback between candidates), compile once. Hold the `Pattern` in a static or a class member. For compile-time-known signatures, `scan::Pattern::literal()` is `consteval` and produces a zero-cost static value:

```cpp
// For compile-time-known signatures: consteval, no runtime cost.
static constexpr auto k_pattern =
    DetourModKit::scan::Pattern::literal("48 89 5C 24 ?? 57 48 83 EC 30");

// For runtime signatures: compile once at startup and reuse.
const auto runtime_result = DetourModKit::scan::Pattern::compile(user_supplied_string);
if (!runtime_result) { /* handle BadPattern */ }
const auto& runtime_pattern = *runtime_result;
```

### Multi-candidate fallback

For a single logical hook, ship two or three candidates. Use a tight one for the current build, a wider one for the previous build, and a generic one as a safety net. Use `scan::resolve` with an ordered ladder. The resolver stops on the first hit and records the `winning_name`.

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

### Verify after match

A lone signature hit is necessary but not sufficient. Two lightweight checks catch the overwhelming majority of mis-hits:

- **First-byte sanity check.** `scan::is_likely_function_prologue(addr)` reads one byte under a fault guard and rejects a fixed poison set. The set is exactly `0x00` (zero-fill), `0xCC` (INT3 pad), `0xC2` (RET imm16), and `0xC3` (RET). Every other first byte passes. A target already inline-hooked by another mod, whose first byte is `0xE9` / `0xEB` / `0xFF`, still passes. It is a cheap one-byte blacklist, not a two-byte `FF 25` decode. Gate a scan hit through it before you hand the address to SafetyHook.
- **`memory::is_readable()` guard.** Before you read more than a single byte, verify that the entire span is inside a committed page with an expected protection flag. Examples: a 5-byte trampoline disassembly, or an RTTI string copy. It takes a `Region` now: `memory::is_readable(DetourModKit::Region{addr, n})`.

```cpp
if (!DetourModKit::scan::is_likely_function_prologue(resolved_addr))
{
    return; // scan poison: zero page, alignment pad, or bare RET
}
```

### Walk-back offsets

`Candidate::direct` accepts a `walk_back` argument (signed): a negative value walks backward from the match. Use it to arrive at the function start after the pattern anchored on a later landmark. The resolver applies it before returning the hit address, so callers receive the already-adjusted `Hit::address`.

```cpp
// walk back 16 bytes from the match to arrive at the function prologue
sc::Candidate::direct("anchor_walkback",
    sc::Pattern::literal("48 8B 88 B8 00 00 00 48 89 4C 24 68"),
    /*walk_back=*/-16)
```

### Name every candidate

Anonymous signatures make regressions unreadable. Attach a human-friendly label to every candidate ( `"player_ctx_load_v1"`, `"fire_weapon_v2_backcompat"`). Log that label when a hit is found or when all candidates fail. It pays for itself the first time a patch breaks one of thirty signatures.

## Worked examples

### Hook a direct `call rel32`

```cpp
namespace sc = DetourModKit::scan;
namespace hk = DetourModKit::hook;

const auto pat_result = sc::Pattern::compile("E8 ?? ?? ?? ?? 48 89 43 10");
if (!pat_result) return;

const auto hit = sc::scan(*pat_result, DetourModKit::Region::host(), 1, sc::Pages::Executable);
if (!hit) return;

// *hit points at 0xE8; the full call is 5 bytes with disp32 at offset 1.
const auto target = sc::resolve_rip_relative(*hit, /*displacement_offset=*/1, /*instruction_length=*/5);
if (!target) return;

// hook::inline_at takes the resolved Address directly and returns a move-only RAII Hook, DISABLED. inline_at does the
// single function-to-void* cast for you; hold the handle for the hook's lifetime (here, a function-static optional).
static std::optional<hk::Hook> g_callee_hook;
auto installed = hk::inline_at(
    hk::InlineRequest{
        .name = "callee_hook",
        .target = *target,
    },
    &Detour_Callee);
if (!installed)
{
    logger.error("callee hook failed: {}", installed.error().message());
    return;
}
// Publish the handle Detour_Callee will read BEFORE arming: enable() is what patches the target, so the detour can
// run the moment it succeeds and g_callee_hook must already hold the handle.
g_callee_hook.emplace(std::move(*installed));
if (!g_callee_hook->enable())
{
    logger.error("callee hook enable failed");
    // Only drop the handle when the target is confirmed unpatched. A DisableFailed result leaves the hook active,
    // so retain it and quiesce or retry teardown rather than resetting a live hook.
    if (!g_callee_hook->is_enabled())
    {
        g_callee_hook.reset();
    }
    return;
}
// Inside Detour_Callee, reach the original via g_callee_hook->original<CalleeFn>() (typed trampoline) or
// g_callee_hook->call<Ret>(args...) (guarded original-call). No separate "original" out-pointer is registered.
```

If your pattern embeds a `|` marker, `scan::scan` has already applied `Pattern::offset()` to the returned address: pass it directly to `resolve_rip_relative`. A second add double-applies and advances past the opcode.

> Resolve-on-install alternative. When the target is a *function entry* found by a `direct` candidate, not a two-step RIP resolution like the one above, skip the manual scan and hand a `scan::OwnedScanRequest` straight to `inline_at` / `mid_at` as the `target`. The verb resolves the ladder at install time, so the same `OwnedScanRequest` you pass to `scan::resolve` doubles as the hook target:
>
> ```cpp
> static std::optional<hk::Hook> g_weapon_fire_hook;
> auto installed = hk::inline_at(
>     hk::InlineRequest{
>         .name = "weapon_fire",
>         .target = sc::OwnedScanRequest{
>             .ladder = {sc::Candidate::direct("weapon_fire_v1",
>                            sc::Pattern::literal("48 89 5C 24 ?? 57 48 83 EC 30"))},
>             .label = "weapon_fire",
>             .scope = DetourModKit::Region::host(),
>             .pages = sc::Pages::Executable,
>             .require_executable_result = true,
>         },
>     },
>     &Detour_WeaponFire);
> if (!installed)
> {
>     logger.error("weapon_fire hook failed: {}", installed.error().message());
>     return;
> }
> g_weapon_fire_hook.emplace(std::move(*installed));
> // The install returns disabled; arm it once the handle is published. Only reset on a confirmed-disabled failure;
> // a DisableFailed result leaves the hook active, so retain it and retry teardown instead.
> if (!g_weapon_fire_hook->enable() && !g_weapon_fire_hook->is_enabled())
> {
>     g_weapon_fire_hook.reset();
> }
> ```

### Resolve a global pointer via `mov rax, [rip+disp32]`

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
auto global_ptr = DetourModKit::memory::read<std::uintptr_t>(*ptr_addr).value_or(0);
```

If `hit` came from a pattern with a `|` offset marker, `scan::scan` has already applied the offset: pass `*hit` directly. A second add double-applies and starts the search window past the intended opcode.

### Scan a packed binary

```cpp
// Code decrypted into anonymous executable pages outside any loaded module.
const auto pat_result = sc::Pattern::compile("48 8B ?? ?? ?? ?? ?? 48 85 C0 74 ?? E8");
if (!pat_result) return;

// Region::whole_process() with Pages::Executable walks all committed execute-readable pages.
const auto hit = sc::scan(*pat_result, DetourModKit::Region::whole_process(), 1, sc::Pages::Executable);
if (!hit) return;

// *hit is the already offset-adjusted address.
```

### Second occurrence with an offset marker

```cpp
//  "48 8B 88 B8 00 00 00 | 48 89 4C 24 68"
// Use the second hit (e.g. the one inside the actual setter, not the reader).
static constexpr auto k_pattern =
    sc::Pattern::literal("48 8B 88 B8 00 00 00 | 48 89 4C 24 68");

const auto hit = sc::scan(k_pattern, DetourModKit::Region::host(), /*occurrence=*/2, sc::Pages::Executable);
if (!hit) return;

// *hit already lands on the `mov [rsp+0x68], rcx` because scan() applied
// Pattern::offset(). Do not add the offset again.
const DetourModKit::Address anchor = *hit;
```

Reminder: `scan::scan` returns the offset-adjusted address when a `|` marker is present, and the match start when it is absent. `Pattern::offset()` is applied for you, so a manual add double-applies.

## Do and avoid

### Do

- Prefer code anchors over data anchors.
- Wildcard every immediate operand: addresses, RVAs, relative offsets, jmp/call targets.
- Keep signatures as short as a unique hit allows. 7 to 16 bytes is the common sweet spot.
- Cache compiled `Pattern` values if you scan more than once. Prefer `Pattern::literal()` for compile-time-known signatures.
- Ship at least one fallback candidate per hook for long-lived projects.
- Verify the match with `memory::is_readable()` and a first-byte sanity check before you hook.
- Log which named candidate matched. Anonymous signatures are unmaintainable at scale.
- Treat the address returned by `scan::scan` as already offset-adjusted. It applies `Pattern::offset()` for you.

### Avoid

- Do not include a static address or RVA in the signature body. It changes next build.
- Do not extend a signature into the `CC` / `90` padding between functions. Linkers rebalance padding freely.
- Do not anchor on a short `Jcc rel8` conditional jump. Compilers flip freely between the `rel8` and `rel32` encodings whenever the branch distance crosses a threshold. A 2-byte `74 xx` becomes a 6-byte `0F 84 xx xx xx xx`, or the reverse. Even a trivial edit to unrelated code can push the branch into a different encoding. The opcode byte then changes, so the signature stops matching.
- Do not assume `scan::resolve_rip_relative` hands back the call target for `FF 15 disp32` / `FF 25 disp32`. The disp32 addresses a pointer slot, and DMK returns that slot's absolute address. Dereference it yourself, for example with `memory::read<std::uintptr_t>`, to obtain the final destination.
- Do not ship a pattern with zero literal bytes (every token `??`). The scan engine matches at the region start every time, which is almost never what the caller wants.
- Do not call `Pattern::compile` in a hot loop on user-supplied strings. Compile once at startup.
- Do not add `Pattern::offset()` to the address returned by `scan::scan`. It already applies the offset. A double-apply walks past the intended byte and is a common source of mysteriously-wrong resolved addresses.
- Do not ignore a `NoMatch` or `UnreadableDisplacement` error. It usually means the signature lost its context, not that the code moved.
- Do not trust a single-build signature in a long-lived mod without a fallback.

## Troubleshooting

- **`Pattern::compile` returns `BadPattern`.** Malformed token, three-digit hex, or a stray `|`. `result.error().message()` reports `BadPattern` plus a numeric `PatternStatus` in the error's `extra` slot (`TooLong`, `InvalidToken`, `InvalidJump`, `DuplicateOffset`, `TooManyJumps`, `Empty`). It does not echo the offending token, so re-check the pattern against the pattern-syntax grammar.
- **`scan::scan` returns `NoMatch` every time.** Wildcards too broad, or the literal bytes include a byte the binary never has. Reduce the wildcard count and print a few hex dumps around the expected site.
- **`scan::scan` hits the wrong site.** `scan::scan` returns the lowest-address Nth match with no uniqueness gate (`require_unique` is a `ScanRequest` field for `resolve` / `resolve_batch`, not a `scan` argument). Tighten the pattern, pass a verified Nth-occurrence, or resolve through `scan::resolve` with `require_unique = true`.
- **`scan::scan` returns `NoMatch` on a signature that worked before or on another machine.** A page faulted mid-scan under the TOCTOU guard (a concurrent decommit / reprotect), or a bounded-jump scan exhausted its region-wide work budget. The page-gated sweep fails closed, because the Nth match can lie in skipped or unexamined bytes. This is not a signature bug: the incomplete sweep is `NoMatch` by contract. Retry or re-scope, and simplify an excessively broad bounded-jump pattern if applicable.
- **`resolve_rip_relative` returns `UnreadableDisplacement`.** Match landed inside a guard page or at a region edge. Validate the `displacement_offset` and `instruction_length`, then use `Region::whole_process()` with `Pages::Executable`.
- **Hit address crashes on first call.** Missing post-match verification, or an anchor drifted into padding on a new build. Gate with `scan::is_likely_function_prologue(addr)` before hooking.
- **Works locally, fails on a different machine.** Packer or anti-cheat transforms the module between load and scan. Use `Region::whole_process()` with `Pages::Executable`, and add a later re-scan on the first frame.
- **Multi-GB scan is slow.** The pattern's only literal bytes are common (`48 8B`, `E8`). Broaden the anchor to include a rarer byte, because the anchor selector prefers rarer bytes.

## Further reading

- [C++ Core Guidelines - in-house coding standards](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
- [omni's hackpad: Fixing Hacks When a Game Gets Patched](https://badecho.com/index.php/2021/10/05/fixing-hacks-after-patch/)
- [Reloaded II Cheat Sheet: Signature Scanning](https://reloaded-project.github.io/Reloaded-II/CheatSheet/SignatureScanning/)
- [UE4SS: Fixing missing AOBs (advanced)](https://docs.ue4ss.com/dev/guides/fixing-compatibility-problems-advanced.html)
- [Guided Hacking: C++ Signature Scan Tutorial](https://guidedhacking.com/threads/c-signature-scan-pattern-scanning-tutorial.3981/)
- [AlliedModders Wiki: Signature Scanning](https://wiki.alliedmods.net/Signature_scanning)
- DMK source of truth:
- [include/DetourModKit/scan.hpp](../../include/DetourModKit/scan.hpp)
- [tests/test_scan_resolve.cpp](../../tests/test_scan_resolve.cpp)
