# AOB Signature Scanning Guide

Practical reference for building, maintaining, and resolving array-of-bytes (AOB) signatures with DetourModKit's `Scanner` module. Written for humans first, but structured so LLM tools can pick specific sections cleanly.

## Contents

1. [Background: what an AOB is and why](#1-background-what-an-aob-is-and-why)
2. [How to find a patch-proof signature](#2-how-to-find-a-patch-proof-signature)
3. [DMK pattern syntax reference](#3-dmk-pattern-syntax-reference)
4. [Scanner API tour](#4-scanner-api-tour)
5. [RIP-relative resolution](#5-rip-relative-resolution)
6. [Patch-proof patterns (cache, fallback, verify)](#6-patch-proof-patterns-cache-fallback-verify)
7. [Worked examples](#7-worked-examples)
8. [DOs and DON'Ts](#8-dos-and-donts)
9. [Troubleshooting](#9-troubleshooting)
10. [Further reading](#10-further-reading)

---

## 1. Background: what an AOB is and why

An **AOB** (array of bytes, also called a **signature** or **sigscan**) is a short byte sequence picked from the `.text` section of a target binary that uniquely identifies an assembly instruction (or small run of instructions) at runtime. Tools like DMK's `Scanner` walk memory looking for that sequence and return the matching address.

Why it matters for modding:

- Module bases change every process launch on Windows (ASLR) and absolute offsets change with every compiler build. A hard-coded RVA fails the next patch day.
- Signatures bind to the **instruction semantics**, not to the binary layout. Good signatures survive many patches; great ones survive entire major version bumps.
- Once an AOB locates the instruction, DMK's hook manager or an `std::expected<uintptr_t, ...>` RIP resolver turns it into an absolute address you can hook, read, or call.

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
| Anti-tamper or packer rewrites bytes | Use `scan_executable_regions()` (searches anonymous executable pages) and plan on a multi-candidate fallback |

## 3. DMK pattern syntax reference

Parsed by `Scanner::parse_aob(std::string_view)` ([include/DetourModKit/scanner.hpp](../../include/DetourModKit/scanner.hpp)). Tokens are split on whitespace (space, tab, `\r`, `\n`, `\f`, `\v`). Leading or trailing whitespace is ignored.

| Token | Meaning |
| ----- | ------- |
| `48`, `8B`, `FF` | Literal byte. Must be exactly two hex digits. Case-insensitive. |
| `??` | Wildcard byte: any value matches at this position. |
| `?` | Same as `??`. Accepted for brevity. |
| `\|` | Offset marker: records the byte position of the next token as the "point of interest", or the position one past the last byte (`offset == bytes.size()`) if placed at the very end of the pattern. Stored on `CompiledPattern::offset`. Cannot appear more than once. |

`parse_aob` returns `std::nullopt` on any malformed token (e.g. `"GG"`, `"1FF"`, three-character tokens, a second `|`) and logs an error through the shared Logger. A malformed token surfaces as `AOB Parser: Invalid token '<token>' at position <n>. Expected hex byte (e.g., FF), '?', or '??'.`. Empty or whitespace-only input is treated as a parse failure.

Example with an offset marker:

```text
"48 8B 88 B8 00 00 00 | 48 89 4C 24 68"
```

The `|` sits after seven literal bytes, so `CompiledPattern::offset == 7`. This lets you anchor on a wide distinctive window while hooking the second instruction in the chain.

## 4. Scanner API tour

Public namespace: `DetourModKit::Scanner`. Errors are returned, never thrown.

### 4.1 Parse once, scan many

`parse_aob()` allocates two small vectors and copies your bytes. It's fine to call it once at startup and reuse the result.

```cpp
#include <DetourModKit/scanner.hpp>

namespace dmk = DetourModKit;
namespace sc = dmk::Scanner;

const auto pattern = sc::parse_aob("48 8B 05 ?? ?? ?? ?? 48 85 C0");
if (!pattern)
{
    // malformed string; parse_aob already logged the reason
    return false;
}
```

### 4.2 Scanning a module range

Pass a module base and size:

```cpp
const HMODULE h = ::GetModuleHandleW(L"game.exe");
MODULEINFO mi{};
::GetModuleInformation(::GetCurrentProcess(), h, &mi, sizeof(mi));

const auto* match = sc::find_pattern(
    static_cast<const std::byte*>(mi.lpBaseOfDll),
    mi.SizeOfImage,
    *pattern);
if (!match)
{
    return false;
}

// match already points at the `|`-marked byte (or at the pattern start when no
// `|` marker is present). find_pattern applies pattern->offset internally, so
// do NOT add it yourself; doing so double-applies and walks past the target.
const auto* target = match;
```

### 4.3 Nth occurrence

`find_pattern` has a second overload that returns the Nth hit (1-based). Passing `0` returns `nullptr` by contract.

```cpp
const auto* third = sc::find_pattern(base, size, *pattern, 3);
```

### 4.4 Process-wide scan

When the target binary is packed, decrypted into anonymous executable pages, or you don't know which module owns the code yet, use `scan_executable_regions()`. It walks `VirtualQuery` and scans every committed `PAGE_EXECUTE_READ*` region that isn't a guard page.

```cpp
const auto* match = sc::scan_executable_regions(*pattern);
```

The function accepts an optional `occurrence` parameter (1-based) for Nth-match semantics; it defaults to `1` and applies `pattern.offset` to the returned pointer.

Pure-execute pages (`PAGE_EXECUTE` with no read bit) are skipped deliberately: such pages are not guaranteed readable and feeding them to `find_pattern` would raise an access violation. Only `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, and `PAGE_EXECUTE_WRITECOPY` regions are inspected; guard and no-access pages are skipped unconditionally.

Note: both `find_pattern()` and `scan_executable_regions()` apply `pattern.offset` to the returned pointer. Callers must never add `pattern->offset` manually on top of the return value; doing so double-applies the offset and walks past the intended byte.

> Do not scan on the render thread. A full-module sweep can run into the tens of milliseconds; a process-wide walk (`scan_executable_regions`) can exceed an entire frame budget on a large game. Resolve signatures at startup, during a loading screen, or on a background worker, and cache the resulting addresses.

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

Internally `find_pattern` does NOT scan byte-by-byte from the start of the pattern. It inspects every non-wildcard byte in the pattern, scores each against a small frequency table (`0x00`, `0xCC`, `0x90`, `0xFF`, `0x48`, `0x8B`, `0x0F`, ... in rough order of "how often this byte appears in typical x64 `.text`"), and picks the rarest one as the anchor. The anchor byte drives a `memchr` sweep; the full pattern is only verified at positions where `memchr` finds the anchor.

Implication: a pattern whose literal bytes are all REX prefixes / common opcodes (`48 8B`, `48 89`, `FF 15`, `E8 ?? ?? ?? ??`) forces the scanner to verify at almost every address. Add at least one uncommon byte (any byte outside the frequency table) and the scan typically drops from tens of milliseconds to sub-millisecond on a full-module sweep. If you have a choice between two otherwise equivalent anchors, pick the one containing a rarer byte.

## 5. RIP-relative resolution

x86-64 code uses RIP-relative addressing heavily. The 4-byte displacement stored inside the instruction is relative to the address of the *next* instruction: `target = instruction_address + instruction_length + disp32`. DMK exposes two helpers and a set of prefix constants.

### 5.1 Two-step: find the match, then resolve

Best when the instruction is part of a wider signature, or when the disp32 is not at the end (e.g. the instruction has an immediate suffix).

```cpp
const auto* hit = sc::find_pattern(base, size, *pattern);
if (!hit)
    return false;

// Suppose the matched instruction is `mov rax, [rip+disp32]` (7 bytes, disp32 at offset 3).
const auto resolved = sc::resolve_rip_relative(hit, /*disp_offset=*/3, /*instr_len=*/7);
if (!resolved)
{
    dmk::Logger::get_instance().error(
        "RIP resolve failed: {}",
        dmk::rip_resolve_error_to_string(resolved.error()));
    return false;
}

const uintptr_t absolute = *resolved;
```

Error values (`RipResolveError`):

| Error | Meaning |
| ----- | ------- |
| `NullInput` | `instruction_address` or `search_start` was null |
| `PrefixNotFound` | (find-and-resolve only) no match within `search_length` |
| `RegionTooSmall` | (find-and-resolve only) `search_length < prefix_len + 4` |
| `UnreadableDisplacement` | disp32 bytes failed `Memory::is_readable()` |

### 5.2 One-step: find the prefix and resolve in the same call

Best when the opcode you want to hook has its disp32 **immediately after the prefix you supply** (e.g. `E8 disp32`, `E9 disp32`, `48 8B 05 disp32`). DMK ships ready-made prefix constants in `scanner.hpp`:

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
const auto resolved = sc::find_and_resolve_rip_relative(
    hit,                              // start of a short search window
    /*search_length=*/64,
    sc::PREFIX_CALL_REL32,            // E8
    /*instruction_length=*/5);        // E8 + disp32
```

### 5.3 What these helpers will not resolve

`resolve_rip_relative` deliberately understands only the 32-bit signed displacement form. The following need manual handling:

- Short jumps (`EB rel8`, `Jcc rel8`) with 8-bit displacements.
- 16-bit displacements and legacy `EA ptr16:32` far jumps.
- Indirect calls through memory: `FF 15 disp32` and `FF 25 disp32`. The disp32 points to a **pointer**; DMK returns the pointer's address, not the final target. Dereference it yourself.
- Instructions where the disp32 is interrupted by a SIB byte combination or a VEX/EVEX prefix boundary: supply your own longer `opcode_prefix` that covers up to the disp32 start.

## 6. Patch-proof patterns (cache, fallback, verify)

The raw Scanner API is intentionally low-level. Anything beyond a single call-site benefits from a thin layer above it. Below are patterns battle-tested in consumer projects.

### 6.1 Cache the `CompiledPattern`

`parse_aob` is cheap but not free. If you scan repeatedly (hot-reload, re-scan after a level load, fallback between candidates), parse once and hold the `CompiledPattern` in a static or a class member:

```cpp
struct AobCandidate
{
    const char* name;               // "player_ctx_v1"
    const char* pattern;
    std::ptrdiff_t offset_to_hook = 0;
};

struct CompiledCandidate
{
    const AobCandidate* source;
    DetourModKit::Scanner::CompiledPattern compiled;
};

// Compile once at startup:
std::vector<CompiledCandidate> compile_all(std::span<const AobCandidate> raw)
{
    std::vector<CompiledCandidate> out;
    out.reserve(raw.size());
    for (const auto& c : raw)
    {
        if (auto parsed = DetourModKit::Scanner::parse_aob(c.pattern))
        {
            out.push_back({&c, std::move(*parsed)});
        }
    }
    return out;
}
```

### 6.2 Multi-candidate fallback

For a single logical hook, ship two or three signatures: one tight one for the current build, one wider one for the previous build, and a generic one as a safety net. Try them in order, stop on the first hit, log which one won.

```cpp
uintptr_t resolve_first_hit(
    std::span<const CompiledCandidate> candidates,
    const std::byte* base, std::size_t size,
    const AobCandidate** matched_out)
{
    for (const auto& c : candidates)
    {
        const auto* hit = DetourModKit::Scanner::find_pattern(base, size, c.compiled);
        if (hit)
        {
            if (matched_out) *matched_out = c.source;
            return reinterpret_cast<uintptr_t>(hit) + c.source->offset_to_hook;
        }
    }
    return 0;
}
```

### 6.3 Verify after match

A lone signature hit is necessary but not sufficient. Two lightweight checks catch the overwhelming majority of mis-hits:

- **First-byte sanity check.** A function prologue does not start with `0x00`, `0xC2`, `0xC3`, or (usually) `0xCC`. Reject obvious garbage before you hand the address to SafetyHook.
- **`Memory::is_readable()` guard.** Confirm the resolved address is inside a committed page with an expected protection flag before dereferencing or hooking.

```cpp
bool looks_like_prologue(const std::byte* addr)
{
    if (!DetourModKit::Memory::is_readable(addr, 1))
        return false;

    const auto b = static_cast<uint8_t>(*addr);
    return b != 0x00 && b != 0xC2 && b != 0xC3 && b != 0xCC;
}
```

### 6.4 Negative offsets

DMK's helpers assume you want to land *on* the match. Real-world hooks sometimes want to step backward from the match, for example to arrive at the function start after anchoring on a later landmark. Store a signed offset per candidate and apply it after the match succeeds:

```cpp
struct AddrCandidate
{
    const char* name;
    const char* pattern;
    std::ptrdiff_t disp_offset;    // negative allowed
};

const auto parsed = sc::parse_aob(candidate.pattern);
if (!parsed) return 0;

const auto* hit = sc::find_pattern(base, size, *parsed);
if (!hit) return 0;

const auto* target = hit + candidate.disp_offset; // may walk backwards
```

### 6.5 Name every candidate

Anonymous signatures make regressions unreadable. Attach a human-friendly label to every candidate (`"player_ctx_load_v1"`, `"fire_weapon_v2_backcompat"`). Log that label when a hit is found or when all candidates fail. It pays for itself the first time a patch breaks one of thirty signatures.

## 7. Worked examples

### 7.1 Hook a direct `call rel32`

```cpp
const auto pattern = sc::parse_aob("E8 ?? ?? ?? ?? 48 89 43 10");
if (!pattern) return;

const auto* hit = sc::find_pattern(module_base, module_size, *pattern);
if (!hit) return;

// hit points at 0xE8; the full call is 5 bytes with disp32 at offset 1.
const auto target = sc::resolve_rip_relative(hit, /*disp_offset=*/1, /*instr_len=*/5);
if (!target) return;

hook_mgr.create_inline_hook("callee_hook", *target, &Detour_Callee,
                            reinterpret_cast<void**>(&g_callee_orig), {});
```

If your pattern embeds a `|` marker, `find_pattern` has already applied `pattern->offset` to `hit`: pass `hit` directly to `resolve_rip_relative`. Adding `pattern->offset` again would double-apply and advance past the opcode.

### 7.2 Resolve a global pointer via `mov rax, [rip+disp32]`

```cpp
// Search 64 bytes from the match for the mov, then resolve.
const auto ptr_addr = sc::find_and_resolve_rip_relative(
    hit, 64, sc::PREFIX_MOV_RAX_RIP, /*instr_len=*/7);
if (!ptr_addr)
{
    logger.error("mov rax, [rip+disp32] not found: {}",
                 dmk::rip_resolve_error_to_string(ptr_addr.error()));
    return;
}

// ptr_addr is the absolute address of the pointer slot, not the pointee.
auto global_ptr = dmk::Memory::read_ptr_unsafe(
    reinterpret_cast<const uintptr_t*>(*ptr_addr));
```

If `hit` came from a pattern with a `|` offset marker, `find_pattern` has already applied the offset, so `hit` already points at the marked byte: pass it directly. Adding `pattern->offset` would double-apply and start the search window past the intended opcode.

### 7.3 Scan a packed binary

```cpp
// Code decrypted into anonymous executable pages outside any loaded module.
const auto pattern = sc::parse_aob("48 8B ?? ?? ?? ?? ?? 48 85 C0 74 ?? E8");
if (!pattern) return;

const auto* hit = sc::scan_executable_regions(*pattern);
if (!hit) return;

// scan_executable_regions() already applied pattern->offset.
```

### 7.4 Second occurrence with an offset marker

```cpp
//  "48 8B 88 B8 00 00 00 | 48 89 4C 24 68"
// Use the second hit (e.g. the one inside the actual setter, not the reader).
const auto pattern = sc::parse_aob("48 8B 88 B8 00 00 00 | 48 89 4C 24 68");
if (!pattern) return;

const auto* hit = sc::find_pattern(base, size, *pattern, /*occurrence=*/2);
if (!hit) return;

// hit already lands on the `mov [rsp+0x68], rcx` because find_pattern applied
// pattern->offset. Do not add pattern->offset again.
const auto* anchor = hit;
```

Reminder: both `find_pattern` overloads return the marked byte when a `|` marker is present (and the match start when it is absent). `pattern->offset` is applied for you; adding it manually double-applies.

## 8. DOs and DON'Ts

### DO

- **Do** prefer code anchors over data anchors.
- **Do** wildcard every immediate operand (addresses, RVAs, relative offsets, jmp/call targets).
- **Do** keep signatures as short as will return a unique hit: 7 to 16 bytes is the common sweet spot.
- **Do** cache `CompiledPattern` if you scan more than once.
- **Do** ship at least one fallback candidate per hook for long-lived projects.
- **Do** verify the match with `Memory::is_readable()` and a first-byte sanity check before hooking.
- **Do** log which named candidate matched; anonymous signatures are unmaintainable at scale.
- **Do** treat the pointer returned by `find_pattern` and `scan_executable_regions` as already offset-adjusted; both apply `pattern->offset` for you.

### DON'T

- **Don't** include a static address or RVA in the signature body: it will change next build.
- **Don't** extend a signature into the `CC`/`90` padding between functions: linkers rebalance padding freely.
- **Don't** anchor on a short `Jcc rel8` conditional jump. Compilers flip freely between the `rel8` and `rel32` encodings (from a 2-byte `74 xx` to a 6-byte `0F 84 xx xx xx xx`, or vice versa) whenever the branch distance crosses a threshold, and even trivial edits to unrelated code can push the branch into a different encoding. The opcode byte changes, so the signature stops matching.
- **Don't** assume `resolve_rip_relative` hands back the call target for `FF 15 disp32` / `FF 25 disp32`. The disp32 addresses a pointer slot, and DMK returns that slot's absolute address; you must dereference it (for example with `Memory::read_ptr_unsafe`) to obtain the final destination.
- **Don't** ship a pattern with zero literal bytes (every token `??`). `find_pattern` will emit a warning and "match" at the region start every time, which is almost never what the caller wants.
- **Don't** call `parse_aob` in a hot loop on user-supplied strings; it logs every malformed input.
- **Don't** add `pattern->offset` to the pointer returned by `find_pattern` or `scan_executable_regions`; they already apply it. Double-applying walks past the intended byte and is a common source of mysteriously-wrong resolved addresses.
- **Don't** ignore a `PrefixNotFound` or `UnreadableDisplacement` error: they almost always mean the signature lost its context, not that the code simply moved.
- **Don't** trust a single-build signature in a long-lived mod without a fallback.

## 9. Troubleshooting

| Symptom | Likely cause | Remedy |
| ------- | ------------ | ------ |
| `parse_aob` returns `nullopt` | Malformed token, three-digit hex, stray `\|` | Check the log; `parse_aob` names the offender |
| `find_pattern` returns `nullptr` every time | Wildcards too broad, or the literal bytes include a byte the binary never has | Reduce wildcard count; print a few hex dumps around the expected site |
| `find_pattern` hits the wrong site | Signature not unique | Pick a tighter neighbour, or use the Nth-occurrence overload with a confirmed N |
| `resolve_rip_relative` returns `UnreadableDisplacement` | Match landed inside a guard page or at a region edge | Validate the caller's `search_length` and `instruction_length`; consider `scan_executable_regions` |
| Hit address crashes on first call | Missing post-match verification; anchor drifted into padding on a new build | Add `looks_like_prologue` and an `is_readable` check before hooking |
| Works locally, fails on a different machine | Packer or anti-cheat transforming the module between load and scan | Switch to `scan_executable_regions`; add a later re-scan on first frame |
| Multi-GB scan is slow | Patterns whose only literal bytes are common (`48 8B`, `E8`, etc.) | Broaden the anchor to include a rarer byte; the anchor selector prefers rarer bytes |

## 10. Further reading

- [C++ Core Guidelines - in-house coding standards](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
- [omni's hackpad: Fixing Hacks When a Game Gets Patched](https://badecho.com/index.php/2021/10/05/fixing-hacks-after-patch/)
- [Reloaded II Cheat Sheet: Signature Scanning](https://reloaded-project.github.io/Reloaded-II/CheatSheet/SignatureScanning/)
- [UE4SS: Fixing missing AOBs (advanced)](https://docs.ue4ss.com/dev/guides/fixing-compatibility-problems-advanced.html)
- [Guided Hacking: C++ Signature Scan Tutorial](https://guidedhacking.com/threads/c-signature-scan-pattern-scanning-tutorial.3981/)
- [AlliedModders Wiki: Signature Scanning](https://wiki.alliedmods.net/Signature_scanning)
- DMK source of truth:
  - [include/DetourModKit/scanner.hpp](../../include/DetourModKit/scanner.hpp)
  - [src/scanner.cpp](../../src/scanner.cpp)
  - [tests/test_scanner.cpp](../../tests/test_scanner.cpp)
