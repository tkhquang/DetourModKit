# Scanner, anchor, manifest, and RTTI resolution design

This note explains address resolution. Rulebook entries with the same `[B-nn]` IDs live in [AGENTS.md](../../AGENTS.md).

Rules owned here: `[B-39]`, `[B-51]`, `[B-52]`, `[B-53]`, `[B-54]`, `[B-55]`, `[B-56]`, `[B-57]`, `[B-58]`, `[B-60]`, `[B-61]`, `[B-62]`, `[B-63]`, `[B-64]`, `[B-65]`, `[B-67]`, `[B-68]`, `[B-76]`, `[B-77]`.

## Concurrency model

### scan

The scan surface is stateless and inherently safe. `scan::resolve_batch` shares caller-owned candidate ladders read-only while it dispatches each request through the existing serial resolver. One worker writes each result slot through an atomic cursor, and all workers join before the call returns.

Hot-path mechanism: None. The subsystem runs at startup only, and the batch resolver is setup/control-plane, never callback-safe.

## Rules

### [B-39]

Either condition makes any occurrence count a lower bound. A hidden match (a duplicate string literal, a second cross-reference) can live in the unread or unexamined bytes. A result that looks unique must therefore fail closed to ambiguous. Every `detail::MatchResult` consumer that gates on uniqueness honors `incomplete` this way: `scan()`, `scan_resolution`, `scan_matching`, `scan_prologue_recovery`, and batch resolution. `find_string_xref` maps `incomplete` (the phase-1 readable sweep) and any incomplete phase-2 window to `StringAmbiguous` / `AmbiguousReference` at all three of its uniqueness gates. Raw first-occurrence helpers also fail closed on a bounded-jump budget exhaustion. They cannot prove that a later candidate is the requested first or Nth match. A new uniqueness path over guarded memory must thread and honor the same incompleteness signal.

### [B-51]

`anchor::evaluate_gate` rolls a resolved-anchor report (or its `AnchorQuality` summary) into a `GateVerdict` (Pass / Degraded / Fail) under a `GatePolicy` that defaults to fail-closed. The default requires that every resolvable anchor heals, with zero failures. Safe-disable a feature on `Fail` rather than patch the game on addresses that the manifest failed to verify. Treat `Degraded` (a resolved-but-pinned `Manual` literal, or nothing assessable) as enable-with-caution. Per-feature gating falls out when only that feature's anchors resolve into their own report. One primitive therefore serves both a whole-manifest health check and a per-feature kill switch. The unsupported `CallArgHome` kind is excluded from the ratio denominator, so a declared forward-compatible kind never drags a healthy manifest below threshold. A `QuorumNotIndependent` outcome counts as a hard failure: it committed no value.

### [B-52]

An `anchor::AnchorKind::Quorum` accepts at least `N` results that agree under its match mode. A zero threshold requires unanimity. An unresolved member casts no vote.

The declaration fails closed under any condition:

- `M` is less than two.
- A member is null or a nested `Quorum`.
- The effective threshold is outside `[2, M]`.
- The match mode is invalid.
- Two slots reference the same `Anchor` object.
- Two members both use `Manual` literals.
- Two `ExportName` members name one export in compatible scopes.
- Any member pair shares one independence atom.

`collect_independence_atoms` reduces each member to an address-independent atom set. `same_backend_config` treats any set intersection as shared evidence. It compares content rather than view storage.

Each atom identifies one declared evidence source:

- A byte tier uses the pattern, the mask, decode parameters, and site offsets.
- A vtable tier uses its mangled type name.
- An export tier uses its declared module and export name.
- A string tier uses its literal text and encoding.
- A `Manual` tier uses its literal value.
- A ladder uses the set of all rung atoms.
- An unsupported or empty tier uses a kind-tagged empty atom.

String scan policy does not change the literal identity. The atom omits `broad_match`, `require_terminator`, and `return_mode`.

`RipGlobal` and `CodeOperand` both use the rung site atom. A `CodeOperand` selector does not create an independent witness.

Rung order does not affect a set. One shared fallback rung makes the pair dependent. A wrapper kind does not create independence.

An atom collision rejects the pair. This direction fails closed. `WithinTolerance` still requires independent evidence for every member pair.

After resolution, physical provenance intersections also reject a pair. Different atoms can still resolve one physical site.

`anchor_fingerprint` remains sensitive to rung order and policy. It sorts member evidence, so quorum member order is insensitive. The fingerprint includes the effective threshold, the match mode, the tolerance, and the sorted member evidence.

Proofs: `AnchorTest.QuorumRejectsContentEqualCandidateArrays` proves content comparison across distinct storage. `AnchorTest.QuorumRejectsDifferentPatternsOverOneCodeOperandSite` proves the post-resolution overlap gate. `AnchorQuorumTest.CorrelatedPhysicalSourceCannotDoubleVote` proves `CodeOperand` site identity.

### [B-53]

`scan`'s prologue fallback rebuilds a Direct candidate's prologue as an inline-hook jump and recovers the uniquely-matching site. That structural gate (a unique rebuilt match, a decoded redirect into executable memory, an in-scope walk-back) is address-blind. A reshaped near-twin whose surviving literal tail matches, and which is itself inline-hooked, resolves here uniformly. A unique match can therefore still be the wrong function.

`scan::FallbackPolicy::RequireIdentity` plus a `scan::FallbackWitness` fails the recovery closed ( `ErrorCode::PrologueIdentityRejected`) on a recovered site the witness cannot certify. `anchor::Anchor::require_validator` fails a resolvable anchor that carries no validator in exactly the same way. A missing witness under RequireIdentity is itself a fail-closed, never a trusted guess. `WarnOnly` (the `borrow_code_target` default) keeps the structural recovery with no identity check and only logs a witness that disagrees, for observe-before-enforce drift detection. `Off` (the `ScanRequest` / `OwnedScanRequest` default) disables recovery, so a full direct miss stays a miss.

Reuse the `anchor::AnchorValidator` predicate shape. `scan::FallbackValidator` is signature-identical, kept a separate alias only because `anchor.hpp` includes `scan.hpp` and the dependency cannot run the other way. One witness form then serves the whole resolver.

### [B-54]

The `manifest` module turns a resolved anchor plus its consumer binding (register / offset chain / vtable slot) into a serializable `SignatureRecord`. A shifted AOB or a moved read contract is then a text edit to a `.signatures.ini`, not a recompiled DLL. Examples: `rcx -> rax`, or a field moved `+0x1C8 -> +0x1D0`.

Ownership and overlay:

- Keep the owning/borrowing split the scan surface uses. A `Signature` owns its compiled `scan::Candidate` ladder and rebuilds an `anchor::Anchor` view on demand, never caches one, the same discipline as `OwnedScanRequest::view`. No stored view then dangles across a move.
- `manifest::overlay` merges file overrides over in-code `anchor::Anchor` defaults by label and is fail-soft like `config::bind`. A malformed override falls back to the in-code default rather than drops the feature.
- `manifest::resolve_and_gate` partitions the merged set into trusted versus safe-disabled by resolve status, fingerprint drift, and a whole-manifest health floor. That carries the `anchor::evaluate_gate` fail-safe intent onto the file-loaded surface. An edited signature declaration is distrusted even when something still resolves at the address. The worst failure mode is a silent wrong-register or wrong-offset read, so it must safe-disable, not act.
- The composite `Quorum` / `CallArgHome` anchor kinds are not file-serializable (a Quorum composes its M voting sub-anchors by pointer). They stay in-code and gate through `anchor::evaluate_gate`.

File format:

- The INI keeps each candidate rung in its own ordered `[sig.<label>.rung.<N>]` sub-section rather than an inline first rung. A section-level key then never doubles as both an anchor field and a candidate field, and round-trip stays mechanical.
- The optional `[manifest] revision` is the author's signature-contract epoch, separate from `schema` (the file-format version DetourModKit parses) and from the per-signature fingerprint gate. The fingerprint gate sees the declared locate evidence plus the binding contract. A consumer gates the file through `manifest::revision_compatible(header, BUILD_REVISION)` and treats a stale or unversioned file as no overrides. A renamed label or a re-meaning of a binding is then a manifest bump, not a silent misread. Bump `BUILD_REVISION` only on a breaking in-code change, so a routine mod update keeps still-valid repair files in service.
- A key that the parser never reads for its section fails closed as `MalformedLine` rather than silent acceptance. That covers a wholly-unknown key and an evidence key inert for the record's kind. A hand-edited file therefore cannot drift from what DMK acts on. Keep the per-section known-key sets in step with the emitter (`serialize_impl` ).

Read-only lookup and mutation authorization are separate trust tiers, and evidence is mandatory for the second. A resolve whose purpose is a READ tolerates missing evidence. The plain `resolve_and_gate` overload, a zero `build_revision`, and an uncaptured baseline all stay usable. The worst outcome is a feature that does not light up. A WRITE authorization does not, because its worst outcome is silent memory corruption in the host. `GatePolicy::mutation_strict` demands the complete set and safe-disables the entry when any part is missing:

- a captured fingerprint,
- a captured AND matching `SignatureRecord::expected_image_identity` (versus the resolved `ResolvedAnchor::witness.image`),
- content-bearing `expected_winning_bytes` that equals the scan witness and a fresh guarded read of its match span,
- a mutation-safe typed binding that is not a Manual pin,
- a contract revision that the gate compared, which means the header-threaded overload with a non-zero `build_revision`.

An absent baseline is a refusal to authorize, never an exemption from the check. `manifest::GateReason` names which gate refused, so a safe-disable is loggable as "cannot locate" versus "must not write here".

The two live baselines answer different questions, and neither substitutes for the other. `scan::ImageIdentity` is LAYOUT identity (PE timestamp, `SizeOfImage`, section-table fields, no section body), so in-place content patched under equal headers leaves it bit-identical. `scan::WinningEvidence` is the content counterpart: the literal winning-span bytes captured during the match that accepted them. Wildcard values and skipped gap bytes are included, and the bytes are never a re-read. Immediately before a strict gate publishes trust, it re-reads that match span through the guarded memory primitive. An unreadable span or any byte mismatch safe-disables the entry with `GateReason::WinningEvidence`. This gate-time check does not make a later consumer write atomic. A consumer that needs write-time certainty must use a compare-and-write or checked install operation. Never describe section-layout hashing as content identity.

Capture is opt-in per query (`ScanQuery::capture_evidence`), and the buffer joins the engine's exclusion floor. A verbatim copy of a matched span is itself matchable, and a sweep that reaches it counts it as another occurrence. `MAX_MUTATION_WITNESS_BYTES` (256) bounds it, and a longer span reports `truncated` with NO bytes, so a prefix can never compare equal to a prefix baseline.

`Signature::recapture` adopts all three baselines scope-aware and fallibly. It computes every one before it stores any, so a failure cannot leave a record that gates one build's content against another's identity. `anchor::anchor_trust_fingerprint` is the scope-bound sibling of `anchor_fingerprint`: it folds the effective image identity, so a build-identity change is caught while ASLR is not. Keep the two distinct, as with the quorum independence model, and keep `anchor_fingerprint` off live memory so the declaration-drift baseline stays stable across image updates.

### [B-55]

A run of `??` matches exactly that many bytes, so it breaks when an intervening instruction grows or shrinks between builds. A bounded jump `[X-Y]` (or exact `[X]`) tolerates the size change. Keep the extension a faithful bounded subset:

- A jump must not lead or trail the pattern, and must not sit adjacent to another. Every segment is a non-empty fixed run.
- The span is capped (`MAX_JUMP_SPAN`, no unbounded `[X-]`).
- The anchor is confined to segment 0 (the run before the first jump) in every anchor selector. The matcher locates that run and then extends across the variable gaps. A byte in a later segment therefore sits at a gap-dependent address that the memchr prefilter cannot sweep for.

A jump-free pattern must keep the exact single fixed-width fast path (`jump_count == 0`), so the common case pays nothing.

### [B-56]

When a page-gated sweep chunks memory (the cross-protection-split back-scan), extend the carry by `max_match_length() - 1`, the longest a match can occupy, not by `size() - 1`. Otherwise a straddling long match is missed. A fixed carry cannot both catch a long straddling match and exclude a short interior one. Prevent the double count with a count floor. Count a match only when its true end reaches past the floor, the boundary that the previous region already scanned. The raw matcher must report that end alongside the start (`RawMatch{start, end, point}`). For a jump-free pattern, `max_match_length() == size()` and every match's end passes the floor, so the counting is byte-identical to the fixed-width scan.

### [B-57]

The `sighealth` module grades a `scan::Pattern` / `manifest::SignatureRecord` / `manifest::Manifest` from its declarative bytes alone (no process, no game) on three axes:

- atom rarity: the longest fully-known run and whether its bytes are rare. It reuses the scan engine's `detail::byte_frequency_class`, so the offline estimate anchors on the same rarity model the prefilter uses.
- byte entropy: a repetitive run is long but low-information.
- expected ambiguity: `nominal_haystack_bytes * 2^(-selectivity_bits)`, an order-of-magnitude estimate of false matches, never a promise.

It returns a `Grade` (`Robust` / `Fragile` / `Unusable`) plus `Finding`s that name each weakness. A byte record starts from its first declared rung, because offline lint cannot know which rung resolves in live memory. Record-level findings and compilation can only worsen that initial grade. `SigHealthRecord.LadderGradesByItsFirstRung` and `SigHealthRecord.UnusableFirstRungIsNotAssumedToMissAtRuntime` prove this contract. A manifest grades by its WEAKEST record, because each signature gates its own feature.

It is a pre-flight lint only. Health never gates behavior. The runtime resolver still verifies uniqueness and fails closed. The lint only catches a brittle signature earlier. Keep the byte-rarity model single-sourced in `detail::byte_frequency_class`. Do not fork a second frequency table for the offline estimate.

### [B-58]

A default-constructed `anchor::Anchor` (a designated-initializer table entry that omits `kind`) is `AnchorKind::Unset`, which `resolve` maps to `Failed`, not to `Manual 0`. The latter hands out a *trusted* address 0 with the populated evidence fields ignored. `Signature::compile` / `adopt` reject `Unset` and reject empty required evidence for their kind: empty `mangled` for VtableIdentity, empty `xref_text` for StringXref. The ladder kinds already need a non-empty ladder.

Every mode-dependent key is MANDATORY, not silently defaulted:

- A `rip_relative` rung must carry both `instruction_length` and `displacement_at`, and the disp32 must fit inside the instruction: `displacement_at >= 0` and `instruction_length >= displacement_at + 4`. Otherwise the rung resolves to `match + 0 + disp32`, an in-module address wrong by the instruction length that `resolve_and_gate` trusts, and a hook there splits an instruction.
- A `manual` record must carry the `manual_value` key. An omitted value otherwise overlays a trusted `Address{0}` over a working in-code default. Presence, not the value, is the gate, so an explicit `manual_value = 0` is still accepted.

This gate must live on EVERY entry to a rung or record, not only the file parser. The value constraint ( `instruction_length >= displacement_at + 4`) is enforced in `compile_rung` as well as `parse_rung`. A programmatic `SignatureRecord` with a defaulted `CandidateSpec` (both offsets 0) otherwise smuggles the same `match + 0 + disp32` past `Signature::compile`. A plain `Direct` rung legitimately omits the decode fields, so scope the required-key gate to the mode that needs it. Feed any parse or decode gate a hand-authored minimal record that OMITS each mode-dependent field in a test, not only a well-formed one. ALSO push that record through the programmatic compile path, not only the file parser.

### [B-60]

The opcode prefix can recur inside one scan region. Pointer plausibility does not prove readability. An early prefix can therefore lead to an inaccessible decoy before a valid occurrence. The last concrete decode error preserves the most useful failure after region exhaustion.

### [B-61]

A `.text` section split by `VirtualProtect` into two abutting execute-readable regions is two windows to `collect_executable_windows`. A reference instruction that STARTS in the first window's tail and ENDS in the second fits in neither window's independent sweep. With two real references, the straddler is dropped and the survivor is falsely certified unique: a wrong-site anchor.

`find_string_xref`'s narrow scan extends an abutting window's start back by `instr_len - 1`. A fixed-length shape makes the carry region disjoint from the previous window's own starts, so no count floor is needed. The broad (Zydis) scan extends back by `ZYDIS_MAX_INSTRUCTION_LENGTH - 1` and de-duplicates with a count floor at the window's real base. An instruction that ends at or before that base was already counted. Bound the carry by the previous window's span so it never reads before it. Check any phase-2 scan for the same cross-window carry its phase-1 sibling has.

Both `find_string_xref` phases count inside ONE traversal, so the located address and the uniqueness verdict describe the same view of memory. Phase 2's two sweeps share one enumeration of the executable windows, so a window lost between them cannot pass for agreement. A phase-2 reference counts only when its resolved target exactly equals the located string address. That address is itself a plausible in-image pointer, so the equality subsumes the plausible-userspace floor without a separate check.

### [B-62]

`build_rebuilt_prologue` drops the leading patch bytes and prepends a jump prefix with a copy of bytes and mask only. It carries no `jumps` across, and it does not rebase their positions past the shifted prologue. A jump-bearing pattern therefore collapses every variable gap into a fixed run and matches a wrong shape. Fail closed (`return std::nullopt`) when `original.has_jumps()`. The jump-bearing tail still resolves through the normal direct scan, so only prologue RECOVERY of such a signature is forgone, never a correct match.

### [B-63]

With `broad_match` false (the default), `ReferencingInstruction` counts only the fast REX.W `lea` / `mov reg, [rip+disp32]` shapes. A second reference of an unmodeled shape is invisible, and the narrow reference is still reported unique. That is acceptable because the returned site genuinely references the string.

Derived returns (`EnclosingFunction` / `StringPointerSlot`) compute an answer from that site. After a single narrow hit, they must therefore run the broad Zydis sweep as a second check. If a rarer second reference exists, they fail closed. That second check does not promote a broad-only reference into a hit. Enable `broad_match` through a query, `anchor::Anchor::xref_broad_match`, or `anchor::ScanProfile::default_broad_string_xref` to accept rarer shapes as the resolved reference, not merely as a veto on a narrow-derived answer.

### [B-64]

`enclosing_function_start` calls `RtlLookupFunctionEntry` first. The x64 exception directory supplies exact half-open bounds. The function follows `UNW_FLAG_CHAININFO` to the primary entry for a funclet or hot/cold fragment.

The bounded RET/INT3 scan applies when authoritative metadata yields no boundary:

- A leaf function has no unwind entry.
- An unregistered region can contain raw or JIT code.
- Malformed registered metadata proves no boundary.

Guarded reads let a partially mapped module use the fallback without a host fault. The hop bound rejects cyclic chains.

`StringXrefTest.EnclosingFunctionFallsBackWhenChainInfoIsCyclic` pins fallback after malformed metadata. `StringXrefTest.EnclosingFunctionRejectsOutOfImageIntermediateChainExtent` pins invalid chained-extent rejection.

### [B-65]

The unmemoized bounded-jump matcher's worst case at one segment-0 start is the PRODUCT of the gap spans, up to `MAX_JUMP_SPAN^MAX_PATTERN_JUMPS`. An untrusted signature can weaponize that into a hang. `extend_segments` caps node visits per position at `detail::SEGMENT_MATCH_STEP_BUDGET` and fails that placement closed. `find_pattern_segmented` also accumulates node visits in a `SegmentedScanBudget` across every start and Nth-occurrence suffix continuation of one physical region. It marks the sweep incomplete once `SEGMENT_MATCH_REGION_STEP_BUDGET` prevents another node visit. Together those caps convert the per-position exponential and its region-wide repetition into bounded work. A `static_assert` keeps the per-position budget above the linear cost of a well-formed pattern, so a real signature is never rejected.

Relatedly, the shared DSL parser `detail::parse_pattern_into` is `constexpr` but NOT `noexcept`. The compile-time fixed-array sink never allocates, but the runtime heap-backed sink's `push_back` can throw `bad_alloc` on an unbounded pattern. `find_string_xref` builds one byte per string byte with no length cap. A `noexcept` mark turns that OOM into `terminate`. The runtime caller `parse_aob` catches `bad_alloc` and fails closed to `nullopt` instead.

### [B-67]

`rtti::TypeIdentity::vtable()` deliberately does not cache a failed resolve. The owning module can map the type later: a DLL loads, or a patch finishes its vtable relocation. A per-frame `matches()` on an absent type then re-sweeps the whole module every frame, the one genuine per-frame cliff. Gate the re-sweep behind a cooldown ( `RESOLVE_RETRY_COOLDOWN_MS`, read through `GetTickCount64` behind a test clock seam). It then runs at most once per cooldown while it still eventually retries. A permanent miss-latch forfeits retry-after-load, a capability regression, and an unthrottled retry pays the full scan every frame. The throttle state is a single atomic timestamp ( `m_last_attempt_ms`) that gates only performance. A lost update at worst costs one extra sweep, and the `now >= last` compare tolerates a non-monotonic clock. Prove the throttle in two steps. Make the type present after a miss and assert that the next in-cooldown call still misses: the sweep was skipped. Then advance the clock past the cooldown and assert that it resolves: the retry capability survived. The changed-generation refresh is also a whole-image sweep. A failed refresh stamps `m_last_attempt_ms` before its writer gate drops. The cooldown gates the next sweep. `RttiReverseProof.TypeIdentityFailedStaleRefreshStartsCooldown` pins that branch.

### [B-68]

The reverse-RTTI sweep tested every candidate through `resolve_col_site`, which re-resolved the owning module through `memory::module_of` (a `GetModuleHandleExW` loader lookup) for each in-scope candidate. Resolve the owning module once at the scan-scope base and hand that span to a `ModuleSpan` -taking overload for every candidate.

The subtlety that makes this correctness-sensitive, not merely an optimization: the owning-module span is not the scan scope. `resolve_col_site` cross-checks the recovered image base (`col_addr - pSelf`) against the module base. It computes the TypeDescriptor and name addresses from module-base plus RVA, so it needs the true module extent. A caller can scope the sweep to a sub-range whose base is not the image base (a tight fixture window). Keep the scope for the meta-slot pre-filter, but validate against `module_of(scope.base)`, with a fallback to the self-resolving overload when that once-resolve is invalid. The scope span passed where the module span is needed silently fails every RVA / pSelf cross-check and finds nothing.

### [B-76]

A forward walk runs from a load (a `lea reg, [rip+string]`) to a dependent instruction (the `mov [rip+slot], reg` that caches the loaded pointer). It MUST fail closed at a `RET`, an unconditional `JMP` (a tail call), `UD2`, or an `INT3` pad. Straight-line flow ends there, so any later instruction belongs to a different function. Its store attributed to this load returns an unrelated address that the caller then writes through, strictly worse than a fail-closed miss. `UD2` and `0xCC` decode as valid instructions, so they need explicit mnemonic stops rather than category checks alone. A CONDITIONAL branch (`Jcc`) is NOT a stop. Its fall-through can legitimately reach the dependent instruction, so a stop there drops a real capability. `scan_store_slot_after_lea` enforces this alongside its existing `CALL` and register-clobber stops.

### [B-77]

Two paths key trust on "is this the only one". They are the quorum independence gate (is this member a distinct signal?) and string-xref uniqueness (is this the only reference?). Both must judge by the CONTENT that determines the resolved site, not by a scan-policy flag or a shape subset.

`collect_independence_atoms` reduces each member to a SET of site-determining atoms. A StringXref reduces to its located-literal identity (text plus encoding), with the `broad_match` / `require_terminator` / `return_mode` facets dropped. A ladder reduces to one atom per rung. It rejects two members whose sets INTERSECT. That canonicalizes a one-rung `RipGlobal` ladder onto the flat kind of its rung AND catches a partial overlap (two ladders that share a rung). Two members that can resolve one site are rejected as dependent instead of double-voters. That holds whether they differ only in a policy flag, in the AnchorKind wrapper, or in only some ladder rungs. Under a `WithinTolerance` quorum, this is what stops two policy-variant views of one site from a landing within tolerance that self-corroborates.

Declared content is not always sufficient. Where it is not, the backend MUST publish the physical source it read, so the post-resolve gate can finish the job. Two export names can be aliases over one `AddressOfFunctions` slot or one function RVA. No declaration can reveal that, because aliasing is a property of the live export table. `resolve_export_with_provenance` therefore reports the resolved module base, slot index, and RVA, and `same_export_site` folds such a pair to one vote. Any future backend whose declared inputs can address one physical site under two spellings owes the same resolved-provenance half.

For a derived string-xref return mode (`EnclosingFunction` / `StringPointerSlot`), the answer is computed from the located reference. The fast narrow scan models only the dominant lea/mov shapes. A narrow `count == 1` is therefore only a shape-local uniqueness claim. With a second reference of a rarer shape (`cmp [rip+d], imm`, a no-REX lea/mov) elsewhere, the derivation attributes the answer to a non-unique site. `find_string_xref` therefore runs the broad Zydis sweep, a superset of every reference shape, before it certifies a derived mode. It proves uniqueness across all shapes even when the caller did not opt into `broad_match`. A second reference then fails the anchor closed to `AmbiguousReference`. `ReferencingInstruction` returns the dominant reference directly and stays on the fast narrow-only path.
