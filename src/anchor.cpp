/**
 * @file anchor.cpp
 * @brief The declarative anchor registry: dispatches each anchor kind to its v4 backend and reports drift uniformly.
 * @details Every kind maps onto exactly one self-healing backend that already fails closed:
 *          - VtableIdentity -> rtti::vtable_for_type (reverse-RTTI vtable resolve),
 *          - RipGlobal      -> scan::resolve         (Direct / RIP-relative candidate cascade),
 *          - CodeOperand    -> scan::read_code_constant (in-code immediate / displacement decode),
 *          - StringXref     -> scan::find_string_xref (string-literal cross-reference resolve),
 *          - ExportName     -> scan::resolve_export   (named export via the module Export Address Table),
 *          - Manual         -> a pinned literal (no backend),
 *          - Quorum         -> N-of-M voting across independent sub-anchors,
 *          - CallArgHome    -> reserved (no resolver yet).
 *          This layer adds no scanning of its own: it maps each backend's typed failure onto the common
 *          AnchorStatus and threads the optional post-resolve validator and the per-game ScanProfile defaults.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/rtti.hpp"

#include "fork_join.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <span>
#include <vector>

namespace DetourModKit
{
    namespace anchor
    {
        namespace
        {
            // Applies the profile's candidate-order preference to a cascade backend that has no order parameter of its
            // own (read_code_constant), by building a local reordered span. The caller's candidate table is typically
            // static storage and must not be mutated, so the vector owns the temporary copy for the backend call.
            // AsDeclared (and a trivially-ordered one-candidate site) returns the original span without allocation.
            [[nodiscard]] std::span<const scan::Candidate> profiled_candidates(const ScanProfile &profile,
                                                                               std::span<const scan::Candidate> site,
                                                                               std::vector<scan::Candidate> &ordered)
            {
                if (profile.candidate_order == scan::CandidateOrder::AsDeclared || site.size() < 2)
                {
                    return site;
                }

                std::vector<std::size_t> indices(site.size());
                const std::size_t count = scan::order_candidates(profile.candidate_order, site, indices);
                ordered.reserve(count);
                for (std::size_t i = 0; i < count; ++i)
                {
                    ordered.push_back(site[indices[i]]);
                }
                return ordered;
            }

            // Fail-closed agreement test for the two quorum signals. A negative tolerance is rejected outright:
            // widening it through unsigned subtraction would turn -1 into a huge bound that accepts almost any gap and
            // defeat the corroboration the quorum exists to provide.
            [[nodiscard]] bool quorum_values_agree(std::int64_t first, std::int64_t second, QuorumMatch match,
                                                   std::int64_t tolerance) noexcept
            {
                if (match == QuorumMatch::ExactValue)
                {
                    return first == second;
                }
                if (tolerance < 0)
                {
                    return false;
                }
                // Order the pair so the gap is hi - lo, then widen through unsigned subtraction to avoid signed
                // overflow across a large address span.
                const std::int64_t lo = (first < second) ? first : second;
                const std::int64_t hi = (first < second) ? second : first;
                const auto gap = static_cast<std::uint64_t>(hi) - static_cast<std::uint64_t>(lo);
                return gap <= static_cast<std::uint64_t>(tolerance);
            }

            // The canonical independence-evidence atoms, defined below with the other fingerprint machinery. Declared
            // here so the independence gate can compare two members by resolved-site CONTENT rather than by the storage
            // identity of their views or the AnchorKind wrapper around that content.
            void collect_independence_atoms(const Anchor &anchor, std::vector<std::uint64_t> &out);

            // True when two resolvable sub-anchors could decode the SAME site -- they share at least one evidence ATOM,
            // so one physical signal could satisfy both and they cannot corroborate each other. Each anchor reduces to
            // a SET of site-determining atoms (one per resolvable rung, or one for a flat kind), canonical across every
            // axis that does NOT change a resolved site: view/span storage (two distinct candidate arrays that compile
            // byte-identically decode one site), ladder ORDER (a fallback ladder's rungs all aim at one target), scan
            // POLICY (a StringXref's return/terminator/broad facets change how the sweep runs, not which literal it
            // finds), and the AnchorKind WRAPPER (a flat StringXref and a one-rung RipGlobal wrapping the same string
            // literal resolve through the identical backend to one site). Two members are dependent when their atom
            // sets INTERSECT -- comparing sets, not whole-anchor hashes, is what catches a PARTIAL overlap: a ladder
            // resolves to its FIRST matching rung, so if two members share any rung they could both land on that one
            // site (one member's primary rung wins, or both members' primaries are patched away onto a shared fallback)
            // and double-vote toward the threshold. The fail-closed direction is a ~2^-64 atom collision rejecting a
            // genuinely-independent pair (the quorum then fails closed, never open). The drift fingerprint
            // (anchor_fingerprint) stays order- and policy-sensitive on purpose; only this gate is canonicalized.
            [[nodiscard]] bool same_backend_config(const Anchor &a, const Anchor &b)
            {
                std::vector<std::uint64_t> atoms_a;
                collect_independence_atoms(a, atoms_a);
                std::vector<std::uint64_t> atoms_b;
                collect_independence_atoms(b, atoms_b);
                for (const std::uint64_t atom_a : atoms_a)
                {
                    for (const std::uint64_t atom_b : atoms_b)
                    {
                        if (atom_a == atom_b)
                        {
                            return true;
                        }
                    }
                }
                return false;
            }

            // Fail-closed independence gate run BEFORE agreement is considered. Two signals are not independent
            // evidence when: (a) they are the exact same Anchor object (pointer-equal); (b) both are Manual literals --
            // two hand-pinned constants agreeing proves only that the author typed the same number twice, not that the
            // live image corroborates it; or (c) they share backend and inputs (same_backend_config), so they decode
            // one site twice. Any of these would let a dependent pair masquerade as corroboration, defeating the
            // quorum's purpose.
            [[nodiscard]] bool quorum_sub_anchors_independent(const Anchor &a, const Anchor &b)
            {
                if (&a == &b)
                {
                    return false;
                }
                if (a.kind == AnchorKind::Manual && b.kind == AnchorKind::Manual)
                {
                    return false;
                }
                return !same_backend_config(a, b);
            }

            // Checks the M members of an N-of-M vote: EVERY pair must be independent evidence. N-of-M only corroborates
            // when no member duplicates another, so a single dependent pair taints the whole vote (one site could be
            // counted twice toward the threshold). This is also what confines a WithinTolerance quorum -- whose votes
            // need only be near, not equal -- to content-independent members, so a cluster of near values can never be
            // an artifact of two members reading adjacent bytes of one site. The caller guarantees no member pointer is
            // null before this runs. O(M^2) over a tiny declared M.
            [[nodiscard]] bool quorum_members_pairwise_independent(std::span<const Anchor *const> members)
            {
                for (std::size_t i = 0; i < members.size(); ++i)
                {
                    for (std::size_t j = i + 1; j < members.size(); ++j)
                    {
                        if (!quorum_sub_anchors_independent(*members[i], *members[j]))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }

            // Counts how many of the cast votes agree with a candidate cluster-center value under the match policy,
            // reusing the same fail-closed pairwise agreement test. A quorum accepts when some member's value anchors a
            // cluster of at least N agreeing votes. Under a negative WithinTolerance the pairwise test rejects even the
            // center against itself, so every cluster is empty and the quorum fails closed, as intended.
            [[nodiscard]] std::size_t votes_agreeing_with(std::int64_t center, std::span<const std::int64_t> votes,
                                                          QuorumMatch match, std::int64_t tolerance) noexcept
            {
                std::size_t agree = 0;
                for (const std::int64_t vote : votes)
                {
                    if (quorum_values_agree(center, vote, match, tolerance))
                    {
                        ++agree;
                    }
                }
                return agree;
            }

            // Commits a backend-resolved value, applying the anchor's optional fail-closed validator. On a validator
            // miss the anchor is reported Failed with no value, identical to a backend miss, so the caller re-heals by
            // re-running resolve.
            void commit_resolved(const Anchor &anchor, ResolvedAnchor &result, std::int64_t value) noexcept
            {
                // Opt-in required-validator policy: a backend-resolved (function/global) target with no domain check is
                // treated as unverified and fails closed. Manual and Quorum are both exempt -- a pinned Manual literal
                // is not a resolved target (require_validator is a backend-target policy, and a Manual only reaches
                // this path at all via validate_manual), and a Quorum's N-of-M corroboration is already the
                // verification. Only the five backend kinds reach this rejection.
                if (anchor.require_validator && anchor.kind != AnchorKind::Quorum &&
                    anchor.kind != AnchorKind::Manual && anchor.validator == nullptr)
                {
                    result.status = AnchorStatus::Failed;
                    result.value = 0;
                    return;
                }
                if (anchor.validator != nullptr && !anchor.validator(value, anchor.validator_context))
                {
                    result.status = AnchorStatus::Failed;
                    result.value = 0;
                    return;
                }
                result.value = value;
                result.status = AnchorStatus::Resolved;
            }

            [[nodiscard]] ResolvedAnchor failed_anchor_result(const Anchor &anchor) noexcept
            {
                return ResolvedAnchor{anchor.label, anchor.kind, AnchorStatus::Failed, 0};
            }

            [[nodiscard]] double clamped_gate_ratio(double ratio) noexcept
            {
                if (std::isnan(ratio))
                {
                    return 1.0;
                }
                if (ratio < 0.0)
                {
                    return 0.0;
                }
                if (ratio > 1.0)
                {
                    return 1.0;
                }
                return ratio;
            }

            // FNV-1a 64 evidence hashing for anchor_fingerprint. The fingerprint must be stable across runs and builds
            // so a persisted manifest can be diffed, so integers are folded least-significant-byte first (a fixed order
            // independent of host endianness) and every variable-length field is length-prefixed to keep adjacent
            // fields unambiguous (the literal "ab" then "" cannot collide with "a" then "b").
            inline constexpr std::uint64_t FNV1A64_OFFSET = 14695981039346656037ULL;
            inline constexpr std::uint64_t FNV1A64_PRIME = 1099511628211ULL;

            [[nodiscard]] std::uint64_t fnv1a_byte(std::uint64_t hash, std::uint8_t value) noexcept
            {
                return (hash ^ value) * FNV1A64_PRIME;
            }

            // Folds an integer least-significant-byte first over sizeof(T) so the result is endianness-independent. The
            // value is widened to u64 before shifting so a 1-byte type never hits a shift-width edge case.
            template <typename T> [[nodiscard]] std::uint64_t fnv1a_int(std::uint64_t hash, T value) noexcept
            {
                auto bits = static_cast<std::uint64_t>(static_cast<std::make_unsigned_t<T>>(value));
                for (std::size_t i = 0; i < sizeof(T); ++i)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(bits & 0xFFu));
                    bits >>= 8;
                }
                return hash;
            }

            // Length-prefixed string field: the size (folded LSB-first) then the bytes, so adjacent fields never alias.
            [[nodiscard]] std::uint64_t fnv1a_field(std::uint64_t hash, std::string_view field) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(field.size()));
                for (const char c : field)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(c));
                }
                return hash;
            }

            // Length-prefixed ASCII case-insensitive field for Windows module basenames. Region::module_named treats
            // basename casing as equivalent, so quorum evidence must do the same or two spellings of one DLL could
            // double-vote as independent exports. Bytes outside ASCII A-Z are preserved for deterministic hashing.
            [[nodiscard]] std::uint64_t fnv1a_module_field(std::uint64_t hash, std::string_view module_name) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(module_name.size()));
                for (const char c : module_name)
                {
                    const auto byte = static_cast<std::uint8_t>(c);
                    const std::uint8_t folded =
                        (byte >= static_cast<std::uint8_t>('A') && byte <= static_cast<std::uint8_t>('Z'))
                            ? static_cast<std::uint8_t>(byte + ('a' - 'A'))
                            : byte;
                    hash = fnv1a_byte(hash, folded);
                }
                return hash;
            }

            // Length-prefixed raw-byte field for a compiled Pattern's bytes / mask spans.
            [[nodiscard]] std::uint64_t fnv1a_bytes(std::uint64_t hash, std::span<const std::byte> data) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(data.size()));
                for (const std::byte b : data)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(b));
                }
                return hash;
            }

            // Hashes one candidate's address-independent CONTENT. scan::Pattern is compiled and does not retain its
            // source string, so the byte tiers hash the compiled bytes + wildcard mask + result-offset plus the decode
            // parameters -- content that is stable across a diff and computable without re-parsing. The text tiers hash
            // their owned name / literal and shape flags directly.
            [[nodiscard]] std::uint64_t fnv1a_candidate(std::uint64_t hash, const scan::Candidate &candidate) noexcept
            {
                hash = fnv1a_byte(hash, static_cast<std::uint8_t>(candidate.mode()));
                switch (candidate.mode())
                {
                case scan::Mode::Direct:
                {
                    const scan::DirectPattern &direct = *candidate.as_direct();
                    hash = fnv1a_bytes(hash, direct.pattern.bytes());
                    hash = fnv1a_bytes(hash, direct.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(direct.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(direct.walk_back));
                    break;
                }
                case scan::Mode::RipRelative:
                {
                    const scan::RipRelativePattern &rip = *candidate.as_rip_relative();
                    hash = fnv1a_bytes(hash, rip.pattern.bytes());
                    hash = fnv1a_bytes(hash, rip.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(rip.displacement_at));
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.instruction_length));
                    break;
                }
                case scan::Mode::RttiVtable:
                    hash = fnv1a_field(hash, candidate.as_rtti_vtable()->mangled);
                    break;
                case scan::Mode::StringXref:
                {
                    const scan::StringXref &xref = *candidate.as_string_xref();
                    hash = fnv1a_field(hash, xref.text);
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(xref.encoding));
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(xref.return_mode));
                    hash = fnv1a_byte(hash, xref.require_terminator ? 1U : 0U);
                    hash = fnv1a_byte(hash, xref.broad_match ? 1U : 0U);
                    break;
                }
                }
                return hash;
            }

            [[nodiscard]] std::uint64_t fnv1a_cascade(std::uint64_t hash,
                                                      std::span<const scan::Candidate> site) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(site.size()));
                for (const scan::Candidate &candidate : site)
                {
                    hash = fnv1a_candidate(hash, candidate);
                }
                return hash;
            }

            // Hashes one anchor's own evidence with no quorum recursion. A Quorum reaching here -- which the public
            // entry point only allows for a malformed sub-anchor, since nesting is rejected at resolve time --
            // contributes only its kind, which bounds recursion to a single level.
            [[nodiscard]] std::uint64_t fingerprint_evidence(const Anchor &anchor) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(anchor.kind));
                switch (anchor.kind)
                {
                case AnchorKind::VtableIdentity:
                    hash = fnv1a_field(hash, anchor.mangled);
                    break;
                case AnchorKind::RipGlobal:
                    hash = fnv1a_cascade(hash, anchor.site);
                    // Preserve legacy fingerprints for the default Readable policy, while treating non-default page
                    // narrowing as a declarative signature change a persisted baseline can detect.
                    if (anchor.pages != scan::Pages::Readable)
                    {
                        hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.pages));
                    }
                    break;
                case AnchorKind::CodeOperand:
                    hash = fnv1a_cascade(hash, anchor.site);
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.operand_kind));
                    hash = fnv1a_byte(hash, anchor.operand_index);
                    hash = fnv1a_byte(hash, anchor.byte_width);
                    break;
                case AnchorKind::StringXref:
                    hash = fnv1a_field(hash, anchor.xref_text);
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.xref_encoding));
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.xref_return));
                    hash = fnv1a_byte(hash, anchor.xref_require_terminator ? 1U : 0U);
                    hash = fnv1a_byte(hash, anchor.xref_broad_match ? 1U : 0U);
                    break;
                case AnchorKind::ExportName:
                    // The module and export name are the whole declarative signature; a renamed export or a retargeted
                    // module is a signature change a persisted baseline should catch as drift.
                    hash = fnv1a_field(hash, anchor.export_module);
                    hash = fnv1a_field(hash, anchor.export_name);
                    break;
                case AnchorKind::Manual:
                    hash = fnv1a_int(hash, anchor.manual_value);
                    break;
                case AnchorKind::CallArgHome:
                case AnchorKind::Quorum:
                case AnchorKind::Unset:
                    // No address-independent evidence beyond the kind byte already folded above.
                    break;
                }
                return hash;
            }

            // Independence evidence (the quorum corroboration gate) answers a different question than the drift
            // fingerprint above: "could these two anchors decode the SAME site?", not "did this anchor's declaration
            // change?". So each anchor reduces to a SET of site-determining ATOMS -- one per resolvable rung, or one
            // for a flat kind -- and two anchors are dependent when their sets intersect. The atoms are canonicalized
            // across two axes the drift fingerprint deliberately keeps:
            //   * scan POLICY is dropped. A StringXref's return_mode / require_terminator / broad_match change how the
            //     sweep runs, never WHICH located literal it resolves, so two members on one literal that differ only in
            //     a facet decode the same reference and must count as one signal. They would otherwise double-vote --
            //     and under a WithinTolerance quorum two policy-variant views of one site could even land within
            //     tolerance and self-corroborate from a single physical signal.
            //   * the AnchorKind WRAPPER is dropped. A flat StringXref and a one-rung RipGlobal whose sole rung is a
            //     StringXref candidate both resolve through find_string_xref to the identical site; a flat
            //     VtableIdentity and a one-rung RipGlobal wrapping an RttiVtable candidate both resolve one vtable. The
            //     gate reduces each anchor to kind-neutral evidence ATOMS so these equivalent spellings collide.
            // Each atom carries an EvidenceClass tag (NOT the AnchorKind and NOT the scan::Mode) so a flat text kind
            // and a candidate rung of the same class fold identically. Comparing atom SETS (not a single whole-anchor
            // hash) is what catches a PARTIAL rung overlap: two ladders that share one rung share that atom, so they
            // are dependent even when their other rungs differ.
            enum class EvidenceClass : std::uint8_t
            {
                ByteDirect = 1,
                ByteRip = 2,
                Vtable = 3,
                String = 4,
                Manual = 5,
                Empty = 6,
                Export = 7,
            };

            // A located literal's identity: its bytes (text) and how it is stored (encoding). Utf8 "foo" and Utf16le
            // "foo" are different image literals at different addresses, so the encoding is evidence; the scan facets
            // are not. A flat StringXref anchor and a StringXref candidate rung both route here so they fold
            // identically.
            [[nodiscard]] std::uint64_t string_evidence_atom(std::string_view text,
                                                             scan::StringEncoding encoding) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::String));
                hash = fnv1a_field(hash, text);
                return fnv1a_byte(hash, static_cast<std::uint8_t>(encoding));
            }

            // A vtable identity's evidence: its mangled type name, resolved the same way whether it is a flat
            // VtableIdentity anchor or an RttiVtable candidate rung.
            [[nodiscard]] std::uint64_t vtable_evidence_atom(std::string_view mangled) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Vtable));
                return fnv1a_field(hash, mangled);
            }

            // A named export's identity: its module and export name, which together determine the single EAT entry it
            // resolves. Two ExportName anchors on the same module+name resolve the identical address, so they fold to
            // one atom and cannot double-vote in a quorum; differ in either the module or the name and they resolve
            // different exports and stay independent. An EAT lookup has no scan facets, so there is nothing further to
            // fold. The module name is part of the atom precisely so kernel32!Foo and ntdll!Foo do not collide.
            //
            // The atom folds the DECLARED module name, not a resolved module base, so it stays independent of load
            // state: Region::module_named yields no base for a not-yet-loaded module, so folding a resolved base would
            // collapse two distinct unloaded modules onto one empty base and wrongly reject them as dependent. The
            // trade-off is that an empty module (which resolves in the caller's scope) is not folded against an
            // explicit module naming that same scope; that redundant pair can double-vote only when the quorum scope
            // equals the named module, and even then both members resolve the identical, correct address.
            [[nodiscard]] std::uint64_t export_evidence_atom(std::string_view module_name,
                                                             std::string_view export_name) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Export));
                hash = fnv1a_module_field(hash, module_name);
                return fnv1a_field(hash, export_name);
            }

            // One candidate rung's site-determining atom, kind-neutral and policy-stripped. A byte tier keeps every
            // field that moves its resolved address (compiled bytes / mask / offset plus the tier-specific walk-back or
            // displacement/length); a text tier reduces to the same atom its flat AnchorKind produces.
            [[nodiscard]] std::uint64_t candidate_evidence_atom(const scan::Candidate &candidate) noexcept
            {
                switch (candidate.mode())
                {
                case scan::Mode::Direct:
                {
                    const scan::DirectPattern &direct = *candidate.as_direct();
                    std::uint64_t hash =
                        fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::ByteDirect));
                    hash = fnv1a_bytes(hash, direct.pattern.bytes());
                    hash = fnv1a_bytes(hash, direct.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(direct.pattern.offset()));
                    return fnv1a_int(hash, static_cast<std::int64_t>(direct.walk_back));
                }
                case scan::Mode::RipRelative:
                {
                    const scan::RipRelativePattern &rip = *candidate.as_rip_relative();
                    std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::ByteRip));
                    hash = fnv1a_bytes(hash, rip.pattern.bytes());
                    hash = fnv1a_bytes(hash, rip.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(rip.displacement_at));
                    return fnv1a_int(hash, static_cast<std::uint64_t>(rip.instruction_length));
                }
                case scan::Mode::RttiVtable:
                    return vtable_evidence_atom(candidate.as_rtti_vtable()->mangled);
                case scan::Mode::StringXref:
                {
                    const scan::StringXref &xref = *candidate.as_string_xref();
                    return string_evidence_atom(xref.text, xref.encoding);
                }
                }
                return fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Empty));
            }

            // Collects the site-determining evidence ATOMS of an anchor, appending to out. Two anchors are dependent
            // evidence iff their atom sets intersect. A flat text/manual kind contributes exactly ONE atom, identical
            // to the atom its one-rung ladder spelling produces, so the two spellings share it and collide. A ladder
            // contributes one atom per rung, so two ladders that share a rung share that atom -- the PARTIAL-overlap
            // case a single whole-anchor hash would miss. The drift fingerprint (fingerprint_evidence /
            // anchor_fingerprint) is deliberately NOT reused here: it stays policy- and order-sensitive because a facet
            // or reorder edit IS a signature change to report as drift, even if it is not independent corroboration.
            void collect_independence_atoms(const Anchor &anchor, std::vector<std::uint64_t> &out)
            {
                const std::size_t start = out.size();
                switch (anchor.kind)
                {
                case AnchorKind::VtableIdentity:
                    out.push_back(vtable_evidence_atom(anchor.mangled));
                    break;
                case AnchorKind::StringXref:
                    out.push_back(string_evidence_atom(anchor.xref_text, anchor.xref_encoding));
                    break;
                case AnchorKind::ExportName:
                    out.push_back(export_evidence_atom(anchor.export_module, anchor.export_name));
                    break;
                case AnchorKind::Manual:
                {
                    std::uint64_t atom = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Manual));
                    out.push_back(fnv1a_int(atom, anchor.manual_value));
                    break;
                }
                case AnchorKind::RipGlobal:
                    // RipGlobal resolves its cascade's site directly (scan::resolve), so each rung's atom is a site the
                    // anchor could land on -- which is why a one-rung RipGlobal shares the flat kind of its rung, and
                    // why a shared fallback rung makes two ladders dependent.
                    for (const scan::Candidate &candidate : anchor.site)
                    {
                        out.push_back(candidate_evidence_atom(candidate));
                    }
                    break;
                case AnchorKind::CodeOperand:
                    // CodeOperand decodes an operand FROM a rung's site, so the operand selector folds onto each rung
                    // atom: two CodeOperands over one site but a different operand_kind / index / width decode
                    // different values and ARE independent. Folding it also keeps a CodeOperand([string_xref]) distinct
                    // from a flat StringXref, which is correct -- they resolve different values.
                    for (const scan::Candidate &candidate : anchor.site)
                    {
                        std::uint64_t atom = candidate_evidence_atom(candidate);
                        atom = fnv1a_byte(atom, static_cast<std::uint8_t>(anchor.operand_kind));
                        atom = fnv1a_byte(atom, anchor.operand_index);
                        out.push_back(fnv1a_byte(atom, anchor.byte_width));
                    }
                    break;
                case AnchorKind::CallArgHome:
                case AnchorKind::Quorum:
                case AnchorKind::Unset:
                    // No resolvable evidence: a nested Quorum member is rejected at resolve time and CallArgHome /
                    // Unset never cast a vote. The post-switch guard contributes a kind-tagged Empty atom.
                    break;
                }
                if (out.size() == start)
                {
                    // No resolvable rung was collected (a composite / reserved kind, or a malformed empty ladder):
                    // contribute one kind-tagged Empty atom so the set is never empty and two such degenerate anchors
                    // of the same kind still compare dependent rather than silently independent.
                    std::uint64_t atom = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Empty));
                    out.push_back(fnv1a_byte(atom, static_cast<std::uint8_t>(anchor.kind)));
                }
            }

            constexpr std::uint64_t NULL_SUB_ANCHOR = 0;

            [[nodiscard]] std::uint64_t quorum_member_evidence(const Anchor *member) noexcept
            {
                return member != nullptr ? fingerprint_evidence(*member) : NULL_SUB_ANCHOR;
            }
        } // anonymous namespace

        scan::StringRefQuery apply_profile(const ScanProfile &profile, scan::StringRefQuery query) noexcept
        {
            // Widen-only: a per-anchor broad_match already set stays set; the profile can turn broad on but never off.
            query.broad_match = query.broad_match || profile.default_broad_string_xref;
            return query;
        }

        ResolvedAnchor resolve_with_profile(const Anchor &anchor, const ScanProfile &profile, Region scope)
        {
            ResolvedAnchor result{anchor.label, anchor.kind, AnchorStatus::Unresolved, 0};

            // Backend deny-list: a denied kind fails closed before any scan. It is never silently replaced by another
            // backend, which would risk returning a different, wrong target. An empty profile (the default resolve()
            // path) denies nothing, so this is a no-op there.
            if (profile.is_denied(anchor.kind))
            {
                result.status = AnchorStatus::Failed;
                return result;
            }

            switch (anchor.kind)
            {
            case AnchorKind::VtableIdentity:
            {
                const std::optional<Address> vtable = DetourModKit::rtti::vtable_for_type(anchor.mangled, scope);
                if (vtable)
                {
                    commit_resolved(anchor, result, static_cast<std::int64_t>(vtable->raw()));
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::RipGlobal:
            {
                if (anchor.pages != scan::Pages::Readable && anchor.pages != scan::Pages::Executable)
                {
                    return failed_anchor_result(anchor);
                }
                // The cascade itself selects Direct vs RIP-relative per candidate, so a plain global address and a
                // RIP-relative one share this backend. The resolver applies the profile's candidate order internally
                // through ScanRequest::order, so no local reordered copy is needed here. The page class defaults to
                // Readable (a Direct rung may resolve a data-page global); a caller that knows every rung anchors on an
                // in-image instruction narrows it to Executable through Anchor::pages so a data-page byte twin cannot
                // alias the site.
                const scan::ScanRequest request{
                    .ladder = anchor.site,
                    .label = anchor.label,
                    .scope = scope,
                    .order = profile.candidate_order,
                    .pages = anchor.pages,
                };
                const Result<scan::Hit> hit = scan::resolve(request);
                if (hit)
                {
                    commit_resolved(anchor, result, static_cast<std::int64_t>(hit->address.raw()));
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::CodeOperand:
            {
                // read_code_constant has no order parameter, so the profile's candidate order is applied by reordering
                // the site into a local ladder up front.
                std::vector<scan::Candidate> ordered_site;
                const scan::CodeConstant code_constant{
                    .site = profiled_candidates(profile, anchor.site, ordered_site),
                    .kind = anchor.operand_kind,
                    .operand_index = anchor.operand_index,
                    .byte_width = anchor.byte_width,
                };
                const Result<std::int64_t> constant = scan::read_code_constant(code_constant, scope);
                if (constant)
                {
                    commit_resolved(anchor, result, *constant);
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::StringXref:
            {
                // Anchor on an immutable string literal, then resolve the instruction (or enclosing function) that
                // references it. The string survives game updates far better than the surrounding code, so this is the
                // most update-resilient backend; it fails closed on a missing, duplicated, or unreferenced string.
                scan::StringRefQuery query{};
                query.text = anchor.xref_text;
                query.encoding = anchor.xref_encoding;
                query.require_terminator = anchor.xref_require_terminator;
                query.return_mode = anchor.xref_return;
                query.broad_match = anchor.xref_broad_match;
                // The profile can only widen the broad sweep on (never off); a per-anchor xref_broad_match still wins.
                query = apply_profile(profile, query);
                const Result<Address> site = scan::find_string_xref(query, scope);
                if (site)
                {
                    commit_resolved(anchor, result, static_cast<std::int64_t>(site->raw()));
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::ExportName:
            {
                // Resolve a named export by walking its module's PE Export Address Table -- the most update-resilient
                // backend, since an export name is a module's documented ABI rather than a patch-fragile byte pattern.
                // The export's owning module is often not the table's shared scan scope (a mod scanning the game exe
                // may anchor on a game DLL's export), so an explicit export_module names it and is resolved through
                // module_named at resolve time; an empty export_module resolves the export within the passed scope. The
                // backend fails closed on an unloaded module, an absent or forwarded export, or a corrupt export
                // directory, so a miss surfaces as Failed with no invented address.
                const Region module = anchor.export_module.empty() ? scope : Region::module_named(anchor.export_module);
                const Result<Address> site = scan::resolve_export(anchor.export_name, module);
                if (site)
                {
                    commit_resolved(anchor, result, static_cast<std::int64_t>(site->raw()));
                }
                else
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::Manual:
                // A pinned literal always "resolves"; a report should still flag it as at-risk (it cannot self-heal) by
                // inspecting the kind. By default the validator is skipped (the pinned-literal exemption); a caller
                // that opts in via validate_manual routes the literal through the same fail-closed validator path as a
                // backend.
                if (anchor.validate_manual)
                {
                    commit_resolved(anchor, result, anchor.manual_value);
                }
                else
                {
                    result.value = anchor.manual_value;
                    result.status = AnchorStatus::Resolved;
                }
                break;
            case AnchorKind::CallArgHome:
                // Reserved for a future prologue-dataflow backend; no resolver yet.
                result.status = AnchorStatus::Unsupported;
                break;
            case AnchorKind::Quorum:
            {
                // A critical target accepts only when at least N of its M candidate signals independently resolve and
                // agree (N-of-M voting). Corroboration this way survives a patch that breaks some of the M signals as
                // long as N of them still agree, which no single backend can. Fail closed on a malformed declaration
                // exactly as the single-signal backends fail closed on ambiguity.
                const std::span<const Anchor *const> members = anchor.quorum_members;

                // A quorum needs at least two members to corroborate; a null member or a member that is itself a Quorum
                // is malformed (rejecting nested Quorum bounds recursion to one level).
                if (members.size() < 2)
                {
                    result.status = AnchorStatus::Failed;
                    break;
                }
                const bool malformed_member =
                    std::any_of(members.begin(), members.end(), [](const Anchor *member) noexcept
                                { return member == nullptr || member->kind == AnchorKind::Quorum; });
                if (malformed_member)
                {
                    result.status = AnchorStatus::Failed;
                    break;
                }

                // Effective N: 0 means unanimous (all members), so a default two-member quorum is the strict 2-of-2.
                // A quorum is corroboration, so an explicit N below 2 or above the member count is a malformed vote and
                // fails closed rather than silently degrading to a single signal.
                const std::size_t threshold = (anchor.quorum_threshold == 0) ? members.size() : anchor.quorum_threshold;
                if (threshold < 2 || threshold > members.size())
                {
                    result.status = AnchorStatus::Failed;
                    break;
                }

                // Independence is a static property of the declaration, so check it before the (potentially expensive)
                // recursive resolves. Every member must be independent of every other; one dependent pair means the
                // vote could count a single site twice, so report it precisely instead of letting it look corroborated.
                if (!quorum_members_pairwise_independent(members))
                {
                    result.status = AnchorStatus::QuorumNotIndependent;
                    break;
                }

                // Resolve each member with the same profile so a denied sub-anchor kind (or a profile broad-default)
                // threads down; only a member that resolves casts a vote. A member that fails contributes nothing
                // rather than vetoing the vote -- that is the whole point of N-of-M: the target still corroborates when
                // one of several independent signals breaks on a patch, so long as N of the rest agree.
                std::vector<std::int64_t> votes;
                votes.reserve(members.size());
                for (const Anchor *member : members)
                {
                    const ResolvedAnchor resolved_member = resolve_with_profile(*member, profile, scope);
                    if (resolved_member.status == AnchorStatus::Resolved)
                    {
                        votes.push_back(resolved_member.value);
                    }
                }

                // Accept if some member's value anchors an agreement cluster of at least N votes. Scanning the votes in
                // declaration order and committing the first qualifying center keeps the corroborated value
                // deterministic: for ExactValue every cluster member shares the value; for WithinTolerance it is the
                // cluster center, within tolerance of the rest. Commit through the shared path so the Quorum's own
                // validator runs on that value (each member's validator already ran in its recursive resolve).
                bool corroborated = false;
                for (const std::int64_t center : votes)
                {
                    if (votes_agreeing_with(center, votes, anchor.quorum_match, anchor.quorum_tolerance) >= threshold)
                    {
                        commit_resolved(anchor, result, center);
                        corroborated = true;
                        break;
                    }
                }
                if (!corroborated)
                {
                    result.status = AnchorStatus::Failed;
                }
                break;
            }
            case AnchorKind::Unset:
                // A default-constructed anchor whose kind was never set. There is no backend to resolve and no value to
                // trust, so fail closed rather than invent one -- this is the whole reason Unset exists.
                result.status = AnchorStatus::Failed;
                break;
            }

            return result;
        }

        ResolvedAnchor resolve(const Anchor &anchor, Region scope)
        {
            // An empty profile denies nothing and widens nothing, so this is exactly the un-profiled resolution.
            return resolve_with_profile(anchor, ScanProfile{}, scope);
        }

        std::size_t resolve_all(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out, Region scope)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = resolve(anchors[i], scope);
            }
            return count;
        }

        std::size_t resolve_all_parallel(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out, Region scope,
                                         std::size_t max_workers)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            const std::vector<ResolvedAnchor> results = DetourModKit::detail::run_fork_join<Anchor, ResolvedAnchor>(
                anchors.first(count), max_workers,
                [scope](const Anchor &anchor) -> ResolvedAnchor { return resolve(anchor, scope); },
                [](const Anchor &anchor) noexcept -> ResolvedAnchor { return failed_anchor_result(anchor); });

            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = results[i];
            }
            return count;
        }

        std::size_t resolve_all_with_profile(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                             const ScanProfile &profile, Region scope)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = resolve_with_profile(anchors[i], profile, scope);
            }
            return count;
        }

        std::size_t resolve_all_with_profile_parallel(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                                      const ScanProfile &profile, Region scope, std::size_t max_workers)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            const std::vector<ResolvedAnchor> results = DetourModKit::detail::run_fork_join<Anchor, ResolvedAnchor>(
                anchors.first(count), max_workers, [&profile, scope](const Anchor &anchor) -> ResolvedAnchor
                { return resolve_with_profile(anchor, profile, scope); },
                [](const Anchor &anchor) noexcept -> ResolvedAnchor { return failed_anchor_result(anchor); });

            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = results[i];
            }
            return count;
        }

        AnchorQuality assess_quality(std::span<const ResolvedAnchor> report) noexcept
        {
            AnchorQuality quality{};
            quality.total = report.size();
            for (const ResolvedAnchor &entry : report)
            {
                switch (entry.status)
                {
                case AnchorStatus::Resolved:
                    ++quality.resolved;
                    break;
                case AnchorStatus::Failed:
                    ++quality.failed;
                    break;
                case AnchorStatus::Unsupported:
                    ++quality.unsupported;
                    break;
                case AnchorStatus::QuorumNotIndependent:
                    ++quality.not_independent;
                    break;
                case AnchorStatus::Unresolved:
                    break;
                }
                // A pinned literal is at-risk regardless of status: it "resolves" but cannot self-heal across a patch.
                if (entry.kind == AnchorKind::Manual)
                {
                    ++quality.manual_at_risk;
                }
                // A corroborated quorum is the strongest evidence: N independent signals had to agree.
                if (entry.kind == AnchorKind::Quorum && entry.status == AnchorStatus::Resolved)
                {
                    ++quality.corroborated;
                }
            }
            return quality;
        }

        GateVerdict evaluate_gate(const AnchorQuality &quality, const GatePolicy &policy) noexcept
        {
            // The span overload always feeds a self-consistent summary, but the direct AnchorQuality overload is
            // public. If a caller supplies impossible counts, fail closed rather than letting an inflated resolved
            // count create a healthy verdict.
            std::size_t accounted = 0;
            const auto count_fits = [&accounted, total = quality.total](std::size_t count) noexcept -> bool
            {
                if (count > total - accounted)
                {
                    return false;
                }
                accounted += count;
                return true;
            };
            if (!count_fits(quality.resolved) || !count_fits(quality.failed) || !count_fits(quality.unsupported) ||
                !count_fits(quality.not_independent))
            {
                return GateVerdict::Fail;
            }

            // A QuorumNotIndependent outcome committed no value (it fails closed exactly like a backend miss), so it
            // counts as a failure alongside Failed for the cap: both mean an anchor the manifest declared did not yield
            // a verified value. Check the hard cap first so a manifest riddled with failures fails the gate even if the
            // few that did resolve happen to clear the ratio.
            if (quality.failed > policy.max_failed)
            {
                return GateVerdict::Fail;
            }
            const std::size_t remaining_failure_budget = policy.max_failed - quality.failed;
            if (quality.not_independent > remaining_failure_budget)
            {
                return GateVerdict::Fail;
            }

            // Resolvable excludes the Unsupported (CallArgHome) kind: it has no backend and can never heal, so folding
            // it into the denominator would permanently penalize a manifest that merely declares a forward-compatible
            // kind. Everything else that could have resolved but did not -- Failed, QuorumNotIndependent, and any
            // untouched Unresolved slot (e.g. a caller that gated the whole output buffer instead of the written
            // prefix) -- stays in the denominator, so a partial resolve drags the ratio down and fails closed rather
            // than flattering the resolved count.
            const std::size_t resolvable = quality.total - quality.unsupported;
            if (resolvable == 0)
            {
                // Nothing assessable proves nothing about runtime health: an empty report or an all-unsupported table
                // should not become a healthy Pass merely because there were no resolvable anchors to contradict it.
                return GateVerdict::Degraded;
            }

            // Clamp a caller-supplied ratio to [0, 1] so an out-of-range value cannot invert the comparison. NaN is
            // treated as the strict default rather than as a threshold that never compares true. Test resolved >= ratio
            // * resolvable as `resolved < ratio * resolvable` to fail closed. The comparison avoids division so the
            // exact-full case (ratio 1.0, every resolvable anchor resolved) stays an exact floating-point equality.
            const double ratio = clamped_gate_ratio(policy.min_resolved_ratio);
            if (static_cast<double>(quality.resolved) < ratio * static_cast<double>(resolvable))
            {
                return GateVerdict::Fail;
            }

            // Cleared the hard thresholds. A pinned Manual literal resolved but cannot self-heal, so surface it as a
            // soft risk when the policy asks: the feature can run, but the caller should log that a manual offset is
            // load-bearing and will silently drift on the next patch.
            if (policy.manual_at_risk_degrades && quality.manual_at_risk > 0)
            {
                return GateVerdict::Degraded;
            }
            return GateVerdict::Pass;
        }

        GateVerdict evaluate_gate(std::span<const ResolvedAnchor> report, const GatePolicy &policy) noexcept
        {
            return evaluate_gate(assess_quality(report), policy);
        }

        std::uint64_t anchor_fingerprint(const Anchor &anchor) noexcept
        {
            if (anchor.kind != AnchorKind::Quorum)
            {
                return fingerprint_evidence(anchor);
            }

            // A quorum's evidence is the combined evidence of its M members, folded order-independently (voting is
            // symmetric, so reordering the members must not change the fingerprint) plus the effective vote threshold
            // and agreement policy. The per-member evidence hashes are emitted in sorted order without allocating: each
            // pass finds the next larger evidence value and folds all duplicates of that value. A null member -- which
            // fails closed at resolve time -- contributes a fixed sentinel so the result stays defined rather than
            // dereferencing through nullptr.
            const std::span<const Anchor *const> members = anchor.quorum_members;

            std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(AnchorKind::Quorum));
            hash = fnv1a_int(hash, static_cast<std::uint64_t>(members.size()));

            std::uint64_t previous = 0;
            bool have_previous = false;
            std::size_t emitted = 0;
            while (emitted < members.size())
            {
                std::uint64_t next = 0;
                bool found_next = false;
                for (const Anchor *member : members)
                {
                    const std::uint64_t evidence = quorum_member_evidence(member);
                    if (have_previous && evidence <= previous)
                    {
                        continue;
                    }
                    if (!found_next || evidence < next)
                    {
                        next = evidence;
                        found_next = true;
                    }
                }

                if (!found_next)
                {
                    break;
                }

                std::size_t duplicate_count = 0;
                for (const Anchor *member : members)
                {
                    if (quorum_member_evidence(member) == next)
                    {
                        ++duplicate_count;
                    }
                }
                for (std::size_t i = 0; i < duplicate_count; ++i)
                {
                    hash = fnv1a_int(hash, next);
                }

                previous = next;
                have_previous = true;
                emitted += duplicate_count;
            }
            const std::size_t effective_threshold =
                (anchor.quorum_threshold == 0) ? members.size() : anchor.quorum_threshold;
            hash = fnv1a_int(hash, static_cast<std::uint64_t>(effective_threshold));
            hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.quorum_match));
            hash = fnv1a_int(hash, anchor.quorum_tolerance);
            return hash;
        }

        std::string_view anchor_status_to_string(AnchorStatus status) noexcept
        {
            switch (status)
            {
            case AnchorStatus::Unresolved:
                return "Unresolved";
            case AnchorStatus::Resolved:
                return "Resolved";
            case AnchorStatus::Failed:
                return "Failed";
            case AnchorStatus::Unsupported:
                return "Unsupported";
            case AnchorStatus::QuorumNotIndependent:
                return "QuorumNotIndependent";
            }
            return "Unknown";
        }

        std::string_view gate_verdict_to_string(GateVerdict verdict) noexcept
        {
            switch (verdict)
            {
            case GateVerdict::Pass:
                return "Pass";
            case GateVerdict::Degraded:
                return "Degraded";
            case GateVerdict::Fail:
                return "Fail";
            }
            return "Unknown";
        }
    } // namespace anchor
} // namespace DetourModKit
