/**
 * @file anchor_evidence.cpp
 * @brief This TU owns anchor evidence identity: the drift fingerprints and the quorum independence atoms.
 *
 * The resolution engine stays in anchor.cpp and reaches the independence gate through
 * internal/anchor_evidence.hpp. Fingerprint results stay stable across runs and builds.
 */

#include "DetourModKit/anchor.hpp"

#include "internal/anchor_evidence.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace DetourModKit
{
    namespace anchor
    {
        namespace
        {
            // FNV-1a 64 hashes evidence for anchor_fingerprint. Integers use least-significant-byte order. Every
            // variable-length field has a length prefix.
            inline constexpr std::uint64_t FNV1A64_OFFSET = 14695981039346656037ULL;
            inline constexpr std::uint64_t FNV1A64_PRIME = 1099511628211ULL;

            [[nodiscard]] std::uint64_t fnv1a_byte(std::uint64_t hash, std::uint8_t value) noexcept
            {
                return (hash ^ value) * FNV1A64_PRIME;
            }

            // Widen to u64 before each shift so a 1-byte type never hits a shift-width edge case.
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

            // Prefixes each string field with its length so adjacent fields never alias.
            [[nodiscard]] std::uint64_t fnv1a_field(std::uint64_t hash, std::string_view field) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(field.size()));
                for (const char c : field)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(c));
                }
                return hash;
            }

            // Uses ASCII case-insensitive module basenames. Case variants of one DLL must not cast independent export
            // votes.
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

            // A length prefix delimits the raw-byte field for a compiled Pattern's byte or mask span.
            [[nodiscard]] std::uint64_t fnv1a_bytes(std::uint64_t hash, std::span<const std::byte> data) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(data.size()));
                for (const std::byte b : data)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(b));
                }
                return hash;
            }

            // Folds the bounded-jump gap structure. bytes()/mask() carry only fixed segments. Without gap data,
            // patterns that differ only by variable gaps share a fingerprint. Jump-free patterns retain their prior
            // fingerprint.
            [[nodiscard]] std::uint64_t fnv1a_pattern_jumps(std::uint64_t hash, const scan::Pattern &pattern) noexcept
            {
                const detail::PatternBuffer &buffer = detail::pattern_buffer(pattern);
                if (buffer.jump_count == 0)
                {
                    return hash;
                }
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(buffer.jump_count));
                for (std::size_t index = 0; index < buffer.jump_count; ++index)
                {
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(buffer.jumps[index].position));
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(buffer.jumps[index].min_skip));
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(buffer.jumps[index].max_skip));
                }
                return hash;
            }

            // Hashes one candidate's address-independent content. It includes compiled bytes, mask, offset, and decode
            // parameters for byte tiers. It includes owned name, literal, and shape flags for text tiers.
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
                    hash = fnv1a_pattern_jumps(hash, direct.pattern);
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
                    hash = fnv1a_pattern_jumps(hash, rip.pattern);
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

            [[nodiscard]] std::uint64_t
            fnv1a_cascade(std::uint64_t hash, std::span<const scan::Candidate> site) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(site.size()));
                for (const scan::Candidate &candidate : site)
                {
                    hash = fnv1a_candidate(hash, candidate);
                }
                return hash;
            }

            // Hashes one anchor's evidence without quorum recursion. If a malformed sub-anchor sends Quorum here,
            // only its kind contributes. This limits recursion to one level.
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
                    // Preserve legacy fingerprints for the default Readable policy. Treat any other page policy as a
                    // declarative signature change that a persisted baseline can detect.
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
                    // The module and export name are the whole declarative signature.
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

            // Independence evidence asks whether two anchors can decode one site, while drift evidence asks whether a
            // declaration changed. Each anchor becomes a set of site evidence atoms. Scan policy and AnchorKind
            // wrappers do not alter the site. Thus policy variants and a flat StringXref versus a one-rung RipGlobal
            // over the same literal count as one signal. EvidenceClass, rather than AnchorKind or scan::Mode, tags each
            // atom.
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

            // A located literal uses its bytes and storage format as identity. Utf8 "foo" and Utf16le "foo" are
            // different image literals. Scan facets are not evidence.
            [[nodiscard]] std::uint64_t
            string_evidence_atom(std::string_view text, scan::StringEncoding encoding) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::String));
                hash = fnv1a_field(hash, text);
                return fnv1a_byte(hash, static_cast<std::uint8_t>(encoding));
            }

            // The mangled type name identifies vtable evidence.
            [[nodiscard]] std::uint64_t vtable_evidence_atom(std::string_view mangled) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Vtable));
                return fnv1a_field(hash, mangled);
            }

            // A named export uses its declared module and export name as identity. The live table decides which names
            // alias, so backend provenance resolves aliases later. Use the declared module name, not a resolved base.
            // A base key collapses distinct unloaded modules onto one empty base. quorum_sub_anchors_independent
            // catches the empty and explicit module overlap.
            [[nodiscard]] std::uint64_t
            export_evidence_atom(std::string_view module_name, std::string_view export_name) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Export));
                hash = fnv1a_module_field(hash, module_name);
                return fnv1a_field(hash, export_name);
            }

            // Builds one candidate rung's site identity atom without kind or policy data. A byte tier keeps every field
            // that moves its address. A text tier reduces to its flat AnchorKind atom.
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
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(direct.walk_back));
                    return fnv1a_pattern_jumps(hash, direct.pattern);
                }
                case scan::Mode::RipRelative:
                {
                    const scan::RipRelativePattern &rip = *candidate.as_rip_relative();
                    std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::ByteRip));
                    hash = fnv1a_bytes(hash, rip.pattern.bytes());
                    hash = fnv1a_bytes(hash, rip.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(rip.displacement_at));
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.instruction_length));
                    return fnv1a_pattern_jumps(hash, rip.pattern);
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

            // Collects one site evidence atom per resolvable rung, or one for a flat kind. Do not reuse the drift
            // fingerprint here. It keeps policy and order because a facet edit or reorder is signature drift.
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
                case AnchorKind::CodeOperand:
                    // Both kinds resolve through a rung site, which defines the failure domain. Each rung contributes
                    // only its site atom. The atom deliberately omits a CodeOperand selector. Two selectors over one
                    // site form one witness.
                    for (const scan::Candidate &candidate : anchor.site)
                    {
                        out.push_back(candidate_evidence_atom(candidate));
                    }
                    break;
                case AnchorKind::CallArgHome:
                case AnchorKind::Quorum:
                case AnchorKind::Unset:
                    // No resolvable evidence exists. The post-switch guard contributes a kind-tagged Empty atom.
                    break;
                }
                if (out.size() == start)
                {
                    // Contribute one kind-tagged Empty atom so the set is never empty. Two degenerate anchors of the
                    // same kind remain dependent.
                    std::uint64_t atom = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Empty));
                    out.push_back(fnv1a_byte(atom, static_cast<std::uint8_t>(anchor.kind)));
                }
            }

            // Returns true when two resolvable sub-anchors can decode one site. Such anchors share at least one
            // evidence atom, so one physical signal can satisfy both. Set intersection catches partial overlap.
            // Two ladders with one shared rung can land on one site and cast two votes. collect_independence_atoms
            // defines the canonical axes. An atom collision rejects a valid pair and therefore fails closed.
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

            // This independence gate fails closed before agreement. The same Anchor object, two Manual literals, or
            // one shared backend config are not independent. Two Manual values prove no live-image corroboration.
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
                // Two same-name ExportName members are one witness if the modules match or either module is empty.
                // The empty module can resolve inside the named module. The static atom cannot detect this overlap.
                if (a.kind == AnchorKind::ExportName && b.kind == AnchorKind::ExportName &&
                    a.export_name == b.export_name &&
                    (a.export_module.empty() || b.export_module.empty() || a.export_module == b.export_module))
                {
                    return false;
                }
                return !same_backend_config(a, b);
            }

            constexpr std::uint64_t NULL_SUB_ANCHOR = 0;

            [[nodiscard]] std::uint64_t quorum_member_evidence(const Anchor *member) noexcept
            {
                return member != nullptr ? fingerprint_evidence(*member) : NULL_SUB_ANCHOR;
            }
        } // anonymous namespace

        namespace internal
        {
            // Contract in internal/anchor_evidence.hpp.
            bool quorum_members_pairwise_independent(std::span<const Anchor *const> members)
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
        } // namespace internal

        std::uint64_t anchor_fingerprint(const Anchor &anchor) noexcept
        {
            if (anchor.kind != AnchorKind::Quorum)
            {
                return fingerprint_evidence(anchor);
            }

            // A quorum folds member evidence without order because the vote is symmetric. It also folds the effective
            // threshold and agreement policy. Member hashes use sorted order without allocation. A null member adds a
            // fixed sentinel.
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

        std::uint64_t anchor_trust_fingerprint(const Anchor &anchor, scan::ImageIdentity scope_identity) noexcept
        {
            std::uint64_t hash = 0;
            if (anchor.kind == AnchorKind::ExportName)
            {
                // Bind the effective module by identity, not by the declared export_module text. An empty module from
                // scope and an explicit name for that module therefore fold to one key.
                hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(AnchorKind::ExportName));
                hash = fnv1a_field(hash, anchor.export_name);
            }
            else
            {
                hash = anchor_fingerprint(anchor);
            }
            // Fold the effective image identity last: a same-base remap changes it, while ASLR alone does not.
            return fnv1a_int(hash, scope_identity.token());
        }
    } // namespace anchor
} // namespace DetourModKit
