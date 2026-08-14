/**
 * @file manifest_overlay.cpp
 * @brief This TU implements Signature compile/adopt, the default-overlay merge, and the resolve-time trust gate.
 * @details Record validation comes from internal/manifest_record_rules.hpp, so this TU and the parse-serialize TU
 *          (manifest.cpp) enforce one rule set. No INI machinery appears here.
 */

#include "DetourModKit/manifest.hpp"

#include "DetourModKit/logger.hpp"

#include "internal/anchor_resolution.hpp"
#include "internal/manifest_record_rules.hpp"
#include "internal/memory_guarded.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace DetourModKit::manifest
{
    namespace
    {
        // Compiles one CandidateSpec into the scan::Candidate for a Signature ladder. An unset or malformed rung fails
        // closed. Only Signature::compile calls this helper. adopt copies an already-resolved ladder.
        [[nodiscard]] Result<scan::Candidate> compile_rung(const CandidateSpec &spec)
        {
            switch (spec.mode)
            {
            case scan::Mode::Direct:
            {
                const Result<scan::Pattern> pattern = scan::Pattern::compile(spec.pattern);
                if (!pattern)
                {
                    return std::unexpected(pattern.error());
                }
                return scan::Candidate::direct(spec.name, *pattern, spec.walk_back);
            }
            case scan::Mode::RipRelative:
            {
                const Result<scan::Pattern> pattern = scan::Pattern::compile(spec.pattern);
                if (!pattern)
                {
                    return std::unexpected(pattern.error());
                }
                // parse_rung guards the file path. Apply the same fail-closed RipRelative constraint here so the
                // programmatic Signature::compile path cannot bypass it. This explicit check reports InvalidArg through
                // Result instead of an exception from the factory.
                if (spec.displacement_at < 0 ||
                    !scan::is_valid_rip_relative_layout(static_cast<std::size_t>(spec.displacement_at),
                                                        spec.instruction_length) ||
                    !rip_pattern_spans_displacement(*pattern, static_cast<std::size_t>(spec.displacement_at)))
                {
                    return fail(ErrorCode::InvalidArg, "manifest::compile");
                }
                return scan::Candidate::rip_relative(spec.name, *pattern, spec.displacement_at,
                                                     spec.instruction_length);
            }
            case scan::Mode::RttiVtable:
                return scan::Candidate::rtti_vtable(spec.name, spec.mangled);
            case scan::Mode::StringXref:
            {
                const scan::StringRefQuery query{
                    .text = spec.string_text,
                    .encoding = spec.string_encoding,
                    .require_terminator = spec.string_require_terminator,
                    .return_mode = spec.string_return,
                    .broad_match = spec.string_broad_match,
                };
                return scan::Candidate::string_xref(spec.name, query);
            }
            }
            return fail(ErrorCode::BadPattern, "manifest::compile");
        }

        // Reports whether a binding can authorize a write against a resolved typed domain. MidHook needs an executable
        // code site. VmtMethod needs a vtable. Address and PointerChain accept only code or data addresses. Scalar,
        // Unknown, and out-of-range kinds authorize nothing.
        [[nodiscard]] constexpr bool binding_authorizes_mutation(BindingKind binding_kind,
                                                                 anchor::ResultDomain domain) noexcept
        {
            switch (binding_kind)
            {
            case BindingKind::VmtMethod:
                return domain == anchor::ResultDomain::VtableAddress;
            case BindingKind::MidHookRegister:
                return domain == anchor::ResultDomain::CodeSite;
            case BindingKind::Address:
            case BindingKind::PointerChain:
                return domain == anchor::ResultDomain::CodeSite || domain == anchor::ResultDomain::DataAddress;
            }
            return false;
        }

        // Extends anchor_fingerprint with the Binding contract through FNV-1a. It uses the endian-independent and
        // length-prefixed discipline from anchor.cpp. The result stays stable across runs and builds. Keep these
        // helpers local because the anchor.cpp FNV primitives are private.
        inline constexpr std::uint64_t FNV1A64_PRIME = 1099511628211ULL;

        [[nodiscard]] std::uint64_t fnv1a_fold_byte(std::uint64_t hash, std::uint8_t value) noexcept
        {
            return (hash ^ value) * FNV1A64_PRIME;
        }

        template <typename T> [[nodiscard]] std::uint64_t fnv1a_fold_int(std::uint64_t hash, T value) noexcept
        {
            auto bits = static_cast<std::uint64_t>(static_cast<std::make_unsigned_t<T>>(value));
            for (std::size_t i = 0; i < sizeof(T); ++i)
            {
                hash = fnv1a_fold_byte(hash, static_cast<std::uint8_t>(bits & 0xFFu));
                bits >>= 8;
            }
            return hash;
        }

        // A length prefix prevents collisions between "ab" and two folded fields "a" plus "b".
        [[nodiscard]] std::uint64_t fnv1a_fold_string(std::uint64_t hash, std::string_view text) noexcept
        {
            hash = fnv1a_fold_int(hash, static_cast<std::uint64_t>(text.size()));
            for (const char c : text)
            {
                hash = fnv1a_fold_byte(hash, static_cast<std::uint8_t>(c));
            }
            return hash;
        }

        // Fold every field, not only those read by the active BindingKind. Any binding edit then reports drift. An
        // inert field edit also reports drift, which is the fail-closed direction.
        [[nodiscard]] std::uint64_t fold_binding(std::uint64_t hash, const Binding &binding) noexcept
        {
            hash = fnv1a_fold_byte(hash, static_cast<std::uint8_t>(binding.kind));
            hash = fnv1a_fold_int(hash, static_cast<std::uint64_t>(binding.offsets.size()));
            for (const std::ptrdiff_t offset : binding.offsets)
            {
                hash = fnv1a_fold_int(hash, static_cast<std::int64_t>(offset));
            }
            hash = fnv1a_fold_byte(hash, binding.value_width);
            hash = fnv1a_fold_byte(hash, static_cast<std::uint8_t>(binding.read_register));
            hash = fnv1a_fold_byte(hash, binding.xmm_index);
            return fnv1a_fold_int(hash, static_cast<std::uint64_t>(binding.vmt_index));
        }
    } // namespace

    Signature::Signature(SignatureRecord record, std::vector<scan::Candidate> ladder) noexcept
        : m_record(std::move(record)), m_ladder(std::move(ladder))
    {
    }

    anchor::Anchor Signature::make_anchor() const noexcept
    {
        // Rebuild a borrowed anchor view over this object's owned storage. View and POD assignments require no
        // allocation. The returned string_views alias m_record strings. Its site span aliases m_ladder. Those aliases
        // remain valid for the resolve or fingerprint call that receives this view.
        anchor::Anchor anchor{};
        anchor.label = m_record.label;
        anchor.kind = m_record.kind;
        anchor.mangled = m_record.mangled;
        anchor.site = m_ladder;
        anchor.operand_kind = m_record.operand_kind;
        anchor.operand_index = m_record.operand_index;
        anchor.byte_width = m_record.byte_width;
        anchor.pages = m_record.pages;
        anchor.xref_text = m_record.xref_text;
        anchor.xref_encoding = m_record.xref_encoding;
        anchor.xref_return = m_record.xref_return;
        anchor.xref_require_terminator = m_record.xref_require_terminator;
        anchor.xref_broad_match = m_record.xref_broad_match;
        // ExportName evidence consists of the export symbol and its module. resolve() also uses the shared module field
        // as its scope. anchor_fingerprint folds export_module only for ExportName evidence. current_fingerprint folds
        // record.module for every kind.
        anchor.export_module = m_record.module;
        anchor.export_name = m_record.export_name;
        anchor.manual_value = m_record.manual_value;
        // Add the post-resolve validator to the borrowed view. A compiled signature can then assert the same domain
        // invariant as an in-code Anchor. Without these fields, the manifest path cannot reach a validator and silently
        // trusts the raw backend address.
        anchor.validator = m_record.validator;
        anchor.validator_context = m_record.validator_context;
        anchor.validate_manual = m_record.validate_manual;
        anchor.require_validator = m_record.require_validator;
        return anchor;
    }

    Result<Signature> Signature::compile(SignatureRecord record)
    {
        // Composite and unset kinds have no flat record form. A trusted zero from Unset is the fail-open case that this
        // check rejects. Quorum and CallArgHome remain in-code anchors under evaluate_gate().
        if (!record_policy_domains_are_valid(record))
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }
        if (!image_identity_is_valid(record.expected_image_identity) ||
            !winning_bytes_are_valid(record.expected_winning_bytes))
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }

        // A label that cannot round-trip as a `[sig.<label>]` section (a structural INI character, or the reserved
        // `.rung.<digits>` grammar) fails closed before Signature construction. The checked encoder cannot faithfully
        // persist such a label.
        if (!label_is_serializable(record.label))
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }

        if (value_is_unserializable(record.module) || value_is_unserializable(record.mangled) ||
            value_is_unserializable(record.xref_text) || value_is_unserializable(record.export_name))
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }
        for (const CandidateSpec &rung : record.ladder)
        {
            if (value_is_unserializable(rung.name) || value_is_unserializable(rung.pattern) ||
                value_is_unserializable(rung.mangled) || value_is_unserializable(rung.string_text))
            {
                return fail(ErrorCode::InvalidArg, "manifest::compile");
            }
        }

        // Each resolvable kind fails closed on empty mandatory evidence, so a hand-built record cannot compile into
        // a Signature that overlays a trusted zero. Manual has no "empty" evidence (any int64 is a valid pin).
        if (record.kind == anchor::AnchorKind::VtableIdentity && record.mangled.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }
        if (record.kind == anchor::AnchorKind::StringXref && record.xref_text.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }
        // An ExportName without an export symbol has no resolution evidence. An empty module name uses the fallback
        // scope, such as a host executable export. Only export_name is mandatory.
        if (record.kind == anchor::AnchorKind::ExportName && record.export_name.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }

        // Reject a binding that the consumer primitive cannot interpret safely.
        if (!binding_structure_is_valid(record.binding))
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }

        std::vector<scan::Candidate> ladder;
        const bool uses_ladder =
            record.kind == anchor::AnchorKind::RipGlobal || record.kind == anchor::AnchorKind::CodeOperand;
        if (uses_ladder)
        {
            if (record.ladder.empty())
            {
                return fail(ErrorCode::EmptyCandidates, "manifest::compile");
            }
            ladder.reserve(record.ladder.size());
            for (const CandidateSpec &spec : record.ladder)
            {
                Result<scan::Candidate> candidate = compile_rung(spec);
                if (!candidate)
                {
                    return std::unexpected(candidate.error());
                }
                ladder.push_back(std::move(*candidate));
            }
        }
        return Signature(std::move(record), std::move(ladder));
    }

    Result<Signature> Signature::adopt(const anchor::Anchor &source)
    {
        SignatureRecord record;
        record.label = std::string(source.label);
        record.kind = source.kind;
        // ExportName stores its module in export_module. Every other kind leaves this field empty. record.module
        // represents this shared field without a kind branch. An empty export_module remains empty.
        record.module = std::string(source.export_module);
        record.export_name = std::string(source.export_name);
        record.mangled = std::string(source.mangled);
        record.operand_kind = source.operand_kind;
        record.operand_index = source.operand_index;
        record.byte_width = source.byte_width;
        record.pages = source.pages;
        record.xref_text = std::string(source.xref_text);
        record.xref_encoding = source.xref_encoding;
        record.xref_return = source.xref_return;
        record.xref_require_terminator = source.xref_require_terminator;
        record.xref_broad_match = source.xref_broad_match;
        record.manual_value = source.manual_value;
        // Preserve the source anchor's post-resolve validator across adoption. Its loss silently downgrades a validated
        // in-code anchor to an unchecked Signature. This causes a fail-open regression.
        record.validator = source.validator;
        record.validator_context = source.validator_context;
        record.validate_manual = source.validate_manual;
        record.require_validator = source.require_validator;

        // Reject composite, unset, and out-of-range kinds through the same policy and checked serialization validation.
        // An adopted Signature never carries a value that the emitter normalizes.
        if (!record_policy_domains_are_valid(record))
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if (!label_is_serializable(record.label) || value_is_unserializable(record.module) ||
            value_is_unserializable(record.mangled) || value_is_unserializable(record.xref_text) ||
            value_is_unserializable(record.export_name))
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if ((record.kind == anchor::AnchorKind::RipGlobal || record.kind == anchor::AnchorKind::CodeOperand) &&
            source.site.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if (record.kind == anchor::AnchorKind::VtableIdentity && record.mangled.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if (record.kind == anchor::AnchorKind::StringXref && record.xref_text.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if (record.kind == anchor::AnchorKind::ExportName && record.export_name.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }

        // An adopted Signature has no captured baseline. Its record.ladder source text stays empty because a compiled
        // Pattern cannot recover source AOB text. The anchor view uses the copied candidates.
        std::vector<scan::Candidate> ladder(source.site.begin(), source.site.end());
        return Signature(std::move(record), std::move(ladder));
    }

    anchor::ResolvedAnchor Signature::resolve(Region fallback_scope) const
    {
        const Region effective = m_record.module.empty() ? fallback_scope : Region::module_named(m_record.module);
        return anchor::resolve(make_anchor(), effective);
    }

    anchor::ResolvedAnchor Signature::resolve_for_gate(Region fallback_scope, Region &winning_span) const
    {
        const Region effective = m_record.module.empty() ? fallback_scope : Region::module_named(m_record.module);
        return anchor::internal::resolve_with_winning_span(make_anchor(), effective, winning_span);
    }

    Region Signature::scope() const noexcept
    {
        return m_record.module.empty() ? Region::host() : Region::module_named(m_record.module);
    }

    std::uint64_t Signature::current_fingerprint() const noexcept
    {
        // anchor_fingerprint covers the locate evidence. Extend it with Binding, which defines the read-it-there
        // contract. This also lets the drift gate detect a binding-only repair. Fold the record label and module last.
        // This makes each baseline label-specific and scope-sensitive. A new module target or label copy registers as
        // drift.
        std::uint64_t hash = fold_binding(anchor::anchor_fingerprint(make_anchor()), m_record.binding);
        hash = fnv1a_fold_string(hash, m_record.label);
        return fnv1a_fold_string(hash, m_record.module);
    }

    FingerprintState Signature::fingerprint_state() const noexcept
    {
        if (m_record.expected_fingerprint == 0)
        {
            return FingerprintState::Unset;
        }
        return current_fingerprint() == m_record.expected_fingerprint ? FingerprintState::Match
                                                                      : FingerprintState::Drifted;
    }

    void Signature::recapture_fingerprint() noexcept
    {
        m_record.expected_fingerprint = current_fingerprint();
    }

    Result<void> Signature::recapture(Region fallback_scope)
    {
        // Resolve through the same path resolve_and_gate will, so the baselines describe the scope the gate compares
        // them in. A signature that names its own module ignores the fallback here exactly as it does there.
        const anchor::ResolvedAnchor resolved = resolve(fallback_scope);
        if (resolved.status != anchor::AnchorStatus::Resolved)
        {
            return fail(ErrorCode::NoMatch, "manifest::recapture");
        }
        // A Scalar has no module. A rung without a literal span has no witness span. The other baselines create an
        // unusable captured record that can never satisfy the gate.
        if (!resolved.witness.image.present() || !resolved.witness.evidence.present())
        {
            return fail(ErrorCode::UnexpectedShape, "manifest::recapture");
        }

        // Compute every baseline before any store. A partial update can pair one game version's content with another
        // version's identity.
        const std::uint64_t fingerprint = current_fingerprint();
        m_record.expected_fingerprint = fingerprint;
        m_record.expected_image_identity = resolved.witness.image;
        m_record.expected_winning_bytes = resolved.witness.evidence;
        return {};
    }

    std::string_view Signature::label() const noexcept
    {
        return m_record.label;
    }

    anchor::AnchorKind Signature::kind() const noexcept
    {
        return m_record.kind;
    }

    const Binding &Signature::binding() const noexcept
    {
        return m_record.binding;
    }

    const SignatureRecord &Signature::record() const noexcept
    {
        return m_record;
    }

    namespace detail
    {
        class GateAccess
        {
        public:
            [[nodiscard]] static anchor::ResolvedAnchor resolve(const Signature &signature, Region scope,
                                                                Region &winning_span)
            {
                return signature.resolve_for_gate(scope, winning_span);
            }
        };
    } // namespace detail

    bool revision_compatible(const ManifestHeader &header, std::uint32_t build_revision) noexcept
    {
        // build_revision 0 opts out of the gate. Otherwise, the file must target this build's exact contract epoch.
        // Any other value identifies a different in-code contract and requires safe disregard.
        return build_revision == 0 || header.revision == build_revision;
    }

    namespace
    {
        [[nodiscard]] anchor::ResultDomain record_declared_domain(const SignatureRecord &record) noexcept
        {
            anchor::Anchor probe{};
            probe.kind = record.kind;
            probe.operand_kind = record.operand_kind;
            probe.byte_width = record.byte_width;
            probe.xref_encoding = record.xref_encoding;
            probe.xref_return = record.xref_return;
            probe.pages = record.pages;
            return anchor::declared_domain(probe);
        }

    } // namespace

    Result<std::vector<Signature>> overlay(std::span<const anchor::Anchor> defaults,
                                           std::span<const SignatureRecord> overrides)
    {
        std::vector<Signature> merged;
        merged.reserve(defaults.size());

        for (const anchor::Anchor &def : defaults)
        {
            // The file overrides only named entries. A default without a match keeps its in-code form.
            const SignatureRecord *override_record = nullptr;
            for (const SignatureRecord &candidate : overrides)
            {
                if (candidate.label == def.label)
                {
                    override_record = &candidate;
                    break;
                }
            }

            if (override_record != nullptr && !is_serializable_anchor_kind(def.kind))
            {
                // A flat file rung cannot preserve Quorum corroboration.
                log().warning("manifest overlay: override '{}' targets a non-serializable in-code default; ignored",
                              def.label);
                override_record = nullptr;
            }

            if (override_record != nullptr &&
                ((override_record->kind == anchor::AnchorKind::Manual) != (def.kind == anchor::AnchorKind::Manual)))
            {
                // Manual anchors bypass backend-only validator requirements.
                log().warning("manifest overlay: override '{}' changes the Manual validation posture; keeping in-code "
                              "default",
                              def.label);
                override_record = nullptr;
            }

            if (override_record != nullptr && record_declared_domain(*override_record) != anchor::declared_domain(def))
            {
                log().warning("manifest overlay: override '{}' changes the declared result domain; keeping in-code "
                              "default",
                              def.label);
                override_record = nullptr;
            }

            if (override_record != nullptr)
            {
                // Validator policy cannot round-trip an INI.
                SignatureRecord effective = *override_record;
                effective.validator = def.validator;
                effective.validator_context = def.validator_context;
                effective.validate_manual = def.validate_manual;
                effective.require_validator = def.require_validator;

                Result<Signature> compiled = Signature::compile(std::move(effective));
                if (compiled)
                {
                    merged.push_back(std::move(*compiled));
                    continue;
                }
                // A malformed override falls back to the in-code default. An override must never produce a worse
                // result than file absence.
                log().warning("manifest overlay: override '{}' failed to compile ({}); keeping in-code default",
                              def.label, compiled.error().message());
            }

            Result<Signature> adopted = Signature::adopt(def);
            if (adopted)
            {
                merged.push_back(std::move(*adopted));
            }
            else
            {
                // A Quorum or CallArgHome default has no flat Signature representation. Skip it rather than mis-adopt
                // it.
                log().warning("manifest overlay: default '{}' is not a serializable anchor kind; gate it in code",
                              def.label);
            }
        }
        return merged;
    }

    const GatedSignature *GateResult::find(std::string_view label) const noexcept
    {
        for (const GatedSignature &entry : trusted)
        {
            if (entry.label == label)
            {
                return &entry;
            }
        }
        return nullptr;
    }

    namespace
    {
        // revision_checked is deliberately separate from revision_ok: "compatible" and "never checked" are the same
        // value there and must not be.
        [[nodiscard]] GateResult gate_impl(std::span<const Signature> signatures, const GatePolicy &policy,
                                           Region scope, bool revision_checked, bool revision_ok)
        {
            GateResult result;

            // Resolve every signature before summary. assess_quality needs the whole report. A signature's fingerprint
            // verdict is independent of the resolve outcome.
            std::vector<anchor::ResolvedAnchor> report;
            report.reserve(signatures.size());
            std::vector<Region> winning_spans;
            winning_spans.reserve(signatures.size());
            for (const Signature &signature : signatures)
            {
                Region winning_span{};
                report.push_back(detail::GateAccess::resolve(signature, scope, winning_span));
                winning_spans.push_back(winning_span);
            }
            result.quality = anchor::assess_quality(report);

            // Keep fingerprint states parallel to result.trusted. The whole-manifest floor demotion then reports the
            // true drift state directly.
            std::vector<FingerprintState> trusted_fingerprints;
            trusted_fingerprints.reserve(signatures.size());

            for (std::size_t index = 0; index < signatures.size(); ++index)
            {
                const Signature &signature = signatures[index];
                const anchor::ResolvedAnchor &resolved = report[index];
                const FingerprintState fingerprint = signature.fingerprint_state();

                // A non-unique or missed locate is never trusted.
                if (resolved.status != anchor::AnchorStatus::Resolved)
                {
                    result.rejected.push_back(RejectedSignature{.label = signature.label(),
                                                                .status = resolved.status,
                                                                .fingerprint = fingerprint,
                                                                .reason = GateReason::Unresolved});
                    continue;
                }
                if (policy.reject_on_fingerprint_drift && fingerprint == FingerprintState::Drifted)
                {
                    result.rejected.push_back(RejectedSignature{.label = signature.label(),
                                                                .status = anchor::AnchorStatus::Resolved,
                                                                .fingerprint = FingerprintState::Drifted,
                                                                .reason = GateReason::FingerprintDrifted});
                    continue;
                }
                if (policy.reject_unset_fingerprint && fingerprint == FingerprintState::Unset)
                {
                    result.rejected.push_back(RejectedSignature{.label = signature.label(),
                                                                .status = anchor::AnchorStatus::Resolved,
                                                                .fingerprint = FingerprintState::Unset,
                                                                .reason = GateReason::FingerprintUnset});
                    continue;
                }
                // Evaluate binding_authorizes_mutation once here. Every later mutation gate uses this live, writable
                // target fact.
                const bool mutation_capable = resolved.kind != anchor::AnchorKind::Manual &&
                                              binding_authorizes_mutation(signature.binding().kind, resolved.domain);
                // A mutation-strict entry must bind a live address through a compatible consumer primitive. A Manual
                // pin or binding-domain mismatch equals !mutation_capable and causes rejection.
                if (policy.require_mutation_safe_binding && !mutation_capable)
                {
                    result.rejected.push_back(RejectedSignature{.label = signature.label(),
                                                                .status = anchor::AnchorStatus::Resolved,
                                                                .fingerprint = fingerprint,
                                                                .reason = GateReason::BindingCannotMutate});
                    continue;
                }
                // An unchecked revision and an incompatible revision both refuse authorization. The first skips
                // comparison. The second comparison finds disagreement.
                if (mutation_capable && (!revision_ok || (policy.require_contract_revision && !revision_checked)))
                {
                    result.rejected.push_back(RejectedSignature{.label = signature.label(),
                                                                .status = anchor::AnchorStatus::Resolved,
                                                                .fingerprint = fingerprint,
                                                                .reason = GateReason::ContractRevision});
                    continue;
                }
                if (mutation_capable && (policy.require_live_image_identity || policy.require_captured_image_identity))
                {
                    const scan::ImageIdentity &expected = signature.record().expected_image_identity;
                    const scan::ImageIdentity &live = resolved.witness.image;
                    const bool missing_baseline = policy.require_captured_image_identity && !expected.present();
                    const bool mismatched = policy.require_live_image_identity && expected.present() &&
                                            (!live.present() || expected != live);
                    if (missing_baseline || mismatched)
                    {
                        result.rejected.push_back(RejectedSignature{.label = signature.label(),
                                                                    .status = anchor::AnchorStatus::Resolved,
                                                                    .fingerprint = fingerprint,
                                                                    .reason = GateReason::ImageIdentity});
                        continue;
                    }
                }
                if (mutation_capable && policy.require_winning_evidence_baseline)
                {
                    // Both sides need complete captures. Empty captures never count as agreement. Re-read the selected
                    // match span directly before trust publication. The direct read detects any content change after
                    // the sweep.
                    const scan::WinningEvidence &expected = signature.record().expected_winning_bytes;
                    const scan::WinningEvidence &live = resolved.witness.evidence;
                    std::array<std::byte, scan::MAX_MUTATION_WITNESS_BYTES> current{};
                    const Region winning_span = winning_spans[index];
                    const bool span_matches =
                        expected.present() && live.present() && expected == live &&
                        winning_span.size == expected.length &&
                        DetourModKit::detail::guarded_read_bytes(winning_span.base.raw(), current.data(),
                                                                 expected.length) &&
                        std::equal(current.begin(), current.begin() + expected.length, expected.bytes.begin());
                    if (!span_matches)
                    {
                        result.rejected.push_back(RejectedSignature{.label = signature.label(),
                                                                    .status = anchor::AnchorStatus::Resolved,
                                                                    .fingerprint = fingerprint,
                                                                    .reason = GateReason::WinningEvidence});
                        continue;
                    }
                }

                result.trusted.push_back(GatedSignature{.label = signature.label(),
                                                        .kind = signature.kind(),
                                                        .address = Address{static_cast<std::uintptr_t>(resolved.value)},
                                                        .binding = &signature.binding()});
                trusted_fingerprints.push_back(fingerprint);
            }

            // If too small a fraction is trustworthy, demote the whole manifest. NaN and negative floors disable the
            // floor, while values above one clamp to one.
            double floor = policy.min_resolved_fraction;
            if (!(floor >= 0.0))
            {
                floor = 0.0;
            }
            if (floor > 1.0)
            {
                floor = 1.0;
            }
            if (!signatures.empty() && floor > 0.0)
            {
                const double fraction =
                    static_cast<double>(result.trusted.size()) / static_cast<double>(signatures.size());
                if (fraction < floor)
                {
                    for (std::size_t index = 0; index < result.trusted.size(); ++index)
                    {
                        result.rejected.push_back(RejectedSignature{.label = result.trusted[index].label,
                                                                    .status = anchor::AnchorStatus::Resolved,
                                                                    .fingerprint = trusted_fingerprints[index],
                                                                    .reason = GateReason::HealthFloor});
                    }
                    result.trusted.clear();
                }
            }

            return result;
        }
    } // namespace

    GateResult resolve_and_gate(std::span<const Signature> signatures, const GatePolicy &policy, Region scope)
    {
        // This overload receives no header, so it performs no contract revision comparison. Read-only gates retain
        // their behavior. A policy that requires a checked revision refuses mutation authorization.
        return gate_impl(signatures, policy, scope, /*revision_checked=*/false, /*revision_ok=*/true);
    }

    GateResult resolve_and_gate(std::span<const Signature> signatures, const ManifestHeader &header,
                                std::uint32_t build_revision, const GatePolicy &policy, Region scope)
    {
        return gate_impl(signatures, policy, scope, /*revision_checked=*/build_revision != 0,
                         revision_compatible(header, build_revision));
    }

    std::string_view fingerprint_state_to_string(FingerprintState state) noexcept
    {
        switch (state)
        {
        case FingerprintState::Unset:
            return "unset";
        case FingerprintState::Match:
            return "match";
        case FingerprintState::Drifted:
            return "drifted";
        }
        return "unset";
    }

    std::string_view gate_reason_to_string(GateReason reason) noexcept
    {
        switch (reason)
        {
        case GateReason::None:
            return "none";
        case GateReason::Unresolved:
            return "unresolved";
        case GateReason::FingerprintDrifted:
            return "fingerprint-drifted";
        case GateReason::FingerprintUnset:
            return "fingerprint-unset";
        case GateReason::BindingCannotMutate:
            return "binding-cannot-mutate";
        case GateReason::ContractRevision:
            return "contract-revision";
        case GateReason::ImageIdentity:
            return "image-identity";
        case GateReason::WinningEvidence:
            return "winning-evidence";
        case GateReason::HealthFloor:
            return "health-floor";
        }
        return "none";
    }
} // namespace DetourModKit::manifest
