#ifndef DETOURMODKIT_ANCHOR_HPP
#define DETOURMODKIT_ANCHOR_HPP

/**
 * @file anchor.hpp
 * @brief Declarative anchor registry: one table that resolves a mod's patch-fragile constants and reports drift.
 * @warning `[B-100]` Under the loader lock, call only the Callback-safe trust and quality queries. Resolution can
 *          allocate, query loader state, scan memory, or create threads.
 */

#include "DetourModKit/error.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace DetourModKit
{
    namespace anchor
    {
        /** @brief Which backend resolves an anchor. `docs/guides/scanning/anchors.md` ranks the kinds by resilience. */
        enum class AnchorKind : std::uint8_t
        {
            /// A class vtable address keyed on its mangled name (@ref rtti::vtable_for_type).
            VtableIdentity,
            /// An absolute address from a Direct or RIP-relative candidate cascade (@ref scan::resolve).
            RipGlobal,
            /// An in-code immediate or `[reg + disp]` displacement (@ref scan::read_code_constant).
            CodeOperand,
            /// A reference to an immutable string literal (@ref scan::find_string_xref).
            StringXref,
            /// A pinned literal with no backend. It cannot self-heal, so @ref AnchorQuality counts it as at risk.
            Manual,
            /// A reserved prologue-dataflow kind with no resolver, which reports @ref AnchorStatus::Unsupported.
            CallArgHome,
            /// A value accepted only when at least N of M independent sub-anchors resolve and agree.
            Quorum,
            /// A named export read from its module's PE Export Address Table (@ref scan::resolve_export).
            ExportName,
            /// The default for an omitted kind, which reports @ref AnchorStatus::Failed instead of a trusted address 0.
            Unset
        };

        /// The number of @ref AnchorKind enumerators, which sizes the per-kind deny-list in @ref ScanProfile.
        inline constexpr std::size_t ANCHOR_KIND_COUNT = 9;
        static_assert(
            static_cast<std::size_t>(AnchorKind::Unset) + 1 == ANCHOR_KIND_COUNT,
            "ANCHOR_KIND_COUNT must track the AnchorKind enumerator count."
        );

        /** @brief How a @ref AnchorKind::Quorum decides that two resolved member values agree. */
        enum class QuorumMatch : std::uint8_t
        {
            /// Two member values agree only when identical.
            ExactValue,
            /// Two member values agree when their gap is at most @ref Anchor::quorum_tolerance.
            WithinTolerance
        };

        /** @brief The resolution outcome of one anchor. */
        enum class AnchorStatus : std::uint8_t
        {
            /// The initial state of an untouched slot, which a resolve never returns.
            Unresolved,
            /// The backend resolved a value, and every applicable validator and corroboration check passed.
            Resolved,
            /// A backend miss, validator rejection, denied backend, or failed quorum, with no invented value.
            Failed,
            /// The kind has no resolver (@ref AnchorKind::CallArgHome).
            Unsupported,
            /// A quorum's members were not all pairwise-independent evidence.
            QuorumNotIndependent,
            /** @brief Values that disagree each reached the quorum threshold. Member order never picks a winner. */
            QuorumAmbiguous
        };

        /** @brief A post-resolve predicate. A false return fails the anchor (@ref AnchorStatus::Failed, value 0). */
        using AnchorValidator = bool (*)(std::int64_t value, const void *context) noexcept;

        /** @brief A registry entry. A kind-labeled field applies only to that kind. Views must outlive the resolve. */
        struct Anchor
        {
            /// An identifier echoed into the @ref ResolvedAnchor.
            std::string_view label;
            /// Which backend resolves this anchor.
            AnchorKind kind = AnchorKind::Unset;

            /// VtableIdentity: the MSVC mangled type name, for example ".?AVGameAudioEffect@engine@@".
            std::string_view mangled;

            /// RipGlobal / CodeOperand: the candidate ladder that resolves to the address or the instruction site.
            std::span<const scan::Candidate> site;
            /// CodeOperand: whether to read an immediate or a memory-operand displacement.
            scan::OperandKind operand_kind = scan::OperandKind::Immediate;
            /// CodeOperand: the index into the instruction's visible operands.
            std::uint8_t operand_index = 0;
            /// CodeOperand: 0 keeps the decoded value, and 1 through 8 narrows non-RIP low bytes and sign-extends.
            std::uint8_t byte_width = 0;

            /// StringXref: the exact literal content to anchor on, without quotes.
            std::string_view xref_text;
            /// StringXref: the byte encoding of the literal in the image (Utf16le for wchar_t literals).
            scan::StringEncoding xref_encoding = scan::StringEncoding::Utf8;
            /// StringXref: whether to return the referencing instruction, its enclosing function, or the pointer slot.
            scan::XrefReturn xref_return = scan::XrefReturn::ReferencingInstruction;
            /// StringXref: if true, match a trailing NUL so that a prefix of a longer literal does not match.
            bool xref_require_terminator = true;
            /// StringXref: if true, add the broad sweep for rarer reference shapes to the lea/mov shape scan.
            bool xref_broad_match = false;

            /// Manual: the pinned literal value, taken as-is unless @ref validate_manual is set.
            std::int64_t manual_value = 0;

            /** @brief An optional post-resolve predicate. For a Quorum, it runs once on the corroborated value. */
            AnchorValidator validator = nullptr;
            /// An opaque pointer forwarded verbatim to @ref validator.
            const void *validator_context = nullptr;
            /// If true, @ref validator also checks a Manual literal.
            bool validate_manual = false;
            /// If true, a backend-resolved anchor with no @ref validator reports Failed. Manual and Quorum are exempt.
            bool require_validator = false;

            /**
             * @brief Quorum: the M sub-anchors that vote. Each member must outlive the resolve call. Fewer than two
             *        members, a null member, or a nested Quorum fails the quorum (@ref AnchorStatus::Failed).
             */
            std::span<const Anchor *const> quorum_members;
            /**
             * @brief Quorum: N, the minimum number of resolved members that must agree. The default 0 means all M
             *        members, and an explicit N below 2 or above M fails the quorum.
             * @details A resolved member value qualifies as a center when at least N resolved votes agree with it.
             *          Qualified centers that disagree give @ref AnchorStatus::QuorumAmbiguous. Otherwise the smallest
             *          qualified center wins. @ref QuorumMatch::WithinTolerance measures agreement against that
             *          center, so the accepted members can span up to two tolerances.
             */
            std::size_t quorum_threshold = 0;
            /// Quorum: the rule that decides whether two resolved member values agree.
            QuorumMatch quorum_match = QuorumMatch::ExactValue;
            /// Quorum: the tolerance for @ref QuorumMatch::WithinTolerance, where a negative value fails closed.
            std::int64_t quorum_tolerance = 0;

            /**
             * @brief RipGlobal: the page class the byte-tier ladder scans. The @ref scan::Pages::Readable default also
             *        matches a global in `.rdata` / `.data`. If every rung anchors on an in-image instruction, set
             *        @ref scan::Pages::Executable. A data-page byte twin then cannot make a unique resolve ambiguous.
             */
            scan::Pages pages = scan::Pages::Readable;

            /// ExportName: the module name for @ref Region::module_named, or empty for the resolve scope.
            std::string_view export_module;
            /// ExportName: the exact, case-sensitive export symbol name without decoration, for example "Sleep".
            std::string_view export_name;
        };

        /** @brief What a resolved value is. See @ref manifest::GatePolicy::require_mutation_safe_binding. */
        enum class ResultDomain : std::uint8_t
        {
            /// An entry that did not resolve, or a Quorum with conflicting member domains. It authorizes no mutation.
            Unknown,
            /// An executable instruction site (an inline-hook or mid-hook target).
            CodeSite,
            /// A non-executable data address (a global variable or a resolved pointer slot).
            DataAddress,
            /// A class vtable base, keyed on its type identity (a VMT-hook target).
            VtableAddress,
            /// A CodeOperand value or pinned Manual literal. It authorizes no write, even when it holds an address.
            Scalar
        };

        /** @brief The normalized evidence backend that produced a resolved value. */
        enum class PhysicalSource : std::uint8_t
        {
            /// No resolved value (failed, unsupported, or unresolved).
            None,
            /// A Direct / RIP-relative byte-signature cascade (an @ref AnchorKind::RipGlobal).
            ByteSignature,
            /// A string-literal cross-reference (an @ref AnchorKind::StringXref).
            StringLiteral,
            /// A reverse-RTTI vtable identity (an @ref AnchorKind::VtableIdentity).
            TypeIdentity,
            /// A PE export-table walk (an @ref AnchorKind::ExportName).
            ExportTable,
            /// A decoded in-code immediate or displacement (an @ref AnchorKind::CodeOperand).
            CodeOperand,
            /// A pinned Manual literal with no backend (an @ref AnchorKind::Manual).
            ManualPin,
            /// A value corroborated by N-of-M voting (an @ref AnchorKind::Quorum), with no single physical source.
            Corroborated
        };

        /** @brief Whether a resolved value came from a complete, authoritative view. A partial sweep fails instead. */
        enum class WitnessCompleteness : std::uint8_t
        {
            /// No assessable completeness, because the entry did not resolve.
            Unknown,
            /// Resolved over a complete, authoritative view of the scope.
            Complete
        };

        /** @brief The evidence behind a resolved value, populated only on @ref AnchorStatus::Resolved. */
        struct ResolvedWitness
        {
            /**
             * @brief Identity of the module that owns the resolved address. Absent for a Scalar or synthetic address.
             *        An unreadable identity, or owner or mapping drift at validation, vote, or commit, gives
             *        @ref AnchorStatus::Failed with no witness.
             */
            scan::ImageIdentity image{};
            /// The normalized backend that produced the value.
            PhysicalSource source = PhysicalSource::None;
            /// For a @ref PhysicalSource::CodeOperand, the decoded operand field, and otherwise unused.
            scan::OperandKind operand_kind = scan::OperandKind::Immediate;
            /// Whether the resolve saw a complete, authoritative view.
            WitnessCompleteness completeness = WitnessCompleteness::Unknown;
            /// The bytes that the byte-pattern rung matched, present only when a RipGlobal resolves on a byte rung.
            scan::WinningEvidence evidence{};
        };

        /** @brief One entry in the drift report: the anchor's identity, outcome, and value. */
        struct ResolvedAnchor
        {
            /// A copy of the @ref Anchor::label view, valid only while the characters it borrows live.
            std::string_view label;
            /// Copied from @ref Anchor::kind.
            AnchorKind kind = AnchorKind::Unset;
            /// The resolution outcome.
            AnchorStatus status = AnchorStatus::Unresolved;
            /** @brief An address cast to int64, or a constant. Meaningful only when @ref status is Resolved. */
            std::int64_t value = 0;
            /**
             * @brief What @ref value is. A resolved entry gets @ref declared_domain, but a CodeSite at a non-executable
             *        address becomes @ref ResultDomain::DataAddress. Any other entry stays Unknown.
             */
            ResultDomain domain = ResultDomain::Unknown;
            /// The evidence behind @ref value (see @ref ResolvedWitness).
            ResolvedWitness witness{};
        };

        /** @brief A robustness summary of a drift report, the input to @ref evaluate_gate. */
        struct AnchorQuality
        {
            /// Total entries in the report.
            std::size_t total = 0;
            /// Entries that resolved.
            std::size_t resolved = 0;
            /// Entries that failed closed (Failed or QuorumAmbiguous).
            std::size_t failed = 0;
            /// Entries whose kind has no resolver (CallArgHome).
            std::size_t unsupported = 0;
            /// Quorum entries rejected because their sub-anchors were not independent.
            std::size_t not_independent = 0;
            /// Pinned Manual literals that cannot self-heal (counted regardless of status).
            std::size_t manual_at_risk = 0;
            /// Corroborated quorums that resolved.
            std::size_t corroborated = 0;
        };

        /** @brief `[B-51]` The startup decision for a drift report: enable, enable with caution, or safe-disable. */
        enum class GateVerdict : std::uint8_t
        {
            /// Healthy enough to enable: within the thresholds, with no at-risk signal.
            Pass,
            /// Within the thresholds, but a pinned Manual literal or a report with nothing assessable adds risk.
            Degraded,
            /** @brief Too few anchors resolved, or too many failed. Safe-disable the feature. */
            Fail
        };

        /** @brief The thresholds for @ref evaluate_gate. The defaults are the strictest and fail closed. */
        struct GatePolicy
        {
            /** @brief Minimum resolved fraction of all non-Unsupported entries, clamped to [0, 1]. NaN means 1.0. */
            double min_resolved_ratio = 1.0;
            /** @brief Cap on failed plus not_independent entries. A count above it fails the gate at any ratio. */
            std::size_t max_failed = 0;
            /// If true, a nonzero @ref AnchorQuality::manual_at_risk count turns Pass into @ref GateVerdict::Degraded.
            bool manual_at_risk_degrades = true;
        };

        /**
         * @brief Turns a drift-report summary into a startup verdict.
         * @details A report with nothing to assess is @ref GateVerdict::Degraded. Status counts above
         *          @ref AnchorQuality::total yield @ref GateVerdict::Fail.
         * @note Callback-safe: allocation-free and side-effect-free.
         */
        [[nodiscard]] GateVerdict evaluate_gate(const AnchorQuality &quality, const GatePolicy &policy = {}) noexcept;

        /**
         * @brief Returns `evaluate_gate(assess_quality(report), policy)`. @p report can be a per-feature sub-span.
         * @note Callback-safe: one allocation-free tally pass plus the threshold arithmetic.
         */
        [[nodiscard]] GateVerdict
        evaluate_gate(std::span<const ResolvedAnchor> report, const GatePolicy &policy = {}) noexcept;

        /** @brief Maps a @ref GateVerdict to a short static label. */
        [[nodiscard]] std::string_view gate_verdict_to_string(GateVerdict verdict) noexcept;

        /** @brief Per-game scan tuning that applies to every anchor in a profiled resolve. */
        struct ScanProfile
        {
            /// Enables the broad sweep for every StringXref anchor, but never turns broad mode off.
            bool default_broad_string_xref = false;
            /// The candidate order for RipGlobal and CodeOperand ladders.
            scan::CandidateOrder candidate_order = scan::CandidateOrder::AsDeclared;
            /// A per-@ref AnchorKind deny-list. A denied backend fails closed, and no other backend replaces it.
            std::array<bool, ANCHOR_KIND_COUNT> deny_backend{};

            /** @brief Reports whether @p kind is in range and denied by this profile. */
            [[nodiscard]] bool is_denied(AnchorKind kind) const noexcept
            {
                const auto index = static_cast<std::size_t>(kind);
                return index < deny_backend.size() && deny_backend[index];
            }
        };

        /** @brief Returns @p query with @ref ScanProfile::default_broad_string_xref applied. It only widens. */
        [[nodiscard]] scan::StringRefQuery
        apply_profile(const ScanProfile &profile, scan::StringRefQuery query) noexcept;

        /**
         * @brief Resolves one anchor through its backend, fail-closed.
         * @param scope One module image or reserved allocation. A VtableIdentity, RipGlobal, CodeOperand, or StringXref
         *              anchor, quorum members included, fails closed if the range spans several allocations. It also
         *              fails closed if the owner or mapping at commit differs from the one captured before the scan.
         * @note Setup/control-plane only: the backend scan can allocate and walk pages.
         */
        [[nodiscard]] ResolvedAnchor resolve(const Anchor &anchor, Region scope = Region::host());

        /**
         * @brief Serially resolves `min(anchors.size(), out.size())` anchors into @p out and returns that count.
         * @note Setup/control-plane only (see @ref resolve).
         */
        [[nodiscard]] std::size_t
        resolve_all(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out, Region scope = Region::host());

        /**
         * @brief @ref resolve_all on a fork-join worker pool, with results in input order.
         * @param max_workers Upper bound on threads. 0 auto-selects from `hardware_concurrency`, clamped to the count.
         * @details Validators run concurrently. If one is order-dependent or thread-unsafe, use @ref resolve_all. If a
         *          resolve throws, this call writes a Failed entry for that anchor and does not rethrow.
         * @note Setup/control-plane only: spawns and joins a worker pool.
         * @warning Never call it under the loader lock, where the worker join hangs.
         */
        [[nodiscard]] std::size_t resolve_all_parallel(
            std::span<const Anchor> anchors,
            std::span<ResolvedAnchor> out,
            Region scope = Region::host(),
            std::size_t max_workers = 0
        );

        /**
         * @brief Rolls a drift report into an @ref AnchorQuality without a new resolve.
         * @note Callback-safe: one allocation-free tally pass over @p report.
         */
        [[nodiscard]] AnchorQuality assess_quality(std::span<const ResolvedAnchor> report) noexcept;

        /**
         * @brief Hashes an anchor's declared resolution evidence into a 64-bit FNV-1a diff key.
         * @details The key excludes the resolved address, @ref Anchor::label, and candidate names. It is identical on
         *          every load of the same declaration, so a persisted key can serve as a drift baseline. A Quorum
         *          folds in its members independent of order, plus its effective threshold, match rule, and tolerance.
         * @note Callback-safe: reads only the declaration, resolves nothing, and allocates nothing.
         */
        [[nodiscard]] std::uint64_t anchor_fingerprint(const Anchor &anchor) noexcept;

        /**
         * @brief Hashes the @ref anchor_fingerprint evidence with @p scope_identity, the identity of the module that
         *        the anchor resolves against. ASLR does not change the key. For ExportName, @p scope_identity
         *        replaces the declared module name, so inherited and explicit spellings of one module give one key.
         * @note Callback-safe: allocation-free and side-effect-free.
         */
        [[nodiscard]] std::uint64_t
        anchor_trust_fingerprint(const Anchor &anchor, scan::ImageIdentity scope_identity) noexcept;

        /** @brief Maps an @ref AnchorStatus to a short static label. */
        [[nodiscard]] std::string_view anchor_status_to_string(AnchorStatus status) noexcept;

        /**
         * @brief The @ref ResultDomain that @p anchor declares. Allocation-free and side-effect-free.
         * @return VtableIdentity gives VtableAddress, and CodeOperand or Manual gives Scalar. StringXref gives
         *         CodeSite, or DataAddress for a StringPointerSlot return. ExportName gives a provisional CodeSite (see
         *         @ref ResolvedAnchor::domain). RipGlobal gives CodeSite only on executable @ref Anchor::pages, else
         *         DataAddress. CallArgHome, Unset, and an out-of-range enum or @ref Anchor::byte_width value in a field
         *         that the kind reads give Unknown. A Quorum gives the one address domain that its members declare,
         *         Scalar if none does, or Unknown if two members declare different ones.
         */
        [[nodiscard]] ResultDomain declared_domain(const Anchor &anchor) noexcept;

        /** @brief Maps a @ref ResultDomain to a short static label. */
        [[nodiscard]] std::string_view result_domain_to_string(ResultDomain domain) noexcept;

        /** @brief Maps a @ref PhysicalSource to a short static label. */
        [[nodiscard]] std::string_view physical_source_to_string(PhysicalSource source) noexcept;

        /**
         * @brief @ref resolve with the deny-list, candidate order, and broad-string default of @p profile applied.
         * @param profile Quorum members use the same profile, so a denied member fails and casts no vote. An empty
         *                profile gives the @ref resolve result.
         * @note Setup/control-plane only (see @ref resolve).
         */
        [[nodiscard]] ResolvedAnchor
        resolve_with_profile(const Anchor &anchor, const ScanProfile &profile, Region scope = Region::host());

        /**
         * @brief @ref resolve_all with @p profile applied (see @ref resolve_with_profile).
         * @note Setup/control-plane only (see @ref resolve).
         */
        [[nodiscard]] std::size_t resolve_all_with_profile(
            std::span<const Anchor> anchors,
            std::span<ResolvedAnchor> out,
            const ScanProfile &profile,
            Region scope = Region::host()
        );

        /**
         * @brief @ref resolve_all_parallel with @p profile applied (see @ref resolve_with_profile).
         * @note Setup/control-plane only (see @ref resolve_all_parallel).
         * @warning Never call it under the loader lock, where the worker join hangs.
         */
        [[nodiscard]] std::size_t resolve_all_with_profile_parallel(
            std::span<const Anchor> anchors,
            std::span<ResolvedAnchor> out,
            const ScanProfile &profile,
            Region scope = Region::host(),
            std::size_t max_workers = 0
        );
    } // namespace anchor
} // namespace DetourModKit

#endif // DETOURMODKIT_ANCHOR_HPP
