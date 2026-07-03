#ifndef DETOURMODKIT_ANCHOR_HPP
#define DETOURMODKIT_ANCHOR_HPP

/**
 * @file anchor.hpp
 * @brief Declarative anchor registry: one table that resolves a mod's patch-fragile constants and reports drift.
 * @details A mod against a fast-patching game accumulates a wall of patch-fragile constants: a vtable matched by
 *          literal, a global resolved by AOB, a struct stride read out of a dispatch loop, the occasional pinned
 *          offset. The registry collapses that wall into one declarative table. Each constant is declared once with
 *          the kind of anchor it is and the inputs its backend needs; the whole table is resolved at init and reported
 *          uniformly, so "this mod is broken on the new patch" becomes a precise, machine-readable diff instead of a
 *          debugging session.
 *
 *          This module adds no resolution logic of its own: it is the consolidation layer over the self-healing
 *          backends that already resolve from a module range alone. Each @ref AnchorKind maps onto one v4 backend --
 *          VtableIdentity -> @ref rtti::vtable_for_type, RipGlobal -> @ref scan::resolve, CodeOperand ->
 *          @ref scan::read_code_constant, StringXref -> @ref scan::find_string_xref -- plus the composite @ref
 *          AnchorKind::Quorum that corroborates a target by N-of-M voting across independent sub-anchors and the
 *          pinned @ref AnchorKind::Manual last resort. Every backend already fails closed, so a missing constant
 *          surfaces as @ref AnchorStatus::Failed (no value invented) rather than a silent wrong address.
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
        /**
         * @enum AnchorKind
         * @brief Which backend resolves an anchor, and therefore how update-resilient it is.
         * @details When a target can be expressed more than one way, prefer the most update-resilient backend:
         *          StringXref > VtableIdentity > RipGlobal > CodeOperand, with a Quorum voting over several of those
         *          raising confidence further and Manual as the last resort. A string literal and a mangled type name
         *          survive game patches far better than the code bytes and addresses around them.
         */
        enum class AnchorKind : std::uint8_t
        {
            /// A class vtable address, keyed on its mangled name, via @ref rtti::vtable_for_type.
            VtableIdentity,
            /// An absolute address (Direct or RIP-relative candidate cascade), via @ref scan::resolve.
            RipGlobal,
            /// An in-code immediate or `[reg + disp]` displacement, via @ref scan::read_code_constant.
            CodeOperand,
            /**
             * @brief The instruction (or enclosing function) that references an immutable string literal, via
             *        @ref scan::find_string_xref. The most update-resilient kind.
             */
            StringXref,
            /// A pinned literal with no backend; reported as at-risk because it cannot self-heal.
            Manual,
            /**
             * @brief Reserved for a future prologue-dataflow backend (a call argument to its register/stack home).
             *        Declaring it now keeps a registry table forward-compatible; it currently reports
             *        @ref AnchorStatus::Unsupported.
             */
            CallArgHome,
            /**
             * @brief A corroborated value accepted only when at least N of M independent sub-anchors resolve and agree
             *        (N-of-M voting). Corroboration survives a patch that breaks some of the M signals as long as N of
             *        them still agree, which a single backend cannot.
             */
            Quorum
        };

        /// The number of @ref AnchorKind enumerators; sizes the per-kind deny-list in @ref ScanProfile.
        inline constexpr std::size_t ANCHOR_KIND_COUNT = 7;
        static_assert(static_cast<std::size_t>(AnchorKind::Quorum) + 1 == ANCHOR_KIND_COUNT,
                      "ANCHOR_KIND_COUNT must track the AnchorKind enumerator count.");

        /**
         * @enum QuorumMatch
         * @brief The agreement policy a @ref AnchorKind::Quorum applies when deciding whether two resolved member
         *        values count as one vote for the same target.
         */
        enum class QuorumMatch : std::uint8_t
        {
            /// Two member values agree only when identical (the default, strongest policy).
            ExactValue,
            /**
             * @brief Two member values agree when their gap is at most @ref Anchor::quorum_tolerance; a negative
             *        tolerance fails closed (never accepts). Because a near-match is looser than an exact one, it is
             *        confined to content-independent members (the fail-closed pairwise-independence gate all quorums
             *        run), so a cluster of near values can never be an artifact of two members decoding adjacent bytes
             *        of one site.
             */
            WithinTolerance
        };

        /**
         * @enum AnchorStatus
         * @brief The outcome of resolving one anchor.
         */
        enum class AnchorStatus : std::uint8_t
        {
            /// The initial state written into an untouched slot; a resolved report never leaves this in place.
            Unresolved,
            /// The backend resolved a value and every applicable validator/corroboration check passed.
            Resolved,
            /**
             * @brief The backend missed, a validator rejected the value, a denied backend was requested, or a quorum
             *        disagreed; no value is invented (fail closed).
             */
            Failed,
            /// The kind has no resolver yet (@ref AnchorKind::CallArgHome).
            Unsupported,
            /// A quorum's members were not all pairwise-independent evidence, so corroboration would be meaningless.
            QuorumNotIndependent
        };

        /**
         * @brief A post-resolve validator predicate: returns false to fail an otherwise-resolved anchor closed.
         * @details Runs on the resolved value just before it is accepted. Returning false resets the value to 0 and
         *          sets @ref AnchorStatus::Failed, identical to a backend miss, so the caller re-heals by re-resolving.
         *          Use it to assert a domain invariant a generic backend cannot know (the target lies in an expected
         *          sub-range, a displacement points into `.rdata`, the site begins with a plausible prologue).
         * @param value The resolved value (an address cast to int64, an in-code constant, or the manual literal).
         * @param context The opaque @ref Anchor::validator_context pointer, forwarded verbatim (nullptr if unused).
         */
        using AnchorValidator = bool (*)(std::int64_t value, const void *context) noexcept;

        /**
         * @struct Anchor
         * @brief One declarative registry entry: what to resolve, how, and how to verify it. Authored as a static
         *        table.
         * @details A flat aggregate authored with designated initializers, so a table lists only the fields its kind
         *          uses and leaves the rest defaulted. The active field set depends on @ref kind; other kinds' fields
         *          are ignored. All views (@ref label, @ref mangled, @ref site, @ref xref_text) are non-owning and must
         *          outlive the resolve call -- the canonical use is a `static constexpr`/`static const` table whose
         *          storage lives for the process.
         */
        struct Anchor
        {
            /// Identifier echoed into the @ref ResolvedAnchor; excluded from @ref anchor_fingerprint.
            std::string_view label;
            /// Which backend resolves this anchor.
            AnchorKind kind = AnchorKind::Manual;

            /// VtableIdentity: the MSVC mangled type name, e.g. ".?AVGameAudioEffect@engine@@".
            std::string_view mangled;

            /**
             * @brief RipGlobal / CodeOperand: the candidate ladder resolving to the address or the instruction site.
             *        Borrowed.
             */
            std::span<const scan::Candidate> site;
            /// CodeOperand: whether to read an immediate or a memory-operand displacement.
            scan::OperandKind operand_kind = scan::OperandKind::Immediate;
            /// CodeOperand: index into the instruction's VISIBLE operands.
            std::uint8_t operand_index = 0;
            /// CodeOperand: 0 returns the decoded width; > 0 narrows to this many bytes then re-sign-extends.
            std::uint8_t byte_width = 0;

            /// StringXref: the exact literal content to anchor on (no quotes). Borrowed.
            std::string_view xref_text;
            /// StringXref: byte encoding of the literal in the image (Utf16le for wchar_t literals).
            scan::StringEncoding xref_encoding = scan::StringEncoding::Utf8;
            /// StringXref: whether to return the referencing instruction, its enclosing function, or the pointer slot.
            scan::XrefReturn xref_return = scan::XrefReturn::ReferencingInstruction;
            /// StringXref: match a trailing NUL so a prefix of a longer literal is not matched.
            bool xref_require_terminator = true;
            /// StringXref: keep the lea/mov shape scan and add the broad Zydis sweep for rarer reference shapes.
            bool xref_broad_match = false;

            /// Manual: the pinned literal value, taken as-is (unless @ref validate_manual runs the validator on it).
            std::int64_t manual_value = 0;

            /**
             * @brief Optional post-resolve predicate; nullptr skips validation. Never applied to Manual unless
             *        @ref validate_manual, nor to CallArgHome; for a Quorum it runs once on the corroborated value.
             */
            AnchorValidator validator = nullptr;
            /// Opaque pointer forwarded verbatim to @ref validator.
            const void *validator_context = nullptr;
            /// Run @ref validator on a Manual anchor too, instead of taking the pinned literal unchecked.
            bool validate_manual = false;
            /**
             * @brief Reject a backend-resolvable anchor that carries no @ref validator (status Failed). Only the four
             *        backend kinds are subject to this: a pinned Manual literal and a Quorum are both exempt -- a
             *        Manual is not a resolved target, and a Quorum's N-of-M corroboration is already the verification.
             */
            bool require_validator = false;

            /**
             * @brief Quorum: the M candidate sub-anchors that vote on the target. Non-owning pointers into the caller's
             *        own anchor storage; every member must outlive the resolve call. The quorum fails closed (status
             *        @ref AnchorStatus::Failed) on a malformed declaration -- fewer than two members, a null member, or
             *        a member that is itself a Quorum (nesting is bounded to one level).
             */
            std::span<const Anchor *const> quorum_members;
            /**
             * @brief Quorum: N, the minimum number of members that must resolve AND agree for the quorum to accept
             *        (N-of-M voting). 0 (the default) means unanimous -- every member in @ref quorum_members must
             *        agree, so a two-member quorum with the default is the strict 2-of-2 corroboration. A quorum is
             *        corroboration, so an explicit N below 2 or above the member count is a malformed vote and fails
             *        the quorum closed rather than degrading to a single signal.
             */
            std::size_t quorum_threshold = 0;
            /// Quorum: how two resolved member values must relate for a vote to count them as agreeing.
            QuorumMatch quorum_match = QuorumMatch::ExactValue;
            /// Quorum: the tolerance for @ref QuorumMatch::WithinTolerance (a negative tolerance fails closed).
            std::int64_t quorum_tolerance = 0;
        };

        /**
         * @struct ResolvedAnchor
         * @brief One resolved entry in the drift report: the anchor's identity plus its outcome and value.
         * @details The report array is the drift report itself: walk it once at init to log what resolved, what failed,
         *          and what is a pinned Manual literal and therefore at risk. @ref value is meaningful only when
         *          @ref status is @ref AnchorStatus::Resolved, and carries the quantity interpreted per @ref kind (a
         *          vtable or global address cast to int64, an in-code constant, or the manual literal).
         */
        struct ResolvedAnchor
        {
            /// Copied from @ref Anchor::label.
            std::string_view label;
            /// Copied from @ref Anchor::kind.
            AnchorKind kind = AnchorKind::Manual;
            /// The resolution outcome.
            AnchorStatus status = AnchorStatus::Unresolved;
            /// The resolved quantity, meaningful only when @ref status is @ref AnchorStatus::Resolved.
            std::int64_t value = 0;
        };

        /**
         * @struct AnchorQuality
         * @brief A one-pass robustness summary of a drift report, for gating "is this manifest healthy enough to run?".
         */
        struct AnchorQuality
        {
            /// Total entries in the report.
            std::size_t total = 0;
            /// Entries that resolved.
            std::size_t resolved = 0;
            /// Entries that failed closed.
            std::size_t failed = 0;
            /// Entries whose kind has no resolver yet (CallArgHome).
            std::size_t unsupported = 0;
            /// Quorum entries rejected because their sub-anchors were not independent.
            std::size_t not_independent = 0;
            /// Pinned Manual literals that cannot self-heal (counted regardless of status).
            std::size_t manual_at_risk = 0;
            /// Corroborated quorums that resolved (the strongest evidence).
            std::size_t corroborated = 0;
        };

        /**
         * @enum GateVerdict
         * @brief The startup decision a drift report yields: enable, enable-with-caution, or safe-disable.
         * @details Drift telemetry on its own only describes health; this is the verdict that lets a mod act on it --
         *          turn a feature off before it runs on unverified addresses instead of logging the low quality and
         *          patching the game's memory anyway.
         */
        enum class GateVerdict : std::uint8_t
        {
            /// Healthy enough to enable outright: the resolve ratio met the threshold and no at-risk signal fired.
            Pass,
            /**
             * @brief Resolved above the threshold, but a soft signal (a pinned Manual literal that cannot self-heal,
             *        or a report with nothing assessable) means the feature should run only with a logged caution.
             */
            Degraded,
            /**
             * @brief Below the threshold -- too few anchors resolved, or too many failed. Safe-disable the feature
             *        rather than run it on addresses the manifest could not verify.
             */
            Fail
        };

        /**
         * @struct GatePolicy
         * @brief The thresholds that turn an @ref AnchorQuality summary into a @ref GateVerdict. Defaults fail closed.
         * @details A plain value with no global state, so a mod can hold one policy per feature (a cosmetic overlay can
         *          tolerate a lower ratio than a frame-time camera patch that writes a live pointer). The defaults are
         *          the strictest: every resolvable anchor must heal and nothing may fail.
         */
        struct GatePolicy
        {
            /**
             * @brief Minimum fraction, in [0, 1], of RESOLVABLE anchors (@ref AnchorQuality::total minus the
             *        unsupported @ref AnchorKind::CallArgHome kind) that must resolve for the gate to pass. A
             *        caller-supplied value outside [0, 1] is clamped; NaN is treated as the strict default. The default
             *        1.0 requires every resolvable anchor to heal.
             */
            double min_resolved_ratio = 1.0;
            /**
             * @brief Hard cap on non-resolving failures (@ref AnchorQuality::failed plus @ref
             *        AnchorQuality::not_independent); exceeding it fails the gate regardless of the ratio. The default
             *        0 tolerates no failure.
             */
            std::size_t max_failed = 0;
            /**
             * @brief When true (the default), a resolved-but-pinned Manual anchor downgrades an otherwise-passing
             *        verdict to @ref GateVerdict::Degraded, because a Manual literal cannot self-heal across a patch.
             */
            bool manual_at_risk_degrades = true;
        };

        /**
         * @brief Turns a drift-report robustness summary into a startup enable/disable decision.
         * @param quality The summary from @ref assess_quality (or @ref diagnostics::Snapshot::anchor_quality).
         * @param policy The thresholds; the default policy fails closed (every resolvable anchor must heal, zero
         *               failures tolerated).
         * @return @ref GateVerdict::Fail when the report is below the threshold (safe-disable the feature), @ref
         *         GateVerdict::Degraded when it resolved but carries a soft risk, else @ref GateVerdict::Pass.
         * @details Feature-granular gating falls out of the report subset: resolve just a feature's anchors into a
         *          report (or gate a sub-span of a shared one), so one primitive serves both a whole-manifest health
         *          check and a per-feature kill switch. The ratio denominator excludes the
         *          unsupported @ref AnchorKind::CallArgHome kind (which has no resolver and can never heal), so
         *          declaring a forward-compatible kind never drags an otherwise-healthy manifest below the threshold.
         *          Everything that could resolve but did not -- a Failed anchor, a QuorumNotIndependent one, or an
         *          untouched Unresolved slot -- stays in the denominator, so a partial resolve fails closed. A report
         *          with nothing to assess (empty, or every anchor unsupported) is @ref GateVerdict::Degraded rather
         *          than a false Pass. Because this overload is public, a hand-built @ref AnchorQuality whose status
         *          counts exceed @ref AnchorQuality::total is rejected as internally inconsistent and fails closed to
         *          @ref GateVerdict::Fail, so a caller assembling a summary directly cannot inflate the resolved count
         *          past a threshold. Allocation-free and side-effect-free.
         */
        [[nodiscard]] GateVerdict evaluate_gate(const AnchorQuality &quality, const GatePolicy &policy = {}) noexcept;

        /**
         * @brief Summarizes a drift report and gates it in one call.
         * @param report The @ref ResolvedAnchor array (or a per-feature sub-span) produced by a resolve_all variant.
         * @param policy The gate thresholds.
         * @return The gate verdict for @p report under @p policy; equivalent to
         *         `evaluate_gate(assess_quality(report), policy)`.
         */
        [[nodiscard]] GateVerdict evaluate_gate(std::span<const ResolvedAnchor> report,
                                                const GatePolicy &policy = {}) noexcept;

        /**
         * @brief Maps a @ref GateVerdict to a short human-readable label.
         * @param verdict The verdict.
         * @return A static string view naming the verdict.
         */
        [[nodiscard]] std::string_view gate_verdict_to_string(GateVerdict verdict) noexcept;

        /**
         * @struct ScanProfile
         * @brief A per-game bundle of setup-only scan-tuning DEFAULTS, applied as a plain value with no global state.
         * @details It supplies defaults only: an explicit per-anchor choice still wins, so wiring a profile never
         *          overrides an explicit setting. The plain @ref resolve / @ref resolve_all are equivalent to resolving
         *          with an empty profile.
         */
        struct ScanProfile
        {
            /**
             * @brief Widen the broad string-xref sweep on for StringXref anchors. It can only widen: a per-anchor
             *        @ref Anchor::xref_broad_match still wins, so this never forces broad mode off.
             */
            bool default_broad_string_xref = false;
            /// The candidate ordering applied to RipGlobal / CodeOperand ladders (reuses the scan module's policy).
            scan::CandidateOrder candidate_order = scan::CandidateOrder::AsDeclared;
            /// A per-@ref AnchorKind deny-list. A denied backend fails closed (never silently replaced by another).
            std::array<bool, ANCHOR_KIND_COUNT> deny_backend{};

            /**
             * @brief Reports whether @p kind's backend is denied by this profile.
             * @param kind The anchor kind to test.
             * @return true when the kind is in range and its deny-list slot is set.
             */
            [[nodiscard]] bool is_denied(AnchorKind kind) const noexcept
            {
                const auto index = static_cast<std::size_t>(kind);
                return index < deny_backend.size() && deny_backend[index];
            }
        };

        /**
         * @brief Applies a profile's string-xref defaults to a query, widening broad-match only.
         * @param profile The profile whose defaults to apply.
         * @param query The base query (typically built from an anchor's xref_* fields).
         * @return The query with @ref ScanProfile::default_broad_string_xref folded in (widen-only: an already-broad
         *         query stays broad, never downgraded).
         */
        [[nodiscard]] scan::StringRefQuery apply_profile(const ScanProfile &profile,
                                                         scan::StringRefQuery query) noexcept;

        /**
         * @brief Resolves one anchor through its backend, fail-closed.
         * @param anchor The anchor to resolve.
         * @param scope The module image to resolve within; defaults to the host executable. Scoping is load-bearing:
         *              the same vtable name or instruction shape can exist in several loaded modules.
         * @return A @ref ResolvedAnchor carrying the outcome and (on success) the value.
         * @details Resolution is idempotent and side-effect-free, so re-running it on a stale value re-heals cleanly.
         */
        [[nodiscard]] ResolvedAnchor resolve(const Anchor &anchor, Region scope = Region::host());

        /**
         * @brief Resolves a table of anchors serially, writing one @ref ResolvedAnchor per input.
         * @param anchors The anchor table.
         * @param out The report buffer; at most `min(anchors.size(), out.size())` entries are written.
         * @param scope The module image to resolve within.
         * @return The number of entries written.
         */
        [[nodiscard]] std::size_t resolve_all(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                              Region scope = Region::host());

        /**
         * @brief Resolves a table of independent anchors concurrently through a fork-join worker pool.
         * @param anchors The anchor table.
         * @param out The report buffer; at most `min(anchors.size(), out.size())` entries are written, in input order.
         * @param scope The module image to resolve within.
         * @param max_workers Upper bound on worker threads (0 = auto-select from hardware_concurrency, clamped).
         * @return The number of entries written.
         * @details Each anchor still goes through the single-anchor @ref resolve path, so backend failures, validators,
         *          quorum checks, and result ordering all match @ref resolve_all. It is opt-in because validators run
         *          concurrently; use the serial @ref resolve_all when a validator context is order-dependent or must be
         *          externally serialized.
         * @note Setup/control-plane only: spawns a worker pool. Never call it from a hook or under the loader lock.
         */
        [[nodiscard]] std::size_t resolve_all_parallel(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                                       Region scope = Region::host(), std::size_t max_workers = 0);

        /**
         * @brief Rolls a drift report into an @ref AnchorQuality summary in one allocation-free pass (no re-resolve).
         * @param report The @ref ResolvedAnchor array produced by a resolve_all variant.
         * @return The tallied summary.
         */
        [[nodiscard]] AnchorQuality assess_quality(std::span<const ResolvedAnchor> report) noexcept;

        /**
         * @brief Hashes an anchor's resolution EVIDENCE into a stable 64-bit diff key, excluding the resolved address.
         * @param anchor The anchor to fingerprint.
         * @return A 64-bit FNV-1a hash of the declarative inputs the backend uses.
         * @details The fingerprint deliberately excludes the resolved address (and the cosmetic @ref Anchor::label and
         *          candidate names), so it is stable when only the address drifts. Persist it next to each resolved
         *          value and a manifest diff on the next game version tells two cases apart: a matching fingerprint
         *          with a moved value is expected drift the anchor self-healed; a changed fingerprint means the
         *          signature itself was rewritten (a new pattern, a renamed type, a different string) and is the entry
         *          to re-review. The evidence is content-derived -- for byte tiers it hashes the compiled Pattern's
         *          bytes, mask, and decode parameters (the source AOB text is not retained past compilation) -- so it
         *          is stable across runs and builds on a given platform. A Quorum combines all of its members'
         *          evidence order-independently (voting is symmetric, so reordering the members must not change the
         *          fingerprint) and folds in the effective vote threshold, agreement mode, and tolerance. It reads only
         *          the declarative views, resolves nothing, and allocates nothing.
         */
        [[nodiscard]] std::uint64_t anchor_fingerprint(const Anchor &anchor) noexcept;

        /**
         * @brief Maps an @ref AnchorStatus to a short human-readable label.
         * @param status The status.
         * @return A static string view naming the status.
         */
        [[nodiscard]] std::string_view anchor_status_to_string(AnchorStatus status) noexcept;

        /**
         * @brief Resolves one anchor with a profile's defaults applied (deny-list, candidate order, broad-string
         * widen).
         * @param anchor The anchor to resolve.
         * @param profile The per-game defaults. A denied backend fails closed; the profile threads into Quorum
         *                 sub-anchors, so a denied sub-anchor kind fails the quorum closed.
         * @param scope The module image to resolve within.
         * @return A @ref ResolvedAnchor carrying the outcome and (on success) the value.
         */
        [[nodiscard]] ResolvedAnchor resolve_with_profile(const Anchor &anchor, const ScanProfile &profile,
                                                          Region scope = Region::host());

        /**
         * @brief Resolves a table serially with a profile's defaults applied.
         * @param anchors The anchor table.
         * @param out The report buffer; at most `min(anchors.size(), out.size())` entries are written.
         * @param profile The per-game defaults.
         * @param scope The module image to resolve within.
         * @return The number of entries written.
         */
        [[nodiscard]] std::size_t resolve_all_with_profile(std::span<const Anchor> anchors,
                                                           std::span<ResolvedAnchor> out, const ScanProfile &profile,
                                                           Region scope = Region::host());

        /**
         * @brief Resolves a table concurrently with a profile's defaults applied.
         * @param anchors The anchor table.
         * @param out The report buffer; at most `min(anchors.size(), out.size())` entries are written, in input order.
         * @param profile The per-game defaults.
         * @param scope The module image to resolve within.
         * @param max_workers Upper bound on worker threads (0 = auto-select).
         * @return The number of entries written.
         * @note Setup/control-plane only: spawns a worker pool. Never call it from a hook or under the loader lock.
         */
        [[nodiscard]] std::size_t resolve_all_with_profile_parallel(std::span<const Anchor> anchors,
                                                                    std::span<ResolvedAnchor> out,
                                                                    const ScanProfile &profile,
                                                                    Region scope = Region::host(),
                                                                    std::size_t max_workers = 0);
    } // namespace anchor
} // namespace DetourModKit

#endif // DETOURMODKIT_ANCHOR_HPP
