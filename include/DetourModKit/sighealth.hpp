#ifndef DETOURMODKIT_SIGHEALTH_HPP
#define DETOURMODKIT_SIGHEALTH_HPP

/**
 * @file sighealth.hpp
 * @brief Offline signature-health analysis: score a signature's robustness before it runs against a game.
 * @details `[B-57]` The analysis is offline and side-effect-free. It reads only the compiled @ref scan::Pattern bytes
 *          and the @ref manifest::SignatureRecord fields, touches no process memory, and starts no worker. Health
 *          never gates runtime behavior. docs/guides/scanning/signature-health.md explains the quality axes.
 * @warning `[B-100]` Every function except `to_string` can allocate. Call only `to_string` under the loader lock.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/manifest.hpp"
#include "DetourModKit/scan.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace sighealth
    {
        /** @brief The concern level of a @ref Finding, ordered least to most. */
        enum class Severity : std::uint8_t
        {
            /// The signature works today but is brittle or weakly selective, so it needs a review.
            Warning,
            /// A structural defect (no fixed byte, empty text, failed compile) or effectively non-unique selectivity.
            Critical
        };

        /** @brief The specific health issue a @ref Finding names. Several kinds can fire on one signature. */
        enum class FindingKind : std::uint8_t
        {
            /// The byte pattern has no fully-known byte to anchor on, so every position needs a masked compare.
            NoFixedAnchor,
            /// A byte-tier rung's AOB string failed to compile (malformed, empty, or over the inline-storage cap).
            UncompilablePattern,
            /// The pattern is shorter than the recommended byte floor, so it is unlikely to be unique.
            ShortPattern,
            /// The longest run of consecutive fully-known bytes (the memchr atom) is short and weakens the prefilter.
            ShortestAnchorRun,
            /// Every fully-known byte is a high-frequency opcode or padding, so a long atom is still a poor anchor.
            CommonBytesOnly,
            /// Wildcards dominate the pattern, so most positions place no constraint on a match.
            HighWildcardRatio,
            /// The fully-known bytes are repetitive (low Shannon entropy): long in bytes but low in information.
            LowByteEntropy,
            /// The expected-match estimate is high, so the pattern is weakly selective.
            WeakSelectivity,
            /// A text anchor (string-xref literal, mangled name, or export name) is empty and cannot resolve anything.
            EmptyAnchorText,
            /// A string-xref literal is short enough to collide with another literal in the image.
            ShortAnchorText,
            /// A Manual pinned literal cannot self-heal across a game patch, so it silently goes stale.
            UnhealableManual,
            /// The record's kind (Quorum, CallArgHome, or Unset) cannot live in a manifest record.
            NonSerializableKind,
            /// No rung in a candidate ladder graded Robust, so the record has no strong tier to fall back on.
            NoRobustRung,
            /// The record fails @ref manifest::Signature::compile and no other finding already graded it Unusable.
            UncompilableRecord,
            /**
             * @brief A RIP-relative rung fixes a byte or nibble of its declared disp32, which a relink can change.
             * @details The check covers only the bytes before the first bounded jump. Use `??` for each disp32 byte.
             */
            VolatileDisplacementBytes
        };

        /** @brief A robustness verdict. The worst finding decides a pattern or rung grade. See @ref analyze_record. */
        enum class Grade : std::uint8_t
        {
            /// A pattern or rung with no finding: the signature is selective and resilient, so ship it.
            Robust,
            /// A pattern or rung whose worst finding is a Warning: review the signature before you ship it.
            Fragile,
            /// A pattern or rung whose worst finding is Critical: the signature cannot anchor reliably.
            Unusable
        };

        /** @brief One health issue: what is wrong (@ref kind) and how much it matters (@ref severity). */
        struct Finding
        {
            /// The specific issue.
            FindingKind kind = FindingKind::NoFixedAnchor;
            /// Its severity, which drives the @ref Grade roll-up.
            Severity severity = Severity::Warning;
        };

        /** @brief The grading thresholds. Defaults target a large game module that patches often. */
        struct HealthPolicy
        {
            /// Module size in bytes that the expected-match estimate models. A larger value is stricter.
            std::size_t nominal_haystack_bytes = 64u * 1024u * 1024u;
            /// A byte pattern shorter than this trips @ref FindingKind::ShortPattern.
            std::size_t min_pattern_bytes = 5;
            /// A non-empty longest fully-known run shorter than this trips @ref FindingKind::ShortestAnchorRun.
            std::size_t min_longest_atom = 4;
            /// A non-empty string-xref literal shorter than this trips @ref FindingKind::ShortAnchorText.
            std::size_t min_anchor_text_bytes = 5;
            /// A full-wildcard fraction above this trips @ref FindingKind::HighWildcardRatio.
            double max_wildcard_ratio = 0.6;
            /// Below this, @ref FindingKind::LowByteEntropy trips once a pattern has enough fully-known bytes to judge.
            double min_byte_entropy_bits = 1.5;
            /// An expected-match estimate above this trips a @ref Severity::Warning @ref FindingKind::WeakSelectivity.
            double warn_expected_matches = 1.0;
            /// An expected-match estimate above this escalates @ref FindingKind::WeakSelectivity to Critical severity.
            double fail_expected_matches = 32.0;
        };

        /** @brief The static analysis of one @ref scan::Pattern. Counts cover the compiled pattern's positions. */
        struct PatternHealth
        {
            /// Number of positions, as @ref scan::Pattern::size reports it (gap bytes excluded).
            std::size_t length = 0;
            /// Positions with a fully-known byte (mask 0xFF).
            std::size_t fixed_bytes = 0;
            /// Positions with one known nibble (mask 0xF0 or 0x0F).
            std::size_t nibble_bytes = 0;
            /// Positions that match any byte (mask 0x00).
            std::size_t wildcard_bytes = 0;
            /// Number of maximal runs of consecutive fully-known bytes. A bounded jump ends an atom.
            std::size_t atom_count = 0;
            /// Length of the longest such run.
            std::size_t longest_atom = 0;
            /// Fraction of positions that are full wildcards, in [0, 1].
            double wildcard_ratio = 0.0;
            /// Selectivity in bits: at most 8 per fully-known byte (fewer if common), 4 per nibble, 0 per wildcard.
            double selectivity_bits = 0.0;
            /// Shannon entropy in bits over the fully-known byte values, or 0 when there are none.
            double byte_entropy_bits = 0.0;
            /// Heuristic expected-match estimate, not a guarantee. The signature-health guide owns the formula.
            double expected_matches = 0.0;
            /// True when every fully-known byte is a high-frequency opcode or padding (low atom rarity).
            bool common_bytes_only = false;
            /// The findings this pattern tripped.
            std::vector<Finding> findings;
            /// The roll-up verdict.
            Grade grade = Grade::Robust;
        };

        /** @brief One rung's health: byte tier (Direct, RipRelative) or text tier (RttiVtable, StringXref). */
        struct CandidateHealth
        {
            /// Which resolution tier this rung uses.
            scan::Mode mode = scan::Mode::Direct;
            /// False when a byte-tier rung's AOB string failed to compile. Always true for a text tier.
            bool compiled = true;
            /// Byte tiers: the compiled pattern's analysis. Text tiers: default-constructed (length 0).
            PatternHealth pattern;
            /// Text tiers: the anchor text length in bytes. 0 for the byte tiers.
            std::size_t anchor_text_bytes = 0;
            /// The rung findings. A byte tier also reports pattern and rung-layout findings.
            std::vector<Finding> findings;
            /// The rung roll-up verdict.
            Grade grade = Grade::Robust;
        };

        /** @brief The health of one @ref manifest::SignatureRecord. @ref analyze_record owns the grade rule. */
        struct RecordHealth
        {
            /// The signature's key.
            std::string label;
            /// Which anchor backend the record uses, and therefore which fields below are meaningful.
            anchor::AnchorKind kind = anchor::AnchorKind::RipGlobal;
            /// Byte backends (RipGlobal, CodeOperand): one entry per rung, in file order. Empty for other backends.
            std::vector<CandidateHealth> ladder;
            /// Text backends (StringXref, VtableIdentity, ExportName): the anchor text length in bytes. 0 otherwise.
            std::size_t anchor_text_bytes = 0;
            /// Selectivity bits of the compiled byte-tier rung with the lowest expected-match estimate, or 0 if none.
            double best_selectivity_bits = 0.0;
            /// The lowest expected-match estimate among the compiled byte-tier rungs, or 0 if none.
            double best_expected_matches = 0.0;
            /// How many ladder rungs graded @ref Grade::Robust.
            std::size_t robust_rungs = 0;
            /// The record-level findings (Manual pin, non-serializable kind, no-robust-rung, text-anchor issues).
            std::vector<Finding> findings;
            /// The record roll-up verdict.
            Grade grade = Grade::Robust;
        };

        /** @brief The health of a whole @ref manifest::Manifest: per-record reports plus a grade tally. */
        struct ManifestHealth
        {
            /// Per-record health, in file order.
            std::vector<RecordHealth> records;
            /// Records that graded @ref Grade::Robust.
            std::size_t robust = 0;
            /// Records that graded @ref Grade::Fragile.
            std::size_t fragile = 0;
            /// Records that graded @ref Grade::Unusable.
            std::size_t unusable = 0;
            /// The weakest record's grade (the whole-manifest verdict).
            Grade grade = Grade::Robust;
        };

        /**
         * @brief Grades one compiled byte pattern's robustness.
         * @note Setup/control-plane only: it allocates.
         */
        [[nodiscard]] PatternHealth analyze_pattern(const scan::Pattern &pattern, const HealthPolicy &policy = {});

        /**
         * @brief Grades one ladder rung. An uncompilable byte-tier AOB grades @ref Grade::Unusable and does not throw.
         * @note Setup/control-plane only: it allocates.
         */
        [[nodiscard]] CandidateHealth
        analyze_candidate(const manifest::CandidateSpec &spec, const HealthPolicy &policy = {});

        /**
         * @brief Grades one signature record: its ladder (byte backends) or its text anchor (text backends).
         * @details A byte record starts from its first declared rung. A text record starts from its anchor text length.
         *          Record-level findings and @ref manifest::Signature::compile can only worsen that grade. A record
         *          that does not compile grades @ref Grade::Unusable.
         * @note Setup/control-plane only: it allocates.
         */
        [[nodiscard]] RecordHealth
        analyze_record(const manifest::SignatureRecord &record, const HealthPolicy &policy = {});

        /**
         * @brief Grades a whole manifest record by record and rolls the results into a manifest verdict.
         * @note Setup/control-plane only: it allocates.
         */
        [[nodiscard]] ManifestHealth
        analyze_manifest(const manifest::Manifest &manifest, const HealthPolicy &policy = {});

        /**
         * @brief Maps a @ref Severity to a short label with static storage.
         * @note Callback-safe: pure value map, no allocation.
         */
        [[nodiscard]] std::string_view to_string(Severity severity) noexcept;

        /**
         * @brief Maps a @ref FindingKind to a short description with static storage.
         * @note Callback-safe: pure value map, no allocation.
         */
        [[nodiscard]] std::string_view to_string(FindingKind kind) noexcept;

        /**
         * @brief Maps a @ref Grade to a short label with static storage.
         * @note Callback-safe: pure value map, no allocation.
         */
        [[nodiscard]] std::string_view to_string(Grade grade) noexcept;

        /**
         * @brief Renders one pattern's health as a multi-line lint report.
         * @param label An optional caption, for example the rung name. The report omits an empty label.
         * @return The grade, the measured counts and figures, and one line per finding.
         * @note Setup/control-plane only: it allocates.
         */
        [[nodiscard]] std::string format_report(const PatternHealth &health, std::string_view label = {});

        /**
         * @brief Renders one signature record's health as a multi-line lint report.
         * @return The label, kind, and grade, the strongest byte rung's figures or the anchor text length, each rung's
         *         grade and findings, and the record-level findings.
         * @note Setup/control-plane only: it allocates.
         */
        [[nodiscard]] std::string format_report(const RecordHealth &health);

        /**
         * @brief Renders a whole manifest's health as a multi-line lint report.
         * @return A first line with the manifest grade and the record count per grade, then one section per record.
         * @note Setup/control-plane only: it allocates.
         */
        [[nodiscard]] std::string format_report(const ManifestHealth &health);
    } // namespace sighealth
} // namespace DetourModKit

#endif // DETOURMODKIT_SIGHEALTH_HPP
