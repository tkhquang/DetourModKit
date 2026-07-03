#ifndef DETOURMODKIT_SIGHEALTH_HPP
#define DETOURMODKIT_SIGHEALTH_HPP

/**
 * @file sighealth.hpp
 * @brief Offline signature-health analysis: score a signature's robustness before it ever runs against a game.
 * @details The @ref anchor and @ref manifest modules answer "did this signature resolve, and does its shape still
 *          match?" -- but only at runtime, against a live image. A brittle signature (three common bytes, a wall of
 *          wildcards, a two-character string) still resolves uniquely today and only breaks silently on the next game
 *          patch, when the author is no longer looking. This module closes that gap: it grades a signature statically,
 *          from its declarative bytes alone, so a weak anchor is caught at authoring time rather than in a bug report.
 *
 *          Everything here is offline and side-effect-free. It touches no process memory, spawns no worker, and needs
 *          no game running -- it reads the compiled @ref scan::Pattern bytes and the @ref manifest::SignatureRecord
 *          fields and returns a report. That makes it the natural companion to the @ref manifest module: once a
 *          signature contract is editable data, its quality becomes checkable data too, and an author (or a CI lane)
 *          can lint a `.signatures.ini` the same way it lints source.
 *
 *          Three axes drive the grade, each a well-known signature-quality signal:
 *
 *          - **Atom rarity.** An "atom" is a maximal run of fully-known bytes -- the only thing a byte prefilter can
 *            memchr for. A long atom of *rare* bytes is a strong anchor; a long atom of padding / common opcodes
 *            (`00`, `CC`, `48`, `8B`) barely narrows the search. The rarity model is the scan engine's own frequency
 *            table (@ref DetourModKit::detail::byte_frequency_class), so the grade matches the byte the engine would
 *            anchor on.
 *          - **Byte entropy.** A run of identical bytes (`90 90 90 90`) is long but carries almost no distinguishing
 *            information. Shannon entropy over the fixed byte values catches that low-information shape a raw byte count
 *            misses.
 *          - **Expected ambiguity.** Combining per-position selectivity into an estimate of how many false matches a
 *            pattern would draw in a nominal module (@ref HealthPolicy::nominal_haystack_bytes) turns "is this unique?"
 *            into a number an author can act on. It is a heuristic order-of-magnitude estimate under an independent-byte
 *            model, not a guarantee -- the runtime resolver still verifies uniqueness -- but it reliably separates a
 *            5-rare-byte anchor (effectively unique) from a 3-common-byte one (thousands of hits).
 *
 *          The analysis layers over the @ref manifest surface the same way the manifest layers over @ref anchor:
 *          @ref analyze_pattern is the primitive over one @ref scan::Pattern; @ref analyze_candidate grades one ladder
 *          rung; @ref analyze_record grades a whole @ref manifest::SignatureRecord (its ladder or its text anchor, per
 *          kind); @ref analyze_manifest rolls up a file. Each level yields a @ref Grade (Robust / Fragile / Unusable)
 *          and a list of @ref Finding values naming exactly what is weak, and the @ref format_report overloads render a
 *          human-readable lint report for a tool or a log.
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
        /**
         * @enum Severity
         * @brief How much a single @ref Finding should worry an author, ordered least to most.
         * @details There is no "informational" tier: every @ref Finding names a real weakness, so a clean report is one
         *          with no findings at all (which grades @ref Grade::Robust), not one whose findings are all benign.
         */
        enum class Severity : std::uint8_t
        {
            /// A real weakness: the signature works today but is brittle or weakly selective and should be reviewed.
            Warning,
            /// A structural defect: the signature cannot anchor reliably (no fixed byte, empty text, will not compile).
            Critical
        };

        /**
         * @enum FindingKind
         * @brief The specific health issue a @ref Finding names. Each maps to one actionable authoring fix.
         * @details The three quality axes (atom rarity, entropy, expected ambiguity) surface as @ref CommonBytesOnly /
         *          @ref ShortestAnchorRun, @ref LowByteEntropy, and @ref WeakSelectivity respectively; the rest are the
         *          structural checks that make those axes actionable. Several kinds can fire on one signature at once (a
         *          short, over-wildcarded, common-byte pattern trips three), which is intentional: each names a distinct
         *          reason and a distinct fix.
         */
        enum class FindingKind : std::uint8_t
        {
            /// The byte pattern has no fully-known byte to anchor on, forcing a masked compare at every position.
            NoFixedAnchor,
            /// A byte-tier rung's AOB string failed to compile (malformed, empty, or over the inline-storage cap).
            UncompilablePattern,
            /// The pattern is shorter than the recommended byte floor, so it is unlikely to be unique.
            ShortPattern,
            /// The longest run of consecutive fully-known bytes (the memchr atom) is short, weakening the prefilter.
            ShortestAnchorRun,
            /// Every fully-known byte is a high-frequency opcode or padding, so a long atom is still a poor anchor.
            CommonBytesOnly,
            /// Wildcards dominate the pattern, so most positions place no constraint on a match.
            HighWildcardRatio,
            /// The fully-known bytes are repetitive (low Shannon entropy): long in bytes but low in information.
            LowByteEntropy,
            /// The estimated false-match count in a nominal module is high; the pattern is weakly selective.
            WeakSelectivity,
            /// A text anchor (string-xref literal or vtable mangled name) is empty and cannot resolve anything.
            EmptyAnchorText,
            /// A text anchor is short enough that it may not be unique in the image (a common literal, a bare name).
            ShortAnchorText,
            /// A Manual pinned literal cannot self-heal across a game patch; it will silently go stale.
            UnhealableManual,
            /// The record's kind (Quorum / CallArgHome) is not file-serializable and cannot live in a manifest record.
            NonSerializableKind,
            /// No rung in a candidate ladder graded Robust, so the record has no strong tier to fall back on.
            NoRobustRung
        };

        /**
         * @enum Grade
         * @brief The overall robustness verdict for a pattern, rung, record, or manifest.
         * @details Derived from the worst @ref Severity present: any @ref Severity::Critical finding yields
         *          @ref Unusable, any @ref Severity::Warning yields @ref Fragile, and a clean report yields @ref Robust.
         *          A record grades by its strongest rung (the resolver tries the ladder until one rung resolves, so a
         *          record is as strong as its best tier); a manifest grades by its weakest record (each signature gates
         *          its own feature, so the file is only as trustworthy as its weakest signature).
         */
        enum class Grade : std::uint8_t
        {
            /// Selective and resilient: ship it.
            Robust,
            /// Resolves today but brittle or weakly selective: review before shipping.
            Fragile,
            /// Cannot anchor reliably: no fixed byte, empty text, will not compile, or effectively non-unique.
            Unusable
        };

        /**
         * @struct Finding
         * @brief One health issue: what is wrong (@ref kind) and how much it matters (@ref severity).
         * @details Deliberately data-only and trivially copyable: the specific numbers (byte counts, entropy, expected
         *          matches) live in the surrounding report struct, so a finding stays a cheap (kind, severity) tag that
         *          @ref to_string names and @ref format_report renders against those numbers.
         */
        struct Finding
        {
            /// The specific issue.
            FindingKind kind = FindingKind::NoFixedAnchor;
            /// Its severity, which drives the @ref Grade roll-up.
            Severity severity = Severity::Warning;
        };

        /**
         * @struct HealthPolicy
         * @brief The thresholds the analysis grades against. Defaults target a large, fast-patching game module.
         * @details A plain value with no global state, so an author can hold one policy per game or per feature (a
         *          small helper DLL scanned inside a 4 MiB module tolerates a looser floor than a signature scanned
         *          inside a 200 MiB game). Every threshold is a documented lint knob, not a hard runtime limit: relaxing
         *          one only changes which findings fire, never what the resolver accepts.
         */
        struct HealthPolicy
        {
            /**
             * @brief The module size, in bytes, the expected-ambiguity estimate models. A larger value is stricter: a
             *        bigger haystack draws more false matches for the same pattern. The default models a large game's
             *        executable pages.
             */
            std::size_t nominal_haystack_bytes = 64u * 1024u * 1024u;
            /// A byte pattern shorter than this trips @ref FindingKind::ShortPattern.
            std::size_t min_pattern_bytes = 5;
            /// A longest fully-known run shorter than this trips @ref FindingKind::ShortestAnchorRun.
            std::size_t min_longest_atom = 4;
            /// A text anchor (string literal / mangled name) shorter than this trips @ref FindingKind::ShortAnchorText.
            std::size_t min_anchor_text_bytes = 5;
            /// A full-wildcard fraction above this trips @ref FindingKind::HighWildcardRatio.
            double max_wildcard_ratio = 0.6;
            /// Fully-known byte entropy below this (given enough fixed bytes) trips @ref FindingKind::LowByteEntropy.
            double min_byte_entropy_bits = 1.5;
            /// An expected-match estimate above this trips a @ref Severity::Warning @ref FindingKind::WeakSelectivity.
            double warn_expected_matches = 1.0;
            /// An expected-match estimate above this escalates @ref FindingKind::WeakSelectivity to Critical severity.
            double fail_expected_matches = 32.0;
        };

        /**
         * @struct PatternHealth
         * @brief The static analysis of one @ref scan::Pattern: its byte composition, selectivity, and findings.
         * @details All counts are over the compiled pattern's positions. The headline signals are @ref longest_atom
         *          (atom rarity, with @ref common_bytes_only), @ref byte_entropy_bits (entropy), and
         *          @ref expected_matches (ambiguity). @ref findings names every threshold the pattern crossed and
         *          @ref grade rolls them up.
         */
        struct PatternHealth
        {
            /// Total bytes in the pattern.
            std::size_t length = 0;
            /// Positions with a fully-known byte (mask 0xFF).
            std::size_t fixed_bytes = 0;
            /// Positions with a single fixed nibble (mask 0xF0 or 0x0F).
            std::size_t nibble_bytes = 0;
            /// Positions that match any byte (mask 0x00).
            std::size_t wildcard_bytes = 0;
            /// Number of maximal runs of consecutive fully-known bytes (the candidate memchr atoms).
            std::size_t atom_count = 0;
            /// Length of the longest such run (the atom a byte prefilter can actually search for).
            std::size_t longest_atom = 0;
            /// Fraction of positions that are full wildcards, in [0, 1].
            double wildcard_ratio = 0.0;
            /**
             * @brief Estimated selectivity in bits: the sum over all positions of how much each constrains a match. A
             *        rare fixed byte contributes up to 8 bits, a common one fewer, a fixed nibble 4, a wildcard 0.
             */
            double selectivity_bits = 0.0;
            /// Shannon entropy in bits over the distribution of fully-known byte VALUES (0 when there are none).
            double byte_entropy_bits = 0.0;
            /**
             * @brief Estimated number of false matches in a haystack of @ref HealthPolicy::nominal_haystack_bytes,
             *        `nominal_haystack_bytes * 2^(-selectivity_bits)`. A heuristic order-of-magnitude figure, not a
             *        guarantee.
             */
            double expected_matches = 0.0;
            /// True when every fully-known byte is a high-frequency opcode or padding (low atom rarity).
            bool common_bytes_only = false;
            /// The findings this pattern tripped.
            std::vector<Finding> findings;
            /// The roll-up verdict.
            Grade grade = Grade::Robust;
        };

        /**
         * @struct CandidateHealth
         * @brief The health of one candidate-ladder rung, byte tier or text tier.
         * @details A ladder rung (@ref manifest::CandidateSpec) resolves through one of the four @ref scan::Mode tiers.
         *          The two byte tiers (Direct, RipRelative) are graded by @ref pattern; the two text tiers (RttiVtable,
         *          StringXref) have no byte pattern and are graded by @ref anchor_text_bytes and the text findings.
         *          @ref findings is the rung's complete finding list at both tiers (for a byte tier it mirrors
         *          @ref pattern's findings), and @ref grade is the rung roll-up, so a caller can read @ref grade and
         *          @ref findings uniformly and drill into @ref pattern only when it wants the byte metrics.
         */
        struct CandidateHealth
        {
            /// Which resolution tier this rung uses.
            scan::Mode mode = scan::Mode::Direct;
            /// Byte tiers only: false when the rung's AOB string failed to compile. Always true for the text tiers.
            bool compiled = true;
            /// Byte tiers: the compiled pattern's analysis. Text tiers: default-constructed (length 0).
            PatternHealth pattern;
            /// Text tiers: the anchor literal / mangled-name length in bytes. 0 for the byte tiers.
            std::size_t anchor_text_bytes = 0;
            /// The rung's complete finding list (mirrors @ref pattern's findings for a byte tier).
            std::vector<Finding> findings;
            /// The rung roll-up verdict.
            Grade grade = Grade::Robust;
        };

        /**
         * @struct RecordHealth
         * @brief The health of one @ref manifest::SignatureRecord: its ladder or text anchor, plus record findings.
         * @details Which fields are meaningful depends on @ref kind, exactly as it does on the record itself. A byte
         *          backend (RipGlobal / CodeOperand) fills @ref ladder with one @ref CandidateHealth per rung and grades
         *          by the strongest rung; a text backend (StringXref / VtableIdentity) leaves @ref ladder empty and
         *          grades by @ref anchor_text_bytes; a Manual pin and the non-serializable composite kinds report a
         *          record-level @ref Finding. @ref label is owned by the report, so a caller may keep or format the
         *          health result after the source record / manifest has gone out of scope. @ref findings holds only
         *          the record-level findings (a Manual pin, a non-serializable kind, a no-robust-rung note, or a
         *          text-anchor issue); per-rung findings live in @ref ladder.
         */
        struct RecordHealth
        {
            /// The signature's key.
            std::string label;
            /// Which anchor backend the record uses, and therefore which fields below are meaningful.
            anchor::AnchorKind kind = anchor::AnchorKind::RipGlobal;
            /// Byte backends: one entry per ladder rung, in file order. Empty for text / Manual backends.
            std::vector<CandidateHealth> ladder;
            /// Text backends: the string literal / mangled-name length in bytes. 0 otherwise.
            std::size_t anchor_text_bytes = 0;
            /// The strongest rung's selectivity in bits (byte backends); 0 for text / Manual backends.
            double best_selectivity_bits = 0.0;
            /// The strongest rung's expected-match estimate (byte backends); 0 for text / Manual backends.
            double best_expected_matches = 0.0;
            /// How many ladder rungs graded @ref Grade::Robust.
            std::size_t robust_rungs = 0;
            /// The record-level findings (Manual pin, non-serializable kind, no-robust-rung, text-anchor issues).
            std::vector<Finding> findings;
            /// The record roll-up verdict.
            Grade grade = Grade::Robust;
        };

        /**
         * @struct ManifestHealth
         * @brief The health of a whole @ref manifest::Manifest: per-record reports plus a grade tally.
         * @details @ref records mirrors the manifest's records in file order and owns each copied label. @ref grade is
         *          the weakest record's grade, because each signature gates its own feature, so a single Unusable
         *          signature makes the file only as trustworthy as that signature even if every other one is Robust.
         *          The three counters partition @ref records by grade for a one-line summary.
         */
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
         * @param pattern The compiled pattern (from @ref scan::Pattern::compile or @ref scan::Pattern::literal).
         * @param policy The grading thresholds.
         * @return The pattern's composition, selectivity, entropy, expected-match estimate, findings, and grade.
         * @note Setup/control-plane only: it allocates the findings vector, so it is not noexcept. It reads no process
         *       memory and needs no game running.
         */
        [[nodiscard]] PatternHealth analyze_pattern(const scan::Pattern &pattern, const HealthPolicy &policy = {});

        /**
         * @brief Grades one candidate-ladder rung, compiling its byte pattern or measuring its text anchor by tier.
         * @param spec The rung to grade.
         * @param policy The grading thresholds.
         * @return The rung's tier-appropriate health. A byte tier whose AOB fails to compile reports
         *         @ref FindingKind::UncompilablePattern and grades @ref Grade::Unusable rather than throwing.
         * @note Setup/control-plane only: allocates, reads no process memory.
         */
        [[nodiscard]] CandidateHealth analyze_candidate(const manifest::CandidateSpec &spec,
                                                        const HealthPolicy &policy = {});

        /**
         * @brief Grades one signature record: its ladder (byte backends) or its text anchor (text backends).
         * @param record The record to grade.
         * @param policy The grading thresholds.
         * @return The record's health. A byte backend grades by its strongest rung; a text backend by its anchor-text
         *         length; a Manual pin and the non-serializable composite kinds report a record-level finding.
         * @note Setup/control-plane only: allocates, reads no process memory.
         */
        [[nodiscard]] RecordHealth analyze_record(const manifest::SignatureRecord &record,
                                                  const HealthPolicy &policy = {});

        /**
         * @brief Grades a whole manifest, record by record, and rolls the results into a manifest verdict.
         * @param manifest The parsed manifest (from @ref manifest::parse or @ref manifest::load).
         * @param policy The grading thresholds.
         * @return The per-record health plus the grade tally; @ref ManifestHealth::grade is the weakest record's grade.
         * @note Setup/control-plane only: allocates, reads no process memory.
         */
        [[nodiscard]] ManifestHealth analyze_manifest(const manifest::Manifest &manifest,
                                                      const HealthPolicy &policy = {});

        /**
         * @brief Maps a @ref Severity to a short human-readable label.
         * @param severity The severity.
         * @return A static string view naming it.
         * @note Callback-safe: pure value map, no allocation.
         */
        [[nodiscard]] std::string_view to_string(Severity severity) noexcept;

        /**
         * @brief Maps a @ref FindingKind to a short human-readable description of the issue.
         * @param kind The finding kind.
         * @return A static string view describing it.
         * @note Callback-safe: pure value map, no allocation.
         */
        [[nodiscard]] std::string_view to_string(FindingKind kind) noexcept;

        /**
         * @brief Maps a @ref Grade to a short human-readable label.
         * @param grade The grade.
         * @return A static string view naming it.
         * @note Callback-safe: pure value map, no allocation.
         */
        [[nodiscard]] std::string_view to_string(Grade grade) noexcept;

        /**
         * @brief Renders one pattern's health as a multi-line lint report.
         * @param health The analyzed pattern.
         * @param label An optional caption for the pattern (e.g. the rung name); rendered when non-empty.
         * @return A human-readable report: the grade, the byte composition, the selectivity and expected-match figures,
         *         and one line per finding.
         * @note Allocates; intended for tool output or a log line, never a hot path.
         */
        [[nodiscard]] std::string format_report(const PatternHealth &health, std::string_view label = {});

        /**
         * @brief Renders one signature record's health as a multi-line lint report.
         * @param health The analyzed record.
         * @return A human-readable report: the record label, kind, grade, the strongest rung's figures, and the
         *         per-rung and record-level findings.
         * @note Allocates; intended for tool output or a log line, never a hot path.
         */
        [[nodiscard]] std::string format_report(const RecordHealth &health);

        /**
         * @brief Renders a whole manifest's health as a multi-line lint report.
         * @param health The analyzed manifest.
         * @return A human-readable report: the grade tally, the manifest verdict, and one section per record.
         * @note Allocates; intended for tool output or a log line, never a hot path.
         */
        [[nodiscard]] std::string format_report(const ManifestHealth &health);
    } // namespace sighealth
} // namespace DetourModKit

#endif // DETOURMODKIT_SIGHEALTH_HPP
