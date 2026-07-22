#include "DetourModKit/sighealth.hpp"

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/manifest.hpp"
#include "DetourModKit/scan.hpp"

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace DetourModKit
{
    namespace sighealth
    {
        namespace
        {
            // Grade algebra
            // Grade is ordered Robust (0) < Fragile (1) < Unusable (2). "Worse" folds two verdicts toward the more
            // severe one (the rule for a manifest, limited by its weakest record); "better" folds toward the milder one
            // (the rule for a record, as strong as its best rung, since the resolver tries the ladder until one hits).

            [[nodiscard]] Grade worse_grade(Grade lhs, Grade rhs) noexcept
            {
                return (static_cast<std::uint8_t>(lhs) >= static_cast<std::uint8_t>(rhs)) ? lhs : rhs;
            }

            [[nodiscard]] Grade better_grade(Grade lhs, Grade rhs) noexcept
            {
                return (static_cast<std::uint8_t>(lhs) <= static_cast<std::uint8_t>(rhs)) ? lhs : rhs;
            }

            // A single Critical finding forces Unusable; any Warning forces Fragile; a report with no findings is
            // Robust. There is no informational tier, so the mere presence of any finding lowers the grade.
            [[nodiscard]] Grade grade_from(const std::vector<Finding> &findings) noexcept
            {
                Grade grade = Grade::Robust;
                for (const Finding &finding : findings)
                {
                    if (finding.severity == Severity::Critical)
                    {
                        return Grade::Unusable;
                    }
                    if (finding.severity == Severity::Warning)
                    {
                        grade = Grade::Fragile;
                    }
                }
                return grade;
            }

            void add_finding(std::vector<Finding> &findings, FindingKind kind, Severity severity)
            {
                findings.push_back(Finding{kind, severity});
            }

            // Byte-selectivity model

            // Estimated selectivity of one fully-known byte, in bits. A byte drawn uniformly at random contributes 8
            // bits (one position in 256 matches). Real x64 .text is far from uniform: padding (0x00), INT3 fill (0xCC),
            // REX prefixes (0x48) and common opcode leads recur so often that pinning one of them barely narrows the
            // search. We reuse the scan engine's own frequency-class table (detail::byte_frequency_class, 0 = rare ..
            // 10 = ubiquitous) so this offline estimate anchors on the same rarity model the engine's prefilter uses,
            // then discount each class step by a fixed amount and floor the result so even the most common byte still
            // counts as some evidence. This discount is exactly what atom-rarity analysis is for: it stops a long run
            // of padding from scoring like a long run of rare bytes.
            [[nodiscard]] double fixed_byte_bits(std::uint8_t value) noexcept
            {
                constexpr double uniform_bits = 8.0;
                constexpr double bits_per_class = 0.7;
                constexpr double bits_floor = 1.0;
                const auto frequency_class = static_cast<double>(detail::byte_frequency_class(value));
                const double bits = uniform_bits - bits_per_class * frequency_class;
                return (bits < bits_floor) ? bits_floor : bits;
            }

            // Shannon entropy in bits over the distribution of fully-known byte values. A run of identical bytes has
            // near-zero entropy; a varied set approaches log2(distinct values). Computed over the fixed bytes only,
            // because nibble and wildcard positions carry no known value to distribute.
            [[nodiscard]] double shannon_entropy_bits(const std::array<std::size_t, 256> &counts,
                                                      std::size_t total) noexcept
            {
                if (total == 0)
                {
                    return 0.0;
                }
                double entropy = 0.0;
                const double denominator = static_cast<double>(total);
                for (const std::size_t count : counts)
                {
                    if (count == 0)
                    {
                        continue;
                    }
                    const double probability = static_cast<double>(count) / denominator;
                    entropy -= probability * std::log2(probability);
                }
                return entropy;
            }

            // Enum naming (local: no public stringifier exists for these)

            [[nodiscard]] std::string_view anchor_kind_name(anchor::AnchorKind kind) noexcept
            {
                switch (kind)
                {
                case anchor::AnchorKind::VtableIdentity:
                    return "VtableIdentity";
                case anchor::AnchorKind::RipGlobal:
                    return "RipGlobal";
                case anchor::AnchorKind::CodeOperand:
                    return "CodeOperand";
                case anchor::AnchorKind::StringXref:
                    return "StringXref";
                case anchor::AnchorKind::ExportName:
                    return "ExportName";
                case anchor::AnchorKind::Manual:
                    return "Manual";
                case anchor::AnchorKind::CallArgHome:
                    return "CallArgHome";
                case anchor::AnchorKind::Quorum:
                    return "Quorum";
                case anchor::AnchorKind::Unset:
                    return "Unset";
                }
                return "Unknown";
            }

            [[nodiscard]] std::string_view mode_name(scan::Mode mode) noexcept
            {
                switch (mode)
                {
                case scan::Mode::Direct:
                    return "Direct";
                case scan::Mode::RipRelative:
                    return "RipRelative";
                case scan::Mode::RttiVtable:
                    return "RttiVtable";
                case scan::Mode::StringXref:
                    return "StringXref";
                }
                return "Unknown";
            }

            // Text-anchor grading
            // Shared by the StringXref rung/record path. A mangled RTTI name is unique by construction, so an empty
            // name is the only defect worth flagging there; a string literal, by contrast, can genuinely collide when
            // it is short (the linker pools identical literals), so a length floor applies to strings but not to type
            // names.

            void grade_text_anchor(std::vector<Finding> &findings, std::size_t text_length, bool apply_length_floor,
                                   const HealthPolicy &policy)
            {
                if (text_length == 0)
                {
                    add_finding(findings, FindingKind::EmptyAnchorText, Severity::Critical);
                    return;
                }
                if (apply_length_floor && text_length < policy.min_anchor_text_bytes)
                {
                    add_finding(findings, FindingKind::ShortAnchorText, Severity::Warning);
                }
            }
        } // namespace

        PatternHealth analyze_pattern(const scan::Pattern &pattern, const HealthPolicy &policy)
        {
            PatternHealth health{};
            health.length = pattern.size();

            const std::span<const std::byte> bytes = pattern.bytes();
            const std::span<const std::byte> mask = pattern.mask();

            std::array<std::size_t, 256> value_counts{};
            std::size_t current_run = 0; // length of the fixed-byte run currently being extended
            bool any_rare_fixed = false; // a fully-known byte the engine treats as rare (frequency class 0)

            for (std::size_t index = 0; index < health.length; ++index)
            {
                const auto mask_byte = std::to_integer<std::uint8_t>(mask[index]);
                if (mask_byte == 0xFF)
                {
                    // Fully-known byte: it contributes to selectivity, to the entropy sample, to the current atom run,
                    // and to the rarity check.
                    const auto value = std::to_integer<std::uint8_t>(bytes[index]);
                    ++health.fixed_bytes;
                    ++value_counts[value];
                    ++current_run;
                    health.selectivity_bits += fixed_byte_bits(value);
                    if (detail::byte_frequency_class(value) == 0)
                    {
                        any_rare_fixed = true;
                    }
                }
                else
                {
                    // Any non-full mask ends the current atom; a half-known nibble still narrows a position by 4 bits
                    // (one hex digit in sixteen), a full wildcard by nothing.
                    if (current_run > 0)
                    {
                        ++health.atom_count;
                        if (current_run > health.longest_atom)
                        {
                            health.longest_atom = current_run;
                        }
                        current_run = 0;
                    }
                    if (mask_byte == 0x00)
                    {
                        ++health.wildcard_bytes;
                    }
                    else
                    {
                        ++health.nibble_bytes;
                        constexpr double nibble_bits = 4.0;
                        health.selectivity_bits += nibble_bits;
                    }
                }
            }
            // Close the final atom if the pattern ended inside a fixed run.
            if (current_run > 0)
            {
                ++health.atom_count;
                if (current_run > health.longest_atom)
                {
                    health.longest_atom = current_run;
                }
            }

            if (health.length > 0)
            {
                health.wildcard_ratio = static_cast<double>(health.wildcard_bytes) / static_cast<double>(health.length);
            }
            health.byte_entropy_bits = shannon_entropy_bits(value_counts, health.fixed_bytes);
            health.common_bytes_only = (health.fixed_bytes > 0) && !any_rare_fixed;

            // expected_matches models the pattern against an independent-byte haystack: each position multiplies the
            // per-position match probability, and selectivity_bits is the sum of the per-position -log2 probabilities,
            // so N * 2^(-selectivity_bits) is the expected count of matching windows. It is an order-of-magnitude
            // heuristic, not a promise -- the runtime resolver still verifies uniqueness -- but it cleanly separates a
            // few-rare-byte anchor (effectively unique) from a short or common one (thousands of hits).
            // A bounded jump multiplies the match opportunities: each of its (max_skip - min_skip + 1) widths is a
            // distinct place the following segment can sit, so a variable-gap signature is less unique than its fixed
            // bytes alone imply. Fold that widening in so health does not over-rate a gapped pattern as if its segments
            // were adjacent. A jump-free pattern keeps a multiplier of 1.
            double gap_multiplier = 1.0;
            const detail::PatternBuffer &buffer = detail::pattern_buffer(pattern);
            for (std::size_t index = 0; index < buffer.jump_count; ++index)
            {
                gap_multiplier *= static_cast<double>(buffer.jumps[index].max_skip - buffer.jumps[index].min_skip + 1);
            }
            health.expected_matches = static_cast<double>(policy.nominal_haystack_bytes) *
                                      std::exp2(-health.selectivity_bits) * gap_multiplier;

            // Findings, most structural first. A pattern with no fully-known byte cannot drive the memchr prefilter at
            // all; every other check assumes at least one fixed byte exists.
            if (health.fixed_bytes == 0)
            {
                add_finding(health.findings, FindingKind::NoFixedAnchor, Severity::Critical);
            }
            else if (health.longest_atom < policy.min_longest_atom)
            {
                add_finding(health.findings, FindingKind::ShortestAnchorRun, Severity::Warning);
            }
            if (health.length < policy.min_pattern_bytes)
            {
                add_finding(health.findings, FindingKind::ShortPattern, Severity::Warning);
            }
            if (health.common_bytes_only)
            {
                add_finding(health.findings, FindingKind::CommonBytesOnly, Severity::Warning);
            }
            if (health.wildcard_ratio > policy.max_wildcard_ratio)
            {
                add_finding(health.findings, FindingKind::HighWildcardRatio, Severity::Warning);
            }
            // Entropy is only meaningful with enough fixed bytes to distribute; a legitimately short 2-3 byte anchor is
            // not "low entropy", it simply has few samples, so gate the check on a minimum sample size.
            constexpr std::size_t min_entropy_sample = 4;
            if (health.fixed_bytes >= min_entropy_sample && health.byte_entropy_bits < policy.min_byte_entropy_bits)
            {
                add_finding(health.findings, FindingKind::LowByteEntropy, Severity::Warning);
            }
            if (health.expected_matches > policy.fail_expected_matches)
            {
                add_finding(health.findings, FindingKind::WeakSelectivity, Severity::Critical);
            }
            else if (health.expected_matches > policy.warn_expected_matches)
            {
                add_finding(health.findings, FindingKind::WeakSelectivity, Severity::Warning);
            }

            health.grade = grade_from(health.findings);
            return health;
        }

        CandidateHealth analyze_candidate(const manifest::CandidateSpec &spec, const HealthPolicy &policy)
        {
            CandidateHealth health{};
            health.mode = spec.mode;

            switch (spec.mode)
            {
            case scan::Mode::Direct:
            case scan::Mode::RipRelative:
            {
                // The file carries the AOB as text; compile it the same way the resolver will, so the analysis sees the
                // exact byte/mask the engine would. A malformed rung is a hard defect (it can never resolve), reported
                // as a finding rather than thrown, so a whole-manifest lint never aborts on one bad rung.
                const Result<scan::Pattern> compiled = scan::Pattern::compile(spec.pattern);
                if (!compiled)
                {
                    health.compiled = false;
                    add_finding(health.findings, FindingKind::UncompilablePattern, Severity::Critical);
                    break;
                }
                health.pattern = analyze_pattern(*compiled, policy);
                health.findings = health.pattern.findings;
                break;
            }
            case scan::Mode::RttiVtable:
            {
                // A mangled type name resolves unique-only through the reverse-RTTI walk, so its only failure mode as
                // an anchor is being empty; a short but valid name is still unique.
                health.anchor_text_bytes = spec.mangled.size();
                grade_text_anchor(health.findings, health.anchor_text_bytes, /*apply_length_floor=*/false, policy);
                break;
            }
            case scan::Mode::StringXref:
            {
                // A string literal can genuinely collide when short (the linker pools identical literals), so the
                // length floor applies here.
                health.anchor_text_bytes = spec.string_text.size();
                grade_text_anchor(health.findings, health.anchor_text_bytes, /*apply_length_floor=*/true, policy);
                break;
            }
            }

            health.grade = grade_from(health.findings);
            return health;
        }

        RecordHealth analyze_record(const manifest::SignatureRecord &record, const HealthPolicy &policy)
        {
            RecordHealth health{};
            health.label = record.label;
            health.kind = record.kind;

            switch (record.kind)
            {
            case anchor::AnchorKind::RipGlobal:
            case anchor::AnchorKind::CodeOperand:
            {
                // A byte backend resolves through its candidate ladder. Grade each rung, then grade the record by its
                // strongest rung: the resolver tries the ladder in order until one resolves uniquely, so a record is as
                // strong as its best tier, with the weaker fallbacks still surfaced per rung for review.
                health.ladder.reserve(record.ladder.size());
                Grade best = Grade::Robust;
                bool have_byte_estimate = false;
                for (const manifest::CandidateSpec &rung : record.ladder)
                {
                    CandidateHealth rung_health = analyze_candidate(rung, policy);
                    if (rung_health.grade == Grade::Robust)
                    {
                        ++health.robust_rungs;
                    }
                    // The strongest BYTE rung supplies the record's numeric selectivity summary; a text-tier rung has
                    // no byte estimate (its uniqueness is guaranteed by the backend, not by byte selectivity). Rank by
                    // expected_matches, which folds each rung's bounded-jump gap widening into the estimate, so the rung
                    // reported as strongest is the one that resolves most uniquely rather than the one with the most
                    // fixed bits: a wide-gap rung can carry more selectivity_bits yet expect more matches than a
                    // gap-free rung with fewer fixed bytes. selectivity_bits breaks a tie on equal expected_matches, and
                    // the first rung wins when both are equal.
                    if (rung_health.compiled &&
                        (rung.mode == scan::Mode::Direct || rung.mode == scan::Mode::RipRelative))
                    {
                        const bool stronger =
                            rung_health.pattern.expected_matches < health.best_expected_matches ||
                            (rung_health.pattern.expected_matches == health.best_expected_matches &&
                             rung_health.pattern.selectivity_bits > health.best_selectivity_bits);
                        if (!have_byte_estimate || stronger)
                        {
                            health.best_selectivity_bits = rung_health.pattern.selectivity_bits;
                            health.best_expected_matches = rung_health.pattern.expected_matches;
                            have_byte_estimate = true;
                        }
                    }
                    health.ladder.push_back(std::move(rung_health));
                }

                if (health.ladder.empty())
                {
                    // A byte backend with no rungs cannot resolve at all; the compiler would reject it
                    // (EmptyCandidates), and the linter flags the same defect on the raw record.
                    add_finding(health.findings, FindingKind::NoRobustRung, Severity::Critical);
                }
                else
                {
                    best = Grade::Unusable;
                    for (const CandidateHealth &rung : health.ladder)
                    {
                        best = better_grade(best, rung.grade);
                    }
                    if (health.robust_rungs == 0)
                    {
                        add_finding(health.findings, FindingKind::NoRobustRung, Severity::Warning);
                    }
                }
                health.grade = worse_grade(best, grade_from(health.findings));
                break;
            }
            case anchor::AnchorKind::StringXref:
            {
                health.anchor_text_bytes = record.xref_text.size();
                grade_text_anchor(health.findings, health.anchor_text_bytes, /*apply_length_floor=*/true, policy);
                health.grade = grade_from(health.findings);
                break;
            }
            case anchor::AnchorKind::VtableIdentity:
            {
                health.anchor_text_bytes = record.mangled.size();
                grade_text_anchor(health.findings, health.anchor_text_bytes, /*apply_length_floor=*/false, policy);
                health.grade = grade_from(health.findings);
                break;
            }
            case anchor::AnchorKind::ExportName:
            {
                // Grade by the export name, but WITHOUT the short-text length floor StringXref applies. An EAT lookup
                // compares an exact name within one module rather than searching image bytes for a statistically
                // selective literal, so a short name ("malloc") is not weaker than a long one; only an empty name is a
                // real defect.
                health.anchor_text_bytes = record.export_name.size();
                grade_text_anchor(health.findings, health.anchor_text_bytes, /*apply_length_floor=*/false, policy);
                health.grade = grade_from(health.findings);
                break;
            }
            case anchor::AnchorKind::Manual:
            {
                // A pinned literal has no backend and cannot self-heal across a patch; it is usable today but will go
                // stale silently, so it is Fragile by design rather than a defect.
                add_finding(health.findings, FindingKind::UnhealableManual, Severity::Warning);
                health.grade = grade_from(health.findings);
                break;
            }
            case anchor::AnchorKind::CallArgHome:
            case anchor::AnchorKind::Quorum:
            case anchor::AnchorKind::Unset:
            {
                // A Quorum composes its M voting sub-anchors by pointer and CallArgHome has no resolver, so neither can
                // be expressed as a flat file record; Unset is a record whose kind was never set. The compiler rejects
                // all three, and the linter names the same reason (a record that can never resolve as a file
                // signature).
                add_finding(health.findings, FindingKind::NonSerializableKind, Severity::Critical);
                health.grade = grade_from(health.findings);
                break;
            }
            }

            // Compilability ceiling. The per-rung analysis grades a byte record by its strongest rung, but the resolver
            // only ever sees a record Signature::compile accepts -- and compile enforces constraints the rung analysis
            // does not model: a RIP-relative rung's (displacement_at, instruction_length) layout, a RipGlobal's page
            // class, the non-serializable composite kinds. Because compile rejects the WHOLE record when any one rung
            // is malformed, a ladder whose best rung reads Robust can still be uncompilable, so grading it Robust would
            // certify a signature the trust gate could never build. Re-check compilability here so the grade cannot
            // EXCEED it: a record compile would reject is floored to Unusable however strong a rung looks in isolation.
            // compile() only ever fails a superset of what the analysis already flags Unusable (empty text or ladder,
            // an uncompilable pattern), so folding it in can only worsen a grade, never inflate one. When the grade is
            // already Unusable the specific reason is already reported, so the generic finding is suppressed to avoid
            // noise while the Unusable floor still holds.
            if (const Result<manifest::Signature> compiled = manifest::Signature::compile(record); !compiled)
            {
                if (health.grade != Grade::Unusable)
                {
                    add_finding(health.findings, FindingKind::UncompilableRecord, Severity::Critical);
                }
                health.grade = worse_grade(health.grade, Grade::Unusable);
            }

            return health;
        }

        ManifestHealth analyze_manifest(const manifest::Manifest &manifest, const HealthPolicy &policy)
        {
            ManifestHealth health{};
            health.records.reserve(manifest.records.size());
            for (const manifest::SignatureRecord &record : manifest.records)
            {
                RecordHealth record_health = analyze_record(record, policy);
                switch (record_health.grade)
                {
                case Grade::Robust:
                    ++health.robust;
                    break;
                case Grade::Fragile:
                    ++health.fragile;
                    break;
                case Grade::Unusable:
                    ++health.unusable;
                    break;
                }
                // A manifest is only as trustworthy as its weakest signature, since each gates its own feature.
                health.grade = worse_grade(health.grade, record_health.grade);
                health.records.push_back(std::move(record_health));
            }
            return health;
        }

        std::string_view to_string(Severity severity) noexcept
        {
            switch (severity)
            {
            case Severity::Warning:
                return "warning";
            case Severity::Critical:
                return "critical";
            }
            return "unknown";
        }

        std::string_view to_string(FindingKind kind) noexcept
        {
            switch (kind)
            {
            case FindingKind::NoFixedAnchor:
                return "no fully-known byte to anchor on (masked compare at every position)";
            case FindingKind::UncompilablePattern:
                return "the AOB pattern failed to compile";
            case FindingKind::ShortPattern:
                return "pattern shorter than the recommended byte floor";
            case FindingKind::ShortestAnchorRun:
                return "longest fully-known byte run is short (weak prefilter atom)";
            case FindingKind::CommonBytesOnly:
                return "every fully-known byte is a common opcode or padding (low atom rarity)";
            case FindingKind::HighWildcardRatio:
                return "wildcards dominate the pattern";
            case FindingKind::LowByteEntropy:
                return "fully-known bytes are repetitive (low entropy)";
            case FindingKind::WeakSelectivity:
                return "high estimated false-match count (weak selectivity)";
            case FindingKind::EmptyAnchorText:
                return "the anchor string or mangled name is empty";
            case FindingKind::ShortAnchorText:
                return "the anchor string is short and may not be unique";
            case FindingKind::UnhealableManual:
                return "a pinned Manual literal cannot self-heal across a patch";
            case FindingKind::NonSerializableKind:
                return "the record kind is not file-serializable (Quorum / CallArgHome / Unset)";
            case FindingKind::NoRobustRung:
                return "no candidate rung graded Robust";
            case FindingKind::UncompilableRecord:
                return "the record does not compile as a signature (bad rung layout, page class, or kind)";
            }
            return "unknown finding";
        }

        std::string_view to_string(Grade grade) noexcept
        {
            switch (grade)
            {
            case Grade::Robust:
                return "Robust";
            case Grade::Fragile:
                return "Fragile";
            case Grade::Unusable:
                return "Unusable";
            }
            return "Unknown";
        }

        namespace
        {
            // Appends "  [severity] description\n" for each finding into an existing report body.
            void append_findings(std::string &out, const std::vector<Finding> &findings)
            {
                for (const Finding &finding : findings)
                {
                    out += std::format("  [{}] {}\n", to_string(finding.severity), to_string(finding.kind));
                }
            }
        } // namespace

        std::string format_report(const PatternHealth &health, std::string_view label)
        {
            std::string out;
            if (!label.empty())
            {
                out += std::format("{}: ", label);
            }
            out += std::format("{}\n", to_string(health.grade));
            out += std::format("  bytes={} fixed={} nibble={} wildcard={} (wildcard {:.0f}%)\n", health.length,
                               health.fixed_bytes, health.nibble_bytes, health.wildcard_bytes,
                               health.wildcard_ratio * 100.0);
            out +=
                std::format("  atoms={} longest_atom={} entropy={:.1f} bits selectivity={:.1f} bits\n",
                            health.atom_count, health.longest_atom, health.byte_entropy_bits, health.selectivity_bits);
            out += std::format("  expected_matches~={:.3g}\n", health.expected_matches);
            append_findings(out, health.findings);
            return out;
        }

        std::string format_report(const RecordHealth &health)
        {
            std::string out = std::format("[{}] kind={} grade={}\n", health.label, anchor_kind_name(health.kind),
                                          to_string(health.grade));
            if (!health.ladder.empty())
            {
                out += std::format("  ladder: {} rungs, {} robust; strongest byte rung selectivity={:.1f} bits, "
                                   "expected_matches~={:.3g}\n",
                                   health.ladder.size(), health.robust_rungs, health.best_selectivity_bits,
                                   health.best_expected_matches);
                for (std::size_t index = 0; index < health.ladder.size(); ++index)
                {
                    const CandidateHealth &rung = health.ladder[index];
                    out += std::format("  rung {} ({}): {}\n", index, mode_name(rung.mode), to_string(rung.grade));
                    append_findings(out, rung.findings);
                }
            }
            else if (health.anchor_text_bytes > 0)
            {
                out += std::format("  anchor text: {} bytes\n", health.anchor_text_bytes);
            }
            append_findings(out, health.findings);
            return out;
        }

        std::string format_report(const ManifestHealth &health)
        {
            std::string out =
                std::format("manifest health: {} ({} robust, {} fragile, {} unusable of {})\n", to_string(health.grade),
                            health.robust, health.fragile, health.unusable, health.records.size());
            for (const RecordHealth &record : health.records)
            {
                out += format_report(record);
            }
            return out;
        }
    } // namespace sighealth
} // namespace DetourModKit
