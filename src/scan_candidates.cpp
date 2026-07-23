/**
 * @file scan_candidates.cpp
 * @brief The candidate-ladder vocabulary functions: order_candidates() and borrow().
 * @details The Candidate factories and accessors are inline in scan.hpp (the variant payload model), so this TU owns
 *          only the ordering permutation and the borrowed-request packer. order_candidates is pure index math over the
 *          variant tiers; borrow packs the borrowed views into a ScanRequest. Both are noexcept and allocate nothing.
 */

#include "DetourModKit/scan.hpp"

#include <algorithm>
#include <cstddef>
#include <span>

namespace DetourModKit
{
    namespace scan
    {
        std::size_t order_candidates(CandidateOrder order, std::span<const Candidate> ladder,
                                     std::span<std::size_t> out) noexcept
        {
            const std::size_t count = std::min(ladder.size(), out.size());
            // This noexcept helper cannot report InvalidArg, so an unknown value preserves declaration order and never
            // selects the UniqueFirst promotion.
            if (order != CandidateOrder::UniqueFirst)
            {
                for (std::size_t i = 0; i < count; ++i)
                {
                    out[i] = i;
                }
                return count;
            }

            // UniqueFirst: three stable passes over the declared order. Every candidate falls into exactly one pass, so
            // the result is a permutation of [0, count).
            std::size_t written = 0;
            const auto emit = [&](auto predicate)
            {
                for (std::size_t i = 0; i < ladder.size() && written < count; ++i)
                {
                    if (predicate(ladder[i]))
                    {
                        out[written] = i;
                        ++written;
                    }
                }
            };
            const auto is_byte_mode = [](const Candidate &candidate)
            { return candidate.mode() == Mode::Direct || candidate.mode() == Mode::RipRelative; };
            const auto is_anchored_byte = [&](const Candidate &candidate)
            {
                // A byte tier (Direct / RipRelative) whose compiled Pattern carries a fully-known rarest byte the
                // prefilter can anchor on; that makes the scan far more selective than a wildcard-led pattern.
                if (const DirectPattern *direct = candidate.as_direct())
                {
                    return direct->pattern.has_anchor();
                }
                if (const RipRelativePattern *rip = candidate.as_rip_relative())
                {
                    return rip->pattern.has_anchor();
                }
                return false;
            };

            // Pass 1: the unique-only text tiers, which fail closed on ambiguity by construction.
            emit([](const Candidate &candidate)
                 { return candidate.mode() == Mode::RttiVtable || candidate.mode() == Mode::StringXref; });
            // Pass 2: anchored byte patterns (a fully-known rarest byte makes the scan far more selective).
            emit([&](const Candidate &candidate) { return is_anchored_byte(candidate); });
            // Pass 3: the remaining byte patterns (no fully-known byte to anchor on).
            emit([&](const Candidate &candidate) { return is_byte_mode(candidate) && !is_anchored_byte(candidate); });
            return written;
        }

        ScanRequest borrow(std::span<const Candidate> ladder, std::string_view label, Region scope,
                           FallbackPolicy fallback_policy, FallbackWitness fallback_witness, bool require_unique,
                           CandidateOrder order, Pages pages) noexcept
        {
            return ScanRequest{
                .ladder = ladder,
                .label = label,
                .scope = scope,
                .fallback_policy = fallback_policy,
                .fallback_witness = fallback_witness,
                .require_unique = require_unique,
                .order = order,
                .pages = pages,
            };
        }

        ScanRequest borrow_code_target(std::span<const Candidate> ladder, std::string_view label, Region scope,
                                       FallbackPolicy fallback_policy, FallbackWitness fallback_witness) noexcept
        {
            // The code-target policy: scan only executable pages (an instruction signature must not alias a byte run in
            // data), promote the unique-only / anchored tiers first, and enable hooked-prologue recovery so a target
            // another mod already inline-hooked is still resolved. The recovery strictness comes from the caller
            // (WarnOnly by default, RequireIdentity + a witness to fail closed on an unconfirmed near-twin).
            // require_unique stays true. Route through borrow() so the common ScanRequest fields are defined in one
            // place, then require its final address to be execute-readable too: a RipRelative candidate can match code
            // bytes but resolve its disp32 to data, and text tiers do not use the byte-page filter at all.
            ScanRequest request = borrow(ladder, label, scope, fallback_policy, fallback_witness,
                                         /*require_unique=*/true, CandidateOrder::UniqueFirst, Pages::Executable);
            request.require_executable_result = true;
            return request;
        }

        ScanRequest borrow_code_target_strict(std::span<const Candidate> ladder, std::string_view label,
                                              FallbackWitness fallback_witness, Region scope) noexcept
        {
            // The strict code-target policy: identical to borrow_code_target but pinned to RequireIdentity, so a
            // hooked-prologue recovery is trusted only when the witness confirms it and a coincidental near-twin fails
            // closed. The witness is mandatory at the call site (a non-defaulted parameter), so RequireIdentity always
            // has something to confirm with -- without one it degenerates to failing closed on every recovery. Route
            // through borrow_code_target so the shared code-target fields (Pages::Executable,
            // require_executable_result, UniqueFirst, require_unique) live in exactly one place.
            return borrow_code_target(ladder, label, scope, FallbackPolicy::RequireIdentity, fallback_witness);
        }
    } // namespace scan
} // namespace DetourModKit
