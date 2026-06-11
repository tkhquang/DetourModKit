/**
 * @file rtti_dissect.cpp
 * @brief Reverse-direction RTTI dissection and self-healing offset resolvers.
 *
 * Builds four layers on top of the verified COL prelude shared with rtti.cpp:
 *   L1 identify_pointee_type  -- reverse-identify the object behind one slot.
 *   L2 reverse_scan_block     -- RTTI-label a block of slots (tooling).
 *   L3 heal_landmark/offset   -- self-heal one field offset after a patch.
 *   L4 solve_fingerprint      -- recover one uniform shift across many fields.
 *
 * Every entry point is noexcept and fails closed. The hot self-heal path allocates nothing (it reuses one stack
 * PointeeType); only the explicitly tooling-only block scanner grows a vector. All reads go through the same
 * SEH-guarded, module-bound-checked prelude the forward walker uses, so an unmapped page or forged COL is a clean
 * non-match, never a fault. Matching is byte-exact on the MSVC most-derived mangled name (no UnDecorateSymbolName).
 */

#include "DetourModKit/rtti_dissect.hpp"
#include "DetourModKit/memory.hpp"

#include "rtti_internal.hpp"

#include <cstdint>

namespace DetourModKit
{
    namespace
    {
        /**
         * @brief Soft policy filter: does a resolved slot's shape satisfy the landmark's required indirection?
         * @details Indirection::Any accepts either shape; the other two pin the slot to the pointer-to-object or
         *          direct-object form. This is a policy-layer decision deliberately kept out of L1 so a consumer can
         *          record Any when capture and heal may straddle a
         *          DLL boundary.
         */
        [[nodiscard]] bool shape_ok(bool was_pointer, Rtti::Indirection ind) noexcept
        {
            switch (ind)
            {
            case Rtti::Indirection::Any:
                return true;
            case Rtti::Indirection::PointerToObject:
                return was_pointer;
            case Rtti::Indirection::ObjectBase:
                return !was_pointer;
            }
            return false;
        }

        /**
         * @brief Probe one slot: resolve, check shape, byte-exact name match.
         * @details Fills @p pt whenever the slot resolves (so the caller can read the match details), and reports
         *          whether it also passed the shape filter and the exact mangled-name compare. The name compare reuses
         *          the same semantics as vtable_is_type: a superstring or a differing byte fails.
         * @return true only on a full resolve + shape + exact-name match.
         */
        [[nodiscard]] bool slot_matches(std::uintptr_t addr, const Rtti::Landmark &lm, Rtti::PointeeType &pt) noexcept
        {
            if (!Rtti::identify_pointee_type(addr, pt))
                return false;
            if (!shape_ok(pt.was_pointer, lm.indirection))
                return false;
            return pt.name() == lm.expected_mangled;
        }

        /**
         * @brief Builds a HealHit from a matched slot.
         * @details healed_offset is the field's offset within the struct base (slot_addr - base), the value a consumer
         *          feeds straight into a pointer chain. It equals nominal_offset when the layout did not drift and
         *          nominal_offset +/- delta after a shift.
         */
        [[nodiscard]] Rtti::HealHit make_hit(std::uintptr_t slot_addr, std::uintptr_t base,
                                             const Rtti::PointeeType &pt) noexcept
        {
            Rtti::HealHit h;
            h.healed_offset = static_cast<std::ptrdiff_t>(slot_addr - base);
            h.slot_addr = slot_addr;
            h.object_addr = pt.object_base;
            h.vtable = pt.vtable;
            h.was_pointer = pt.was_pointer;
            return h;
        }

        /**
         * @brief Validates a landmark's type/shape descriptor fields.
         * @details Shared by heal_landmark and solve_fingerprint. Does not touch @ref Rtti::Landmark::base or @ref
         *          Rtti::Landmark::window, which the two callers validate differently.
         * @return true when expected_mangled is a sane length and indirection is a known enumerator.
         */
        [[nodiscard]] bool descriptor_ok(const Rtti::Landmark &lm) noexcept
        {
            if (lm.expected_mangled.empty() || lm.expected_mangled.size() >= Rtti::MAX_TYPE_NAME_LEN)
                return false;
            switch (lm.indirection)
            {
            case Rtti::Indirection::PointerToObject:
            case Rtti::Indirection::ObjectBase:
            case Rtti::Indirection::Any:
                return true;
            }
            return false;
        }
    } // anonymous namespace

    bool Rtti::identify_pointee_type(std::uintptr_t slot_addr, PointeeType &out) noexcept
    {
        if (slot_addr < detail::MIN_VALID_PTR)
            return false;

        const auto slot_opt = Memory::seh_read<std::uintptr_t>(slot_addr);
        if (!slot_opt || *slot_opt < detail::MIN_VALID_PTR)
            return false;
        const std::uintptr_t slot_val = *slot_opt;

        detail::ColSite site;
        bool was_pointer = false;
        std::uintptr_t object_base = 0;
        std::uintptr_t vtable = 0;

        // Pointer-to-object first: treat slot_val as a pointer to an object and try to resolve the pointee's vtable
        // (*slot_val). A direct object would read its own first vtable entry here, which practically never satisfies
        // the COL signature + pSelf cross-check, so this ordering does not misclassify real direct objects.
        const auto vt2_opt = Memory::seh_read<std::uintptr_t>(slot_val);
        if (vt2_opt && *vt2_opt >= detail::MIN_VALID_PTR && detail::resolve_col_site(*vt2_opt, site))
        {
            was_pointer = true;
            object_base = slot_val;
            vtable = *vt2_opt;
        }
        // Else direct object base: the slot itself is the object, its value is the vtable. Pinned to ground truth: the
        // object base is the slot
        // ADDRESS, the vtable is the value READ at it (not a second deref).
        else if (detail::resolve_col_site(slot_val, site))
        {
            was_pointer = false;
            object_base = slot_addr;
            vtable = slot_val;
        }
        else
        {
            return false;
        }

        // Read the name into the output buffer through the same page-bounded copy the forward walker uses. A faulted or
        // empty name is a non-resolution.
        const std::size_t name_len = detail::read_name_seh(site.name_addr, out.name_buf, sizeof(out.name_buf));
        if (name_len == 0)
            return false;

        out.vtable = vtable;
        out.col_addr = site.col_addr;
        out.td_addr = site.td_addr;
        out.name_addr = site.name_addr;
        out.object_base = object_base;
        out.col_offset = site.col_offset;
        out.pointer_value = slot_val;
        out.was_pointer = was_pointer;
        out.name_len = static_cast<std::uint16_t>(name_len);

        // Complete object with underflow clamp: a garbage or forged col_offset larger than object_base must not wrap
        // the address; report object_base itself in that (non-physical) case.
        out.complete_obj = (object_base < site.col_offset) ? object_base : object_base - site.col_offset;
        return true;
    }

    std::size_t Rtti::reverse_scan_block(std::uintptr_t start, std::size_t slot_count, std::vector<LabeledSlot> &out,
                                         std::size_t stride) noexcept
    {
        if (start < detail::MIN_VALID_PTR || slot_count == 0)
            return 0;
        if (stride == 0)
            stride = sizeof(std::uintptr_t);

        // Overflow guard mirroring find_in_pointer_table: reject a span that overflows size_t or wraps the address
        // space.
        if (slot_count > SIZE_MAX / stride)
            return 0;
        const std::uintptr_t span = static_cast<std::uintptr_t>(slot_count * stride);
        if (start + span < start)
            return 0;

        std::size_t added = 0;
        PointeeType pt;
        for (std::size_t i = 0; i < slot_count; ++i)
        {
            const std::uintptr_t slot_addr = start + i * stride;
            if (!identify_pointee_type(slot_addr, pt))
                continue;
            try
            {
                out.push_back(LabeledSlot{slot_addr, i, pt});
            }
            catch (...)
            {
                // A reallocation failure must not escape the noexcept boundary;
                // stop and report the slots already appended.
                return added;
            }
            ++added;
        }
        return added;
    }

    std::size_t Rtti::reverse_scan_block_bytes(std::uintptr_t start, std::size_t byte_len,
                                               std::vector<LabeledSlot> &out, std::size_t stride) noexcept
    {
        if (stride == 0)
            stride = sizeof(std::uintptr_t);
        return reverse_scan_block(start, byte_len / stride, out, stride);
    }

    std::expected<Rtti::HealHit, Rtti::HealError> Rtti::heal_landmark(const Landmark &lm) noexcept
    {
        // 1. Descriptor validation. Every check below touches no memory.
        if (lm.base < detail::MIN_VALID_PTR)
            return std::unexpected(HealError::BadDescriptor);
        if (!descriptor_ok(lm))
            return std::unexpected(HealError::BadDescriptor);
        if (lm.window > MAX_HEAL_WINDOW)
            return std::unexpected(HealError::BadDescriptor);
        const std::size_t stride = (lm.stride == 0) ? sizeof(std::uintptr_t) : lm.stride;

        // 2. Single bounds computation. Unsigned arithmetic is wrap-defined; a
        //    nominal_offset that wraps the address space or lands outside the
        //    canonical user-mode window is rejected here, before any read. With
        //    a validated nominal_slot (>= MIN_VALID_PTR) and window <= MAX_HEAL_WINDOW
        //    (4096) << MIN_VALID_PTR (0x10000), the lo/hi derivations below
        //    cannot themselves underflow or wrap.
        const std::uintptr_t nominal_slot = lm.base + static_cast<std::uintptr_t>(lm.nominal_offset);
        if (!Memory::plausible_userspace_ptr(nominal_slot))
            return std::unexpected(HealError::BadDescriptor);
        std::uintptr_t lo = nominal_slot - lm.window;
        if (lo < detail::MIN_VALID_PTR)
            lo = detail::MIN_VALID_PTR;
        const std::uintptr_t hi = nominal_slot + lm.window;

        PointeeType pt;

        // 3. Nominal slot first. An exact-offset match short-circuits before the
        //    window scan, so an unchanged offset -- or a same-typed neighbour in
        //    the window -- never reaches the ambiguity test.
        if (slot_matches(nominal_slot, lm, pt))
            return make_hit(nominal_slot, lm.base, pt);

        // 4. Widened grid scan, nearest distance first. Candidate slots are
        //    congruent to nominal_slot modulo stride, so every probe stays pointer-aligned
        //    to the nominal slot. At each distance ring the -d and +d slots are
        //    both evaluated before deciding, so an equidistant tie is detected
        //    rather than silently resolved to one side.
        for (std::size_t k = 1;; ++k)
        {
            const std::size_t step = k * stride;
            const bool minus_in = step <= (nominal_slot - lo);
            const bool plus_in = step <= (hi - nominal_slot);
            if (!minus_in && !plus_in)
                break;

            bool minus_match = false;
            HealHit minus_hit{};
            if (minus_in && slot_matches(nominal_slot - step, lm, pt))
            {
                minus_match = true;
                minus_hit = make_hit(nominal_slot - step, lm.base, pt);
            }

            bool plus_match = false;
            HealHit plus_hit{};
            if (plus_in && slot_matches(nominal_slot + step, lm, pt))
            {
                plus_match = true;
                plus_hit = make_hit(nominal_slot + step, lm.base, pt);
            }

            // A uniquely nearest match heals; an equidistant +d/-d pair is the irreducible ambiguity and fails closed.
            if (minus_match && plus_match)
                return std::unexpected(HealError::Ambiguous);
            if (minus_match)
                return minus_hit;
            if (plus_match)
                return plus_hit;
        }

        return std::unexpected(HealError::NoMatch);
    }

    std::optional<std::ptrdiff_t> Rtti::heal_offset(const Landmark &lm) noexcept
    {
        const auto result = heal_landmark(lm);
        if (!result)
            return std::nullopt;
        return result->healed_offset;
    }

    std::string_view Rtti::heal_error_to_string(HealError error) noexcept
    {
        switch (error)
        {
        case HealError::BadDescriptor:
            return "Landmark descriptor is invalid";
        case HealError::NoMatch:
            return "No slot in the window resolved to the expected type";
        case HealError::Ambiguous:
            return "Equidistant slots both match; offset is ambiguous";
        }
        return "Unknown heal error";
    }

    std::expected<Rtti::FingerprintHit, Rtti::HealError>
    Rtti::solve_fingerprint(std::uintptr_t base, std::span<const Landmark> fp, std::size_t window_bytes) noexcept
    {
        // Validation. No memory is touched until a delta is probed below.
        if (base < detail::MIN_VALID_PTR)
            return std::unexpected(HealError::BadDescriptor);
        if (fp.empty() || fp.size() > MAX_FINGERPRINT_LANDMARKS)
            return std::unexpected(HealError::BadDescriptor);
        if (window_bytes > MAX_HEAL_WINDOW)
            return std::unexpected(HealError::BadDescriptor);

        std::size_t required_count = 0;
        for (const Landmark &lm : fp)
        {
            if (!descriptor_ok(lm))
                return std::unexpected(HealError::BadDescriptor);
            if (lm.required)
                ++required_count;
        }
        // A template with no required landmark cannot fail closed against a dense region, so it is rejected rather than
        // guessed.
        if (required_count == 0)
            return std::unexpected(HealError::BadDescriptor);

        // Enumerate uniform deltas in [-window, +window] stepping by pointer size (real-world layout shifts are
        // pointer-granular). A delta is a candidate only when it satisfies EVERY required landmark; among candidates
        // the most optional hits wins, and a tie at the top latches
        // Ambiguous (fail closed).
        constexpr std::ptrdiff_t step = static_cast<std::ptrdiff_t>(sizeof(std::uintptr_t));
        const std::ptrdiff_t w = static_cast<std::ptrdiff_t>(window_bytes);

        PointeeType pt;
        bool have_best = false;
        bool tie = false;
        std::ptrdiff_t best_delta = 0;
        std::size_t best_optional = 0;

        const auto eval_delta = [&](std::ptrdiff_t delta) noexcept
        {
            std::size_t opt_hits = 0;
            for (const Landmark &lm : fp)
            {
                const std::uintptr_t addr =
                    base + static_cast<std::uintptr_t>(lm.nominal_offset) + static_cast<std::uintptr_t>(delta);
                const bool ok = Memory::plausible_userspace_ptr(addr) && slot_matches(addr, lm, pt);
                if (lm.required)
                {
                    // A missing required landmark disqualifies this delta outright; abandon it without scoring the
                    // rest.
                    if (!ok)
                        return;
                }
                else if (ok)
                {
                    ++opt_hits;
                }
            }

            // Every required landmark matched: this delta is a candidate.
            if (!have_best || opt_hits > best_optional)
            {
                have_best = true;
                best_optional = opt_hits;
                best_delta = delta;
                tie = false;
            }
            else if (opt_hits == best_optional)
            {
                tie = true;
            }
        };

        // Iterate magnitudes 0, +step, -step, +2*step, ... so the scan is nearest-first; the decision itself is
        // score-based, not distance-based.
        for (std::ptrdiff_t m = 0; m <= w; m += step)
        {
            eval_delta(m);
            if (m != 0)
                eval_delta(-m);
        }

        if (!have_best)
            return std::unexpected(HealError::NoMatch);
        if (tie)
            return std::unexpected(HealError::Ambiguous);
        return FingerprintHit{best_delta, required_count, best_optional};
    }

    std::size_t Rtti::heal_report(std::span<const Landmark> landmarks, std::span<DriftEntry> out) noexcept
    {
        const std::size_t written = (landmarks.size() < out.size()) ? landmarks.size() : out.size();
        for (std::size_t i = 0; i < written; ++i)
        {
            const Landmark &landmark = landmarks[i];
            DriftEntry &entry = out[i];
            // Start from a clean entry so a failed heal cannot expose stale healed_offset/delta from a reused
            // (non-zeroed) output buffer.
            entry = DriftEntry{};
            entry.name = landmark.expected_mangled;
            entry.nominal_offset = landmark.nominal_offset;

            const auto heal = heal_landmark(landmark);
            if (heal)
            {
                entry.ok = true;
                entry.healed_offset = heal->healed_offset;
                // delta is the realised layout shift: 0 when the field did not move, signed when it did. It is the
                // headline number a changelog wants, derived purely from the existing heal result.
                entry.delta = heal->healed_offset - landmark.nominal_offset;
            }
            else
            {
                // ok stays false; healed_offset and delta stay 0 (valid only when ok).
                entry.error = heal.error();
            }
        }
        return written;
    }
} // namespace DetourModKit
