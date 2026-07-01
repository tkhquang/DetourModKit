/**
 * @file rtti_dissect.cpp
 * @brief Reverse-direction RTTI dissection, self-healing offset resolvers, and the frame-scheduled heal runner.
 *
 * Builds on top of the verified COL prelude shared with rtti.cpp:
 *   L1 identify_pointee_type  -- reverse-identify the object behind one slot.
 *   L2 reverse_scan_block     -- RTTI-label a block of slots (tooling).
 *   L3 heal_landmark          -- self-heal one field offset after a patch.
 *   L4 solve_fingerprint      -- recover one uniform shift across many fields.
 *   L5 HealScheduler          -- drive the heals on a frame cadence, latch per group, warn once on real drift.
 *
 * Every L1-L4 entry point is noexcept and fails closed. The hot self-heal path allocates nothing (it reuses one stack
 * PointeeType); only the explicitly tooling-only block scanner grows a vector. All reads go through the same
 * SEH-guarded, module-bound-checked prelude the forward walker uses, so an unmapped page or forged COL is a clean
 * non-match, never a fault. Matching is byte-exact on the MSVC most-derived mangled name (no UnDecorateSymbolName).
 *
 * The public surface speaks the v4 Address vocabulary and reports failures through the unified Error/ErrorCode channel
 * (the former IdentifyError / HealError enumerators now live in the ErrorCategory::Rtti block). Address <-> integer
 * punning is confined to the raw-slot arithmetic below.
 */

#include "DetourModKit/rtti_dissect.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/memory_guarded.hpp"
#include "rtti_internal.hpp"

#include <cstdint>
#include <iterator>
#include <memory>
#include <utility>

namespace DetourModKit
{
    namespace
    {
        /**
         * @brief Soft policy filter: does a resolved slot's shape (and subobject position) satisfy the landmark's
         *        required indirection?
         * @details Indirection::Any accepts either shape; PointerToObject and ObjectBase pin the slot to the
         *          pointer-to-object or direct-object form. This is a policy-layer decision deliberately kept out
         *          of L1 so a consumer can record Any when capture and heal may straddle a DLL boundary.
         *          CompleteObject adds a subobject constraint on top of the direct-object shape, which is why
         *          @p col_offset is consulted here.
         * @param was_pointer The resolved slot's shape (PointeeType::was_pointer).
         * @param col_offset The resolved object's COL.offset (PointeeType::col_offset): 0 for the primary subobject,
         *                   nonzero for a multiple-inheritance secondary base.
         * @param ind The landmark's required indirection.
         */
        [[nodiscard]] bool shape_ok(bool was_pointer, std::uint32_t col_offset, rtti::Indirection ind) noexcept
        {
            switch (ind)
            {
            case rtti::Indirection::Any:
                return true;
            case rtti::Indirection::PointerToObject:
                return was_pointer;
            case rtti::Indirection::ObjectBase:
                return !was_pointer;
            case rtti::Indirection::CompleteObject:
                // A direct object base pinned to the most-derived (primary) subobject. Under multiple inheritance every
                // base subobject has its own vtable, and each vtable's COL names the same complete type. COL.offset
                // distinguishes those subobjects; the primary subobject has col_offset == 0, so its base is the
                // complete object. Rejecting col_offset != 0 keeps a heal from latching a secondary base's adjacent
                // vtable and reporting an offset shifted by that subobject delta.
                return !was_pointer && col_offset == 0;
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
        [[nodiscard]] bool slot_matches(std::uintptr_t addr, const rtti::Landmark &lm, rtti::PointeeType &pt) noexcept
        {
            if (!rtti::identify_pointee_type(Address{addr}, pt))
                return false;
            if (!shape_ok(pt.was_pointer, pt.col_offset, lm.indirection))
                return false;
            return pt.name() == lm.expected_mangled;
        }

        /**
         * @brief Builds a HealHit from a matched slot.
         * @details healed_offset is the field's offset within the struct base (slot_addr - base), the value a consumer
         *          feeds straight into a pointer chain. It equals nominal_offset when the layout did not drift and
         *          nominal_offset +/- delta after a shift.
         */
        [[nodiscard]] rtti::HealHit make_hit(std::uintptr_t slot_addr, std::uintptr_t base,
                                             const rtti::PointeeType &pt) noexcept
        {
            rtti::HealHit h;
            h.healed_offset = static_cast<std::ptrdiff_t>(slot_addr - base);
            h.slot_addr = Address{slot_addr};
            h.object_addr = pt.object_base;
            h.vtable = pt.vtable;
            h.col_offset = pt.col_offset;
            h.was_pointer = pt.was_pointer;
            return h;
        }

        /**
         * @brief Validates a landmark's type/shape descriptor fields.
         * @details Shared by heal_from and solve_fingerprint. Does not touch @ref rtti::Landmark::base or @ref
         *          rtti::Landmark::window, which the two callers validate differently.
         * @return true when expected_mangled is a sane length and indirection is a known enumerator.
         */
        [[nodiscard]] bool descriptor_ok(const rtti::Landmark &lm) noexcept
        {
            if (lm.expected_mangled.empty() || lm.expected_mangled.size() >= rtti::MAX_TYPE_NAME_LEN)
                return false;
            switch (lm.indirection)
            {
            case rtti::Indirection::PointerToObject:
            case rtti::Indirection::ObjectBase:
            case rtti::Indirection::CompleteObject:
            case rtti::Indirection::Any:
                return true;
            }
            return false;
        }

        /**
         * @brief Self-heal engine shared by heal_landmark and HealRun::heal_into.
         * @details Takes the struct @p base explicitly (rather than reading @c lm.base) so a scheduler can heal
         *          from a per-frame live base without copying the landmark. Otherwise identical to the documented
         *          heal_landmark contract: nominal short-circuit, nearest-first widened grid, equidistant tie ->
         *          HealAmbiguous, exhausted window -> HealNoMatch, malformed descriptor -> BadDescriptor.
         */
        [[nodiscard]] Result<rtti::HealHit> heal_from(const rtti::Landmark &lm, Address base) noexcept
        {
            // 1. Descriptor validation. Every check below touches no memory.
            if (base.raw() < rtti::detail::MIN_VALID_PTR)
                return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::heal_landmark", base.raw()});
            if (!descriptor_ok(lm))
                return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::heal_landmark"});
            if (lm.window > rtti::MAX_HEAL_WINDOW)
                return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::heal_landmark"});
            const std::size_t stride = (lm.stride == 0) ? sizeof(std::uintptr_t) : lm.stride;

            // 2. Single bounds computation. Unsigned arithmetic is wrap-defined; a
            //    nominal_offset that wraps the address space or lands outside the
            //    canonical user-mode window is rejected here, before any read. With
            //    a validated nominal_slot (>= MIN_VALID_PTR) and window <= MAX_HEAL_WINDOW
            //    (4096) << MIN_VALID_PTR (0x10000), the lo/hi derivations below
            //    cannot themselves underflow or wrap.
            const std::uintptr_t nominal_slot = base.raw() + static_cast<std::uintptr_t>(lm.nominal_offset);
            if (!DetourModKit::detail::is_plausible_ptr(nominal_slot))
                return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::heal_landmark", nominal_slot});
            std::uintptr_t lo = nominal_slot - lm.window;
            if (lo < rtti::detail::MIN_VALID_PTR)
                lo = rtti::detail::MIN_VALID_PTR;
            const std::uintptr_t hi = nominal_slot + lm.window;

            rtti::PointeeType pt;

            // 3. Nominal slot first. An exact-offset match short-circuits before the
            //    window scan, so an unchanged offset -- or a same-typed neighbour in
            //    the window -- never reaches the ambiguity test.
            if (slot_matches(nominal_slot, lm, pt))
                return make_hit(nominal_slot, base.raw(), pt);

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
                rtti::HealHit minus_hit{};
                if (minus_in && slot_matches(nominal_slot - step, lm, pt))
                {
                    minus_match = true;
                    minus_hit = make_hit(nominal_slot - step, base.raw(), pt);
                }

                bool plus_match = false;
                rtti::HealHit plus_hit{};
                if (plus_in && slot_matches(nominal_slot + step, lm, pt))
                {
                    plus_match = true;
                    plus_hit = make_hit(nominal_slot + step, base.raw(), pt);
                }

                // A uniquely nearest match heals; an equidistant +d/-d pair is the irreducible ambiguity and fails
                // closed.
                if (minus_match && plus_match)
                    return std::unexpected(Error{ErrorCode::HealAmbiguous, "rtti::heal_landmark", nominal_slot});
                if (minus_match)
                    return minus_hit;
                if (plus_match)
                    return plus_hit;
            }

            return std::unexpected(Error{ErrorCode::HealNoMatch, "rtti::heal_landmark", nominal_slot});
        }
    } // anonymous namespace

    Result<void> rtti::identify_pointee_typed(Address slot_addr, PointeeType &out) noexcept
    {
        if (slot_addr.raw() < detail::MIN_VALID_PTR)
            return std::unexpected(Error{ErrorCode::BadSlotAddress, "rtti::identify_pointee", slot_addr.raw()});

        const auto slot_opt = DetourModKit::detail::guarded_read<std::uintptr_t>(slot_addr.raw());
        if (!slot_opt || *slot_opt < detail::MIN_VALID_PTR)
            return std::unexpected(Error{ErrorCode::UnreadableSlot, "rtti::identify_pointee", slot_addr.raw()});
        const std::uintptr_t slot_val = *slot_opt;

        detail::ColSite site;
        bool was_pointer = false;
        std::uintptr_t object_base = 0;
        std::uintptr_t vtable = 0;

        // Pointer-to-object first: treat slot_val as a pointer to an object and try to resolve the pointee's vtable
        // (*slot_val). A direct object would read its own first vtable entry here, which practically never satisfies
        // the COL signature + pSelf cross-check, so this ordering does not misclassify real direct objects.
        const auto vt2_opt = DetourModKit::detail::guarded_read<std::uintptr_t>(slot_val);
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
            object_base = slot_addr.raw();
            vtable = slot_val;
        }
        else
        {
            return std::unexpected(Error{ErrorCode::NoRtti, "rtti::identify_pointee", slot_addr.raw()});
        }

        // Read the name into the output buffer through the same page-bounded copy the forward walker uses. A faulted or
        // empty name is a non-resolution.
        const std::size_t name_len = detail::read_name_seh(site.name_addr, out.name_buf, sizeof(out.name_buf));
        if (name_len == 0)
            return std::unexpected(Error{ErrorCode::NoRtti, "rtti::identify_pointee", slot_addr.raw()});

        out.vtable = Address{vtable};
        out.col_addr = Address{site.col_addr};
        out.td_addr = Address{site.td_addr};
        out.name_addr = Address{site.name_addr};
        out.object_base = Address{object_base};
        out.col_offset = site.col_offset;
        out.pointer_value = Address{slot_val};
        out.was_pointer = was_pointer;
        out.name_len = static_cast<std::uint16_t>(name_len);

        // Complete object with underflow clamp: a garbage or forged col_offset larger than object_base must not wrap
        // the address; report object_base itself in that (non-physical) case.
        out.complete_obj = Address{(object_base < site.col_offset) ? object_base : object_base - site.col_offset};
        return {};
    }

    bool rtti::identify_pointee_type(Address slot_addr, PointeeType &out) noexcept
    {
        // The bool primitive is exactly has_value() over the typed core: one probe, one prelude walk, one
        // implementation. Callers that need the WHY of a miss use identify_pointee_typed / identify_pointee_type_or.
        return identify_pointee_typed(slot_addr, out).has_value();
    }

    std::size_t rtti::reverse_scan_block(Address start, std::size_t slot_count, std::vector<LabeledSlot> &out,
                                         std::size_t stride) noexcept
    {
        if (start.raw() < detail::MIN_VALID_PTR || slot_count == 0)
            return 0;
        if (stride == 0)
            stride = sizeof(std::uintptr_t);

        // Overflow guard mirroring find_in_pointer_table: reject a span that overflows size_t or wraps the address
        // space.
        if (slot_count > SIZE_MAX / stride)
            return 0;
        const std::uintptr_t start_raw = start.raw();
        const std::uintptr_t span = static_cast<std::uintptr_t>(slot_count * stride);
        if (start_raw + span < start_raw)
            return 0;

        std::size_t added = 0;
        PointeeType pt;
        for (std::size_t i = 0; i < slot_count; ++i)
        {
            const std::uintptr_t slot_addr = start_raw + i * stride;
            if (!identify_pointee_type(Address{slot_addr}, pt))
                continue;
            try
            {
                out.push_back(LabeledSlot{Address{slot_addr}, i, pt});
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

    std::size_t rtti::reverse_scan_block_bytes(Address start, std::size_t byte_len, std::vector<LabeledSlot> &out,
                                               std::size_t stride) noexcept
    {
        if (stride == 0)
            stride = sizeof(std::uintptr_t);
        return reverse_scan_block(start, byte_len / stride, out, stride);
    }

    Result<rtti::HealHit> rtti::heal_landmark(const Landmark &lm) noexcept
    {
        return heal_from(lm, lm.base);
    }

    Result<rtti::FingerprintHit> rtti::solve_fingerprint(Address base, std::span<const Landmark> fp,
                                                         std::size_t window_bytes) noexcept
    {
        // Validation. No memory is touched until a delta is probed below.
        if (base.raw() < detail::MIN_VALID_PTR)
            return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::solve_fingerprint", base.raw()});
        if (fp.empty() || fp.size() > MAX_FINGERPRINT_LANDMARKS)
            return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::solve_fingerprint"});
        if (window_bytes > MAX_HEAL_WINDOW)
            return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::solve_fingerprint"});

        std::size_t required_count = 0;
        for (std::size_t i = 0; i < fp.size(); ++i)
        {
            if (!descriptor_ok(fp[i]))
                return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::solve_fingerprint"});
            for (std::size_t j = 0; j < i; ++j)
            {
                if (fp[j].nominal_offset == fp[i].nominal_offset)
                    return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::solve_fingerprint"});
            }
            if (fp[i].required)
                ++required_count;
        }
        // A template with no required landmark cannot fail closed against a dense region, so it is rejected rather than
        // guessed.
        if (required_count == 0)
            return std::unexpected(Error{ErrorCode::BadDescriptor, "rtti::solve_fingerprint"});

        // Enumerate uniform deltas in [-window, +window] stepping by pointer size (real-world layout shifts are
        // pointer-granular). A delta is a candidate only when it satisfies EVERY required landmark; among candidates
        // the most optional hits wins, and a tie at the top latches
        // HealAmbiguous (fail closed).
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
                    base.raw() + static_cast<std::uintptr_t>(lm.nominal_offset) + static_cast<std::uintptr_t>(delta);
                const bool ok = DetourModKit::detail::is_plausible_ptr(addr) && slot_matches(addr, lm, pt);
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
            return std::unexpected(Error{ErrorCode::HealNoMatch, "rtti::solve_fingerprint", base.raw()});
        if (tie)
            return std::unexpected(Error{ErrorCode::HealAmbiguous, "rtti::solve_fingerprint", base.raw()});
        return FingerprintHit{best_delta, required_count, best_optional};
    }

    std::size_t rtti::heal_report(std::span<const Landmark> landmarks, std::span<DriftEntry> out) noexcept
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
                entry.error = heal.error().code;
            }
        }
        return written;
    }

    // --- HealScheduler / HealRun -------------------------------------------------------------------------------------

    struct rtti::HealScheduler::Impl
    {
        // One independently-latched heal group: its own retry countdown and its own success latch, so a group whose
        // target comes up late retries on the interval without freezing any sibling group.
        struct Group
        {
            Work work;
            Gate gate;
            bool latched = false;
            std::uint32_t frames_until_retry = 0;
        };

        HealConfig config;
        // The single process-wide "layout has drifted" latch, claimed by CAS so exactly one Warning is emitted across
        // every group even when several fields moved on the same frame.
        std::atomic<bool> drift_warned{false};
        std::vector<Group> groups;
        // Groups registered from within a running tick() (a callback calling add_group) are staged here and merged into
        // `groups` after the scan loop, so add_group can never reallocate `groups` while tick's range-for holds a
        // reference into it.
        std::vector<Group> pending;
        bool ticking = false;
    };

    Result<rtti::HealScheduler> rtti::HealScheduler::start(HealConfig config) noexcept
    {
        // A zero interval would divide-by-nothing the retry budget (every tick is a scan), which is a caller mistake,
        // not a valid cadence; reject it up front rather than silently reinterpret it.
        if (config.interval_frames == 0)
            return std::unexpected(Error{ErrorCode::InvalidArg, "rtti::HealScheduler::start"});
        try
        {
            auto impl = std::make_unique<Impl>();
            impl->config = config;
            return HealScheduler{std::move(impl)};
        }
        catch (...)
        {
            return std::unexpected(Error{ErrorCode::OutOfMemory, "rtti::HealScheduler::start"});
        }
    }

    rtti::HealScheduler::HealScheduler(std::unique_ptr<Impl> impl) noexcept : m_impl(std::move(impl)) {}
    rtti::HealScheduler::HealScheduler(HealScheduler &&) noexcept = default;
    rtti::HealScheduler &rtti::HealScheduler::operator=(HealScheduler &&) noexcept = default;
    rtti::HealScheduler::~HealScheduler() noexcept = default;

    void rtti::HealScheduler::add_group(Work work, Gate gate)
    {
        if (!m_impl)
            return;
        // A group with no heal work can never resolve; ignore an empty callback rather than let it reach tick(), where
        // invoking an empty std::move_only_function would be undefined behavior.
        if (!work)
            return;
        // Defer a group added from within a running tick (a work/gate callback re-entering add_group) so tick's
        // range-for reference into `groups` is never invalidated by a reallocation mid-iteration; it starts scanning on
        // the next tick.
        std::vector<Impl::Group> &target = m_impl->ticking ? m_impl->pending : m_impl->groups;
        target.push_back(Impl::Group{std::move(work), std::move(gate), false, 0});
    }

    void rtti::HealScheduler::tick() noexcept
    {
        if (!m_impl)
            return;
        // Mark the scan in flight so a re-entrant add_group (from a work/gate callback) defers into `pending` rather
        // than mutating `groups` under the range-for below.
        m_impl->ticking = true;
        for (Impl::Group &group : m_impl->groups)
        {
            if (group.latched)
                continue;

            // Silent pre-gate, evaluated BEFORE the interval countdown: a target that is not constructed yet is polled
            // cheaply every frame and skipped without spending the retry budget or logging. A throwing gate is treated
            // as "not ready".
            if (group.gate)
            {
                bool ready = false;
                try
                {
                    ready = group.gate();
                }
                catch (...)
                {
                    ready = false;
                }
                if (!ready)
                    continue;
            }

            // Fixed-interval countdown. The scan frame itself does not decrement: after a scan the counter is reset to
            // interval_frames and the next interval_frames ticks are skips, so scans land on frames 0, interval+1,
            // 2*(interval)+2, ... -- a fixed cadence, never a geometric backoff.
            if (group.frames_until_retry > 0)
            {
                --group.frames_until_retry;
                continue;
            }
            group.frames_until_retry = m_impl->config.interval_frames;

            HealRun run{m_impl->config, m_impl->drift_warned};
            bool resolved = false;
            try
            {
                resolved = group.work(run);
            }
            catch (...)
            {
                // A throwing work callback is treated as "did not resolve this frame"; the group retries next interval.
                resolved = false;
            }
            if (resolved)
                group.latched = true;
        }

        // The scan loop is done; adopt any groups a callback deferred while ticking. insert() reserves once up front
        // (so on OOM it throws before moving any element, leaving `pending` intact to retry next tick) and then
        // move-constructs each element (a std::move_only_function move is noexcept), keeping tick() noexcept.
        m_impl->ticking = false;
        if (!m_impl->pending.empty())
        {
            try
            {
                m_impl->groups.insert(m_impl->groups.end(), std::make_move_iterator(m_impl->pending.begin()),
                                      std::make_move_iterator(m_impl->pending.end()));
                m_impl->pending.clear();
            }
            catch (...)
            {
                // Allocation failed; leave `pending` untouched so the deferred groups are retried on the next tick.
            }
        }
    }

    bool rtti::HealScheduler::all_resolved() const noexcept
    {
        if (!m_impl)
            return true;
        for (const Impl::Group &group : m_impl->groups)
        {
            if (!group.latched)
                return false;
        }
        return true;
    }

    const rtti::HealConfig &rtti::HealScheduler::config() const noexcept
    {
        // A moved-from scheduler is inert (m_impl == nullptr), the same contract tick / add_group / all_resolved honor.
        // config() returns a reference, so it cannot no-op; hand back a reference to a static default rather than
        // dereferencing null, keeping the accessor safe on an inert instance too.
        if (!m_impl)
        {
            static const HealConfig k_inert_config{};
            return k_inert_config;
        }
        return m_impl->config;
    }

    void rtti::HealRun::warn_drift_once(std::string_view label, std::ptrdiff_t delta) noexcept
    {
        const std::ptrdiff_t magnitude = (delta < 0) ? -delta : delta;
        if (magnitude <= m_config.drift_warn_threshold)
            return;
        // CAS one-shot: the first drift to clear the latch emits the single actionable Warning. The recovered POINTER
        // offsets self-healed, but the non-healable scalar/flag offsets in the same structs silently rode the same
        // shift and need a human to re-verify -- that is the actionable headline this one line carries.
        bool expected = false;
        if (m_drift_warned.compare_exchange_strong(expected, true, std::memory_order_relaxed))
        {
            log().warning("Self-heal: layout drifted (first change: {} by {:+#x}); pointer offsets recovered. "
                          "Re-verify non-healable scalars.",
                          label, delta);
        }
    }

    Result<rtti::HealHit> rtti::HealRun::heal_into(std::string_view label, const Landmark &landmark, Address base,
                                                   std::atomic<std::ptrdiff_t> &slot, bool required) noexcept
    {
        // heal_from takes the base explicitly, so the landmark is not copied -- keeping heal_into allocation-free and
        // truly noexcept even for a landmark whose owned name would not fit the small-string buffer.
        Result<HealHit> result = heal_from(landmark, base);
        Logger &logger = log();
        if (result)
        {
            slot.store(result->healed_offset, std::memory_order_relaxed);
            const std::ptrdiff_t delta = result->healed_offset - landmark.nominal_offset;
            if (delta != 0)
            {
                warn_drift_once(label, delta);
                logger.info("Self-heal: {} moved {:+#x} ({:#x} -> {:#x})", label, delta, landmark.nominal_offset,
                            result->healed_offset);
            }
            else
            {
                logger.debug("Self-heal: {} confirmed at nominal {:#x}", label, landmark.nominal_offset);
            }
            return result;
        }

        // Fail closed: the slot keeps whatever nominal it was seeded with (untouched above). A required miss escalates
        // to a Warning under WarnRequired; an optional or Quiet miss stays at Debug so a legitimately-absent target
        // does not spam the log on the frames before it comes up.
        const std::string_view reason = to_string(result.error().code);
        if (required && m_config.escalate == HealEscalation::WarnRequired)
        {
            logger.warning("Self-heal: {} unresolved ({}); kept nominal {:#x} (re-author if drifted)", label, reason,
                           landmark.nominal_offset);
        }
        else
        {
            logger.debug("Self-heal: {} not resolvable now ({}); keeping nominal {:#x}", label, reason,
                         landmark.nominal_offset);
        }
        return result;
    }

    void rtti::HealRun::note_drift(std::string_view label, std::ptrdiff_t nominal_offset,
                                   std::ptrdiff_t healed_offset) noexcept
    {
        const std::ptrdiff_t delta = healed_offset - nominal_offset;
        Logger &logger = log();
        if (delta != 0)
        {
            warn_drift_once(label, delta);
            logger.info("Self-heal: {} moved {:+#x} ({:#x} -> {:#x})", label, delta, nominal_offset, healed_offset);
        }
        else
        {
            logger.debug("Self-heal: {} confirmed at nominal {:#x}", label, nominal_offset);
        }
    }
} // namespace DetourModKit
