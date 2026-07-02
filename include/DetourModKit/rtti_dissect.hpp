#ifndef DETOURMODKIT_RTTI_DISSECT_HPP
#define DETOURMODKIT_RTTI_DISSECT_HPP

/**
 * @file rtti_dissect.hpp
 * @brief Reverse-direction RTTI dissection, self-healing offsets, and the frame-scheduled heal runner.
 * @details The forward walker in rtti.hpp answers "what type is the object behind this vtable?". This header answers
 *          the inverse, slot-first questions a mod actually asks against a drifting game binary:
 *
 *          - @ref identify_pointee_type -- "what object does this pointer
 *            slot refer to, and what is its RTTI type?" (the per-slot primitive).
 *          - @ref reverse_scan_block -- "RTTI-label every pointer slot in
 *            this struct" (allocating, init-time/tooling triage).
 *          - @ref heal_landmark -- "a small patch shifted the layout; find
 *            where the field of type T moved to" (the self-healing offset resolver).
 *          - @ref solve_fingerprint -- "several fields co-moved; find the
 *            single uniform shift that satisfies every landmark" (rigid multi-field drift recovery).
 *          - @ref HealScheduler -- "run those heals on a frame cadence, latch
 *            each group once it resolves, and warn once when the layout has actually drifted" (the render-loop driver).
 *
 *          Every non-scheduler entry point is noexcept and fails closed. All reads go through the same SEH-guarded,
 *          module-bound-checked prelude the forward walker uses, so an unmapped page, a forged COL, or an ambiguous
 *          match is a clean failure return, never a fault and never a silently-wrong offset. Matching compares MSVC
 *          mangled bytes exactly; no UnDecorateSymbolName runs on any path. Scope is x64 MSVC.
 */

#include "DetourModKit/error.hpp"
#include "DetourModKit/rtti.hpp"

#include <atomic>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace rtti
    {
        /**
         * @brief Hard cap on a self-heal search radius (bytes per side). Bounds the worst-case probe count so an
         *        accidental SIZE_MAX window cannot hang.
         */
        inline constexpr std::size_t MAX_HEAL_WINDOW = 4096;

        /**
         * @brief Hard cap on the number of landmarks in one @ref solve_fingerprint template.
         */
        inline constexpr std::size_t MAX_FINGERPRINT_LANDMARKS = 32;

        /**
         * @struct PointeeType
         * @brief Result of reverse-identifying the object behind one slot.
         * @details Populated by @ref identify_pointee_type on success. Carries the resolved vtable and COL coordinates,
         *          the object base, the complete-object base recovered from COL.offset, and an inline copy of the
         *          mangled name so the struct is self-contained (no pointer into transient buffers). The struct is ~1
         *          KiB because of @ref name_buf; the hot self-heal path reuses a single stack instance, while @ref
         *          reverse_scan_block embeds it by value (tooling only).
         */
        struct PointeeType
        {
            /// Resolved vtable pointer.
            Address vtable{};
            /// COL the vtable points back to.
            Address col_addr{};
            /// TypeDescriptor base.
            Address td_addr{};
            /// Mangled-name buffer (td_addr + 0x10).
            Address name_addr{};
            /// Start of the resolved (sub)object.
            Address object_base{};
            /// object_base - col_offset (underflow-clamped).
            Address complete_obj{};
            /// Raw qword read at the probed slot.
            Address pointer_value{};
            /// COL.offset (+0x04): this vtable's offset in the complete object.
            std::uint32_t col_offset = 0;
            /// true when the slot held a pointer-to-object (deref'd once).
            bool was_pointer = false;
            /// Length of the mangled name in @ref name_buf.
            std::uint16_t name_len = 0;
            /// NUL-terminated mangled name.
            char name_buf[MAX_TYPE_NAME_LEN + 1] = {};

            /// Non-owning view of the mangled name held in @ref name_buf.
            [[nodiscard]] std::string_view name() const noexcept { return std::string_view(name_buf, name_len); }
        };

        /**
         * @brief Reverse-RTTI-identify the object a pointer slot refers to.
         * @details Reads the qword at @p slot_addr, then accepts whichever of two shapes resolves through the verified
         *          COL prelude:
         *          - pointer-to-object (tried first): the slot value is a
         *            pointer to an object; dereference once and resolve the pointee's vtable. @c was_pointer is set and
         *            @c object_base is the pointee.
         *          - direct object base: the slot itself is the object, its
         *            value is the vtable. @c was_pointer is clear and @c object_base is @p slot_addr.
         *
         *          Classifying by resolvability rather than by module membership means an object whose vtable lives in
         *          a different
         *          DLL than the struct still resolves; @c was_pointer becomes a report, not a gate.
         * @param slot_addr Address of the pointer-sized slot to probe.
         * @param out Receives the identification on success. On a false return its contents are unspecified, so callers
         *            must check the return before reading it.
         * @return true when a real RTTI type resolved, false on a null/low slot, an unreadable slot, or neither shape
         *         resolving.
         */
        [[nodiscard]] bool identify_pointee_type(Address slot_addr, PointeeType &out) noexcept;

        /**
         * @brief Typed form of @ref identify_pointee_type.
         * @details Same probe and same @p out contract, but reports the specific fail-closed reason through the unified
         *          Error channel instead of a bool. @ref identify_pointee_type is exactly @c has_value() over this --
         *          one probe, one prelude walk, one implementation. The Error's code is one of
         *          @ref ErrorCode::BadSlotAddress (null/low slot), @ref ErrorCode::UnreadableSlot (faulted or null/low
         *          slot value), or @ref ErrorCode::NoRtti (neither shape carried a verifiable COL). Use this (or @ref
         *          identify_pointee_type_or) when the reason for a miss matters (cascade diagnostics, telemetry); use
         *          the bool form otherwise.
         * @param slot_addr Address of the pointer-sized slot to probe.
         * @param out Receives the identification on success; unspecified on an error return.
         * @return A value on resolve, or the typed Error on failure.
         */
        [[nodiscard]] Result<void> identify_pointee_typed(Address slot_addr, PointeeType &out) noexcept;

        /**
         * @concept SlotAddress
         * @brief A value usable as a probe slot address: an @ref Address (or nullptr).
         * @details Constrains the @ref identify_pointee_type_or fallback pack so every alternate is a candidate
         *          ADDRESS. A raw pointer or a bare integer is intentionally rejected: Address's pointer/integer
         *          constructors are explicit, so a consumer wraps one in `Address{...}` at the call site, exactly as
         *          the rest of the API expects. A hard, readable compile error beats a deep template instantiation
         *          failure.
         */
        template <typename T>
        concept SlotAddress = std::convertible_to<T, Address>;

        /**
         * @brief Reverse-RTTI-identify the first of several candidate slots that resolves.
         * @details Probes @p candidate, then each fallback address in declaration order, stopping at the first slot
         * that
         *          resolves; @p out then holds that slot's identification. When NO candidate resolves, returns the
         *          FIRST (the @p candidate's) failure -- the earliest, most specific fail-closed reason -- so a cascade
         *          reports "the primary slot was unreadable" rather than a generic miss. The fold short-circuits, so no
         *          fallback past the winner is probed and each candidate is probed at most once (no extra prelude walk
         *          per fallback beyond the single probe the bare primitive performs). The cascade selects the first
         *          RESOLVING slot, not the "best" one: with several valid-but-different objects, declaration order is
         *          the only disambiguator -- a consumer needing type discrimination uses @ref heal_landmark / @ref
         *          solve_fingerprint instead. On a failure return @p out is reset to a default-constructed @ref
         *          PointeeType, so a caller that ignores the error never reads a slot's partially written fields.
         * @tparam Fallbacks Pack of alternate slot addresses, each an @ref Address.
         * @param candidate The primary slot address to probe first.
         * @param out Receives the first resolving slot's identification; reset to a default PointeeType on failure.
         * @param fallbacks Alternate slot addresses, tried in order after @p candidate.
         * @return A value on first resolve (@p out populated), or the @p candidate's Error when all candidates fail.
         */
        template <SlotAddress... Fallbacks>
        [[nodiscard]] Result<void> identify_pointee_type_or(Address candidate, PointeeType &out,
                                                            Fallbacks... fallbacks) noexcept
        {
            // Capture the primary's typed error before the fold runs so a later probe cannot clobber the value we
            // preserve; Error is a trivially copyable value.
            Result<void> primary = identify_pointee_typed(candidate, out);
            if (primary)
            {
                return {};
            }
            // Unary left fold over ||: left-to-right, short-circuiting at the first resolver, so no fallback past the
            // winner is probed.
            const bool any = (identify_pointee_typed(static_cast<Address>(fallbacks), out).has_value() || ...);
            if (any)
            {
                return {};
            }
            // Every candidate failed. The last probe may have left @p out half-written (e.g. a partial name_buf on a
            // NoRtti-after-name miss), so reset it to a clean default before returning. This keeps a caller that
            // ignores the error code from reading partially-written fields, while the FIRST (primary) error is still
            // the one surfaced.
            out = PointeeType{};
            return primary;
        }

        /**
         * @struct LabeledSlot
         * @brief One slot from a @ref reverse_scan_block sweep that resolved to a real RTTI type.
         */
        struct LabeledSlot
        {
            /// Address of the resolved slot.
            Address slot_addr{};
            /// Zero-based index of the slot in the swept block.
            std::size_t slot_index = 0;
            /// Reverse-identified type (carries its own name buffer).
            PointeeType type;
        };

        /**
         * @brief RTTI-label a block of pointer-sized slots.
         * @details Walks @p slot_count slots from @p start (stepping by @p stride) and appends a @ref LabeledSlot for
         *          every slot that @ref identify_pointee_type resolves. This is the dump/triage face of the feature
         *          ("tell me the RTTI type of every pointer field in this struct").
         * @param start Address of the first slot.
         * @param slot_count Number of slots to probe.
         * @param out Receives the resolved slots, appended in slot order.
         * @param stride Byte distance between adjacent slots. Zero is treated as sizeof(std::uintptr_t).
         * @return Number of slots appended to @p out.
         * @warning ALLOCATES (grows @p out) and calls the syscall-heavy prelude per slot. Init-time / tooling only --
         *          never the hot path.
         * @note The (slot_count * stride) span is overflow-guarded; a malformed tuple is treated as an empty block and
         *       returns 0. If a reallocation of @p out throws, the sweep stops early and returns the count appended so
         *       far (the noexcept contract holds).
         */
        [[nodiscard]] std::size_t reverse_scan_block(Address start, std::size_t slot_count,
                                                     std::vector<LabeledSlot> &out,
                                                     std::size_t stride = sizeof(std::uintptr_t)) noexcept;

        /**
         * @brief Byte-length overload of @ref reverse_scan_block.
         * @details Equivalent to reverse_scan_block(start, byte_len / stride, out, stride).
         * @param start Address of the first slot.
         * @param byte_len Length of the block in bytes.
         * @param out Receives the resolved slots, appended in slot order.
         * @param stride Byte distance between adjacent slots. Zero is treated as sizeof(std::uintptr_t).
         * @return Number of slots appended to @p out.
         */
        [[nodiscard]] std::size_t reverse_scan_block_bytes(Address start, std::size_t byte_len,
                                                           std::vector<LabeledSlot> &out,
                                                           std::size_t stride = sizeof(std::uintptr_t)) noexcept;

        /**
         * @enum Indirection
         * @brief Slot shape (and, for @ref CompleteObject, subobject position) a self-heal landmark requires of a
         *        matching slot.
         * @details Applied as a soft policy filter on top of @ref identify_pointee_type's resolvability classification.
         * @note Under multiple inheritance each base subobject carries its own vtable, and each vtable's COL names the
         *       same most-derived type; COL.offset is what distinguishes them. A direct-object heal keyed on @ref
         *       ObjectBase or @ref Any can therefore match a secondary base's vtable and report an offset shifted by
         *       that subobject delta. Use @ref CompleteObject for an embedded object that may use multiple inheritance:
         *       it matches only the primary subobject (COL.offset == 0), so the healed offset is always the true
         *       complete-object base. @ref HealHit::was_pointer and @ref HealHit::col_offset let an @ref ObjectBase /
         *       @ref Any consumer detect the direct-object case after the fact.
         */
        enum class Indirection : std::uint8_t
        {
            /// Match only slots that held a pointer-to-object.
            PointerToObject = 0,
            /// Match only a direct object base (any subobject, including a multiple-inheritance secondary).
            ObjectBase = 1,
            /// Match either shape (use when capture and heal may straddle a DLL boundary).
            Any = 2,
            /**
             * @brief Match only a direct object base whose vtable is the most-derived (primary) subobject,
             *        COL.offset == 0.
             * @details Like @ref ObjectBase, but rejects a multiple-inheritance secondary base whose vtable sits
             *          adjacent to the primary and whose COL still names the complete type. This keeps a heal from
             *          latching that secondary slot and reporting an offset shifted by the subobject delta (a silent
             *          off-by-a-subobject heal). Prefer it whenever the landmarked object may have more than one base.
             */
            CompleteObject = 3
        };

        /**
         * @struct Landmark
         * @brief A consumer-owned, serializable record of "a field of a known type lives near a known offset within a
         *        struct."
         * @details Recorded once and persisted (config). The persisted form carries @ref nominal_offset, @ref window,
         *          an owned copy of @ref expected_mangled, @ref indirection, @ref stride, and (for fingerprints) @ref
         *          required. @ref base is never persisted: it is an ASLR'd runtime address resolved fresh each session
         *          (typically from a scan::resolve ladder/AOB anchor or a live object pointer) and filled in at call
         *          time.
         * @note @ref expected_mangled must name a type that is stable across patches (a base/engine type, not a
         *       game-specific most-derived subtype), because matching is byte-exact on the most-derived name. A subtype
         *       rename defeats healing and fails closed via @ref ErrorCode::HealNoMatch.
         * @note @ref expected_mangled is OWNED (a std::string), so a Landmark is self-contained and safe to build from
         *       a string literal, a config-loaded value, or any transient string_view without a dangling view: the
         *       common in-code form is a Landmark built from a mangled string literal, mirroring a scan::Candidate
         *       ladder.
         */
        struct Landmark
        {
            /// Resolved struct base. Filled at call time; never persisted.
            Address base{};
            /// Last known field offset within @ref base.
            std::ptrdiff_t nominal_offset = 0;
            /// Search radius per side in bytes (capped at MAX_HEAL_WINDOW).
            std::size_t window = 0x40;
            /// Owned MSVC mangled name to match (byte-exact on the most-derived name).
            std::string expected_mangled;
            /// Required slot shape.
            Indirection indirection = Indirection::PointerToObject;
            /// Probe step (and candidate alignment). Zero -> 8.
            std::size_t stride = sizeof(std::uintptr_t);
            /// Consulted only by @ref solve_fingerprint; a required landmark must match.
            bool required = true;
        };

        /**
         * @struct HealHit
         * @brief Successful self-heal outcome from @ref heal_landmark.
         */
        struct HealHit
        {
            /// slot_addr - base: the field offset to use (== nominal_offset on no drift).
            std::ptrdiff_t healed_offset = 0;
            /// Address of the matching slot.
            Address slot_addr{};
            /// Resolved object base behind the slot.
            Address object_addr{};
            /// Resolved vtable of the matched object.
            Address vtable{};
            /**
             * @brief COL.offset of the matched object: 0 for the primary (complete) subobject, nonzero for a
             *        multiple-inheritance secondary base.
             * @details On a direct-object match (@ref was_pointer is false), a nonzero value means the slot landed on
             *          a secondary base, so @ref healed_offset is shifted that many bytes from the complete-object
             *          base. An @ref Indirection::CompleteObject heal only matches col_offset == 0, so this is always
             *          0 there.
             */
            std::uint32_t col_offset = 0;
            /// Shape of the matched slot.
            bool was_pointer = false;
        };

        /**
         * @brief Self-heal one field offset after a layout shift.
         * @details Checks the nominal slot (@c base + @c nominal_offset) first;
         *          an unchanged offset short-circuits and returns immediately, so an unpatched binary -- or one with a
         *          same-typed neighbour in the window -- never trips the ambiguity test. On a nominal miss it scans the
         *          +/- @c window grid (stepping by @c stride, so probes stay congruent to the nominal slot and never
         *          straddle a field), nearest-first, and returns the uniquely nearest matching slot. A slot matches
         *          when it resolves via @ref identify_pointee_type, satisfies @c indirection, and its most-derived
         *          mangled name byte-equals @c expected_mangled.
         * @param lm The landmark, with @c base filled in.
         * @return The healed offset and match details, or:
         *         - @ref ErrorCode::BadDescriptor for a malformed landmark
         *           (low @c base, empty/oversized name, unknown @c indirection, @c window over MAX_HEAL_WINDOW, or a
         *           nominal address outside
         *           the user-mode window), before any read;
         *         - @ref ErrorCode::HealNoMatch when no slot matched;
         *         - @ref ErrorCode::HealAmbiguous when both the @c +d and @c -d slots
         *           at the nearest matching distance match (an irreducible tie).
         * @warning FAIL-WRONG HAZARD when the window is crowded with same-typed slots. A single landmark resolves to
         * the
         *          uniquely NEAREST slot that satisfies the type + shape, so any of these wins SILENTLY and returns a
         *          confidently-wrong offset rather than failing closed:
         *          - a strictly-nearer same-typed DECOY field at the wrong offset (both satisfy the slot shape, and the
         *            nearer one is returned before the intended field is ever probed);
         *          - under multiple inheritance, a secondary base subobject whose vtable sits nearer than the primary
         *            and whose COL still names the complete type (use @ref Indirection::CompleteObject to reject it).
         *          The @ref ErrorCode::HealAmbiguous result fires ONLY for an exact +/- distance tie at the nearest
         *          matching ring, never for a nearer decoy, so a wrong-but-nearer slot is not flagged. Whenever the
         *          window may be crowded -- a struct that holds more than one field of @c expected_mangled's type, or
         *          an object that may use multiple inheritance -- prefer @ref solve_fingerprint, which disambiguates
         *          structurally because one uniform delta must fit every field at once, or narrow @c window / tighten
         *          the type to a name that is unique in the neighbourhood.
         * @note Init-time / re-heal-on-miss, not per-frame: each probe runs the syscall-heavy prelude up to twice. The
         *       window cap bounds the worst case. Allocates nothing (one reused stack @ref PointeeType).
         */
        [[nodiscard]] Result<HealHit> heal_landmark(const Landmark &lm) noexcept;

        /**
         * @struct FingerprintHit
         * @brief Successful outcome from @ref solve_fingerprint.
         */
        struct FingerprintHit
        {
            /// The single uniform byte shift applied to every landmark offset.
            std::ptrdiff_t delta = 0;
            /// Required landmarks satisfied at @ref delta (equals the required count).
            std::size_t matched = 0;
            /// Optional landmarks also satisfied at @ref delta.
            std::size_t optional_matched = 0;
        };

        /**
         * @brief Rigid multi-field drift recovery.
         * @details Finds the single uniform delta in [-window_bytes, +window_bytes] (stepping by
         *          sizeof(std::uintptr_t)) such that every required landmark at @c base + @c nominal_offset + @c delta
         *          reverse-resolves to its type with its required shape. A dense window of same-typed neighbours that
         *          defeats a single @ref heal_landmark is structurally disambiguated here because one delta must fit
         *          the whole template at once. Optional landmarks (@c required == false) are scored only to break ties
         *          between deltas that satisfy every required landmark. Degenerates to a single-field solve when @p
         *          fp.size() == 1.
         * @param base Resolved struct base (the landmarks' own @c base fields are ignored; this one is used for every
         *             probe).
         * @param fp The landmark template. Each landmark's @c nominal_offset, @c expected_mangled, @c indirection, and
         *           @c required are consulted; @c window and @c stride are not (probing is a single shifted slot, not a
         *           per-landmark window).
         * @param window_bytes Maximum uniform shift to search per side, capped at MAX_HEAL_WINDOW.
         * @return The recovered delta, or:
         *         - @ref ErrorCode::BadDescriptor for an empty span, over-cap
         *           span, no required landmark, an oversized @p window_bytes, a
         *           malformed landmark, or a low @p base;
         *         - @ref ErrorCode::HealNoMatch when no delta satisfied every
         *           required landmark;
         *         - @ref ErrorCode::HealAmbiguous when two or more deltas tie for the
         *           most optional matches.
         * @note Each landmark in @p fp must have a distinct @c nominal_offset. Corroboration is scored by counting the
         *       required landmarks satisfied at a delta, so two landmarks sharing a nominal_offset would probe the same
         *       slot and double-count it. Duplicate offsets are rejected as @ref ErrorCode::BadDescriptor before any
         *       memory is touched.
         * @warning Init-time only: the probe count is (2 * window_bytes / 8 + 1) * fp.size() prelude walks. Allocates
         *          nothing.
         */
        [[nodiscard]] Result<FingerprintHit> solve_fingerprint(Address base, std::span<const Landmark> fp,
                                                               std::size_t window_bytes) noexcept;

        /**
         * @struct DriftEntry
         * @brief One landmark's heal outcome, for a structured drift report.
         * @details The raw "what moved and by how much" record a consumer logs to a changelog or scans to spot a
         *          patch's re-layout at a glance. All fields are derived from an existing @ref heal_landmark result;
         *          this adds no new analysis.
         */
        struct DriftEntry
        {
            /// Aliases the landmark's @c expected_mangled.
            std::string_view name;
            /// The landmark's last-known offset.
            std::ptrdiff_t nominal_offset = 0;
            /// The resolved offset (valid only when @ref ok).
            std::ptrdiff_t healed_offset = 0;
            /// healed_offset - nominal_offset (valid only when @ref ok).
            std::ptrdiff_t delta = 0;
            /// Whether the landmark healed.
            bool ok = false;
            /// Failure code (its category is @ref ErrorCategory::Rtti); meaningful only when @ref ok is false.
            ErrorCode error{ErrorCode::Ok};
        };

        /**
         * @brief Heals a set of landmarks and writes a per-landmark drift report.
         * @details Runs @ref heal_landmark on each landmark in order and records the outcome (nominal, healed, delta,
         *          or the typed failure code) into @p out. Each landmark must already have its @c base filled in,
         *          exactly as for a direct @ref heal_landmark call. This is a thin aggregation over the existing heal
         *          path: it performs no read the individual heals would not, and allocates nothing.
         * @param landmarks The landmarks to heal (each with @c base set).
         * @param out Destination, parallel to @p landmarks. At most @c out.size() entries are written.
         * @return The number of entries written: @c min(landmarks.size(), out.size()).
         */
        [[nodiscard]] std::size_t heal_report(std::span<const Landmark> landmarks, std::span<DriftEntry> out) noexcept;

        /**
         * @enum HealEscalation
         * @brief Log-severity policy a @ref HealScheduler applies to a landmark that does not resolve during a scan.
         */
        enum class HealEscalation : std::uint8_t
        {
            /**
             * A REQUIRED landmark that stays unresolved after a scan logs at Warning (the "kept nominal, re-author if
             * drifted" headline); an OPTIONAL landmark's miss stays at Debug. The default.
             */
            WarnRequired = 0,
            /**
             * Every miss (required or optional) stays at Debug -- for a group whose target is legitimately absent much
             * of the time and whose miss is not itself actionable.
             */
            Quiet = 1
        };

        /**
         * @struct HealConfig
         * @brief Tunables for a @ref HealScheduler: retry cadence, drift-warning threshold, and miss escalation.
         */
        struct HealConfig
        {
            /**
             * @brief Frames between retry scans of an un-latched group. A group that does not resolve is re-attempted
             *        on this cadence, never every frame (the RTTI prelude is syscall-heavy), with NO attempt cap: it
             *        keeps retrying until it resolves, then latches and stops. This is a fixed interval, deliberately
             *        NOT a geometric backoff -- a target that is briefly absent (a load, a menu) reappears on a
             *        predictable schedule rather than after an ever-growing wait.
             * @note A value of 0 is rejected by @ref HealScheduler::start with @ref ErrorCode::InvalidArg.
             */
            std::uint32_t interval_frames = 30;
            /**
             * @brief A realised drift whose absolute delta exceeds this threshold fires the one-shot layout-drift
             *        Warning. The default of 0 warns on ANY nonzero drift.
             */
            std::ptrdiff_t drift_warn_threshold = 0;
            /// Log-severity policy for a landmark that does not resolve during a scan.
            HealEscalation escalate = HealEscalation::WarnRequired;
        };

        class HealScheduler;

        /**
         * @class HealRun
         * @brief The per-scan heal context a @ref HealScheduler hands to a group's work callback.
         * @details Owns the store-on-success, fail-closed-on-miss, per-outcome logging, and one-shot drift-Warning
         *          machinery, so a group callback only expresses WHICH landmarks to heal from WHICH live base. It is a
         *          transient view over the scheduler's state, valid only for the duration of the callback; do not store
         *          it.
         */
        class HealRun
        {
        public:
            // Non-owning, scheduler-scoped, and valid only for the duration of one work callback: it aliases the
            // scheduler's config and warn-once state. Copying or moving it would let a callback smuggle those aliases
            // out to outlive the scheduler, so every copy/move is deleted to make the transient lifetime unextendable.
            HealRun(const HealRun &) = delete;
            HealRun &operator=(const HealRun &) = delete;
            HealRun(HealRun &&) = delete;
            HealRun &operator=(HealRun &&) = delete;

            /**
             * @brief Heal one landmark from a live base and publish the result to a caller-owned offset slot.
             * @details Copies @p landmark, fills its base with @p base, and runs @ref heal_landmark. On a resolve the
             *          @p slot takes the healed offset (which equals the nominal when nothing drifted, via the nominal
             *          short-circuit) and the outcome is logged (a recovered drift at Info plus the one-shot drift
             *          Warning; a confirmation at nominal at Debug). On a miss the @p slot is left untouched (fail
             *          closed: it keeps whatever nominal it was seeded with) and the miss is logged per the config's
             *          @ref HealConfig::escalate policy and @p required flag.
             * @param label Short human-readable field name for the log lines.
             * @param landmark The landmark template; its own @c base is ignored in favour of @p base.
             * @param base The live, resolved struct base for this frame.
             * @param slot The caller-owned offset cache slot (typically seeded with the nominal offset).
             * @param required Whether an unresolved miss escalates to Warning under @ref HealEscalation::WarnRequired.
             * @return The @ref heal_landmark result (the caller can inspect the details or the Error).
             */
            [[nodiscard]] Result<HealHit> heal_into(std::string_view label, const Landmark &landmark, Address base,
                                                    std::atomic<std::ptrdiff_t> &slot, bool required = true) noexcept;

            /**
             * @brief Report a drift a group recovered itself (e.g. through @ref solve_fingerprint), so the one-shot
             *        Warning and the per-field Info line fire consistently with @ref heal_into.
             * @details Use this for a corroborated bracket that writes its own slots: after storing the shifted
             *          offsets, call note_drift once per moved field. A zero delta logs a nominal confirmation at Debug
             *          and fires no Warning.
             * @param label Short human-readable field name.
             * @param nominal_offset The field's last-known offset.
             * @param healed_offset The recovered offset.
             */
            void note_drift(std::string_view label, std::ptrdiff_t nominal_offset,
                            std::ptrdiff_t healed_offset) noexcept;

        private:
            friend class HealScheduler;
            HealRun(const HealConfig &config, std::atomic<bool> &drift_warned) noexcept
                : m_config(config), m_drift_warned(drift_warned)
            {
            }

            // Fires the one-shot layout-drift Warning if |delta| exceeds the configured threshold and no earlier drift
            // has already claimed the latch (CAS, so exactly one Warning is emitted across the whole scheduler).
            void warn_drift_once(std::string_view label, std::ptrdiff_t delta) noexcept;

            const HealConfig &m_config;
            std::atomic<bool> &m_drift_warned;
        };

        /**
         * @class HealScheduler
         * @brief Frame-driven runner for a set of independently-latched self-heal groups.
         * @details Captures the recurring render-loop pattern of a self-healing offset cache: on each @ref tick, every
         *          un-latched group that has waited out the configured frame interval runs its heal work; a group that
         *          reports success latches and stops being scanned, and the FIRST realised drift across all groups
         *          fires exactly one process-wide layout-drift Warning (a CAS one-shot). A group can also carry a cheap
         *          per-frame gate that runs BEFORE the interval countdown, so a target that is not constructed yet is
         *          skipped silently without spending the retry budget or logging.
         *
         *          The scheduler owns the cadence, the per-group latches, and the warn-once state; each group's work
         *          callback expresses only its own heal logic (a single @ref HealRun::heal_into, a @ref
         *          solve_fingerprint bracket, a dependent hop through a healed offset, ...) and returns whether
         *          the group has fully resolved. There is NO attempt cap: an unresolved group is retried on the fixed
         *          interval for as long as it takes, then latches.
         * @note Render-thread only. The scheduler is single-owner and move-only; construct it once (via @ref start) and
         *       drive it from the same thread that walks the pointer chains. The offset SLOTS a group writes are the
         *       cross-thread channel (a std::atomic<std::ptrdiff_t> per offset), not the scheduler itself.
         */
        class HealScheduler
        {
        public:
            /// A cheap per-frame precondition; returning false skips the group's scan without spending the interval.
            using Gate = std::move_only_function<bool()>;
            /**
             * A group's heal work; returning true latches the group (no more scans). Returning false retries next
             * interval.
             */
            using Work = std::move_only_function<bool(HealRun &)>;

            /**
             * @brief Constructs a scheduler with the given config.
             * @param config Retry cadence, drift-warning threshold, and miss escalation.
             * @return The scheduler, or @ref ErrorCode::InvalidArg when @c config.interval_frames is 0.
             */
            [[nodiscard]] static Result<HealScheduler> start(HealConfig config = {}) noexcept;

            HealScheduler(HealScheduler &&) noexcept;
            HealScheduler &operator=(HealScheduler &&) noexcept;
            HealScheduler(const HealScheduler &) = delete;
            HealScheduler &operator=(const HealScheduler &) = delete;
            ~HealScheduler() noexcept;

            /**
             * @brief Registers an independently-latched heal group.
             * @param work The group's heal work, run on the configured interval while un-latched. Returning true
             *             latches the group; returning false retries on the next interval.
             * @param gate Optional per-frame precondition, evaluated before the interval countdown. When it returns
             *             false the group is skipped silently and the interval budget is not spent, so a not-yet-live
             *             target is polled cheaply every frame until it appears.
             * @note An empty @p work is ignored (no group is registered), since a group with no heal work could never
             *       resolve. Primarily a setup call; if invoked re-entrantly from within a running @ref tick (a work or
             *       gate callback adding a group), the new group is deferred and starts scanning on the next tick, so
             *       it never reallocates the group container while tick is iterating it.
             */
            void add_group(Work work, Gate gate = {});

            /**
             * @brief Advances the scheduler by one frame: scans every un-latched, gate-passing, interval-due group.
             * @details Never throws; a work or gate callback that throws is treated as "did not resolve this frame".
             */
            void tick() noexcept;

            /// Returns true when every registered group has latched (vacuously true with no groups).
            [[nodiscard]] bool all_resolved() const noexcept;

            /// Returns the config the scheduler was started with.
            [[nodiscard]] const HealConfig &config() const noexcept;

        private:
            struct Impl;
            explicit HealScheduler(std::unique_ptr<Impl> impl) noexcept;
            std::unique_ptr<Impl> m_impl;
        };
    } // namespace rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_RTTI_DISSECT_HPP
