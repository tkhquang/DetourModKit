#ifndef DETOURMODKIT_RTTI_DISSECT_HPP
#define DETOURMODKIT_RTTI_DISSECT_HPP

/**
 * @file rtti_dissect.hpp
 * @brief Reverse-direction RTTI dissection, self-healing offsets, and the frame-scheduled heal runner.
 * @details Every non-scheduler entry point is noexcept and fails closed. Entry points reach foreign memory only
 *          through the guarded RTTI prelude. Matching uses exact MSVC-mangled bytes. Scope is x64 MSVC.
 * @warning `[B-100]` Under the loader lock, call only a @ref HealedSlot read. Dissection and self-heal query the
 *          loader through RTTI, while scheduler setup allocates.
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
         * @details Self-contained: @ref name_buf holds an inline copy of the mangled name, so no field points into a
         *          transient buffer. The struct is ~1 KiB. The self-heal path reuses one stack instance.
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
         * @details Tries pointer-to-object first, then treats the slot as a direct object base. Either shape must
         *          pass the verified COL prelude; @c was_pointer reports the winning shape without imposing module
         *          locality.
         * @param slot_addr Address of the pointer-sized slot to probe.
         * @param out Receives the identification on success. On a false return its contents are unspecified, so callers
         *            must check the return before reading it.
         * @return true when a real RTTI type resolved, false on a null/low slot, an unreadable slot, or neither shape
         *         resolving.
         */
        [[nodiscard]] bool identify_pointee_type(Address slot_addr, PointeeType &out) noexcept;

        /**
         * @brief Typed form of @ref identify_pointee_type.
         * @details @ref identify_pointee_type is exactly @c has_value() over this. The Error code is
         *          @ref ErrorCode::BadSlotAddress (null/low slot), @ref ErrorCode::UnreadableSlot (faulted or null/low
         *          slot value), or @ref ErrorCode::NoRtti (neither shape carried a verifiable COL). Use this form when
         *          the reason for a miss matters.
         * @param slot_addr Address of the pointer-sized slot to probe.
         * @param out Receives the identification on success; unspecified on an error return.
         * @return A value on resolve, or the typed Error on failure.
         */
        [[nodiscard]] Result<void> identify_pointee_typed(Address slot_addr, PointeeType &out) noexcept;

        /**
         * @concept SlotAddress
         * @brief A value usable as a probe slot address: an @ref Address (or nullptr).
         * @details Raw pointers and bare integers are rejected because Address's converting constructors are explicit.
         *          Wrap one in `Address{...}` at the call site.
         */
        template <typename T>
        concept SlotAddress = std::convertible_to<T, Address>;

        /**
         * @brief Reverse-RTTI-identify the first of several candidate slots that resolves.
         * @details Probes in declaration order and stops at the first resolve. If all miss, returns the primary
         *          error and resets @p out; declaration order is the only tie-breaker between valid candidates.
         *
         * @tparam Fallbacks Pack of alternate slot addresses, each an @ref Address.
         * @param candidate The primary slot address to probe first.
         * @param out Receives the first resolving slot's identification; reset to a default PointeeType on failure.
         * @param fallbacks Alternate slot addresses, tried in order after @p candidate.
         * @return A value on first resolve (@p out populated), or the @p candidate's Error when all candidates fail.
         */
        template <SlotAddress... Fallbacks>
        [[nodiscard]] Result<void>
        identify_pointee_type_or(Address candidate, PointeeType &out, Fallbacks... fallbacks) noexcept
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
            // Every candidate failed. The last probe may have left @p out half-written, so reset it. The FIRST
            // (primary) error is the one surfaced.
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
         *          every slot that @ref identify_pointee_type resolves.
         * @param start Address of the first slot.
         * @param slot_count Number of slots to probe.
         * @param out Receives the resolved slots, appended in slot order.
         * @param stride Byte distance between adjacent slots. Zero is treated as sizeof(std::uintptr_t).
         * @return Number of slots appended to @p out.
         * @warning ALLOCATES (grows @p out) and calls the syscall-heavy prelude per slot. Init-time / tooling only,
         *          never the hot path.
         * @note The (slot_count * stride) span is overflow-guarded; a malformed tuple is treated as an empty block and
         *       returns 0. If a reallocation of @p out throws, the sweep stops early and returns the count appended so
         *       far (the noexcept contract holds).
         */
        [[nodiscard]] std::size_t reverse_scan_block(
            Address start,
            std::size_t slot_count,
            std::vector<LabeledSlot> &out,
            std::size_t stride = sizeof(std::uintptr_t)
        ) noexcept;

        /**
         * @brief Byte-length overload of @ref reverse_scan_block.
         * @details Equivalent to reverse_scan_block(start, byte_len / stride, out, stride).
         * @param start Address of the first slot.
         * @param byte_len Length of the block in bytes.
         * @param out Receives the resolved slots, appended in slot order.
         * @param stride Byte distance between adjacent slots. Zero is treated as sizeof(std::uintptr_t).
         * @return Number of slots appended to @p out.
         */
        [[nodiscard]] std::size_t reverse_scan_block_bytes(
            Address start,
            std::size_t byte_len,
            std::vector<LabeledSlot> &out,
            std::size_t stride = sizeof(std::uintptr_t)
        ) noexcept;

        /**
         * @enum Indirection
         * @brief Slot shape (and, for @ref CompleteObject, subobject position) a self-heal landmark requires of a
         *        matching slot.
         * @details Applied as a policy filter on top of @ref identify_pointee_type's resolvability classification.
         * @note Under multiple inheritance every base subobject's COL names the same most-derived type. Only
         *       COL.offset distinguishes them, so an @ref ObjectBase or @ref Any heal can match a secondary base and
         *       report an offset shifted by that subobject delta. Use @ref CompleteObject for an object that may use
         *       multiple inheritance: it matches only COL.offset == 0.
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
             * @details Rejects a multiple-inheritance secondary base, so a heal cannot latch a secondary slot and
             *          report an offset shifted by the subobject delta. Prefer it when the landmarked object may have
             *          more than one base.
             */
            CompleteObject = 3
        };

        /**
         * @struct Landmark
         * @brief A consumer-owned, serializable record of "a field of a known type lives near a known offset within a
         *        struct."
         * @details Every field except @ref base is persistable. @ref base is an ASLR'd runtime address, resolved
         *          fresh each session and filled in at call time.
         * @note @ref expected_mangled must name a type that is stable across patches, because matching is byte-exact
         *       on the most-derived name. A rename defeats healing and fails closed via @ref ErrorCode::HealNoMatch.
         * @note @ref expected_mangled is OWNED (a std::string), so a Landmark built from a transient string_view holds
         *       no dangling view.
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
             * @details On a direct-object match, a nonzero value means the slot landed on a secondary base, so
             *          @ref healed_offset is shifted from the complete-object base. Always 0 under
             *          @ref Indirection::CompleteObject.
             */
            std::uint32_t col_offset = 0;
            /// Shape of the matched slot.
            bool was_pointer = false;
        };

        /**
         * @brief Self-heal one field offset after a layout shift.
         * @details Checks the nominal slot (@c base + @c nominal_offset) first. An unchanged offset short-circuits
         *          and never trips the ambiguity test. On a nominal miss it scans the +/- @c window grid
         *          nearest-first, stepping by @c stride, and returns the uniquely nearest slot that resolves via
         *          @ref identify_pointee_type, satisfies @c indirection, and byte-equals @c expected_mangled on the
         *          most-derived name.
         * @param lm The landmark, with @c base filled in.
         * @return The healed offset and match details, or:
         *         - @ref ErrorCode::BadDescriptor for a malformed landmark (low @c base, empty/oversized name, unknown
         *           @c indirection, @c window over MAX_HEAL_WINDOW, or a nominal address outside the user-mode
         *           window), before any read;
         *         - @ref ErrorCode::HealNoMatch when no slot matched;
         *         - @ref ErrorCode::HealAmbiguous when the @c +d and @c -d slots at the nearest matching distance both
         *           match.
         * @warning FAIL-WRONG HAZARD in a crowded window: a strictly-nearer same-typed decoy slot, or a
         *          multiple-inheritance secondary base, wins SILENTLY and returns a confidently-wrong offset.
         *          @ref ErrorCode::HealAmbiguous fires only for an exact +/- distance tie, never for a nearer decoy.
         *          When the window may be crowded, prefer @ref solve_fingerprint (one uniform delta must fit every
         *          field at once), use @ref Indirection::CompleteObject, or narrow @c window.
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
         *          reverse-resolves to its type with its required shape. Optional landmarks (@c required == false) are
         *          scored only to break ties between deltas that satisfy every required landmark.
         * @param base Resolved struct base (the landmarks' own @c base fields are ignored; this one is used for every
         *             probe).
         * @param fp The landmark template. Each landmark's @c nominal_offset, @c expected_mangled, @c indirection, and
         *           @c required are consulted; @c window and @c stride are not (probing is a single shifted slot, not a
         *           per-landmark window).
         * @param window_bytes Maximum uniform shift to search per side, capped at MAX_HEAL_WINDOW.
         * @return The recovered delta, or:
         *         - @ref ErrorCode::BadDescriptor for an empty span, over-cap span, no required landmark, an oversized
         *           @p window_bytes, a malformed landmark, or a low @p base;
         *         - @ref ErrorCode::HealNoMatch when no delta satisfied every required landmark;
         *         - @ref ErrorCode::HealAmbiguous when two or more nonzero deltas tie for the most optional matches. A
         *           zero-drift delta that satisfies every required landmark wins a top-score tie outright. A strictly
         *           higher optional score at any delta still wins.
         * @note Each landmark in @p fp must have a distinct @c nominal_offset. Duplicate offsets probe the same slot
         *       and double-count it, so they are rejected as @ref ErrorCode::BadDescriptor before any memory is
         *       touched.
         * @warning Init-time only: the probe count is (2 * window_bytes / 8 + 1) * fp.size() prelude walks. Allocates
         *          nothing.
         */
        [[nodiscard]] Result<FingerprintHit>
        solve_fingerprint(Address base, std::span<const Landmark> fp, std::size_t window_bytes) noexcept;

        /**
         * @struct DriftEntry
         * @brief One landmark's heal outcome, for a structured drift report.
         * @details All fields are derived from an existing @ref heal_landmark result. This adds no new analysis.
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
         * @details Runs @ref heal_landmark on each landmark in order and records the outcome into @p out. Each
         *          landmark must already have its @c base filled in. Adds no reads over the individual heals and
         *          allocates nothing.
         * @param landmarks The landmarks to heal (each with @c base set).
         * @param out Destination, parallel to @p landmarks. At most @c out.size() entries are written.
         * @return The number of entries written: @c min(landmarks.size(), out.size()).
         */
        [[nodiscard]] std::size_t heal_report(std::span<const Landmark> landmarks, std::span<DriftEntry> out) noexcept;

        /**
         * @enum OffsetValidity
         * @brief Whether a healed-offset value may be consumed, and how
         *        strongly.
         */
        enum class OffsetValidity : std::uint8_t
        {
            /// A required heal missed: the retained value is unverified and has no established image generation.
            Invalid = 0,
            /** @brief An optional miss retained a nominal that is only usable as a hint. */
            Unverified = 1,
            /// A heal resolved the offset with a nonzero image generation.
            Confirmed = 2
        };

        /**
         * @struct HealedOffset
         * @brief A consistent snapshot of a healed-offset slot: value, resolving-image generation, and validity.
         * @details A confirmed value is stamped from the resolved vtable's image. Invalid and Unverified snapshots use
         *          generation 0 because no matching image established the layout.
         */
        struct HealedOffset
        {
            /** @brief The offset, meaningful for consumption only when validity is Confirmed. */
            std::ptrdiff_t value = 0;
            /// @ref rtti::image_generation of the resolved vtable's image; 0 until a heal confirms the value.
            std::uint64_t generation = 0;
            /// Whether @ref value may be consumed.
            OffsetValidity validity = OffsetValidity::Invalid;

            /// True only when the value is Confirmed and carries a nonzero image generation.
            [[nodiscard]] bool usable() const noexcept
            {
                return validity == OffsetValidity::Confirmed && generation != 0;
            }
        };

        /**
         * @class HealedSlot
         * @brief Validity-bearing cross-thread channel for one healed offset: the safe alternative to a bare
         *        @c std::atomic<std::ptrdiff_t>.
         * @details Publishing is single-producer (the heal thread). Loads use a bounded seqlock retry and return an
         *          Invalid snapshot if contention persists, so a consumer never blocks the producer or accepts a torn
         *          value. Hold one per offset at a stable address.
         * @note The raw @c std::atomic<std::ptrdiff_t> @ref HealRun::heal_into overload carries no validity, so a
         *       required miss leaves a consumable nominal. Prefer this channel whenever a healed offset authorizes a
         *       write or a hook.
         */
        class HealedSlot
        {
        public:
            HealedSlot() noexcept = default;
            HealedSlot(const HealedSlot &) = delete;
            HealedSlot &operator=(const HealedSlot &) = delete;
            HealedSlot(HealedSlot &&) = delete;
            HealedSlot &operator=(HealedSlot &&) = delete;
            ~HealedSlot() noexcept = default;

            /**
             * @brief Seeds the slot with an unconfirmed nominal offset (generation 0, @ref OffsetValidity::Unverified).
             * @details A consumer that reads the slot before the first successful heal gets the nominal with an
             *          explicit Unverified status, never a Confirmed value.
             */
            void seed_nominal(std::ptrdiff_t nominal) noexcept;

            /**
             * @brief Publishes a snapshot atomically (single producer).
             * @details Non-Confirmed states are normalized to generation 0; Confirmed with generation 0 becomes
             * Invalid.
             */
            void publish(std::ptrdiff_t value, std::uint64_t generation, OffsetValidity validity) noexcept;

            /// Returns a consistent snapshot, or Invalid if bounded retries cannot observe one.
            [[nodiscard]] HealedOffset load() const noexcept;

            /**
             * @brief Returns the offset only when it is @ref OffsetValidity::Confirmed.
             * @return The Confirmed value, or @ref ErrorCode::OffsetNotConfirmed when validity or generation is absent.
             *         This is the validity gate; it does not check the current
             *         generation. Use the overload taking @p current_generation to also reject a stale image.
             * @note Callback-safe: a bounded seqlock read, no allocation, locking, or I/O.
             * @warning For mutation authorization tied to a module mapping, use the generation-checking overload.
             */
            [[nodiscard]] Result<std::ptrdiff_t> authorized() const noexcept;

            /**
             * @brief Returns the offset only when it is Confirmed AND still tied to @p current_generation.
             * @param current_generation A nonzero, current @ref rtti::image_generation of the resolved type's module.
             * @return The value, or @ref ErrorCode::OffsetNotConfirmed when the slot is not Confirmed or its generation
             *         is zero or no longer matches @p current_generation.
             */
            [[nodiscard]] Result<std::ptrdiff_t> authorized(std::uint64_t current_generation) const noexcept;

        private:
            // Single-producer seqlock: even = stable, odd = write in progress. The payload atomics are read/written
            // relaxed and made consistent by the sequence counter's acquire/release fences.
            std::atomic<std::uint32_t> m_seq{0};
            std::atomic<std::ptrdiff_t> m_value{0};
            std::atomic<std::uint64_t> m_generation{0};
            std::atomic<std::uint8_t> m_validity{static_cast<std::uint8_t>(OffsetValidity::Invalid)};
        };

        /**
         * @enum HealEscalation
         * @brief Log-severity policy a @ref HealScheduler applies to a landmark that does not resolve during a scan.
         */
        enum class HealEscalation : std::uint8_t
        {
            /// A required landmark that stays unresolved logs at Warning. An optional miss stays at Debug. The default.
            WarnRequired = 0,
            /// Every miss (required or optional) stays at Debug.
            Quiet = 1
        };

        /**
         * @struct HealConfig
         * @brief Tunables for a @ref HealScheduler: retry cadence, drift-warning threshold, and miss escalation.
         */
        struct HealConfig
        {
            /**
             * @brief Frames between retry scans of an un-latched group. The interval is fixed, with no attempt cap: a
             *        group retries until it resolves, then latches and stops.
             * @note A value of 0 is rejected by @ref HealScheduler::start with @ref ErrorCode::InvalidArg.
             */
            std::uint32_t interval_frames = 30;
            /**
             * @brief A realised drift whose absolute delta exceeds this threshold fires the one-shot layout-drift
             *        Warning. The default of 0 warns on ANY nonzero drift.
             * @note A negative value is rejected by @ref HealScheduler::start with @ref ErrorCode::InvalidArg.
             */
            std::ptrdiff_t drift_warn_threshold = 0;
            /// Log-severity policy for a landmark that does not resolve during a scan.
            HealEscalation escalate = HealEscalation::WarnRequired;
        };

        class HealScheduler;

        /**
         * @class HealRun
         * @brief The per-scan heal context a @ref HealScheduler hands to a group's work callback.
         * @details A transient view over the scheduler's state, valid only for the duration of the callback. Do not
         *          store it.
         */
        class HealRun
        {
        public:
            // Aliases the scheduler's config and warn-once state, so copy/move are deleted to keep the transient
            // lifetime unextendable.
            HealRun(const HealRun &) = delete;
            HealRun &operator=(const HealRun &) = delete;
            HealRun(HealRun &&) = delete;
            HealRun &operator=(HealRun &&) = delete;

            /**
             * @brief Heal one landmark from a live base and publish the result to a caller-owned offset slot.
             * @details Runs @ref heal_landmark at @p base, stores only a resolved offset, and logs confirmation,
             *          drift, or failure under @ref HealConfig::escalate. A miss leaves the raw slot untouched.
             * @param label Short human-readable field name for the log lines.
             * @param landmark The landmark template; its own @c base is ignored in favour of @p base.
             * @param base The live, resolved struct base for this frame.
             * @param slot The caller-owned offset cache slot (typically seeded with the nominal offset).
             * @param required Whether an unresolved miss escalates to Warning under @ref HealEscalation::WarnRequired.
             * @return The @ref heal_landmark result (the caller can inspect the details or the Error).
             * @warning A raw atomic carries no validity, so a retained nominal cannot authorize mutation. Use the
             *          @ref HealedSlot overload for writes or hooks; this form remains for compatibility/read-only
             *          use.
             */
            [[nodiscard]] Result<HealHit> heal_into(
                std::string_view label,
                const Landmark &landmark,
                Address base,
                std::atomic<std::ptrdiff_t> &slot,
                bool required = true
            ) noexcept;

            /**
             * @brief Validity-bearing form of @ref heal_into: publishes {value, generation, validity} to a @ref
             *        HealedSlot instead of a bare atomic.
             * @details A resolve publishes Confirmed with the nonzero image generation that brackets
             *          re-established evidence. Generation drift, missing identity, or changed evidence returns
             *          @ref ErrorCode::OffsetNotConfirmed. Any miss retains the value but publishes Invalid when
             *          required or Unverified when optional, so @ref HealedSlot::authorized rejects it.
             * @param label Short human-readable field name for the log lines.
             * @param landmark The landmark template; its own @c base is ignored in favour of @p base.
             * @param base The live, resolved struct base for this frame.
             * @param slot The caller-owned validity-bearing slot (typically @ref HealedSlot::seed_nominal'd first).
             * @param required True marks a missing target as a required-field failure: it escalates the log to Warning
             *                  under @ref HealEscalation::WarnRequired AND publishes @ref OffsetValidity::Invalid
             *                  rather than @ref OffsetValidity::Unverified.
             * @return The @ref heal_landmark result, or @ref ErrorCode::OffsetNotConfirmed when the heal resolved but
             *         its vtable image carried no stable generation across the evidence.
             */
            [[nodiscard]] Result<HealHit> heal_into(
                std::string_view label,
                const Landmark &landmark,
                Address base,
                HealedSlot &slot,
                bool required = true
            ) noexcept;

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
            void
            note_drift(std::string_view label, std::ptrdiff_t nominal_offset, std::ptrdiff_t healed_offset) noexcept;

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
         * @details On each @ref tick, every un-latched group that waited out the frame interval runs its heal work. A
         *          group that reports success latches and stops. The first realised drift across a scheduler's groups
         *          fires that scheduler's one layout-drift Warning (a CAS one-shot). A group's gate runs before the
         *          interval countdown, so an unconstructed target is skipped without spending the retry budget or
         *          logging.
         * @note Render-thread only, single-owner, move-only. The offset slots a group writes are the cross-thread
         *       channel, not the scheduler itself.
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
             * @return The scheduler, or @ref ErrorCode::InvalidArg for a zero interval or negative drift threshold.
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
             * @note An empty @p work is ignored (no group is registered). A re-entrant call from within @ref tick
             *       defers the new group to the next tick. The group counts as registered from this call, so
             *       @ref all_resolved reports false until it latches.
             */
            void add_group(Work work, Gate gate = {});

            /**
             * @brief Advances the scheduler by one frame: scans every un-latched, gate-passing, interval-due group.
             * @details Never throws. A work or gate callback that throws is treated as "did not resolve this frame".
             *          Deferred groups are adopted at tick exit. An adoption that failed on memory pressure is retried
             *          at the next tick's entry, so no tick count is lost.
             */
            void tick() noexcept;

            /**
             * @brief Returns true when every registered group has latched (vacuously true with no groups).
             * @details Covers groups still waiting in the deferred-adoption queue.
             */
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
