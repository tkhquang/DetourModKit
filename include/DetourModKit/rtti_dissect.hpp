#ifndef DETOURMODKIT_RTTI_DISSECT_HPP
#define DETOURMODKIT_RTTI_DISSECT_HPP

/**
 * @file rtti_dissect.hpp
 * @brief Reverse-direction RTTI dissection, self-healing offsets, and the frame-scheduled heal runner.
 * @details Every non-scheduler entry point reaches foreign memory only through guarded reads and fails closed, except
 *          for the `[B-20]` re-arm fault that memory.hpp states. See docs/guides/rtti/rtti-self-heal.md.
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
        /** @brief Hard cap on a self-heal search radius in bytes per side. */
        inline constexpr std::size_t MAX_HEAL_WINDOW = 4096;

        /** @brief Hard cap on the number of landmarks in one @ref solve_fingerprint template. */
        inline constexpr std::size_t MAX_FINGERPRINT_LANDMARKS = 32;

        /** @brief Result of @ref identify_pointee_type for one slot. It is about 1 KiB. */
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
            /// true when the slot held a pointer to the object, dereferenced once.
            bool was_pointer = false;
            /// Length of the mangled name in @ref name_buf.
            std::uint16_t name_len = 0;
            /// Inline NUL-terminated copy of the mangled name, so no field points into a transient buffer.
            char name_buf[MAX_TYPE_NAME_LEN + 1] = {};

            /// Non-owning view of the mangled name held in @ref name_buf.
            [[nodiscard]] std::string_view name() const noexcept { return std::string_view(name_buf, name_len); }
        };

        /**
         * @brief Reverse-RTTI-identify the object a pointer slot refers to.
         * @details Tries a pointer-to-object first, then a direct object base. @c was_pointer reports the shape that
         *          resolved and does not impose module locality.
         * @param out Receives the identification. Its contents are unspecified after a false return.
         * @return false on a null or low slot, an unreadable slot, or when neither shape resolves.
         */
        [[nodiscard]] bool identify_pointee_type(Address slot_addr, PointeeType &out) noexcept;

        /**
         * @brief Typed form of @ref identify_pointee_type, which equals @c has_value() of this call.
         * @return A value on resolve. @ref ErrorCode::BadSlotAddress reports a null or low slot.
         *         @ref ErrorCode::UnreadableSlot reports a faulted, null, or low slot value. @ref ErrorCode::NoRtti
         *         reports that neither shape carried a verifiable COL, or that its name is empty, unreadable, or has
         *         no terminator inside its module. @p out is unspecified after an error.
         */
        [[nodiscard]] Result<void> identify_pointee_typed(Address slot_addr, PointeeType &out) noexcept;

        /** @brief A probe slot address: an @ref Address or nullptr. Wrap a raw pointer or integer in `Address{...}`. */
        template <typename T>
        concept SlotAddress = std::convertible_to<T, Address>;

        /**
         * @brief Reverse-RTTI-identify the first of several candidate slots that resolves.
         * @details Probes @p candidate, then @p fallbacks in declaration order, and stops at the first resolve.
         * @param out Receives the identification of the first slot that resolves. It is reset to a default PointeeType
         *            when every candidate fails.
         * @return A value on the first resolve, or the error of @p candidate when every candidate fails.
         */
        template <SlotAddress... Fallbacks>
        [[nodiscard]] Result<void>
        identify_pointee_type_or(Address candidate, PointeeType &out, Fallbacks... fallbacks) noexcept
        {
            Result<void> primary = identify_pointee_typed(candidate, out);
            if (primary)
            {
                return {};
            }
            const bool any = (identify_pointee_typed(static_cast<Address>(fallbacks), out).has_value() || ...);
            if (any)
            {
                return {};
            }
            // The last probe can leave out half-written.
            out = PointeeType{};
            return primary;
        }

        /** @brief One slot from a @ref reverse_scan_block sweep that resolved to a real RTTI type. */
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
         * @details Walks @p slot_count slots from @p start, @p stride bytes apart, and appends a @ref LabeledSlot in
         *          slot order for every slot that @ref identify_pointee_type resolves. A zero @p stride means
         *          sizeof(std::uintptr_t). A (slot_count * stride) span that overflows counts as an empty block.
         * @return Number of slots appended to @p out. If a reallocation of @p out throws, the sweep stops and returns
         *         the count appended so far.
         * @warning Allocates (grows @p out) and runs the syscall-heavy prelude per slot. Use it at init time or in
         *          tooling, never on the hot path.
         */
        [[nodiscard]] std::size_t reverse_scan_block(
            Address start,
            std::size_t slot_count,
            std::vector<LabeledSlot> &out,
            std::size_t stride = sizeof(std::uintptr_t)
        ) noexcept;

        /**
         * @brief Byte-length form of @ref reverse_scan_block.
         * @details Equals reverse_scan_block(start, byte_len / stride, out, stride), with the same zero-stride rule.
         */
        [[nodiscard]] std::size_t reverse_scan_block_bytes(
            Address start,
            std::size_t byte_len,
            std::vector<LabeledSlot> &out,
            std::size_t stride = sizeof(std::uintptr_t)
        ) noexcept;

        /**
         * @brief Slot shape, and for @ref CompleteObject the subobject position, that a self-heal landmark requires.
         * @details Under multiple inheritance, every base subobject's COL names the same most-derived type. An
         *          @ref ObjectBase or @ref Any heal can therefore match a secondary base and report a shifted offset.
         */
        enum class Indirection : std::uint8_t
        {
            /// Match only slots that held a pointer-to-object.
            PointerToObject = 0,
            /// Match only a direct object base at any subobject, a multiple-inheritance secondary base too.
            ObjectBase = 1,
            /// Match either shape. If capture and heal can straddle a DLL boundary, use it.
            Any = 2,
            /** @brief Match only a direct object base with COL.offset == 0. Prefer it under multiple inheritance. */
            CompleteObject = 3
        };

        /**
         * @brief Consumer-owned, serializable record of a field of a known type near a known offset in a struct.
         * @details @ref expected_mangled must name a type that stays stable across patches. A rename fails closed with
         *          @ref ErrorCode::HealNoMatch.
         */
        struct Landmark
        {
            /// Resolved ASLR runtime struct base, filled at call time and never persisted.
            Address base{};
            /// Last known field offset within @ref base.
            std::ptrdiff_t nominal_offset = 0;
            /// Search radius per side in bytes, at most MAX_HEAL_WINDOW.
            std::size_t window = 0x40;
            /// MSVC mangled name to match, byte-exact on the most-derived name.
            std::string expected_mangled;
            /// Required slot shape.
            Indirection indirection = Indirection::PointerToObject;
            /// Probe step and candidate alignment. Zero means 8.
            std::size_t stride = sizeof(std::uintptr_t);
            /// Consulted only by @ref solve_fingerprint. A required landmark must match.
            bool required = true;
        };

        /** @brief Successful self-heal outcome from @ref heal_landmark. */
        struct HealHit
        {
            /// slot_addr - base: the field offset to use (== nominal_offset on no drift).
            std::ptrdiff_t healed_offset = 0;
            /// Address of the slot that matched.
            Address slot_addr{};
            /// Resolved object base behind the slot.
            Address object_addr{};
            /// Resolved vtable of the matched object.
            Address vtable{};
            /// Matched COL.offset. For a direct object, its complete object is at @ref healed_offset minus this value.
            std::uint32_t col_offset = 0;
            /// Shape of the matched slot.
            bool was_pointer = false;
        };

        /**
         * @brief Self-heal one field offset after a layout shift.
         * @details Checks the nominal slot (@c base + @c nominal_offset of @p lm) first. An unchanged offset returns
         *          at once and never trips the ambiguity test. On a nominal miss, the call scans the +/- @c window
         *          grid nearest-first in @c stride steps. It returns the uniquely nearest slot that resolves through
         *          @ref identify_pointee_type, satisfies @c indirection, and byte-equals @c expected_mangled.
         * @return The healed offset and match details. @ref ErrorCode::BadDescriptor reports a malformed landmark
         *         before any read: a low @c base, an empty or oversized name, an unknown @c indirection, or a @c window
         *         over MAX_HEAL_WINDOW. A nominal address outside the user-mode window also counts as malformed.
         *         @ref ErrorCode::HealNoMatch reports that no slot matched. @ref ErrorCode::HealAmbiguous reports that
         *         both the @c +d and @c -d slots match at the nearest match distance.
         * @warning Fail-wrong hazard: a strictly nearer same-typed decoy, or a secondary base, wins silently with a
         *          wrong offset. @ref ErrorCode::HealAmbiguous fires only for an exact +/- tie. For a crowded window,
         *          use @ref solve_fingerprint, @ref Indirection::CompleteObject, or a narrower @c window.
         * @note Init-time or re-heal-on-miss only, not per frame: each probe runs the syscall-heavy prelude up to
         *       twice. Allocates nothing.
         */
        [[nodiscard]] Result<HealHit> heal_landmark(const Landmark &lm) noexcept;

        /** @brief Successful outcome from @ref solve_fingerprint. */
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
         * @details Finds the single uniform delta in [-window_bytes, +window_bytes], in sizeof(std::uintptr_t) steps.
         *          At that delta, every required landmark at @p base + @c nominal_offset + delta reverse-resolves to
         *          its type and shape. Optional landmarks (@c required == false) only break ties between such deltas.
         * @param base Struct base for every probe. The landmarks' own @c base fields are ignored.
         * @param fp Landmark template. Each landmark's @c window and @c stride are ignored.
         * @param window_bytes Largest uniform shift per side in bytes, at most MAX_HEAL_WINDOW.
         * @return The recovered delta. @ref ErrorCode::BadDescriptor reports, before any memory read, an empty or
         *         over-cap span or no required landmark. It also reports, before any memory read, an oversized
         *         @p window_bytes, a malformed landmark, a duplicate @c nominal_offset, or a low @p base.
         *         @ref ErrorCode::HealNoMatch reports that no delta satisfied every required landmark.
         *         @ref ErrorCode::HealAmbiguous reports that two or more nonzero deltas tie for the most optional
         *         matches. A zero-drift delta that satisfies every required landmark wins a top-score tie outright, but
         *         a strictly higher optional score at any delta still wins.
         * @warning Init-time only: the probe count is (2 * window_bytes / 8 + 1) * fp.size() prelude walks. Allocates
         *          nothing.
         */
        [[nodiscard]] Result<FingerprintHit>
        solve_fingerprint(Address base, std::span<const Landmark> fp, std::size_t window_bytes) noexcept;

        /** @brief One landmark's heal outcome in a drift report, derived from its @ref heal_landmark result. */
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
            /// Failure code in @ref ErrorCategory::Rtti, meaningful only when @ref ok is false.
            ErrorCode error{ErrorCode::Ok};
        };

        /**
         * @brief Heals a set of landmarks and writes a per-landmark drift report.
         * @details Runs @ref heal_landmark on each landmark in order. Each landmark must have its @c base filled in.
         *          The call adds no reads over the individual heals and allocates nothing.
         * @param out Destination, parallel to @p landmarks.
         * @return The number of entries written: @c min(landmarks.size(), out.size()).
         */
        [[nodiscard]] std::size_t heal_report(std::span<const Landmark> landmarks, std::span<DriftEntry> out) noexcept;

        /** @brief Whether a healed-offset value can be consumed, and how strongly. */
        enum class OffsetValidity : std::uint8_t
        {
            /// A required heal missed. The retained value is not confirmed and has no established image generation.
            Invalid = 0,
            /** @brief An optional miss retained a nominal that is only usable as a hint. */
            Unverified = 1,
            /// A heal resolved the offset with a nonzero image generation.
            Confirmed = 2
        };

        /** @brief Consistent snapshot of a healed-offset slot: value, image generation, and validity. */
        struct HealedOffset
        {
            /** @brief The offset, meaningful for consumption only when validity is Confirmed. */
            std::ptrdiff_t value = 0;
            /// @ref rtti::image_generation of the resolved vtable's image. Invalid and Unverified snapshots carry 0.
            std::uint64_t generation = 0;
            /// Whether @ref value can be consumed.
            OffsetValidity validity = OffsetValidity::Invalid;

            /// True only when the value is Confirmed and carries a nonzero image generation.
            [[nodiscard]] bool usable() const noexcept
            {
                return validity == OffsetValidity::Confirmed && generation != 0;
            }
        };

        /**
         * @brief Validity-bearing cross-thread channel for one healed offset.
         * @details A consumer never blocks the producer or accepts a torn value. Hold it at a stable address.
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

            /** @brief Seeds the slot with a nominal offset as @ref OffsetValidity::Unverified with generation 0. */
            void seed_nominal(std::ptrdiff_t nominal) noexcept;

            /**
             * @brief Publishes a snapshot atomically. Single producer only.
             * @details A non-Confirmed state gets generation 0. Confirmed with generation 0 becomes Invalid.
             */
            void publish(std::ptrdiff_t value, std::uint64_t generation, OffsetValidity validity) noexcept;

            /// Returns a consistent snapshot, or Invalid if bounded retries cannot observe one.
            [[nodiscard]] HealedOffset load() const noexcept;

            /**
             * @brief Returns the offset only when it is @ref OffsetValidity::Confirmed.
             * @return The value, or @ref ErrorCode::OffsetNotConfirmed when validity or generation is absent.
             * @note Callback-safe: a bounded seqlock read, with no allocation, lock, or I/O.
             * @warning For mutation authorization tied to a module mapping, use the generation-checking overload.
             */
            [[nodiscard]] Result<std::ptrdiff_t> authorized() const noexcept;

            /**
             * @brief Returns the offset only when it is Confirmed and still tied to @p current_generation.
             * @param current_generation A nonzero, current @ref rtti::image_generation of the resolved type's module.
             * @return The value, or @ref ErrorCode::OffsetNotConfirmed when the slot is not Confirmed or its generation
             *         is zero or differs from @p current_generation.
             */
            [[nodiscard]] Result<std::ptrdiff_t> authorized(std::uint64_t current_generation) const noexcept;

        private:
            // Single-producer seqlock: even = stable, odd = write in progress. The sequence fences order the payload.
            std::atomic<std::uint32_t> m_seq{0};
            std::atomic<std::ptrdiff_t> m_value{0};
            std::atomic<std::uint64_t> m_generation{0};
            std::atomic<std::uint8_t> m_validity{static_cast<std::uint8_t>(OffsetValidity::Invalid)};
        };

        /** @brief Log-severity policy a @ref HealScheduler applies to a landmark that does not resolve in a scan. */
        enum class HealEscalation : std::uint8_t
        {
            /// A required landmark that stays unresolved logs at Warning. An optional miss stays at Debug. The default.
            WarnRequired = 0,
            /// Every miss (required or optional) stays at Debug.
            Quiet = 1
        };

        /** @brief Tunables for a @ref HealScheduler. */
        struct HealConfig
        {
            /** @brief Frames between retry scans of an un-latched group, which retries with no cap until it latches. */
            std::uint32_t interval_frames = 30;
            /**
             * @brief A realized drift whose absolute delta exceeds this value fires the one-shot layout-drift Warning.
             *        The default 0 warns on any nonzero drift.
             */
            std::ptrdiff_t drift_warn_threshold = 0;
            /// Log-severity policy for a landmark that does not resolve during a scan.
            HealEscalation escalate = HealEscalation::WarnRequired;
        };

        class HealScheduler;

        /**
         * @brief Per-scan heal context that a @ref HealScheduler passes to a group's work callback.
         * @details A transient view over the scheduler's state, valid only during the callback. Do not store it.
         */
        class HealRun
        {
        public:
            HealRun(const HealRun &) = delete;
            HealRun &operator=(const HealRun &) = delete;
            HealRun(HealRun &&) = delete;
            HealRun &operator=(HealRun &&) = delete;

            /**
             * @brief Heal one landmark from a live base and publish the result to a caller-owned offset slot.
             * @details Runs @ref heal_landmark at @p base in place of the @c base of @p landmark. Only a resolved
             *          offset is stored, and a miss leaves @p slot untouched. The call logs confirmation, drift, or
             *          failure, with @p label as the field name.
             * @param required Whether an unresolved miss escalates to Warning under @ref HealEscalation::WarnRequired.
             * @return The @ref heal_landmark result.
             * @warning A raw atomic carries no validity, so a required miss leaves a consumable nominal. This form is
             *          for read-only use. For writes or hooks, use the @ref HealedSlot overload.
             */
            [[nodiscard]] Result<HealHit> heal_into(
                std::string_view label,
                const Landmark &landmark,
                Address base,
                std::atomic<std::ptrdiff_t> &slot,
                bool required = true
            ) noexcept;

            /**
             * @brief Validity-bearing form of @ref heal_into that publishes {value, generation, validity} to @p slot.
             * @details A resolve publishes Confirmed with the nonzero image generation that brackets the re-established
             *          evidence. Any miss retains the value but publishes Invalid when @p required or Unverified when
             *          optional, so @ref HealedSlot::authorized rejects it.
             * @param required Also escalates a miss log to Warning under @ref HealEscalation::WarnRequired.
             * @return The @ref heal_landmark result, or @ref ErrorCode::OffsetNotConfirmed when the heal resolved but
             *         the vtable image generation was absent or changed, or the evidence changed.
             */
            [[nodiscard]] Result<HealHit> heal_into(
                std::string_view label,
                const Landmark &landmark,
                Address base,
                HealedSlot &slot,
                bool required = true
            ) noexcept;

            /**
             * @brief Report a drift that a group recovered itself, for example through @ref solve_fingerprint.
             * @details The one-shot Warning and the per-field Info line then fire as for @ref heal_into. After a group
             *          stores its shifted offsets, call it once per moved field. A zero delta logs a nominal
             *          confirmation at Debug and fires no Warning.
             */
            void
            note_drift(std::string_view label, std::ptrdiff_t nominal_offset, std::ptrdiff_t healed_offset) noexcept;

        private:
            friend class HealScheduler;
            HealRun(const HealConfig &config, std::atomic<bool> &drift_warned) noexcept
                : m_config(config), m_drift_warned(drift_warned)
            {
            }

            // Fires the one-shot drift Warning when |delta| exceeds the threshold and this call wins the CAS latch.
            void warn_drift_once(std::string_view label, std::ptrdiff_t delta) noexcept;

            const HealConfig &m_config;
            std::atomic<bool> &m_drift_warned;
        };

        /**
         * @brief Frame-driven runner for a set of independently latched self-heal groups.
         * @details The first drift over @c drift_warn_threshold fires the scheduler's one layout-drift Warning.
         * @note Render-thread only, single owner. The offset slots a group writes are the cross-thread channel, not
         *       the scheduler.
         */
        class HealScheduler
        {
        public:
            /// Cheap per-frame precondition. A false result skips the group silently and does not spend the interval.
            using Gate = std::move_only_function<bool()>;
            /// A group's heal work. A true result latches the group. A false result retries at the next interval.
            using Work = std::move_only_function<bool(HealRun &)>;

            /**
             * @brief Constructs a scheduler with @p config.
             * @return The scheduler, @ref ErrorCode::InvalidArg for a zero interval or a negative drift threshold, or
             *         @ref ErrorCode::OutOfMemory when the allocation fails.
             */
            [[nodiscard]] static Result<HealScheduler> start(HealConfig config = {}) noexcept;

            HealScheduler(HealScheduler &&) noexcept;
            HealScheduler &operator=(HealScheduler &&) noexcept;
            HealScheduler(const HealScheduler &) = delete;
            HealScheduler &operator=(const HealScheduler &) = delete;
            ~HealScheduler() noexcept;

            /**
             * @brief Registers an independently latched heal group.
             * @param work The group's heal work, run on the configured interval while un-latched.
             * @param gate Optional per-frame precondition (see @ref Gate), run before the interval countdown.
             * @return @ref ErrorCode::OutOfMemory when the registration allocation fails, with the scheduler unchanged.
             * @note An empty @p work is ignored (no group is registered, reported as success). A re-entrant call from
             *       within @ref tick defers the new group to the next tick. A registered group counts from this call,
             *       so @ref all_resolved reports false until it latches.
             * @note Setup/control-plane only: registration can allocate and mutate scheduler state.
             */
            [[nodiscard]] Result<void> add_group(Work work, Gate gate = {}) noexcept;

            /**
             * @brief Advances the scheduler by one frame: scans every un-latched, gate-passing, interval-due group.
             * @details A work or gate callback that throws counts as "did not resolve this frame". Deferred groups are
             *          adopted at tick exit. An adoption that failed on memory pressure is retried at the next tick's
             *          entry, so no tick count is lost.
             */
            void tick() noexcept;

            /** @brief Returns true when every registered group latched, deferred groups too, or when none exists. */
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
