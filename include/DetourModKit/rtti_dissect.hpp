#ifndef DETOURMODKIT_RTTI_DISSECT_HPP
#define DETOURMODKIT_RTTI_DISSECT_HPP

#include "DetourModKit/rtti.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    /**
     * @namespace DetourModKit::Rtti
     * @brief Reverse-direction RTTI dissection and self-healing offsets.
     * @details The forward walker in rtti.hpp answers "what type is the object
     *          behind this vtable?". This header answers the inverse, slot-first
     *          questions a mod actually asks against a drifting game binary:
     *
     *          - @ref identify_pointee_type -- "what object does this pointer
     *            slot refer to, and what is its RTTI type?" (the per-slot
     *            primitive).
     *          - @ref reverse_scan_block -- "RTTI-label every pointer slot in
     *            this struct" (allocating, init-time/tooling triage).
     *          - @ref heal_landmark / @ref heal_offset -- "a small patch shifted
     *            the layout; find where the field of type T moved to" (the
     *            self-healing offset resolver).
     *          - @ref solve_fingerprint -- "several fields co-moved; find the
     *            single uniform shift that satisfies every landmark" (rigid
     *            multi-field drift recovery).
     *
     *          Every entry point is noexcept and fails closed. All reads go
     *          through the same SEH-guarded, module-bound-checked prelude the
     *          forward walker uses, so an unmapped page, a forged COL, or an
     *          ambiguous match is a clean failure return, never a fault and
     *          never a silently-wrong offset. Matching compares MSVC mangled
     *          bytes exactly; no UnDecorateSymbolName runs on any path. Scope is
     *          x64 MSVC.
     */
    namespace Rtti
    {
        /// Hard cap on a self-heal search radius (bytes per side). Bounds the
        /// worst-case probe count so an accidental SIZE_MAX window cannot hang.
        inline constexpr std::size_t MAX_HEAL_WINDOW = 4096;

        /// Hard cap on the number of landmarks in one @ref solve_fingerprint
        /// template.
        inline constexpr std::size_t MAX_FINGERPRINT_LANDMARKS = 32;

        /**
         * @struct PointeeType
         * @brief Result of reverse-identifying the object behind one slot.
         * @details Populated by @ref identify_pointee_type on success. Carries
         *          the resolved vtable and COL coordinates, the object base, the
         *          complete-object base recovered from COL.offset, and an
         *          inline copy of the mangled name so the struct is
         *          self-contained (no pointer into transient buffers). The
         *          struct is ~1 KiB because of @ref name_buf; the hot self-heal
         *          path reuses a single stack instance, while
         *          @ref reverse_scan_block embeds it by value (tooling only).
         */
        struct PointeeType
        {
            std::uintptr_t vtable = 0;        ///< Resolved vtable pointer.
            std::uintptr_t col_addr = 0;      ///< COL the vtable points back to.
            std::uintptr_t td_addr = 0;       ///< TypeDescriptor base.
            std::uintptr_t name_addr = 0;     ///< Mangled-name buffer (td_addr + 0x10).
            std::uintptr_t object_base = 0;   ///< Start of the resolved (sub)object.
            std::uintptr_t complete_obj = 0;  ///< object_base - col_offset (underflow-clamped).
            std::uintptr_t pointer_value = 0; ///< Raw qword read at the probed slot.
            std::uint32_t col_offset = 0;     ///< COL.offset (+0x04): this vtable's offset in the complete object.
            bool was_pointer = false;         ///< true when the slot held a pointer-to-object (deref'd once).
            std::uint16_t name_len = 0;       ///< Length of the mangled name in @ref name_buf.
            char name_buf[Rtti::MAX_TYPE_NAME_LEN + 1] = {}; ///< NUL-terminated mangled name.

            /// Non-owning view of the mangled name held in @ref name_buf.
            [[nodiscard]] std::string_view name() const noexcept
            {
                return std::string_view(name_buf, name_len);
            }
        };

        /**
         * @brief Reverse-RTTI-identify the object a pointer slot refers to.
         * @details Reads the qword at @p slot_addr, then accepts whichever of
         *          two shapes resolves through the verified COL prelude:
         *          - pointer-to-object (tried first): the slot value is a
         *            pointer to an object; dereference once and resolve the
         *            pointee's vtable. @c was_pointer is set and
         *            @c object_base is the pointee.
         *          - direct object base: the slot itself is the object, its
         *            value is the vtable. @c was_pointer is clear and
         *            @c object_base is @p slot_addr.
         *
         *          Classifying by resolvability rather than by module
         *          membership means an object whose vtable lives in a different
         *          DLL than the struct still resolves; @c was_pointer becomes a
         *          report, not a gate.
         * @param slot_addr Address of the pointer-sized slot to probe.
         * @param out Receives the identification on success. On a false return
         *            its contents are unspecified, so callers must check the
         *            return before reading it.
         * @return true when a real RTTI type resolved, false on a null/low slot,
         *         an unreadable slot, or neither shape resolving.
         */
        [[nodiscard]] bool identify_pointee_type(std::uintptr_t slot_addr,
                                                 PointeeType &out) noexcept;

        /**
         * @struct LabeledSlot
         * @brief One slot from a @ref reverse_scan_block sweep that resolved to
         *        a real RTTI type.
         */
        struct LabeledSlot
        {
            std::uintptr_t slot_addr = 0; ///< Address of the resolved slot.
            std::size_t slot_index = 0;   ///< Zero-based index of the slot in the swept block.
            PointeeType type;             ///< Reverse-identified type (carries its own name buffer).
        };

        /**
         * @brief RTTI-label a block of pointer-sized slots.
         * @details Walks @p slot_count slots from @p start (stepping by
         *          @p stride) and appends a @ref LabeledSlot for every slot that
         *          @ref identify_pointee_type resolves. This is the dump/triage
         *          face of the feature ("tell me the RTTI type of every pointer
         *          field in this struct").
         * @param start Address of the first slot.
         * @param slot_count Number of slots to probe.
         * @param out Receives the resolved slots, appended in slot order.
         * @param stride Byte distance between adjacent slots. Zero is treated as
         *               sizeof(std::uintptr_t).
         * @return Number of slots appended to @p out.
         * @warning ALLOCATES (grows @p out) and calls the syscall-heavy prelude
         *          per slot. Init-time / tooling only -- never the hot path.
         * @note The (slot_count * stride) span is overflow-guarded; a malformed
         *       tuple is treated as an empty block and returns 0. If a
         *       reallocation of @p out throws, the sweep stops early and returns
         *       the count appended so far (the noexcept contract holds).
         */
        [[nodiscard]] std::size_t reverse_scan_block(std::uintptr_t start,
                                                     std::size_t slot_count,
                                                     std::vector<LabeledSlot> &out,
                                                     std::size_t stride = sizeof(std::uintptr_t)) noexcept;

        /**
         * @brief Byte-length overload of @ref reverse_scan_block.
         * @details Equivalent to reverse_scan_block(start, byte_len / stride,
         *          out, stride).
         * @param start Address of the first slot.
         * @param byte_len Length of the block in bytes.
         * @param out Receives the resolved slots, appended in slot order.
         * @param stride Byte distance between adjacent slots. Zero is treated as
         *               sizeof(std::uintptr_t).
         * @return Number of slots appended to @p out.
         */
        [[nodiscard]] std::size_t reverse_scan_block_bytes(std::uintptr_t start,
                                                           std::size_t byte_len,
                                                           std::vector<LabeledSlot> &out,
                                                           std::size_t stride = sizeof(std::uintptr_t)) noexcept;

        /**
         * @enum Indirection
         * @brief Slot shape a self-heal landmark requires of a matching slot.
         * @details Applied as a soft policy filter on top of
         *          @ref identify_pointee_type's resolvability classification.
         */
        enum class Indirection : std::uint8_t
        {
            PointerToObject, ///< Match only slots that held a pointer-to-object.
            ObjectBase,      ///< Match only slots that were a direct object base.
            Any              ///< Match either shape (use when capture and heal may straddle a DLL boundary).
        };

        /**
         * @enum HealError
         * @brief Reasons a self-heal resolve may fail. Every value fails closed.
         */
        enum class HealError : std::uint8_t
        {
            BadDescriptor, ///< The landmark/fingerprint is malformed; no memory was touched.
            NoMatch,       ///< No slot in the window resolved to the expected type.
            Ambiguous      ///< Equidistant slots both match (heal) or tied-score deltas (fingerprint).
        };

        /**
         * @struct Landmark
         * @brief A consumer-owned, serializable record of "a field of a known
         *        type lives near a known offset within a struct."
         * @details Recorded once and persisted (config). The persisted form
         *          carries @ref nominal_offset, @ref window, an owned copy of
         *          @ref expected_mangled, @ref indirection, @ref stride, and (for
         *          fingerprints) @ref required. @ref base is never persisted: it
         *          is an ASLR'd runtime address resolved fresh each session
         *          (typically from a Scanner cascade/AOB anchor or a live object
         *          pointer) and filled in at call time. The in-code common case
         *          is a @c static @c constexpr Landmark with a mangled string
         *          literal, mirroring the existing AddrCandidate cascade tables.
         * @note @ref expected_mangled must name a type that is stable across
         *       patches (a base/engine type, not a game-specific most-derived
         *       subtype), because matching is byte-exact on the most-derived
         *       name. A subtype rename defeats healing and fails closed via
         *       @ref HealError::NoMatch.
         */
        struct Landmark
        {
            std::uintptr_t base = 0;           ///< Resolved struct base. Filled at call time; never persisted.
            std::ptrdiff_t nominal_offset = 0; ///< Last known field offset within @ref base.
            std::size_t window = 0x40;         ///< Search radius per side in bytes (capped at MAX_HEAL_WINDOW).
            std::string_view expected_mangled; ///< MSVC mangled name to match. Aliases caller storage.
            Indirection indirection = Indirection::PointerToObject; ///< Required slot shape.
            std::size_t stride = sizeof(std::uintptr_t);            ///< Probe step (and candidate alignment). Zero -> 8.
            bool required = true; ///< Consulted only by @ref solve_fingerprint; a required landmark must match.
        };

        /**
         * @struct HealHit
         * @brief Successful self-heal outcome from @ref heal_landmark.
         */
        struct HealHit
        {
            std::ptrdiff_t healed_offset = 0; ///< slot_addr - base: the field offset to use (== nominal_offset on no drift).
            std::uintptr_t slot_addr = 0;     ///< Address of the matching slot.
            std::uintptr_t object_addr = 0;   ///< Resolved object base behind the slot.
            std::uintptr_t vtable = 0;        ///< Resolved vtable of the matched object.
            bool was_pointer = false;         ///< Shape of the matched slot.
        };

        /**
         * @brief Self-heal one field offset after a layout shift.
         * @details Checks the nominal slot (@c base + @c nominal_offset) first;
         *          an unchanged offset short-circuits and returns immediately, so
         *          an unpatched binary -- or one with a same-typed neighbour in
         *          the window -- never trips the ambiguity test. On a nominal
         *          miss it scans the +/- @c window grid (stepping by @c stride,
         *          so probes stay congruent to the nominal slot and never
         *          straddle a field), nearest-first, and returns the uniquely
         *          nearest matching slot. A slot matches when it resolves via
         *          @ref identify_pointee_type, satisfies @c indirection, and its
         *          most-derived mangled name byte-equals @c expected_mangled.
         * @param lm The landmark, with @c base filled in.
         * @return The healed offset and match details, or:
         *         - @ref HealError::BadDescriptor for a malformed landmark
         *           (low @c base, empty/oversized name, unknown @c indirection,
         *           @c window over MAX_HEAL_WINDOW, or a nominal address outside
         *           the user-mode window), before any read;
         *         - @ref HealError::NoMatch when no slot matched;
         *         - @ref HealError::Ambiguous when both the @c +d and @c -d slots
         *           at the nearest matching distance match (an irreducible tie).
         * @warning Init-time / re-heal-on-miss, not per-frame: each probe runs
         *          the syscall-heavy prelude up to twice. The window cap bounds
         *          the worst case. Allocates nothing (one reused stack
         *          @ref PointeeType).
         */
        [[nodiscard]] std::expected<HealHit, HealError> heal_landmark(const Landmark &lm) noexcept;

        /**
         * @brief Convenience wrapper over @ref heal_landmark returning just the
         *        healed byte offset.
         * @details Feeds straight into a @c std::span<const std::ptrdiff_t>
         *          pointer-chain API.
         * @param lm The landmark, with @c base filled in.
         * @return The healed offset, or std::nullopt on any failure.
         */
        [[nodiscard]] std::optional<std::ptrdiff_t> heal_offset(const Landmark &lm) noexcept;

        /**
         * @brief Human-readable mapping for @ref HealError.
         * @param e The error code.
         * @return A string view describing the error.
         */
        [[nodiscard]] std::string_view heal_error_to_string(HealError e) noexcept;

        /**
         * @struct FingerprintHit
         * @brief Successful outcome from @ref solve_fingerprint.
         */
        struct FingerprintHit
        {
            std::ptrdiff_t delta = 0;       ///< The single uniform byte shift applied to every landmark offset.
            std::size_t matched = 0;        ///< Required landmarks satisfied at @ref delta (equals the required count).
            std::size_t optional_matched = 0; ///< Optional landmarks also satisfied at @ref delta.
        };

        /**
         * @brief Rigid multi-field drift recovery.
         * @details Finds the single uniform delta in [-window_bytes,
         *          +window_bytes] (stepping by sizeof(std::uintptr_t)) such that
         *          every required landmark at @c base + @c nominal_offset +
         *          @c delta reverse-resolves to its type with its required
         *          shape. A dense window of same-typed neighbours that defeats a
         *          single @ref heal_landmark is structurally disambiguated here
         *          because one delta must fit the whole template at once.
         *          Optional landmarks (@c required == false) are scored only to
         *          break ties between deltas that satisfy every required
         *          landmark. Degenerates to a single-field solve when
         *          @p fp.size() == 1.
         * @param base Resolved struct base (the landmarks' own @c base fields are
         *             ignored; this one is used for every probe).
         * @param fp The landmark template. Each landmark's @c nominal_offset,
         *           @c expected_mangled, @c indirection, and @c required are
         *           consulted; @c window and @c stride are not (probing is a
         *           single shifted slot, not a per-landmark window).
         * @param window_bytes Maximum uniform shift to search per side, capped
         *                     at MAX_HEAL_WINDOW.
         * @return The recovered delta, or:
         *         - @ref HealError::BadDescriptor for an empty span, over-cap
         *           span, no required landmark, an oversized @p window_bytes, a
         *           malformed landmark, or a low @p base;
         *         - @ref HealError::NoMatch when no delta satisfied every
         *           required landmark;
         *         - @ref HealError::Ambiguous when two or more deltas tie for the
         *           most optional matches.
         * @warning Init-time only: the probe count is
         *          (2 * window_bytes / 8 + 1) * fp.size() prelude walks.
         *          Allocates nothing.
         */
        [[nodiscard]] std::expected<FingerprintHit, HealError>
        solve_fingerprint(std::uintptr_t base, std::span<const Landmark> fp,
                          std::size_t window_bytes) noexcept;

        /**
         * @struct DriftEntry
         * @brief One landmark's heal outcome, for a structured drift report.
         * @details The raw "what moved and by how much" record a consumer logs to
         *          a changelog or scans to spot a patch's re-layout at a glance.
         *          All fields are derived from an existing @ref heal_landmark
         *          result; this adds no new analysis.
         */
        struct DriftEntry
        {
            std::string_view name;             ///< Aliases the landmark's @c expected_mangled.
            std::ptrdiff_t nominal_offset = 0; ///< The landmark's last-known offset.
            std::ptrdiff_t healed_offset = 0;  ///< The resolved offset (valid only when @ref ok).
            std::ptrdiff_t delta = 0;          ///< healed_offset - nominal_offset (valid only when @ref ok).
            bool ok = false;                   ///< Whether the landmark healed.
            HealError error{};                 ///< Failure reason; meaningful only when @ref ok is false.
        };

        /**
         * @brief Heals a set of landmarks and writes a per-landmark drift report.
         * @details Runs @ref heal_landmark on each landmark in order and records
         *          the outcome (nominal, healed, delta, or the typed failure) into
         *          @p out. Each landmark must already have its @c base filled in,
         *          exactly as for a direct @ref heal_landmark call. This is a thin
         *          aggregation over the existing heal path: it performs no read the
         *          individual heals would not, and allocates nothing.
         * @param landmarks The landmarks to heal (each with @c base set).
         * @param out Destination, parallel to @p landmarks. At most
         *            @c out.size() entries are written.
         * @return The number of entries written: @c min(landmarks.size(),
         *         out.size()).
         */
        [[nodiscard]] std::size_t heal_report(std::span<const Landmark> landmarks,
                                              std::span<DriftEntry> out) noexcept;
    } // namespace Rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_RTTI_DISSECT_HPP
