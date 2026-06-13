#ifndef DETOURMODKIT_ANCHORS_HPP
#define DETOURMODKIT_ANCHORS_HPP

#include "DetourModKit/memory.hpp"
#include "DetourModKit/scanner.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace DetourModKit
{
    /**
     * @namespace DetourModKit::Anchors
     * @brief One declarative registry over DMK's self-healing backends.
     * @details Each magic constant a mod depends on is declared once, with the kind of anchor it is and the inputs that
     *          backend needs, then the whole table is resolved at init and reported uniformly. This replaces a
     *          scattered wall of hand-maintained constexpr offsets and per-call-site resolvers with a single
     *          self-validating table.
     *
     *          Scope: the registry unifies the backends whose inputs resolve from
     *          a module range alone -- a vtable by RTTI name (@ref Rtti::vtable_for_type), a global address by AOB/RIP
     *          cascade (@ref Scanner::resolve_cascade_in_module), an in-code constant (@ref
     *          Scanner::read_code_constant), and the instruction (or function) that references a string literal (@ref
     *          Scanner::find_string_xref)
     *          -- plus a pinned @ref AnchorKind::Manual literal. RTTI pointer-field offset healing (@ref
     *          Rtti::heal_landmark) is intentionally not a registry
     *          kind: it needs a runtime struct base resolved from another anchor,
     *          so it is driven directly once that base is known. @ref AnchorKind::CallArgHome is reserved for a future
     *          prologue-dataflow backend and is not yet resolvable. @ref AnchorKind::Quorum layers corroboration over
     *          those single-signal backends: it accepts a target only when two independent sub-anchors resolve and
     *          agree. Any backend-resolved anchor may also carry an optional @ref AnchorValidator that screens the
     *          resolved value and can reject it (fail closed).
     *
     *          Re-heal on a validation miss is the caller's loop: a resolved value is cached in the returned @ref
     *          ResolvedAnchor, and when a later validation fails the caller simply re-runs @ref resolve on that anchor
     *          (resolution is idempotent and side-effect-free).
     */
    namespace Anchors
    {
        /**
         * @enum AnchorKind
         * @brief Which backend resolves an anchor.
         * @details Backend preference order, most update-resilient first, when a target can be expressed more than one
         *          way: @ref StringXref (an immutable string literal survives game patches far better than surrounding
         *          code) > @ref VtableIdentity (an RTTI class name is stable) > @ref RipGlobal (a unique AOB/RIP
         *          cascade) > @ref CodeOperand (an in-code immediate, the most patch-sensitive). @ref Quorum over two
         *          of those raises confidence further by demanding corroboration. @ref Manual is the last resort: a
         *          pinned literal cannot self-heal and is surfaced as at-risk in a quality report. Prefer the highest
         *          backend a target supports.
         */
        enum class AnchorKind : std::uint8_t
        {
            /// Rtti::vtable_for_type -> a class vtable address by name.
            VtableIdentity,
            /// Scanner cascade -> an absolute address (Direct or RipRelative candidates).
            RipGlobal,
            /// Scanner::read_code_constant -> an in-code immediate/displacement value.
            CodeOperand,
            /// Scanner::find_string_xref -> the instruction (or function) referencing a string literal.
            StringXref,
            /// A pinned literal; surfaced as at-risk in a report.
            Manual,
            /// Reserved for a future prologue-dataflow backend; not yet resolvable.
            CallArgHome,
            /// Two independent sub-anchors that must resolve and agree before acceptance.
            Quorum
        };

        /**
         * @brief Number of @ref AnchorKind enumerators.
         * @details Sizes per-kind tables (e.g. a backend deny-list) so a new kind forces a compile-time update via the
         *          static_assert below rather than silently leaving the new kind out of range.
         */
        inline constexpr std::size_t ANCHOR_KIND_COUNT = 7;
        static_assert(static_cast<std::size_t>(AnchorKind::Quorum) + 1 == ANCHOR_KIND_COUNT,
                      "ANCHOR_KIND_COUNT is out of sync with AnchorKind; update it when adding a kind.");

        /**
         * @enum QuorumMatch
         * @brief How an @ref AnchorKind::Quorum decides its two signals agree.
         */
        enum class QuorumMatch : std::uint8_t
        {
            /// Both sub-anchors must resolve to the identical value.
            ExactValue,
            /// Resolved values may differ by at most @ref Anchor::quorum_tolerance.
            WithinTolerance
        };

        /**
         * @enum AnchorStatus
         * @brief Outcome of resolving an anchor.
         */
        enum class AnchorStatus : std::uint8_t
        {
            /// Not yet attempted.
            Unresolved,
            /// Resolved; @ref ResolvedAnchor::value is valid.
            Resolved,
            /// The backend failed (fail closed: no value).
            Failed,
            /// The kind has no backend yet (CallArgHome).
            Unsupported,
            /**
             * @brief A @ref AnchorKind::Quorum whose two sub-anchors are not independent evidence.
             * @details Covers the same object used twice, two pinned @ref AnchorKind::Manual literals, or the same
             *          backend and inputs decoded twice. Rejected before agreement is even considered, so a dependent
             *          pair can never masquerade as corroboration.
             */
            QuorumNotIndependent
        };

        /**
         * @brief Optional caller-supplied post-resolve predicate.
         * @details Invoked after a backend resolves an anchor, with the resolved value interpreted exactly as @ref
         *          ResolvedAnchor::value for the anchor's @ref AnchorKind (a vtable/global address, a code constant, or
         *          a string-xref site). Returning false fails the anchor closed:
         *          @ref resolve reports @ref AnchorStatus::Failed and resets the value to 0, identical to a backend
         *          miss, so a caller re-heals by re-running @ref resolve.
         * @param value The backend-resolved value (per-kind, as @ref ResolvedAnchor::value).
         * @param context The opaque @ref Anchor::validator_context pointer, verbatim.
         * @return true to accept the resolution; false to reject it (fail closed).
         * @note Must be noexcept; it runs on the side-effect-free resolution path and may be re-run on a validation
         *       miss. Not invoked for @ref AnchorKind::Manual (unless @ref Anchor::validate_manual is set) or @ref
         *       AnchorKind::CallArgHome.
         */
        using AnchorValidator = bool (*)(std::int64_t value, const void *context) noexcept;

        /**
         * @struct Anchor
         * @brief One declarative anchor entry. The active input fields depend on @ref kind.
         * @details Names and cascades are non-owning views into caller storage (typically a static table), mirroring
         *          the existing @ref Scanner::AddrCandidate / @ref Rtti::Landmark table style.
         */
        struct Anchor
        {
            /// Human-readable id, echoed in the result.
            std::string_view label;
            /// Which backend resolves this anchor.
            AnchorKind kind = AnchorKind::Manual;

            /// VtableIdentity: the class mangled name.
            std::string_view mangled;

            /// RipGlobal / CodeOperand: the cascade.
            std::span<const Scanner::AddrCandidate> site;
            /// CodeOperand.
            Scanner::OperandKind operand_kind = Scanner::OperandKind::Immediate;
            /// CodeOperand: visible operand index.
            std::uint8_t operand_index = 0;
            /// CodeOperand: 0 = decoded width.
            std::uint8_t byte_width = 0;

            /// StringXref: the string literal content.
            std::string_view xref_text;
            /// StringXref: how the string is stored.
            Scanner::StringEncoding xref_encoding = Scanner::StringEncoding::Utf8;
            /// StringXref: instruction, enclosing function, or cached global pointer slot.
            Scanner::XrefReturn xref_return = Scanner::XrefReturn::ReferencingInstruction;
            /// StringXref: match a trailing NUL.
            bool xref_require_terminator = true;
            /// StringXref: keep lea/mov scan and add Zydis rarer shapes.
            bool xref_broad_match = false;

            /// Manual: the pinned literal.
            std::int64_t manual_value = 0;

            /**
             * @brief Optional fail-closed post-resolve check. nullptr (default) accepts whatever the backend resolves,
             *        preserving the unguarded behaviour.
             * @details Example domain checks a caller can wire here: the target lies in an expected sub-range, a
             *          displacement points into .rdata, or the byte at the site is a plausible prologue (@ref
             *          Scanner::is_likely_function_prologue). Not invoked for @ref AnchorKind::Manual (unless @ref
             *          validate_manual is set) or @ref AnchorKind::CallArgHome, whose statuses are fixed by definition.
             *          For @ref AnchorKind::Quorum it runs once on the corroborated value after both sub-anchors agree.
             */
            AnchorValidator validator = nullptr;

            /// Opaque pointer passed verbatim to @ref validator; nullptr if unused.
            const void *validator_context = nullptr;

            /**
             * @brief Run @ref validator for a @ref AnchorKind::Manual anchor too.
             * @details Default false keeps the pinned-literal exemption (a Manual always resolves to its literal
             *          unchecked). Lets a caller assert a domain invariant on a hand-pinned constant (e.g. the literal
             *          lies in an expected range) without changing the behaviour of any anchor that leaves the flag at
             *          its default.
             */
            bool validate_manual = false;

            /**
             * @brief Reject a backend-resolvable anchor that carries no @ref validator (fail closed: status Failed).
             *        Default false preserves the unguarded behaviour.
             * @details Opt-in hardening for function targets: an anchor that resolves to a function/global address with
             *          no domain check is treated as unverified. Applies to the backend kinds (VtableIdentity,
             *          RipGlobal, CodeOperand, StringXref) and to a Manual that opted in via @ref validate_manual. A
             *          @ref AnchorKind::Quorum is exempt because its two-signal corroboration is itself the
             *          verification.
             */
            bool require_validator = false;

            /// Quorum: first independent sub-anchor (non-owning).
            const Anchor *quorum_a = nullptr;
            /// Quorum: second independent sub-anchor (non-owning).
            const Anchor *quorum_b = nullptr;
            /// Quorum: how the two values must agree.
            QuorumMatch quorum_match = QuorumMatch::ExactValue;
            /// Quorum: max |first - second| when WithinTolerance.
            std::int64_t quorum_tolerance = 0;
        };

        /**
         * @struct ResolvedAnchor
         * @brief Result of resolving an @ref Anchor: the cached value plus status.
         * @details @ref value carries the resolved quantity interpreted per kind:
         *          a vtable or global address (cast to uintptr_t), a code constant, the referencing-instruction (or
         *          enclosing-function) address of a string xref (cast to uintptr_t), or the manual literal. Meaningful
         *          only when @ref status is @ref AnchorStatus::Resolved.
         */
        struct ResolvedAnchor
        {
            std::string_view label;
            AnchorKind kind = AnchorKind::Manual;
            AnchorStatus status = AnchorStatus::Unresolved;
            std::int64_t value = 0;
        };

        /**
         * @brief Resolves one anchor against a module range.
         * @details Dispatches to the backend for @c anchor.kind and maps its typed failure to @ref
         *          AnchorStatus::Failed. @ref AnchorKind::Manual always resolves to its literal; @ref
         *          AnchorKind::CallArgHome always reports @ref AnchorStatus::Unsupported. A backend-resolved value is
         *          passed through @c anchor.validator (when set) and fails closed if the validator rejects it.
         *          Idempotent: call again to re-resolve after a validation miss.
         * @note @ref AnchorKind::Quorum resolves its two sub-anchors through this same function and accepts only when
         *       both resolve and agree under @ref Anchor::quorum_match; a null sub-anchor, a sub-anchor that is itself
         *       a @ref AnchorKind::Quorum (nesting is not allowed), or a disagreement fails closed. Recursion is
         *       bounded to one level. Before resolving, the two sub-anchors are checked for independence: the same
         *       object used twice, two @ref AnchorKind::Manual literals, or the same backend and inputs decoded twice
         *       report @ref AnchorStatus::QuorumNotIndependent and are never treated as corroboration.
         * @param anchor The anchor declaration.
         * @param range Module image to resolve in. Defaults to the host EXE.
         * @return The resolved value and status.
         */
        [[nodiscard]] ResolvedAnchor resolve(const Anchor &anchor,
                                             Memory::ModuleRange range = Memory::host_module_range());

        /**
         * @brief Resolves a whole anchor table in one pass (the drift report).
         * @param anchors The declarative anchor table.
         * @param out Destination, parallel to @p anchors. At most @c out.size() entries are written.
         * @param range Module image to resolve in. Defaults to the host EXE.
         * @return The number of entries written: @c min(anchors.size(), out.size()).
         */
        [[nodiscard]] std::size_t resolve_all(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                              Memory::ModuleRange range = Memory::host_module_range());

        /**
         * @struct AnchorQuality
         * @brief Robustness summary over a resolved anchor table -- the manifest quality diagnostic.
         * @details A single-pass tally that lets a consumer see, at a glance, how update-resilient a manifest is: how
         *          many anchors resolved, how many failed, how many are pinned literals that cannot self-heal, and how
         *          many are corroborated by a quorum. Derived purely from a @ref ResolvedAnchor report; it does not
         *          re-resolve anything.
         */
        struct AnchorQuality
        {
            /// Anchors examined (the report length).
            std::size_t total = 0;
            /// status == @ref AnchorStatus::Resolved.
            std::size_t resolved = 0;
            /// status == @ref AnchorStatus::Failed.
            std::size_t failed = 0;
            /// status == @ref AnchorStatus::Unsupported.
            std::size_t unsupported = 0;
            /// status == @ref AnchorStatus::QuorumNotIndependent.
            std::size_t not_independent = 0;
            /// kind == @ref AnchorKind::Manual (a pinned literal that cannot self-heal, regardless of status).
            std::size_t manual_at_risk = 0;
            /// kind == @ref AnchorKind::Quorum and status == @ref AnchorStatus::Resolved (the strongest evidence).
            std::size_t corroborated = 0;
        };

        /**
         * @brief Summarizes a resolved report into a robustness diagnostic.
         * @details Single pass over @p report tallying by status and kind. Does not re-resolve and performs no
         *          allocation; safe to call from any context.
         * @param report The parallel @ref ResolvedAnchor output from @ref resolve_all (or a hand-built report).
         * @return Aggregate counts describing how update-resilient the manifest is.
         */
        [[nodiscard]] AnchorQuality assess_quality(std::span<const ResolvedAnchor> report) noexcept;

        /**
         * @brief Human-readable mapping for @ref AnchorStatus.
         * @param status The status.
         * @return A string view describing the status.
         */
        [[nodiscard]] std::string_view anchor_status_to_string(AnchorStatus status) noexcept;
    } // namespace Anchors
} // namespace DetourModKit

#endif // DETOURMODKIT_ANCHORS_HPP
