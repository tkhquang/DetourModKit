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
     * @details Each magic constant a mod depends on is declared once, with the
     *          kind of anchor it is and the inputs that backend needs, then the
     *          whole table is resolved at init and reported uniformly. This
     *          replaces a scattered wall of hand-maintained constexpr offsets and
     *          per-call-site resolvers with a single self-validating table.
     *
     *          Scope: the registry unifies the backends whose inputs resolve from
     *          a module range alone -- a vtable by RTTI name (@ref Rtti::vtable_for_type),
     *          a global address by AOB/RIP cascade (@ref Scanner::resolve_cascade_in_module),
     *          an in-code constant (@ref Scanner::read_code_constant), and the instruction
     *          (or function) that references a string literal (@ref Scanner::find_string_xref)
     *          -- plus a pinned @ref AnchorKind::Manual literal. RTTI pointer-field offset
     *          healing (@ref Rtti::heal_landmark) is intentionally not a registry
     *          kind: it needs a runtime struct base resolved from another anchor,
     *          so it is driven directly once that base is known. @ref AnchorKind::CallArgHome
     *          is reserved for a future prologue-dataflow backend and is not yet
     *          resolvable.
     *
     *          Re-heal on a validation miss is the caller's loop: a resolved value
     *          is cached in the returned @ref ResolvedAnchor, and when a later
     *          validation fails the caller simply re-runs @ref resolve on that
     *          anchor (resolution is idempotent and side-effect-free).
     */
    namespace Anchors
    {
        /**
         * @enum AnchorKind
         * @brief Which backend resolves an anchor.
         */
        enum class AnchorKind : std::uint8_t
        {
            VtableIdentity, ///< Rtti::vtable_for_type -> a class vtable address by name.
            RipGlobal,      ///< Scanner cascade -> an absolute address (Direct or RipRelative candidates).
            CodeOperand,    ///< Scanner::read_code_constant -> an in-code immediate/displacement value.
            StringXref,     ///< Scanner::find_string_xref -> the instruction (or function) referencing a string literal.
            Manual,         ///< A pinned literal; surfaced as at-risk in a report.
            CallArgHome     ///< Reserved for a future prologue-dataflow backend; not yet resolvable.
        };

        /**
         * @enum AnchorStatus
         * @brief Outcome of resolving an anchor.
         */
        enum class AnchorStatus : std::uint8_t
        {
            Unresolved,  ///< Not yet attempted.
            Resolved,    ///< Resolved; @ref ResolvedAnchor::value is valid.
            Failed,      ///< The backend failed (fail closed: no value).
            Unsupported  ///< The kind has no backend yet (CallArgHome).
        };

        /**
         * @struct Anchor
         * @brief One declarative anchor entry. The active input fields depend on
         *        @ref kind.
         * @details Names and cascades are non-owning views into caller storage
         *          (typically a static table), mirroring the existing
         *          @ref Scanner::AddrCandidate / @ref Rtti::Landmark table style.
         */
        struct Anchor
        {
            std::string_view label;                  ///< Human-readable id, echoed in the result.
            AnchorKind kind = AnchorKind::Manual;    ///< Which backend resolves this anchor.

            std::string_view mangled;                ///< VtableIdentity: the class mangled name.

            std::span<const Scanner::AddrCandidate> site; ///< RipGlobal / CodeOperand: the cascade.
            Scanner::OperandKind operand_kind = Scanner::OperandKind::Immediate; ///< CodeOperand.
            std::uint8_t operand_index = 0;          ///< CodeOperand: visible operand index.
            std::uint8_t byte_width = 0;             ///< CodeOperand: 0 = decoded width.

            std::string_view xref_text;              ///< StringXref: the string literal content.
            Scanner::StringEncoding xref_encoding =
                Scanner::StringEncoding::Utf8;       ///< StringXref: how the string is stored.
            Scanner::XrefReturn xref_return =
                Scanner::XrefReturn::ReferencingInstruction; ///< StringXref: instruction vs function.
            bool xref_require_terminator = true;     ///< StringXref: match a trailing NUL.
            bool xref_broad_match = false;           ///< StringXref: keep lea/mov scan and add Zydis rarer shapes.

            std::int64_t manual_value = 0;           ///< Manual: the pinned literal.
        };

        /**
         * @struct ResolvedAnchor
         * @brief Result of resolving an @ref Anchor: the cached value plus status.
         * @details @ref value carries the resolved quantity interpreted per kind:
         *          a vtable or global address (cast to uintptr_t), a code constant,
         *          the referencing-instruction (or enclosing-function) address of a
         *          string xref (cast to uintptr_t), or the manual literal.
         *          Meaningful only when @ref status is @ref AnchorStatus::Resolved.
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
         * @details Dispatches to the backend for @c anchor.kind and maps its typed
         *          failure to @ref AnchorStatus::Failed. @ref AnchorKind::Manual
         *          always resolves to its literal; @ref AnchorKind::CallArgHome
         *          always reports @ref AnchorStatus::Unsupported. Idempotent: call
         *          again to re-resolve after a validation miss.
         * @param anchor The anchor declaration.
         * @param range Module image to resolve in. Defaults to the host EXE.
         * @return The resolved value and status.
         */
        [[nodiscard]] ResolvedAnchor resolve(
            const Anchor &anchor, Memory::ModuleRange range = Memory::host_module_range());

        /**
         * @brief Resolves a whole anchor table in one pass (the drift report).
         * @param anchors The declarative anchor table.
         * @param out Destination, parallel to @p anchors. At most @c out.size()
         *            entries are written.
         * @param range Module image to resolve in. Defaults to the host EXE.
         * @return The number of entries written: @c min(anchors.size(), out.size()).
         */
        [[nodiscard]] std::size_t resolve_all(
            std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
            Memory::ModuleRange range = Memory::host_module_range());

        /**
         * @brief Human-readable mapping for @ref AnchorStatus.
         * @param status The status.
         * @return A string view describing the status.
         */
        [[nodiscard]] std::string_view anchor_status_to_string(AnchorStatus status) noexcept;
    } // namespace Anchors
} // namespace DetourModKit

#endif // DETOURMODKIT_ANCHORS_HPP
