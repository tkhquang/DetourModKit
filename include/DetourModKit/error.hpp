#ifndef DETOURMODKIT_ERROR_HPP
#define DETOURMODKIT_ERROR_HPP

/**
 * @file error.hpp
 * @brief The single error idiom for the v4 surface: ErrorCode, Error, and Result<T>.
 * @details v3 carried eight separate per-operation error enums (one per subsystem) plus a parallel family of
 *          `*_error_to_string` helpers, and mixed three return idioms (bool, std::optional, std::expected) across the
 *          API. v4 collapses the error-returning core onto one currency: a fallible operation on the Result-bearing
 *          surfaces (memory, scan, resolve, anchor, manifest, and the hook core) returns `Result<T>` (an alias for
 *          `std::expected<T, Error>`), an `Error` is a trivially copyable record carrying one `ErrorCode` plus two
 *          raw context slots, and a single `DMK_TRY` / `DMK_TRY_VOID` pair propagates failures without the
 *          `has_value()` dance ever appearing at a call site. The error model is two-tier, not uniform: deliberately
 *          best-effort and query surfaces stay outside this currency by design -- the RTTI query API, config
 *          load/reload/bind (fail-soft to registered defaults), and EventDispatcher return `bool` / `std::optional` /
 *          `void` and never surface an `Error`.
 *
 *          The eight domain enums are folded into one `ErrorCode` rather than reduced to a handful of generic codes:
 *          every distinguishing enumerator survives, so a consumer that needed to tell `TargetPrologueUnsafe` from
 *          `ReentrantCallRejected` still can. To recover the lost-by-collapse "which subsystem?" axis, the category
 *          is encoded in the high byte of each enumerator's value, so `category(code)` is a constexpr shift with no
 *          side table to keep in sync, and a raw code surviving into a log line or crash dump still names its
 *          subsystem.
 */

#include "DetourModKit/defines.hpp"

#include <cstdint>
#include <expected>
#include <format>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace DetourModKit
{
    /**
     * @enum ErrorCategory
     * @brief The subsystem an ErrorCode belongs to, recovered from the high byte of its value.
     * @details The category is the coarse "who failed" axis that the eight-enum collapse would otherwise erase. It is
     *          kept deliberately at subsystem granularity (matching the v4 namespaces) so an error stays assertable
     *          and greppable by the module that raised it. New categories are appended with the next free high byte;
     *          existing values never move, so a category added later never renumbers the codes already shipped.
     */
    enum class ErrorCategory : std::uint8_t
    {
        /// Cross-cutting codes raised directly by the v4 surface (argument checks, OOM, patterns).
        General = 0x00,
        /// Inline / mid / VMT hooking (the former HookError).
        Hook = 0x01,
        /// AOB cascade, RIP-relative resolve, and string-xref resolution (the former scanner enums).
        Scan = 0x02,
        /// Guarded reads/writes and protection changes (the former MemoryError).
        Memory = 0x03,
        /// Reverse-RTTI identification and self-heal (the former IdentifyError / HealError).
        Rtti = 0x04,
        /// Drift-manifest serialize/parse (the former ManifestError).
        Manifest = 0x05,
        /// Session / bootstrap process lifecycle (start, single-instance gating, worker spawn).
        Lifecycle = 0x06
    };

    /**
     * @enum ErrorCode
     * @brief The single, flat superset of every v4 failure code, tagged by subsystem in its high byte.
     * @details Each block is based at `category << 8`, so the high byte names the subsystem (see ErrorCategory and
     *          category()) and the low byte is the ordinal within it. Most enumerators keep the exact name they had
     *          as a per-domain enum, so the collapse is a mechanical rename rather than a re-design. Two adjustments
     *          were forced by folding everything into one identifier space: the former HookError::SafetyHookError is
     *          spelled BackendFailed so no public name leaks the hooking backend, and the two heal codes that would
     *          have collided with scan codes carry a `Heal` prefix.
     */
    enum class ErrorCode : std::uint16_t
    {
        // General (0x00xx): cross-cutting codes the v4 surface raises directly
        /// Success sentinel; never stored in an Error that is actually surfaced as a failure.
        Ok = 0x0000,
        /// A factory/operation rejected its arguments (empty name, null target, empty ladder, ...).
        InvalidArg,
        /// An allocation failed; constructed without allocating so the noexcept batch seed can use it.
        OutOfMemory,
        /// An AOB pattern failed to parse or exceeded the inline-storage cap.
        BadPattern,
        /// A pointer-chain walk was handed a null root.
        NullChain,
        /// Last-resort code when no more specific one applies.
        Unknown,

        // Hook failures (0x01xx).
        /// The hook backend allocator could not be obtained.
        AllocatorNotAvailable = 0x0100,
        /// The target address to hook was null or unusable.
        InvalidTargetAddress,
        /// The supplied detour function pointer was null or unusable.
        InvalidDetourFunction,
        /// The trampoline out-pointer was null.
        InvalidTrampolinePointer,
        /// A hook with that name is already registered.
        HookAlreadyExists,
        /// No hook with that name is registered.
        HookNotFound,
        /// The manager is tearing down and rejects new operations.
        ShutdownInProgress,
        /// The underlying hooking backend reported a failure.
        BackendFailed,
        /// Enabling (arming) the hook failed.
        EnableFailed,
        /// Disabling the hook failed.
        DisableFailed,
        /// The hook was in a state that does not permit the requested operation.
        InvalidHookState,
        /// The object (e.g. VMT instance) was null or invalid.
        InvalidObject,
        /// No VMT hook is registered for that object.
        VmtHookNotFound,
        /// That VMT slot/method is already hooked.
        MethodAlreadyHooked,
        /// That VMT slot/method is not hooked.
        MethodNotFound,
        /// Another component in the process already hooked the target.
        TargetAlreadyHookedInProcess,
        /// A re-entrant call into the guarded path was rejected.
        ReentrantCallRejected,
        /// The target prologue could not be relocated safely.
        TargetPrologueUnsafe,
        /// The backend returned an unclassified error.
        UnknownError,
        /**
         * @brief The operation would have altered target bytes a newer layered hook on the same target still owns.
         * @details Refused without changing anything. Tear down or disable the newer layer first.
         */
        LayerConflict,
        /**
         * @brief Every mid-hook adapter is in use; no further mid hook can be installed until one is destroyed.
         * @details A mid hook needs one adapter from a fixed pool, because the backend's callback signature carries no
         *          user-data parameter and a distinct function is the only way to pass per-hook identity. Nothing was
         *          patched. Destroy a mid hook you no longer need, or hook fewer sites; inline and VMT hooks are
         *          unaffected.
         */
        MidHookCapacityExhausted,

        // Scan (0x02xx): cascade resolve + read_code_constant + RIP resolve + string xref
        /// No candidates were supplied to the cascade.
        EmptyCandidates = 0x0200,
        /// No cascade candidate matched the scanned scope.
        NoMatch,
        /// Every byte-candidate pattern failed to parse.
        AllPatternsInvalid,
        /// The prologue-recovery fallback pattern was too short to be unique.
        PrologueFallbackNotApplicable,
        /// The supplied module range was not a valid mapped image.
        InvalidRange,
        /// read_code_constant: the resolved site did not decode.
        DecodeFailed,
        /// read_code_constant: the operand was not the requested kind.
        UnexpectedShape,
        /// read_code_constant: the operand index was past the operand count.
        OperandOutOfRange,
        /// RIP resolve: the input pointer was null.
        NullInput,
        /// RIP resolve: the opcode prefix was not found in the search region.
        PrefixNotFound,
        /// RIP resolve: the search region was too small to hold the displacement.
        RegionTooSmall,
        /// RIP resolve: the displacement bytes could not be read.
        UnreadableDisplacement,
        /// RIP resolve: the resolved target was not a plausible address.
        ImplausibleTarget,
        /// String xref: the query text was empty.
        EmptyQuery,
        /// String xref: the literal was not found in any readable page.
        StringNotFound,
        /// String xref: the literal occurs more than once.
        StringAmbiguous,
        /// String xref: no recognized RIP-relative reference resolves to it.
        NoReference,
        /// String xref: more than one instruction references it.
        AmbiguousReference,
        /// String xref: no prologue within the enclosing-function back-scan window.
        FunctionNotFound,
        /// String xref: no pointer-slot store of the loaded pointer follows the reference.
        StoreNotFound,
        /// Prologue recovery found a unique site, but identity confirmation rejected it or was missing.
        PrologueIdentityRejected,
        /// Export resolve: the module's export directory holds no name matching the requested export (or has none).
        ExportNotFound,
        /// Export resolve: the export is a forwarder to another module (a "Dll.Func" string, not code); fails closed.
        ExportForwarded,
        /**
         * @brief A bounded-jump pattern spent its backtracking work budget, so the traversal stopped short.
         * @details Distinct from NoMatch: the scan proved nothing about the unvisited positions. Add a literal byte to
         *          the pattern's leading segment, or narrow the scope, then retry.
         */
        BudgetExceeded,
        /**
         * @brief A page-gated sweep skipped a region that faulted mid-scan, so its occurrence count is a lower bound.
         * @details Distinct from NoMatch: a match (or a duplicate that would have made the result ambiguous) may live
         *          in the skipped bytes. Caused by a concurrent decommit or reprotect of the scanned range.
         */
        IncompleteScan,
        /**
         * @brief The scan could not prove its result unique because query-owned storage may participate in it.
         * @details Raised by a readable-page scan whose scope is not confined to one mapped image or one reserved
         *          allocation: DMK cannot discover caller-retained copies of the query bytes, so a match in that scope
         *          is not authoritative. Confine the scope, scan Pages::Executable, or supply those copies as
         *          exclusions. Also raised when more exclusion spans are declared than the bounded set holds after
         *          merging, which would leave some query storage visible to the sweep; declare fewer, or narrow the
         *          scope so fewer of them are in range.
         */
        NotAuthoritative,
        /// String xref: the query text is not well-formed UTF-8, or it violates the embedded-NUL policy.
        MalformedQueryText,
        /**
         * @brief Prologue recovery rebuilt a usable hook shape, but it matched more than one executable site.
         * @details Distinct from NoMatch and PrologueFallbackNotApplicable: the rebuilt pattern collides at two or
         *          more sites, so no single redirected target can be trusted. Sharpen the signature's surviving tail.
         */
        PrologueFallbackAmbiguous,

        // Memory (0x03xx): the former MemoryError plus the guarded-read and guarded-write fault codes
        /// The write target address was null.
        NullTargetAddress = 0x0300,
        /// The source byte span was null.
        NullSourceBytes,
        /// The operation size exceeded the permitted bound.
        SizeTooLarge,
        /// Changing page protection failed.
        ProtectionChangeFailed,
        /// Restoring the original page protection failed.
        ProtectionRestoreFailed,
        /// A guarded read faulted; Error::detail holds the faulting address, or the failing hop index for walk.
        ReadFaulted,
        /// A guarded in-place write faulted with no byte modified: the target was not writable. Error::detail holds it.
        WriteFaulted,
        /**
         * A guarded write faulted after a forward copy may already have modified a prefix of the span (it wrote into a
         * writable page, then faulted on an unwritable or unmapped byte further in). No byte outside the requested span
         * was written, but the target is in an indeterminate partial state. Error::detail holds the target address.
         */
        WriteMayBePartial,
        /// A code patch wrote its bytes but the instruction-cache flush failed. Error::detail holds the target address.
        InstructionFlushFailed,
        /**
         * A typed read encountered a byte pattern that is not a valid object representation of the requested type (for
         * example a foreign byte other than 0 or 1 decoded through @ref memory::read_bool). No value was formed.
         * Error::detail holds the source address.
         */
        InvalidRepresentation,

        // Rtti (0x04xx): the former IdentifyError + HealError
        /// The slot address was null or below the user-mode floor; no read was attempted.
        BadSlotAddress = 0x0400,
        /// The slot read faulted, or the qword held a null/low value.
        UnreadableSlot,
        /// The slot resolved to neither a pointer-to-object nor a direct object.
        NoRtti,
        /// The landmark/fingerprint descriptor is malformed; no memory was touched.
        BadDescriptor,
        /// No slot in the window resolved to the expected type.
        HealNoMatch,
        /// Equidistant slots both match, or fingerprint deltas tied.
        HealAmbiguous,
        /**
         * A validity-bearing healed-offset slot was not @ref rtti::OffsetValidity::Confirmed for consumption: a
         * required heal missed (the slot is Invalid) or an optional heal retained an unconfirmed nominal (Unverified).
         * The value must not authorize a mutation. Consult @ref rtti::HealedSlot::load for the retained value and its
         * validity.
         */
        OffsetNotConfirmed,

        // Manifest failures (0x05xx).
        /// The first non-blank line was not the manifest header.
        MissingHeader = 0x0500,
        /// A record line had the wrong field count or an unparseable field.
        MalformedLine,
        /// The file could not be opened (missing, locked, denied, or not a regular file).
        FileOpenFailed,
        /// The file opened but a subsequent write failed (disk full, an I/O error, or the stream went bad mid-write).
        FileWriteFailed,

        // Lifecycle (0x06xx): Session / bootstrap process lifecycle
        /// The running executable did not match ModInfo::game_process_name; the session declined to load (not a fault).
        ProcessMismatch = 0x0600,
        /// The single-instance mutex was already held: another load of this mod is already live in the process.
        InstanceAlreadyRunning,
        /// start()/bootstrap() was called while a Session is already active in this process (a caller sequencing bug).
        SessionAlreadyActive,
        /// A Win32 lifecycle operation failed; Error::detail = GetLastError().
        SystemCallFailed,
        /// A bootstrap lifecycle operation raced a concurrent attach, a drain, or the previous generation's retirement.
        SessionShutdownInProgress,
        /// Loader detach already claimed the bootstrap state, so a synchronous drain can no longer be guaranteed.
        SessionShutdownUnavailable,
        /**
         * @brief A synchronous bootstrap drain was refused because waiting would block.
         * @details Either the calling thread may hold the Windows loader lock, or it is the bootstrap worker itself,
         *          whose exit the drain would otherwise wait for.
         */
        SessionShutdownWouldBlock
    };

    /**
     * @brief Recovers the subsystem category of an ErrorCode from its high byte.
     * @param code The error code.
     * @return The ErrorCategory the code belongs to.
     * @details Pure shift, no lookup table: by construction every enumerator is based at `category << 8`, so the
     *          high byte IS the category. This is why the category can never drift out of sync with the codes.
     */
    [[nodiscard]] constexpr ErrorCategory category(ErrorCode code) noexcept
    {
        return static_cast<ErrorCategory>((static_cast<std::uint16_t>(code) >> 8) & 0xFFU);
    }

    /**
     * @brief Returns a short human-readable label for a subsystem category.
     * @param value The category.
     * @return A static string view; "unknown" for an out-of-range value.
     */
    [[nodiscard]] constexpr std::string_view to_string(ErrorCategory value) noexcept
    {
        switch (value)
        {
        case ErrorCategory::General:
            return "general";
        case ErrorCategory::Hook:
            return "hook";
        case ErrorCategory::Scan:
            return "scan";
        case ErrorCategory::Memory:
            return "memory";
        case ErrorCategory::Rtti:
            return "rtti";
        case ErrorCategory::Manifest:
            return "manifest";
        case ErrorCategory::Lifecycle:
            return "lifecycle";
        }
        return "unknown";
    }

    /**
     * @brief Returns the enumerator name for an ErrorCode.
     * @param code The error code.
     * @return A static string view naming the code; "UnknownCode" for an out-of-range value.
     * @details The single replacement for v3's eight `*_error_to_string` helpers. The trailing return handles a value
     *          outside the named set; every named enumerator is listed, so `-Wswitch` flags any future code added
     *          without a label here.
     */
    [[nodiscard]] constexpr std::string_view to_string(ErrorCode code) noexcept
    {
        switch (code)
        {
        case ErrorCode::Ok:
            return "Ok";
        case ErrorCode::InvalidArg:
            return "InvalidArg";
        case ErrorCode::OutOfMemory:
            return "OutOfMemory";
        case ErrorCode::BadPattern:
            return "BadPattern";
        case ErrorCode::NullChain:
            return "NullChain";
        case ErrorCode::Unknown:
            return "Unknown";
        case ErrorCode::AllocatorNotAvailable:
            return "AllocatorNotAvailable";
        case ErrorCode::InvalidTargetAddress:
            return "InvalidTargetAddress";
        case ErrorCode::InvalidDetourFunction:
            return "InvalidDetourFunction";
        case ErrorCode::InvalidTrampolinePointer:
            return "InvalidTrampolinePointer";
        case ErrorCode::HookAlreadyExists:
            return "HookAlreadyExists";
        case ErrorCode::HookNotFound:
            return "HookNotFound";
        case ErrorCode::ShutdownInProgress:
            return "ShutdownInProgress";
        case ErrorCode::BackendFailed:
            return "BackendFailed";
        case ErrorCode::EnableFailed:
            return "EnableFailed";
        case ErrorCode::DisableFailed:
            return "DisableFailed";
        case ErrorCode::InvalidHookState:
            return "InvalidHookState";
        case ErrorCode::InvalidObject:
            return "InvalidObject";
        case ErrorCode::VmtHookNotFound:
            return "VmtHookNotFound";
        case ErrorCode::MethodAlreadyHooked:
            return "MethodAlreadyHooked";
        case ErrorCode::MethodNotFound:
            return "MethodNotFound";
        case ErrorCode::TargetAlreadyHookedInProcess:
            return "TargetAlreadyHookedInProcess";
        case ErrorCode::ReentrantCallRejected:
            return "ReentrantCallRejected";
        case ErrorCode::TargetPrologueUnsafe:
            return "TargetPrologueUnsafe";
        case ErrorCode::UnknownError:
            return "UnknownError";
        case ErrorCode::LayerConflict:
            return "LayerConflict";
        case ErrorCode::MidHookCapacityExhausted:
            return "MidHookCapacityExhausted";
        case ErrorCode::EmptyCandidates:
            return "EmptyCandidates";
        case ErrorCode::NoMatch:
            return "NoMatch";
        case ErrorCode::AllPatternsInvalid:
            return "AllPatternsInvalid";
        case ErrorCode::PrologueFallbackNotApplicable:
            return "PrologueFallbackNotApplicable";
        case ErrorCode::PrologueFallbackAmbiguous:
            return "PrologueFallbackAmbiguous";
        case ErrorCode::InvalidRange:
            return "InvalidRange";
        case ErrorCode::DecodeFailed:
            return "DecodeFailed";
        case ErrorCode::UnexpectedShape:
            return "UnexpectedShape";
        case ErrorCode::OperandOutOfRange:
            return "OperandOutOfRange";
        case ErrorCode::NullInput:
            return "NullInput";
        case ErrorCode::PrefixNotFound:
            return "PrefixNotFound";
        case ErrorCode::RegionTooSmall:
            return "RegionTooSmall";
        case ErrorCode::UnreadableDisplacement:
            return "UnreadableDisplacement";
        case ErrorCode::ImplausibleTarget:
            return "ImplausibleTarget";
        case ErrorCode::EmptyQuery:
            return "EmptyQuery";
        case ErrorCode::StringNotFound:
            return "StringNotFound";
        case ErrorCode::StringAmbiguous:
            return "StringAmbiguous";
        case ErrorCode::NoReference:
            return "NoReference";
        case ErrorCode::AmbiguousReference:
            return "AmbiguousReference";
        case ErrorCode::FunctionNotFound:
            return "FunctionNotFound";
        case ErrorCode::StoreNotFound:
            return "StoreNotFound";
        case ErrorCode::PrologueIdentityRejected:
            return "PrologueIdentityRejected";
        case ErrorCode::ExportNotFound:
            return "ExportNotFound";
        case ErrorCode::ExportForwarded:
            return "ExportForwarded";
        case ErrorCode::BudgetExceeded:
            return "BudgetExceeded";
        case ErrorCode::IncompleteScan:
            return "IncompleteScan";
        case ErrorCode::NotAuthoritative:
            return "NotAuthoritative";
        case ErrorCode::MalformedQueryText:
            return "MalformedQueryText";
        case ErrorCode::NullTargetAddress:
            return "NullTargetAddress";
        case ErrorCode::NullSourceBytes:
            return "NullSourceBytes";
        case ErrorCode::SizeTooLarge:
            return "SizeTooLarge";
        case ErrorCode::ProtectionChangeFailed:
            return "ProtectionChangeFailed";
        case ErrorCode::ProtectionRestoreFailed:
            return "ProtectionRestoreFailed";
        case ErrorCode::ReadFaulted:
            return "ReadFaulted";
        case ErrorCode::WriteFaulted:
            return "WriteFaulted";
        case ErrorCode::WriteMayBePartial:
            return "WriteMayBePartial";
        case ErrorCode::InstructionFlushFailed:
            return "InstructionFlushFailed";
        case ErrorCode::InvalidRepresentation:
            return "InvalidRepresentation";
        case ErrorCode::BadSlotAddress:
            return "BadSlotAddress";
        case ErrorCode::UnreadableSlot:
            return "UnreadableSlot";
        case ErrorCode::NoRtti:
            return "NoRtti";
        case ErrorCode::BadDescriptor:
            return "BadDescriptor";
        case ErrorCode::HealNoMatch:
            return "HealNoMatch";
        case ErrorCode::HealAmbiguous:
            return "HealAmbiguous";
        case ErrorCode::OffsetNotConfirmed:
            return "OffsetNotConfirmed";
        case ErrorCode::MissingHeader:
            return "MissingHeader";
        case ErrorCode::MalformedLine:
            return "MalformedLine";
        case ErrorCode::FileOpenFailed:
            return "FileOpenFailed";
        case ErrorCode::FileWriteFailed:
            return "FileWriteFailed";
        case ErrorCode::ProcessMismatch:
            return "ProcessMismatch";
        case ErrorCode::InstanceAlreadyRunning:
            return "InstanceAlreadyRunning";
        case ErrorCode::SessionAlreadyActive:
            return "SessionAlreadyActive";
        case ErrorCode::SystemCallFailed:
            return "SystemCallFailed";
        case ErrorCode::SessionShutdownInProgress:
            return "SessionShutdownInProgress";
        case ErrorCode::SessionShutdownUnavailable:
            return "SessionShutdownUnavailable";
        case ErrorCode::SessionShutdownWouldBlock:
            return "SessionShutdownWouldBlock";
        }
        return "UnknownCode";
    }

    /**
     * @struct Error
     * @brief One trivially copyable failure record: a code plus a static label and two raw context slots.
     * @details Construction never allocates (it is a plain aggregate of a code, a pointer, and two integers), so an
     *          Error can be built on the noexcept batch/seed paths where throwing would terminate. Only message()
     *          allocates. `where` is a `const char *` by strong convention pointing at a static/literal label (e.g.
     *          "scan", "hook::inline"); that documents intent and keeps the common case dangle-free, but it is a
     *          convention the type cannot enforce -- a caller can still hand it a pointer into a transient buffer, so
     *          callers must pass only static storage. The two raw slots carry whatever context the raising code
     *          documents for that ErrorCode (an address, a failing-hop index, a candidate ordinal, ...).
     */
    struct Error
    {
        /// The failure code; its category names the raising subsystem.
        ErrorCode code{ErrorCode::Ok};
        /// Static/literal label for the raising site, e.g. "scan" or "hook::inline".
        const char *where{""};
        /// Primary raw context: address / instruction pointer / failing-hop index, per the code's documentation.
        std::uintptr_t detail{0};
        /// Secondary raw context: candidate index / slot / hop count, per the code's documentation.
        std::uint32_t extra{0};

        /**
         * @brief Composes a single greppable diagnostic line for this error.
         * @return A formatted string: "[category] CodeName @ where (detail=0x..., extra=...)".
         * @details The ONLY allocating member. It is never called on a hot path: the noexcept batch paths pre-seed
         *          their result vectors with Errors and only ever format them later, off the critical section.
         */
        [[nodiscard]] std::string message() const;
    };

    // The non-allocating-construction guarantee that the noexcept batch seed relies on is only true while Error stays
    // trivially copyable (a code, a pointer, two integers). Pin it so a future field with a non-trivial type cannot
    // silently make Error construction able to throw.
    static_assert(std::is_trivially_copyable_v<Error>, "Error must stay trivially copyable for the noexcept seed.");

    /**
     * @brief The single fallible-return alias: a value of type @p T on success, an Error on failure.
     * @tparam T The success type; use `Result<void>` for an operation that returns no value.
     */
    template <class T> using Result = std::expected<T, Error>;

    inline std::string Error::message() const
    {
        // Keep the distinctive code name whole and lead with the subsystem so the line stays both human-readable and
        // greppable by category. An empty/absent label is rendered as "?" rather than a blank gap.
        const char *label = (where != nullptr && where[0] != '\0') ? where : "?";
        return std::format("[{}] {} @ {} (detail=0x{:X}, extra={})", to_string(category(code)), to_string(code), label,
                           detail, extra);
    }

} // namespace DetourModKit

/**
 * @def DMK_TRY
 * @brief Unwraps a `Result<T>` into @p var, or returns the propagated Error from the enclosing function.
 * @details The value-binding propagation form. It expands to three statements (bind the result, short-circuit on
 *          failure, move the value out), so it must live in a braced block -- it cannot be the sole controlled
 *          statement of a brace-less `if`/`for`. The enclosing function must itself return a `Result`/`std::expected`
 *          so the `std::unexpected(...)` early-return is well-formed. The temporary is named after @p var, so several
 *          DMK_TRY uses in one scope never collide.
 */
#define DMK_TRY(var, expr)                                                                                             \
    auto &&_r_##var = (expr);                                                                                          \
    if (!_r_##var)                                                                                                     \
        return std::unexpected(_r_##var.error());                                                                      \
    auto var = std::move(*_r_##var)

/**
 * @def DMK_TRY_VOID
 * @brief Propagates the Error from a `Result<void>` (or any Result whose value is discarded), binding nothing.
 * @details The void form has no value to bind, so it wraps its temporary in a `do { ... } while (0)` block. That
 *          gives it a fresh scope (so nested uses never collide on the temporary name) and makes the whole macro a
 *          single statement that IS safe as the controlled statement of a brace-less `if`/`for`. As with DMK_TRY, the
 *          enclosing function must return a `Result`/`std::expected`.
 */
#define DMK_TRY_VOID(expr)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        auto &&_r = (expr);                                                                                            \
        if (!_r)                                                                                                       \
            return std::unexpected(_r.error());                                                                        \
    } while (0)

#endif // DETOURMODKIT_ERROR_HPP
