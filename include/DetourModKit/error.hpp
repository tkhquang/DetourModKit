#ifndef DETOURMODKIT_ERROR_HPP
#define DETOURMODKIT_ERROR_HPP

/**
 * @file error.hpp
 * @brief Shared ErrorCode, Error, and Result<T> definitions.
 * @details Result-tier APIs return `Result<T>`, and DMK_TRY and DMK_TRY_VOID propagate its Error. Best-effort APIs
 *          return their own documented types, for example `bool`, `std::optional`, or `void`, and never an Error.
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
    /** @brief The subsystem of an ErrorCode, held in the high byte of its value. The category values are stable. */
    enum class ErrorCategory : std::uint8_t
    {
        /// Cross-cutting codes such as argument checks, allocation failures, and pattern errors.
        General = 0x00,
        /// Inline, mid-function, and VMT hooking.
        Hook = 0x01,
        /// AOB cascade, RIP-relative resolve, and string-xref resolution.
        Scan = 0x02,
        /// Guarded reads, writes, and protection changes.
        Memory = 0x03,
        /// Reverse-RTTI identification and self-heal.
        Rtti = 0x04,
        /// Manifest serialization and parsing.
        Manifest = 0x05,
        /// Session and bootstrap process lifecycle: start, single-instance gate, and worker spawn.
        Lifecycle = 0x06
    };

    /**
     * @brief The library-wide failure code, with its @ref ErrorCategory in the high byte.
     * @details Each category block starts at `category << 8`. Only the high byte is stable. The low byte follows
     *          declaration order, so a new enumerator renumbers every later member of its block. Branch on the
     *          enumerator, never on its numeric value. If a log, wire, or telemetry format needs a fixed value, write a
     *          versioned symbol for each enumerator.
     */
    enum class ErrorCode : std::uint16_t
    {
        // General (0x00xx).
        /// Success sentinel. An Error that reports a failure never holds it.
        Ok = 0x0000,
        /// A factory or operation rejected its arguments, for example an empty name, a null target, or an empty ladder.
        InvalidArg,
        /// An allocation failed.
        OutOfMemory,
        /// An AOB pattern failed to parse or exceeded the inline-storage cap.
        BadPattern,
        /// A pointer-chain walk received a null root.
        NullChain,
        /// Last-resort code when no more specific one applies.
        Unknown,

        // Hook (0x01xx).
        /// The hook backend allocator was not available.
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
        /// The manager is in teardown and rejects new operations.
        ShutdownInProgress,
        /// The hook backend reported a failure.
        BackendFailed,
        /// The hook failed to enable.
        EnableFailed,
        /// The hook failed to disable.
        DisableFailed,
        /// The hook was in a state that does not permit the requested operation.
        InvalidHookState,
        /// The object, for example a VMT instance, was null or invalid.
        InvalidObject,
        /// No VMT hook is registered for that object.
        VmtHookNotFound,
        /// That VMT slot/method is already hooked.
        MethodAlreadyHooked,
        /// That VMT slot/method is not hooked.
        MethodNotFound,
        /**
         * @brief This linked DMK instance already holds the target, and the install asked to refuse a duplicate.
         * @details The same-kit ledger reports it, with a scope of one linked archive, not the process. A hook that is
         *          created but not enabled also holds a record, so this code does not prove that the prologue is
         *          patched. Drop the prior handle, or clear Options::fail_if_already_hooked to layer on it. A pinned
         *          record (hook::Hook::release, or a teardown that failed to restore) belongs to no handle and is never
         *          erased. It refuses every later strict install on that address, also after the allocator reissues the
         *          address. A recorded target reports this code even after a foreign module patches it, because the
         *          ledger check runs before the @ref TargetAlreadyHookedByAnotherModule decode.
         */
        TargetAlreadyHookedByThisKit,
        /**
         * @brief The target's prologue already branches out of its own module, and the install asked to refuse.
         * @details The foreign-JMP decode reports it when the same-kit ledger has no record. A destination in no loaded
         *          module also counts, for example a detour in private trampoline memory. This kit owns nothing to
         *          drop, so the caller either layers on the target or abandons it.
         */
        TargetAlreadyHookedByAnotherModule,
        /// A re-entrant call into the guarded path was rejected.
        ReentrantCallRejected,
        /// The target prologue is not safe to relocate.
        TargetPrologueUnsafe,
        /// An unclassified hook error: an unmapped backend failure, or a failed hook gate acquisition.
        UnknownError,
        /** @brief Refused with no change: a newer layered hook owns the target bytes. Disable or tear it down first. */
        LayerConflict,
        /**
         * @brief Every mid-hook adapter in the fixed pool is in use, so nothing was patched.
         * @details Destroy an unneeded mid hook, or hook fewer sites. Inline and VMT hooks are unaffected.
         */
        MidHookCapacityExhausted,
        /// The hook module refuses mutation under its loader-lock precondition.
        LoaderLockActive,

        // Scan (0x02xx).
        /// No candidates were supplied to the cascade.
        EmptyCandidates = 0x0200,
        /// No cascade candidate matched the scanned scope.
        NoMatch,
        /// Every byte-candidate pattern failed to parse.
        AllPatternsInvalid,
        /// A Direct candidate existed, but none was safe to rebuild as a hooked prologue.
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
        /// RIP resolve: the displacement bytes were unreadable.
        UnreadableDisplacement,
        /// RIP resolve: the resolved target was not a plausible address.
        ImplausibleTarget,
        /** @brief RIP resolve: the last matched prefix resolved to a plausible, unreadable address in Error::detail. */
        UnreadableTarget,
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
        /// Export resolve: no usable export with the requested name. @ref scan::resolve_export lists the cases.
        ExportNotFound,
        /// Export resolve: the export forwards to another module as a "Dll.Func" string, not code. It fails closed.
        ExportForwarded,
        /**
         * @brief A bounded-jump pattern spent its backtracking work budget, so the traversal stopped short.
         * @details Distinct from NoMatch: the scan proved nothing about the unvisited positions. Before a retry, add a
         *          literal byte to the leading segment of the pattern, or narrow the scope.
         */
        BudgetExceeded,
        /**
         * @brief A page-gated sweep skipped a region, so its occurrence count is a lower bound.
         * @details Distinct from NoMatch: the skipped bytes can hold a match, or a duplicate that makes the result
         *          ambiguous. A concurrent decommit or reprotect of the scanned range causes it. So does a MinGW sweep
         *          with no guarded-read fault handler installed (@ref diagnostics::ScannerFaultEvent).
         */
        IncompleteScan,
        /**
         * @brief The scan did not prove its result unique, because query-owned storage can participate in it.
         * @details Raised under the Readable authority rule of @ref scan::Pages, which lists its remedies. Also raised
         *          when the merged exclusion spans overflow their bounded set. The overflow remedy is fewer declared
         *          spans or a narrower scope.
         */
        NotAuthoritative,
        /// String xref: the query text is not well-formed UTF-8, or it violates the embedded-NUL policy.
        MalformedQueryText,
        /**
         * @brief Prologue recovery rebuilt a usable hook shape, but it matched more than one executable site.
         * @details No single redirected target is trustworthy. Sharpen the surviving tail of the signature.
         */
        PrologueFallbackAmbiguous,
        /**
         * @brief The selected byte rung no longer resolves the decoded site at the fresh epoch.
         * @details The selector evidence is stale. Its physical span can fail to match, a bounded-gap result point can
         *          move, or a wildcarded RIP locator can resolve elsewhere.
         */
        EvidenceMismatch,

        // Memory (0x03xx).
        /// The write target address was null.
        NullTargetAddress = 0x0300,
        /// The source byte span was null.
        NullSourceBytes,
        /// The operation size exceeded the permitted bound.
        SizeTooLarge,
        /// The page protection change failed.
        ProtectionChangeFailed,
        /// The restore of the original page protection failed.
        ProtectionRestoreFailed,
        /**
         * @brief A guarded read faulted.
         * @details `Error::detail` holds the address of the fault, inside the requested span. For the small spans of a
         *          typed read, it is the first unreadable byte. A wide span can fault out of order in `memcpy`, so a
         *          later byte can be reported. A span refused before any access reports its start: below
         *          @ref memory::USERSPACE_PTR_MIN, an end past @ref memory::USERSPACE_PTR_MAX, or an end that wraps.
         *          The MinGW fallback, which validates through `VirtualQuery` without a fault, also reports the start.
         *          For @ref memory::walk, the field is the failing hop index, not an address.
         */
        ReadFaulted,
        /// A guarded write failed before it changed any byte. Error::detail holds the target address.
        WriteFaulted,
        /**
         * @brief A guarded write reached a writable page, then faulted on an unwritable or unmapped byte further in.
         * @details The changed prefix of the span has an unknown length and can be empty. A fixed-width store that
         *          straddles a writable and an unwritable page changes no byte but still reports this code. No byte
         *          outside the requested span changes. Treat the whole target as indeterminate. Error::detail holds the
         *          target address.
         */
        WriteMayBePartial,
        /// A code patch wrote its bytes but the instruction-cache flush failed. Error::detail holds the target address.
        InstructionFlushFailed,
        /**
         * @brief A typed read found bytes that are not a valid object representation of the requested type.
         * @details An example is a byte other than 0 or 1 for @ref memory::read_bool. No value was formed.
         *          Error::detail holds the source address.
         */
        InvalidRepresentation,
        /**
         * @brief The caller buffer or source span overlaps the target range, in either direction.
         * @details The copy primitives require disjoint half-open ranges and refuse an overlap before any byte moves.
         *          Error::detail holds the target address.
         */
        OverlappingRanges,

        // Rtti (0x04xx).
        /// The slot address was null or below the user-mode floor. No read was attempted.
        BadSlotAddress = 0x0400,
        /// The slot read faulted, or the qword held a null/low value.
        UnreadableSlot,
        /// The slot resolved to neither a pointer-to-object nor a direct object.
        NoRtti,
        /// The landmark/fingerprint descriptor is malformed. No memory was touched.
        BadDescriptor,
        /// No slot in the window resolved to the expected type.
        HealNoMatch,
        /// Equidistant slots both match, or fingerprint deltas tied.
        HealAmbiguous,
        /**
         * @brief A healed offset is not confirmed for use.
         * @details A required heal missed (Invalid), or an optional heal kept an unconfirmed nominal (Unverified).
         *          The HealedSlot form of @ref rtti::HealRun::heal_into also returns it when the image generation of a
         *          resolved heal is absent or changed, or its evidence changed. @ref rtti::HealedSlot::authorized also
         *          rejects a Confirmed slot with a zero or stale generation. The value must not authorize a mutation.
         *          @ref rtti::HealedSlot::load returns the retained value and its validity.
         */
        OffsetNotConfirmed,

        // Manifest (0x05xx).
        /// The `[manifest]` section or its `schema` key is absent, or the schema is unsupported.
        MissingHeader = 0x0500,
        /// A line, key, or value that @ref manifest::parse rejects, as manifest.hpp lists.
        MalformedLine,
        /// The file did not open or read, for example because it is missing, locked, denied, or not a regular file.
        FileOpenFailed,
        /// The file opened but a later write failed, for example on a full disk, an I/O error, or a failed stream.
        FileWriteFailed,
        /**
         * @brief Two section or key identities collide after case folding or exact/whitespace normalization.
         * @details The whole manifest fails before parsing or trust evaluation can observe an ambiguous contract.
         */
        ManifestIdentityCollision = 0x0504,
        /**
         * @brief A raw manifest frames a multi-line (heredoc) value unsafely.
         * @details The unsafe shapes are an unclosed block, an opener with an empty tag, and a first body line that is
         *          its own terminator. Checked serialization reports an unsafe source value as InvalidArg before it
         *          writes the value.
         */
        ManifestFramingUnsafe,

        // Lifecycle (0x06xx).
        /// The running executable did not match ModInfo::game_process_name. The session declined to load (not a fault).
        ProcessMismatch = 0x0600,
        /// The single-instance mutex was already held: another load of this mod is live in the process.
        InstanceAlreadyRunning,
        /// start()/bootstrap() was called while a Session is already active in this process (a caller sequencing bug).
        SessionAlreadyActive,
        /**
         * @brief A system lifecycle operation failed.
         * @details Error::detail holds GetLastError() unless the function that reports it documents another value.
         */
        SystemCallFailed,
        /// A bootstrap lifecycle operation raced a concurrent attach, a drain, or the previous generation's retirement.
        SessionShutdownInProgress,
        /// Loader detach already claimed the bootstrap state, so a synchronous drain can no longer be guaranteed.
        SessionShutdownUnavailable,
        /**
         * @brief A synchronous bootstrap drain was refused because the wait can block.
         * @details The caller possibly holds the loader lock, or it is the bootstrap worker that the drain waits for.
         */
        SessionShutdownWouldBlock
    };

    /** @brief Returns the @ref ErrorCategory in the high byte of @p code. */
    [[nodiscard]] constexpr ErrorCategory category(ErrorCode code) noexcept
    {
        return static_cast<ErrorCategory>((static_cast<std::uint16_t>(code) >> 8) & 0xFFU);
    }

    /** @brief Returns a static label for @p value, or "unknown" for an out-of-range value. */
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

    /** @brief Returns the static enumerator name of @p code, or "UnknownCode" for an out-of-range value. */
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
        case ErrorCode::TargetAlreadyHookedByThisKit:
            return "TargetAlreadyHookedByThisKit";
        case ErrorCode::TargetAlreadyHookedByAnotherModule:
            return "TargetAlreadyHookedByAnotherModule";
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
        case ErrorCode::LoaderLockActive:
            return "LoaderLockActive";
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
        case ErrorCode::UnreadableTarget:
            return "UnreadableTarget";
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
        case ErrorCode::EvidenceMismatch:
            return "EvidenceMismatch";
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
        case ErrorCode::OverlappingRanges:
            return "OverlappingRanges";
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
        case ErrorCode::ManifestIdentityCollision:
            return "ManifestIdentityCollision";
        case ErrorCode::ManifestFramingUnsafe:
            return "ManifestFramingUnsafe";
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
     * @brief One trivially copyable failure record: a code, a static label, and two raw context slots.
     * @details Construction never allocates or throws, so noexcept paths can build an Error. Only message() allocates.
     *          The function that reports the error, or its ErrorCode, documents what `detail` and `extra` hold.
     */
    struct Error
    {
        /// The failure code. Its category names the subsystem that raised it.
        ErrorCode code{ErrorCode::Ok};
        /// Label of the site that raised the error, for example "scan". It must point at static storage.
        const char *where{""};
        /// Primary raw context, for example an address, an instruction pointer, or a failing-hop index.
        std::uintptr_t detail{0};
        /// Secondary raw context, for example a candidate index, a slot, a hop count, or an OS error.
        std::uint32_t extra{0};

        /** @brief Formats one greppable line: "[category] CodeName @ where (detail=0x..., extra=...)". */
        [[nodiscard]] std::string message() const;
    };

    // Error construction stays non-throwing only while Error is trivially copyable.
    static_assert(std::is_trivially_copyable_v<Error>, "Error must stay trivially copyable for the noexcept seed.");

    /** @brief The fallible return type: a @p T on success, an Error on failure. Use `Result<void>` for no value. */
    template <class T> using Result = std::expected<T, Error>;

    inline std::string Error::message() const
    {
        // An empty or null label prints as "?".
        const char *label = (where != nullptr && where[0] != '\0') ? where : "?";
        return std::format(
            "[{}] {} @ {} (detail=0x{:X}, extra={})",
            to_string(category(code)),
            to_string(code),
            label,
            detail,
            extra
        );
    }

} // namespace DetourModKit

/**
 * @brief Unwraps a `Result<T>` into @p var, or returns its Error from the enclosing function.
 * @details It expands to three statements, so it cannot be the body of a brace-less `if` or `for`. The enclosing
 *          function must return a `Result` or `std::expected`. Uses with distinct @p var in one scope do not collide.
 */
#define DMK_TRY(var, expr)                                                                                             \
    auto &&_r_##var = (expr);                                                                                          \
    if (!_r_##var)                                                                                                     \
        return std::unexpected(_r_##var.error());                                                                      \
    auto var = std::move(*_r_##var)

/**
 * @brief Propagates the Error from a `Result<void>`, or from any Result whose value is discarded.
 * @details It expands to one scoped statement, so it is safe as the body of a brace-less `if` or `for`, and nested uses
 *          do not collide. The enclosing function must return a `Result` or `std::expected`.
 */
#define DMK_TRY_VOID(expr)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        auto &&_r = (expr);                                                                                            \
        if (!_r)                                                                                                       \
            return std::unexpected(_r.error());                                                                        \
    } while (0)

#endif // DETOURMODKIT_ERROR_HPP
