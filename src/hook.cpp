/**
 * @file hook.cpp
 * @brief Implementation of the hooking surface: the free verbs, the RAII handles, and the backend bridge.
 * @details This is the single translation unit (with internal/hook_backend.hpp) that names the SafetyHook backend.
 *          It hosts: the opaque MidContext <-> backend-context reinterpret_cast accessors; the process-wide
 *          allocator; the inline/mid create paths (target resolution, duplicate detection, prologue pre-flight,
 *          backend create, ledger bookkeeping); the RAII Hook and VmtHook handle bodies (including the loader-lock
 *          leaf teardown discipline); the declarative install_all; and the VMT object-clone plus per-method lifecycle.
 */

#include "DetourModKit/hook.hpp"

#include "internal/hook_backend.hpp"
#include "internal/hook_ledger.hpp"
#include "internal/memory_guarded.hpp"

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/format.hpp"
#include "DetourModKit/logger.hpp"

#include "platform.hpp"
#include "x86_decode.hpp"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace DetourModKit
{
    // File-local helpers. These live at DetourModKit scope (not inside namespace hook) so a bare `detail::` resolves to
    // DetourModKit::detail (the memory/x86/platform engine), not the hook::detail sub-namespace that would otherwise
    // shadow it and break the unqualified lookup.
    namespace
    {
        /// Result of the foreign-inline-hook pre-flight: whether the target already redirects, and to where.
        enum class PrehookState : std::uint8_t
        {
            NotHooked,
            HookedBySameModule,
            HookedByOtherModule
        };

        struct PrehookDetection
        {
            PrehookState state{PrehookState::NotHooked};
            std::uintptr_t jmp_destination{0};
        };

        /**
         * @brief Releases a module reference automatically unless ownership is handed to a hook Impl.
         */
        class ModuleRefGuard
        {
        public:
            explicit ModuleRefGuard(HMODULE module) noexcept : m_module(module) {}

            ~ModuleRefGuard() noexcept { detail::release_module_ref(m_module); }

            ModuleRefGuard(const ModuleRefGuard &) = delete;
            ModuleRefGuard &operator=(const ModuleRefGuard &) = delete;
            ModuleRefGuard(ModuleRefGuard &&) = delete;
            ModuleRefGuard &operator=(ModuleRefGuard &&) = delete;

            [[nodiscard]] HMODULE release() noexcept { return std::exchange(m_module, nullptr); }

            [[nodiscard]] HMODULE get() const noexcept { return m_module; }

        private:
            HMODULE m_module{nullptr};
        };

        /**
         * @brief Decodes a leading inline-hook redirect at @p target_address and returns its destination.
         * @details Recognises the three redirect shapes a foreign hook plants over a prologue: E9 (jmp rel32), FF 25
         *          (jmp [rip+disp32]), and 48 B8 imm64; FF E0 (mov rax, imm64; jmp rax, the absolute-jump trampoline a
         *          hooking library emits when its detour is beyond rel32 reach and it does not use the FF 25 form). The
         *          opcode bytes are read under a fault guard; returns the jump destination, or nullopt when the
         *          prologue is not one of those redirect shapes.
         */
        std::optional<std::uintptr_t> decode_prehook_destination(std::uintptr_t target_address) noexcept
        {
            // Read the opcode bytes under a fault guard and dispatch on the copy; an unguarded dereference of
            // target_address could fault if the page is unmapped or guarded.
            std::array<std::uint8_t, 2> opcode{};
            if (!detail::guarded_read_bytes(target_address, opcode.data(), opcode.size()))
            {
                return std::nullopt;
            }

            // E9 (jmp rel32), FF 25 (jmp [rip+disp32]), and 48 B8 imm64; FF E0 (mov rax, imm64; jmp rax) are the
            // redirect shapes that can land a prologue in a foreign hook trampoline in another module. EB (jmp rel8)
            // reaches at most +/-127 bytes, far too short to land in a foreign hook stub, so a leading 0xEB is ordinary
            // code, not a pre-existing inline hook; matching it would only add false positives on functions that
            // legitimately begin with a short jump.
            if (opcode[0] == 0xE9)
            {
                return detail::decode_e9_rel32(target_address);
            }
            if (opcode[0] == 0xFF && opcode[1] == 0x25)
            {
                return detail::decode_ff25_indirect(target_address);
            }
            if (opcode[0] == 0x48 && opcode[1] == 0xB8)
            {
                // 48 B8 begins `mov rax, imm64`; decode_mov_rax_imm64_jmp_rax validates the trailing FF E0 (jmp rax)
                // over the full 12-byte shape and returns nullopt for a bare mov that is not the abs-jump trampoline.
                return detail::decode_mov_rax_imm64_jmp_rax(target_address);
            }
            return std::nullopt;
        }

        /**
         * @brief Detects whether @p target_address is already inline-hooked.
         * @details Classifies the redirect as into the same module (likely our own prior patch) or another module
         *          (a foreign hook).
         */
        PrehookDetection detect_existing_inline_hook(std::uintptr_t target_address) noexcept
        {
            PrehookDetection result;
            if (target_address == 0)
            {
                return result;
            }
            const auto destination_opt = decode_prehook_destination(target_address);
            if (!destination_opt)
            {
                return result;
            }
            const auto destination = *destination_opt;
            result.jmp_destination = destination;

            HMODULE target_module = nullptr;
            HMODULE dest_module = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(target_address), &target_module))
            {
                target_module = nullptr;
            }
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(destination), &dest_module))
            {
                dest_module = nullptr;
            }
            result.state = (dest_module != nullptr && target_module == dest_module) ? PrehookState::HookedBySameModule
                                                                                    : PrehookState::HookedByOtherModule;
            return result;
        }

        /// The flagged prologue shapes the inline/mid pre-flight refuses under Prologue::Fail.
        enum class PrologueRisk : std::uint8_t
        {
            None,
            LeadingCall, // 0xE8 call rel32
            Breakpoint   // 0xCC int3 / 0xCD int n
        };

        // Classifies the first opcode byte of an inline/mid hook target. A leading E8 (call rel32) means the prologue
        // is a relative call whose displacement is computed from the original site; the backend relocates the stolen
        // prologue into a trampoline at a different address, so the relocated call can dispatch to the wrong absolute
        // target. A leading 0xCC (int3) or 0xCD (int n) means the entry is already a breakpoint -- a foreign hook's
        // stub, a patched slot, or alignment padding -- not a real function body. The E9 / FF 25 redirect shapes are
        // handled separately by detect_existing_inline_hook, and EB rel8 is ordinary short-jump code; this classifier
        // intentionally flags only the call and breakpoint shapes. The read is fault-guarded so an unmapped or guarded
        // page yields None rather than faulting the host (the backend create validates separately).
        PrologueRisk classify_prologue_risk(std::uintptr_t target_address) noexcept
        {
            if (target_address == 0)
            {
                return PrologueRisk::None;
            }
            std::uint8_t first_byte = 0;
            if (!detail::guarded_read_bytes(target_address, &first_byte, sizeof(first_byte)))
            {
                return PrologueRisk::None;
            }
            switch (first_byte)
            {
            case 0xE8:
                return PrologueRisk::LeadingCall;
            case 0xCC:
            case 0xCD:
                return PrologueRisk::Breakpoint;
            default:
                return PrologueRisk::None;
            }
        }

        /// Human-readable fragment describing a flagged prologue risk, for the diagnostic log lines.
        [[nodiscard]] std::string_view prologue_risk_description(PrologueRisk risk) noexcept
        {
            switch (risk)
            {
            case PrologueRisk::LeadingCall:
                return "a call (E8)";
            case PrologueRisk::Breakpoint:
                return "a breakpoint (0xCC/0xCD)";
            case PrologueRisk::None:
                return "an unremarkable byte";
            }
            return "an unremarkable byte";
        }

        // Mid-hook detour bridge. hook::MidHookFn (void(*)(MidContext&)) and the backend callback
        // (void(*)(Context64&)) are ABI-identical because MidContext is never more than a pass-through alias for
        // Context64: identical calling convention, identical single pointer-sized argument. The reinterpret_cast is
        // therefore sound, but it crosses a nominal parameter-type boundary that GCC's -Wcast-function-type (and
        // MSVC's C4191) flag. Confining the cast to this one converter localizes and documents the bridge.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4191)
#endif
        [[nodiscard]] safetyhook::MidHookFn to_backend_detour(hook::MidHookFn fn) noexcept
        {
            return reinterpret_cast<safetyhook::MidHookFn>(fn);
        }
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

        // File-local backend error formatters. The backend error TYPES never reach a public name (every backend
        // failure collapses to ErrorCode::BackendFailed); these render the rich backend reason into the diagnostic
        // log so the distinct failure mode is not lost even though the structured code is a single BackendFailed.
        std::string backend_error_string(const safetyhook::InlineHook::Error &err)
        {
            const int type_int = static_cast<int>(err.type);
            const auto ip_str = format::format_address(reinterpret_cast<std::uintptr_t>(err.ip));
            switch (err.type)
            {
            case safetyhook::InlineHook::Error::BAD_ALLOCATION:
                return std::format("InlineHook backend error ({}): bad allocation (allocator error {})", type_int,
                                   static_cast<int>(err.allocator_error));
            case safetyhook::InlineHook::Error::FAILED_TO_DECODE_INSTRUCTION:
                return std::format("InlineHook backend error ({}): failed to decode instruction at {}", type_int,
                                   ip_str);
            case safetyhook::InlineHook::Error::SHORT_JUMP_IN_TRAMPOLINE:
                return std::format("InlineHook backend error ({}): short jump in trampoline at {}", type_int, ip_str);
            case safetyhook::InlineHook::Error::IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE:
                return std::format("InlineHook backend error ({}): IP-relative instruction out of range at {}",
                                   type_int, ip_str);
            case safetyhook::InlineHook::Error::UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE:
                return std::format("InlineHook backend error ({}): unsupported instruction in trampoline at {}",
                                   type_int, ip_str);
            case safetyhook::InlineHook::Error::FAILED_TO_UNPROTECT:
                return std::format("InlineHook backend error ({}): failed to unprotect memory at {}", type_int, ip_str);
            case safetyhook::InlineHook::Error::NOT_ENOUGH_SPACE:
                return std::format("InlineHook backend error ({}): prologue too short for the hook at {}", type_int,
                                   ip_str);
            default:
                return std::format("InlineHook backend error ({}): unknown error type", type_int);
            }
        }

        std::string backend_error_string(const safetyhook::MidHook::Error &err)
        {
            const int type_int = static_cast<int>(err.type);
            switch (err.type)
            {
            case safetyhook::MidHook::Error::BAD_ALLOCATION:
                return std::format("MidHook backend error ({}): bad allocation (allocator error {})", type_int,
                                   static_cast<int>(err.allocator_error));
            case safetyhook::MidHook::Error::BAD_INLINE_HOOK:
                return std::format("MidHook backend error ({}): bad underlying inline hook. {}", type_int,
                                   backend_error_string(err.inline_hook_error));
            default:
                return std::format("MidHook backend error ({}): unknown error type", type_int);
            }
        }

        /**
         * @brief Returns the inline trampoline pointer for a hook backend, or nullptr for a mid hook / empty backend.
         * @details This is the value published into the @ref hook::Hook::CallGate while an inline hook is armed, so a
         *          guarded @ref hook::Hook::call can dispatch to it, and the value @ref hook::Hook::original returns on
         *          its unguarded path. A mid hook holds a MidHook alternative (no callable original), so the get_if
         *          fails and this returns nullptr.
         */
        [[nodiscard]] void *
        inline_trampoline(const std::variant<safetyhook::InlineHook, safetyhook::MidHook> &backend) noexcept
        {
            const auto *inline_backend = std::get_if<safetyhook::InlineHook>(&backend);
            if (inline_backend == nullptr || !*inline_backend)
            {
                return nullptr;
            }
            return inline_backend->original<void *>();
        }

        /// Serializes VMT object-vptr check/swap/record sequences across create/apply/remove/teardown.
        [[nodiscard]] std::mutex &vmt_object_mutex() noexcept
        {
            static std::mutex mutex;
            return mutex;
        }

        /**
         * @brief Acquires the VMT object gate, returning an unowned lock if the OS mutex acquisition fails.
         * @details The VMT create/apply/remove paths return an Error on an unowned lock instead of throwing through a
         *          Result-returning control-plane API. Teardown leaks the backend (keeping its install-time module
         *          reference) if the gate cannot be acquired, because restoring without the gate would race another
         *          object-vptr transition.
         */
        [[nodiscard]] std::unique_lock<std::mutex> acquire_vmt_object_lock() noexcept
        {
            try
            {
                return std::unique_lock<std::mutex>(vmt_object_mutex());
            }
            catch (...)
            {
                return std::unique_lock<std::mutex>{};
            }
        }

        // Decides whether @p slot_value (the first qword of a vtable slot) looks like a callable function body. A 0x00
        // first byte is the uninitialised-page sentinel; 0xCC/0xCD are int3/int padding; 0xC2/0xC3 are bare RETs; an
        // EB/E9 same-module jump is a stub (an incremental-link ILT entry or a patched slot), and cloning it makes the
        // new "original" a forwarder. MSVC adjustor thunks begin with the this-adjust (0x48) and pass; tail-calls to a
        // foreign module pass. The reads are fault-guarded.
        bool looks_like_function_vmt_slot(std::uintptr_t slot_value) noexcept
        {
            if (slot_value == 0)
            {
                return false;
            }
            std::uint8_t first_byte = 0;
            if (!detail::guarded_read_bytes(slot_value, &first_byte, sizeof(first_byte)))
            {
                return false;
            }
            switch (first_byte)
            {
            case 0x00:
            case 0xCC:
            case 0xCD:
            case 0xC2:
            case 0xC3:
                return false;
            default:
                break;
            }

            if (first_byte == 0xEB || first_byte == 0xE9)
            {
                HMODULE slot_module = nullptr;
                HMODULE jmp_module = nullptr;
                if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                       reinterpret_cast<LPCWSTR>(slot_value), &slot_module) == 0)
                {
                    return false;
                }
                const std::optional<std::uintptr_t> jmp_target =
                    (first_byte == 0xE9) ? detail::decode_e9_rel32(slot_value) : detail::decode_eb_rel8(slot_value);
                if (!jmp_target)
                {
                    return false;
                }
                if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                       reinterpret_cast<LPCWSTR>(*jmp_target), &jmp_module) == 0)
                {
                    return false;
                }
                if (slot_module == jmp_module)
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * @brief Hard cap on the vtable slot walk, mirroring the bounded RTTI walkers.
         * @details The walk terminates naturally at the first non-executable qword, but a corrupted or
         *          attacker-controlled vptr can point at an arbitrarily long run of executable-looking qwords, which
         *          would otherwise make the SEH-guarded scan run unboundedly. No real class vtable approaches this
         *          many virtual methods, so hitting the cap means the seed object is malformed; count_vmt_method_slots
         *          fails closed (which vmt_for reports as InvalidObject) rather than scanning without limit.
         */
        constexpr std::size_t MAX_VMT_SLOTS = 4096;

        /**
         * @brief Counts callable slots from the object's current vptr.
         * @details Uses the same executable-address sentinel the backend uses before cloning. Every vtable slot read
         * is guarded so a malformed object fails closed before the backend can index through it. The walk is hard
         * capped at @ref MAX_VMT_SLOTS so a malformed vptr over a long executable-looking run cannot spin unbounded.
         */
        [[nodiscard]] std::optional<std::size_t> count_vmt_method_slots(void *object) noexcept
        {
            const std::optional<std::uintptr_t> vptr =
                detail::guarded_read<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(object));
            if (!vptr)
            {
                return std::nullopt;
            }

            std::size_t count = 0;
            for (;;)
            {
                if (count >= MAX_VMT_SLOTS)
                {
                    // A run this long is not a real vtable; fail closed rather than continue an unbounded guarded walk.
                    return std::nullopt;
                }
                if (count > (std::numeric_limits<std::uintptr_t>::max() - *vptr) / sizeof(std::uintptr_t))
                {
                    return std::nullopt;
                }

                const std::uintptr_t slot_address = *vptr + (count * sizeof(std::uintptr_t));
                const std::optional<std::uintptr_t> slot = detail::guarded_read<std::uintptr_t>(slot_address);
                if (!slot)
                {
                    return std::nullopt;
                }
                if (!safetyhook::is_executable(reinterpret_cast<std::uint8_t *>(*slot)))
                {
                    return count;
                }
                ++count;
            }
        }

        /**
         * @brief Resolves a hook Target to an absolute address.
         * @details An absolute Address
         * passes straight through; a deferred OwnedScanRequest is resolved through
         *          scan::resolve and its winning address returned (or its Error).
         */
        // NOLINTNEXTLINE(bugprone-exception-escape): scan::resolve throw is caught; std::get is on a checked variant
        Result<std::uintptr_t> resolve_target(const hook::Target &target) noexcept
        {
            if (const Address *absolute = std::get_if<Address>(&target))
            {
                return absolute->raw();
            }
            const scan::OwnedScanRequest &request = std::get<scan::OwnedScanRequest>(target);
            // scan::resolve is a control-plane cascade that may allocate (e.g. a broad-match string-xref candidate),
            // so it can throw. This helper is noexcept, so contain the throw and report it as an Error rather than
            // terminating the host from a deferred-scan install under memory pressure.
            try
            {
                Result<scan::Hit> hit = scan::resolve(request.view());
                if (!hit)
                {
                    return std::unexpected(hit.error());
                }
                return hit->address.raw();
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::resolve_target"});
            }
            catch (...)
            {
                return std::unexpected(Error{ErrorCode::Unknown, "hook::resolve_target"});
            }
        }

        /// Emits a hook lifecycle event, swallowing any sink failure so a noexcept path stays no-throw.
        void emit_lifecycle(std::string_view name, std::uint64_t ledger_id, diagnostics::HookKind kind,
                            diagnostics::HookTransition transition) noexcept
        {
            try
            {
                diagnostics::hook_lifecycle().emit_safe(diagnostics::HookLifecycleEvent{
                    .name = name, .ledger_id = ledger_id, .kind = kind, .transition = transition});
            }
            catch (...)
            {
            }
        }

        /// The resolved target plus the ledger id @ref preflight_target reserved for it.
        struct PreflightResult
        {
            std::uintptr_t address{0};
            std::uint64_t ledger_id{0};
        };

        /**
         * @brief Resolves, validates, pre-flights, and reserves a ledger slot for an inline/mid hook target.
         * @return The target address and its reserved ledger id, or the Error that should fail the install.
         * @details Shared by inline_at_raw and mid_at, which patch the same prologue and need identical duplicate
         *          detection (ledger exact-match then foreign-JMP heuristic) and prologue-risk pre-flight. The ledger
         *          reservation is taken here, under one lock, so the "is it already hooked?" check and the id record
         *          are a single atomic step (closing the check/record race two concurrent same-target installs would
         *          otherwise slip through). It also waits until this reservation is first in the target's pending queue
         *          before returning, so backend patching for one target is creation-order serial. On success the caller
         *          OWNS the returned ledger id and must either commit it (after backend create and all fallible setup
         *          have succeeded) or roll it back via HookLedger::release_hook if a later create step fails. Layering
         *          and Relocate-policy installs are warned but not refused; a strict fail_if_already_hooked match, an
         *          out-of-memory reservation, or a Fail-policy risky prologue is refused with the matching ErrorCode
         *          (rolling back the reservation first where one was taken).
         */
        Result<PreflightResult> preflight_target(const hook::Target &target, const hook::Options &options,
                                                 std::string_view name, const char *where) noexcept
        {
            Result<std::uintptr_t> resolved = resolve_target(target);
            if (!resolved)
            {
                return std::unexpected(resolved.error());
            }
            const std::uintptr_t address = *resolved;
            if (address == 0)
            {
                return std::unexpected(Error{ErrorCode::InvalidTargetAddress, where});
            }

            // Atomic check-and-reserve. try_reserve_hook folds the exact same-kit duplicate check and the id record
            // into one locked step, so a concurrent same-target install cannot slip between them. A reservation on an
            // already-tracked target reports preexisting == true (this kit layered on its own prior hook); the
            // fail_if_already_hooked gate is applied inside the reservation and reported as AlreadyHooked.
            const detail::HookLedger::Reservation reservation =
                detail::HookLedger::instance().try_reserve_hook(address, options.fail_if_already_hooked);
            if (reservation.status == detail::HookLedger::ReserveStatus::OutOfMemory)
            {
                // The bookkeeping allocation failed: fail closed rather than installing a live-but-unledgered hook.
                return std::unexpected(Error{ErrorCode::OutOfMemory, where, address});
            }
            if (reservation.status == detail::HookLedger::ReserveStatus::AlreadyHooked)
            {
                return std::unexpected(Error{ErrorCode::TargetAlreadyHookedInProcess, where, address});
            }

            if (reservation.preexisting)
            {
                // Layered on a hook this kit already placed (fail_if_already_hooked was false, else the reservation
                // would have refused): warn but install.
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: '{}' layers on a hook this kit already placed at {}; destroy layered hooks newest-first.",
                    name, format::format_address(address));
            }
            else
            {
                // Not previously in the ledger, so consult the foreign-JMP heuristic for a patch placed by something
                // else. On a strict refusal, roll the just-taken reservation back before failing.
                const PrehookDetection prehook = detect_existing_inline_hook(address);
                if (prehook.state == PrehookState::HookedByOtherModule)
                {
                    if (options.fail_if_already_hooked)
                    {
                        (void)detail::HookLedger::instance().release_hook(address, reservation.id);
                        return std::unexpected(Error{ErrorCode::TargetAlreadyHookedInProcess, where, address});
                    }
                    (void)log().try_log(
                        LogLevel::Warning,
                        "hook: '{}' target {} is already inline-hooked by another module (JMP -> {}); layering on top.",
                        name, format::format_address(address), format::format_address(prehook.jmp_destination));
                }
            }

            // Prologue pre-flight, independent of the layering checks: a target can be unhooked yet still begin with a
            // call thunk or a patched int3. On a Fail-policy refusal, roll the reservation back before failing.
            const PrologueRisk risk = classify_prologue_risk(address);
            if (risk != PrologueRisk::None)
            {
                if (options.prologue == hook::Prologue::Fail)
                {
                    (void)detail::HookLedger::instance().release_hook(address, reservation.id);
                    return std::unexpected(Error{ErrorCode::TargetPrologueUnsafe, where, address});
                }
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: '{}' target {} begins with {}; installed anyway under the Relocate prologue policy.", name,
                    format::format_address(address), prologue_risk_description(risk));
            }
            return PreflightResult{address, reservation.id};
        }
    } // namespace

    namespace hook
    {
        // hook::MidContext accessor bridge.
        //
        // At every mid-hook call the backend hands the detour a safetyhook::Context64& (the captured register file).
        // DMK exposes that as an OPAQUE hook::MidContext& so a consumer never names the backend. MidContext is never
        // defined, so these accessors are the single place that recovers the real type by reinterpret_cast; the cast
        // is well-defined precisely because MidContext is forever incomplete and is only ever the very Context64 the
        // backend passed in.
        std::uintptr_t &gpr(MidContext &ctx, Gpr reg) noexcept
        {
            auto &context = reinterpret_cast<safetyhook::Context64 &>(ctx);
            switch (reg)
            {
            case Gpr::Rax:
                return context.rax;
            case Gpr::Rbx:
                return context.rbx;
            case Gpr::Rcx:
                return context.rcx;
            case Gpr::Rdx:
                return context.rdx;
            case Gpr::Rsi:
                return context.rsi;
            case Gpr::Rdi:
                return context.rdi;
            case Gpr::Rbp:
                return context.rbp;
            case Gpr::R8:
                return context.r8;
            case Gpr::R9:
                return context.r9;
            case Gpr::R10:
                return context.r10;
            case Gpr::R11:
                return context.r11;
            case Gpr::R12:
                return context.r12;
            case Gpr::R13:
                return context.r13;
            case Gpr::R14:
                return context.r14;
            case Gpr::R15:
                return context.r15;
            }
            // Unreachable: Gpr is a fixed enum and every enumerator is handled. Returning rax keeps the
            // reference-returning function well-formed on compilers that cannot prove the switch is exhaustive.
            return context.rax;
        }

        std::uintptr_t stack_pointer(const MidContext &ctx) noexcept
        {
            return reinterpret_cast<const safetyhook::Context64 &>(ctx).rsp;
        }

        std::uintptr_t &resume_stack_pointer(MidContext &ctx) noexcept
        {
            return reinterpret_cast<safetyhook::Context64 &>(ctx).trampoline_rsp;
        }

        std::uintptr_t &instruction_pointer(MidContext &ctx) noexcept
        {
            return reinterpret_cast<safetyhook::Context64 &>(ctx).rip;
        }

        std::uintptr_t &flags(MidContext &ctx) noexcept
        {
            return reinterpret_cast<safetyhook::Context64 &>(ctx).rflags;
        }

        XmmView xmm(const MidContext &ctx, std::size_t index) noexcept
        {
            XmmView view{};
            // Fail closed on an out-of-range index: only xmm0..xmm15 exist, so indexing past 15 would read past the
            // captured context. Context64 lays out the 16 Xmm unions contiguously, so indexing from &xmm0 selects
            // register number @p index. The 16 bytes are copied out by value: XMM is surfaced read-only.
            if (index >= 16)
            {
                return view;
            }
            const auto &context = reinterpret_cast<const safetyhook::Context64 &>(ctx);
            const safetyhook::Xmm &reg = (&context.xmm0)[index];
            std::memcpy(view.bytes.data(), reg.u8, view.bytes.size());
            return view;
        }

        const std::shared_ptr<safetyhook::Allocator> &backend_allocator() noexcept
        {
            // One allocator per process, lazily and thread-safely initialized. global() is itself process-wide, so
            // holding it through this static shared_ptr is a refcount hold that keeps the backend allocator alive for
            // the kit's lifetime.
            static const std::shared_ptr<safetyhook::Allocator> allocator = safetyhook::Allocator::global();
            return allocator;
        }

        // Hook -- RAII handle for one inline or mid hook.
        Hook::Hook(std::unique_ptr<Impl> impl, std::shared_ptr<CallGate> gate) noexcept : m_impl(std::move(impl))
        {
            m_gate.store(std::move(gate), std::memory_order_release);
        }

        Hook::Hook(Hook &&other) noexcept : m_impl(std::move(other.m_impl))
        {
            // std::atomic is not movable, so transfer the gate reference by hand. exchange leaves the source's gate
            // empty, so a moved-from handle is fully disengaged: its ~Hook takes the early return and its call()
            // reads an empty gate and returns the inactive default.
            m_gate.store(other.m_gate.exchange(nullptr, std::memory_order_acq_rel), std::memory_order_release);
        }

        Hook &Hook::operator=(Hook &&other) noexcept
        {
            if (this != &other)
            {
                // Adopt the current hook into a temporary whose destructor unhooks it at the end of this scope, then
                // take the source's impl and gate. Constructing `discard` from *this moves out BOTH members (see the
                // move constructor), so a concurrent call() that pinned this handle's gate before the move keeps the
                // old trampoline alive until it returns, while `discard`'s ~Hook runs the loader-lock-aware teardown.
                Hook discard(std::move(*this));
                m_impl = std::move(other.m_impl);
                m_gate.store(other.m_gate.exchange(nullptr, std::memory_order_acq_rel), std::memory_order_release);
            }
            return *this;
        }

        Hook::~Hook()
        {
            // Take the handle's gate reference out for the whole teardown. A concurrent call() that already pinned the
            // gate keeps its recursive_mutex (and, in the loader-lock branch, the leaked-but-live trampoline) alive via
            // its own reference, so nulling the callable below is enough to make a late caller fail closed.
            std::shared_ptr<CallGate> gate = m_gate.exchange(nullptr, std::memory_order_acq_rel);
            if (!m_impl)
            {
                return;
            }

            // Loader-lock leaf discipline: under the OS loader lock (DllMain / FreeLibrary), restoring the prologue and
            // freeing the trampoline can deadlock against another thread waiting on a loader callback. Leave the
            // backend hook installed and leak the Impl rather than tear it down here. The Impl carries the module
            // reference taken before the backend was published (self_ref), so leaking it keeps the trampoline's code
            // pages mapped -- the gate's published callable stays valid and a late guarded call() through it still
            // dispatches correctly.
            if (DetourModKit::detail::is_loader_lock_held())
            {
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                (void)m_impl.release();
                return;
            }

            const std::uintptr_t target = m_impl->target;
            const std::uint64_t ledger_id = m_impl->ledger_id;
            const diagnostics::HookKind kind =
                m_impl->is_inline ? diagnostics::HookKind::Inline : diagnostics::HookKind::Mid;
            // Copy the name out before the backend is restored below: the post-restore warning and lifecycle event read
            // it, but m_impl (which owns the name storage) is gone once reset() runs, so a view would dangle. A
            // std::string copy allocates for a non-SSO name and can throw under OOM, which a noexcept destructor must
            // not do, so contain the copy in a try/catch and degrade to an empty name on failure rather than letting
            // the throw escape.
            std::string name;
            try
            {
                name = m_impl->name;
            }
            catch (...)
            {
            }

            // Serialize with any in-flight call() through the shared gate. A caller holding gate->mutex for its whole
            // invocation runs to completion before this acquires it (the drain for callers that already locked).
            // Publishing a null callable under the same mutex then makes a caller that locks AFTER this -- one that had
            // only pinned the gate, not yet locked, when this teardown began -- read a null trampoline and return the
            // inactive default instead of dispatching through the trampoline the reset below frees. The gate outlives
            // that late caller because the caller holds its own reference; only the backend/trampoline is freed here.
            if (gate)
            {
                std::unique_lock<std::recursive_mutex> guard = acquire_call_lock(gate.get());
                if (!guard.owns_lock())
                {
                    // If the guard itself cannot be acquired, restoring is no longer provably safe. Leak the backend
                    // (and, with it, the install-time module reference in the Impl, which keeps the trampoline mapped)
                    // rather than risk freeing a trampoline that a guarded caller may still use.
                    diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                    (void)m_impl.release();
                    return;
                }
                gate->callable = nullptr;
                m_impl->status.store(HookState::Disabled, std::memory_order_release);
            }

            // Restore the prologue and free the trampoline FIRST, while the ledger still records this hook on the
            // target, THEN release the ledger entry. Releasing before the backend is restored would open a window in
            // which the ledger reads the target as un-hooked while the patch is still physically installed: a
            // concurrent inline_at/mid_at on the same address could slip into that window, install over the live patch,
            // and then be clobbered by this restore (a trampoline use-after-free). Restoring first means a racing
            // create still sees the target as hooked (the safe direction) right up until the ledger entry is dropped.
            // No call() can be dispatching through the trampoline here: the gate published a null callable under its
            // mutex, and any caller that had already locked was drained above.
            //
            // Grab the install-time module reference before reset() destroys the Impl, then release it after the
            // backend is torn down and no lock is held (release_module_ref calls FreeLibrary, which takes the loader
            // lock). The caller is still executing this module's code and the host holds its own load reference, so
            // this release is never the terminal one that could unmap the module out from under us.
            const HMODULE self_ref = static_cast<HMODULE>(m_impl->self_ref);
            m_impl.reset();
            DetourModKit::detail::release_module_ref(self_ref);

            const std::size_t newer = DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
            if (newer > 0)
            {
                // Best-effort warning on a noexcept teardown path: try_log swallows any formatting/sink failure so a
                // log allocation under memory pressure cannot throw out of the destructor.
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: '{}' at {} destroyed while {} newer hook(s) remain layered on the same target; destroy "
                    "layered hooks newest-first to avoid a trampoline use-after-free.",
                    name, format::format_address(target), newer);
            }
            emit_lifecycle(name, ledger_id, kind, diagnostics::HookTransition::Removed);
        }

        Hook::operator bool() const noexcept
        {
            return m_impl != nullptr;
        }

        std::string_view Hook::name() const noexcept
        {
            return m_impl ? std::string_view{m_impl->name} : std::string_view{};
        }

        bool Hook::is_enabled() const noexcept
        {
            return m_impl && m_impl->status.load(std::memory_order_acquire) == HookState::Active;
        }

        void *Hook::original_address() const noexcept
        {
            // The UNGUARDED hot path behind original<Fn>(): a plain lock-free read of the backend trampoline. It
            // deliberately does not touch the call gate, so it costs no atomic-shared_ptr load; the caller owns the
            // hook-outlives-the-call guarantee.
            return m_impl ? inline_trampoline(m_impl->backend) : nullptr;
        }

        std::shared_ptr<Hook::CallGate> Hook::pin_call_gate() const noexcept
        {
            // Atomically copy the gate reference into a strong local so call() can hold the trampoline and mutex alive
            // across a concurrent teardown that drops the handle's own reference.
            return m_gate.load(std::memory_order_acquire);
        }

        std::unique_lock<std::recursive_mutex> Hook::acquire_call_lock(CallGate *gate) const noexcept
        {
            try
            {
                return std::unique_lock<std::recursive_mutex>(gate->mutex);
            }
            catch (...)
            {
                // recursive_mutex::lock can throw std::system_error (max recursion / resource exhaustion). Fail
                // closed: an unowned lock makes call() return the inactive default rather than dispatching unguarded
                // or letting the throw escape the non-noexcept call() into a host that may be mid-teardown.
                return std::unique_lock<std::recursive_mutex>{};
            }
        }

        void *Hook::active_trampoline(CallGate *gate) const noexcept
        {
            // Read the callable published under the gate mutex the caller already holds. create/enable/disable/~Hook
            // all write gate->callable under the same mutex, so this observes either the live trampoline or the
            // nullptr a teardown published before freeing the backend -- never a dangling pointer.
            return gate->callable;
        }

        // NOLINTNEXTLINE(bugprone-exception-escape): std::visit is on a checked variant and cannot throw here
        Result<void> Hook::enable() noexcept
        {
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            // A live handle always has a gate (created with the Impl); the null check fails closed on the broken
            // invariant rather than dereferencing a null control block.
            const std::shared_ptr<CallGate> gate = m_gate.load(std::memory_order_acquire);
            if (!gate)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            std::unique_lock<std::recursive_mutex> guard = acquire_call_lock(gate.get());
            if (!guard.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            if (!std::visit([](auto &backend) { return static_cast<bool>(backend); }, m_impl->backend))
            {
                return std::unexpected(Error{ErrorCode::BackendFailed, "hook::enable"});
            }

            HookState expected = HookState::Disabled;
            if (!m_impl->status.compare_exchange_strong(expected, HookState::Enabling, std::memory_order_acq_rel))
            {
                if (expected == HookState::Active)
                {
                    return {};
                }
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            if (std::visit([](auto &backend) { return backend.enable().has_value(); }, m_impl->backend))
            {
                m_impl->status.store(HookState::Active, std::memory_order_release);
                // Publish the callable trampoline under the gate mutex so a guarded call() dispatches to the freshly
                // armed hook. A mid hook has no callable original, so inline_trampoline yields nullptr and call()
                // keeps returning the inactive default for it.
                gate->callable = inline_trampoline(m_impl->backend);
                const diagnostics::HookKind kind =
                    m_impl->is_inline ? diagnostics::HookKind::Inline : diagnostics::HookKind::Mid;
                const std::string_view name = m_impl->name;
                const std::uint64_t ledger_id = m_impl->ledger_id;
                // Release the gate guard before dispatching the lifecycle event: emit_lifecycle runs arbitrary
                // subscriber code, which must not execute while DMK's per-hook mutex is held (CP.22 -- never call
                // unknown code under a lock). enable() does not reset m_impl, so the captured name view and ledger id
                // stay valid.
                guard.unlock();
                emit_lifecycle(name, ledger_id, kind, diagnostics::HookTransition::Enabled);
                return {};
            }
            m_impl->status.store(HookState::Disabled, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable"});
        }

        // NOLINTNEXTLINE(bugprone-exception-escape): std::visit is on a checked variant and cannot throw here
        Result<void> Hook::disable() noexcept
        {
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            const std::shared_ptr<CallGate> gate = m_gate.load(std::memory_order_acquire);
            if (!gate)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            std::unique_lock<std::recursive_mutex> guard = acquire_call_lock(gate.get());
            if (!guard.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            if (!std::visit([](auto &backend) { return static_cast<bool>(backend); }, m_impl->backend))
            {
                return std::unexpected(Error{ErrorCode::BackendFailed, "hook::disable"});
            }

            HookState expected = HookState::Active;
            if (!m_impl->status.compare_exchange_strong(expected, HookState::Disabling, std::memory_order_acq_rel))
            {
                if (expected == HookState::Disabled)
                {
                    return {};
                }
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            if (std::visit([](auto &backend) { return backend.disable().has_value(); }, m_impl->backend))
            {
                m_impl->status.store(HookState::Disabled, std::memory_order_release);
                // Clear the callable under the gate mutex so a call() that arrives after this stops dispatching
                // through the now-disarmed trampoline and returns the inactive default. A concurrent in-flight call()
                // holding the gate mutex has already drained this disable (it blocks on guard above until the call
                // returns).
                gate->callable = nullptr;
                const diagnostics::HookKind kind =
                    m_impl->is_inline ? diagnostics::HookKind::Inline : diagnostics::HookKind::Mid;
                const std::string_view name = m_impl->name;
                const std::uint64_t ledger_id = m_impl->ledger_id;
                // Release the gate guard before dispatching the lifecycle event (CP.22, see enable()); disable() does
                // not reset m_impl, so the captured name view and ledger id stay valid past the unlock.
                guard.unlock();
                emit_lifecycle(name, ledger_id, kind, diagnostics::HookTransition::Disabled);
                return {};
            }
            m_impl->status.store(HookState::Active, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::DisableFailed, "hook::disable"});
        }

        void Hook::release() noexcept
        {
            if (!m_impl)
            {
                return;
            }
            // Leak the backend hook intentionally: it stays installed for the process lifetime. The ledger entry is
            // left in place too, since is_target_hooked must still report the target as hooked. Clearing the gate
            // disengages the handle: a later call()/enable()/disable() sees an empty gate and fails closed (matching
            // the moved-from contract), while a call() that pinned the gate before this keeps dispatching to the
            // still-installed (leaked) trampoline until it returns.
            (void)m_impl.release();
            m_gate.store(nullptr, std::memory_order_release);
        }

        // Free install verbs.
        namespace detail
        {
            Result<Hook> inline_at_raw(InlineRequest request, void *detour)
            {
                if (request.name.empty())
                {
                    return std::unexpected(Error{ErrorCode::InvalidArg, "hook::inline_at"});
                }
                if (detour == nullptr)
                {
                    return std::unexpected(Error{ErrorCode::InvalidDetourFunction, "hook::inline_at"});
                }
                Result<PreflightResult> preflight =
                    preflight_target(request.target, request.options, request.name, "hook::inline_at");
                if (!preflight)
                {
                    return std::unexpected(preflight.error());
                }
                const std::uintptr_t target = preflight->address;
                // preflight_target reserved this ledger id and waited for this target's install turn. From here on
                // every failure path rolls it back, and the success path commits it after all throwing setup succeeds.
                const std::uint64_t ledger_id = preflight->ledger_id;

                const std::shared_ptr<safetyhook::Allocator> &allocator = backend_allocator();
                if (!allocator)
                {
                    (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                    return std::unexpected(Error{ErrorCode::AllocatorNotAvailable, "hook::inline_at"});
                }
                ModuleRefGuard self_ref(DetourModKit::detail::acquire_module_ref());
                if (self_ref.get() == nullptr)
                {
                    (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                    return std::unexpected(Error{ErrorCode::SystemCallFailed, "hook::inline_at"});
                }
                try
                {
                    auto created = safetyhook::InlineHook::create(allocator, reinterpret_cast<void *>(target), detour,
                                                                  safetyhook::InlineHook::Default);
                    if (!created)
                    {
                        log().error("hook::inline_at: backend create failed for '{}' at {}: {}", request.name,
                                    format::format_address(target), backend_error_string(created.error()));
                        (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                        return std::unexpected(Error{ErrorCode::BackendFailed, "hook::inline_at", target});
                    }
                    auto backend_hook = std::move(created.value());
                    const HookState state = backend_hook.enabled() ? HookState::Active : HookState::Disabled;
                    // Store the reserved ledger id in the Impl (its teardown releases it). make_unique, the gate
                    // allocation, and the info log are the only steps that can still throw under OOM; the catch below
                    // rolls the reservation back, and `impl` (if built) unwinds through ~Impl to restore the prologue.
                    auto impl = std::make_unique<Hook::Impl>(std::move(backend_hook), std::move(request.name), target,
                                                             ledger_id, state);
                    auto gate = std::make_shared<Hook::CallGate>();
                    // Publish the callable trampoline for an already-armed inline hook so a guarded call() dispatches
                    // immediately; a disabled create leaves it null until enable() publishes it.
                    if (state == HookState::Active)
                    {
                        gate->callable = inline_trampoline(impl->backend);
                    }
                    const std::string_view created_name = impl->name;
                    log().info("hook::inline_at: created inline hook '{}' at {}.", created_name,
                               format::format_address(target));
                    DetourModKit::detail::HookLedger::instance().commit_hook(target, ledger_id);
                    emit_lifecycle(created_name, ledger_id, diagnostics::HookKind::Inline,
                                   diagnostics::HookTransition::Created);
                    // The module reference was taken before SafetyHook patched the target, because a detour can become
                    // callable as soon as the backend create succeeds. Hand it to the Impl only after every fallible
                    // setup step has completed; until then ModuleRefGuard releases it on rollback.
                    impl->self_ref = self_ref.release();
                    return Hook(std::move(impl), std::move(gate));
                }
                catch (const std::bad_alloc &)
                {
                    (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                    return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::inline_at", target});
                }
                catch (...)
                {
                    (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                    return std::unexpected(Error{ErrorCode::UnknownError, "hook::inline_at", target});
                }
            }
        } // namespace detail

        Result<Hook> mid_at(MidRequest request, MidHookFn detour)
        {
            if (request.name.empty())
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "hook::mid_at"});
            }
            if (detour == nullptr)
            {
                return std::unexpected(Error{ErrorCode::InvalidDetourFunction, "hook::mid_at"});
            }
            Result<PreflightResult> preflight =
                preflight_target(request.target, request.options, request.name, "hook::mid_at");
            if (!preflight)
            {
                return std::unexpected(preflight.error());
            }
            const std::uintptr_t target = preflight->address;
            // preflight_target reserved this ledger id and waited for this target's install turn. Every failure path
            // rolls it back, and the success path commits it after all throwing setup succeeds.
            const std::uint64_t ledger_id = preflight->ledger_id;

            const std::shared_ptr<safetyhook::Allocator> &allocator = backend_allocator();
            if (!allocator)
            {
                (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                return std::unexpected(Error{ErrorCode::AllocatorNotAvailable, "hook::mid_at"});
            }
            ModuleRefGuard self_ref(DetourModKit::detail::acquire_module_ref());
            if (self_ref.get() == nullptr)
            {
                (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "hook::mid_at"});
            }
            try
            {
                auto created = safetyhook::MidHook::create(allocator, reinterpret_cast<void *>(target),
                                                           to_backend_detour(detour), safetyhook::MidHook::Default);
                if (!created)
                {
                    log().error("hook::mid_at: backend create failed for '{}' at {}: {}", request.name,
                                format::format_address(target), backend_error_string(created.error()));
                    (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                    return std::unexpected(Error{ErrorCode::BackendFailed, "hook::mid_at", target});
                }
                auto backend_hook = std::move(created.value());
                const HookState state = backend_hook.enabled() ? HookState::Active : HookState::Disabled;
                // Store the reserved ledger id in the Impl (see inline_at_raw). make_unique, the gate allocation, and
                // the info log are the only steps that can throw under OOM; the catch below rolls the reservation back
                // and `impl` (if built) unwinds to restore the prologue.
                auto impl = std::make_unique<Hook::Impl>(std::move(backend_hook), std::move(request.name), target,
                                                         ledger_id, state);
                // A mid hook has no callable original, so its gate stays null-callable (a guarded call() returns the
                // inactive default); it still carries the gate so enable/disable/teardown serialize through it.
                auto gate = std::make_shared<Hook::CallGate>();
                const std::string_view created_name = impl->name;
                log().info("hook::mid_at: created mid hook '{}' at {}.", created_name, format::format_address(target));
                DetourModKit::detail::HookLedger::instance().commit_hook(target, ledger_id);
                emit_lifecycle(created_name, ledger_id, diagnostics::HookKind::Mid,
                               diagnostics::HookTransition::Created);
                // The module reference was taken before SafetyHook patched the target; hand it to the Impl only after
                // every fallible setup step has completed.
                impl->self_ref = self_ref.release();
                return Hook(std::move(impl), std::move(gate));
            }
            catch (const std::bad_alloc &)
            {
                (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::mid_at", target});
            }
            catch (...)
            {
                (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                return std::unexpected(Error{ErrorCode::UnknownError, "hook::mid_at", target});
            }
        }

        Result<std::vector<InstallOutcome>> install_all(std::span<const HookSpec> table) noexcept
        {
            // Roll back a partially-built install NEWEST-FIRST. A std::vector<InstallOutcome> destroys its elements
            // oldest-first (forward element destruction), which for hooks layered on one target restores an older
            // hook's prologue over a newer hook's live trampoline (a use-after-free). This guard owns the teardown
            // order for BOTH failure paths -- the mandatory-miss early return and an exception (a bad_alloc copying a
            // row's scan request or growing the vector) unwinding the loop -- by popping from the back in its
            // destructor, unless the rows were committed out to the caller on success.
            class InstallRollback
            {
            public:
                InstallRollback() = default;
                InstallRollback(const InstallRollback &) = delete;
                InstallRollback &operator=(const InstallRollback &) = delete;
                ~InstallRollback()
                {
                    while (!m_rows.empty())
                    {
                        m_rows.pop_back();
                    }
                }

                [[nodiscard]] std::vector<InstallOutcome> &rows() noexcept { return m_rows; }
                [[nodiscard]] std::vector<InstallOutcome> commit() noexcept { return std::move(m_rows); }

            private:
                std::vector<InstallOutcome> m_rows;
            };

            try
            {
                InstallRollback rollback;
                rollback.rows().reserve(table.size());
                for (const HookSpec &spec : table)
                {
                    // Build the per-row request from the spec. The OwnedScanRequest is copied so install_all never
                    // moves out of the caller's (possibly const) table; the policy is the safe default Options.
                    Target target = spec.m_target;
                    Result<Hook> installed =
                        std::holds_alternative<InlineDetour>(spec.m_detour)
                            ? detail::inline_at_raw(InlineRequest{spec.m_name, std::move(target), Options{}},
                                                    std::get<InlineDetour>(spec.m_detour).fn)
                            : mid_at(MidRequest{spec.m_name, std::move(target), Options{}},
                                     std::get<MidHookFn>(spec.m_detour));

                    if (!installed && spec.m_severity == Severity::Mandatory)
                    {
                        // Fail fast: returning here runs ~InstallRollback, which unhooks every already-installed row
                        // newest-first before the error propagates, so a mandatory miss rolls the whole table back
                        // (in the safe order) rather than leaving a partial install.
                        return std::unexpected(installed.error());
                    }
                    rollback.rows().push_back(InstallOutcome{spec.m_name, spec.m_severity, std::move(installed)});
                }
                return rollback.commit();
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::install_all"});
            }
            catch (...)
            {
                return std::unexpected(Error{ErrorCode::UnknownError, "hook::install_all"});
            }
        }

        bool is_target_hooked(Address target) noexcept
        {
            return DetourModKit::detail::HookLedger::instance().is_target_hooked(target.raw());
        }

        // VmtHook -- RAII handle for a cloned vtable (object-level clone lifecycle).
        VmtHook::VmtHook(std::unique_ptr<Impl> impl) noexcept : m_impl(std::move(impl)) {}

        VmtHook::VmtHook(VmtHook &&other) noexcept : m_impl(std::move(other.m_impl)) {}

        VmtHook &VmtHook::operator=(VmtHook &&other) noexcept
        {
            if (this != &other)
            {
                VmtHook discard(std::move(*this));
                m_impl = std::move(other.m_impl);
            }
            return *this;
        }

        VmtHook::~VmtHook()
        {
            if (!m_impl)
            {
                return;
            }
            // Loader-lock leaf discipline: under the loader lock, leave the cloned vtables installed rather than
            // restore vptrs, which is a bare write that could race a loader callback. Leak the Impl; it carries the
            // module reference taken before the clone was published (self_ref), so leaking it keeps the clone's code
            // pages mapped.
            if (DetourModKit::detail::is_loader_lock_held())
            {
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                (void)m_impl.release();
                return;
            }
            const std::uint64_t ledger_id = m_impl->ledger_id;
            // Copy the name out before reset (which restores the vptrs and destroys the name storage); the lifecycle
            // event below reads it. A std::string copy can throw under OOM and this is a noexcept destructor, so
            // contain the copy and degrade to an empty name rather than letting the throw escape.
            std::string name;
            try
            {
                name = m_impl->name;
            }
            catch (...)
            {
            }
            // Restore the original vptr on every applied object FIRST, while the ledger still records this clone, THEN
            // release the ledger entry -- the same ordering as Hook::~Hook, so a concurrent vmt_for/apply_to keeps
            // seeing the clone base as live until its restore completes instead of racing a half-removed clone.
            HMODULE self_ref = nullptr;
            {
                std::unique_lock<std::mutex> object_gate = acquire_vmt_object_lock();
                if (!object_gate.owns_lock())
                {
                    // Leak the Impl (with its install-time module reference, which keeps the clone mapped) rather than
                    // restore vptrs without the gate.
                    diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                    (void)m_impl.release();
                    return;
                }
                self_ref = static_cast<HMODULE>(m_impl->self_ref);
                m_impl.reset();
            }
            // Release outside the object gate: release_module_ref calls FreeLibrary, which takes the loader lock, and
            // we must not hold the process-wide VMT gate while acquiring the loader lock. The host still holds its own
            // load reference, so this is never the terminal release.
            DetourModKit::detail::release_module_ref(self_ref);
            DetourModKit::detail::HookLedger::instance().release_vmt(ledger_id);
            emit_lifecycle(name, ledger_id, diagnostics::HookKind::Vmt, diagnostics::HookTransition::Removed);
        }

        VmtHook::operator bool() const noexcept
        {
            return m_impl != nullptr;
        }

        std::string_view VmtHook::name() const noexcept
        {
            return m_impl ? std::string_view{m_impl->name} : std::string_view{};
        }

        Result<void> VmtHook::apply_to(void *object, VmtOptions options)
        {
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::vmt_apply"});
            }
            if (object == nullptr)
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_apply"});
            }
            std::unique_lock<std::mutex> object_gate = acquire_vmt_object_lock();
            if (!object_gate.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::UnknownError, "hook::vmt_apply"});
            }
            // Exclusive write across the whole apply: the pre-flight decision (already-on-my-clone / foreign-clone) and
            // the backend swap are one atomic step, and an original() snapshot reader dispatching through this handle
            // observes the object either fully on the clone or not yet. The process-wide object gate serializes this
            // vptr transition against vmt_for/apply/remove on other handles targeting the same object.
            std::unique_lock<DetourModKit::detail::SrwSharedMutex> gate(m_impl->method_mutex);
            if (options.fail_if_already_hooked || options.fail_on_non_function_pointer)
            {
                const std::optional<std::uintptr_t> current_vptr =
                    DetourModKit::detail::guarded_read<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(object));
                if (!current_vptr)
                {
                    return std::unexpected(
                        Error{ErrorCode::InvalidObject, "hook::vmt_apply", reinterpret_cast<std::uintptr_t>(object)});
                }
                if (options.fail_if_already_hooked)
                {
                    if (*current_vptr == m_impl->cloned_vptr_base)
                    {
                        // Already on this hook's own clone -- a clean no-op rather than a silent re-apply.
                        return {};
                    }
                    if (DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(*current_vptr))
                    {
                        // On a clone owned by a different VmtHook of this kit: refuse rather than chain on top.
                        return std::unexpected(Error{ErrorCode::HookAlreadyExists, "hook::vmt_apply", *current_vptr});
                    }
                }
                if (options.fail_on_non_function_pointer)
                {
                    const std::optional<std::uintptr_t> slot0 =
                        DetourModKit::detail::guarded_read<std::uintptr_t>(*current_vptr);
                    if (!slot0)
                    {
                        return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_apply", *current_vptr});
                    }
                    if (!looks_like_function_vmt_slot(*slot0))
                    {
                        return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_apply", *slot0});
                    }
                }
            }
            // The backend tracks the applied object in an internal container, so apply can throw bad_alloc; contain it
            // so a failed apply returns an Error instead of unwinding out of the handle method.
            try
            {
                m_impl->backend.apply(object);
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::vmt_apply"});
            }
            catch (...)
            {
                return std::unexpected(
                    Error{ErrorCode::BackendFailed, "hook::vmt_apply", reinterpret_cast<std::uintptr_t>(object)});
            }
            return {};
        }

        Result<void> VmtHook::remove_from(void *object)
        {
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::vmt_remove"});
            }
            if (object == nullptr)
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_remove"});
            }
            std::unique_lock<std::mutex> object_gate = acquire_vmt_object_lock();
            if (!object_gate.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::UnknownError, "hook::vmt_remove"});
            }
            // Take the exclusive write so an un-apply cannot race a concurrent original() snapshot reader:
            // the reader sees the clone either fully applied to @p object or fully removed, never a torn transition.
            // The object gate serializes the actual vptr restore against other handle-level vptr transitions.
            std::unique_lock<DetourModKit::detail::SrwSharedMutex> gate(m_impl->method_mutex);
            // Best-effort restore: the backend restores the original vptr on @p object, and removing an object that is
            // not on this clone is a harmless no-op.
            m_impl->backend.remove(object);
            return {};
        }

        Result<void> VmtHook::hook_method_raw(std::size_t index, void *detour)
        {
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::vmt_hook_method"});
            }
            if (detour == nullptr)
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "hook::vmt_hook_method"});
            }
            {
                // Exclusive write: the map insert and the backend slot patch must be atomic against a concurrent
                // original() snapshot reader, which traverses this same map under the shared read.
                std::unique_lock<DetourModKit::detail::SrwSharedMutex> gate(m_impl->method_mutex);
                if (index >= m_impl->method_count)
                {
                    return std::unexpected(Error{ErrorCode::InvalidArg, "hook::vmt_hook_method", index});
                }
                if (m_impl->method_hooks.contains(index))
                {
                    // One method hook per slot: a second hook_method on the same index would read the first detour as
                    // the "original", silently chaining the mods. Refuse instead, matching the object-clone double-hook
                    // guard.
                    return std::unexpected(Error{ErrorCode::MethodAlreadyHooked, "hook::vmt_hook_method", index});
                }
                try
                {
                    // hook_method<T> stores the raw pointer bytes into the cloned slot, so a void* detour installs the
                    // same 8 bytes a typed function pointer would; the public hook_method<Fn> already vetted the ABI.
                    auto created = m_impl->backend.hook_method(index, detour);
                    if (!created)
                    {
                        return std::unexpected(Error{ErrorCode::BackendFailed, "hook::vmt_hook_method", index});
                    }
                    // The returned VmHook captured the pre-hook slot value (its original()) and already wrote the
                    // detour into the clone; storing it here keeps that snapshot for original() and defers the slot
                    // restore to remove_method / teardown (the VmHook destructor rewrites the slot). emplace is the
                    // last fallible step and the commit point: a bad_alloc here unwinds the just-created VmHook and
                    // rolls the slot back, so nothing is half-registered.
                    m_impl->method_hooks.emplace(index, std::move(created.value()));
                }
                catch (const std::bad_alloc &)
                {
                    return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::vmt_hook_method", index});
                }
                catch (...)
                {
                    return std::unexpected(Error{ErrorCode::BackendFailed, "hook::vmt_hook_method", index});
                }
            }
            // The method hook is committed. Logging is best-effort observability that must run after the commit yet
            // must not flip a committed install into a failure: log().info formats into a std::string and can throw
            // bad_alloc, so contain it and degrade to no log line (the same guard ~VmtHook uses for its name copy).
            // Emitting the log before the commit would instead risk a success line for a slot that emplace rolled back.
            try
            {
                log().info("hook::hook_method: hooked method index {} on VMT hook '{}'.", index,
                           std::string_view{m_impl->name});
            }
            catch (...)
            {
            }
            return {};
        }

        void *VmtHook::method_original_address(std::size_t index) const noexcept
        {
            if (!m_impl)
            {
                return nullptr;
            }
            // Shared read: copy the immutable pre-hook slot pointer out and return it. The lock serialises this
            // snapshot against a concurrent hook_method / remove_method / apply_to / remove_from exclusive write so the
            // map traversal is never torn; the copied pointer is then called lock-free by contract (see original()).
            std::shared_lock<DetourModKit::detail::SrwSharedMutex> gate(m_impl->method_mutex);
            const auto it = m_impl->method_hooks.find(index);
            if (it == m_impl->method_hooks.end())
            {
                return nullptr;
            }
            return it->second.original<void *>();
        }

        Result<void> VmtHook::remove_method(std::size_t index)
        {
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::vmt_remove_method"});
            }
            {
                // Exclusive write: erasing the entry runs the VmHook destructor, which rewrites the cloned slot back to
                // the original pointer; that restore must not race an original() snapshot reader on the same slot.
                std::unique_lock<DetourModKit::detail::SrwSharedMutex> gate(m_impl->method_mutex);
                const auto it = m_impl->method_hooks.find(index);
                if (it == m_impl->method_hooks.end())
                {
                    return std::unexpected(Error{ErrorCode::MethodNotFound, "hook::vmt_remove_method", index});
                }
                m_impl->method_hooks.erase(it);
            }
            // The removal is committed (the VmHook destructor already restored the slot). Contain the best-effort log
            // so a formatting bad_alloc degrades to no log line rather than escaping this Result-returning function as
            // an exception.
            try
            {
                log().info("hook::remove_method: removed method index {} from VMT hook '{}'.", index,
                           std::string_view{m_impl->name});
            }
            catch (...)
            {
            }
            return {};
        }

        void VmtHook::release() noexcept
        {
            if (!m_impl)
            {
                return;
            }
            // Leak the cloned vtable intentionally: applied objects keep the clone for the process lifetime. The
            // ledger entry stays so is_vmt_clone_base still recognises the live clone base.
            (void)m_impl.release();
        }

        Result<VmtHook> vmt_for(std::string name, void *object, VmtOptions options)
        {
            if (name.empty())
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "hook::vmt_for"});
            }
            if (object == nullptr)
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for"});
            }
            // Take the module reference BEFORE the process-wide VMT object gate. On any rollback (a create/record/setup
            // failure after this point) the ModuleRefGuard destructor calls release_module_ref -> FreeLibrary, which
            // takes the OS loader lock; running that while holding the object gate would invert the lock order ~VmtHook
            // is careful to avoid (it releases its reference OUTSIDE the gate for exactly this reason) and could
            // deadlock a VMT op dispatched from a loader-lock context. Declaring the guard before the gate makes the
            // gate (a later-declared local) unlock first, so the guard's FreeLibrary always runs outside the gate. The
            // reference is object-independent and still precedes publication (the clone create and vptr swap below),
            // and is handed to the Impl on success (self_ref.release()).
            ModuleRefGuard self_ref(DetourModKit::detail::acquire_module_ref());
            if (self_ref.get() == nullptr)
            {
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "hook::vmt_for"});
            }
            std::unique_lock<std::mutex> object_gate = acquire_vmt_object_lock();
            if (!object_gate.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::UnknownError, "hook::vmt_for"});
            }
            if (options.fail_if_already_hooked || options.fail_on_non_function_pointer)
            {
                const std::optional<std::uintptr_t> current_vptr =
                    DetourModKit::detail::guarded_read<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(object));
                if (!current_vptr)
                {
                    return std::unexpected(
                        Error{ErrorCode::InvalidObject, "hook::vmt_for", reinterpret_cast<std::uintptr_t>(object)});
                }
                if (options.fail_if_already_hooked &&
                    DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(*current_vptr))
                {
                    return std::unexpected(Error{ErrorCode::HookAlreadyExists, "hook::vmt_for", *current_vptr});
                }
                if (options.fail_on_non_function_pointer)
                {
                    const std::optional<std::uintptr_t> slot0 =
                        DetourModKit::detail::guarded_read<std::uintptr_t>(*current_vptr);
                    if (!slot0)
                    {
                        return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for", *current_vptr});
                    }
                    if (!looks_like_function_vmt_slot(*slot0))
                    {
                        return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for", *slot0});
                    }
                }
            }
            const std::optional<std::size_t> method_count = count_vmt_method_slots(object);
            if (!method_count)
            {
                return std::unexpected(
                    Error{ErrorCode::InvalidObject, "hook::vmt_for", reinterpret_cast<std::uintptr_t>(object)});
            }
            try
            {
                auto created = safetyhook::VmtHook::create(object);
                if (!created)
                {
                    return std::unexpected(
                        Error{ErrorCode::BackendFailed, "hook::vmt_for", reinterpret_cast<std::uintptr_t>(object)});
                }
                auto backend_hook = std::move(created.value());

                // Capture the clone address point the backend just installed; future apply/fail-if-hooked checks
                // compare against it. The read is fault-guarded; on a fault, returning before recording lets
                // backend_hook's destructor roll the original vptr back rather than dereferencing a bad pointer.
                const std::optional<std::uintptr_t> base =
                    DetourModKit::detail::guarded_read<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(object));
                if (!base)
                {
                    return std::unexpected(
                        Error{ErrorCode::InvalidObject, "hook::vmt_for", reinterpret_cast<std::uintptr_t>(object)});
                }
                // make_unique, the only step that can still throw under OOM, runs before the ledger record so a throw
                // unwinds `impl` (restoring the object's vptr) without leaving a phantom ledger entry.
                auto impl =
                    std::make_unique<VmtHook::Impl>(std::move(backend_hook), std::move(name), *base, *method_count, 0);
                const std::string_view created_name = impl->name;
                // Record the clone as the final committed step. try_record_vmt is noexcept: on an out-of-memory
                // bookkeeping failure it returns nullopt, and failing the create here unwinds `impl` (restoring the
                // vptr off the clone) rather than leaving a live-but-untracked clone that is_vmt_clone_base cannot see.
                const std::optional<std::uint64_t> recorded =
                    DetourModKit::detail::HookLedger::instance().try_record_vmt(*base);
                if (!recorded)
                {
                    return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::vmt_for"});
                }
                impl->ledger_id = *recorded;
                // The object gate has served its purpose (the check / vptr swap / ledger record are now one ordered
                // step). Release it BEFORE the create log and the lifecycle event: emit_lifecycle runs arbitrary
                // subscriber code, which must not execute while the process-wide VMT mutex is held (CP.22 -- never call
                // unknown code under a lock), or a subscriber that re-enters vmt_for/apply_to/remove_from on this
                // thread would self-deadlock on the non-recursive mutex; and the info log formats a std::string and
                // touches the sink, work that likewise must not run under a process-wide gate that serializes every VMT
                // transition.
                object_gate.unlock();
                // Best-effort post-commit log, now outside the gate. log().info can throw bad_alloc on the format, so
                // contain it and degrade to no log line rather than failing an already-committed clone (matching the
                // post-commit logs in hook_method_raw / remove_method).
                try
                {
                    log().info("hook::vmt_for: created VMT hook '{}' on object {}.", created_name,
                               format::format_address(reinterpret_cast<std::uintptr_t>(object)));
                }
                catch (...)
                {
                }
                emit_lifecycle(created_name, *recorded, diagnostics::HookKind::Vmt,
                               diagnostics::HookTransition::Created);
                // The module reference was taken before the object vptr was swapped to the clone; hand it to the Impl
                // only after every fallible setup step has completed.
                impl->self_ref = self_ref.release();
                return VmtHook(std::move(impl));
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::vmt_for"});
            }
            catch (...)
            {
                return std::unexpected(Error{ErrorCode::UnknownError, "hook::vmt_for"});
            }
        }
    } // namespace hook
} // namespace DetourModKit
