/**
 * @file hook.cpp
 * @brief Implementation of the hooking surface: the free verbs, the RAII handles, and the backend bridge.
 * @details This is the single translation unit (with internal/hook_backend.hpp) that names the SafetyHook backend.
 *          It hosts: the opaque MidContext <-> backend-context reinterpret_cast accessors; the process-wide
 *          allocator; the inline/mid create paths (target resolution, duplicate detection, prologue pre-flight,
 *          backend create, ledger bookkeeping); the RAII Hook and VmtHook handle bodies (including the loader-lock
 *          leaf teardown discipline); the declarative install_all; and the VMT object-clone lifecycle.
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
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace DetourModKit
{
    // -----------------------------------------------------------------------------------------------------------------
    // File-local helpers. These live at DetourModKit scope (not inside namespace hook) so a bare `detail::` resolves to
    // DetourModKit::detail (the memory/x86/platform engine), not the hook::detail sub-namespace that would otherwise
    // shadow it and break the unqualified lookup.
    // -----------------------------------------------------------------------------------------------------------------
    namespace
    {
        /// Result of the foreign-inline-hook pre-flight: whether the target already redirects, and to where.
        enum class PrehookState
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
         * @brief Decodes a leading E9 (jmp rel32) or FF 25 (jmp [rip+disp32]) redirect at @p target_address.
         * @details The opcode bytes are read under a fault guard; returns the jump destination, or nullopt when the
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

            // Only E9 (jmp rel32) and FF 25 (jmp [rip+disp32]) can redirect a prologue into a hook trampoline in
            // another module. EB (jmp rel8) reaches at most +/-127 bytes, far too short to land in a foreign hook
            // stub, so a leading 0xEB is ordinary code, not a pre-existing inline hook; matching it would only add
            // false positives on functions that legitimately begin with a short jump.
            if (opcode[0] == 0xE9)
            {
                return detail::decode_e9_rel32(target_address);
            }
            if (opcode[0] == 0xFF && opcode[1] == 0x25)
            {
                return detail::decode_ff25_indirect(target_address);
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
        enum class PrologueRisk
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
            const auto ip_str = Format::format_address(reinterpret_cast<std::uintptr_t>(err.ip));
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
         * @brief Resolves a hook Target to an absolute address.
         * @details An absolute Address passes straight through; a deferred OwnedScanRequest is resolved through
         *          scan::resolve and its winning address returned (or its Error).
         */
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
        void emit_lifecycle(std::string_view name, std::uint64_t ledger_id, Diagnostics::HookKind kind,
                            Diagnostics::HookTransition transition) noexcept
        {
            try
            {
                Diagnostics::hook_lifecycle().emit_safe(Diagnostics::HookLifecycleEvent{
                    .name = name, .ledger_id = ledger_id, .kind = kind, .transition = transition});
            }
            catch (...)
            {
            }
        }

        /**
         * @brief Resolves, validates, and pre-flights an inline/mid hook target before the backend create.
         * @return The absolute target address, or the Error that should fail the install.
         * @details Shared by inline_at_raw and mid_at, which patch the same prologue and need identical duplicate
         *          detection (ledger exact-match then foreign-JMP heuristic) and prologue-risk pre-flight. Layering
         *          and Relocate-policy installs are warned but not refused; a strict fail_if_already_hooked match or a
         *          Fail-policy risky prologue is refused with the matching ErrorCode.
         */
        Result<std::uintptr_t> preflight_target(const hook::Target &target, const hook::Options &options,
                                                std::string_view name, const char *where) noexcept
        {
            Result<std::uintptr_t> resolved = resolve_target(target);
            if (!resolved)
            {
                return resolved;
            }
            const std::uintptr_t address = *resolved;
            if (address == 0)
            {
                return std::unexpected(Error{ErrorCode::InvalidTargetAddress, where});
            }

            // Duplicate detection. The ledger answers the exact "does this kit already patch here?" question; the
            // foreign-JMP heuristic (only consulted when the ledger says no) catches a patch placed by something else.
            if (detail::HookLedger::instance().is_target_hooked(address))
            {
                if (options.fail_if_already_hooked)
                {
                    return std::unexpected(Error{ErrorCode::TargetAlreadyHookedInProcess, where, address});
                }
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: '{}' layers on a hook this kit already placed at {}; destroy layered hooks newest-first.",
                    name, Format::format_address(address));
            }
            else
            {
                const PrehookDetection prehook = detect_existing_inline_hook(address);
                if (prehook.state == PrehookState::HookedByOtherModule)
                {
                    if (options.fail_if_already_hooked)
                    {
                        return std::unexpected(Error{ErrorCode::TargetAlreadyHookedInProcess, where, address});
                    }
                    (void)log().try_log(
                        LogLevel::Warning,
                        "hook: '{}' target {} is already inline-hooked by another module (JMP -> {}); layering on top.",
                        name, Format::format_address(address), Format::format_address(prehook.jmp_destination));
                }
            }

            // Prologue pre-flight, independent of the layering checks: a target can be unhooked yet still begin with a
            // call thunk or a patched int3.
            const PrologueRisk risk = classify_prologue_risk(address);
            if (risk != PrologueRisk::None)
            {
                if (options.prologue == hook::Prologue::Fail)
                {
                    return std::unexpected(Error{ErrorCode::TargetPrologueUnsafe, where, address});
                }
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: '{}' target {} begins with {}; installed anyway under the Relocate prologue policy.", name,
                    Format::format_address(address), prologue_risk_description(risk));
            }
            return address;
        }
    } // namespace

    namespace hook
    {
        // -------------------------------------------------------------------------------------------------------------
        // hook::MidContext accessor bridge.
        //
        // At every mid-hook call the backend hands the detour a safetyhook::Context64& (the captured register file).
        // DMK exposes that as an OPAQUE hook::MidContext& so a consumer never names the backend. MidContext is never
        // defined, so these accessors are the single place that recovers the real type by reinterpret_cast; the cast
        // is well-defined precisely because MidContext is forever incomplete and is only ever the very Context64 the
        // backend passed in.
        // -------------------------------------------------------------------------------------------------------------
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

        // -------------------------------------------------------------------------------------------------------------
        // Hook -- RAII handle for one inline or mid hook.
        // -------------------------------------------------------------------------------------------------------------
        Hook::Hook(std::unique_ptr<Impl> impl) noexcept : m_impl(std::move(impl)) {}

        Hook::Hook(Hook &&other) noexcept : m_impl(std::move(other.m_impl)) {}

        Hook &Hook::operator=(Hook &&other) noexcept
        {
            if (this != &other)
            {
                // Adopt the current hook into a temporary whose destructor unhooks it at the end of this scope, then
                // take the source's hook. This reuses ~Hook's loader-lock-aware teardown without duplicating it.
                Hook discard(std::move(*this));
                m_impl = std::move(other.m_impl);
            }
            return *this;
        }

        Hook::~Hook()
        {
            if (!m_impl)
            {
                return;
            }

            // Loader-lock leaf discipline: under the OS loader lock (DllMain / FreeLibrary), restoring the prologue and
            // freeing the trampoline can deadlock against another thread waiting on a loader callback. Pin the module
            // so the code pages stay live, record the intentional leak, and leave the backend hook installed rather
            // than tear it down here.
            if (DetourModKit::detail::is_loader_lock_held())
            {
                DetourModKit::detail::pin_current_module();
                Diagnostics::record_intentional_leak(Diagnostics::LeakSubsystem::HookManager);
                (void)m_impl.release();
                return;
            }

            const std::uintptr_t target = m_impl->target;
            const std::uint64_t ledger_id = m_impl->ledger_id;
            const Diagnostics::HookKind kind =
                m_impl->is_inline ? Diagnostics::HookKind::Inline : Diagnostics::HookKind::Mid;
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

            // Serialize with any in-flight call(): it holds call_mutex for its whole invocation, so acquiring it here
            // waits the call out, and marking the hook Disabled makes a subsequently-arriving call() return its default
            // instead of dispatching through the trampoline (which the reset below frees).
            {
                std::unique_lock<std::recursive_mutex> guard(m_impl->call_mutex);
                m_impl->status.store(HookState::Disabled, std::memory_order_release);
            }

            // Restore the prologue and free the trampoline FIRST, while the ledger still records this hook on the
            // target, THEN release the ledger entry. Releasing before the backend is restored would open a window in
            // which the ledger reads the target as un-hooked while the patch is still physically installed: a
            // concurrent inline_at/mid_at on the same address could slip into that window, install over the live patch,
            // and then be clobbered by this restore (a trampoline use-after-free). Restoring first means a racing
            // create still sees the target as hooked (the safe direction) right up until the ledger entry is dropped.
            // No call() can be dispatching through it here: status is Disabled and the guard above drained any
            // in-flight call.
            m_impl.reset();

            const std::size_t newer = DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
            if (newer > 0)
            {
                // Best-effort warning on a noexcept teardown path: try_log swallows any formatting/sink failure so a
                // log allocation under memory pressure cannot throw out of the destructor.
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: '{}' at {} destroyed while {} newer hook(s) remain layered on the same target; destroy "
                    "layered hooks newest-first to avoid a trampoline use-after-free.",
                    name, Format::format_address(target), newer);
            }
            emit_lifecycle(name, ledger_id, kind, Diagnostics::HookTransition::Removed);
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
            if (!m_impl || !m_impl->is_inline)
            {
                return nullptr;
            }
            const auto *inline_backend = std::get_if<safetyhook::InlineHook>(&m_impl->backend);
            if (inline_backend == nullptr || !*inline_backend)
            {
                return nullptr;
            }
            return inline_backend->original<void *>();
        }

        std::unique_lock<std::recursive_mutex> Hook::acquire_call_lock() const
        {
            // Precondition: a live handle. call() on a moved-from / released handle is documented undefined behaviour.
            return std::unique_lock<std::recursive_mutex>(m_impl->call_mutex);
        }

        void *Hook::active_trampoline() const noexcept
        {
            if (!m_impl || !m_impl->is_inline || m_impl->status.load(std::memory_order_acquire) != HookState::Active)
            {
                return nullptr;
            }
            const auto *inline_backend = std::get_if<safetyhook::InlineHook>(&m_impl->backend);
            if (inline_backend == nullptr || !*inline_backend)
            {
                return nullptr;
            }
            return inline_backend->original<void *>();
        }

        Result<void> Hook::enable() noexcept
        {
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            std::unique_lock<std::recursive_mutex> guard(m_impl->call_mutex);
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
                const Diagnostics::HookKind kind =
                    m_impl->is_inline ? Diagnostics::HookKind::Inline : Diagnostics::HookKind::Mid;
                const std::string_view name = m_impl->name;
                const std::uint64_t ledger_id = m_impl->ledger_id;
                // Release the call guard before dispatching the lifecycle event: emit_lifecycle runs arbitrary
                // subscriber code, which must not execute while DMK's per-hook mutex is held (CP.22 -- never call
                // unknown code under a lock). enable() does not reset m_impl, so the captured name view and ledger id
                // stay valid.
                guard.unlock();
                emit_lifecycle(name, ledger_id, kind, Diagnostics::HookTransition::Enabled);
                return {};
            }
            m_impl->status.store(HookState::Disabled, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable"});
        }

        Result<void> Hook::disable() noexcept
        {
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::disable"});
            }
            std::unique_lock<std::recursive_mutex> guard(m_impl->call_mutex);
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
                const Diagnostics::HookKind kind =
                    m_impl->is_inline ? Diagnostics::HookKind::Inline : Diagnostics::HookKind::Mid;
                const std::string_view name = m_impl->name;
                const std::uint64_t ledger_id = m_impl->ledger_id;
                // Release the call guard before dispatching the lifecycle event (CP.22, see enable()); disable() does
                // not reset m_impl, so the captured name view and ledger id stay valid past the unlock.
                guard.unlock();
                emit_lifecycle(name, ledger_id, kind, Diagnostics::HookTransition::Disabled);
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
            // left in place too, since is_target_hooked must still report the target as hooked.
            (void)m_impl.release();
        }

        // -------------------------------------------------------------------------------------------------------------
        // Free install verbs.
        // -------------------------------------------------------------------------------------------------------------
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
                Result<std::uintptr_t> address =
                    preflight_target(request.target, request.options, request.name, "hook::inline_at");
                if (!address)
                {
                    return std::unexpected(address.error());
                }
                const std::uintptr_t target = *address;

                const std::shared_ptr<safetyhook::Allocator> &allocator = backend_allocator();
                if (!allocator)
                {
                    return std::unexpected(Error{ErrorCode::AllocatorNotAvailable, "hook::inline_at"});
                }
                try
                {
                    auto created = safetyhook::InlineHook::create(allocator, reinterpret_cast<void *>(target), detour,
                                                                  safetyhook::InlineHook::Default);
                    if (!created)
                    {
                        log().error("hook::inline_at: backend create failed for '{}' at {}: {}", request.name,
                                    Format::format_address(target), backend_error_string(created.error()));
                        return std::unexpected(Error{ErrorCode::BackendFailed, "hook::inline_at", target});
                    }
                    auto backend_hook = std::move(created.value());
                    const HookState state = backend_hook.enabled() ? HookState::Active : HookState::Disabled;
                    // Record in the ledger as the final committed step. make_unique and the info log are the only steps
                    // that can throw under OOM; running both BEFORE record_hook means a throw unwinds `impl` (its
                    // destructor restores the prologue) without ever leaving a phantom ledger entry whose hook never
                    // came to exist. record_hook is noexcept (0 == untracked) and nothing fallible runs after it.
                    auto impl = std::make_unique<Hook::Impl>(std::move(backend_hook), std::move(request.name), target,
                                                             0, state);
                    const std::string_view created_name = impl->name;
                    log().info("hook::inline_at: created inline hook '{}' at {}.", created_name,
                               Format::format_address(target));
                    impl->ledger_id = DetourModKit::detail::HookLedger::instance().record_hook(target);
                    emit_lifecycle(created_name, impl->ledger_id, Diagnostics::HookKind::Inline,
                                   Diagnostics::HookTransition::Created);
                    return Hook(std::move(impl));
                }
                catch (const std::bad_alloc &)
                {
                    return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::inline_at", target});
                }
                catch (...)
                {
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
            Result<std::uintptr_t> address =
                preflight_target(request.target, request.options, request.name, "hook::mid_at");
            if (!address)
            {
                return std::unexpected(address.error());
            }
            const std::uintptr_t target = *address;

            const std::shared_ptr<safetyhook::Allocator> &allocator = backend_allocator();
            if (!allocator)
            {
                return std::unexpected(Error{ErrorCode::AllocatorNotAvailable, "hook::mid_at"});
            }
            try
            {
                auto created = safetyhook::MidHook::create(allocator, reinterpret_cast<void *>(target),
                                                           to_backend_detour(detour), safetyhook::MidHook::Default);
                if (!created)
                {
                    log().error("hook::mid_at: backend create failed for '{}' at {}: {}", request.name,
                                Format::format_address(target), backend_error_string(created.error()));
                    return std::unexpected(Error{ErrorCode::BackendFailed, "hook::mid_at", target});
                }
                auto backend_hook = std::move(created.value());
                const HookState state = backend_hook.enabled() ? HookState::Active : HookState::Disabled;
                // Record in the ledger as the final committed step (see inline_at_raw): make_unique and the info log,
                // the only steps that can throw under OOM, run before record_hook so a throw unwinds `impl` without
                // leaving a phantom ledger entry. record_hook is noexcept and nothing fallible runs after it.
                auto impl =
                    std::make_unique<Hook::Impl>(std::move(backend_hook), std::move(request.name), target, 0, state);
                const std::string_view created_name = impl->name;
                log().info("hook::mid_at: created mid hook '{}' at {}.", created_name, Format::format_address(target));
                impl->ledger_id = DetourModKit::detail::HookLedger::instance().record_hook(target);
                emit_lifecycle(created_name, impl->ledger_id, Diagnostics::HookKind::Mid,
                               Diagnostics::HookTransition::Created);
                return Hook(std::move(impl));
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::mid_at", target});
            }
            catch (...)
            {
                return std::unexpected(Error{ErrorCode::UnknownError, "hook::mid_at", target});
            }
        }

        Result<std::vector<InstallOutcome>> install_all(std::span<const HookSpec> table) noexcept
        {
            try
            {
                std::vector<InstallOutcome> outcomes;
                outcomes.reserve(table.size());
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
                        // Fail fast: discarding `outcomes` here unhooks every row already installed, so a mandatory
                        // miss rolls the whole table back rather than leaving a partial install.
                        return std::unexpected(installed.error());
                    }
                    outcomes.push_back(InstallOutcome{spec.m_name, spec.m_severity, std::move(installed)});
                }
                return outcomes;
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

        // -------------------------------------------------------------------------------------------------------------
        // VmtHook -- RAII handle for a cloned vtable (object-level clone lifecycle).
        // -------------------------------------------------------------------------------------------------------------
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
            // Loader-lock leaf discipline: under the loader lock, leave the cloned vtables installed (pinned) rather
            // than restore vptrs, which is a bare write that could race a loader callback.
            if (DetourModKit::detail::is_loader_lock_held())
            {
                DetourModKit::detail::pin_current_module();
                Diagnostics::record_intentional_leak(Diagnostics::LeakSubsystem::HookManager);
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
            m_impl.reset();
            DetourModKit::detail::HookLedger::instance().release_vmt(ledger_id);
            emit_lifecycle(name, ledger_id, Diagnostics::HookKind::Vmt, Diagnostics::HookTransition::Removed);
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
            // Best-effort restore: the backend restores the original vptr on @p object, and removing an object that is
            // not on this clone is a harmless no-op.
            m_impl->backend.remove(object);
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
            try
            {
                auto created = safetyhook::VmtHook::create(object);
                if (!created)
                {
                    return std::unexpected(
                        Error{ErrorCode::BackendFailed, "hook::vmt_for", reinterpret_cast<std::uintptr_t>(object)});
                }
                auto backend_hook = std::move(created.value());

                // Capture the vptr the backend just installed (*object == &clone[1]); future apply/fail-if-hooked
                // checks compare against it. The read is fault-guarded; on a fault, returning before recording lets
                // backend_hook's destructor roll the original vptr back rather than dereferencing a bad pointer.
                const std::optional<std::uintptr_t> base =
                    DetourModKit::detail::guarded_read<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(object));
                if (!base)
                {
                    return std::unexpected(
                        Error{ErrorCode::InvalidObject, "hook::vmt_for", reinterpret_cast<std::uintptr_t>(object)});
                }
                // Record in the ledger as the final committed step (see inline_at_raw): make_unique and the info log,
                // the only steps that can throw under OOM, run before record_vmt so a throw unwinds `impl` without
                // leaving a phantom ledger entry. record_vmt is noexcept and nothing fallible runs after it.
                auto impl = std::make_unique<VmtHook::Impl>(std::move(backend_hook), std::move(name), *base, 0);
                const std::string_view created_name = impl->name;
                log().info("hook::vmt_for: created VMT hook '{}' on object {}.", created_name,
                           Format::format_address(reinterpret_cast<std::uintptr_t>(object)));
                impl->ledger_id = DetourModKit::detail::HookLedger::instance().record_vmt(*base);
                emit_lifecycle(created_name, impl->ledger_id, Diagnostics::HookKind::Vmt,
                               Diagnostics::HookTransition::Created);
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
