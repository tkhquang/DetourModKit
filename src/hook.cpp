/**
 * @file hook.cpp
 * @brief This TU implements the hook surface, free verbs, RAII handles, and backend bridge.
 * @details This TU and internal/hook_backend.hpp form the only layer that names the SafetyHook backend.
 */

#include "DetourModKit/hook.hpp"

#include "internal/diagnostics_population.hpp"
#include "internal/hook_backend.hpp"
#include "internal/hook_fault_boundary.hpp"
#include "internal/hook_ledger.hpp"
#include "internal/hook_patch_witness.hpp"
#include "internal/lifecycle_context.hpp"
#if defined(DMK_ENABLE_TEST_SEAMS)
#include "internal/hook_publication.hpp"
#endif
#include "internal/drain_backoff.hpp"
#include "internal/memory_guarded.hpp"
#include "internal/mid_hook_adapter.hpp"

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/format.hpp"
#include "DetourModKit/logger.hpp"

#include "platform.hpp"
#include "x86_decode.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    namespace
    {
        std::atomic<std::size_t> s_backend_toggle_exception_catches{0};
        std::atomic<std::uint64_t> s_hook_impl_destructions{0};
    } // namespace

    std::uint64_t hook_impl_destruction_count_for_test() noexcept
    {
        return s_hook_impl_destructions.load(std::memory_order_relaxed);
    }

    void note_hook_impl_destruction_for_test() noexcept
    {
        s_hook_impl_destructions.fetch_add(1, std::memory_order_relaxed);
    }

    // The test-only acquire_hook_self_ref() override lets the suite drive the otherwise-unreachable acquire failure
    // branch. The override must SetLastError before a nullptr return to satisfy error.hpp's
    // `detail = GetLastError()` contract.
    HMODULE (*g_hook_module_ref_override)() noexcept = nullptr;

    // Overrides the byte witness Hook::enable() takes after the backend reports a successful patch. The suite can then
    // drive the negative branch a real backend does not produce on demand.
    bool (*g_hook_enable_witness_override)(bool) noexcept = nullptr;
    // Runs after a managed backend disable returns or throws and before DMK witnesses its target bytes.
    void (*g_hook_backend_disable_probe)() noexcept = nullptr;
    // Overrides whether ~Hook attempts backend disable. A false return or exception models a pre-mutation failure.
    // It leaves the target patched. Post-process after a completed disable makes the pin unobservable.
    bool (*g_hook_teardown_restore_override)() = nullptr;
    // Fires at each inline/mid publication step after that step's state is visible. It is not noexcept on purpose.
    // A probe exception exercises the same rollback as a real bad_alloc.
    void (*g_hook_publish_probe)(HookPublishStep) = nullptr;
    // HookTogglePublicationOrder.* owns this proof seam.
    void (*g_hook_toggle_publication_probe)(bool, bool, bool, bool) noexcept = nullptr;
    // Fires at the first operation boundary after one mutation entry passes its loader-lock veto.
    void (*g_hook_post_loader_veto_probe)(HookLoaderEntry) noexcept = nullptr;
    // This probe fires after the vtable pre-count and before the guarded snapshot capture.
    void (*g_vmt_before_capture_probe)() noexcept = nullptr;
    // This probe fires after the captured slot count becomes fixed and before the backend sizes its clone.
    void (*g_vmt_before_backend_clone_probe)() noexcept = nullptr;
    // This probe fires after VMT validation and before the guarded atomic publication attempt.
    void (*g_vmt_before_publish_probe)(void *) noexcept = nullptr;
    // This probe fires after the VMT object gate release and before the leak warning reaches the logger.
    void (*g_vmt_teardown_warning_probe)() noexcept = nullptr;
    // This probe fires inside the mid-hook adapter between the fast-path live check and callback commit. See its
    // declaration in internal/mid_hook_adapter.hpp for the race it exists to make reachable.
    void (*g_mid_adapter_precommit_probe)() noexcept = nullptr;
    // Selects one thread whose adapter entry-chain store reports failure. See its declaration in
    // internal/mid_hook_adapter.hpp for the platform condition it stands in for.
    std::atomic<std::uint32_t> g_mid_entry_store_failure_thread{0};
    std::atomic<std::uint64_t> g_mid_entry_store_failure_hits{0};

    // Arms the backend's post-commit transaction seam for one target, or disarms it with nullptr. The backend can
    // return an error over a fully committed patch. enable() and disable() reconcile that exact state. This translation
    // unit forwards the seam because only it names the backend.
    void set_backend_reprotect_failure_target(void *target) noexcept
    {
        safetyhook::g_trap_restore_failure_override.store(static_cast<std::uint8_t *>(target),
                                                          std::memory_order_release);
    }

    // Arms a backend bad_alloc after transaction setup but before its mutation callback, or immediately after that
    // callback. trap_threads still restores protections and removes its trap before it rethrows into DMK's boundary.
    void set_backend_toggle_exception_for_test(void *target, bool after_mutation) noexcept
    {
        if (target == nullptr)
        {
            safetyhook::g_trap_exception_stage_override.store(safetyhook::TrapExceptionStage::NONE,
                                                              std::memory_order_release);
            safetyhook::g_trap_exception_target_override.store(nullptr, std::memory_order_relaxed);
            return;
        }

        s_backend_toggle_exception_catches.store(0, std::memory_order_relaxed);
        safetyhook::g_trap_exception_target_override.store(static_cast<std::uint8_t *>(target),
                                                           std::memory_order_relaxed);
        safetyhook::g_trap_exception_stage_override.store(after_mutation
                                                              ? safetyhook::TrapExceptionStage::AFTER_MUTATION
                                                              : safetyhook::TrapExceptionStage::BEFORE_MUTATION,
                                                          std::memory_order_release);
    }

    /// Reports how many managed backend exceptions the current test arm reached and contained.
    std::size_t backend_toggle_exception_catches_for_test() noexcept
    {
        return s_backend_toggle_exception_catches.load(std::memory_order_relaxed);
    }

    void set_mid_route_park_for_test(MidRouteParkStage stage) noexcept
    {
        safetyhook::RouteParkStage backend_stage = safetyhook::RouteParkStage::NONE;
        if (stage == MidRouteParkStage::BeforeAdapter)
        {
            backend_stage = safetyhook::RouteParkStage::BEFORE_DESTINATION;
        }
        else if (stage == MidRouteParkStage::AfterAdapter)
        {
            backend_stage = safetyhook::RouteParkStage::BEFORE_EXIT;
        }
        safetyhook::set_route_park_for_test(backend_stage);
    }

    bool mid_route_park_reached_for_test() noexcept
    {
        return safetyhook::route_park_reached_for_test();
    }

    void set_backend_trap_transaction_hold_for_test(bool hold) noexcept
    {
        if (hold)
        {
            safetyhook::g_trap_transaction_reached.store(false, std::memory_order_relaxed);
        }
        safetyhook::g_trap_transaction_hold.store(hold, std::memory_order_release);
    }

    bool backend_trap_transaction_reached_for_test() noexcept
    {
        return safetyhook::g_trap_transaction_reached.load(std::memory_order_acquire);
    }

    std::size_t backend_trap_protect_calls_for_test() noexcept
    {
        return safetyhook::g_trap_protect_calls.load(std::memory_order_relaxed);
    }

    void retire_backend_trap_runtime_for_test() noexcept
    {
        safetyhook::retire_trap_runtime_for_test();
    }

    TrapTransactionOutcome drive_backend_trap_transaction_for_test(void *from, void *to, std::size_t len,
                                                                   const std::function<void()> &run_fn) noexcept
    {
        try
        {
            safetyhook::reset_trap_restore_trace_for_test();
            const std::expected<void, safetyhook::OsError> result = safetyhook::trap_threads(
                static_cast<std::uint8_t *>(from), static_cast<std::uint8_t *>(to), len, run_fn);
            return result ? TrapTransactionOutcome::Restored : TrapTransactionOutcome::ReportedFailure;
        }
        catch (...)
        {
            return TrapTransactionOutcome::Threw;
        }
    }

    void set_backend_trap_change_failure_target_for_test(void *segment_address) noexcept
    {
        safetyhook::g_trap_change_failure_override.store(static_cast<std::uint8_t *>(segment_address),
                                                         std::memory_order_release);
    }

    void set_backend_trap_segment_restore_failure_target_for_test(void *segment_address) noexcept
    {
        safetyhook::g_trap_segment_restore_failure_override.store(static_cast<std::uint8_t *>(segment_address),
                                                                  std::memory_order_release);
    }

    std::size_t backend_trap_restore_trace_size_for_test() noexcept
    {
        return safetyhook::trap_restore_trace_size_for_test();
    }

    void *backend_trap_restore_trace_address_for_test(std::size_t index) noexcept
    {
        return safetyhook::trap_restore_trace_address_for_test(index);
    }
#endif

    // The mid-hook dispatch pool uses constant initialization and trivial destruction. It registers no destructor, so
    // it outlives an adapter that remains active during static destruction.
    namespace
    {
        MidAdapterSlot s_mid_slots[MID_ADAPTER_CAPACITY];
        std::atomic<DWORD> s_mid_entry_tls{TLS_OUT_OF_INDEXES};

        /// Defines the committed callback wait bound. Expiry pins the backend instead of a hang (MidHookDrainTest).
        constexpr auto MID_CALLBACK_DRAIN_TIMEOUT = std::chrono::seconds{5};

        /// Defines the post-restore adapter-body drain bound. Expiry retains the slot and stub (MidHookDrainTest).
        constexpr auto MID_ADAPTER_ENTRY_DRAIN_TIMEOUT = std::chrono::seconds{1};

#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<std::size_t> s_last_claimed_mid_slot{MID_ADAPTER_CAPACITY};
#endif
    } // namespace

    MidAdapterSlot *mid_adapter_slots() noexcept
    {
        return s_mid_slots;
    }

    std::atomic<DWORD> &mid_entry_tls_index() noexcept
    {
        return s_mid_entry_tls;
    }

    bool ensure_mid_entry_tls() noexcept
    {
        if (s_mid_entry_tls.load(std::memory_order_acquire) != TLS_OUT_OF_INDEXES)
        {
            return true;
        }
        const DWORD fresh = ::TlsAlloc();
        if (fresh == TLS_OUT_OF_INDEXES)
        {
            return false;
        }
        DWORD expected = TLS_OUT_OF_INDEXES;
        if (!s_mid_entry_tls.compare_exchange_strong(expected, fresh, std::memory_order_acq_rel,
                                                     std::memory_order_acquire))
        {
            // Another installer won. Its index is already public, and this slot contains no value.
            ::TlsFree(fresh);
        }
        return true;
    }

    bool thread_is_inside_mid_adapter(const MidAdapterSlot &slot) noexcept
    {
        if (slot.untracked_entries.load(std::memory_order_seq_cst) != 0)
        {
            // An unrecorded entrant is in flight, so self-entry cannot be disproven. Claim it: a wrong "no"
            // deadlocks while a wrong "yes" only pins.
            return true;
        }
        const DWORD tls = s_mid_entry_tls.load(std::memory_order_acquire);
        for (const auto *frame = static_cast<const MidEntryFrame *>(::TlsGetValue(tls)); frame != nullptr;
             frame = frame->prev)
        {
            if (frame->slot == &slot)
            {
                return true;
            }
        }
        return false;
    }

    void note_contained_mid_exception(MidAdapterSlot &slot) noexcept
    {
        // The counter is exact. The log fires only on a slot's first escape, so a per-frame exception cannot flood the
        // host's hot path.
        const std::uint64_t previous = slot.contained_exceptions.fetch_add(1, std::memory_order_relaxed);
        if (previous != 0)
        {
            return;
        }
        (void)log().try_log(LogLevel::Error,
                            "hook: a mid-hook callback at 0x{:0{}X} threw; the exception was contained at the DMK "
                            "adapter "
                            "boundary and the callback treated as complete. A mid-hook callback must not throw: the "
                            "backend stub it returns into adjusts the stack pointer dynamically and carries no unwind "
                            "data. Further escapes at this site are counted but not logged.",
                            slot.target.load(std::memory_order_relaxed), sizeof(std::uintptr_t) * 2);
    }

    std::size_t claim_mid_adapter_slot() noexcept
    {
        for (std::size_t index = 0; index < MID_ADAPTER_CAPACITY; ++index)
        {
            bool expected = false;
            if (s_mid_slots[index].claimed.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                                                   std::memory_order_relaxed))
            {
                s_mid_slots[index].detour.store(nullptr, std::memory_order_relaxed);
                s_mid_slots[index].live.store(false, std::memory_order_relaxed);
#if defined(DMK_ENABLE_TEST_SEAMS)
                s_last_claimed_mid_slot.store(index, std::memory_order_release);
#endif
                return index;
            }
        }
        return MID_ADAPTER_CAPACITY;
    }

    void release_mid_adapter_slot(std::size_t index) noexcept
    {
        if (index >= MID_ADAPTER_CAPACITY)
        {
            return;
        }
        // This path runs only after the slot is tombstoned and drained. No thread is inside its adapter, so the
        // contents can be recycled. The slot storage itself is never reclaimed.
        s_mid_slots[index].detour.store(nullptr, std::memory_order_relaxed);
        s_mid_slots[index].claimed.store(false, std::memory_order_release);
    }

    MidRundown run_down_mid_slot(MidAdapterSlot &slot) noexcept
    {
        if (thread_is_inside_mid_adapter(slot))
        {
            // This thread can itself be the in-flight entrant. The drain below then never observes zero. The caller
            // pins instead of a wait.
            return MidRundown::Unwaitable;
        }
        return drain_until_zero([&slot]() noexcept { return slot.callbacks_in_flight.load(std::memory_order_seq_cst); },
                                std::chrono::steady_clock::now() + MID_CALLBACK_DRAIN_TIMEOUT)
                   ? MidRundown::Drained
                   : MidRundown::Expired;
    }

    bool drain_mid_adapter_entries(MidAdapterSlot &slot) noexcept
    {
        return drain_until_zero([&slot]() noexcept { return slot.adapter_entries.load(std::memory_order_seq_cst); },
                                std::chrono::steady_clock::now() + MID_ADAPTER_ENTRY_DRAIN_TIMEOUT);
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    std::size_t last_claimed_mid_slot_for_test() noexcept
    {
        return s_last_claimed_mid_slot.load(std::memory_order_acquire);
    }

    bool mid_slot_claimed_for_test(std::size_t index) noexcept
    {
        return index < MID_ADAPTER_CAPACITY && s_mid_slots[index].claimed.load(std::memory_order_acquire);
    }

    void adjust_mid_adapter_entries_for_test(std::size_t index, std::int32_t delta) noexcept
    {
        if (index >= MID_ADAPTER_CAPACITY)
        {
            return;
        }
        s_mid_slots[index].adapter_entries.fetch_add(static_cast<std::uint32_t>(delta), std::memory_order_seq_cst);
    }
#endif
} // namespace DetourModKit::detail

namespace DetourModKit
{
    // File-local helpers live at DetourModKit scope, outside namespace hook. A bare `detail::` therefore resolves to
    // DetourModKit::detail, the memory/x86/platform engine. A hook::detail subnamespace otherwise shadows it and
    // breaks the unqualified lookup.
    namespace
    {
        /**
         * @brief Takes a counted reference on this module for an install path and honors the test override.
         * @details On failure the primitive restores the thread's last-error, so the caller can read GetLastError()
         *          immediately after a null return.
         */
        [[nodiscard]] HMODULE acquire_hook_self_ref() noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *override_fn = DetourModKit::detail::g_hook_module_ref_override)
            {
                return override_fn();
            }
#endif
            return DetourModKit::detail::acquire_module_ref();
        }
        /// Reports whether the foreign-inline-hook preflight found a present redirect and its destination.
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

        /// Releases a module reference automatically unless ownership is handed to a hook Impl.
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

        /// Returns a claimed mid-adapter slot to the pool unless the install transaction commits it to an Impl.
        class MidAdapterSlotGuard
        {
        public:
            explicit MidAdapterSlotGuard(std::size_t index) noexcept : m_index(index) {}

            // The guard is safe without a rundown because it fires only before hook arm. No adapter entry occurred.
            // Once the Impl owns the slot, teardown runs its rundown instead.
            ~MidAdapterSlotGuard() noexcept { detail::release_mid_adapter_slot(m_index); }

            MidAdapterSlotGuard(const MidAdapterSlotGuard &) = delete;
            MidAdapterSlotGuard &operator=(const MidAdapterSlotGuard &) = delete;
            MidAdapterSlotGuard(MidAdapterSlotGuard &&) = delete;
            MidAdapterSlotGuard &operator=(MidAdapterSlotGuard &&) = delete;

            [[nodiscard]] std::size_t release() noexcept
            {
                return std::exchange(m_index, detail::MID_ADAPTER_CAPACITY);
            }

        private:
            std::size_t m_index{detail::MID_ADAPTER_CAPACITY};
        };

        /**
         * @brief Decodes an initial inline-hook redirect at @p target_address and returns its destination.
         * @details Recognizes three redirect shapes that a foreign hook plants over a prologue. These shapes are E9
         *          rel32, FF 25 [rip+disp32], and 48 B8 imm64 plus FF E0. Returns nullopt for any other prologue.
         */
        std::optional<std::uintptr_t> decode_prehook_destination(std::uintptr_t target_address) noexcept
        {
            std::array<std::uint8_t, 2> opcode{};
            if (!detail::guarded_read_bytes(target_address, opcode.data(), opcode.size()))
            {
                return std::nullopt;
            }

            // EB (jmp rel8) reaches at most +/-127 bytes. This range is too short to land in a foreign hook stub. An
            // initial 0xEB is ordinary code and deliberately does not match.
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
                return detail::decode_mov_rax_imm64_jmp_rax(target_address);
            }
            return std::nullopt;
        }

        /// Detects whether @p target_address is already inline-hooked and classifies the module that owns the redirect.
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

        /// PrologueRisk classifies the target's first byte during inline or mid preflight.
        enum class PrologueRisk : std::uint8_t
        {
            None,
            // Prologue::Fail refuses a 0xCC int3 or 0xCD int n.
            Breakpoint,
            // Every policy refuses an unreadable first byte.
            Unreadable
        };

        // An initial rel32 call is left to the backend, which relocates it or fails typed. An unreadable first byte
        // stays a distinct fail-closed result because the target can change after window validation.
        PrologueRisk classify_prologue_risk(std::uintptr_t target_address) noexcept
        {
            if (target_address == 0)
            {
                return PrologueRisk::None;
            }
            std::uint8_t first_byte = 0;
            if (!detail::guarded_read_bytes(target_address, &first_byte, sizeof(first_byte)))
            {
                return PrologueRisk::Unreadable;
            }
            switch (first_byte)
            {
            case 0xCC:
            case 0xCD:
                return PrologueRisk::Breakpoint;
            default:
                return PrologueRisk::None;
            }
        }

        /// Returns a human-readable fragment for a flagged prologue risk in diagnostic log lines.
        [[nodiscard]] std::string_view prologue_risk_description(PrologueRisk risk) noexcept
        {
            switch (risk)
            {
            case PrologueRisk::Breakpoint:
                return "a breakpoint (0xCC/0xCD)";
            case PrologueRisk::Unreadable:
                return "an unreadable byte";
            case PrologueRisk::None:
                return "an unremarkable byte";
            }
            return "an unremarkable byte";
        }

        // These formatters preserve each backend reason in the diagnostic log after failures map to
        // ErrorCode::BackendFailed.
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
            case safetyhook::InlineHook::Error::FAILED_TO_REGISTER_UNWIND:
                return std::format("InlineHook backend error ({}): the platform refused unwind metadata for the routed "
                                   "wrapper at {}",
                                   type_int, ip_str);
            case safetyhook::InlineHook::Error::ROUTE_RETENTION_EXHAUSTED:
                return std::format("InlineHook backend error ({}): the routed retention ceiling refused the permanent "
                                   "chain for {}",
                                   type_int, ip_str);
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
         * @details The @ref hook::Hook::CallGate publishes this value while an inline hook is armed.
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

        /// Applies a visitor that does not throw, or returns @p fallback when no managed backend is active.
        template <typename Result, typename BackendVariant, typename Visitor>
        [[nodiscard]] Result backend_value_or(BackendVariant &backend, Result fallback, Visitor &&visitor) noexcept
        {
            using InlineReference = decltype(*std::get_if<safetyhook::InlineHook>(&backend));
            using MidReference = decltype(*std::get_if<safetyhook::MidHook>(&backend));
            static_assert(std::is_nothrow_invocable_r_v<Result, Visitor, InlineReference>);
            static_assert(std::is_nothrow_invocable_r_v<Result, Visitor, MidReference>);

            if (auto *inline_backend = std::get_if<safetyhook::InlineHook>(&backend))
            {
                return std::forward<Visitor>(visitor)(*inline_backend);
            }
            if (auto *mid_backend = std::get_if<safetyhook::MidHook>(&backend))
            {
                return std::forward<Visitor>(visitor)(*mid_backend);
            }
            return fallback;
        }

        /// Applies a visitor that does not throw and reports whether a managed backend is active.
        template <typename BackendVariant, typename Visitor>
        [[nodiscard]] bool apply_backend(BackendVariant &backend, Visitor &&visitor) noexcept
        {
            using InlineReference = decltype(*std::get_if<safetyhook::InlineHook>(&backend));
            using MidReference = decltype(*std::get_if<safetyhook::MidHook>(&backend));
            static_assert(std::is_nothrow_invocable_v<Visitor, InlineReference>);
            static_assert(std::is_nothrow_invocable_v<Visitor, MidReference>);

            if (auto *inline_backend = std::get_if<safetyhook::InlineHook>(&backend))
            {
                std::forward<Visitor>(visitor)(*inline_backend);
                return true;
            }
            if (auto *mid_backend = std::get_if<safetyhook::MidHook>(&backend))
            {
                std::forward<Visitor>(visitor)(*mid_backend);
                return true;
            }
            return false;
        }

        /// Serializes VMT object-vptr check/swap/record sequences across create/apply/remove/teardown.
        [[nodiscard]] std::mutex &vmt_object_mutex() noexcept
        {
            static std::mutex mutex;
            return mutex;
        }

        /**
         * @brief Acquires the VMT object gate and returns an unowned lock if the OS mutex acquisition fails.
         * @details Callers fail closed on an unowned lock. A restore without the gate races another object-vptr
         *          transition.
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

        // Decides whether @p slot_value, the first qword of a vtable slot, resembles a callable function body. A 0x00
        // first byte marks an uninitialized page. Bytes 0xCC/0xCD are int3/int padding. Bytes 0xC2/0xC3 are bare RETs.
        // An EB/E9 same-module jump is a stub, such as an incremental-link ILT entry or a patched slot. Its clone makes
        // the new "original" a forwarder. MSVC adjustor thunks start with byte 0x48 and pass. Tail calls to a foreign
        // module pass. The reads use fault guards.
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
         * @brief Defines the hard cap on the vtable slot walk, which matches the bounded RTTI walkers.
         * @details No real vtable approaches this many virtual methods. A walk that reaches the cap treats the seed
         *          object as malformed and fails closed.
         */
        constexpr std::size_t MAX_VMT_SLOTS = 4096;

        // SafetyHook sizes a clone through an executable check for each slot target. This module-owned code address
        // fixes that answer after DMK counts the captured words. The detached clone receives the captured function
        // pointers before any host object can observe it.
        void vmt_snapshot_executable_marker() noexcept {}

        /**
         * @brief Counts callable slots from the object's current vptr, guarded and capped at @ref MAX_VMT_SLOTS.
         * @note The result bounds the guarded capture in @ref clone_vmt_snapshot. It is not the clone's slot count:
         *       the backend derives that from the captured snapshot, which is the only bound a slot write respects.
         */
        [[nodiscard]] std::optional<std::size_t> count_vmt_method_slots(std::uintptr_t vptr) noexcept
        {
            std::size_t count = 0;
            for (;;)
            {
                if (count >= MAX_VMT_SLOTS)
                {
                    return std::nullopt;
                }
                if (count > (std::numeric_limits<std::uintptr_t>::max() - vptr) / sizeof(std::uintptr_t))
                {
                    return std::nullopt;
                }

                const std::uintptr_t slot_address = vptr + (count * sizeof(std::uintptr_t));
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
         * @struct DetachedVmtBackend
         * @brief Stores a backend clone that no host object points at yet and the facts its publisher needs.
         * @details method_count matches the clone the backend allocated, not the caller's pre-count. It is the only
         *          bound between a caller's index and an unchecked slot write.
         */
        struct DetachedVmtBackend
        {
            safetyhook::VmtHook backend;
            std::uintptr_t cloned_vptr_base{0};
            std::size_t method_count{0};
        };

        /**
         * @brief Clones an owned, count-normalized vtable snapshot. The backend remains unattached to any object.
         * @return The detached backend, InvalidObject on a bad prefix/capture/empty table, or BackendFailed.
         */
        [[nodiscard]] Result<DetachedVmtBackend> clone_vmt_snapshot(std::uintptr_t vptr, std::size_t slot_budget)
        {
            constexpr std::size_t header_count = safetyhook::VMT_HEADER;
            constexpr std::uintptr_t header_bytes = header_count * sizeof(std::uintptr_t);
            if (vptr < header_bytes)
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for", vptr});
            }

            // The final zero is a private non-executable sentinel for the backend slot walk.
            std::vector<std::uintptr_t> snapshot(header_count + slot_budget + 1, 0);
            const std::uintptr_t snapshot_source = vptr - header_bytes;
            const std::size_t snapshot_bytes = (header_count + slot_budget) * sizeof(std::uintptr_t);
            if (!detail::guarded_read_bytes(snapshot_source, snapshot.data(), snapshot_bytes))
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for", snapshot_source});
            }

            // Walk the captured words again rather than trust slot_budget. The budget came from foreign memory a
            // moment earlier. The backend sizes its clone from THIS buffer. The two can disagree if the vtable changes
            // between those steps. The backend bounds-checks no slot write, and hook_method admits any index below the
            // count published here. A count for slots absent from the clone therefore causes an out-of-bounds write.
            std::size_t cloned_slots = 0;
            while (cloned_slots < slot_budget &&
                   safetyhook::is_executable(reinterpret_cast<std::uint8_t *>(snapshot[header_count + cloned_slots])))
            {
                ++cloned_slots;
            }
            if (cloned_slots == 0)
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for", vptr});
            }
            // Terminate the counted run so no later step can reach past it.
            snapshot[header_count + cloned_slots] = 0;

            // The captured pointer words are stable, but the execute protections of the pages they name are not. If a
            // target loses execute permission between the walk above and SafetyHook's walk, the backend can allocate
            // fewer slots than method_count permits. Give the backend an equally-sized run of a module-owned marker,
            // then restore the captured pointers into its detached clone before publication.
            std::vector<std::uintptr_t> backend_snapshot = snapshot;
            const std::uintptr_t executable_marker = reinterpret_cast<std::uintptr_t>(&vmt_snapshot_executable_marker);
            std::fill_n(backend_snapshot.begin() + static_cast<std::ptrdiff_t>(header_count), cloned_slots,
                        executable_marker);
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *probe = DetourModKit::detail::g_vmt_before_backend_clone_probe)
            {
                probe();
            }
#endif
            auto *surrogate_vptr = reinterpret_cast<std::uint8_t **>(backend_snapshot.data() + header_count);
            auto created = safetyhook::VmtHook::create(static_cast<void *>(&surrogate_vptr));
            if (!created)
            {
                return std::unexpected(Error{ErrorCode::BackendFailed, "hook::vmt_for", vptr});
            }

            safetyhook::VmtHook backend = std::move(created.value());
            const std::uintptr_t cloned_vptr_base = reinterpret_cast<std::uintptr_t>(surrogate_vptr);
            std::copy_n(snapshot.data() + header_count, cloned_slots,
                        reinterpret_cast<std::uintptr_t *>(cloned_vptr_base));
            // Erase the stack surrogate from the backend before it leaves scope. Real host objects are published and
            // restored only through DMK's guarded swaps, so the backend never retains a foreign object pointer.
            backend.remove(static_cast<void *>(&surrogate_vptr));
            return DetachedVmtBackend{std::move(backend), cloned_vptr_base, cloned_slots};
        }

        [[nodiscard]] bool publish_vmt_object_word(void *object, std::uintptr_t expected,
                                                   std::uintptr_t replacement) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *probe = DetourModKit::detail::g_vmt_before_publish_probe)
            {
                probe(object);
            }
#endif
            return detail::guarded_compare_exchange_word(reinterpret_cast<std::uintptr_t>(object), expected,
                                                         replacement);
        }

        /// Resolves a hook Target to an absolute address, through scan::resolve for a deferred OwnedScanRequest.
        Result<std::uintptr_t> resolve_target(const hook::Target &target) noexcept
        {
            if (const Address *absolute = std::get_if<Address>(&target))
            {
                return absolute->raw();
            }
            const auto *request = std::get_if<scan::OwnedScanRequest>(&target);
            if (request == nullptr)
            {
                return std::unexpected(Error{ErrorCode::InvalidTargetAddress, "hook::resolve_target"});
            }
            // scan::resolve can allocate and throw. This helper is noexcept, so it contains the exception and reports
            // an Error instead of host termination.
            try
            {
                Result<scan::Hit> hit = scan::resolve(request->view());
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

        struct RemovalPopulationState
        {
            bool was_active{false};
            bool remains_live{false};
        };

        /**
         * @brief Owns the identity for one enable or disable lifecycle event.
         * @details The owned name stays valid if a subscriber destroys the hook before synchronous emission ends. A
         *          failed name copy preserves the transition and publishes an empty name (HookLifecycleName.*).
         */
        struct LifecycleSnapshot
        {
            std::string name;
            std::uint64_t ledger_id{0};
            diagnostics::HookKind kind{diagnostics::HookKind::Inline};
        };

        [[nodiscard]] LifecycleSnapshot snapshot_lifecycle(const std::string &name, std::uint64_t ledger_id,
                                                           bool is_inline) noexcept
        {
            LifecycleSnapshot snapshot;
            snapshot.ledger_id = ledger_id;
            snapshot.kind = is_inline ? diagnostics::HookKind::Inline : diagnostics::HookKind::Mid;
            try
            {
                snapshot.name = name;
            }
            catch (...)
            {
            }
            return snapshot;
        }

        /**
         * @brief Updates the live population tally, then emits the associated hook lifecycle event.
         * @param removal Population state for a Removed event. Teardown must capture @c was_active before it forces its
         *                status to Disabled. Set @c remains_live when the target stays conservatively tracked.
         * @details The tally moves first so a subscriber that calls collect() observes the completed transition.
         */
        void emit_lifecycle(std::string_view name, std::uint64_t ledger_id, diagnostics::HookKind kind,
                            diagnostics::HookTransition transition, RemovalPopulationState removal = {}) noexcept
        {
            switch (transition)
            {
            case diagnostics::HookTransition::Created:
                DetourModKit::detail::hook_population::record_created(kind == diagnostics::HookKind::Vmt);
                break;
            case diagnostics::HookTransition::Enabled:
            case diagnostics::HookTransition::Disabled:
                // The status store updates the count while it still holds the call gate. This code runs after unlock.
                // Otherwise, two toggles can commit +1/-1 in an order opposite their serialized transitions.
                break;
            case diagnostics::HookTransition::Removed:
                if (!removal.remains_live)
                {
                    DetourModKit::detail::hook_population::record_removed(removal.was_active);
                }
                break;
            }
            try
            {
                diagnostics::hook_lifecycle().emit_safe(diagnostics::HookLifecycleEvent{
                    .name = name, .ledger_id = ledger_id, .kind = kind, .transition = transition});
            }
            catch (...)
            {
            }
        }

        /// ReservedTarget contains the resolved target and its ledger id from @ref preflight_target.
        struct PreflightResult
        {
            std::uintptr_t address{0};
            std::uint64_t ledger_id{0};
        };

        /**
         * @brief Resolves, validates, checks, and reserves a ledger slot for an inline or mid hook target.
         * @return The target address and its reserved ledger id, or the Error that fails the install.
         * @details Waits until the reservation is first in the target queue. Backend patches for one target
         *          follow creation order. On success, the caller owns the returned ledger id. Commit it before handle
         *          publication, or roll it back through HookLedger::release_hook.
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

            // The backend capability floor runs before any reservation, so a refusal needs no rollback.
            // Options::prologue does not alter this check. Prologue::Relocate must not authorize an unreadable
            // prologue.
            const detail::TargetWindowResult window = detail::validate_backend_steal_window(address);
            if (window.verdict != detail::TargetWindowVerdict::Ok)
            {
                (void)log().try_log(LogLevel::Warning, "hook: '{}' refused target {}: {}.", name,
                                    format::format_address(address), detail::target_window_description(window.verdict));
                return std::unexpected(Error{window.verdict == detail::TargetWindowVerdict::Unreadable
                                                 ? ErrorCode::ReadFaulted
                                                 : ErrorCode::TargetPrologueUnsafe,
                                             where, window.detail});
            }

            // try_reserve_hook folds the same-kit duplicate check and the id record into one locked step, so a
            // concurrent same-target install cannot slip between them.
            const detail::HookLedger::Reservation reservation =
                detail::HookLedger::instance().try_reserve_hook(address, options.fail_if_already_hooked);
            if (reservation.status == detail::HookLedger::ReserveStatus::OutOfMemory)
            {
                // The ledger allocation failed. Fail closed instead of an install of a live but unledgered hook.
                return std::unexpected(Error{ErrorCode::OutOfMemory, where, address});
            }
            if (reservation.status == detail::HookLedger::ReserveStatus::AlreadyHooked)
            {
                return std::unexpected(Error{ErrorCode::TargetAlreadyHookedByThisKit, where, address});
            }

            if (reservation.preexisting)
            {
                // If this install layers on a same-kit hook, warn and continue.
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: '{}' layers on a hook this kit already placed at {}; destroy layered hooks newest-first.",
                    name, format::format_address(address));
            }
            else
            {
                // Consult the foreign-JMP heuristic. On a strict refusal, roll back the reservation before failure.
                const PrehookDetection prehook = detect_existing_inline_hook(address);
                if (prehook.state == PrehookState::HookedByOtherModule)
                {
                    if (options.fail_if_already_hooked)
                    {
                        (void)detail::HookLedger::instance().release_hook(address, reservation.id);
                        return std::unexpected(Error{ErrorCode::TargetAlreadyHookedByAnotherModule, where, address});
                    }
                    (void)log().try_log(
                        LogLevel::Warning,
                        "hook: '{}' target {} is already inline-hooked by another module (JMP -> {}); layering on top.",
                        name, format::format_address(address), format::format_address(prehook.jmp_destination));
                }
            }

            // Prologue preflight is independent of the layer checks. An unhooked target can still start with a call
            // thunk or patched int3. On a Fail-policy refusal, roll back the reservation before failure.
            const PrologueRisk risk = classify_prologue_risk(address);
            if (risk == PrologueRisk::Unreadable)
            {
                (void)detail::HookLedger::instance().release_hook(address, reservation.id);
                return std::unexpected(Error{ErrorCode::ReadFaulted, where, address});
            }
            if (risk == PrologueRisk::Breakpoint)
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

        using detail::PatchWitness;
        using detail::witness_description;
        using detail::witness_patch;
        using detail::witness_permits_write;

        /**
         * @brief Reports whether the backend left this hook's own patch armed after a target toggle.
         * @details enable() publishes Active only for bytes it can attribute to itself.
         */
        template <class Backend> [[nodiscard]] bool enable_patch_is_confirmed(const Backend &backend) noexcept
        {
            const bool confirmed = backend.enabled() && witness_patch(backend) == PatchWitness::OwnedPatch;
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *override_fn = DetourModKit::detail::g_hook_enable_witness_override)
            {
                return override_fn(confirmed);
            }
#endif
            return confirmed;
        }

        /// Runs a managed backend enable and contains backend synchronization or allocation exceptions.
        template <class Backend> [[nodiscard]] bool try_backend_enable(Backend &backend) noexcept
        {
            try
            {
                return backend.enable().has_value();
            }
            catch (...)
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                DetourModKit::detail::s_backend_toggle_exception_catches.fetch_add(1, std::memory_order_relaxed);
#endif
                return false;
            }
        }

        /// Runs a managed backend disable and contains backend synchronization or allocation exceptions.
        template <class Backend> [[nodiscard]] bool try_backend_disable(Backend &backend) noexcept
        {
            try
            {
                const bool disabled = backend.disable().has_value();
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *probe = DetourModKit::detail::g_hook_backend_disable_probe)
                {
                    probe();
                }
#endif
                return disabled;
            }
            catch (...)
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                DetourModKit::detail::s_backend_toggle_exception_catches.fetch_add(1, std::memory_order_relaxed);
                if (auto *probe = DetourModKit::detail::g_hook_backend_disable_probe)
                {
                    probe();
                }
#endif
                return false;
            }
        }

        /// Returns the current target-byte witness, or Indeterminate when no backend is reachable.
        template <class BackendVariant> [[nodiscard]] PatchWitness witness_of(BackendVariant &backend) noexcept
        {
            return backend_value_or(backend, PatchWitness::Indeterminate,
                                    [](auto &one) noexcept { return witness_patch(one); });
        }

        /**
         * @brief Runs the teardown backend disable and reports the later owner of the target bytes.
         * @details The witness is taken whatever the disable reported, because the two disagree in both directions.
         *          The byte class is the complete verdict. Only @ref PatchWitness::Original authorizes backend
         *          destruction.
         */
        template <class BackendVariant>
        [[nodiscard]] PatchWitness run_teardown_restore(BackendVariant &backend) noexcept
        {
            // Classify before the restore, so foreign bytes are refused rather than overwritten.
            const PatchWitness before = witness_of(backend);
            if (!witness_permits_write(before))
            {
                return before;
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            // A false result or exception models a pre-mutation failure because it suppresses the backend call. The
            // witness below reconciles real backend exceptions after try_backend_disable contains them.
            bool run_restore = true;
            try
            {
                if (auto *override_fn = DetourModKit::detail::g_hook_teardown_restore_override)
                {
                    run_restore = override_fn();
                }
            }
            catch (...)
            {
                run_restore = false;
            }
            if (run_restore)
#endif
            {
                (void)backend_value_or(backend, false, [](auto &one) noexcept { return try_backend_disable(one); });
            }
            const PatchWitness after = witness_of(backend);
            if (after == PatchWitness::Original)
            {
                // The byte witness proves the target cannot reach this trampoline. Clear a stale backend flag so its
                // destructor cannot retry the caught operation outside this noexcept containment boundary.
                (void)apply_backend(backend, [](auto &one) noexcept { one.reconcile_enabled(false); });
            }
            return after;
        }

        /**
         * @brief Bounds the wait for backend-route entrants admitted before target restoration.
         * @details Only the generated stub's own instructions remain here, so expiry is evidence of a parked or
         *          indefinitely descheduled thread, not a slow one.
         */
        constexpr auto ROUTE_DRAIN_TIMEOUT = std::chrono::seconds{1};

        /**
         * @brief Waits for the backend route to empty, or reports that proof of an empty route timed out.
         * @note A false return never licenses reclamation. The caller must retain the backend.
         */
        template <class BackendVariant> [[nodiscard]] bool drain_backend_route(BackendVariant &backend) noexcept
        {
            return DetourModKit::detail::drain_until_zero(
                [&backend]() noexcept
                {
                    return backend_value_or(backend, std::size_t{1},
                                            [](const auto &one) noexcept { return one.route_entries(); });
                },
                std::chrono::steady_clock::now() + ROUTE_DRAIN_TIMEOUT);
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        /** @brief Fires the publication probe after @p step is complete. */
        void note_publish_step(DetourModKit::detail::HookPublishStep step)
        {
            if (auto *probe = DetourModKit::detail::g_hook_publish_probe)
            {
                probe(step);
            }
        }
#endif

        /**
         * @brief Checks the backend steal window immediately before the patch and releases @p ledger_id on failure.
         * @details The self-reference acquire takes the loader lock exactly when another thread can complete an unload.
         * @warning This check narrows the window but does not close it (see hook_fault_boundary.hpp). It provides error
         *          attribution, not a safety property.
         */
        std::optional<Error> revalidate_before_patch(std::uintptr_t target, std::uint64_t ledger_id,
                                                     const char *where) noexcept
        {
            const detail::TargetWindowResult window = detail::validate_backend_steal_window(target);
            if (window.verdict == detail::TargetWindowVerdict::Ok)
            {
                return std::nullopt;
            }
            (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
            return Error{window.verdict == detail::TargetWindowVerdict::Unreadable ? ErrorCode::ReadFaulted
                                                                                   : ErrorCode::TargetPrologueUnsafe,
                         where, window.detail};
        }
    } // namespace

    namespace hook
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        Hook::Impl::~Impl() noexcept
        {
            DetourModKit::detail::note_hook_impl_destruction_for_test();
        }
#endif

        // The hook::MidContext accessor bridge keeps MidContext incomplete. These accessors alone recover the real
        // safetyhook::Context64 through reinterpret_cast. The reference always denotes the exact Context64 from the
        // backend, so the cast is well-defined.
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
            // Every enumerator returns above. The rax return keeps the function well-formed.
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

        // The mid-hook assembly stub stores each captured register at a fixed offset. These assertions pin the C++
        // layout to the complete frame ABI, with the XMM prefix and integer/resume tail (T-XMM). Pointer
        // arithmetic from &xmm0 across distinct members is undefined C++. Layout assertions do not legalize it, so the
        // switch below uses explicit member selection.
        static_assert(sizeof(safetyhook::Xmm) == 16);
        static_assert(offsetof(safetyhook::Context64, xmm0) == 0);
        static_assert(offsetof(safetyhook::Context64, xmm1) == 16);
        static_assert(offsetof(safetyhook::Context64, xmm2) == 32);
        static_assert(offsetof(safetyhook::Context64, xmm3) == 48);
        static_assert(offsetof(safetyhook::Context64, xmm4) == 64);
        static_assert(offsetof(safetyhook::Context64, xmm5) == 80);
        static_assert(offsetof(safetyhook::Context64, xmm6) == 96);
        static_assert(offsetof(safetyhook::Context64, xmm7) == 112);
        static_assert(offsetof(safetyhook::Context64, xmm8) == 128);
        static_assert(offsetof(safetyhook::Context64, xmm9) == 144);
        static_assert(offsetof(safetyhook::Context64, xmm10) == 160);
        static_assert(offsetof(safetyhook::Context64, xmm11) == 176);
        static_assert(offsetof(safetyhook::Context64, xmm12) == 192);
        static_assert(offsetof(safetyhook::Context64, xmm13) == 208);
        static_assert(offsetof(safetyhook::Context64, xmm14) == 224);
        static_assert(offsetof(safetyhook::Context64, xmm15) == 240);
        static_assert(offsetof(safetyhook::Context64, rflags) == 256);
        static_assert(offsetof(safetyhook::Context64, r15) == 264);
        static_assert(offsetof(safetyhook::Context64, r14) == 272);
        static_assert(offsetof(safetyhook::Context64, r13) == 280);
        static_assert(offsetof(safetyhook::Context64, r12) == 288);
        static_assert(offsetof(safetyhook::Context64, r11) == 296);
        static_assert(offsetof(safetyhook::Context64, r10) == 304);
        static_assert(offsetof(safetyhook::Context64, r9) == 312);
        static_assert(offsetof(safetyhook::Context64, r8) == 320);
        static_assert(offsetof(safetyhook::Context64, rdi) == 328);
        static_assert(offsetof(safetyhook::Context64, rsi) == 336);
        static_assert(offsetof(safetyhook::Context64, rdx) == 344);
        static_assert(offsetof(safetyhook::Context64, rcx) == 352);
        static_assert(offsetof(safetyhook::Context64, rbx) == 360);
        static_assert(offsetof(safetyhook::Context64, rax) == 368);
        static_assert(offsetof(safetyhook::Context64, rbp) == 376);
        static_assert(offsetof(safetyhook::Context64, rsp) == 384);
        static_assert(offsetof(safetyhook::Context64, trampoline_rsp) == 392);
        static_assert(offsetof(safetyhook::Context64, rip) == 400);
        static_assert(sizeof(safetyhook::Context64) == 408);

        XmmView xmm(const MidContext &ctx, std::size_t index) noexcept
        {
            XmmView view{};
            const auto &context = reinterpret_cast<const safetyhook::Context64 &>(ctx);
            const safetyhook::Xmm *reg = nullptr;
            switch (index)
            {
            case 0:
                reg = &context.xmm0;
                break;
            case 1:
                reg = &context.xmm1;
                break;
            case 2:
                reg = &context.xmm2;
                break;
            case 3:
                reg = &context.xmm3;
                break;
            case 4:
                reg = &context.xmm4;
                break;
            case 5:
                reg = &context.xmm5;
                break;
            case 6:
                reg = &context.xmm6;
                break;
            case 7:
                reg = &context.xmm7;
                break;
            case 8:
                reg = &context.xmm8;
                break;
            case 9:
                reg = &context.xmm9;
                break;
            case 10:
                reg = &context.xmm10;
                break;
            case 11:
                reg = &context.xmm11;
                break;
            case 12:
                reg = &context.xmm12;
                break;
            case 13:
                reg = &context.xmm13;
                break;
            case 14:
                reg = &context.xmm14;
                break;
            case 15:
                reg = &context.xmm15;
                break;
            default:
                // Fail closed: an out-of-range index returns the zeroed view.
                return view;
            }
            // The 16 bytes are copied out by value: XMM is surfaced read-only.
            std::memcpy(view.bytes.data(), reg->u8, view.bytes.size());
            return view;
        }

        const std::shared_ptr<safetyhook::Allocator> &backend_allocator() noexcept
        {
            // One allocator hold exists per linked DMK instance. It occupies static storage and is never released. A
            // plain function-local static registers a destructor. A later Hook destructor can otherwise free its
            // trampoline into a destroyed allocator arena.
            alignas(std::shared_ptr<safetyhook::Allocator>) static unsigned char
                storage[sizeof(std::shared_ptr<safetyhook::Allocator>)];
            static const std::shared_ptr<safetyhook::Allocator> *const allocator = ::new (static_cast<void *>(storage))
                std::shared_ptr<safetyhook::Allocator>(safetyhook::Allocator::global());
            return *allocator;
        }

        // Hook is the RAII handle for one inline or mid hook.
        Hook::Hook(std::unique_ptr<Impl> impl, std::shared_ptr<CallGate> gate) noexcept : m_impl(std::move(impl))
        {
            m_gate.store(std::move(gate), std::memory_order_release);
        }

        Hook::Hook(Hook &&other) noexcept : m_impl(std::move(other.m_impl))
        {
            // std::atomic is not movable. exchange leaves the source's gate empty, so a moved-from handle is fully
            // disengaged and fails closed.
            m_gate.store(other.m_gate.exchange(nullptr, std::memory_order_acq_rel), std::memory_order_release);
        }

        Hook &Hook::operator=(Hook &&other) noexcept
        {
            if (this != &other)
            {
                // Adopt the current hook into a temporary whose ~Hook runs the loader-lock-aware teardown. A
                // concurrent call() that pinned this handle's gate keeps the old trampoline alive until it returns.
                Hook discard(std::move(*this));
                m_impl = std::move(other.m_impl);
                m_gate.store(other.m_gate.exchange(nullptr, std::memory_order_acq_rel), std::memory_order_release);
            }
            return *this;
        }

        Hook::~Hook() noexcept
        {
            // Take the gate reference out for the complete teardown. A pinned caller keeps the gate alive through its
            // own reference. A null callable below makes a late caller fail closed.
            std::shared_ptr<CallGate> gate = m_gate.exchange(nullptr, std::memory_order_acq_rel);
            if (!m_impl)
            {
                return;
            }

            // Tombstone the mid-hook adapter before any teardown decision below. A late entrant exits at the adapter's
            // second live check. A pinned stub then becomes inert instead of a call to a destroyed owner. Inline hooks
            // have no slot. Their detour is the user function.
            const std::size_t mid_slot = m_impl->mid_slot;
            const bool has_mid_slot = mid_slot < DetourModKit::detail::MID_ADAPTER_CAPACITY;
            if (has_mid_slot)
            {
                DetourModKit::detail::mid_adapter_slots()[mid_slot].live.store(false, std::memory_order_seq_cst);
            }

            // Loader-lock leaf discipline forbids a prologue restore or backend destruction under the loader lock.
            // Either action can deadlock, so leak the Impl instead. Its module reference keeps the trampoline code
            // pages mapped, so the gate callable stays valid.
            if (!DetourModKit::detail::blocking_teardown_permitted())
            {
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                (void)m_impl.release();
                return;
            }

            const DetourModKit::detail::MidRundown mid_rundown =
                has_mid_slot
                    ? DetourModKit::detail::run_down_mid_slot(DetourModKit::detail::mid_adapter_slots()[mid_slot])
                    : DetourModKit::detail::MidRundown::Drained;

            const std::uintptr_t target = m_impl->target;
            const std::uint64_t ledger_id = m_impl->ledger_id;
            const diagnostics::HookKind kind =
                m_impl->is_inline ? diagnostics::HookKind::Inline : diagnostics::HookKind::Mid;
            // Capture the armed state before the gate block below forces status to Disabled. Otherwise, the Removed
            // emission leaves the enable armed unit on the tally forever.
            const bool was_active = m_impl->status.load(std::memory_order_acquire) == HookState::Active;
            // Copy the name out before reset() destroys its storage. The copy can throw under OOM inside a noexcept
            // destructor, so contain it and degrade to an empty name.
            std::string name;
            try
            {
                name = m_impl->name;
            }
            catch (...)
            {
            }

            // Serialize with any in-flight call() through the shared gate. A caller that owns the lock drains to
            // completion. A caller with only a pin reads the null callable under the same mutex and returns the
            // inactive default.
            if (gate)
            {
                std::unique_lock<std::recursive_mutex> guard = acquire_call_lock(gate.get());
                if (!guard.owns_lock())
                {
                    // An unowned guard makes restore safety unprovable. Leak the backend instead of a free of a
                    // trampoline that a guarded caller can still use.
                    diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                    (void)m_impl.release();
                    return;
                }
                gate->callable = nullptr;
                m_impl->status.store(HookState::Disabled, std::memory_order_release);
            }

            // Decide leak or restore under this target's install-serialization slot. The slot makes the decision and
            // restore atomic against a concurrent same-target install. Restore is sound only for the newest layer
            // (newer == 0). Newer layers still chain through this trampoline. A pristine prologue below them causes a
            // trampoline use-after-free. The count under the slot also closes the race between a peek and restore.
            auto &ledger = DetourModKit::detail::HookLedger::instance();
            const std::size_t newer = ledger.acquire_target_slot(target, ledger_id);
            if (newer > 0)
            {
                // For out-of-order, oldest-first teardown, leak this backend instead of a restore. This preserves the
                // newer layer chain into this trampoline. The Impl module reference remains held, so the
                // trampoline pages stay mapped. release_target_slot keeps the ledger order entry: the target remains
                // physically hooked and must not be reported clean.
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                (void)m_impl.release();
                ledger.release_target_slot(target, ledger_id);
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: '{}' at 0x{:0{}X} destroyed while {} newer hook(s) remain layered on the same target; "
                    "leaked the older backend to avoid a trampoline use-after-free. Tear layered hooks down "
                    "newest-first (hold them in a HookStack).",
                    name, target, sizeof(std::uintptr_t) * 2, newer);
                emit_lifecycle(name, ledger_id, kind, diagnostics::HookTransition::Removed,
                               RemovalPopulationState{.remains_live = true});
                return;
            }

            // Close the backend-owned route before restore, so admitted callers stay counted across the generated
            // stub. An Unwaitable self-owned mid teardown deliberately skips the drain. The pin below keeps its route
            // alive.
            (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.begin_route_rundown(); });
            // Disable the backend here instead of in ~Impl. Its backend destructor discards a failed disable and
            // reclaims storage regardless. Only a prologue at its original bytes authorizes backend destruction.
            // Foreign and Indeterminate fail closed to the pin (see run_teardown_restore).
            const PatchWitness restore = run_teardown_restore(m_impl->backend);
            if (restore != PatchWitness::Original)
            {
                (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.cancel_route_rundown(); });
                // The target can still dispatch through this trampoline. Pin the Impl to keep its pages mapped. Book
                // the leak and keep the creation-order entry, so is_target_hooked stays true.
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                (void)m_impl.release();
                ledger.release_target_slot(target, ledger_id);
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: '{}' at 0x{:0{}X} could not restore its target's prologue during teardown ({}); leaked the "
                    "backend to keep the possibly reachable trampoline mapped. The target remains tracked as hooked.",
                    name, target, sizeof(std::uintptr_t) * 2, witness_description(restore));
                emit_lifecycle(name, ledger_id, kind, diagnostics::HookTransition::Removed,
                               RemovalPopulationState{.remains_live = true});
                return;
            }
            (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.finish_route_rundown(); });

            // A successful restore stops new target entries. Reclamation still uses a bounded wait for the backend
            // route.
            // Expiry retains the backend exactly as an unprovable adapter rundown does. The short circuit expresses
            // "no wait was owed": an unproven rundown is handled by the pin branch below and must not be waited on.
            const bool route_drained =
                mid_rundown != DetourModKit::detail::MidRundown::Drained || drain_backend_route(m_impl->backend);

            // Newest-first teardown occurs under the target install-serialization slot. Restore the prologue and
            // destroy the backend first. Release the ledger entry next and the module reference last.
            // release_module_ref calls FreeLibrary, which takes the loader lock. A prior slot release prevents a
            // lock-order inversion against a DllMain install parked on this slot. The caller still executes this
            // module's code and the host holds its own load reference, so this release is never the terminal one.
            if (mid_rundown != DetourModKit::detail::MidRundown::Drained || !route_drained)
            {
                // An entrant remains counted after its drain and can still return through the stub. Pin the Impl to
                // keep the stub mapped and leave the slot claimed. This case applies only to mid hooks.
                // A managed inline hook route count stays zero, so its drain cannot expire.
                const char *blocked_stage = mid_rundown == DetourModKit::detail::MidRundown::Unwaitable ? "callback"
                                            : mid_rundown == DetourModKit::detail::MidRundown::Expired
                                                ? "callback past its bounded drain"
                                                : "backend route after a bounded wait";
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                (void)m_impl.release();
                (void)ledger.release_hook(target, ledger_id);
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: mid hook '{}' at 0x{:0{}X} was torn down while a thread can still be inside its {}. "
                    "The target was restored, but the backend is pinned so that thread can return through its stub. "
                    "The callback will not be entered again, and the adapter is not reclaimed.",
                    name, target, sizeof(std::uintptr_t) * 2, blocked_stage);
                emit_lifecycle(name, ledger_id, kind, diagnostics::HookTransition::Removed,
                               RemovalPopulationState{.was_active = was_active});
                return;
            }

            if (has_mid_slot &&
                !DetourModKit::detail::drain_mid_adapter_entries(DetourModKit::detail::mid_adapter_slots()[mid_slot]))
            {
                // A thread remains inside the adapter body past the bounded wait. This counter is the slot-reuse
                // authority, so the slot and stub stay retained. The ledger entry is clean.
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                (void)m_impl.release();
                (void)ledger.release_hook(target, ledger_id);
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook: mid hook '{}' at 0x{:0{}X} was torn down while a thread can still be inside its adapter "
                    "body past its bounded drain. The target was restored, but the backend and adapter slot are "
                    "pinned so that thread can return through its stub.",
                    name, target, sizeof(std::uintptr_t) * 2);
                emit_lifecycle(name, ledger_id, kind, diagnostics::HookTransition::Removed,
                               RemovalPopulationState{.was_active = was_active});
                return;
            }

            const HMODULE self_ref = static_cast<HMODULE>(m_impl->self_ref);
            m_impl.reset();
            // The drain completed, or this was never a mid hook. No thread is inside the adapter, so slot contents can
            // be reused.
            if (has_mid_slot)
            {
                DetourModKit::detail::release_mid_adapter_slot(mid_slot);
            }
            (void)ledger.release_hook(target, ledger_id);
            DetourModKit::detail::release_module_ref(self_ref);
            emit_lifecycle(name, ledger_id, kind, diagnostics::HookTransition::Removed,
                           RemovalPopulationState{.was_active = was_active});
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
            const std::shared_ptr<CallGate> gate = m_gate.load(std::memory_order_acquire);
            if (!gate)
            {
                return false;
            }
            std::unique_lock<std::recursive_mutex> guard = acquire_call_lock(gate.get());
            if (!guard.owns_lock() || !m_impl)
            {
                return false;
            }
            // Both the published state and the reconciled backend view must agree. The gate serializes this read
            // with every backend flag update.
            return m_impl->status.load(std::memory_order_acquire) == HookState::Active &&
                   backend_value_or(m_impl->backend, false, [](auto &backend) noexcept
                                    { return static_cast<bool>(backend) && backend.enabled(); });
        }

        void *Hook::original_address() const noexcept
        {
            // The original<Fn>() path uses no gate or atomic shared-pointer load. The caller guarantees that the hook
            // outlives the call.
            return m_impl ? inline_trampoline(m_impl->backend) : nullptr;
        }

        std::shared_ptr<Hook::CallGate> Hook::pin_call_gate() const noexcept
        {
            // Copy the gate reference atomically into a strong local. call() can then keep the trampoline and mutex
            // alive across a concurrent teardown that drops the handle's own reference.
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
                // recursive_mutex::lock can throw std::system_error. Fail closed: an unowned lock makes call()
                // return the inactive default.
                return std::unique_lock<std::recursive_mutex>{};
            }
        }

        void *Hook::active_trampoline(CallGate *gate) const noexcept
        {
            // Every writer publishes gate->callable under the mutex the caller already holds, so this observes the
            // live trampoline or nullptr, never a stale pointer.
            return gate->callable;
        }

        namespace
        {
            /**
             * @brief Implements the hook.hpp loader-lock precondition.
             * @details T-HOOK-LOADER pins this gate before each mutation boundary.
             */
            [[nodiscard]] std::optional<Error> refuse_on_loader_lock(const char *operation) noexcept
            {
                if (DetourModKit::detail::is_loader_lock_held())
                {
                    return Error{ErrorCode::LoaderLockActive, operation};
                }
                return std::nullopt;
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            void note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry entry) noexcept
            {
                if (auto *probe = DetourModKit::detail::g_hook_post_loader_veto_probe)
                {
                    probe(entry);
                }
            }
#endif

            /**
             * @class TargetSlot
             * @brief Holds a target's ledger write slot across a toggle that can alter its bytes.
             * @details The slot blocks every same-target install while held, so it MUST be released before the
             *          caller runs user code or takes the loader lock.
             */
            class TargetSlot
            {
            public:
                TargetSlot(std::uintptr_t target, std::uint64_t id) noexcept
                    : m_target(target), m_id(id),
                      m_newer(DetourModKit::detail::HookLedger::instance().acquire_target_slot(target, id))
                {
                }

                ~TargetSlot() noexcept { release(); }

                TargetSlot(const TargetSlot &) = delete;
                TargetSlot &operator=(const TargetSlot &) = delete;
                TargetSlot(TargetSlot &&) = delete;
                TargetSlot &operator=(TargetSlot &&) = delete;

                void release() noexcept
                {
                    if (!std::exchange(m_released, true))
                    {
                        DetourModKit::detail::HookLedger::instance().release_target_slot(m_target, m_id);
                    }
                }

                /// Reports whether this hook is the newest live layer with authority to write target bytes.
                [[nodiscard]] bool is_top_layer() const noexcept { return m_newer == 0; }

            private:
                std::uintptr_t m_target;
                std::uint64_t m_id;
                std::size_t m_newer;
                bool m_released{false};
            };

            /**
             * @brief Publishes one enable or disable outcome in the single toggle order.
             * @details The status store and population count run under the call gate that serialized the transition.
             *          Callable publication also runs under the gate mutex. An armed inline hook publishes its
             *          trampoline, while a mid hook gate stays null. A disable clears the callable, so a later call()
             *          returns the inactive default. The identity snapshot, slot release, unlock, and emission follow
             *          (HookLifecycleName.*). The caller must read no hook state after this call because a subscriber
             *          can destroy the hook before emission ends.
             */
            template <class ImplT, class GateT>
            void publish_toggle(ImplT &impl, GateT &gate, TargetSlot &slot,
                                std::unique_lock<std::recursive_mutex> &guard, bool armed) noexcept
            {
                if (armed)
                {
                    impl.status.store(HookState::Active, std::memory_order_release);
                    DetourModKit::detail::hook_population::record_enabled();
                    gate.callable = inline_trampoline(impl.backend);
                }
                else
                {
                    impl.status.store(HookState::Disabled, std::memory_order_release);
                    DetourModKit::detail::hook_population::record_disabled();
                    gate.callable = nullptr;
                }
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *probe = DetourModKit::detail::g_hook_toggle_publication_probe)
                {
                    const HookState expected = armed ? HookState::Active : HookState::Disabled;
                    const bool callable_matches = (gate.callable != nullptr) == (armed && impl.is_inline);
                    probe(armed, guard.owns_lock(), impl.status.load(std::memory_order_relaxed) == expected,
                          callable_matches);
                }
#endif
                const LifecycleSnapshot snapshot = snapshot_lifecycle(impl.name, impl.ledger_id, impl.is_inline);
                slot.release();
                guard.unlock();
                emit_lifecycle(snapshot.name, snapshot.ledger_id, snapshot.kind,
                               armed ? diagnostics::HookTransition::Enabled : diagnostics::HookTransition::Disabled);
            }
        } // namespace

        Result<void> Hook::enable() noexcept
        {
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::enable"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::Enable);
#endif
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::enable"});
            }
            // A live handle always has a gate. The null check fails closed on the broken invariant.
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
            if (!backend_value_or(m_impl->backend, false,
                                  [](auto &backend) noexcept { return static_cast<bool>(backend); }))
            {
                return std::unexpected(Error{ErrorCode::BackendFailed, "hook::enable"});
            }

            // Only the newest live layer can write target bytes. The slot makes the {decide, patch} pair atomic
            // against a concurrent same-target install. Claim it before the state CAS so a refusal changes nothing.
            TargetSlot slot(m_impl->target, m_impl->ledger_id);
            if (!slot.is_top_layer())
            {
                return std::unexpected(Error{ErrorCode::LayerConflict, "hook::enable", m_impl->target});
            }

            // Classify before the transition claim. The backend emits its jmp over the current bytes. Foreign or
            // unreadable bytes must refuse here while the hook remains as the caller left it.
            if (const PatchWitness before = witness_of(m_impl->backend); !witness_permits_write(before))
            {
                (void)log().try_log(LogLevel::Warning, "hook: '{}' at 0x{:0{}X} refused enable: {}.", m_impl->name,
                                    m_impl->target, sizeof(std::uintptr_t) * 2, witness_description(before));
                return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable", m_impl->target});
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
            // Create leaves the target unpatched, so this is the first operation that can make the detour reachable.
            const bool backend_enabled = backend_value_or(m_impl->backend, false, [](auto &backend) noexcept
                                                          { return try_backend_enable(backend); });
            const bool patch_confirmed = backend_value_or(m_impl->backend, false, [](auto &backend) noexcept
                                                          { return enable_patch_is_confirmed(backend); });
            if (backend_enabled && patch_confirmed)
            {
                publish_toggle(*m_impl, *gate, slot, guard, true);
                return {};
            }
            // A backend error says nothing about the target. The patch commits inside the thread trap transaction, so
            // an error can sit over a fully armed target. Witness the bytes before publication.
            if (!backend_enabled)
            {
                const bool mutation_committed =
                    backend_value_or(m_impl->backend, false, [](auto &backend) noexcept { return backend.enabled(); });
                const PatchWitness after_failure = witness_of(m_impl->backend);
                if (mutation_committed && after_failure != PatchWitness::Original)
                {
                    // The mutation committed, so Original is the only witness that proves the hook disarmed. Retain
                    // the conservative Active state and report that safe disarm lacks confirmation.
                    const std::uintptr_t armed_target = m_impl->target;
                    publish_toggle(*m_impl, *gate, slot, guard, true);
                    const ErrorCode code =
                        after_failure == PatchWitness::OwnedPatch ? ErrorCode::BackendFailed : ErrorCode::DisableFailed;
                    return std::unexpected(Error{code, "hook::enable", armed_target});
                }
                // The backend committed no mutation, or the target already returned to Original. This hook is disarmed.
                if (after_failure == PatchWitness::Original)
                {
                    (void)apply_backend(m_impl->backend,
                                        [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                }
                m_impl->status.store(HookState::Disabled, std::memory_order_release);
                return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable"});
            }

            // The backend reported success but the bytes are not this hook's patch. Publish Disabled only after a
            // compensation disable leaves the prologue at its original bytes. The rollback receives the same
            // classification as any other toggle. A third party that took the window can otherwise lose its bytes to
            // the unconditional restore. Refusal therefore falls through to the Active publication below.
            if (const PatchWitness rollback_before = witness_of(m_impl->backend);
                witness_permits_write(rollback_before))
            {
                (void)backend_value_or(m_impl->backend, false,
                                       [](auto &backend) noexcept { return try_backend_disable(backend); });
                if (witness_of(m_impl->backend) == PatchWitness::Original)
                {
                    (void)apply_backend(m_impl->backend,
                                        [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                    m_impl->status.store(HookState::Disabled, std::memory_order_release);
                    return std::unexpected(Error{ErrorCode::EnableFailed, "hook::enable"});
                }
            }

            // A completed restore can be followed by a newer or uncertain owner. Retain backend reachability so
            // is_enabled() and a later disable retry agree with the conservative Active state.
            (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.reconcile_enabled(true); });
            publish_toggle(*m_impl, *gate, slot, guard, true);
            return std::unexpected(Error{ErrorCode::DisableFailed, "hook::enable"});
        }

        Result<void> Hook::disable() noexcept
        {
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::disable"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::Disable);
#endif
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
            if (!backend_value_or(m_impl->backend, false,
                                  [](auto &backend) noexcept { return static_cast<bool>(backend); }))
            {
                return std::unexpected(Error{ErrorCode::BackendFailed, "hook::disable"});
            }

            // Only the newest live layer can write target bytes. A restore of this hook's saved prologue below a newer
            // layer clobbers it. Refuse without any mutation.
            TargetSlot slot(m_impl->target, m_impl->ledger_id);
            if (!slot.is_top_layer())
            {
                return std::unexpected(Error{ErrorCode::LayerConflict, "hook::disable", m_impl->target});
            }

            // Classify before the transition claim (see enable()). The unconditional prologue restore clobbers a
            // foreign writer's bytes. Refuse and leave the hook Active.
            if (const PatchWitness before = witness_of(m_impl->backend); !witness_permits_write(before))
            {
                (void)log().try_log(LogLevel::Warning, "hook: '{}' at 0x{:0{}X} refused disable: {}.", m_impl->name,
                                    m_impl->target, sizeof(std::uintptr_t) * 2, witness_description(before));
                return std::unexpected(Error{ErrorCode::DisableFailed, "hook::disable", m_impl->target});
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
            // Confirm the saved prologue is back before Disabled publication. The witness is taken whatever the
            // backend returns. An error can sit over restored bytes. A success without byte corroboration must not
            // publish Disabled.
            const bool backend_disabled = backend_value_or(m_impl->backend, false, [](auto &backend) noexcept
                                                           { return try_backend_disable(backend); });
            const PatchWitness after = witness_of(m_impl->backend);
            if (after == PatchWitness::Original)
            {
                (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.reconcile_enabled(false); });
                const std::uintptr_t target = m_impl->target;
                publish_toggle(*m_impl, *gate, slot, guard, false);
                if (!backend_disabled)
                {
                    // The disarm took effect, but the backend reported a post-commit failure (its page-protection
                    // restore). Report it rather than swallow it.
                    return std::unexpected(Error{ErrorCode::BackendFailed, "hook::disable", target});
                }
                return {};
            }
            // A completed restore can be followed by a newer or uncertain owner. Retain backend reachability so
            // is_enabled() and a later disable retry agree with the conservative Active state.
            (void)apply_backend(m_impl->backend, [](auto &backend) noexcept { backend.reconcile_enabled(true); });
            m_impl->status.store(HookState::Active, std::memory_order_release);
            return std::unexpected(Error{ErrorCode::DisableFailed, "hook::disable"});
        }

        void Hook::release() noexcept
        {
            if (!m_impl)
            {
                return;
            }
            // Leak the backend hook intentionally: it stays installed for the process lifetime and the ledger entry
            // stays so is_target_hooked still reports it. A gate clear disengages the handle, which matches the
            // moved-from contract. The ledger records it like every defensive pin in ~Hook.
            diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
            (void)m_impl.release();
            m_gate.store(nullptr, std::memory_order_release);
        }

        namespace detail
        {
            Result<Hook> inline_at_raw(InlineRequest request, void *detour)
            {
                if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::inline_at"))
                {
                    return std::unexpected(*vetoed);
                }
#if defined(DMK_ENABLE_TEST_SEAMS)
                note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::InlineAt);
#endif
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
                // Every failure path below rolls back this reservation. Success commits it after all fallible setup.
                const std::uint64_t ledger_id = preflight->ledger_id;

                const std::shared_ptr<safetyhook::Allocator> &allocator = backend_allocator();
                if (!allocator)
                {
                    (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                    return std::unexpected(Error{ErrorCode::AllocatorNotAvailable, "hook::inline_at"});
                }
                ModuleRefGuard self_ref(acquire_hook_self_ref());
                if (self_ref.get() == nullptr)
                {
                    // Capture the acquire's last-error before release_hook can clobber it (error.hpp documents
                    // SystemCallFailed's detail = GetLastError()).
                    const DWORD acquire_error = ::GetLastError();
                    (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                    return std::unexpected(Error{ErrorCode::SystemCallFailed, "hook::inline_at", acquire_error});
                }
                if (const std::optional<Error> stale = revalidate_before_patch(target, ledger_id, "hook::inline_at"))
                {
                    return std::unexpected(*stale);
                }
                try
                {
                    // StartDisabled makes this an install transaction. The detour stays unreachable while the fallible
                    // steps below publish the caller state. No fault boundary wraps this code. See
                    // hook_fault_boundary.hpp.
                    auto created = safetyhook::InlineHook::create(allocator, reinterpret_cast<void *>(target), detour,
                                                                  safetyhook::InlineHook::StartDisabled);
                    if (!created)
                    {
                        log().error("hook::inline_at: backend create failed for '{}' at {}: {}", request.name,
                                    format::format_address(target), backend_error_string(created.error()));
                        (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                        return std::unexpected(Error{ErrorCode::BackendFailed, "hook::inline_at", target});
                    }
                    auto backend_hook = std::move(created.value());
#if defined(DMK_ENABLE_TEST_SEAMS)
                    note_publish_step(DetourModKit::detail::HookPublishStep::BackendCreated);
#endif
                    auto impl = std::make_unique<Hook::Impl>(std::move(backend_hook), std::move(request.name), target,
                                                             ledger_id, HookState::Disabled);
#if defined(DMK_ENABLE_TEST_SEAMS)
                    note_publish_step(DetourModKit::detail::HookPublishStep::ImplConstructed);
#endif
                    // The gate starts null-callable, exactly as disable() leaves it. enable() publishes the
                    // trampoline once the target is armed.
                    auto gate = std::make_shared<Hook::CallGate>();
#if defined(DMK_ENABLE_TEST_SEAMS)
                    note_publish_step(DetourModKit::detail::HookPublishStep::GatePublished);
#endif
                    const std::string_view created_name = impl->name;
                    if (!DetourModKit::detail::HookLedger::instance().commit_hook(target, ledger_id))
                    {
                        (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                        return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::inline_at", target});
                    }
                    log().info("hook::inline_at: created inline hook '{}' at {} (disabled).", created_name,
                               format::format_address(target));
#if defined(DMK_ENABLE_TEST_SEAMS)
                    note_publish_step(DetourModKit::detail::HookPublishStep::LedgerCommitted);
#endif
                    emit_lifecycle(created_name, ledger_id, diagnostics::HookKind::Inline,
                                   diagnostics::HookTransition::Created);
                    // Hand the module reference to the Impl only after completion of every fallible setup step.
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
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::mid_at"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::MidAt);
#endif
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
            // Every failure path below rolls back this reservation. Success commits it after all fallible setup.
            const std::uint64_t ledger_id = preflight->ledger_id;

            const std::shared_ptr<safetyhook::Allocator> &allocator = backend_allocator();
            if (!allocator)
            {
                (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                return std::unexpected(Error{ErrorCode::AllocatorNotAvailable, "hook::mid_at"});
            }
            // Reserve the entry TLS index before dispatch becomes possible. A later acquire allocates on a host thread
            // during a callback.
            if (!DetourModKit::detail::ensure_mid_entry_tls())
            {
                const DWORD tls_error = ::GetLastError();
                (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "hook::mid_at", tls_error});
            }
            ModuleRefGuard self_ref(acquire_hook_self_ref());
            if (self_ref.get() == nullptr)
            {
                // Capture the acquire's last-error before release_hook can clobber it (see inline_at_raw).
                const DWORD acquire_error = ::GetLastError();
                (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "hook::mid_at", acquire_error});
            }
            if (const std::optional<Error> stale = revalidate_before_patch(target, ledger_id, "hook::mid_at"))
            {
                return std::unexpected(*stale);
            }
            // One adapter exists per live mid hook. MidAdapterSlotGuard releases the slot on every failure path below.
            // No adapter entry occurred because StartDisabled leaves the target unpatched until enable().
            const std::size_t slot_index = DetourModKit::detail::claim_mid_adapter_slot();
            if (slot_index >= DetourModKit::detail::MID_ADAPTER_CAPACITY)
            {
                (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                return std::unexpected(Error{ErrorCode::MidHookCapacityExhausted, "hook::mid_at", target});
            }
            MidAdapterSlotGuard slot_guard(slot_index);
            DetourModKit::detail::MidAdapterSlot &slot = DetourModKit::detail::mid_adapter_slots()[slot_index];
            slot.target.store(target, std::memory_order_relaxed);
            slot.detour.store(detour, std::memory_order_relaxed);
            slot.contained_exceptions.store(0, std::memory_order_relaxed);
            // Publish the callback before the adapter address reaches the backend.
            slot.live.store(true, std::memory_order_release);
            try
            {
                // This is the StartDisabled install transaction. See inline_at_raw and hook_fault_boundary.hpp. The
                // destination is the pool slot_index adapter, a real void(safetyhook::Context&).
                auto created = safetyhook::MidHook::create(allocator, reinterpret_cast<void *>(target),
                                                           DetourModKit::detail::MID_ADAPTER_TABLE[slot_index],
                                                           safetyhook::MidHook::StartDisabled);
                if (!created)
                {
                    log().error("hook::mid_at: backend create failed for '{}' at {}: {}", request.name,
                                format::format_address(target), backend_error_string(created.error()));
                    (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                    return std::unexpected(Error{ErrorCode::BackendFailed, "hook::mid_at", target});
                }
                auto backend_hook = std::move(created.value());
#if defined(DMK_ENABLE_TEST_SEAMS)
                note_publish_step(DetourModKit::detail::HookPublishStep::BackendCreated);
#endif
                auto impl = std::make_unique<Hook::Impl>(std::move(backend_hook), std::move(request.name), target,
                                                         ledger_id, HookState::Disabled);
#if defined(DMK_ENABLE_TEST_SEAMS)
                note_publish_step(DetourModKit::detail::HookPublishStep::ImplConstructed);
#endif
                // A mid hook gate is null-callable for life. It still serializes enable, disable, and teardown.
                auto gate = std::make_shared<Hook::CallGate>();
#if defined(DMK_ENABLE_TEST_SEAMS)
                note_publish_step(DetourModKit::detail::HookPublishStep::GatePublished);
#endif
                const std::string_view created_name = impl->name;
                if (!DetourModKit::detail::HookLedger::instance().commit_hook(target, ledger_id))
                {
                    (void)DetourModKit::detail::HookLedger::instance().release_hook(target, ledger_id);
                    return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::mid_at", target});
                }
                log().info("hook::mid_at: created mid hook '{}' at {} (disabled).", created_name,
                           format::format_address(target));
#if defined(DMK_ENABLE_TEST_SEAMS)
                note_publish_step(DetourModKit::detail::HookPublishStep::LedgerCommitted);
#endif
                emit_lifecycle(created_name, ledger_id, diagnostics::HookKind::Mid,
                               diagnostics::HookTransition::Created);
                // Hand the module reference and adapter slot to the Impl. Teardown owns both after this point.
                impl->self_ref = self_ref.release();
                impl->mid_slot = slot_guard.release();
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
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::install_all"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::InstallAll);
#endif
            // InstallRollback removes a partial install newest-first. A vector's front-to-back destruction is unsafe
            // for layered hooks on one target. InstallRollback handles mandatory misses and exceptions unless commit()
            // moves the rows out.
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
                    // The OwnedScanRequest copy preserves the caller table entries for install_all. Each row's Options
                    // value carries its install policy.
                    Target target = spec.m_target;
                    Result<Hook> installed =
                        std::holds_alternative<InlineDetour>(spec.m_detour)
                            ? detail::inline_at_raw(InlineRequest{spec.m_name, std::move(target), spec.m_options},
                                                    std::get<InlineDetour>(spec.m_detour).fn)
                            : mid_at(MidRequest{spec.m_name, std::move(target), spec.m_options},
                                     std::get<MidHookFn>(spec.m_detour));

                    if (!installed && spec.m_severity == Severity::Mandatory)
                    {
                        // Fail fast: ~InstallRollback unhooks every already-installed row newest-first before the
                        // error propagates.
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

        // VmtHook is the RAII handle for a cloned vtable and its object-level clone lifecycle.
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

        VmtHook::~VmtHook() noexcept
        {
            if (!m_impl)
            {
                return;
            }
            // Loader-lock leaf discipline requires an Impl leak instead of vptr restoration here. Its module reference
            // keeps the clone code pages mapped.
            if (!DetourModKit::detail::blocking_teardown_permitted())
            {
                diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                (void)m_impl.release();
                return;
            }
            const std::uint64_t ledger_id = m_impl->ledger_id;
            // Copy the name out before reset destroys its storage. Contain an OOM exception and degrade to an empty
            // name (noexcept destructor).
            std::string name;
            try
            {
                name = m_impl->name;
            }
            catch (...)
            {
            }
            // Teardown restores every applied object before it releases the ledger entry per Hook::~Hook order. This
            // order prevents a race between a vmt_for or apply_to operation and clone removal.
            HMODULE self_ref = nullptr;
            {
                std::unique_lock<std::mutex> object_gate = acquire_vmt_object_lock();
                if (!object_gate.owns_lock())
                {
                    // Leak the Impl rather than restore vptrs without the gate.
                    diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                    (void)m_impl.release();
                    return;
                }
                // Restore every object with known state. A different vptr can belong to a successor that recorded this
                // clone as its original. An unreadable or non-writable word is equally unsafe to overwrite.
                std::size_t unrestorable = 0;
                for (const auto &binding : m_impl->object_bindings)
                {
                    const DetourModKit::detail::ObjectWordResult word = DetourModKit::detail::validate_vmt_object_word(
                        reinterpret_cast<std::uintptr_t>(binding.object));
                    if (word.verdict != DetourModKit::detail::ObjectWordVerdict::Unreadable &&
                        word.vptr == binding.original_vptr)
                    {
                        continue;
                    }
                    if (word.verdict == DetourModKit::detail::ObjectWordVerdict::Ok &&
                        word.vptr == m_impl->cloned_vptr_base)
                    {
                        if (publish_vmt_object_word(binding.object, m_impl->cloned_vptr_base, binding.original_vptr))
                        {
                            continue;
                        }
                    }
                    ++unrestorable;
                }
                if (unrestorable > 0)
                {
                    const std::size_t object_count = m_impl->object_bindings.size();
                    diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
                    (void)m_impl.release();
                    object_gate.unlock();
#if defined(DMK_ENABLE_TEST_SEAMS)
                    if (auto *probe = DetourModKit::detail::g_vmt_teardown_warning_probe)
                    {
                        probe();
                    }
#endif
                    (void)log().try_log(LogLevel::Warning,
                                        "hook::~VmtHook: VMT hook '{}' destroyed while {} of its {} object(s) could "
                                        "not be provably restored to their original vtable; leaked this clone to "
                                        "avoid a vtable use-after-free. Destroy VMT hooks newest-first to restore "
                                        "the original table.",
                                        std::string_view{name}, unrestorable, object_count);
                    return;
                }
                self_ref = static_cast<HMODULE>(m_impl->self_ref);
                m_impl.reset();
            }
            // Release outside the object gate: FreeLibrary takes the loader lock, which must not nest inside the
            // process-wide VMT gate.
            DetourModKit::detail::release_module_ref(self_ref);
            DetourModKit::detail::HookLedger::instance().release_vmt(ledger_id);
            // A VMT hook is live from creation and has no enable/disable transition, so it is always counted armed.
            emit_lifecycle(name, ledger_id, diagnostics::HookKind::Vmt, diagnostics::HookTransition::Removed,
                           RemovalPopulationState{.was_active = true});
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
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::vmt_apply"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::VmtApply);
#endif
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
            // Exclusive write keeps the policy decision and guarded swap atomic against this handle's readers. The
            // process-wide object gate serializes the vptr transition against other DMK VMT handles.
            std::unique_lock<DetourModKit::detail::SrwSharedMutex> gate(m_impl->method_mutex);
            // Object-word validation is not a policy: every option set requires a capturable writable word, and the
            // later guarded compare-exchange closes a protection/unmap race.
            const DetourModKit::detail::ObjectWordResult word =
                DetourModKit::detail::validate_vmt_object_word(reinterpret_cast<std::uintptr_t>(object));
            if (word.verdict != DetourModKit::detail::ObjectWordVerdict::Ok)
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_apply", word.detail});
            }
            const std::uintptr_t current_vptr = word.vptr;
            // Locate this object's restoration binding before any policy branch. Teardown restores from the
            // binding. Refusal is the only outcome that keeps every recorded original true.
            const auto binding = std::find_if(m_impl->object_bindings.begin(), m_impl->object_bindings.end(),
                                              [object](const auto &entry) -> bool { return entry.object == object; });
            const bool already_tracked = binding != m_impl->object_bindings.end();
            if (current_vptr == m_impl->cloned_vptr_base)
            {
                if (!already_tracked)
                {
                    // This handle holds no original vptr for this object. A new binding records the clone base as its
                    // own original, and teardown then frees the clone below it.
                    return std::unexpected(Error{ErrorCode::HookAlreadyExists, "hook::vmt_apply", current_vptr});
                }
                // If the object already uses this handle's clone, every policy treats the apply as a no-op.
                return {};
            }
            else if (already_tracked && current_vptr != binding->original_vptr)
            {
                // Another actor moved the object off the recorded vptr, usually through a newer layer. A new
                // publication displaces state that this binding does not name.
                return std::unexpected(Error{ErrorCode::HookAlreadyExists, "hook::vmt_apply", current_vptr});
            }
            if (options.fail_if_already_hooked || options.fail_on_non_function_pointer)
            {
                if (options.fail_if_already_hooked)
                {
                    if (DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(current_vptr))
                    {
                        // If a different same-kit VmtHook owns the clone, refuse another layer.
                        return std::unexpected(Error{ErrorCode::HookAlreadyExists, "hook::vmt_apply", current_vptr});
                    }
                }
                if (options.fail_on_non_function_pointer)
                {
                    const std::optional<std::uintptr_t> slot0 =
                        DetourModKit::detail::guarded_read<std::uintptr_t>(current_vptr);
                    if (!slot0)
                    {
                        return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_apply", current_vptr});
                    }
                    if (!looks_like_function_vmt_slot(*slot0))
                    {
                        return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_apply", *slot0});
                    }
                }
            }
            else if (DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(current_vptr))
            {
                // The permissive default permits a chain on another kit clone. This copies its hooked slots into this
                // handle "original" snapshot, which creates the silent double hook. Proceed per contract but warn.
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook::vmt_apply: applying VMT hook '{}' onto object {} whose vptr {} is already a clone owned by "
                    "another DMK VMT hook; that clone's hooked slots will be captured as this hook's original. Set "
                    "VmtOptions::fail_if_already_hooked to refuse instead.",
                    std::string_view{m_impl->name}, format::format_address(reinterpret_cast<std::uintptr_t>(object)),
                    format::format_address(current_vptr));
            }
            // Reserve the restoration binding before publication. Capacity growth after publication can throw with
            // the object already on the clone but absent from the state that teardown needs.
            if (!already_tracked)
            {
                try
                {
                    m_impl->object_bindings.reserve(m_impl->object_bindings.size() + 1);
                }
                catch (const std::bad_alloc &)
                {
                    return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::vmt_apply"});
                }
            }
            if (!publish_vmt_object_word(object, current_vptr, m_impl->cloned_vptr_base))
            {
                return std::unexpected(
                    Error{ErrorCode::InvalidObject, "hook::vmt_apply", reinterpret_cast<std::uintptr_t>(object)});
            }
            if (!already_tracked)
            {
                // The reserved capacity guarantees that this push cannot throw.
                m_impl->object_bindings.push_back({object, current_vptr});
            }
            return {};
        }

        Result<void> VmtHook::remove_from(void *object)
        {
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::vmt_remove"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::VmtRemove);
#endif
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
            // The exclusive write prevents a race between unapply and an original() snapshot reader during transition.
            std::unique_lock<DetourModKit::detail::SrwSharedMutex> gate(m_impl->method_mutex);
            const auto binding = std::find_if(m_impl->object_bindings.begin(), m_impl->object_bindings.end(),
                                              [object](const auto &entry) -> bool { return entry.object == object; });
            if (binding == m_impl->object_bindings.end())
            {
                return {};
            }

            // Keep the full binding if a successor still outranks this clone. A later rollback can return it here.
            const DetourModKit::detail::ObjectWordResult word =
                DetourModKit::detail::validate_vmt_object_word(reinterpret_cast<std::uintptr_t>(object));
            if (word.verdict == DetourModKit::detail::ObjectWordVerdict::Ok && word.vptr == m_impl->cloned_vptr_base)
            {
                // The re-read below is the authority: an object already at its original restores nothing yet must
                // still release its binding.
                (void)publish_vmt_object_word(object, m_impl->cloned_vptr_base, binding->original_vptr);
            }

            const std::optional<std::uintptr_t> after =
                DetourModKit::detail::guarded_read<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(object));
            if (after && *after == binding->original_vptr)
            {
                m_impl->object_bindings.erase(binding);
            }
            return {};
        }

        Result<void> VmtHook::hook_method_raw(std::size_t index, void *detour)
        {
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::vmt_hook_method"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::VmtHookMethod);
#endif
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::vmt_hook_method"});
            }
            if (detour == nullptr)
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "hook::vmt_hook_method"});
            }
            {
                // The map insert and backend slot patch must be atomic against a concurrent original() snapshot reader.
                // That reader traverses this same map under the shared read.
                std::unique_lock<DetourModKit::detail::SrwSharedMutex> gate(m_impl->method_mutex);
                if (index >= m_impl->method_count)
                {
                    return std::unexpected(Error{ErrorCode::InvalidArg, "hook::vmt_hook_method", index});
                }
                if (m_impl->method_hooks.contains(index))
                {
                    // One method hook exists per slot. A second hook reads the first detour as the "original" and
                    // creates a silent mod chain.
                    return std::unexpected(Error{ErrorCode::MethodAlreadyHooked, "hook::vmt_hook_method", index});
                }
                try
                {
                    // A void* detour installs the same 8 bytes as a typed pointer. hook_method<Fn> vetted the ABI.
                    auto created = m_impl->backend.hook_method(index, detour);
                    if (!created)
                    {
                        return std::unexpected(Error{ErrorCode::BackendFailed, "hook::vmt_hook_method", index});
                    }
                    // emplace is the last fallible step and the commit point. A bad_alloc unwinds the new VmHook. Its
                    // destructor rolls the slot back, so nothing is half-registered.
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
            // This post-commit best-effort log contains a format bad_alloc, so it cannot flip a committed install into
            // a failure.
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
            // A shared read serializes the snapshot against exclusive writers. The copied pointer is then called
            // lock-free by contract (see original()).
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
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::vmt_remove_method"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::VmtRemoveMethod);
#endif
            if (!m_impl)
            {
                return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::vmt_remove_method"});
            }
            {
                // An exclusive write runs the VmHook destructor when it erases the entry. The destructor restores the
                // cloned slot to its original pointer. That restore must not race an original() snapshot reader.
                std::unique_lock<DetourModKit::detail::SrwSharedMutex> gate(m_impl->method_mutex);
                const auto it = m_impl->method_hooks.find(index);
                if (it == m_impl->method_hooks.end())
                {
                    return std::unexpected(Error{ErrorCode::MethodNotFound, "hook::vmt_remove_method", index});
                }
                m_impl->method_hooks.erase(it);
            }
            // This post-commit log is best-effort. Contain a format bad_alloc.
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
            // Leak the cloned vtable intentionally. Applied objects keep the clone for the process lifetime. The ledger
            // entry stays so is_vmt_clone_base still recognizes the live clone base. HookManager records the leak.
            diagnostics::record_intentional_leak(diagnostics::LeakSubsystem::HookManager);
            (void)m_impl.release();
        }

        Result<VmtHook> vmt_for(std::string name, void *object, VmtOptions options)
        {
            if (std::optional<Error> vetoed = refuse_on_loader_lock("hook::vmt_for"))
            {
                return std::unexpected(*vetoed);
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            note_loader_veto_passed(DetourModKit::detail::HookLoaderEntry::VmtFor);
#endif
            if (name.empty())
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "hook::vmt_for"});
            }
            if (object == nullptr)
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for"});
            }
            // Take the module reference before the process-wide VMT object gate. A rollback runs FreeLibrary, which
            // takes the loader lock and must not nest inside the gate per ~VmtHook lock order. Declare the guard first.
            // The gate then unlocks first, so the guard FreeLibrary call always runs outside it.
            ModuleRefGuard self_ref(acquire_hook_self_ref());
            if (self_ref.get() == nullptr)
            {
                // acquire_module_ref restores GetLastError() on failure (error.hpp documents the detail contract).
                return std::unexpected(Error{ErrorCode::SystemCallFailed, "hook::vmt_for", ::GetLastError()});
            }
            std::unique_lock<std::mutex> object_gate = acquire_vmt_object_lock();
            if (!object_gate.owns_lock())
            {
                return std::unexpected(Error{ErrorCode::UnknownError, "hook::vmt_for"});
            }
            // Object-word validation is not a policy (see apply_to).
            const DetourModKit::detail::ObjectWordResult word =
                DetourModKit::detail::validate_vmt_object_word(reinterpret_cast<std::uintptr_t>(object));
            if (word.verdict != DetourModKit::detail::ObjectWordVerdict::Ok)
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for", word.detail});
            }
            const std::uintptr_t current_vptr = word.vptr;
            if (options.fail_if_already_hooked || options.fail_on_non_function_pointer)
            {
                if (options.fail_if_already_hooked &&
                    DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(current_vptr))
                {
                    return std::unexpected(Error{ErrorCode::HookAlreadyExists, "hook::vmt_for", current_vptr});
                }
                if (options.fail_on_non_function_pointer)
                {
                    const std::optional<std::uintptr_t> slot0 =
                        DetourModKit::detail::guarded_read<std::uintptr_t>(current_vptr);
                    if (!slot0)
                    {
                        return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for", current_vptr});
                    }
                    if (!looks_like_function_vmt_slot(*slot0))
                    {
                        return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for", *slot0});
                    }
                }
            }
            else if (DetourModKit::detail::HookLedger::instance().is_vmt_clone_base(current_vptr))
            {
                // For the permissive default, see the associated warning in apply_to. vmt_for creates a fresh clone,
                // so it needs no own-clone-base exclusion here.
                (void)log().try_log(
                    LogLevel::Warning,
                    "hook::vmt_for: cloning object {} for VMT hook '{}' whose vptr {} is already a clone owned by "
                    "another DMK VMT hook; that clone's hooked slots will be captured as this hook's original. Set "
                    "VmtOptions::fail_if_already_hooked to refuse instead.",
                    format::format_address(reinterpret_cast<std::uintptr_t>(object)), std::string_view{name},
                    format::format_address(current_vptr));
            }
            const std::optional<std::size_t> slot_budget = count_vmt_method_slots(current_vptr);
            if (!slot_budget)
            {
                return std::unexpected(
                    Error{ErrorCode::InvalidObject, "hook::vmt_for", reinterpret_cast<std::uintptr_t>(object)});
            }
            // An engaged zero found no callable slot. The clone is unusable by construction.
            if (*slot_budget == 0)
            {
                return std::unexpected(Error{ErrorCode::InvalidObject, "hook::vmt_for", current_vptr});
            }
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *probe = DetourModKit::detail::g_vmt_before_capture_probe)
            {
                probe();
            }
#endif
            try
            {
                Result<DetachedVmtBackend> cloned = clone_vmt_snapshot(current_vptr, *slot_budget);
                if (!cloned)
                {
                    return std::unexpected(cloned.error());
                }
                const std::uintptr_t cloned_vptr_base = cloned->cloned_vptr_base;
                auto impl = std::make_unique<VmtHook::Impl>(std::move(cloned->backend), std::move(name),
                                                            cloned_vptr_base, cloned->method_count, 0);
                impl->object_bindings.push_back({object, current_vptr});
                const std::string_view created_name = impl->name;
                const std::optional<std::uint64_t> recorded =
                    DetourModKit::detail::HookLedger::instance().try_record_vmt(cloned_vptr_base);
                if (!recorded)
                {
                    return std::unexpected(Error{ErrorCode::OutOfMemory, "hook::vmt_for"});
                }
                impl->ledger_id = *recorded;
                // Publication is last: every allocation, binding, and ledger step completes before the guarded store
                // can expose the clone to host dispatch.
                if (!publish_vmt_object_word(object, current_vptr, cloned_vptr_base))
                {
                    DetourModKit::detail::HookLedger::instance().release_vmt(*recorded);
                    return std::unexpected(
                        Error{ErrorCode::InvalidObject, "hook::vmt_for", reinterpret_cast<std::uintptr_t>(object)});
                }
                // Release the gate BEFORE the log and lifecycle event: subscriber code must not run under the
                // process-wide VMT mutex (CP.22), because a reentrant subscriber self-deadlocks.
                object_gate.unlock();
                // This post-commit log is best-effort. Contain a format bad_alloc (see hook_method_raw).
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
                // Hand the module reference to the Impl only after completion of every fallible setup step.
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
