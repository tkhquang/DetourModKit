#ifndef DETOURMODKIT_INTERNAL_HOOK_BACKEND_HPP
#define DETOURMODKIT_INTERNAL_HOOK_BACKEND_HPP

/**
 * @file internal/hook_backend.hpp
 * @brief Backend-coupled pimpl bodies and the per-instance allocator for the hook subsystem.
 * @details hook.hpp holds each backend-owning handle's nested Impl behind std::unique_ptr. This header completes those
 *          bodies with safetyhook.hpp visible. scripts/check_header_hygiene.py owns and gates BACKEND_SOURCE_ISLANDS.
 *          docs/design/hooking.md ("Backend confinement") describes the islands. hook.hpp owns the rule that
 *          hook::MidContext stays incomplete, so no definition belongs here.
 */

#include "DetourModKit/hook.hpp"

#include "internal/srw_shared_mutex.hpp"

#include <safetyhook.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace DetourModKit
{
    namespace hook
    {
        /**
         * @enum HookState
         * @brief Internal enable/disable state machine for a managed Hook (never public).
         * @details The intermediate Enabling / Disabling states let an atomic compare-exchange publish a terminal
         *          state only after the backend toggle returns, so a concurrent reader never observes a speculative
         *          Active/Disabled while the backend call is mid-flight.
         */
        enum class HookState : std::uint8_t
        {
            Active,
            Disabled,
            Enabling,
            Disabling
        };

        /**
         * @brief The refcounted call gate that outlives the backend it fronts, so a late @ref Hook::call is safe.
         * @details A caller pins the gate before locking, and teardown nulls @ref callable under the same mutex before
         *          freeing the trampoline. The recursive mutex permits a detour to re-enter @ref Hook::call. During
         *          loader-lock teardown the backend and its module reference are intentionally leaked, so callable
         *          remains valid. Every access to callable holds the mutex.
         */
        struct Hook::CallGate
        {
            std::recursive_mutex mutex;
            void *callable{nullptr};
        };

        /// The return-site lists that the calls of a counted thunk outside its counted window can fill.
        inline constexpr std::size_t COUNTED_HELPER_SITE_LISTS = 4;

        /**
         * @brief The thunk of a counted hook: its counters and the code that its drain proof scans (`[B-106]`).
         * @details The range is the thunk's unchained RUNTIME_FUNCTION. A helper site is the return into the thunk
         *          of a call that runs before the enter count or after the exit count. An unoptimized consumer build
         *          can emit such a call, and only a stack read finds a thread inside it.
         */
        struct CountedThunk
        {
            detail::CountedBlock *block{nullptr};
            safetyhook::AddressRange range{};
            std::array<safetyhook::ReturnSites, COUNTED_HELPER_SITE_LISTS> helper_sites{};
            std::size_t helper_site_lists{0};
        };

        /**
         * @brief The complete backend state behind a @ref Hook handle.
         * @details Holds one backend hook, its state, identity, target, and ledger token. The call mutex lives in the
         *          separate refcounted @ref Hook::CallGate. Atomic state makes this type non-movable.
         */
        struct Hook::Impl
        {
            std::variant<safetyhook::InlineHook, safetyhook::MidHook> backend;
            std::atomic<HookState> status;
            std::string name;
            std::uintptr_t target{0};
            std::uint64_t ledger_id{0};
            bool is_inline{false};
            // Index into the mid-hook adapter pool, or SIZE_MAX for an inline hook. Kept as a bare index (rather than a
            // slot pointer) so this header does not have to name the adapter pool. Teardown runs the slot down through
            // it; a pinned Impl carries it away and the slot is never reclaimed, which is what keeps a still-reachable
            // stub's adapter pointing at storage that outlives it.
            std::size_t mid_slot{static_cast<std::size_t>(-1)};
            // Counted reference on the module that holds the detour and adapter code, taken before the backend is
            // published while the module is mapped. Trampolines live in allocator memory, so the reference protects
            // only image code that a retained chain can still reach. ~Hook releases it when no path reaches that code:
            // after a restore, or after a bypass and drain. A leak branch keeps it with the leaked Impl. Holds an
            // HMODULE (kept as void* so the acquire/release stay in hook.cpp). See detail::acquire_module_ref.
            void *self_ref{nullptr};
            // True while the switch word sends every caller past the detour and the target patch stays in the chain.
            // Written under the call gate mutex. A claimed backend starts bypassed.
            bool bypassed{false};
            // The thunk of a counted inline hook, or empty for a raw inline or a mid hook.
            std::optional<CountedThunk> counted;

#if defined(DMK_ENABLE_TEST_SEAMS)
            ~Impl() noexcept;
#endif

            Impl(
                safetyhook::InlineHook hook,
                std::string hook_name,
                std::uintptr_t hook_target,
                std::uint64_t ledger,
                HookState initial_state
            )
                : backend(std::move(hook)), status(initial_state), name(std::move(hook_name)), target(hook_target),
                  ledger_id(ledger), is_inline(true)
            {
            }

            Impl(
                safetyhook::MidHook hook,
                std::string hook_name,
                std::uintptr_t hook_target,
                std::uint64_t ledger,
                HookState initial_state
            )
                : backend(std::move(hook)), status(initial_state), name(std::move(hook_name)), target(hook_target),
                  ledger_id(ledger), is_inline(false)
            {
            }
        };

        /**
         * @brief The complete backend state behind a @ref VmtHook handle.
         * @details Owns the detached backend clone, its identity, bindings, and per-index method hooks. SafetyHook is
         *          created on a private snapshot surrogate whose counted run is normalized to a stable executable
         *          marker, then populated with the captured targets. It retains no host object pointer; DMK publishes
         *          and restores every binding through guarded stores. method_count exactly matches the backend-owned
         *          allocation and bounds every unchecked VmHook slot access.
         *
         *          Per-method hooks are backend VmHooks keyed by vtable index. Each VmHook, on destruction, rewrites
         *          its cloned-vtable slot back to the original function pointer, so erasing an entry (@ref
         *          VmtHook::remove_method) or destroying the map (handle teardown) restores that method. The map dies
         *          before `backend`, keeping the clone allocation alive until every VmHook has released it.
         *
         *          method_mutex is the reader/writer guard for per-method state: @ref VmtHook::original snapshots a
         *          slot's original pointer under a shared read, while @ref VmtHook::hook_method,
         *          @ref VmtHook::remove_method, @ref VmtHook::apply_to, and @ref VmtHook::remove_from mutate under the
         *          exclusive write, so a snapshot reader never traverses the map (or observes an apply)
         *          mid-mutation. It is an SRWLOCK wrapper rather than std::shared_mutex because winpthreads' rwlock
         *          corrupts under reader contention; all of its operations are noexcept, which is what lets
         *          @ref VmtHook::original stay noexcept.
         */
        struct VmtHook::Impl
        {
            struct ObjectBinding
            {
                void *object{nullptr};
                std::uintptr_t original_vptr{0};
            };

            safetyhook::VmtHook backend;
            std::string name;
            std::uintptr_t cloned_vptr_base{0};
            std::size_t method_count{0};
            std::uint64_t ledger_id{0};
            // Counted reference on the module this clone's code lives in, taken before the clone is published;
            // released on clean teardown, left outstanding with the leaked Impl on a leak branch. Holds an HMODULE;
            // acquire/release live in hook.cpp.
            void *self_ref{nullptr};
            // Complete restoration state for objects whose dependency on this clone has not been safely released.
            // Guarded by the process-wide VMT object gate.
            std::vector<ObjectBinding> object_bindings;
            mutable DetourModKit::detail::SrwSharedMutex method_mutex;

            /**
             * @brief One hooked slot: the original pointer read from the clone and the backend's slot patch.
             * @details The node exists before the backend stores the slot, so @ref VmtHook::original resolves from
             *          the instant a detour can run. VmtHookFaultProof.MethodMapNodeAllocatesBeforeSlotStore pins it.
             */
            struct MethodHook
            {
                void *original{nullptr};
                safetyhook::VmHook backend;
            };
            std::unordered_map<std::size_t, MethodHook> method_hooks;

            Impl(
                safetyhook::VmtHook hook,
                std::string hook_name,
                std::uintptr_t base,
                std::size_t methods,
                std::uint64_t ledger
            )
                : backend(std::move(hook)), name(std::move(hook_name)), cloned_vptr_base(base), method_count(methods),
                  ledger_id(ledger)
            {
            }
        };

        /// How the teardown of one Hook ended. @ref HookRetirement counts each value.
        enum class TeardownOutcome : std::uint8_t
        {
            /// The handle owned no hook.
            Empty,
            /// The hook restored its target.
            Restored,
            /// The hook retired by bypass as residue and reaches no image code.
            Vacated,
            /// The backend leaked with its detour possibly reachable. HookManager counts it.
            Pinned,
        };

        namespace detail
        {
            /// The access path of hook.cpp and hook_retirement.cpp to the private state of a Hook.
            struct HookAccess
            {
                /// Returns the backend state of @p hook, or nullptr for a disengaged handle.
                [[nodiscard]] static Hook::Impl *impl(const Hook &hook) noexcept { return hook.m_impl.get(); }

                /// Builds the handle that an install verb returns.
                [[nodiscard]] static Hook
                make(std::unique_ptr<Hook::Impl> impl, std::shared_ptr<Hook::CallGate> gate) noexcept
                {
                    return Hook(std::move(impl), std::move(gate));
                }

                /// Runs the ~Hook contract on @p hook and reports how it ended. The handle ends disengaged.
                [[nodiscard]] static TeardownOutcome teardown(Hook &hook) noexcept;

                /**
                 * @brief Installs a disabled inline hook whose relay jumps to @p destination, after the preflight
                 *        reserved @p ledger_id on @p target.
                 * @details @p counted carries the thunk of a counted hook. Every failure releases the reservation.
                 */
                [[nodiscard]] static Result<Hook> install_inline(
                    InlineRequest request,
                    std::uintptr_t target,
                    std::uint64_t ledger_id,
                    void *destination,
                    std::optional<CountedThunk> counted
                );
            };

            /// The thunk geometry that the install decodes. The positions serve the region-boundary proofs.
            struct CountedThunkShape
            {
                CountedThunk thunk;
                /**
                 * @brief The offset of the locked increment that counts an entry.
                 * @details A stack word equal to a helper site keeps the drain Busy, so the shape holds offsets.
                 */
                std::size_t enter_count_offset{0};
                /// The offset of the first instruction after the locked increment that counts an exit.
                std::size_t after_exit_count_offset{0};
                /// The calls outside the counted window. Each one adds a helper site.
                std::size_t helper_calls{0};
                /// The calls inside the counted window: the detour call, plus any argument copy helper.
                std::size_t counted_calls{0};
                /// The push and pop instructions before the return, so a proof can check a balanced frame.
                std::size_t pushes{0};
                std::size_t pops{0};
            };

            /**
             * @brief Decodes the counted thunk at @p entry, through any incremental-link jump, for the drain proof.
             * @return The shape, or a sentence that names why the proof cannot cover the thunk. The proof needs one
             *         unchained RUNTIME_FUNCTION of straight-line code with exactly two locked increments and at
             *         least one call between them.
             */
            [[nodiscard]] std::expected<CountedThunkShape, const char *> inspect_counted_thunk(void *entry) noexcept;

            /// The verdict of @ref drain_counted.
            struct CountedDrain
            {
                bool idle{false};
                /// The calls between enter and exit at the last counter read.
                std::uint64_t in_flight{0};
            };

            /**
             * @brief Proves that no thread runs the thunks behind @p blocks or their detours (`[B-106]`).
             * @details The relays must already send every caller past the thunks. The proof runs pass 1 over
             *          @p ranges and @p sites, reads every exit count and then every enter count, and runs pass 2. It
             *          accepts only a clean pass 1, equal sums, and a clean pass 2. Otherwise it retries until
             *          @p deadline and holds no coordinator or ledger slot between passes.
             */
            [[nodiscard]] CountedDrain drain_counted(
                std::span<const safetyhook::AddressRange> ranges,
                std::span<const safetyhook::ReturnSites *const> sites,
                std::span<CountedBlock *const> blocks,
                std::chrono::steady_clock::time_point deadline
            ) noexcept;

            /**
             * @brief Reports whether a return address on the current thread's stack lies inside one of @p ranges.
             * @details An unwind of the current thread through its function tables finds the frames, so a stale stack
             *          word never matches. A walk deeper than its frame bound misses the frames beyond it.
             */
            [[nodiscard]] bool current_thread_returns_into(std::span<const safetyhook::AddressRange> ranges) noexcept;
        } // namespace detail

        /**
         * @brief Returns the SafetyHook allocator shared by every hook this linked instance installs.
         * @details The hold keeps the trampoline arena mapped and is never released (`[B-47]`). A hook owned by a
         *          namespace-scope object runs ~Impl during static destruction and must not free its trampoline into
         *          a destroyed arena. An empty result means the backend provided no global allocator, which the
         *          create paths report as ErrorCode::AllocatorNotAvailable.
         */
        [[nodiscard]] const std::shared_ptr<safetyhook::Allocator> &backend_allocator() noexcept;
    } // namespace hook

#if defined(DMK_ENABLE_TEST_SEAMS)
    namespace detail
    {
        /// Holds or releases a backend trap transaction immediately before its first protection change.
        void set_backend_trap_transaction_hold_for_test(bool hold) noexcept;

        /// Reports whether the held backend trap transaction reached its deterministic park.
        [[nodiscard]] bool backend_trap_transaction_reached_for_test() noexcept;

        /// Returns the number of page-protection calls made by backend trap transactions.
        [[nodiscard]] std::size_t backend_trap_protect_calls_for_test() noexcept;

        /// Closes backend trap-transaction admission and retires its vectored handler.
        void retire_backend_trap_runtime_for_test() noexcept;

        /// Describes the result of a directly driven backend protection transaction.
        enum class TrapTransactionOutcome : std::uint8_t
        {
            Restored,
            ReportedFailure,
            Threw,
        };

        /**
         * @brief Runs a backend protection transaction over caller-owned spans.
         * @param from Source span start.
         * @param to Destination span start.
         * @param len Span length in bytes.
         * @param run_fn Function that runs inside the transaction.
         * @return The transaction outcome.
         */
        [[nodiscard]] TrapTransactionOutcome drive_backend_trap_transaction_for_test(
            void *from,
            void *to,
            std::size_t len,
            const std::function<void()> &run_fn
        ) noexcept;

        /// Arms one forward segment-protection change to report failure, or disarms it with nullptr.
        void set_backend_trap_change_failure_target_for_test(void *segment_address) noexcept;

        /// Arms one segment restore to report failure, or disarms it with nullptr.
        void set_backend_trap_segment_restore_failure_target_for_test(void *segment_address) noexcept;

        /// Returns the number of segment restore attempts in the latest directly driven transaction.
        [[nodiscard]] std::size_t backend_trap_restore_trace_size_for_test() noexcept;

        /// Returns one segment address from the latest ordered restore trace.
        [[nodiscard]] void *backend_trap_restore_trace_address_for_test(std::size_t index) noexcept;

        /// Describes one backend instruction-cache flush and its transaction position.
        struct BackendInstructionFlushObservation
        {
            void *address{nullptr};
            std::size_t size{0};
            std::size_t protect_calls_before{0};
            bool succeeded{false};
        };

        /** @brief Clears the backend flush trace and makes the current thread its only recorder. */
        void reset_backend_instruction_flush_trace_for_test() noexcept;

        /// Forces one upcoming backend instruction-cache flush call to fail, or disables failure with zero.
        void set_backend_instruction_flush_failure_call_for_test(std::size_t call) noexcept;

        /** @brief Returns the trace size for the recorder, or zero for any other thread. */
        [[nodiscard]] std::size_t backend_instruction_flush_trace_size_for_test() noexcept;

        /// Returns one backend instruction-cache flush trace record.
        [[nodiscard]] BackendInstructionFlushObservation
        backend_instruction_flush_trace_for_test(std::size_t index) noexcept;

        /// Forces the next backend inline setup to use its FF path.
        void force_backend_ff_hook_for_test(bool force) noexcept;

        /// Returns the latest backend E9 instruction-boundary count for the current thread.
        [[nodiscard]] std::size_t backend_instruction_boundary_trace_size_for_test() noexcept;

        /// Returns one original-to-trampoline instruction boundary.
        [[nodiscard]] std::array<std::size_t, 2>
        backend_instruction_boundary_trace_for_test(std::size_t index) noexcept;

        /// Returns the latest backend inline error type for the current thread.
        [[nodiscard]] std::uint8_t backend_last_inline_error_type_for_test() noexcept;

        /// Returns an address whose page cannot enter a non-executable backend transaction.
        [[nodiscard]] void *backend_non_executable_transaction_marker_for_test() noexcept;

        /// Withholds the position claim from inline_at and mid_at. See hook.cpp.
        extern std::atomic<bool> g_hook_position_claims_refused_for_test;

        /// Makes every later backend setup emit the trampoline shape of a 4.3.0 copy, with no relay cell.
        void omit_backend_relay_cell_for_test(bool omit) noexcept;

        /// Selects 0 for no refusal, or a safetyhook::g_coordinator_refusal_for_test value.
        void set_backend_coordinator_refusal_for_test(unsigned refusal) noexcept;

        /// Counts the process route records by state.
        struct BackendCoordinatorCounts
        {
            std::size_t live{0};
            std::size_t retained{0};
            std::size_t vacant{0};
            std::size_t free{0};
        };

        /// Reads the process route records under the coordinator.
        [[nodiscard]] BackendCoordinatorCounts backend_coordinator_counts_for_test() noexcept;

        /// Selects the kind of a raw backend probe.
        enum class BackendProbeKind : std::uint8_t
        {
            Inline,
            Mid,
            Routed,
        };

        /// Names one operation that a proof drives on a raw backend probe.
        enum class BackendProbeOperation : std::uint8_t
        {
            Enable,
            Disable,
            Bypass,
            Resume,
            Vacate,
            Reset,
            MoveAssign,
            RetainRoute,
        };

        /// Reads one raw backend probe. A null address means absent.
        struct BackendProbeState
        {
            bool valid{false};
            bool enabled{false};
            bool claimed{false};
            bool bypassed{false};
            void *trampoline{nullptr};
            void *relay_slot{nullptr};
            void *relay_cell{nullptr};
        };

        /// One raw backend hook that a proof drives without a Hook handle.
        struct BackendProbe;

        /**
         * @brief Creates a disabled raw backend hook on @p target with the claim of @p position_name.
         * @param destination The detour, or a `void(safetyhook::Context &)` callback for a mid probe.
         * @return The probe, or nullptr when the backend refused.
         */
        [[nodiscard]] BackendProbe *create_backend_probe_for_test(
            BackendProbeKind kind,
            void *target,
            void *destination,
            std::string_view position_name
        ) noexcept;

        /// Drives @p operation on @p probe and reports the backend result.
        [[nodiscard]] bool drive_backend_probe_for_test(BackendProbe *probe, BackendProbeOperation operation) noexcept;

        /// Reads @p probe.
        [[nodiscard]] BackendProbeState backend_probe_state_for_test(const BackendProbe *probe) noexcept;

        /// Destroys @p probe through the backend destructor.
        void destroy_backend_probe_for_test(BackendProbe *probe) noexcept;

        /// Adds up to @p count one-byte filler records to the process route registry and returns the number added.
        [[nodiscard]] std::size_t fill_backend_coordinator_for_test(std::size_t count) noexcept;

        /// Removes every filler record that fill_backend_coordinator_for_test added.
        void clear_backend_coordinator_fill_for_test() noexcept;

        /// Names the point of a counted drain proof at which @ref g_counted_drain_probe runs.
        enum class CountedDrainStage : std::uint8_t
        {
            AfterFirstPass,
            BetweenCounterReads,
            AfterCounterReads,
        };

        /// Runs at each stage of every counted drain proof while it is not null.
        extern void (*g_counted_drain_probe)(CountedDrainStage) noexcept;

        /// The decoded thunk of a counted hook. Every address is null for a raw or disengaged hook.
        struct CountedThunkProbe
        {
            void *entry{nullptr};
            void *range_end{nullptr};
            void *enter_count{nullptr};
            void *after_exit_count{nullptr};
            std::size_t helper_calls{0};
            std::size_t counted_calls{0};
            std::size_t pushes{0};
            std::size_t pops{0};
        };

        /// Decodes the thunk of the counted hook behind @p hook.
        [[nodiscard]] CountedThunkProbe counted_thunk_for_test(const hook::Hook &hook) noexcept;
    } // namespace detail
#endif
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_HOOK_BACKEND_HPP
