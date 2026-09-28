#ifndef DETOURMODKIT_HOOK_HPP
#define DETOURMODKIT_HOOK_HPP

/**
 * @file hook.hpp
 * @brief The hooking surface: free verbs that return move-only RAII handles. It hides SafetyHook and Zydis.
 * @details @ref inline_at, @ref mid_at, and @ref install_all return a disabled hook, and `Hook::enable()` arms it
 *          (`[B-83]`). @ref vmt_for is live at creation.
 *
 *          Do not call a hook mutation from DllMain or from a thread that holds the loader lock. Every install, toggle,
 *          batch, VMT creation, and VMT mutation returns @ref ErrorCode::LoaderLockActive before its own object-gate,
 *          ledger, backend, allocation, or protection work. Argument construction at the call site stays the caller's.
 *          The Hook and VmtHook destructors retain unsafe state instead of a wait.
 *
 *          Participants are the DetourModKit copies in this process that share the process route coordinator in
 *          docs/design/hooking.md. They share backend patch order and route dependencies, and teardown must proceed
 *          newest-first across them. A coordinator refusal prevents mutation or retains the route. Foreign libraries
 *          outside that protocol receive no cross-instance lifetime guarantee.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/scan.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace DetourModKit
{
    namespace hook
    {
        /** @brief Opaque mid-hook register state. Never define it: the accessor casts need an incomplete type. */
        struct MidContext;

        /**
         * @brief DMK-owned mid-hook detour signature.
         * @warning The callback must not throw (`[B-84]`). DMK contains an exception that escapes, counts it, and logs
         *          once per site. DMK then treats the callback as complete, with the context as the callback left it.
         * @note The callback can re-enter the hooked target.
         * @warning A callback that destroys its own Hook retains the backend. See @ref Hook::~Hook.
         */
        using MidHookFn = void (*)(MidContext &);

        /** @brief Selects a general-purpose register other than rsp and rip for gpr() at a mid-hook site. */
        enum class Gpr : std::uint8_t
        {
            Rax,
            Rbx,
            Rcx,
            Rdx,
            Rsi,
            Rdi,
            Rbp,
            R8,
            R9,
            R10,
            R11,
            R12,
            R13,
            R14,
            R15
        };

        /** @brief Read-only by-value snapshot of one 128-bit XMM register captured at the mid-hook site. */
        struct alignas(16) XmmView
        {
            std::array<std::byte, 16> bytes;

            /**
             * @brief Returns the index-th T-sized lane of the captured bytes, or zero for an out-of-range lane.
             * @tparam T A scalar lane type. The constraint excludes `bool`, because a captured byte is not a valid
             *         `bool` object representation. MidContextXmmViewTest.LaneRejectsBoolAndAdmitsScalars pins the set.
             * @note Callback-safe: a pure read of the captured context.
             */
            template <typename T>
                requires(std::is_trivially_copyable_v<T> && !std::is_same_v<T, bool>)
            [[nodiscard]] T lane(std::size_t index) const noexcept
            {
                T value{};
                if (index >= bytes.size() / sizeof(T))
                {
                    return value;
                }
                std::memcpy(&value, bytes.data() + index * sizeof(T), sizeof(T));
                return value;
            }
        };

        static_assert(sizeof(void *) == 8, "MidContext register set is Windows x64 only");

        /**
         * @brief Returns a mutable reference to a captured general-purpose register. A write survives the resume.
         * @note Callback-safe: a pure read or write of the captured context.
         */
        [[nodiscard]] std::uintptr_t &gpr(MidContext &ctx, Gpr reg) noexcept;

        /**
         * @brief Returns the captured stack pointer (rsp) by value. To move the stack, use resume_stack_pointer().
         * @note Callback-safe: a pure read of the captured context.
         */
        [[nodiscard]] std::uintptr_t stack_pointer(const MidContext &ctx) noexcept;

        /**
         * @brief Returns a mutable reference to the stack pointer that the resumed original code runs on.
         * @note Callback-safe: a pure read or write of the captured context.
         */
        [[nodiscard]] std::uintptr_t &resume_stack_pointer(MidContext &ctx) noexcept;

        /**
         * @brief Returns a mutable reference to the captured instruction pointer (rip).
         * @details The resume lands at this value. Write the address of a same-signature function to resume there.
         * @note Callback-safe: a pure read or write of the captured context.
         */
        [[nodiscard]] std::uintptr_t &instruction_pointer(MidContext &ctx) noexcept;

        /**
         * @brief Returns a mutable reference to the captured rflags, which the trampoline restores on resume.
         * @note Callback-safe: a pure read or write of the captured context.
         */
        [[nodiscard]] std::uintptr_t &flags(MidContext &ctx) noexcept;

        /**
         * @brief Returns a snapshot of XMM register @p index (0 to 15), or a zeroed view for an out-of-range index.
         * @note Callback-safe: a pure read of the captured context.
         * @warning The mid-hook frame preserves only XMM0 to XMM15. A detour must not clobber YMM or ZMM upper state,
         *          ZMM16 to ZMM31, opmask registers, x87, MMX, or MXCSR state.
         */
        [[nodiscard]] XmmView xmm(const MidContext &ctx, std::size_t index) noexcept;

        /**
         * @brief Policy for a target whose first byte is 0xCC or 0xCD (int3 or int n) instead of a function body.
         * @details @ref Fail refuses the create with @ref ErrorCode::TargetPrologueUnsafe. @ref Relocate logs and
         *          installs anyway. The backend decode decides relocation, so a relative call passes this check. A
         *          backend refusal returns @ref ErrorCode::BackendFailed and logs the reason. Both policies refuse a
         *          target whose bytes are not readable, executable, committed memory.
         */
        enum class Prologue : std::uint8_t
        {
            Fail,
            Relocate
        };

        /**
         * @brief Per-row policy for a @ref HookSpec in @ref install_all.
         * @details A @ref Mandatory miss fails the call. A @ref BestEffort miss records its Error in the row outcome
         *          and skips the row.
         */
        enum class Severity : std::uint8_t
        {
            BestEffort,
            Mandatory
        };

        /** @brief Per-hook policy for @ref inline_at and @ref mid_at. */
        struct Options
        {
            /// The policy for a breakpoint first byte. See @ref Prologue.
            Prologue prologue = Prologue::Fail;

            /**
             * @brief Refuses the install when the target already appears hooked.
             * @details A same-kit hook in this instance's ledger returns @ref ErrorCode::TargetAlreadyHookedByThisKit.
             *          Otherwise a foreign jump over the prologue returns
             *          @ref ErrorCode::TargetAlreadyHookedByAnotherModule. The jump forms are E9 rel32, FF25 indirect,
             *          and `mov rax, imm64` then `jmp rax`. The default (false) layers the new hook on top.
             */
            bool fail_if_already_hooked = false;
        };

        namespace detail
        {
            /// Satisfied only by a pointer-to-function type, the valid cast target for Hook::original.
            template <typename T>
            concept FunctionPointer = std::is_pointer_v<T> && std::is_function_v<std::remove_pointer_t<T>>;
        } // namespace detail

        /// An absolute @ref Address, or a @ref scan::OwnedScanRequest that the install resolves through scan::resolve.
        using Target = std::variant<Address, scan::OwnedScanRequest>;

        /// A request to install one inline hook by @ref inline_at.
        struct InlineRequest
        {
            std::string name;
            Target target;
            Options options{};
        };

        /// A request to install one mid hook by @ref mid_at.
        struct MidRequest
        {
            std::string name;
            Target target;
            Options options{};
        };

        class Hook;

        namespace detail
        {
            /// The non-template inline-install primitive behind @ref inline_at.
            [[nodiscard]] Result<Hook> inline_at_raw(InlineRequest request, void *detour);
        } // namespace detail

#ifdef _MSC_VER
#pragma warning(push)
// The gate slot storage carries the slot's alignment, so the padding that C4324 reports is intended.
#pragma warning(disable : 4324)
#endif

        /**
         * @brief Move-only RAII handle for one inline or mid hook. The destructor restores the prologue.
         * @note If two hooks share one target, destroy the newer one first, or own them in a @ref HookStack. An
         *       inverted teardown retains the older backend, logs a warning, and keeps the newer trampoline chain.
         * @note Lock order: a toggle takes the per-hook call gate before the HookLedger target slot and releases them
         *       in reverse order. Logs and lifecycle events follow both releases.
         */
        class Hook
        {
        public:
            Hook(Hook &&other) noexcept;
            Hook &operator=(Hook &&other) noexcept;
            Hook(const Hook &) = delete;
            Hook &operator=(const Hook &) = delete;

            /**
             * @brief Restores the target when safe and reclaims an idle mid route.
             * @details Teardown frees the backend only over Original bytes. Foreign or unreadable bytes, the loader
             *          lock, a newer layer, an unproved restore, an unresolved continuation, or a nonlocal exit retains
             *          it. A backend retention at reset also retains it and logs the reason. A retained backend keeps
             *          its module reference for the process lifetime, and a mid backend also keeps its adapter and
             *          capacity charge. Teardown inside a displaced callee retains the backend without a route drain
             *          wait.
             *
             *          A retained patch keeps the target tracked as hooked, and `[B-73]` attributes each retention to
             *          @ref diagnostics::LeakSubsystem::HookManager. A mid hook tombstones its callback before `[B-85]`
             *          rundown, so no new callback begins after destruction returns. Mid teardown waits a bounded time
             *          for admitted callbacks and adapter bodies. The loader lock, a published unload phase,
             *          self-destruction, or an unrecorded entrant prevents that wait. An expired or prevented wait
             *          retains the backend, and an admitted callback can still run after destruction returns.
             * @warning Inline hook quiescence is caller-owned. See @ref inline_at.
             * @note Setup/control-plane only: teardown mutates the target and can wait for callbacks and continuations.
             */
            ~Hook() noexcept;

            /// True while this handle owns a live hook (false for a moved-from or released handle).
            [[nodiscard]] explicit operator bool() const noexcept;

            /// The hook's registered name (empty for a moved-from or released handle).
            [[nodiscard]] std::string_view name() const noexcept;

            /**
             * @brief True when the hook is armed or conservatively retained as possibly reachable.
             * @details It reads the published state and backend flag, not target bytes, and never repairs drift. A
             *          toggle that reads Foreign or unreadable bytes after a committed restore keeps it true, because a
             *          newer layer can still reach the trampoline. A toggle that reads Original bytes after the restore
             *          makes it false.
             * @note Setup/control-plane only: it waits on the per-hook call gate for an in-flight call or toggle.
             */
            [[nodiscard]] bool is_enabled() const noexcept;

            /**
             * @brief Returns the unguarded typed trampoline of an inline hook. If teardown can race, use @ref call.
             * @return The trampoline, or nullptr for a mid hook, a disengaged handle, or a backend miss.
             * @note Callback-safe: one indirection, with no lock. The caller must keep the hook alive across the call.
             */
            template <detail::FunctionPointer Fn> [[nodiscard]] Fn original() const noexcept
            {
                return reinterpret_cast<Fn>(original_address());
            }

            /**
             * @brief Calls the original of an inline hook through the trampoline under the per-hook call gate.
             * @tparam Args The exact by-value parameter types of the original, because a deduced reference rebuilds the
             *         wrong function-pointer ABI. A move-constructible argument moves into the dispatch.
             * @return The original's return value, or a value-initialized Ret when the hook is inactive or not inline.
             * @details Teardown can race the call: a late call fails closed, and an in-flight call drains before
             *          teardown frees backend storage. The Hook object's storage must outlive the call. The gate does
             *          not drain a thread that entered the original by another path.
             * @note Callback-safe: the atomic gate pin is bounded, and no allocation or I/O precedes dispatch.
             * @warning Concurrent calls through one handle serialize on the recursive gate mutex for the full call.
             *          For a hot target on several threads, use @ref original.
             */
            template <typename Ret = void, typename... Args> Ret call(Args... args) const
            {
                // GuardedDispatch pins the gate and holds its lock through this invocation.
                const GuardedDispatch dispatch{*this};
                if (dispatch.trampoline == nullptr)
                {
                    if constexpr (!std::is_void_v<Ret>)
                    {
                        return Ret{};
                    }
                    else
                    {
                        return;
                    }
                }
                return reinterpret_cast<Ret (*)(Args...)>(dispatch.trampoline)(forward_call_argument<Args>(args)...);
            }

            /**
             * @brief Works as @ref call, but reports a refused dispatch as an error instead of a value-initialized Ret.
             * @return The original's return value, or InvalidHookState when the gate refuses dispatch.
             * @note Callback-safe on the same terms as @ref call.
             */
            template <typename Ret = void, typename... Args> [[nodiscard]] Result<Ret> try_call(Args... args) const
            {
                const GuardedDispatch dispatch{*this};
                if (dispatch.trampoline == nullptr)
                {
                    return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::try_call"});
                }
                if constexpr (std::is_void_v<Ret>)
                {
                    reinterpret_cast<void (*)(Args...)>(dispatch.trampoline)(forward_call_argument<Args>(args)...);
                    return {};
                }
                else
                {
                    return reinterpret_cast<Ret (*)(Args...)>(dispatch.trampoline)(
                        forward_call_argument<Args>(args)...
                    );
                }
            }

            /**
             * @brief Arms the hook: patches the target so that the detour runs.
             * @return Success when the hook is active. Otherwise LoaderLockActive, LayerConflict, BackendFailed,
             *         EnableFailed, DisableFailed, or InvalidHookState.
             * @details The target bytes decide the published state (`[B-97]`), and Foreign or unreadable bytes after a
             *          committed arm keep the hook Active. Foreign or unreadable bytes before the write refuse with
             *          EnableFailed and write nothing. If the hook claims Active over Original bytes, the call first
             *          reconciles it to Disabled. EnableFailed means that this call published no new arm. A byte
             *          refusal keeps the prior state and bytes, and any other EnableFailed leaves the hook Disabled.
             *          BackendFailed means that the hook is active, but page protection can stay unrestored.
             * @warning DisableFailed means that this call did not prove a disarm after a rejected or uncertain arm. The
             *          handle stays active, so quiesce or disable it before teardown.
             * @note Only the target's newest live layer can arm it (`[B-16]`). LayerConflict writes no bytes and keeps
             *       the hook's state, but a coordinator refusal after the reconciliation leaves it Disabled. A lower
             *       local layer gets LayerConflict even when it is already armed. Arm the base hook before you create
             *       the one above it. Under another participant's newer layer, the arm returns LayerConflict, or
             *       EnableFailed when that armed patch fails the byte witness first.
             * @note Idempotent and thread-safe. Publish everything the detour needs before this call (`[B-83]`).
             * @note Setup/control-plane only: the arm patches the target and serializes on the per-hook call gate.
             */
            [[nodiscard]] Result<void> enable() noexcept;

            /**
             * @brief Disarms the hook but leaves it installed.
             * @return Success when the hook is disabled. Otherwise LoaderLockActive, LayerConflict, BackendFailed,
             *         DisableFailed, or InvalidHookState.
             * @details As in @ref enable, the target bytes decide the state (`[B-97]`), and Disabled publishes only
             *          once Original bytes read back. Any other bytes after the restore keep the hook Active, so a
             *          retry can disarm after this hook's exact patch bytes return. Foreign or unreadable bytes before
             *          the write refuse with DisableFailed and keep the prior state and bytes, and teardown then
             *          retains the backend. If the hook claims Disabled over its exact patch bytes, the call first
             *          reconciles it to Active and retries the restore. DisableFailed means that this call did not
             *          prove a disarm, and except for that byte refusal, it leaves the hook Active. BackendFailed means
             *          that the disarm took effect, but page protection can stay unrestored.
             * @note Only the target's newest live layer can disarm it, even when it is already disabled (`[B-16]`).
             *       Disable or destroy the newer layer first. After LayerConflict, an armed lower layer stays armed and
             *       @ref is_enabled reports true. Under another participant's newer layer, the disarm returns
             *       LayerConflict, or DisableFailed when that armed patch fails the byte witness first.
             * @note Setup/control-plane only: the disarm restores the target and serializes on the per-hook call gate.
             */
            [[nodiscard]] Result<void> disable() noexcept;

            /**
             * @brief Detaches the hook from this handle. The hook keeps its state, backend, and ledger record for the
             *        process lifetime.
             * @note @ref diagnostics::total_intentional_leaks counts the release. @ref is_target_hooked still reports
             *       the target, and an install with @ref Options::fail_if_already_hooked stays refused. A layer under
             *       this one can no longer write bytes and gets the @ref enable and @ref disable codes. A layer
             *       installed after it tears down normally.
             * @note Setup/control-plane only.
             * @warning The detour and everything it reaches must stay mapped for the rest of the process.
             */
            void release() noexcept;

        private:
            struct Impl;

            template <typename Arg>
            [[nodiscard]] static decltype(auto) forward_call_argument(std::remove_reference_t<Arg> &arg) noexcept
            {
                if constexpr (!std::is_reference_v<Arg> && !std::is_move_constructible_v<Arg>)
                {
                    return (arg);
                }
                else
                {
                    return std::forward<Arg>(arg);
                }
            }

            /// The refcounted call guard in src/internal/hook_backend.hpp. A call pins it, so teardown cannot free it.
            struct CallGate;
            Hook(std::unique_ptr<Impl> impl, std::shared_ptr<CallGate> gate) noexcept;

            /// The raw inline trampoline or nullptr, without a guard, behind original<Fn>().
            [[nodiscard]] void *original_address() const noexcept;

            /// Copies the atomic call-gate reference into a strong local for @ref call to pin.
            [[nodiscard]] std::shared_ptr<CallGate> pin_call_gate() const noexcept;

            /// Locks the gate's recursive_mutex for @ref call. A lock failure returns an unowned lock.
            [[nodiscard]] std::unique_lock<std::recursive_mutex> acquire_call_lock(CallGate *gate) const noexcept;

            /// The gate's published trampoline, or nullptr when inactive. Read it with the call lock held.
            [[nodiscard]] void *active_trampoline(CallGate *gate) const noexcept;

            /** @brief Pins, locks, and snapshots the call gate. A failed stage leaves @ref trampoline null. */
            struct GuardedDispatch
            {
                explicit GuardedDispatch(const Hook &hook)
                {
                    gate = hook.pin_call_gate();
                    if (!gate)
                        return;
                    guard = hook.acquire_call_lock(gate.get());
                    if (!guard.owns_lock())
                        return;
                    trampoline = hook.active_trampoline(gate.get());
                }

                std::shared_ptr<CallGate> gate;
                std::unique_lock<std::recursive_mutex> guard;
                /// The live trampoline to dispatch through, or nullptr when any gate stage failed closed.
                void *trampoline = nullptr;
            };

            std::unique_ptr<Impl> m_impl;

            /// The atomic holder of the shared call gate. @ref call pins it, so a teardown or move cannot race it.
            using GateSlot = std::atomic<std::shared_ptr<CallGate>>;

            /**
             * @brief Never-destroyed gate slot storage (`[B-47]`), so a @ref call that races ~Hook reads a valid null
             *        slot. HookConcurrency.CallRacesDestructorOnRetainedStorage pins the race.
             */
            alignas(GateSlot) unsigned char m_gate_storage[sizeof(GateSlot)]{};

            [[nodiscard]] GateSlot &gate_slot() noexcept;
            [[nodiscard]] const GateSlot &gate_slot() const noexcept;

            friend Result<Hook> mid_at(MidRequest request, MidHookFn detour);
            friend Result<Hook> detail::inline_at_raw(InlineRequest request, void *detour);
        };

#ifdef _MSC_VER
#pragma warning(pop)
#endif

        /**
         * @brief Move-only owner of Hook handles that tears them down newest-first (`[B-16]`).
         * @details A `std::vector<Hook>` does not guarantee that order. Use HookStack for hooks layered on one target.
         * @note HookStack has no internal synchronization. Build it and tear it down on the setup thread.
         */
        class HookStack
        {
        public:
            /**
             * @brief Constructs an empty hook stack.
             * @note Setup/control-plane only.
             */
            HookStack() noexcept = default;

            /**
             * @brief Adopts the hooks of @p other without a teardown.
             * @note Setup/control-plane only.
             */
            HookStack(HookStack &&other) noexcept : m_hooks(std::move(other.m_hooks)) { other.m_hooks.clear(); }

            /**
             * @brief Tears down this stack's hooks newest-first, then adopts the hooks of @p other and leaves it empty.
             * @note Setup/control-plane only.
             */
            HookStack &operator=(HookStack &&other) noexcept
            {
                if (this != &other)
                {
                    teardown_newest_first();
                    m_hooks = std::move(other.m_hooks);
                    other.m_hooks.clear();
                }
                return *this;
            }

            HookStack(const HookStack &) = delete;
            HookStack &operator=(const HookStack &) = delete;

            /**
             * @brief Restores every owned hook newest-first.
             * @note Setup/control-plane only: destroy it after the detours and workers that use its hooks quiesce.
             * @note The destructor can run from loader-lock teardown, where every ~Hook fails closed.
             */
            ~HookStack() noexcept { teardown_newest_first(); }

            /**
             * @brief Moves @p hook onto the top of the stack. Push order is layer order, so push the base hook first.
             * @return The stored @ref Hook, valid until the next @ref push, @ref reserve, @ref clear, or move.
             * @throws std::bad_alloc If storage growth fails. The stack then destroys @p hook, which restores its
             *         prologue, and keeps the stored hooks.
             * @note Setup/control-plane only: the push can allocate.
             */
            Hook &push(Hook hook)
            {
                m_hooks.push_back(std::move(hook));
                return m_hooks.back();
            }

            /**
             * @brief Reserves storage for @p capacity hooks, so a batch of @ref push calls does not reallocate.
             * @note Setup/control-plane only: the reserve can allocate.
             */
            void reserve(std::size_t capacity) { m_hooks.reserve(capacity); }

            /**
             * @brief Returns the number of owned hooks.
             * @note Callback-safe while no thread mutates or destroys this stack.
             */
            [[nodiscard]] std::size_t size() const noexcept { return m_hooks.size(); }

            /**
             * @brief Reports whether the stack owns no hooks.
             * @note Callback-safe while no thread mutates or destroys this stack.
             */
            [[nodiscard]] bool empty() const noexcept { return m_hooks.empty(); }

            /**
             * @brief Tears down every owned hook newest-first and keeps the capacity.
             * @note Setup/control-plane only.
             */
            void clear() noexcept { teardown_newest_first(); }

        private:
            /// Destroys the owned hooks back to front, newest layer first.
            void teardown_newest_first() noexcept
            {
                while (!m_hooks.empty())
                {
                    m_hooks.pop_back();
                }
            }

            std::vector<Hook> m_hooks;
        };

        /**
         * @brief Installs a disabled inline hook at the request's target. Call @ref Hook::enable to arm it.
         * @return The @ref Hook with the target unpatched, or an Error. This call reports every install failure,
         *         including a scan miss for a deferred target.
         * @warning The detour must not throw. The patched target calls it directly, so an exception that escapes
         *          terminates the host.
         * @warning Unlike @ref mid_at, quiescence before teardown is caller-owned: DMK cannot wait for a thread inside
         *          the detour. Prove that no thread can execute the detour before the handle dies.
         * @warning For a Logic DLL detour, stop and join every thread that can reach the target. Then destroy the
         *          handle. Then unmap the provider. DMK cannot detect another order.
         * @note Setup/control-plane only: the install allocates the trampoline and validates the target.
         */
        template <class Fn> [[nodiscard]] Result<Hook> inline_at(InlineRequest request, Fn *detour)
        {
            static_assert(sizeof(Fn *) == sizeof(void *), "function pointer must be word-sized");
            return detail::inline_at_raw(std::move(request), reinterpret_cast<void *>(detour));
        }

        /**
         * @brief Installs a disabled mid-function hook at the request's target. Call @ref Hook::enable to arm it.
         * @return The @ref Hook with the target unpatched, or an Error. @ref ErrorCode::MidHookCapacityExhausted means
         *         that every mid-hook adapter is in use and the call patched nothing.
         * @details DMK owns callback exception containment and rundown. @ref Hook::~Hook owns the retention rules.
         * @note Each hook holds one adapter from a fixed pool until clean teardown. Displaced instructions and their
         *       callees own the route until an ordinary exit completes, so dormant fibers and unresolved exception
         *       continuations retain it at teardown. Exception unwind or a nonlocal exit can abandon ownership and
         *       cause permanent retention.
         * @note After a displaced call, an instruction with RSP as an explicit destination is unsupported, except ADD
         *       of a nonnegative immediate. Creation then fails before publication with @ref ErrorCode::BackendFailed.
         * @warning Before teardown, quiesce saved contexts outside the counted displaced execution. These contexts
         *          include entry and exit gaps, copied contexts, and later reuse of a captured instruction pointer. If
         *          quiescence is unproved, keep the Hook and its code providers alive.
         * @warning A retained route does not authorize provider unload. Every admitted callback and continuation needs
         *          its code providers until it exits. @ref Hook::release also keeps callback dispatch active.
         * @note Setup/control-plane only: the install claims an adapter and builds the routed chain.
         */
        [[nodiscard]] Result<Hook> mid_at(MidRequest request, MidHookFn detour);

        struct InstallOutcome;

        /// Internal tag that carries the function-to-void* cast of an inline @ref HookSpec.
        struct InlineDetour
        {
            void *fn = nullptr;
        };

        /** @brief One row of an @ref install_all table. The @ref inline_hook and @ref mid_hook factories build it. */
        class HookSpec
        {
        public:
            /**
             * @brief Builds an inline-hook row. See @ref Severity and @ref Options for the row policy.
             * @note Setup/control-plane only: the row can allocate through @p name and @p target.
             */
            template <class Fn>
            [[nodiscard]] static HookSpec inline_hook(
                std::string name,
                scan::OwnedScanRequest target,
                Fn *detour,
                Severity severity = Severity::Mandatory,
                Options options = {}
            )
            {
                static_assert(sizeof(Fn *) == sizeof(void *), "function pointer must be word-sized");
                return HookSpec{
                    std::move(name),
                    std::move(target),
                    InlineDetour{reinterpret_cast<void *>(detour)},
                    severity,
                    options
                };
            }

            /**
             * @brief Builds a mid-hook row. See @ref Severity and @ref Options for the row policy.
             * @note Setup/control-plane only: the row can allocate through @p name and @p target.
             */
            [[nodiscard]] static HookSpec mid_hook(
                std::string name,
                scan::OwnedScanRequest target,
                MidHookFn detour,
                Severity severity = Severity::Mandatory,
                Options options = {}
            )
            {
                return HookSpec{std::move(name), std::move(target), detour, severity, options};
            }

            /// Returns the row name forwarded to the eventual install request.
            [[nodiscard]] std::string_view name() const noexcept { return m_name; }
            /// Returns whether this row is mandatory or best-effort.
            [[nodiscard]] Severity severity() const noexcept { return m_severity; }
            /// Returns the per-row install policy applied by @ref install_all.
            [[nodiscard]] const Options &options() const noexcept { return m_options; }

        private:
            HookSpec(
                std::string name,
                scan::OwnedScanRequest target,
                std::variant<InlineDetour, MidHookFn> detour,
                Severity severity,
                Options options
            ) noexcept
                : m_name(std::move(name)), m_target(std::move(target)), m_detour(std::move(detour)),
                  m_severity(severity), m_options(options)
            {
            }

            std::string m_name;
            scan::OwnedScanRequest m_target;
            /// The active alternative selects an inline or a mid hook.
            std::variant<InlineDetour, MidHookFn> m_detour;
            Severity m_severity;
            /// Per-row install policy applied verbatim by @ref install_all.
            Options m_options;

            friend Result<std::vector<InstallOutcome>> install_all(std::span<const HookSpec> table) noexcept;
        };

        /**
         * @brief Per-row result of @ref install_all, in table order.
         * @warning A `std::vector<InstallOutcome>` does not guarantee newest-first destruction (`[B-16]`). Move the
         *          successful hooks into a @ref HookStack in table order.
         */
        struct InstallOutcome
        {
            std::string name;
            Severity severity;
            /// The installed Hook, or an Error such as NoMatch when @ref install_all skipped the row.
            Result<Hook> hook;
        };

        /**
         * @brief Installs a table of disabled hooks and returns one outcome per row.
         * @return The per-row outcomes. LoaderLockActive fails before any row. The first @ref Severity::Mandatory miss
         *         fails the outer Result. An allocation failure that no row reports fails it with OutOfMemory, and any
         *         other escaped exception fails it with UnknownError.
         * @details Every row stays disabled until the call returns, so a rollback has no live hook to disarm. Every
         *          outer failure removes the installed rows newest-first. To arm a row, call @ref Hook::enable on it
         *          after you take ownership of the outcomes.
         * @warning See the @ref InstallOutcome teardown-order warning.
         * @note Setup/control-plane only: the batch resolves scans and allocates per row.
         */
        [[nodiscard]] Result<std::vector<InstallOutcome>> install_all(std::span<const HookSpec> table) noexcept;

        /**
         * @brief Reports whether a hook from this DMK instance owns @p target, or an install in progress reserved it.
         * @details The query reads this instance's ledger only, so it does not see foreign hooks or other DMK copies.
         *          To also refuse foreign hooks, set @ref Options::fail_if_already_hooked on the install.
         * @note Setup/control-plane only: the query takes the ledger mutex that installs and teardowns contend on.
         */
        [[nodiscard]] bool is_target_hooked(Address target) noexcept;

        /** @brief Policy for @ref vmt_for and @ref VmtHook::apply_to. */
        struct VmtOptions
        {
            /**
             * @brief Refuses to clone or apply onto an object whose vptr already points at a clone from this kit.
             * @details A clone of a clone treats the hooked methods of the first clone as its originals.
             */
            bool fail_if_already_hooked = false;

            /**
             * @brief Decodes the first byte of the original vtable slot and refuses a slot that is not a function body.
             * @details The pre-flight refuses a 0xCC or 0xCD breakpoint pad, a 0x00 byte, and a bare RET (0xC2 or
             *          0xC3). It also refuses a same-module `jmp rel8/rel32` stub such as an incremental-link ILT
             *          entry, and a jump whose slot or target lies in no module. MSVC adjustor thunks pass. Known false
             *          positives: a /INCREMENTAL consumer routes every function through an ILT stub, and an empty
             *          virtual body can compile to a bare RET.
             */
            bool fail_on_non_function_pointer = false;
        };

        class VmtHook;

        /**
         * @brief Clones the vtable of @p object, swaps @p object onto the clone, and returns the @ref VmtHook.
         * @return The @ref VmtHook, or LoaderLockActive, InvalidArg, InvalidObject, HookAlreadyExists, BackendFailed,
         *         OutOfMemory, SystemCallFailed, or UnknownError. InvalidObject covers an unreadable vtable or RTTI
         *         header prefix. It also covers an unreadable, non-writable, unaligned, unmapped, reprotected, or
         *         displaced object word.
         * @warning Clone during setup or a host-quiesced window.
         * @note Setup/control-plane only: the clone allocates and mutates the vptr of @p object.
         */
        [[nodiscard]] Result<VmtHook> vmt_for(std::string name, void *object, VmtOptions options = {});

        /**
         * @brief Move-only RAII handle for a cloned vtable applied to one or more live objects.
         * @details A @ref hook_method call affects every object on the clone.
         * @warning Quiesce virtual dispatch across create, apply, and remove. Keep every applied object alive through
         *          removal. Guarded vptr access contains faults but is not an ownership protocol.
         * @note An object gate serializes the vptr transitions of @ref vmt_for, @ref apply_to, @ref remove_from, and
         *       teardown, so each duplicate check and swap is one ordered operation. @ref original reads its slot under
         *       a shared lock and never sees a torn mutation.
         */
        class VmtHook
        {
        public:
            VmtHook(VmtHook &&other) noexcept;
            VmtHook &operator=(VmtHook &&other) noexcept;
            VmtHook(const VmtHook &) = delete;
            VmtHook &operator=(const VmtHook &) = delete;

            /**
             * @brief Restores each applied object's original vptr, unless the handle is released, moved, or outranked.
             * @details Each object follows the @ref remove_from rules. An unresolved dependency then retains the clone.
             *          @ref diagnostics::LeakSubsystem::HookManager counts it, and the log names the hook. Destroy VMT
             *          hooks newest-first to get the original table back.
             * @note Setup/control-plane only: quiesce virtual dispatch first.
             */
            ~VmtHook() noexcept;

            /// True while this handle owns a live cloned vtable (false for a moved-from or released handle).
            [[nodiscard]] explicit operator bool() const noexcept;

            /// The hook's registered name (empty for a moved-from or released handle).
            [[nodiscard]] std::string_view name() const noexcept;

            /**
             * @brief Swaps @p object onto the cloned vtable.
             * @return Success, or LoaderLockActive, InvalidHookState, InvalidObject, HookAlreadyExists, OutOfMemory, or
             *         UnknownError. InvalidObject covers an unreadable, non-writable, or unaligned object word, and a
             *         protection change, displacement, or unmap before publication. Under any @p options,
             *         HookAlreadyExists also means that this handle cannot name the vptr that it displaces. That covers
             *         an object that carries this clone but that this handle never applied, or that moved off its
             *         recorded vptr. A repeat apply of a tracked, published object succeeds as a no-op.
             * @warning Apply only while @p object is host-quiesced. The atomic vptr swap does not synchronize dispatch.
             * @note Setup/control-plane only: the apply mutates the vptr under the exclusive object gate.
             */
            [[nodiscard]] Result<void> apply_to(void *object, VmtOptions options = {});

            /**
             * @brief Restores the original vptr on one applied object.
             * @return Success, or LoaderLockActive, InvalidObject for a null @p object, InvalidHookState for a
             *         disengaged handle, or UnknownError when the exclusive object gate is unavailable.
             * @details Success does not mean that a restore happened. An untracked object is a no-op. A tracked object
             *          releases its binding only once its word reads as the recorded original. A writable object on
             *          this clone swaps back unless a protection change or unmap defeats the swap. An object already at
             *          the original needs no write and releases its binding, even when its word is not writable. Any
             *          other or unreadable value stays unchanged and keeps the dependency, because a successor can
             *          still restore an object to this clone.
             * @warning Quiesce @p object before the restore. Fault containment does not drain in-flight dispatch.
             * @note Setup/control-plane only: the restore mutates the vptr under the exclusive object gate.
             */
            [[nodiscard]] Result<void> remove_from(void *object);

            /**
             * @brief Points the cloned vtable slot at @p index to @p detour.
             * @param index The zero-based index among virtual methods, in declaration order. The ABI vtable header
             *        (Itanium offset-to-top and RTTI, or the MSVC RTTI locator) is not part of the index.
             * @param detour Its ABI must match the method's true signature, with the object pointer as the first
             *        integer argument (`this` in rcx). DMK cannot validate the signature, and a mismatch silently
             *        corrupts the ABI.
             * @return Success, or LoaderLockActive, InvalidHookState for a disengaged handle, InvalidArg for a null
             *         @p detour or an out-of-range @p index, MethodAlreadyHooked for an occupied index, BackendFailed,
             *         or OutOfMemory.
             * @warning The detour must not throw (`[B-84]`). The slot calls it directly, so no DMK frame contains an
             *          exception, and an exception that escapes terminates the host.
             * @note Setup/control-plane only: the call mutates the clone under the exclusive write lock. Install all
             *       method hooks during setup. Do not call it from a detour while another thread reads this handle.
             */
            template <detail::FunctionPointer Fn> [[nodiscard]] Result<void> hook_method(std::size_t index, Fn detour)
            {
                static_assert(sizeof(Fn) == sizeof(void *), "function pointer must be word-sized");
                return hook_method_raw(index, reinterpret_cast<void *>(detour));
            }

            /**
             * @brief Returns the pre-hook function of the method at @p index, typed as Fn.
             * @tparam Fn The full function-pointer type, with the object pointer as the first parameter.
             * @return The original, or nullptr for an unhooked @p index or a disengaged handle. The pointer stays valid
             *         for the hook's lifetime, and a call through it takes no lock. Keep the hook alive for the call.
             * @note Callback-safe: the read is a shared-lock snapshot copy.
             */
            template <detail::FunctionPointer Fn> [[nodiscard]] Fn original(std::size_t index) const noexcept
            {
                return reinterpret_cast<Fn>(method_original_address(index));
            }

            /**
             * @brief Restores the cloned vtable slot at @p index to the original method.
             * @return Success, or LoaderLockActive, InvalidHookState for a disengaged handle, or MethodNotFound when
             *         @p index has no hook on this handle.
             * @note Setup/control-plane only: the restore is a bare pointer write under the exclusive write lock. It
             *       does not protect an in-flight dispatch through the slot. Quiesce the method first.
             */
            [[nodiscard]] Result<void> remove_method(std::size_t index);

            /**
             * @brief Retains the clone for the process lifetime without a vptr restore, and disengages the handle.
             * @note @ref diagnostics::total_intentional_leaks counts the release. The clone stays recorded, so
             *       @ref VmtOptions::fail_if_already_hooked still recognizes it.
             * @note Setup/control-plane only.
             * @warning Applied objects keep the clone. Each method detour and its callees must stay mapped until
             *          process exit. DMK holds a module reference on its own module, not on the detour provider, so a
             *          Logic DLL detour needs that DLL to stay loaded.
             */
            void release() noexcept;

        private:
            struct Impl;
            explicit VmtHook(std::unique_ptr<Impl> impl) noexcept;

            /// The non-template method-install primitive behind @ref hook_method.
            [[nodiscard]] Result<void> hook_method_raw(std::size_t index, void *detour);

            /// Copies the original slot for @p index under the shared lock, or returns nullptr (see @ref original).
            [[nodiscard]] void *method_original_address(std::size_t index) const noexcept;

            std::unique_ptr<Impl> m_impl;

            friend Result<VmtHook> vmt_for(std::string name, void *object, VmtOptions options);
        };
    } // namespace hook
} // namespace DetourModKit

#endif // DETOURMODKIT_HOOK_HPP
