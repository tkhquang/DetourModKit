#ifndef DETOURMODKIT_HOOK_HPP
#define DETOURMODKIT_HOOK_HPP

/**
 * @file hook.hpp
 * @brief The hooking surface: free verbs returning move-only RAII handles, with the SafetyHook backend hidden.
 * @details Three free verbs -- `inline_at`, `mid_at`, and the declarative `install_all` -- each return a move-only
 *          RAII `Hook` whose destructor restores the prologue, so a hook's lifetime is bound to the handle the caller
 *          holds rather than to a hidden registry. Everything that operates on one hook (enable / disable / the typed
 *          trampoline) is a handle method.
 *
 *          Install is a two-step transaction: every verb returns a hook whose target is NOT yet patched, and
 *          `Hook::enable()` arms it. A detour reaches the original through the very handle the verb has not returned
 *          yet, so arming inside the verb would expose a window where the detour is reachable and the handle it needs
 *          does not exist. Publish the handle where the detour can see it, then enable.
 *
 *          Inline and mid hooks divide callback responsibility differently, and the split is not cosmetic. A mid-hook
 *          callback is reached through a DMK frame, so DMK contains its exceptions and runs it down on teardown. An
 *          inline detour REPLACES the target and runs with DMK nowhere in the call path, so it must not throw and its
 *          quiescence is the caller's. See `mid_at` and `inline_at`.
 *
 *          Backend confinement: SafetyHook (and the Zydis decoder it drags in) is named only in src/hook.cpp and the
 *          internal backend headers; a translation unit that includes only this header pulls in neither. The mid-hook
 *          register file is reached through free accessor functions over an opaque `MidContext`, never by mirroring the
 *          backend's context layout in a public header.
 *
 *          A small per-instance ledger (src/internal/hook_ledger.hpp -- not a public registry, no name lookup, no
 *          introspection) backs two safety properties that need shared state once hooks are owned by handles rather
 *          than a central registry: exact same-kit duplicate detection for `Options::fail_if_already_hooked`, and
 *          layer-order tracking for hooks stacked on one target address. Only the newest live layer on a target may
 *          alter its bytes: a lower layer's enable/disable is refused with `ErrorCode::LayerConflict`, and a lower
 *          layer's destructor leaks its backend rather than restoring over a newer trampoline.
 *
 *          LEDGER SCOPE: one ledger per linked DetourModKit instance, NOT per process. DetourModKit is a static
 *          archive, so two DLLs that each link it have two independent ledgers. Duplicate detection, layering and
 *          teardown ordering are therefore exact within one linked instance and blind across instances: a hook another
 *          separately-linked kit placed on the same target is absent from this ledger.
 *          `Options::fail_if_already_hooked` covers part of that blind spot without the ledger, by decoding the
 *          target's actual prologue for a foreign JMP; nothing recovers layer ORDER across instances, so
 *          cross-instance stacking has no defined teardown order.
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
        /**
         * @struct MidContext
         * @brief Opaque handle for the CPU register state captured at a mid-hook site.
         * @details Deliberately left INCOMPLETE: it is never defined in any translation unit. At the hook point the
         *          backend hands the detour a backend-context reference, and DMK reinterpret_casts that reference to
         *          MidContext& (and back, inside the accessors in src/hook.cpp). Because MidContext is only ever a
         *          pass-through alias for the live backend context, that cast is well-defined ONLY while the type
         *          stays incomplete; a CI grep gate forbids any `struct/class MidContext { ... }` definition so a
         *          future edit cannot silently turn the reinterpret_cast into undefined behaviour.
         */
        struct MidContext;

        /**
         * @brief DMK-owned mid-hook detour signature.
         * @details Names only DMK types, so writing a detour pulls in neither SafetyHook nor Zydis.
         * @warning MUST NOT THROW. DMK reaches the callback from its own adapter frame and contains any exception that
         *          escapes, because the generated stub the callback returns into carries no unwind data and an
         *          escaping throw would terminate the host. A contained escape is counted, logged once per site, and
         *          the callback treated as complete with the captured context left as the callback last set it.
         *          Containment is a safety net for a bug, not a contract to program against. The type is not
         *          `noexcept` because requiring it would reject every existing detour; the rule is documented rather
         *          than compiler-enforced.
         * @note Re-entering the hooked target from inside the callback is supported.
         * @warning Destroying the callback's own Hook from inside it is permitted but pins the backend; see @ref Hook.
         */
        using MidHookFn = void (*)(MidContext &);

        /**
         * @enum Gpr
         * @brief Selects a general-purpose register for gpr() read/write access at a mid-hook site.
         * @details rsp and rip are intentionally absent from this set. rsp is read-only at the capture point (the
         *          backend documents that writing it has no effect; query it with stack_pointer() and rewrite the
         *          resume stack with resume_stack_pointer()), and rip is control flow with its own writable accessor
         *          instruction_pointer(). Everything here is a plain integer register the detour may both read and
         *          overwrite, and the overwrite survives the trampoline resume.
         */
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

        /**
         * @struct XmmView
         * @brief Read-only by-value snapshot of one 128-bit XMM register captured at the mid-hook site.
         * @details XMM state is surfaced read-only: the backend's XMM fields are writable, but a detour that only
         *          needs to read a captured vector argument should not be handed a mutable reference into the live
         *          context, so DMK copies the 16 bytes out by value. A writable `xmm_ref()` accessor is the natural
         *          extension point should an in-place XMM write ever be required. lane<T>(index) reinterprets the
         *          captured bytes as the caller's lane type (e.g.
         *          lane<float>(0) for the first single-precision lane), mirroring the union-of-lanes shape of the
         *          underlying register without naming the backend's union.
         */
        struct alignas(16) XmmView
        {
            std::array<std::byte, 16> bytes;

            /**
             * @brief Reinterprets the captured bytes as the index-th T-sized lane; an out-of-range lane returns zero.
             * @tparam T A trivially-copyable scalar lane type (float, double, an integer). memcpy-ing the raw register
             *         bytes into a non-trivially-copyable T would be undefined behaviour, so the type is constrained.
             * @note Callback-safe: a pure read over the captured context, no allocation, locking, or I/O.
             */
            template <typename T> [[nodiscard]] T lane(std::size_t index) const noexcept
            {
                static_assert(std::is_trivially_copyable_v<T>,
                              "XmmView::lane<T> requires a trivially-copyable lane type");
                T value{};
                // Fail closed on an out-of-range lane: a bad index must not read past the 16-byte register.
                if (index >= bytes.size() / sizeof(T))
                {
                    return value;
                }
                std::memcpy(&value, bytes.data() + index * sizeof(T), sizeof(T));
                return value;
            }
        };

        // The mid-hook register set mirrors the Win64 capture context one-to-one; the accessors below reinterpret an
        // opaque MidContext& as that 64-bit layout, so they are meaningful only on Windows x64.
        static_assert(sizeof(void *) == 8, "MidContext register set is Windows x64 only");

        /**
         * @brief Returns a mutable reference to a captured general-purpose register.
         * @details Reading observes the live argument/scratch register at the hook point; writing overwrites it and
         *          the new value survives the trampoline resume. Defined in src/hook.cpp, the only TU that sees the
         *          backend; it reinterpret_casts the opaque MidContext& back to the real captured-context reference.
         * @note Callback-safe: a pure register read/write over the captured context, no allocation, locking, or I/O.
         */
        [[nodiscard]] std::uintptr_t &gpr(MidContext &ctx, Gpr reg) noexcept;

        /**
         * @brief Returns the captured stack pointer (rsp); read-only by backend contract, modifying it has no effect.
         * @note Callback-safe: a pure register read over the captured context, no allocation, locking, or I/O.
         */
        [[nodiscard]] std::uintptr_t stack_pointer(const MidContext &ctx) noexcept;

        /**
         * @brief Returns a mutable reference to the captured resume stack pointer (the backend's trampoline_rsp).
         * @details Unlike rsp (read-only, see stack_pointer), this is the stack pointer the trampoline restores when
         *          it resumes the original code, so writing it relocates the stack the resumed body runs on -- the
         *          accessor a detour reaches for when it needs to adjust where execution resumes.
         * @note Callback-safe: a pure register read/write over the captured context, no allocation, locking, or I/O.
         */
        [[nodiscard]] std::uintptr_t &resume_stack_pointer(MidContext &ctx) noexcept;

        /**
         * @brief Returns a mutable reference to the captured instruction pointer (rip).
         * @details Writing it redirects execution on resume: the trampoline's terminal return pops this (possibly
         *          rewritten) slot, so storing another same-signature function's address makes the resume land there
         *          instead of the original body.
         * @note Callback-safe: a pure register read/write over the captured context, no allocation, locking, or I/O.
         */
        [[nodiscard]] std::uintptr_t &instruction_pointer(MidContext &ctx) noexcept;

        /**
         * @brief Returns a mutable reference to the captured flags register (rflags).
         * @details Writing it alters the condition flags the trampoline restores on resume, so a detour can flip a
         *          comparison result the original code is about to branch on.
         * @note Callback-safe: a pure register read/write over the captured context, no allocation, locking, or I/O.
         */
        [[nodiscard]] std::uintptr_t &flags(MidContext &ctx) noexcept;

        /**
         * @brief Read-only by-value snapshot of XMM register @p index (0..15); out-of-range returns a zeroed view.
         * @note Callback-safe: a pure register read over the captured context, no allocation, locking, or I/O.
         */
        [[nodiscard]] XmmView xmm(const MidContext &ctx, std::size_t index) noexcept;

        /**
         * @enum Prologue
         * @brief Escalation policy for a target whose prologue is a breakpoint rather than a function body.
         * @details A leading 0xCC/0xCD (int3 / int n) means the slot is a breakpoint stub, a patched byte, or alignment
         *          padding. @ref Fail refuses the create with @ref ErrorCode::TargetPrologueUnsafe; @ref Relocate logs
         *          and installs anyway.
         * @note This policy governs only the prologue's shape. Whether the prologue can be relocated at all is left to
         *       the backend's own decode rather than guessed from its first byte, so a relative call is not refused
         *       here; if the backend cannot relocate it, the create fails with @ref ErrorCode::BackendFailed and the
         *       backend's specific reason is logged rather than returned. A target whose bytes are not readable
         *       executable committed memory is refused under BOTH policies: @ref Relocate cannot authorize decoding
         *       non-code.
         */
        enum class Prologue : std::uint8_t
        {
            Fail,
            Relocate
        };

        /**
         * @enum Severity
         * @brief Per-row policy for a declarative @ref HookSpec inside @ref install_all.
         * @details Folds the mandatory-vs-best-effort if-tree of a hand-rolled install loop into a field. A
         *          @ref Mandatory miss fails the whole @ref install_all call; a @ref BestEffort miss warns, records
         *          the per-row Error, skips, and lets the call still succeed.
         */
        enum class Severity : std::uint8_t
        {
            BestEffort,
            Mandatory
        };

        /**
         * @struct Options
         * @brief Per-hook policy for @ref inline_at / @ref mid_at.
         */
        struct Options
        {
            /// Prologue escalation policy; defaults to the safe-by-default Fail (see @ref Prologue).
            Prologue prologue = Prologue::Fail;

            /**
             * @brief Refuse the install when the target already appears hooked.
             * @details The pre-flight first consults this instance's ledger for an exact same-kit hook at the target
             *          address, then falls back to a foreign-JMP heuristic: an E9 rel32 jump, an FF25 indirect jump,
             *          or a mov rax, imm64; jmp rax absolute-jump trampoline planted over the prologue, each decoded
             *          under a fault guard. The default (false) installs anyway and the new hook layers on top.
             */
            bool fail_if_already_hooked = false;
        };

        namespace detail
        {
            /// Satisfied only by a pointer-to-function type; the valid cast target for Hook::original.
            template <typename T>
            concept FunctionPointer = std::is_pointer_v<T> && std::is_function_v<std::remove_pointer_t<T>>;
        } // namespace detail

        /**
         * @brief Where a hook installs: an absolute @ref Address, or a deferred @ref scan::OwnedScanRequest.
         * @details An owning OwnedScanRequest (never a borrowed ScanRequest) is used for the deferred case so the
         *          stored request closes the span-dangling hazard; it is resolved to an address at install time via
         *          scan::resolve.
         */
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
            /// The non-template inline-install primitive; @ref inline_at funnels its typed detour through this.
            [[nodiscard]] Result<Hook> inline_at_raw(InlineRequest request, void *detour);
        } // namespace detail

        /**
         * @class Hook
         * @brief Move-only RAII handle for one installed inline or mid hook; its destructor restores the prologue.
         * @details Constructed by @ref inline_at, @ref mid_at, or @ref install_all, always DISABLED; @ref enable arms
         *          it. Dropping the handle unhooks; @ref release intentionally leaves the hook installed for the
         *          process lifetime.
         * @note Teardown ordering: when two hooks are layered on the same target address, the newer one must be
         *       destroyed first. Use @ref HookStack when layered hooks live in a container. If the ledger detects an
         *       inversion, teardown leaks the older installed backend to preserve the newer trampoline chain and logs
         *       a warning; the target remains tracked as hooked.
         */
        class Hook
        {
        public:
            Hook(Hook &&other) noexcept;
            Hook &operator=(Hook &&other) noexcept;
            Hook(const Hook &) = delete;
            Hook &operator=(const Hook &) = delete;

            /**
             * @brief Restores the patched prologue and frees the trampoline, unless the handle was released or
             *        moved-from.
             * @details Restoration is conditional on proof, never assumed. The prologue is restored and the trampoline
             *          freed only when the backend disarms AND the target's bytes read back as the original. Under the
             *          loader lock, from underneath a newer layer, or when that proof cannot be obtained, the backend
             *          and its module reference are intentionally pinned instead: any possibly reachable trampoline
             *          stays mapped, the target remains conservatively reported as hooked, and the leak is booked to
             *          @ref DetourModKit::diagnostics::LeakSubsystem::HookManager. Freeing a trampoline the target may
             *          still jump into would be a use-after-free, so a pinned leak is the deliberate trade.
             *
             *          For a MID hook this also runs the callback down. The callback is retired first, so a pinned hook
             *          goes INERT rather than call into a destroyed owner. When the caller is authorized to block, the
             *          destructor waits for callbacks already executing on every teardown branch. On the restoring path
             *          it also waits for every adapter body to leave before freeing the stub. After this returns, no
             *          new mid-hook callback begins.
             * @note An authorized teardown blocks while a mid-hook callback is in flight, for as long as that callback
             *       takes. An unauthorized one -- an unload phase is published, or the fail-closed loader-lock probe
             *       vetoes -- pins without waiting; a callback that began before teardown may still finish.
             * @warning Destroying a mid hook from INSIDE its own callback cannot wait (the waiter would be the thread
             *          it waits for). That is detected: the callback is retired, the backend pinned, and the leak
             *          booked. Prefer destroying from a thread that is not inside the hook. Teardown pins the same way
             *          whenever it cannot prove no thread is inside the callback, so a pin is not by itself evidence
             *          of misuse.
             * @warning An INLINE hook has no such rundown; quiescence is caller-owned (see @ref inline_at).
             * @note Explicitly noexcept (a destructor is implicitly noexcept already): this runs from
             *       DLL_PROCESS_DETACH / loader-lock teardown where an escaping exception terminates the host, so the
             *       no-throw contract is pinned at the declaration and every path inside fails closed.
             */
            ~Hook() noexcept;

            /// True while this handle owns a live hook (false after a move-out or @ref release).
            [[nodiscard]] explicit operator bool() const noexcept;

            /// The hook's registered name (empty for a moved-from / released handle).
            [[nodiscard]] std::string_view name() const noexcept;

            /**
             * @brief True when the hook is currently armed (its detour is active); false until @ref enable succeeds.
             * @details Answers from DMK's published state AND the backend's own view, not from a local flag alone, so
             *          true means the backend still holds this hook armed rather than merely that DMK once armed it.
             *          It does not re-decode the target's bytes, so a foreign patch applied out of band by another
             *          component is not detected here. The backend query is serialized with enable/disable through
             *          the per-hook call gate because the backend's enabled flag is not atomic.
             * @note Setup/control-plane only: may wait for an in-flight guarded call or hook state transition.
             */
            [[nodiscard]] bool is_enabled() const noexcept;

            /**
             * @brief Returns the typed original-function trampoline (inline hooks only); the UNGUARDED fast path.
             * @tparam Fn The full function-pointer type of the original (e.g. `void(*)(void*)`).
             * @return A trampoline of type Fn, or nullptr for a mid hook, a disengaged handle, or a backend miss.
             * @details This is the common process-lifetime game-detour path: `h.original<fn>()(args...)` is one
             *          indirection and takes no lock, so the caller MUST guarantee the hook outlives the call. For the
             *          opt-in guarded form used when teardown may race an in-flight call, use @ref call. Mid hooks
             *          have no callable original, so original<Fn>() is nullptr for them.
             */
            template <detail::FunctionPointer Fn> [[nodiscard]] Fn original() const noexcept
            {
                return reinterpret_cast<Fn>(original_address());
            }

            /**
             * @brief Calls the original function through the trampoline under DMK's per-hook guard (inline hooks only).
             * @tparam Ret The original's return type (defaults to void).
             * @tparam Args The original's parameter types, taken BY VALUE so the reconstructed pointer type is the
             *         real by-value C ABI.
             * @return The original's return value, or a value-initialized Ret when the hook is inactive / not inline.
             * @details Pins the refcounted call gate before taking its recursive mutex and holds both through the
             *          invocation. Teardown publishes a null trampoline under the same mutex before freeing it, so a
             *          late call fails closed and an in-flight call drains first. Use @ref original when the hook
             *          lifetime is already guaranteed and this guard is unnecessary.
             *
             *          The Hook object's storage must outlive this member call, although teardown work may race it.
             *          Args are intentionally by value: callers must supply the original function's exact parameter
             *          types, because a deduced reference would reconstruct the wrong function-pointer ABI. This
             *          guard does not drain a thread that entered the original by another path.
             * @note Callback-safe: takes one bounded internal lock and performs no allocation or I/O before dispatch.
             * @note Not marked [[nodiscard]]: with the default Ret = void the attribute is inert, and firing it only
             *       for non-void instantiations would be surprising and inconsistent with the backend, which marks no
             *       call-family method [[nodiscard]].
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
                return reinterpret_cast<Ret (*)(Args...)>(dispatch.trampoline)(args...);
            }

            /**
             * @brief The fail-closed-distinguishing sibling of @ref call: dispatches through the original and reports
             *        whether the guarded gate actually let the call through.
             * @tparam Ret The original's return type (default void), reconstructed by value as in @ref call.
             * @tparam Args The original's exact by-value parameter types; see @ref call.
             * @return The original's return value, or InvalidHookState when the guarded gate refuses dispatch.
             * @details Uses the same lifetime guard as @ref call but preserves a suppressed call in the error channel,
             *          which distinguishes it from a legitimate value-initialized result. `try_call<void>()` reports
             *          whether dispatch occurred.
             * @note Callback-safe on the same terms as @ref call: it takes one bounded internal lock and performs no
             *       allocation or I/O before dispatching.
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
                    reinterpret_cast<void (*)(Args...)>(dispatch.trampoline)(args...);
                    return {};
                }
                else
                {
                    return reinterpret_cast<Ret (*)(Args...)>(dispatch.trampoline)(args...);
                }
            }

            /**
             * @brief Arms the hook: patches the target so the detour begins running.
             * @return Success if the hook is now active (or already was and is the target's newest live layer). On
             *         failure the Error carries the reason (LayerConflict, BackendFailed, EnableFailed, DisableFailed,
             *         InvalidHookState). LayerConflict changes nothing at all: not the target's bytes and not the
             *         hook's own state, so an already-armed lower layer stays armed and keeps dispatching. EnableFailed
             *         leaves the hook disabled and the target unchanged. DisableFailed means arming could not be
             *         confirmed and rollback also failed, so the handle truthfully remains active and must be quiesced
             *         or disabled again before teardown.
             * @details This is the point at which a hook installed by @ref inline_at, @ref mid_at, or @ref install_all
             *          first becomes reachable, so call it only once anything the detour needs -- above all the handle
             *          itself, which is how the detour reaches @ref call or @ref original -- is published where the
             *          detour can reach it. Success is published only after the target's bytes are read back and
             *          confirmed patched, so a backend that reports success without arming is reported as EnableFailed
             *          rather than trusted. Idempotent via an atomic CAS status machine; thread-safe without external
             *          synchronization.
             * @note Only the newest live hook on a target may arm it. Arming from underneath a newer layer would stamp
             *       this detour over that layer's patch and silently bypass it, so it is refused with LayerConflict and
             *       nothing is written. The layer check precedes the idempotency check, so a lower layer that is
             *       ALREADY armed also gets LayerConflict rather than the no-op Success it would get on top: the
             *       refusal reports "you do not own this target", which a caller re-arming defensively must not read as
             *       a lost hook. To stack detours, arm the base hook BEFORE creating the one above it: a hook created
             *       while the layer below is armed captures the patched prologue and resumes into it.
             */
            [[nodiscard]] Result<void> enable() noexcept;

            /**
             * @brief Disarms the hook without destroying it.
             * @return Success if the hook is now disabled (or already was and is the target's newest live layer). On
             *         failure the Error carries the reason (LayerConflict, BackendFailed, DisableFailed,
             *         InvalidHookState). LayerConflict changes nothing at all, so a still-armed lower layer keeps
             *         dispatching and truthfully reports @ref is_enabled.
             * @note Only the newest live hook on a target may disarm it. Disabling from underneath a newer layer would
             *       restore the prologue THIS hook saved, which predates that layer's patch, unhooking the target
             *       wholesale while the newer handle still reported enabled; it is refused with LayerConflict and
             *       nothing is written. As in @ref enable, the layer check precedes the idempotency check. Tear down or
             *       disable the newer layer first.
             */
            [[nodiscard]] Result<void> disable() noexcept;

            /**
             * @brief Detaches the hook from this handle, leaving it installed for the process lifetime.
             * @details The handle becomes disengaged (operator bool is then false and ~Hook is a no-op); the backend
             *          hook is intentionally leaked so the detour stays live forever. This is the explicit form of the
             *          "install once, never unhook" pattern; it is not an error path.
             */
            void release() noexcept;

        private:
            struct Impl;
            /**
             * @brief Refcounted call guard defined in src/internal/hook_backend.hpp.
             * @details A late @ref call pins it before locking, so concurrent teardown cannot free its mutex.
             */
            struct CallGate;
            Hook(std::unique_ptr<Impl> impl, std::shared_ptr<CallGate> gate) noexcept;

            /// Raw inline trampoline (or nullptr); the UNGUARDED backend touch behind original<Fn>(). Defined in .cpp.
            [[nodiscard]] void *original_address() const noexcept;

            /// Copies the atomic call-gate reference into a strong local for @ref call to pin. Defined in .cpp.
            [[nodiscard]] std::shared_ptr<CallGate> pin_call_gate() const noexcept;

            /**
             * @brief Locks the gate's recursive_mutex and returns the owning token; the @ref call guard. Defined in
             *        .cpp.
             * @details noexcept: a recursive_mutex::lock failure yields an unowned lock (the caller checks
             *          owns_lock()) rather than throwing out of the non-noexcept @ref call.
             */
            [[nodiscard]] std::unique_lock<std::recursive_mutex> acquire_call_lock(CallGate *gate) const noexcept;

            /// The gate's published callable trampoline (nullptr when inactive); read with the call lock held.
            [[nodiscard]] void *active_trampoline(CallGate *gate) const noexcept;

            /**
             * @brief One entry through the call gate, shared verbatim by @ref call and @ref try_call.
             * @details Pins the gate, locks it, and snapshots its trampoline. Any failed stage leaves @ref trampoline
             *          null. Retaining the gate and lock prevents teardown from freeing an in-flight trampoline.
             */
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
            /**
             * @brief The shared call gate, held atomically so @ref call can pin it without racing a concurrent
             *        teardown/move that publishes over it.
             */
            std::atomic<std::shared_ptr<CallGate>> m_gate;

            friend Result<Hook> mid_at(MidRequest request, MidHookFn detour);
            friend Result<Hook> detail::inline_at_raw(InlineRequest request, void *detour);
        };

        /**
         * @class HookStack
         * @brief Move-only owner of a set of Hook handles that guarantees newest-first (LIFO) teardown.
         * @details Same-target layers must unwind newest-first, or the older layer's restore clobbers a prologue the
         *          newer layer's live trampoline still chains through (see @ref Hook). A bare `std::vector<Hook>`
         *          destroys in storage order, i.e. oldest-first; teardown then contains the hazard by permanently
         *          leaking the older backend. This container restores back-to-front instead, so when it owns the whole
         *          layer set and hooks were pushed in creation order, neither the leak nor its warning can occur.
         *          Prefer it over a bare vector whenever hooks are kept alive together, especially any layered on one
         *          address or the successes returned by @ref install_all (push them in table order).
         *
         *          Inline/mid @ref Hook handles only: @ref VmtHook already unwinds its objects newest-first.
         * @note Move-only, mirroring @ref Hook. Not internally synchronized: build and tear it down on the setup
         *       thread, exactly like the hooks it holds.
         */
        class HookStack
        {
        public:
            /**
             * @brief Constructs an empty hook stack.
             * @note Setup/control-plane only: build hook ownership during init/shutdown or worker setup, not from a
             *       hook callback.
             */
            HookStack() noexcept = default;

            /**
             * @brief Move-constructs by adopting @p other's hooks without tearing them down.
             * @note Setup/control-plane only: moving a stack transfers ownership and is not internally synchronized
             *       with concurrent reads or teardown.
             */
            HookStack(HookStack &&other) noexcept : m_hooks(std::move(other.m_hooks)) { other.m_hooks.clear(); }

            /**
             * @brief Move-assigns by tearing down this stack's current hooks newest-first, then adopting @p other's.
             * @details Deliberately not defaulted. A defaulted move-assignment would let the underlying vector destroy
             *          or overwrite the replaced hooks in a container-defined order, reopening the layered-hook
             *          use-after-free this type exists to prevent. Draining newest-first here keeps the LIFO guarantee
             *          even when a live stack is overwritten. The moved-from source is explicitly cleared afterward so
             *          empty() remains a stable post-move query.
             * @note Setup/control-plane only: move-assignment may restore existing hooks and is not synchronized with
             *       hook callbacks or concurrent stack access.
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
             * @brief Restores every owned hook's prologue, newest-first.
             * @note Setup/control-plane only: destroy the stack after detour entry points and worker calls that might
             *       use its hooks are quiescent.
             * @note Explicitly noexcept: like @ref Hook::~Hook this can run from DLL_PROCESS_DETACH / loader-lock
             *       teardown, where an escaping exception terminates the host. Every ~Hook it invokes already fails
             *       closed, so no exception escapes.
             */
            ~HookStack() noexcept { teardown_newest_first(); }

            /**
             * @brief Moves @p hook onto the top of the stack and returns a reference to the stored handle.
             * @return A reference to the just-stored @ref Hook, valid until the next @ref push / @ref clear / move
             *         (the standard vector-reference invalidation contract). Use it to capture the trampoline right
             *         after pushing, e.g. `stack.push(std::move(h)).original<Fn>()`; call @ref reserve up front to keep
             *         earlier references stable across a batch of pushes.
             * @details Push order IS layer order: push the base hook first and each hook layered on top of it after, so
             *          the newest-first destructor restores them in the safe order. A `std::bad_alloc` from growing the
             *          storage unwinds @p hook (restoring its own prologue) and leaves the already-stored hooks intact
             *          -- a clean partial state, never a half-owned live hook.
             * @note Setup/control-plane only: may allocate and may publish a new hook owner; do not call from a hook
             *       callback.
             */
            Hook &push(Hook hook)
            {
                m_hooks.push_back(std::move(hook));
                return m_hooks.back();
            }

            /**
             * @brief Reserves storage for @p capacity hooks so a batch of @ref push calls does not reallocate.
             * @note Setup/control-plane only: may allocate.
             */
            void reserve(std::size_t capacity) { m_hooks.reserve(capacity); }

            /**
             * @brief Returns the number of hooks currently owned.
             * @note Callback-safe: non-blocking and non-allocating when no thread mutates or destroys this stack
             *       concurrently.
             */
            [[nodiscard]] std::size_t size() const noexcept { return m_hooks.size(); }

            /**
             * @brief Reports whether the stack owns no hooks.
             * @note Callback-safe: non-blocking and non-allocating when no thread mutates or destroys this stack
             *       concurrently.
             */
            [[nodiscard]] bool empty() const noexcept { return m_hooks.empty(); }

            /**
             * @brief Tears down every owned hook newest-first, leaving the stack empty and retaining capacity.
             * @note Setup/control-plane only: restores hooks and is not synchronized with callbacks or concurrent
             *       stack access.
             */
            void clear() noexcept { teardown_newest_first(); }

        private:
            /**
             * @brief Restores the owned hooks strictly back-to-front (newest layer first).
             * @details pop_back destroys the last (newest) element before the ones beneath it, which is the exact order
             *          the trampoline-chaining hazard demands; relying on the raw vector destructor or move-assignment
             *          would not provide this ownership contract.
             */
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
         * @brief Installs a DISABLED inline hook at the request's target; call @ref Hook::enable to arm it.
         * @tparam Fn The detour's function type; the function-to-void* cast happens here, once, behind a word-size
         *         static_assert, so the call site never writes a reinterpret_cast.
         * @param request Name, target (absolute or deferred scan), and policy.
         * @param detour Pointer to the detour function.
         * @return The RAII @ref Hook on success, with the target unpatched, or an Error.
         * @details The trampoline is built and the target validated here, so a failure to install is reported by this
         *          call; only the arming is deferred. Publish the returned handle where the detour can reach it, then
         *          enable (see the two-step transaction in this file's overview).
         *
         *          An inline detour REPLACES the target, so it runs with DMK nowhere in the call path. That is what
         *          makes the two rules below the caller's to keep: unlike @ref mid_at, there is no DMK frame here that
         *          could contain an exception or count an entry, and adding one would require knowing the target's
         *          signature, which this erased form does not.
         * @warning The detour MUST NOT THROW. It is called directly from the patched target, so an escaping exception
         *          unwinds through a caller that never expected one -- frequently foreign or optimized code -- and
         *          terminates the host. This is not enforced by the type: `Fn *` accepts an ordinary function pointer,
         *          and demanding a `noexcept` function type would reject every detour written against this header.
         * @warning Quiescence before teardown is CALLER-OWNED. Destroying the @ref Hook restores the prologue, but DMK
         *          cannot know whether a thread is still inside the detour, so it cannot wait for one. Ensure no
         *          thread can be executing the detour before the handle dies. @ref mid_at owns this for you; this form
         *          does not.
         */
        template <class Fn> [[nodiscard]] Result<Hook> inline_at(InlineRequest request, Fn *detour)
        {
            static_assert(sizeof(Fn *) == sizeof(void *), "function pointer must be word-sized");
            return detail::inline_at_raw(std::move(request), reinterpret_cast<void *>(detour));
        }

        /**
         * @brief Installs a DISABLED mid-function hook at the request's target; call @ref Hook::enable to arm it.
         * @param request Name, target (absolute or deferred scan), and policy.
         * @param detour The DMK-typed mid-hook detour (keeps its MidHookFn type; no raw cast at the call site).
         * @return The RAII @ref Hook on success, with the target unpatched, or an Error.
         *         `ErrorCode::MidHookCapacityExhausted` means every mid-hook adapter is in use and nothing was patched.
         * @details See @ref inline_at for the two-step install transaction; it applies identically here.
         *
         *          Unlike @ref inline_at, DMK reaches a mid-hook callback through its own adapter, and therefore owns
         *          what that frame makes possible: exceptions are contained (@ref MidHookFn), and destroying the handle
         *          runs the callback down -- no callback begins after ~Hook returns, and off loader lock a callback
         *          already running is waited out on every teardown branch.
         * @note A mid hook holds one adapter from a fixed pool for its lifetime, because the backend's callback
         *       signature has no user-data parameter and a distinct function is the only way to carry per-hook
         *       identity. A clean teardown returns the adapter. A teardown that pins the backend instead (see
         *       @ref Hook::~Hook), and a hook retained by @ref Hook::release, keep theirs for the process lifetime:
         *       the stub stays reachable, so the adapter it calls must stay valid. Pinning is not always a failure --
         *       loader-lock teardown and destroying a hook from inside its own callback both pin by design -- so a
         *       host that does either at scale spends pool capacity permanently.
         */
        [[nodiscard]] Result<Hook> mid_at(MidRequest request, MidHookFn detour);

        struct InstallOutcome;

        /// Internal tag carrying the one audited function-to-void* cast for a declarative inline @ref HookSpec.
        struct InlineDetour
        {
            void *fn = nullptr;
        };

        /**
         * @class HookSpec
         * @brief One row of a declarative install table consumed by @ref install_all.
         * @details The factories are the SOLE constructor (the data ctor is private, so HookSpec is not an aggregate
         *          and a bare designated-init does not compile): a forgotten name or target is a COMPILE error, not a
         *          debug-only runtime trip. The detour is held as a typed variant -- an @ref InlineDetour produced by
         *          the inline_hook factory (the one audited cast) or a typed MidHookFn -- so the table author never
         *          writes a reinterpret_cast and the mid case never loses its type. Each row also carries its own
         *          @ref Options (default-constructed unless the factory's trailing options arg is supplied), which
         *          @ref install_all applies verbatim, so one row can request @ref Prologue::Relocate or
         *          fail_if_already_hooked while its neighbours keep the safe default.
         */
        class HookSpec
        {
        public:
            /**
             * @brief Builds an inline-hook row; performs the single audited function-to-void* cast.
             * @tparam Fn The detour's function type (word-size static_assert).
             * @param name Row name, forwarded to the eventual @ref InlineRequest.
             * @param target Owned scan request that resolves the hook target.
             * @param detour Typed inline detour function.
             * @param severity Mandatory rows abort @ref install_all on failure; best-effort rows report the error and
             *        let later rows continue.
             * @param options Per-row install policy (@ref Prologue escalation, fail_if_already_hooked). Defaults to the
             *        safe @ref Options default, so an existing table needs no change; set it to give one row a
             *        different policy than the rest without an out-of-band install call.
             * @return A declarative table row consumed by @ref install_all.
             * @note Setup/control-plane only: table construction may allocate through @p name and @p target.
             */
            template <class Fn>
            [[nodiscard]] static HookSpec inline_hook(std::string name, scan::OwnedScanRequest target, Fn *detour,
                                                      Severity severity = Severity::Mandatory, Options options = {})
            {
                static_assert(sizeof(Fn *) == sizeof(void *), "function pointer must be word-sized");
                return HookSpec{std::move(name), std::move(target), InlineDetour{reinterpret_cast<void *>(detour)},
                                severity, options};
            }

            /**
             * @brief Builds a mid-hook row; the @ref MidHookFn stays typed, with no raw cast at the call site.
             * @param name Row name, forwarded to the eventual @ref MidRequest.
             * @param target Owned scan request that resolves the hook target.
             * @param detour Typed mid-hook detour.
             * @param severity Mandatory rows abort @ref install_all on failure; best-effort rows report the error and
             *        let later rows continue.
             * @param options Per-row install policy applied by @ref install_all.
             * @return A declarative table row consumed by @ref install_all.
             * @note Setup/control-plane only: table construction may allocate through @p name and @p target.
             */
            [[nodiscard]] static HookSpec mid_hook(std::string name, scan::OwnedScanRequest target, MidHookFn detour,
                                                   Severity severity = Severity::Mandatory, Options options = {})
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
            HookSpec(std::string name, scan::OwnedScanRequest target, std::variant<InlineDetour, MidHookFn> detour,
                     Severity severity, Options options) noexcept
                : m_name(std::move(name)), m_target(std::move(target)), m_detour(std::move(detour)),
                  m_severity(severity), m_options(options)
            {
            }

            std::string m_name;
            scan::OwnedScanRequest m_target;
            /// Inline vs mid is encoded by the active alternative.
            std::variant<InlineDetour, MidHookFn> m_detour;
            Severity m_severity;
            /// Per-row install policy applied verbatim by @ref install_all.
            Options m_options;

            friend Result<std::vector<InstallOutcome>> install_all(std::span<const HookSpec> table) noexcept;
        };

        /**
         * @struct InstallOutcome
         * @brief Per-row result of @ref install_all, in table order, so a mod can correlate which optional hooks
         *        landed.
         * @warning A `std::vector<InstallOutcome>` (this is what @ref install_all returns) destroys its rows
         *          front-to-back, i.e. the hooks it holds are torn down OLDEST-first. For hooks layered on one target
         *          that is the inverted order: the older layer restores its prologue while a newer layer's trampoline
         *          still chains through it. @ref Hook::~Hook now contains that hazard (it leaks the older backend
         *          instead of corrupting, and logs a warning) rather than crashing, but the leak is real. To tear the
         *          hooks down cleanly (newest-first, no leak, no warning), move the successful ones out of the outcomes
         *          into a @ref HookStack in table order and let the stack own them; see @ref HookStack.
         */
        struct InstallOutcome
        {
            std::string name;
            Severity severity;
            /// The installed Hook on success; an Error (e.g. NoMatch) when the row was skipped.
            Result<Hook> hook;
        };

        /**
         * @brief Installs a whole declarative table of DISABLED hooks, returning one outcome per row.
         * @param table The spec rows. Taken as a const span so a `const k_hook_table` binds; install_all copies each
         *        OwnedScanRequest it needs and never moves out of the caller's table.
         * @return The per-row outcomes on success, every successful row's hook unpatched. The outer Result fails fast
         *         on the FIRST @ref Severity::Mandatory miss (an all-Mandatory table short-circuits); otherwise it
         *         succeeds and every row's status is in the vector.
         * @details Every row is installed disabled (see @ref inline_at), so a table lands as one unarmed unit: take
         *          ownership of the outcomes, then arm the rows you want by calling @ref Hook::enable on each. Rolling
         *          back a partial table therefore never has to disarm a live hook. noexcept, matching
         *          scan::resolve_batch: it catches bad_alloc / backend failure internally and reports it per row rather
         *          than throwing across the init path.
         * @warning The returned `std::vector<InstallOutcome>` owns the installed hooks and, if simply dropped, tears
         *          them down OLDEST-first (front-to-back). That is the wrong order for hooks layered on one target and
         *          leaks the older backend to stay memory-safe (see @ref InstallOutcome and @ref Hook::~Hook). When any
         *          rows may target the same address -- or whenever you keep several hooks alive together -- move the
         *          successful hooks out into a @ref HookStack in table order so teardown is newest-first by
         *          construction rather than by caller discipline.
         */
        [[nodiscard]] Result<std::vector<InstallOutcome>> install_all(std::span<const HookSpec> table) noexcept;

        /**
         * @brief Reports whether a DMK hook (this kit) currently owns or is installing @p target.
         * @details Consults this instance's ledger only; it is the exact same-kit query, not the foreign-JMP
         *          heuristic. Hooks installed by other statically-linked DMK consumers in the same process are not
         *          visible. During a concurrent install it may report true after the target is reserved but before the
         *          backend patch is committed; that fail-closed bias prevents a redundant racing install from treating
         *          the target as free. Use it to short-circuit a redundant install; to also catch foreign hooks, set
         *          Options::fail_if_already_hooked on the install instead.
         */
        [[nodiscard]] bool is_target_hooked(Address target) noexcept;

        /**
         * @struct VmtOptions
         * @brief Policy for @ref vmt_for and @ref VmtHook::apply_to, symmetric with @ref Options.
         */
        struct VmtOptions
        {
            /**
             * @brief Refuse to clone/apply onto an object whose vptr already points at a vtable cloned by this kit.
             * @details Cloning an object that is already on a clone reads the first clone as if it were the original
             *          vtable, so the first mod's hooked methods get baked into the second's "original" -- the silent
             *          double-hook failure mode. Default false preserves the permissive behaviour.
             */
            bool fail_if_already_hooked = false;

            /**
             * @brief Pre-flight-decode the first byte of the original vtable slot and refuse a breakpoint/jump-stub.
             * @details A 0xCC/0xCD first byte is a breakpoint pad, not a function; a same-module `jmp rel8/rel32` is a
             *          jump stub (e.g. an incremental-link ILT entry). Both are rejected; MSVC adjustor thunks and
             *          real functions pass. Default false. Known false positive: a /INCREMENTAL consumer routes every
             *          function through an ILT stub, which this rejects.
             */
            bool fail_on_non_function_pointer = false;
        };

        class VmtHook;

        /**
         * @brief Clones the seed object's vtable and swaps the seed onto the clone, returning the owning handle.
         * @param name A descriptive name for the hook.
         * @param object The seed object whose vtable is cloned and whose vptr is swapped to the clone.
         * @param options Create-time policy (fail-if-already-hooked, pre-flight slot decode).
         * @return The RAII @ref VmtHook on success, or an Error (InvalidArg, InvalidObject, HookAlreadyExists,
         *         BackendFailed, OutOfMemory, SystemCallFailed, or UnknownError). InvalidObject covers an unreadable,
         *         non-writable, or unaligned object word, an unreadable vtable or RTTI header prefix, a table with no
         *         callable slot, and a protection change, unmap, or displacement of the object word before the
         *         fault-contained atomic compare-exchange that publishes the clone. A displaced vptr is never
         *         overwritten.
         * @warning Clone during setup or a host-quiesced window. Fault containment does not synchronize virtual
         *          dispatch or make concurrent object destruction safe.
         */
        [[nodiscard]] Result<VmtHook> vmt_for(std::string name, void *object, VmtOptions options = {});

        /**
         * @class VmtHook
         * @brief Move-only RAII handle for a cloned (hooked) vtable applied to one or more live objects.
         * @details One clone may serve multiple objects; a @ref hook_method affects all of them. VMT hooks have no
         *          enable/disable operation.
         * @warning The caller must quiesce virtual dispatch across create/apply/remove and keep every applied object
         *          alive through removal. Guarded vptr access is fault containment, not an ownership protocol.
         * @note Concurrency: object-vptr transitions in @ref vmt_for / @ref apply_to / @ref remove_from / teardown are
         *       serialized by a setup-time object gate so duplicate create/apply checks and swaps are one ordered
         *       operation. @ref original copies the pre-hook slot pointer out under a shared-read lock and returns it,
         *       so TAKING that snapshot is serialised against a concurrent @ref apply_to / @ref hook_method /
         *       @ref remove_method (each takes the matching exclusive write) and never reads a torn mutation. The lock
         *       guards the snapshot, not the call: the returned pointer is then invoked lock-free, so the caller still
         *       owns the hook-outlives-the-call guarantee, exactly as with @ref Hook::original.
         */
        class VmtHook
        {
        public:
            VmtHook(VmtHook &&other) noexcept;
            VmtHook &operator=(VmtHook &&other) noexcept;
            VmtHook(const VmtHook &) = delete;
            VmtHook &operator=(const VmtHook &) = delete;

            /**
             * @brief Restores the original vptr on every applied object, unless released, moved-from, or outranked.
             * @details A writable object still on this clone is restored to its binding's original vptr.
             *          An object already at that original needs no write and releases the binding safely even when its
             *          word is not writable. Any other or unreadable value retains the dependency because a successor
             *          may still record this clone as the table it will restore. Safely restorable peers are restored,
             *          then an unresolved dependency leaks the clone rather than free a table still in use. The leak
             *          is counted on @ref diagnostics::LeakSubsystem::HookManager and logged with the hook's name.
             *          Destroy VMT hooks newest-first to get the original table back.
             * @note Explicitly noexcept (a destructor is implicitly noexcept already): like @ref Hook::~Hook it runs
             *       from loader-lock teardown, so the no-throw contract is pinned at the declaration.
             */
            ~VmtHook() noexcept;

            /// True while this handle owns a live cloned vtable (false after a move-out or @ref release).
            [[nodiscard]] explicit operator bool() const noexcept;

            /// The hook's registered name (empty for a moved-from / released handle).
            [[nodiscard]] std::string_view name() const noexcept;

            /**
             * @brief Applies the cloned vtable to an additional live object, swapping its vptr.
             * @param object The object to put on the clone.
             * @param options Apply-time policy (fail-if-already-hooked, pre-flight slot decode).
             * @return Success, or an Error (InvalidHookState, InvalidObject, HookAlreadyExists, OutOfMemory, or
             *         UnknownError). An unreadable or non-writable object word is InvalidObject under every
             *         @p options value, as is an unaligned object word, protection change, displacement, or unmap
             *         before the fault-contained atomic compare-exchange. A displaced vptr is never overwritten.
             *         HookAlreadyExists is likewise returned under every @p options value when this
             *         handle cannot name what it would displace: @p object already carries this clone but was never
             *         applied here, or @p object has since moved off the vptr this handle recorded for it (usually a
             *         newer @ref VmtHook layered on it). Re-applying either would leave teardown restoring a vptr
             *         @p object never had. Applying an object this handle already tracks and already published is a
             *         success no-op.
             * @warning Apply only while @p object is host-quiesced; the atomic vptr update does not synchronize
             *          dispatch.
             */
            [[nodiscard]] Result<void> apply_to(void *object, VmtOptions options = {});

            /**
             * @brief Restores the original vptr on one applied object.
             * @param object The object to restore.
             * @return Success, or InvalidObject for a null @p object / InvalidHookState for a disengaged handle.
             * @details Success does not assert that @p object was applied here, nor that a restore happened: an
             *          untracked object is a harmless no-op, and a tracked one releases its binding only once its word
             *          is observed at the recorded original. A writable object on this clone is swapped back to that
             *          original unless a protection change or unmap defeats the swap. An object already at the original
             *          needs no write and releases the binding even when its word is not writable. Any other or
             *          unreadable value is left unchanged and retains the dependency, so teardown can restore it if it
             *          returns to this clone or leak the clone rather than free a table a successor may still restore.
             * @warning Quiesce @p object before restoring it; fault containment does not drain in-flight dispatch.
             */
            [[nodiscard]] Result<void> remove_from(void *object);

            /**
             * @brief Redirects the virtual method at vtable @p index to @p detour in this handle's cloned vtable.
             * @tparam Fn The detour's function-pointer type; the function-to-void* cast happens here, once, behind a
             * word-size static_assert, so the call site never writes a reinterpret_cast.
             * @param index The zero-based vtable index of the method to hook. Count only virtual functions: the
             * ABI-specific vtable header (the Itanium offset-to-top + RTTI pointers, or the MSVC RTTI locator) is not
             * part of the index -- index 0 is the first virtual method as declared.
             * @param detour The replacement function. It is installed straight into a vtable slot, so its ABI must
             * match the original virtual method's true signature: the object pointer arrives as the first integer
             * argument (`this` in rcx under the Win64 ABI) followed by the declared parameters, so a free function
             * taking the object pointer first is the correct shape. hook_method cannot validate that signature; a
             * mismatch is silent ABI corruption, the same caller caveat @ref Hook::call carries.
             * @return Success, or an Error: InvalidHookState (disengaged handle), InvalidArg (null @p detour or an
             * out-of-range @p index), MethodAlreadyHooked (@p index is already hooked on this handle), BackendFailed
             * or OutOfMemory.
             * @note Setup/control-plane only: mutates the cloned vtable and the per-index hook table under the
             * exclusive write lock. Do not call it from a hooked method's detour while another thread reads the same
             * handle; install all method hooks during setup.
             */
            template <detail::FunctionPointer Fn> [[nodiscard]] Result<void> hook_method(std::size_t index, Fn detour)
            {
                static_assert(sizeof(Fn) == sizeof(void *), "function pointer must be word-sized");
                return hook_method_raw(index, reinterpret_cast<void *>(detour));
            }

            /**
             * @brief Returns the pre-hook function pointer for the method at vtable @p index, typed as Fn.
             * @tparam Fn The full function-pointer type of the original method, including the leading object pointer
             * as the first parameter (the Win64 ABI passes it in rcx).
             * @param index The zero-based vtable index used at @ref hook_method time.
             * @return A function pointer of type Fn to the original method's slot, or nullptr for an unhooked @p index
             * or a disengaged handle.
             * @details The per-method analogue of @ref Hook::original: the pre-hook slot value is copied out (an
             * immutable snapshot the backend recorded when @ref hook_method cloned the slot) under a shared-read lock,
             * then returned so the detour can invoke the original lock-free through the returned pointer. It never
             * needs a guarded @ref Hook::call twin because the slot pointer is fixed for the hook's lifetime; the
             * caller only has to keep the hook alive across the call.
             * @note Callback-safe on the read side (a shared-lock snapshot copy, no allocation or I/O); the returned
             * pointer's invocation is the caller's responsibility.
             */
            template <detail::FunctionPointer Fn> [[nodiscard]] Fn original(std::size_t index) const noexcept
            {
                return reinterpret_cast<Fn>(method_original_address(index));
            }

            /**
             * @brief Lifts the method hook at vtable @p index, restoring the cloned vtable slot to the original.
             * @param index The zero-based vtable index previously passed to @ref hook_method.
             * @return Success, or an Error: InvalidHookState (disengaged handle) / MethodNotFound (@p index is not
             *         hooked on this handle).
             * @note Setup/control-plane only: rewrites the cloned vtable slot back to the original function pointer
             *       under the exclusive write lock. This clone-slot restore is a bare pointer write with no thread
             *       protection against an in-flight dispatch through the slot; quiesce the method before lifting it.
             */
            [[nodiscard]] Result<void> remove_method(std::size_t index);

            /// Detaches the cloned vtable for the process lifetime (no vptr is restored; handle becomes disengaged).
            void release() noexcept;

        private:
            struct Impl;
            explicit VmtHook(std::unique_ptr<Impl> impl) noexcept;

            /// The non-template method-install primitive behind @ref hook_method; defined in src/hook.cpp.
            [[nodiscard]] Result<void> hook_method_raw(std::size_t index, void *detour);

            /**
             * @brief Snapshots the original slot pointer for @p index under the shared-read lock; the backend touch
             *        behind @ref original. Returns nullptr for an unhooked index or a disengaged handle. Defined in
             *        src/hook.cpp.
             */
            [[nodiscard]] void *method_original_address(std::size_t index) const noexcept;

            std::unique_ptr<Impl> m_impl;

            friend Result<VmtHook> vmt_for(std::string name, void *object, VmtOptions options);
        };
    } // namespace hook
} // namespace DetourModKit

#endif // DETOURMODKIT_HOOK_HPP
