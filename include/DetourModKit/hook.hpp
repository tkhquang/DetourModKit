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
 *          Backend confinement: SafetyHook (and the Zydis decoder it drags in) is named only in src/hook.cpp and
 *          src/internal/hook_backend.hpp; a translation unit that includes only this header pulls in neither. The
 *          mid-hook register file is reached through free accessor functions over an opaque `MidContext`, never by
 *          mirroring the backend's context layout in a public header.
 *
 *          A small process-wide ledger (src/internal/hook_ledger.hpp -- not a public registry, no name lookup, no
 *          introspection) backs two safety properties that need shared state once hooks are owned by handles rather
 *          than a central registry: exact same-kit duplicate detection for `Options::fail_if_already_hooked`, and
 *          newest-first teardown-order tracking for hooks layered on one target address (a violation is detected and
 *          warned, not silently corrupted).
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
         * @details Names only DMK types, so writing a detour pulls in neither SafetyHook nor Zydis. It is layout- and
         *          ABI-identical to the backend's mid-hook callback (both are `void(*)(<captured-context>&)` under the
         *          Win64 ABI), which is why mid_at can reinterpret_cast a MidHookFn to the backend callback type when
         *          it registers the hook.
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
             * @details The pre-flight first consults the process-wide ledger for an exact same-kit hook at the target
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
         * @details Constructed only by @ref inline_at / @ref mid_at / @ref install_all. The backend hook, a DMK-owned
         *          `std::recursive_mutex` call guard, the atomic enable/disable status machine, and the ledger token
         *          all live behind the pimpl, so this header never names SafetyHook. Dropping the handle (or letting
         *          it go out of scope) unhooks; @ref release detaches the hook for the process lifetime instead.
         * @note Teardown ordering: when two hooks are layered on the same target address, the newer one must be
         *       destroyed first (it saved the older hook's jump as its own original bytes). Natural reverse-order
         *       destruction of stack/member handles satisfies this automatically; if you store layered same-target
         *       handles in a container whose destruction order is not creation-reverse, destroy them newest-first.
         *       When the ledger detects a violation (an older layer torn down while a newer one is still live), the
         *       destructor contains the use-after-free by LEAKING the older backend rather than restoring it -- so the
         *       newer layer's trampoline chain stays valid -- and logs a warning. The target remains tracked as hooked
         *       because the leaked backend is still physically installed. The containment is safe but the leak is real
         *       and permanent, so prefer the correct order. To make it correct by construction rather than by
         *       discipline (no leak, no warning), hold the handles in a @ref HookStack, which always tears down
         *       newest-first.
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
             * @note Explicitly noexcept (a destructor is implicitly noexcept already): this runs from
             *       DLL_PROCESS_DETACH / loader-lock teardown where an escaping exception terminates the host, so the
             *       no-throw contract is pinned at the declaration and every path inside fails closed.
             */
            ~Hook() noexcept;

            /// True while this handle owns a live hook (false after a move-out or @ref release).
            [[nodiscard]] explicit operator bool() const noexcept;

            /// The hook's registered name (empty for a moved-from / released handle).
            [[nodiscard]] std::string_view name() const noexcept;

            /// True when the hook is currently armed (its detour is active).
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
             * @details The opt-in safety twin of @ref original, modelled on SafetyHook's own call/unsafe_call split.
             *          It pins a refcounted per-hook control block (the call gate: a recursive_mutex plus the currently
             *          callable trampoline, published under that mutex) into a local strong reference BEFORE locking,
             *          then holds the mutex across the trampoline invocation. Two properties follow. First, a
             *          concurrent @ref enable / @ref disable / ~Hook / @ref operator=(Hook&&) that drops the handle's
             *          own reference cannot free the gate itself while this call is entering: the local strong
             *          reference keeps the gate (its mutex and its published-callable slot) alive until the call
             *          returns, so a caller stalled just before locking still finds a live mutex to lock and a live
             *          slot to read. A teardown that wins the race publishes a null callable under the mutex, so a
             *          late caller reads null and fails closed to the inactive default rather than dispatching through
             *          a freed trampoline. Second, the trampoline's own liveness comes from the mutex, not the gate
             *          reference: a teardown frees the backend trampoline only after acquiring that same mutex and
             *          nulling the callable, and this call holds the mutex across the dispatch, so a teardown cannot
             *          free the trampoline while a call is in-flight. Reach for it when the hook can be torn down
             *          (dynamically unloaded) while another thread is calling through it; for the common
             *          hook-outlives-the-process case, @ref original is cheaper.
             *
             *          Lifetime precondition: the Hook object itself must outlive the call. The gate refcount keeps
             *          the trampoline and mutex alive across a concurrent teardown, but reading this handle to reach
             *          the gate is still an ordinary member access, so a caller must not race the destruction of the
             *          `Hook` object's storage. Teardown work (restoring the prologue, freeing the trampoline) may run
             *          concurrently with a call; only the handle's storage must remain alive until the member call has
             *          copied the gate.
             *
             *          Parameters are `Args... args` BY VALUE (not a forwarding reference): for an lvalue argument a
             *          forwarding reference would deduce `Args` as a reference type, making the reconstructed
             *          `Ret(*)(Args...)` a reference-parameter function-pointer type that passes a hidden pointer
             *          where the real by-value trampoline expects the scalar -- silent, value-category-dependent ABI
             *          UB. By value, the reconstructed `Ret(*)(Args...)` is the true by-value signature; args... are
             *          passed directly with no std::forward. The caller must still supply argument types matching the
             *          original's real signature; call cannot validate them. The guard blocks teardown from STARTING
             *          during a call but cannot drain a thread already inside the original's body.
             * @note Not marked [[nodiscard]]: with the default Ret = void the attribute is inert, and firing it only
             *       for non-void instantiations would be surprising and inconsistent with the backend, which marks no
             *       call-family method [[nodiscard]].
             */
            template <typename Ret = void, typename... Args> Ret call(Args... args) const
            {
                // Pin the gate, take its lock, and resolve the live trampoline through the shared @ref GuardedDispatch
                // protocol; a null trampoline is any fail-closed path (disengaged handle, lock failure, torn-down or
                // not-yet-armed hook), for which call returns the value-initialized default a caller cannot tell apart
                // from a genuine one. The lock and pinned gate stay held for the object's lifetime, so the trampoline
                // cannot be freed under this dispatch.
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
                // By-value reconstruction (see the parameter note): Ret(*)(Args...) is the real by-value C ABI, and
                // args... are passed straight through with no std::forward.
                return reinterpret_cast<Ret (*)(Args...)>(dispatch.trampoline)(args...);
            }

            /**
             * @brief The fail-closed-distinguishing sibling of @ref call: dispatches through the original and reports
             *        whether the guarded gate actually let the call through.
             * @tparam Ret The original's return type (default void), reconstructed by value exactly as in @ref call.
             * @tparam Args The original's parameter types, taken BY VALUE for the same ABI reason @ref call documents
             *         (a forwarding reference would deduce a reference type and corrupt the reconstructed
             *         `Ret(*)(Args...)` signature).
             * @return The original's return value on a dispatched call. On any fail-closed path -- a disengaged handle
             *         (moved-from or released), a call-lock acquisition failure, or a torn-down / disabled /
             *         not-yet-armed trampoline -- an InvalidHookState error. That is the whole point: @ref call
             *         collapses every one of those into a value-initialized `Ret{}` a caller cannot tell apart from a
             *         genuine `Ret{}` the original returned, whereas try_call keeps "the gate refused the call" in the
             *         error channel.
             * @details Runs the identical pin-gate / acquire-lock / read-trampoline protocol as @ref call; only the
             *          return channel differs. Reach for it when a value-initialized `Ret` is a legal result of the
             *          original (a query that can legitimately return `0` / `nullptr` / `false`) and a suppressed call
             *          must not be mistaken for that result. `try_call<void>()` still reports whether the call
             *          dispatched. It offers no stronger call-site guarantee than @ref call: it takes the same one
             *          bounded internal lock, so it is callback-safe on exactly the same terms.
             * @note Callback-safe on the same terms as @ref call: it takes one bounded internal lock and performs no
             *       allocation or I/O before dispatching.
             */
            template <typename Ret = void, typename... Args> [[nodiscard]] Result<Ret> try_call(Args... args) const
            {
                // Same @ref GuardedDispatch protocol as @ref call; only the fail-closed report differs: a null
                // trampoline (any suppressed path) becomes an InvalidHookState error instead of a value-initialized
                // Ret.
                const GuardedDispatch dispatch{*this};
                if (dispatch.trampoline == nullptr)
                {
                    return std::unexpected(Error{ErrorCode::InvalidHookState, "hook::try_call"});
                }
                if constexpr (std::is_void_v<Ret>)
                {
                    // A void original still reports dispatch success: run it, then return the valued Result<void>.
                    reinterpret_cast<void (*)(Args...)>(dispatch.trampoline)(args...);
                    return {};
                }
                else
                {
                    return reinterpret_cast<Ret (*)(Args...)>(dispatch.trampoline)(args...);
                }
            }

            /**
             * @brief Arms the hook.
             * @return Success if the hook is now active (or already was). On failure the Error carries the reason
             *         (BackendFailed, EnableFailed, InvalidHookState).
             * @details Idempotent via an atomic CAS status machine; thread-safe without external synchronization. An
             *          intermediate Enabling state prevents another thread from observing a speculative terminal
             *          state while the backend enable is in progress.
             */
            [[nodiscard]] Result<void> enable() noexcept;

            /**
             * @brief Disarms the hook without destroying it.
             * @return Success if the hook is now disabled (or already was). On failure the Error carries the reason
             *         (BackendFailed, DisableFailed, InvalidHookState).
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
             * @brief The refcounted per-hook call guard (recursive_mutex + published trampoline) defined in
             *        src/internal/hook_backend.hpp.
             * @details Held behind a shared_ptr so a late @ref call keeps the mutex and trampoline alive after the
             *          handle's teardown drops its own reference; see @ref call and the CallGate definition.
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
             * @details Constructing it runs the three-stage protocol both call-family methods need: pin the refcounted
             *          gate into a local strong reference (so a concurrent ~Hook / operator=(Hook&&) cannot free the
             *          gate's mutex or the published trampoline while this call is entering), take that gate's
             *          recursive lock, and read the published trampoline under the lock. Any stage that fails closed
             *          leaves @ref trampoline null: a disengaged handle (moved-from / released) has an empty gate; a
             *          recursive_mutex::lock failure yields an unowned lock (acquire_call_lock is noexcept and never
             *          lets a std::system_error escape); a torn-down / disabled / not-yet-armed hook publishes a null
             *          callable. On success it retains the strong gate reference and the held lock for the object's
             *          lifetime, so the backend cannot free the trampoline under an in-flight dispatch. call and
             *          try_call then diverge only in how they report a null trampoline.
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
         * @details Layering two inline/mid hooks on the same target address chains their trampolines: the newer hook
         *          patches the prologue that already holds the older hook's jump, so the newer trampoline resumes into
         *          the older hook's body. Restoring the older hook first therefore writes the pristine prologue back
         *          over a site the newer hook's live trampoline still chains through -- a use-after-free the moment the
         *          newer hook is next called or itself torn down. The only safe unwind is strictly newest-first.
         *
         *          A bare `std::vector<Hook>` has no newest-first teardown contract. A container that destroys or
         *          overwrites layered hooks in storage order tries to restore the older layer while the newer layer is
         *          still live. The process-wide ledger detects that inversion: @ref Hook::~Hook then LEAKS the older
         *          backend rather than restoring it (keeping the newer layer's trampoline chain valid), keeps the
         *          target tracked as hooked, and logs a warning (see the teardown-ordering note on @ref Hook). That
         *          contains the use-after-free, but the leak is real and permanent. HookStack closes the gap at the type
         *          level: it always restores its hooks back-to-front, so a newer layer owned by the stack is unhooked
         *          before the one beneath it. When the stack owns the complete same-target layer set and hooks were
         *          pushed in creation order, neither the leak nor the ledger warning can occur for those hooks. Reach
         *          for it whenever several hooks are kept alive together -- especially any layered on one address, or
         *          the successful hooks returned by @ref install_all (push them in table order) -- instead of a bare
         *          vector, so the destroy order is correct by construction rather than by caller discipline.
         *
         *          Scope is inline/mid @ref Hook handles only. @ref VmtHook already restores its applied objects
         *          newest-first inside its own destructor and is not order-tracked by the ledger, so it needs no
         *          external ordering wrapper.
         * @note Move-only, mirroring @ref Hook: a stack cannot be copied, and moving one leaves the source empty. Not
         *       internally synchronized: build and tear it down on the setup thread, exactly like the hooks it holds.
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
         * @brief Installs an inline hook at the request's target.
         * @tparam Fn The detour's function type; the function-to-void* cast happens here, once, behind a word-size
         *         static_assert, so the call site never writes a reinterpret_cast.
         * @param request Name, target (absolute or deferred scan), and policy.
         * @param detour Pointer to the detour function.
         * @return The RAII @ref Hook on success, or an Error.
         */
        template <class Fn> [[nodiscard]] Result<Hook> inline_at(InlineRequest request, Fn *detour)
        {
            static_assert(sizeof(Fn *) == sizeof(void *), "function pointer must be word-sized");
            return detail::inline_at_raw(std::move(request), reinterpret_cast<void *>(detour));
        }

        /**
         * @brief Installs a mid-function hook at the request's target.
         * @param request Name, target (absolute or deferred scan), and policy.
         * @param detour The DMK-typed mid-hook detour (keeps its MidHookFn type; no raw cast at the call site).
         * @return The RAII @ref Hook on success, or an Error.
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
         * @brief Installs a whole declarative table of hooks, returning one outcome per row.
         * @param table The spec rows. Taken as a const span so a `const k_hook_table` binds; install_all copies each
         *        OwnedScanRequest it needs and never moves out of the caller's table.
         * @return The per-row outcomes on success. The outer Result fails fast on the FIRST @ref Severity::Mandatory
         *         miss (an all-Mandatory table short-circuits); otherwise it succeeds and every row's status is in the
         *         vector.
         * @details noexcept, matching scan::resolve_batch: it catches bad_alloc / backend failure internally and
         *          reports it per row rather than throwing across the init path.
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
         * @details Consults the process-wide ledger only; it is the exact same-kit query, not the foreign-JMP
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
         * @return The RAII @ref VmtHook on success, or an Error (InvalidObject, HookAlreadyExists, BackendFailed).
         */
        [[nodiscard]] Result<VmtHook> vmt_for(std::string name, void *object, VmtOptions options = {});

        /**
         * @class VmtHook
         * @brief Move-only RAII handle for a cloned (hooked) vtable applied to one or more live objects.
         * @details VMT hooking is many-to-many (one cloned vtable, applied to M live objects) and has NO
         *          enable/disable (a backend VmtHook limitation), so it is a dedicated owning type rather than a flat
         *          @ref Hook. @ref vmt_for clones the seed object's vtable; @ref apply_to swaps the clone onto another
         *          object of the same class; the destructor restores every patched vptr (newest-first across applied
         *          objects). Individual virtual methods are redirected with @ref hook_method (by vtable index), the
         *          pre-hook slot is recovered typed with @ref original, and a single method hook is lifted with
         *          @ref remove_method. Because the redirect lives in the one cloned vtable, a @ref hook_method takes
         *          effect on every object the clone is currently applied to, and a later @ref apply_to inherits it.
         * @warning Restoring a vptr is a bare pointer write with no thread protection: the caller must guarantee no
         *          thread is dispatching through a cloned slot across create/apply/remove, that each applied object
         *          outlives the hook, and that the object's vptr was not re-layered since the clone went on.
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
             * @brief Restores the original vptr on every applied object (newest-first), unless released or moved-from.
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
             * @return Success, or an Error (InvalidObject, HookAlreadyExists, BackendFailed).
             * @warning Swapping @p object's vptr is a bare pointer write with no dispatch-time synchronization (the
             *          class @warning covers the full contract): it is safe only while no thread is dispatching a
             *          virtual call through @p object. Apply during setup or a host-quiesced window, not against an
             *          object a game thread is actively calling into.
             */
            [[nodiscard]] Result<void> apply_to(void *object, VmtOptions options = {});

            /**
             * @brief Restores the original vptr on one applied object.
             * @param object The object to restore.
             * @return Success, or InvalidObject for a null @p object / InvalidHookState for a disengaged handle.
             * @details Best-effort restore: removing an object that is not on this clone is a harmless no-op, so a
             *          successful return does not assert that @p object was previously applied.
             * @warning Restoring @p object's vptr is a bare pointer write with no protection against an in-flight
             *          dispatch through the slot (see the class @warning): quiesce the object, or restore only at a
             *          safe host-shutdown point, before removing it.
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
             *       under the exclusive write lock. Like every VMT restore this is a bare pointer write with no thread
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
