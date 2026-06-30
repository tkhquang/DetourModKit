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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
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
         * @brief Escalation policy for the inline/mid hook prologue pre-flight.
         * @details The pre-flight fault-guard-reads the target's first byte. A leading 0xE8 (call rel32) means the
         *          5-byte E9 patch would steal a relative call whose displacement was computed from the original
         *          site, so the relocated trampoline copy can dispatch the call to the wrong absolute target; a
         *          leading 0xCC/0xCD (int3 / int n breakpoint) means the slot is already a breakpoint stub, a patched
         *          byte, or alignment padding, not a real function body. @ref Relocate logs and installs anyway;
         *          @ref Fail refuses the create with @ref ErrorCode::TargetPrologueUnsafe.
         * @note The library DEFAULT is Fail (safe-by-default): a non-relocatable prologue fails the install rather
         *       than installing a hook that can dispatch to the wrong target. Opt into install-anyway with
         *       `Options{.prologue = Prologue::Relocate}`.
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
             *          address, then falls back to a foreign-JMP prologue heuristic (an E9 rel32 or FF25 indirect jump
             *          already at the site, decoded under a fault guard). The default (false) installs anyway and the
             *          new hook simply layers on top.
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
         * @note Teardown ordering: when two hooks are layered on the SAME target address, the newer one must be
         *       destroyed first (it saved the older hook's jump as its own original bytes). Natural reverse-order
         *       destruction of stack/member handles satisfies this automatically; if you store layered same-target
         *       handles in a container whose destruction order is not creation-reverse, destroy them newest-first.
         *       The ledger detects and warns on a violation.
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
             *          It holds DMK's OWN per-hook recursive_mutex across the trampoline invocation, so @ref enable,
             *          @ref disable, and ~Hook cannot run concurrently and free the trampoline mid-call. Reach for it
             *          when the hook can be torn down (dynamically unloaded) while another thread is calling through
             *          it; for the common hook-outlives-the-process case, @ref original is cheaper.
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
                // A disengaged handle (moved-from or released) has no Impl and therefore no call_mutex to lock; return
                // the inactive default here so call() matches the null-tolerance of original()/active_trampoline()
                // instead of dereferencing a null Impl inside acquire_call_lock().
                if (!m_impl)
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
                // Hold DMK's own per-hook guard for the whole invocation so a concurrent disable()/~Hook on another
                // thread blocks until the call returns, instead of freeing the trampoline under our feet.
                std::unique_lock<std::recursive_mutex> guard = acquire_call_lock();
                void *trampoline = active_trampoline();
                if (trampoline == nullptr)
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
                return reinterpret_cast<Ret (*)(Args...)>(trampoline)(args...);
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
            explicit Hook(std::unique_ptr<Impl> impl) noexcept;

            /// Raw inline trampoline (or nullptr); the UNGUARDED backend touch behind original<Fn>(). Defined in .cpp.
            [[nodiscard]] void *original_address() const noexcept;

            /// Locks DMK's per-hook recursive_mutex and returns the owning token; the call() guard. Defined in .cpp.
            [[nodiscard]] std::unique_lock<std::recursive_mutex> acquire_call_lock() const;

            /// Inline trampoline if the hook is active, else nullptr; read with the call lock held. Defined in .cpp.
            [[nodiscard]] void *active_trampoline() const noexcept;

            std::unique_ptr<Impl> m_impl;

            friend Result<Hook> mid_at(MidRequest request, MidHookFn detour);
            friend Result<Hook> detail::inline_at_raw(InlineRequest request, void *detour);
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
         *          writes a reinterpret_cast and the mid case never loses its type.
         */
        class HookSpec
        {
        public:
            /**
             * @brief Builds an inline-hook row; performs the single audited function-to-void* cast.
             * @tparam Fn The detour's function type (word-size static_assert).
             */
            template <class Fn>
            [[nodiscard]] static HookSpec inline_hook(std::string name, scan::OwnedScanRequest target, Fn *detour,
                                                      Severity severity = Severity::Mandatory)
            {
                static_assert(sizeof(Fn *) == sizeof(void *), "function pointer must be word-sized");
                return HookSpec{std::move(name), std::move(target), InlineDetour{reinterpret_cast<void *>(detour)},
                                severity};
            }

            /// Builds a mid-hook row; the MidHookFn stays typed, no cast.
            [[nodiscard]] static HookSpec mid_hook(std::string name, scan::OwnedScanRequest target, MidHookFn detour,
                                                   Severity severity = Severity::Mandatory)
            {
                return HookSpec{std::move(name), std::move(target), detour, severity};
            }

            [[nodiscard]] std::string_view name() const noexcept { return m_name; }
            [[nodiscard]] Severity severity() const noexcept { return m_severity; }

        private:
            HookSpec(std::string name, scan::OwnedScanRequest target, std::variant<InlineDetour, MidHookFn> detour,
                     Severity severity) noexcept
                : m_name(std::move(name)), m_target(std::move(target)), m_detour(std::move(detour)),
                  m_severity(severity)
            {
            }

            std::string m_name;
            scan::OwnedScanRequest m_target;
            /// Inline vs mid is encoded by the active alternative.
            std::variant<InlineDetour, MidHookFn> m_detour;
            Severity m_severity;

            friend Result<std::vector<InstallOutcome>> install_all(std::span<const HookSpec> table) noexcept;
        };

        /**
         * @struct InstallOutcome
         * @brief Per-row result of @ref install_all, in table order, so a mod can correlate which optional hooks
         *        landed.
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
         */
        [[nodiscard]] Result<std::vector<InstallOutcome>> install_all(std::span<const HookSpec> table) noexcept;

        /**
         * @brief Reports whether a DMK hook (this kit) currently patches @p target.
         * @details Consults the process-wide ledger only; it is the exact same-kit query, not the foreign-JMP
         *          heuristic. Hooks installed by other statically-linked DMK consumers in the same process are not
         *          visible. Use it to short-circuit a redundant install; to also catch foreign hooks, set
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
         *          objects). A per-method typed hook surface (`hook_method<Fn>` / `original<T>(index)`) and a
         *          lock-free apply_to reader are deferred to a later release; this handle provides the object-level
         *          clone lifecycle with the documented thread-safety limitations below.
         * @warning Restoring a vptr is a bare pointer write with no thread protection: the caller must guarantee no
         *          thread is dispatching through a cloned slot across create/apply/remove, that each applied object
         *          outlives the hook, and that the object's vptr was not re-layered since the clone went on.
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
             */
            [[nodiscard]] Result<void> apply_to(void *object, VmtOptions options = {});

            /**
             * @brief Restores the original vptr on one applied object.
             * @param object The object to restore.
             * @return Success, or InvalidObject for a null @p object / InvalidHookState for a disengaged handle.
             * @details Best-effort restore: removing an object that is not on this clone is a harmless no-op, so a
             *          successful return does not assert that @p object was previously applied.
             */
            [[nodiscard]] Result<void> remove_from(void *object);

            /// Detaches the cloned vtable for the process lifetime (no vptr is restored; handle becomes disengaged).
            void release() noexcept;

        private:
            struct Impl;
            explicit VmtHook(std::unique_ptr<Impl> impl) noexcept;
            std::unique_ptr<Impl> m_impl;

            friend Result<VmtHook> vmt_for(std::string name, void *object, VmtOptions options);
        };
    } // namespace hook
} // namespace DetourModKit

#endif // DETOURMODKIT_HOOK_HPP
