#ifndef DETOURMODKIT_INTERNAL_HOOK_BACKEND_HPP
#define DETOURMODKIT_INTERNAL_HOOK_BACKEND_HPP

/**
 * @file internal/hook_backend.hpp
 * @brief Backend-coupled pimpl bodies and the process-wide allocator for the hook subsystem.
 * @details This is the only DetourModKit header that names the SafetyHook backend. hook.hpp forward-declares the
 *          nested Impl of every backend-owning handle (Hook, VmtHook) and holds it behind a std::unique_ptr; those
 *          Impl bodies are completed here, where safetyhook.hpp is visible. It is never installed and only
 *          src/hook.cpp includes it, so the backend (and the Zydis headers it drags in) stays confined to that single
 *          translation unit. A public consumer that includes hook.hpp pulls in none of it.
 *
 *          The opaque hook::MidContext bridge is deliberately NOT defined here. MidContext must stay an incomplete
 *          type in every translation unit so that the backend-context <-> MidContext reinterpret_cast remains a pure
 *          pass-through; the casts therefore live in the accessor function bodies in src/hook.cpp, never as a type
 *          definition.
 */

#include "DetourModKit/hook.hpp"

#include "internal/srw_shared_mutex.hpp"

#include "safetyhook.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>

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
         * @details The guarded @ref Hook::call must survive a concurrent teardown that frees the backend trampoline.
         *          It cannot do that if the mutex it locks lives inside the same @ref Hook::Impl the teardown
         *          destroys, because a caller stalled just before acquiring the lock would then dereference freed
         *          storage. The gate breaks that coupling: it holds only the per-hook recursive_mutex and the
         *          currently-callable trampoline pointer, is owned by a shared_ptr that @ref Hook::call copies into a
         *          local strong reference BEFORE locking, and is therefore kept alive by any in-flight call even after
         *          the handle drops its own reference during teardown. The trampoline is published under the mutex, so
         *          a late caller that acquires the lock after teardown reads a nullptr callable and fails closed to the
         *          inactive default instead of dispatching through a trampoline the backend destructor has freed.
         *
         *          The mutex is recursive because a detour may re-enter @ref Hook::call on the same handle (the
         *          original it calls can itself be hooked). `callable` is the inline trampoline while the hook is armed
         *          and inline, and nullptr otherwise: a disabled hook, a mid hook, or a normally torn-down hook (~Hook
         *          nulls it under `mutex` before freeing the backend). The one exception is the loader-lock teardown
         *          branch, which intentionally leaks the backend with the module pinned and LEAVES `callable` set, so a
         *          late guarded @ref Hook::call through a still-pinned gate keeps dispatching to the leaked-but-live
         *          trampoline. It is a plain pointer guarded by `mutex`, not an atomic, because every reader and writer
         *          holds `mutex`.
         */
        struct Hook::CallGate
        {
            std::recursive_mutex mutex;
            void *callable{nullptr};
        };

        /**
         * @brief The complete backend state behind a @ref Hook handle.
         * @details Holds the backend inline OR mid hook in a variant (inline vs mid is the active alternative), the
         *          atomic enable/disable status, the registered name, the patched target address, and the ledger id
         *          used to deregister on teardown. The per-hook recursive_mutex that serializes call/enable/disable/
         *          teardown lives in a separate refcounted @ref Hook::CallGate (not here) so a late @ref Hook::call
         *          keeps the mutex alive after this Impl is destroyed; see that type. The atomic status makes Impl
         *          non-movable, which is why it lives behind a unique_ptr.
         */
        struct Hook::Impl
        {
            std::variant<safetyhook::InlineHook, safetyhook::MidHook> backend;
            std::atomic<HookState> status;
            std::string name;
            std::uintptr_t target{0};
            std::uint64_t ledger_id{0};
            bool is_inline{false};

            Impl(safetyhook::InlineHook hook, std::string hook_name, std::uintptr_t hook_target, std::uint64_t ledger,
                 HookState initial_state)
                : backend(std::move(hook)), status(initial_state), name(std::move(hook_name)), target(hook_target),
                  ledger_id(ledger), is_inline(true)
            {
            }

            Impl(safetyhook::MidHook hook, std::string hook_name, std::uintptr_t hook_target, std::uint64_t ledger,
                 HookState initial_state)
                : backend(std::move(hook)), status(initial_state), name(std::move(hook_name)), target(hook_target),
                  ledger_id(ledger), is_inline(false)
            {
            }
        };

        /**
         * @brief The complete backend state behind a @ref VmtHook handle.
         * @details Owns the backend VMT hook (the cloned vtable), the registered name, the cloned-vptr base recorded
         *          at create (so an apply can tell "already on my clone" from "on another hook's clone"), the number
         *          of callable slots in the clone, the ledger id, and the per-index method-hook table.
         *
         *          Per-method hooks are backend VmHooks keyed by vtable index. Each VmHook, on destruction, rewrites
         *          its cloned-vtable slot back to the original function pointer, so erasing an entry (@ref
         *          VmtHook::remove_method) or destroying the map (handle teardown) restores that method. The map is
         *          declared last so it is destroyed first: method slots in the clone are restored before `backend`
         *          restores each applied object's vptr off the clone entirely -- the intuitive unhook-methods-then-
         *          unapply-objects order (either order is memory-safe because the clone allocation is a shared_ptr
         *          kept alive by both the VmtHook and every VmHook).
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
            safetyhook::VmtHook backend;
            std::string name;
            std::uintptr_t cloned_vptr_base{0};
            std::size_t method_count{0};
            std::uint64_t ledger_id{0};
            mutable DetourModKit::detail::SrwSharedMutex method_mutex;
            std::unordered_map<std::size_t, safetyhook::VmHook> method_hooks;

            Impl(safetyhook::VmtHook hook, std::string hook_name, std::uintptr_t base, std::size_t methods,
                 std::uint64_t ledger)
                : backend(std::move(hook)), name(std::move(hook_name)), cloned_vptr_base(base), method_count(methods),
                  ledger_id(ledger)
            {
            }
        };

        /**
         * @brief Returns the process-wide SafetyHook allocator shared by every hook this kit installs.
         * @details One allocator per process, kept behind this accessor (a function-local static, lazily and
         *          thread-safely initialized). The returned shared_ptr is empty only if the backend could not provide
         *          a global allocator, which the create paths report as ErrorCode::AllocatorNotAvailable.
         */
        [[nodiscard]] const std::shared_ptr<safetyhook::Allocator> &backend_allocator() noexcept;
    } // namespace hook
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_HOOK_BACKEND_HPP
