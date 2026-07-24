#ifndef DETOURMODKIT_INTERNAL_HOOK_BACKEND_HPP
#define DETOURMODKIT_INTERNAL_HOOK_BACKEND_HPP

/**
 * @file internal/hook_backend.hpp
 * @brief Backend-coupled pimpl bodies and the per-instance allocator for the hook subsystem.
 * @details hook.hpp forward-declares the nested Impl of every backend-owning handle (Hook, VmtHook) and holds it behind
 *          a std::unique_ptr; those Impl bodies are completed here, where safetyhook.hpp is visible. This and
 *          internal/mid_hook_adapter.hpp are the only DetourModKit headers that name the SafetyHook backend; neither is
 *          installed and only src/hook.cpp includes either, so the backend (and the Zydis headers it drags in) stays
 *          confined to that single translation unit. A public consumer that includes hook.hpp pulls in none of it.
 *
 *          The opaque hook::MidContext bridge is deliberately NOT defined here. MidContext must stay an incomplete
 *          type in every translation unit so that the backend-context <-> MidContext reinterpret_cast remains a pure
 *          pass-through; the casts therefore live in the accessor function bodies in src/hook.cpp, never as a type
 *          definition.
 */

#include "DetourModKit/hook.hpp"

#include "internal/srw_shared_mutex.hpp"

#include <safetyhook.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
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
            // Counted reference on the module this hook's trampoline/detour code lives in, taken before the backend is
            // published while the module is mapped. ~Hook releases it on the clean off-loader-lock teardown; on a leak
            // branch it rides along with the leaked Impl (never released), keeping the trampoline mapped for a late
            // foreign caller. Holds an HMODULE (kept as void* so the acquire/release stay in hook.cpp). See
            // detail::acquire_module_ref.
            void *self_ref{nullptr};

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
            std::unordered_map<std::size_t, safetyhook::VmHook> method_hooks;

            Impl(safetyhook::VmtHook hook, std::string hook_name, std::uintptr_t base, std::size_t methods,
                 std::uint64_t ledger)
                : backend(std::move(hook)), name(std::move(hook_name)), cloned_vptr_base(base), method_count(methods),
                  ledger_id(ledger)
            {
            }
        };

        /**
         * @brief Returns the SafetyHook allocator shared by every hook this linked instance installs.
         * @details The reference is a refcount hold on the backend's allocator that keeps the trampoline arena mapped,
         *          and it is deliberately never released: a hook owned by a namespace-scope object runs ~Impl during
         *          static destruction and would otherwise free its trampoline into an already-destroyed arena. The
         *          returned shared_ptr is empty only if the backend could not provide a global allocator, which the
         *          create paths report as ErrorCode::AllocatorNotAvailable.
         */
        [[nodiscard]] const std::shared_ptr<safetyhook::Allocator> &backend_allocator() noexcept;
    } // namespace hook
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_HOOK_BACKEND_HPP
