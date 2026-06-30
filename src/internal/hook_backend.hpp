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

#include "safetyhook.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
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
         * @brief The complete backend state behind a @ref Hook handle.
         * @details Holds the backend inline OR mid hook in a variant (inline vs mid is the active alternative), DMK's
         *          own per-hook recursive_mutex (the @ref Hook::call guard, also taken by enable/disable/teardown so
         *          none can race a call), the atomic enable/disable status, the registered name, the patched target
         *          address, and the ledger id used to deregister on teardown. The recursive_mutex and the atomic make
         *          Impl non-movable, which is why it lives behind a unique_ptr.
         */
        struct Hook::Impl
        {
            std::variant<safetyhook::InlineHook, safetyhook::MidHook> backend;
            std::recursive_mutex call_mutex;
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
         *          at create (so an apply can tell "already on my clone" from "on another hook's clone"), and the
         *          ledger id.
         */
        struct VmtHook::Impl
        {
            safetyhook::VmtHook backend;
            std::string name;
            std::uintptr_t cloned_vptr_base{0};
            std::uint64_t ledger_id{0};

            Impl(safetyhook::VmtHook hook, std::string hook_name, std::uintptr_t base, std::uint64_t ledger)
                : backend(std::move(hook)), name(std::move(hook_name)), cloned_vptr_base(base), ledger_id(ledger)
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
