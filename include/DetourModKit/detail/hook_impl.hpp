#ifndef DETOURMODKIT_DETAIL_HOOK_IMPL_HPP
#define DETOURMODKIT_DETAIL_HOOK_IMPL_HPP

/**
 * @file detail/hook_impl.hpp
 * @brief Backend-coupled pimpl bodies for the hook subsystem.
 * @details This is the ONLY DetourModKit header that names the SafetyHook backend. hook_manager.hpp forward-declares
 *          the nested Impl of every backend-owning class (InlineHook, MidHook, detail::VmtHookEntry, HookManager) and
 *          holds it behind a std::unique_ptr; those Impl bodies are completed here, where safetyhook.hpp is visible.
 *          Only src/hook_manager.cpp includes this header, so the backend (and the Zydis headers it drags in) stays
 *          confined to that single translation unit. A public consumer that includes hook_manager.hpp pulls in none of
 *          it.
 *
 *          The opaque hook::MidContext bridge is deliberately NOT defined here. MidContext must stay
 *          an incomplete type in every translation unit so that the Context64 <-> MidContext reinterpret_cast remains a
 *          pure pass-through; the casts therefore live in the accessor function bodies in hook_manager.cpp, never as a
 *          type definition.
 */

#include "DetourModKit/hook_manager.hpp"

#include "safetyhook.hpp"

#include <memory>
#include <utility>

namespace DetourModKit
{
    /// Owns the backend inline-hook object for a managed InlineHook.
    struct InlineHook::Impl
    {
        safetyhook::InlineHook hook;
        explicit Impl(safetyhook::InlineHook h) : hook(std::move(h)) {}
    };

    /// Owns the backend mid-hook object for a managed MidHook.
    struct MidHook::Impl
    {
        safetyhook::MidHook hook;
        explicit Impl(safetyhook::MidHook h) : hook(std::move(h)) {}
    };

    /**
     * @brief Owns the HookManager's shared backend allocator.
     * @details Carried behind a pimpl so the allocator's type never appears in the public header.
     */
    struct HookManager::Impl
    {
        std::shared_ptr<safetyhook::Allocator> allocator;
    };

    namespace detail
    {
        /**
         * @brief Owns the backend VMT hook (the cloned vtable) for a VmtHookEntry.
         * @details The per-method hook layer is deferred until reintroduced, so only the object-level clone is stored
         *          here.
         */
        struct VmtHookEntry::Impl
        {
            safetyhook::VmtHook hook;
            explicit Impl(safetyhook::VmtHook h) : hook(std::move(h)) {}
        };
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_DETAIL_HOOK_IMPL_HPP
