#ifndef DETOURMODKIT_INTERNAL_HOOK_BACKEND_VISIT_HPP
#define DETOURMODKIT_INTERNAL_HOOK_BACKEND_VISIT_HPP

/**
 * @file internal/hook_backend_visit.hpp
 * @brief Nothrow visitation and toggle primitives over the inline/mid backend variant.
 * @details The hook sibling TUs (src/hook.cpp and src/hook_toggle.cpp) share these helpers, so each visitation and
 *          exception-containment contract is stated exactly once. Every helper is noexcept and contains backend
 *          synchronization or allocation exceptions at this boundary.
 */

#include "internal/hook_patch_witness.hpp"

#include <safetyhook.hpp>

#include <atomic>
#include <cstddef>
#include <type_traits>
#include <utility>
#include <variant>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    // Overrides the byte witness Hook::enable() takes after the backend reports a successful patch. The suite can
    // then drive the negative branch a real backend does not produce on demand.
    extern bool (*g_hook_enable_witness_override)(bool) noexcept;
    // Runs after a managed backend disable returns or throws and before DMK witnesses its target bytes.
    extern void (*g_hook_backend_disable_probe)() noexcept;
    // Counts managed backend toggle exceptions the containment boundaries below reached and contained.
    extern std::atomic<std::size_t> g_backend_toggle_exception_catches;
#endif

    /**
     * @brief Returns the inline trampoline pointer for a hook backend, or nullptr for a mid hook / empty backend.
     * @details The @ref hook::Hook::CallGate publishes this value while an inline hook is armed.
     */
    [[nodiscard]] inline void *
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
    template <typename ValueT, typename BackendVariant, typename Visitor>
    [[nodiscard]] ValueT backend_value_or(BackendVariant &backend, ValueT fallback, Visitor &&visitor) noexcept
    {
        using InlineReference = decltype(*std::get_if<safetyhook::InlineHook>(&backend));
        using MidReference = decltype(*std::get_if<safetyhook::MidHook>(&backend));
        static_assert(std::is_nothrow_invocable_r_v<ValueT, Visitor, InlineReference>);
        static_assert(std::is_nothrow_invocable_r_v<ValueT, Visitor, MidReference>);

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

    /**
     * @brief Reports whether the backend left this hook's own patch armed after a target toggle.
     * @details enable() publishes Active only for bytes it can attribute to itself.
     */
    template <class Backend> [[nodiscard]] bool enable_patch_is_confirmed(const Backend &backend) noexcept
    {
        const bool confirmed = backend.enabled() && detail::witness_patch(backend) == detail::PatchWitness::OwnedPatch;
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
            DetourModKit::detail::g_backend_toggle_exception_catches.fetch_add(1, std::memory_order_relaxed);
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
            DetourModKit::detail::g_backend_toggle_exception_catches.fetch_add(1, std::memory_order_relaxed);
            if (auto *probe = DetourModKit::detail::g_hook_backend_disable_probe)
            {
                probe();
            }
#endif
            return false;
        }
    }

    /// Returns the current target-byte witness, or Indeterminate when no backend is reachable.
    template <class BackendVariant> [[nodiscard]] detail::PatchWitness witness_of(BackendVariant &backend) noexcept
    {
        return backend_value_or(
            backend,
            detail::PatchWitness::Indeterminate,
            [](auto &one) noexcept { return detail::witness_patch(one); }
        );
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_HOOK_BACKEND_VISIT_HPP
