#ifndef DETOURMODKIT_INTERNAL_HOOK_BACKEND_VISIT_HPP
#define DETOURMODKIT_INTERNAL_HOOK_BACKEND_VISIT_HPP

/**
 * @file internal/hook_backend_visit.hpp
 * @brief Nothrow visitation, toggle, and drain primitives over the inline/mid backend variant.
 * @details The hook sibling TUs (src/hook.cpp, src/hook_toggle.cpp, and src/hook_retirement.cpp) share these
 *          helpers, so each visitation and exception-containment contract is stated exactly once. The XInput route
 *          retirement in src/internal/input_intercept.cpp shares the residue budget. Every helper is noexcept and
 *          contains backend synchronization or allocation exceptions at this boundary.
 */

#include "internal/hook_patch_witness.hpp"

#include <safetyhook.hpp>

#include <intrin.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_view>
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

    /// Names a backend toggle refusal that the process route coordinator decided before any mutation.
    enum class CoordinatorRefusal : std::uint8_t
    {
        None,
        LayerConflict,
        Unavailable,
    };

    [[nodiscard]] inline CoordinatorRefusal coordinator_refusal(const safetyhook::InlineHook::Error &error) noexcept
    {
        switch (error.type)
        {
        case safetyhook::InlineHook::Error::LAYER_CONFLICT:
            return CoordinatorRefusal::LayerConflict;
        case safetyhook::InlineHook::Error::COORDINATION_UNAVAILABLE:
            return CoordinatorRefusal::Unavailable;
        default:
            return CoordinatorRefusal::None;
        }
    }

    [[nodiscard]] inline CoordinatorRefusal coordinator_refusal(const safetyhook::MidHook::Error &error) noexcept
    {
        return error.type == safetyhook::MidHook::Error::BAD_INLINE_HOOK ? coordinator_refusal(error.inline_hook_error)
                                                                         : CoordinatorRefusal::None;
    }

    /// Returns the warning text for @p refusal, or an empty view for CoordinatorRefusal::None.
    [[nodiscard]] constexpr std::string_view coordinator_refusal_description(CoordinatorRefusal refusal) noexcept
    {
        switch (refusal)
        {
        case CoordinatorRefusal::LayerConflict:
            return "a newer participant owns the target";
        case CoordinatorRefusal::Unavailable:
            return "process coordinator unavailable or timed out";
        default:
            return {};
        }
    }

    /**
     * @brief Runs a managed backend enable and contains backend synchronization or allocation exceptions.
     * @param refusal Receives the coordinator refusal of a failed enable when non-null.
     */
    template <class Backend>
    [[nodiscard]] bool try_backend_enable(Backend &backend, CoordinatorRefusal *refusal = nullptr) noexcept
    {
        try
        {
            const auto result = backend.enable();
            if (!result && refusal != nullptr)
            {
                *refusal = coordinator_refusal(result.error());
            }
            return result.has_value();
        }
        catch (...)
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            DetourModKit::detail::g_backend_toggle_exception_catches.fetch_add(1, std::memory_order_relaxed);
#endif
            return false;
        }
    }

    /**
     * @brief Runs a managed backend disable and contains backend synchronization or allocation exceptions.
     * @param refusal Receives the coordinator refusal of a failed disable when non-null.
     */
    template <class Backend>
    [[nodiscard]] bool try_backend_disable(Backend &backend, CoordinatorRefusal *refusal = nullptr) noexcept
    {
        try
        {
            const auto result = backend.disable();
            if (!result && refusal != nullptr)
            {
                *refusal = coordinator_refusal(result.error());
            }
            const bool disabled = result.has_value();
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

    /// Reports whether the backend owns a position that it claimed from an earlier hook generation.
    template <class BackendVariant> [[nodiscard]] bool backend_claimed(BackendVariant &backend) noexcept
    {
        return backend_value_or(backend, false, [](const auto &one) noexcept { return one.claimed(); });
    }

    /**
     * @brief Switches the backend off (@p on false) or back on without a target write.
     * @details An inline hook stores its relay slot, and a mid hook stores its route state. Neither waits.
     * @return False when the backend cannot switch, so the caller keeps its published state.
     */
    template <class BackendVariant> [[nodiscard]] bool switch_backend(BackendVariant &backend, bool on) noexcept
    {
        return backend_value_or(backend, false, [on](auto &one) noexcept { return on ? one.resume() : one.bypass(); });
    }

    /// Hands a bypassed and drained backend's position to a later generation. See safetyhook::InlineHook::vacate.
    template <class BackendVariant> [[nodiscard]] bool vacate_backend(BackendVariant &backend) noexcept
    {
        return backend_value_or(backend, false, [](auto &one) noexcept { return one.vacate(); });
    }

    /// Reports whether the backend's switch word sends every caller past its detour. An empty variant reports false.
    template <class BackendVariant> [[nodiscard]] bool backend_bypassed(BackendVariant &backend) noexcept
    {
        return backend_value_or(backend, false, [](const auto &one) noexcept { return one.bypassed(); });
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

    /// The deepest target chain at which a fresh layer still leaves a residue position.
    inline constexpr std::size_t RESIDUE_LAYER_LIMIT = 16;
    /// The fewest free process records at which a fresh layer still leaves a residue position.
    inline constexpr std::size_t RESIDUE_FREE_RECORD_FLOOR = 64;

    /**
     * @brief Reports whether one more residue position fits beside the record keyed by @p trampoline: at most
     *        @ref RESIDUE_LAYER_LIMIT layers on its target and at least @ref RESIDUE_FREE_RECORD_FLOOR free records.
     * @details A full registry fails every inline and mid create that claims no Vacant position, so the guard
     *          stops the growth first. An unusable coordinator fails the check.
     */
    [[nodiscard]] inline bool
    residue_fits_budget(const safetyhook::ProcessCoordinator &coordinator, std::uint8_t *trampoline) noexcept
    {
        return coordinator && coordinator.layer_count(trampoline) <= RESIDUE_LAYER_LIMIT &&
               coordinator.free_record_count() >= RESIDUE_FREE_RECORD_FLOOR;
    }

    /// Applies the residue budget to the record of @p backend under its own coordinator acquisition.
    template <class BackendVariant> [[nodiscard]] bool residue_fits_budget(BackendVariant &backend) noexcept
    {
        const safetyhook::ProcessCoordinator coordinator;
        return residue_fits_budget(
            coordinator,
            backend_value_or(
                backend,
                static_cast<std::uint8_t *>(nullptr),
                [](const auto &one) noexcept { return one.trampoline().data(); }
            )
        );
    }

    /// A time-stamp counter budget of about one to four seconds on a 1 GHz to 4 GHz counter.
    inline constexpr std::uint64_t CLOSING_DRAIN_TICK_BUDGET = 4'000'000'000ULL;

    /**
     * @brief Waits for a CLOSING mid route to empty, with no call into any export.
     * @details A call that reaches the hooked export spins in the gateway while the route is CLOSING. A clock read,
     *          a yield, or a sleep can be that export, so the wait reads only the entry count and the time-stamp
     *          counter. New entrants wait outside the count, so the count can only fall.
     * @return False when @p tick_budget expired first. A false return never licenses a vacate.
     */
    template <class BackendVariant>
    [[nodiscard]] bool drain_closing_route(BackendVariant &backend, std::uint64_t tick_budget) noexcept
    {
        const std::uint64_t start = __rdtsc();
        while (
            backend_value_or(backend, std::size_t{1}, [](const auto &one) noexcept { return one.route_entries(); }) != 0
        )
        {
            if (__rdtsc() - start > tick_budget)
            {
                return false;
            }
            _mm_pause();
        }
        return true;
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_HOOK_BACKEND_VISIT_HPP
