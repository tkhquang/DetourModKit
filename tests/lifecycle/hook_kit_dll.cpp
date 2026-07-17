/**
 * @file hook_kit_dll.cpp
 * @brief One of the two DLLs that each statically link DetourModKit for the ledger-scope proof.
 * @details DetourModKit is a static archive, so every DLL that links it carries its own HookLedger. Building this one
 *          source twice (kit_a, kit_b) puts two independent kits in a single process, which is the only configuration
 *          that can observe the scope include/DetourModKit/hook.hpp documents. The host drives both through these
 *          exports and compares their answers; keeping both kits on one source holds everything except the linked
 *          instance constant.
 *
 *          The hook set is reached through a never-destroyed pointer rather than a namespace-scope object: this proof
 *          is about ledger scope, and a static-destruction-ordered teardown here would drag in the unrelated concern
 *          Lifecycle.StaticHookCannotOutliveLedgerState already owns.
 */

#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"

#include "internal/hook_ledger.hpp"

#include <cstdint>
#include <new>
#include <utility>

namespace
{
    DetourModKit::hook::HookStack *kit_stack() noexcept
    {
        // The DLL intentionally retains its hook owner until the host calls dmk_kit_release. Never-destroyed storage
        // avoids introducing static-teardown ordering into this instance-scope fixture.
        static DetourModKit::hook::HookStack *const stack = new (std::nothrow) DetourModKit::hook::HookStack();
        return stack;
    }

    /// Distinct per DLL: each kit compiles its own copy, so the two detours never share an address.
    int kit_detour(int base, int modifier)
    {
        return base + modifier + 1;
    }
} // namespace

extern "C"
{
    /**
     * @brief The address of this kit's ledger.
     * @details The structural witness behind the behavioral scenarios: two separately linked kits must report two
     *          different addresses. A process-shared registry would collapse them to one.
     */
    __declspec(dllexport) std::uintptr_t dmk_kit_ledger_address() noexcept
    {
        return reinterpret_cast<std::uintptr_t>(&DetourModKit::detail::HookLedger::instance());
    }

    /**
     * @brief Installs one inline hook on @p target through THIS kit.
     * @param strict Sets Options::fail_if_already_hooked.
     * @param arm Enables the hook after creation; leaving it unarmed keeps the target's prologue pristine.
     * @return 0 on success, otherwise the DetourModKit::ErrorCode as an integer.
     */
    __declspec(dllexport) int dmk_kit_install(std::uintptr_t target, int strict, int arm) noexcept
    {
        using namespace DetourModKit;

        try
        {
            hook::HookStack *const stack = kit_stack();
            if (stack == nullptr)
            {
                return static_cast<int>(ErrorCode::OutOfMemory);
            }

            hook::InlineRequest request{};
            request.name = "KitHook";
            request.target = Address{target};
            request.options.fail_if_already_hooked = (strict != 0);

            Result<hook::Hook> created = hook::inline_at(request, &kit_detour);
            if (!created.has_value())
            {
                return static_cast<int>(created.error().code);
            }
            if (arm != 0)
            {
                Result<void> enabled = created->enable();
                if (!enabled.has_value())
                {
                    return static_cast<int>(enabled.error().code);
                }
            }
            stack->push(std::move(*created));
            return 0;
        }
        catch (const std::bad_alloc &)
        {
            return static_cast<int>(ErrorCode::OutOfMemory);
        }
        catch (...)
        {
            return static_cast<int>(ErrorCode::Unknown);
        }
    }

    /// Whether THIS kit currently tracks @p target, asked through the public query whose scope contract is under test.
    __declspec(dllexport) int dmk_kit_target_hooked(std::uintptr_t target) noexcept
    {
        return DetourModKit::hook::is_target_hooked(DetourModKit::Address{target}) ? 1 : 0;
    }

    /// Drops every hook this kit owns, newest-first.
    __declspec(dllexport) void dmk_kit_release() noexcept
    {
        if (DetourModKit::hook::HookStack *const stack = kit_stack())
        {
            stack->clear();
        }
    }
}
