/**
 * @file test_hook_backend.cpp
 * @brief Proofs for managed hook/backend transaction ownership and exception containment.
 *
 * The backend can report failure or throw before or after its mutation callback. Address-scoped seams prove that DMK
 * contains those exceptions, reconciles committed bytes, and preserves state across enable, disable, rollback, and
 * teardown. Ownership cases prove that emitted-patch provenance is required and that Foreign bytes are never
 * overwritten. Each throwing GoogleTest is discovered as a separate CTest child, so an exception escaping a noexcept
 * boundary fails the case as a process termination.
 */

#include <gtest/gtest.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"

#include "fixtures/scratch_page.hpp"
#include "internal/diagnostics_population.hpp"
#include "test_alloc_probe.hpp"

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    void set_backend_reprotect_failure_target(void *target) noexcept;
    void set_backend_toggle_exception_for_test(void *target, bool after_mutation) noexcept;
    [[nodiscard]] std::size_t backend_toggle_exception_catches_for_test() noexcept;
    extern bool (*g_hook_enable_witness_override)(bool) noexcept;
    extern void (*g_hook_backend_disable_probe)() noexcept;
    extern void (*g_hook_toggle_publication_probe)(bool, bool, bool, bool) noexcept;
#endif
} // namespace DetourModKit::detail

namespace
{
    using DetourModKit::Address;
    using DetourModKit::ErrorCode;
    using DetourModKit::Result;
    using DetourModKit::hook::Hook;
    using DetourModKit::hook::inline_at;
    using DetourModKit::hook::InlineRequest;
    using DetourModKit::hook::is_target_hooked;
    using DetourModKit::hook::mid_at;
    using DetourModKit::hook::MidContext;
    using DetourModKit::hook::MidRequest;

    using LeafFn = int (*)();

    /// The value the planted leaf returns, and the value the detour returns in its place.
    constexpr int LEAF_RESULT = 1;
    constexpr int DETOUR_RESULT = 0x5EED;
    constexpr std::size_t ZEROED_SPAN_BYTES = 32;

    using PrologueSpan = std::array<std::uint8_t, ZEROED_SPAN_BYTES>;

    enum class ToggleExceptionStage : std::uint8_t
    {
        BeforeMutation,
        AfterMutation
    };

    enum class PostDisableWitness : std::uint8_t
    {
        Foreign,
        Indeterminate
    };

    std::atomic<std::size_t> s_mid_detour_calls{0};

    int detour_leaf() noexcept
    {
        return DETOUR_RESULT;
    }

    void mid_detour(MidContext &) noexcept
    {
        s_mid_detour_calls.fetch_add(1, std::memory_order_relaxed);
    }

    /// Plants `mov eax, 1; ret` at offset 0: a complete leaf function, long enough for either patch form.
    void plant_leaf(dmk_test::ScratchPage &page) noexcept
    {
        page.put(0, {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3});
    }

    Result<Hook> install_leaf(dmk_test::ScratchPage &page, const char *name)
    {
        return inline_at(InlineRequest{.name = name, .target = Address{page.addr(0)}},
                         reinterpret_cast<void (*)()>(&detour_leaf));
    }

    Result<Hook> install_mid_leaf(dmk_test::ScratchPage &page, const char *name)
    {
        return mid_at(MidRequest{.name = name, .target = Address{page.addr(0)}}, &mid_detour);
    }

    /// A volatile indirection forces the call to reach the patched entry even when the optimizer can see the callee.
    int call_target(dmk_test::ScratchPage &page) noexcept
    {
        const LeafFn volatile indirect = reinterpret_cast<LeafFn>(page.addr(0));
        return indirect();
    }

    std::size_t armed_population() noexcept
    {
        return DetourModKit::diagnostics::collect().hooks_active;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    struct TogglePublicationObservation
    {
        bool armed{false};
        bool gate_owned{false};
        bool status_matches{false};
        bool callable_matches{false};
        std::size_t total{0};
        std::size_t active{0};
        std::size_t disabled{0};
        std::size_t calls{0};
    };

    TogglePublicationObservation s_toggle_publication;

    void observe_toggle_publication(bool armed, bool gate_owned, bool status_matches, bool callable_matches) noexcept
    {
        s_toggle_publication.armed = armed;
        s_toggle_publication.gate_owned = gate_owned;
        s_toggle_publication.status_matches = status_matches;
        s_toggle_publication.callable_matches = callable_matches;
        DetourModKit::detail::hook_population::read(s_toggle_publication.total, s_toggle_publication.active,
                                                    s_toggle_publication.disabled);
        ++s_toggle_publication.calls;
    }

    class HookTogglePublicationProbeScope
    {
    public:
        HookTogglePublicationProbeScope() noexcept
        {
            s_toggle_publication = {};
            DetourModKit::detail::g_hook_toggle_publication_probe = &observe_toggle_publication;
        }

        ~HookTogglePublicationProbeScope() noexcept { DetourModKit::detail::g_hook_toggle_publication_probe = nullptr; }

        HookTogglePublicationProbeScope(const HookTogglePublicationProbeScope &) = delete;
        HookTogglePublicationProbeScope &operator=(const HookTogglePublicationProbeScope &) = delete;
        HookTogglePublicationProbeScope(HookTogglePublicationProbeScope &&) = delete;
        HookTogglePublicationProbeScope &operator=(HookTogglePublicationProbeScope &&) = delete;
    };

    /// Arms the backend's post-commit transaction seam for one address, and always disarms it.
    class BackendReprotectFailureScope
    {
    public:
        explicit BackendReprotectFailureScope(std::uintptr_t target) noexcept
        {
            DetourModKit::detail::set_backend_reprotect_failure_target(reinterpret_cast<void *>(target));
        }
        ~BackendReprotectFailureScope() noexcept
        {
            DetourModKit::detail::set_backend_reprotect_failure_target(nullptr);
        }
        BackendReprotectFailureScope(const BackendReprotectFailureScope &) = delete;
        BackendReprotectFailureScope &operator=(const BackendReprotectFailureScope &) = delete;
        BackendReprotectFailureScope(BackendReprotectFailureScope &&) = delete;
        BackendReprotectFailureScope &operator=(BackendReprotectFailureScope &&) = delete;
    };

    /// Makes one backend toggle throw at the requested transaction stage, and always disarms the seam.
    class BackendToggleExceptionScope
    {
    public:
        BackendToggleExceptionScope(std::uintptr_t target, ToggleExceptionStage stage) noexcept
        {
            DetourModKit::detail::set_backend_toggle_exception_for_test(reinterpret_cast<void *>(target),
                                                                        stage == ToggleExceptionStage::AfterMutation);
        }
        ~BackendToggleExceptionScope() noexcept
        {
            DetourModKit::detail::set_backend_toggle_exception_for_test(nullptr, false);
        }
        BackendToggleExceptionScope(const BackendToggleExceptionScope &) = delete;
        BackendToggleExceptionScope &operator=(const BackendToggleExceptionScope &) = delete;
        BackendToggleExceptionScope(BackendToggleExceptionScope &&) = delete;
        BackendToggleExceptionScope &operator=(BackendToggleExceptionScope &&) = delete;
    };

    /// Disarms a toggle-exception seam after a hook declared later has finished teardown.
    class BackendToggleExceptionDisarmScope
    {
    public:
        BackendToggleExceptionDisarmScope() = default;
        ~BackendToggleExceptionDisarmScope() noexcept
        {
            DetourModKit::detail::set_backend_toggle_exception_for_test(nullptr, false);
        }
        BackendToggleExceptionDisarmScope(const BackendToggleExceptionDisarmScope &) = delete;
        BackendToggleExceptionDisarmScope &operator=(const BackendToggleExceptionDisarmScope &) = delete;
        BackendToggleExceptionDisarmScope(BackendToggleExceptionDisarmScope &&) = delete;
        BackendToggleExceptionDisarmScope &operator=(BackendToggleExceptionDisarmScope &&) = delete;
    };
#endif

    /// Overwrites the target's first bytes with a jmp no DMK hook in this process emitted.
    void plant_foreign_patch(dmk_test::ScratchPage &page) noexcept
    {
        DWORD previous = 0;
        if (::VirtualProtect(page.base(), dmk_test::ScratchPage::PAGE_SIZE, PAGE_EXECUTE_READWRITE, &previous) == FALSE)
        {
            return;
        }
        // E9 rel32 back to the page's own second half: a well-formed patch whose bytes match neither the saved
        // prologue nor anything the backend emitted for this target.
        page.put(0, {0xE9, 0x7B, 0x00, 0x00, 0x00, 0x90});
        DWORD ignored = 0;
        (void)::VirtualProtect(page.base(), dmk_test::ScratchPage::PAGE_SIZE, previous, &ignored);
    }

    std::array<std::uint8_t, 6> read_prologue(const dmk_test::ScratchPage &page) noexcept
    {
        std::array<std::uint8_t, 6> bytes{};
        std::memcpy(bytes.data(), reinterpret_cast<const void *>(page.addr(0)), bytes.size());
        return bytes;
    }

    PrologueSpan read_prologue_span(const dmk_test::ScratchPage &page) noexcept
    {
        PrologueSpan bytes{};
        std::memcpy(bytes.data(), reinterpret_cast<const void *>(page.addr(0)), bytes.size());
        return bytes;
    }

    void write_prologue_span(dmk_test::ScratchPage &page, const PrologueSpan &bytes) noexcept
    {
        std::memcpy(page.base(), bytes.data(), bytes.size());
    }

    void expect_zeroed_first_enable_is_refused(dmk_test::ScratchPage &page, Result<Hook> installed)
    {
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        const PrologueSpan pristine = read_prologue_span(page);
        const PrologueSpan zeroed{};
        write_prologue_span(page, zeroed);

        const Result<void> enabled = hook.enable();
        EXPECT_FALSE(enabled.has_value());
        if (!enabled)
        {
            EXPECT_EQ(enabled.error().code, ErrorCode::EnableFailed);
        }
        EXPECT_FALSE(hook.is_enabled());
        EXPECT_EQ(read_prologue_span(page), zeroed);

        // Restore the disabled backend's saved prologue before its destructor so the proof does not deliberately pin
        // a backend merely to preserve the foreign zero span it just verified. A successful retry distinguishes the
        // terminal Disabled state from a handle stranded in its transient Enabling state.
        write_prologue_span(page, pristine);
        ASSERT_TRUE(hook.enable().has_value());
        EXPECT_TRUE(hook.is_enabled());
        ASSERT_TRUE(hook.disable().has_value());
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    void expect_enable_exceptions_reconciled(dmk_test::ScratchPage &page, Result<Hook> installed, bool is_inline,
                                             std::string_view name)
    {
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        const PrologueSpan pristine = read_prologue_span(page);
        const std::size_t armed_before = armed_population();
        std::size_t enabled_events = 0;
        auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [&enabled_events, name](const DetourModKit::diagnostics::HookLifecycleEvent &event)
            {
                if (event.name == name && event.transition == DetourModKit::diagnostics::HookTransition::Enabled)
                {
                    ++enabled_events;
                }
            });

        Result<void> before_mutation;
        {
            const BackendToggleExceptionScope seam{page.addr(0), ToggleExceptionStage::BeforeMutation};
            before_mutation = hook.enable();
        }
        ASSERT_FALSE(before_mutation.has_value());
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_EQ(before_mutation.error().code, ErrorCode::EnableFailed);
        EXPECT_FALSE(hook.is_enabled());
        EXPECT_EQ(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before);
        EXPECT_FALSE(hook.try_call<int>().has_value());
        EXPECT_EQ(call_target(page), LEAF_RESULT);
        EXPECT_EQ(enabled_events, 0u);

        const std::size_t mid_calls_before = s_mid_detour_calls.load(std::memory_order_relaxed);
        Result<void> after_mutation;
        {
            const BackendToggleExceptionScope seam{page.addr(0), ToggleExceptionStage::AfterMutation};
            after_mutation = hook.enable();
        }
        ASSERT_FALSE(after_mutation.has_value());
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_EQ(after_mutation.error().code, ErrorCode::BackendFailed);
        EXPECT_TRUE(hook.is_enabled());
        EXPECT_NE(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before + 1);
        EXPECT_EQ(enabled_events, 1u);
        if (is_inline)
        {
            EXPECT_EQ(call_target(page), DETOUR_RESULT);
            const Result<int> original = hook.try_call<int>();
            ASSERT_TRUE(original.has_value()) << original.error().message();
            EXPECT_EQ(*original, LEAF_RESULT);
        }
        else
        {
            EXPECT_FALSE(hook.try_call<int>().has_value());
            EXPECT_EQ(call_target(page), LEAF_RESULT);
            EXPECT_EQ(s_mid_detour_calls.load(std::memory_order_relaxed), mid_calls_before + 1);
        }

        ASSERT_TRUE(hook.disable().has_value());
        EXPECT_EQ(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before);
    }

    void expect_disable_exceptions_reconciled(dmk_test::ScratchPage &page, Result<Hook> installed, bool is_inline,
                                              std::string_view name)
    {
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        const PrologueSpan pristine = read_prologue_span(page);
        const std::size_t armed_before = armed_population();
        ASSERT_TRUE(hook.enable().has_value());
        const PrologueSpan armed = read_prologue_span(page);
        ASSERT_NE(armed, pristine);
        ASSERT_EQ(armed_population(), armed_before + 1);
        std::size_t disabled_events = 0;
        auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [&disabled_events, name](const DetourModKit::diagnostics::HookLifecycleEvent &event)
            {
                if (event.name == name && event.transition == DetourModKit::diagnostics::HookTransition::Disabled)
                {
                    ++disabled_events;
                }
            });

        Result<void> before_mutation;
        {
            const BackendToggleExceptionScope seam{page.addr(0), ToggleExceptionStage::BeforeMutation};
            before_mutation = hook.disable();
        }
        ASSERT_FALSE(before_mutation.has_value());
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_EQ(before_mutation.error().code, ErrorCode::DisableFailed);
        EXPECT_TRUE(hook.is_enabled());
        EXPECT_EQ(read_prologue_span(page), armed);
        EXPECT_EQ(armed_population(), armed_before + 1);
        EXPECT_EQ(disabled_events, 0u);
        if (is_inline)
        {
            EXPECT_EQ(call_target(page), DETOUR_RESULT);
            const Result<int> original = hook.try_call<int>();
            ASSERT_TRUE(original.has_value()) << original.error().message();
            EXPECT_EQ(*original, LEAF_RESULT);
        }
        else
        {
            EXPECT_FALSE(hook.try_call<int>().has_value());
        }

        Result<void> after_mutation;
        {
            const BackendToggleExceptionScope seam{page.addr(0), ToggleExceptionStage::AfterMutation};
            after_mutation = hook.disable();
        }
        ASSERT_FALSE(after_mutation.has_value());
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_EQ(after_mutation.error().code, ErrorCode::BackendFailed);
        EXPECT_FALSE(hook.is_enabled());
        EXPECT_EQ(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before);
        EXPECT_FALSE(hook.try_call<int>().has_value());
        EXPECT_EQ(disabled_events, 1u);

        ASSERT_TRUE(hook.enable().has_value());
        EXPECT_TRUE(hook.is_enabled());
        if (is_inline)
        {
            EXPECT_EQ(call_target(page), DETOUR_RESULT);
        }
        else
        {
            const std::size_t mid_calls_before = s_mid_detour_calls.load(std::memory_order_relaxed);
            EXPECT_EQ(call_target(page), LEAF_RESULT);
            EXPECT_EQ(s_mid_detour_calls.load(std::memory_order_relaxed), mid_calls_before + 1);
        }
        ASSERT_TRUE(hook.disable().has_value());
    }

    void expect_teardown_after_mutation_exception_reconciled(dmk_test::ScratchPage &page, Result<Hook> installed,
                                                             std::string_view name)
    {
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        const PrologueSpan pristine = read_prologue_span(page);
        const std::size_t armed_before = armed_population();
        const std::size_t leaks_before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
        std::size_t removed_events = 0;
        auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [&removed_events, name](const DetourModKit::diagnostics::HookLifecycleEvent &event)
            {
                if (event.name == name && event.transition == DetourModKit::diagnostics::HookTransition::Removed)
                {
                    ++removed_events;
                }
            });

        {
            // Declared first so it disarms only after Hook's destructor consumes the armed exception seam.
            const BackendToggleExceptionDisarmScope disarm;
            Hook hook = std::move(*installed);
            ASSERT_TRUE(hook.enable().has_value());
            ASSERT_EQ(armed_population(), armed_before + 1);
            DetourModKit::detail::set_backend_toggle_exception_for_test(reinterpret_cast<void *>(page.addr(0)), true);
        }

        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_EQ(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before);
        const bool target_still_hooked = is_target_hooked(Address{page.addr(0)});
        EXPECT_FALSE(target_still_hooked);
        EXPECT_EQ(
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
            leaks_before);
        EXPECT_EQ(removed_events, 1u);
        if (target_still_hooked)
        {
            // A regressed teardown pins the backend. Keep its target mapped so a direct all-tests run cannot recycle
            // the address underneath the pinned ledger entry after reporting this failure.
            page.abandon();
        }
    }
#endif

#if defined(DMK_ENABLE_TEST_SEAMS)
    /// The page the witness override below plants on. The seam is a plain function pointer, so it cannot capture.
    dmk_test::ScratchPage *s_witness_override_page = nullptr;
    ToggleExceptionStage s_rollback_exception_stage = ToggleExceptionStage::BeforeMutation;
    PostDisableWitness s_post_disable_witness = PostDisableWitness::Foreign;
    PrologueSpan s_owned_patch_before_override{};
    DWORD s_witness_previous_protection = 0;
    bool s_witness_page_unreadable = false;
    std::size_t s_enable_witness_callbacks = 0;
    std::size_t s_enable_confirmed_callbacks = 0;

    /// Replaces a completed backend restore with Foreign or Indeterminate evidence before DMK's final witness.
    void perturb_post_disable_witness() noexcept
    {
        if (s_witness_override_page == nullptr)
        {
            return;
        }
        if (s_post_disable_witness == PostDisableWitness::Foreign)
        {
            // Change only the five-byte patch window. Leaving the planted ret at offset 5 intact keeps the inline
            // trampoline callable while the test observes the retained call gate.
            s_witness_override_page->put(0, {0xE9, 0x7B, 0x00, 0x00, 0x00});
            return;
        }
        DWORD previous = 0;
        if (::VirtualProtect(s_witness_override_page->base(), dmk_test::ScratchPage::PAGE_SIZE, PAGE_NOACCESS,
                             &previous) != FALSE)
        {
            s_witness_previous_protection = previous;
            s_witness_page_unreadable = true;
        }
    }

    // Every scope below restores BEFORE clearing s_witness_override_page, so nesting them is order-independent:
    // whichever destructor runs first performs the restore and the rest are no-ops.
    bool restore_witness_page_access() noexcept
    {
        if (!s_witness_page_unreadable || s_witness_override_page == nullptr)
        {
            return true;
        }
        DWORD ignored = 0;
        if (::VirtualProtect(s_witness_override_page->base(), dmk_test::ScratchPage::PAGE_SIZE,
                             s_witness_previous_protection, &ignored) == FALSE)
        {
            return false;
        }
        s_witness_page_unreadable = false;
        return true;
    }

    /**
     * @brief Stands in for a third party that takes the window between the backend's committed patch and DMK's
     *        witness of it: the arm really landed, and by the time DMK looks the bytes belong to somebody else.
     */
    bool plant_foreign_then_reject(bool confirmed) noexcept
    {
        ++s_enable_witness_callbacks;
        if (confirmed)
        {
            ++s_enable_confirmed_callbacks;
        }
        if (s_witness_override_page != nullptr)
        {
            s_owned_patch_before_override = read_prologue_span(*s_witness_override_page);
            plant_foreign_patch(*s_witness_override_page);
        }
        return false;
    }

    /// Makes the final enable witness Indeterminate after preserving the committed patch for cleanup.
    bool make_unreadable_then_reject(bool confirmed) noexcept
    {
        ++s_enable_witness_callbacks;
        if (confirmed)
        {
            ++s_enable_confirmed_callbacks;
        }
        if (s_witness_override_page != nullptr)
        {
            s_owned_patch_before_override = read_prologue_span(*s_witness_override_page);
            DWORD previous = 0;
            if (::VirtualProtect(s_witness_override_page->base(), dmk_test::ScratchPage::PAGE_SIZE, PAGE_NOACCESS,
                                 &previous) != FALSE)
            {
                s_witness_previous_protection = previous;
                s_witness_page_unreadable = true;
            }
        }
        return false;
    }

    /// Arms a throw for the compensating disable that follows a rejected enable witness.
    bool arm_rollback_exception_then_reject(bool confirmed) noexcept
    {
        ++s_enable_witness_callbacks;
        if (confirmed)
        {
            ++s_enable_confirmed_callbacks;
        }
        if (s_witness_override_page != nullptr)
        {
            s_owned_patch_before_override = read_prologue_span(*s_witness_override_page);
            DetourModKit::detail::set_backend_toggle_exception_for_test(
                reinterpret_cast<void *>(s_witness_override_page->addr(0)),
                s_rollback_exception_stage == ToggleExceptionStage::AfterMutation);
        }
        return false;
    }

    /// Arms the enable-witness seam, and always disarms it.
    class HookEnableWitnessOverrideScope
    {
    public:
        HookEnableWitnessOverrideScope(bool (*override_fn)(bool) noexcept, dmk_test::ScratchPage &page) noexcept
        {
            s_witness_override_page = &page;
            DetourModKit::detail::g_hook_enable_witness_override = override_fn;
        }
        ~HookEnableWitnessOverrideScope() noexcept
        {
            (void)restore_witness_page_access();
            DetourModKit::detail::g_hook_enable_witness_override = nullptr;
            s_witness_override_page = nullptr;
            DetourModKit::detail::set_backend_toggle_exception_for_test(nullptr, false);
        }
        HookEnableWitnessOverrideScope(const HookEnableWitnessOverrideScope &) = delete;
        HookEnableWitnessOverrideScope &operator=(const HookEnableWitnessOverrideScope &) = delete;
        HookEnableWitnessOverrideScope(HookEnableWitnessOverrideScope &&) = delete;
        HookEnableWitnessOverrideScope &operator=(HookEnableWitnessOverrideScope &&) = delete;
    };

    /// Arms a post-disable byte perturbation and restores page access before leaving the test scope.
    class BackendDisableProbeScope
    {
    public:
        BackendDisableProbeScope(dmk_test::ScratchPage &page, PostDisableWitness witness) noexcept
        {
            s_witness_override_page = &page;
            s_post_disable_witness = witness;
            DetourModKit::detail::g_hook_backend_disable_probe = &perturb_post_disable_witness;
        }
        ~BackendDisableProbeScope() noexcept
        {
            DetourModKit::detail::g_hook_backend_disable_probe = nullptr;
            (void)restore_witness_page_access();
            s_witness_override_page = nullptr;
        }
        BackendDisableProbeScope(const BackendDisableProbeScope &) = delete;
        BackendDisableProbeScope &operator=(const BackendDisableProbeScope &) = delete;
        BackendDisableProbeScope(BackendDisableProbeScope &&) = delete;
        BackendDisableProbeScope &operator=(BackendDisableProbeScope &&) = delete;
    };

    void expect_post_disable_uncertainty_reconciled(dmk_test::ScratchPage &page, Result<Hook> installed, bool is_inline,
                                                    PostDisableWitness witness, std::string_view name)
    {
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        const PrologueSpan pristine = read_prologue_span(page);
        const std::size_t armed_before = armed_population();
        ASSERT_TRUE(hook.enable().has_value());
        const PrologueSpan owned_patch = read_prologue_span(page);
        ASSERT_NE(owned_patch, pristine);
        std::size_t disabled_events = 0;
        auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [&disabled_events, name](const DetourModKit::diagnostics::HookLifecycleEvent &event)
            {
                if (event.name == name && event.transition == DetourModKit::diagnostics::HookTransition::Disabled)
                {
                    ++disabled_events;
                }
            });

        Result<void> disabled;
        {
            const BackendToggleExceptionScope exception{page.addr(0), ToggleExceptionStage::AfterMutation};
            const BackendDisableProbeScope probe{page, witness};
            disabled = hook.disable();
        }

        ASSERT_FALSE(disabled.has_value());
        EXPECT_EQ(disabled.error().code, ErrorCode::DisableFailed);
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_TRUE(hook.is_enabled());
        EXPECT_EQ(armed_population(), armed_before + 1);
        EXPECT_EQ(disabled_events, 0u);
        if (is_inline)
        {
            const Result<int> original = hook.try_call<int>();
            ASSERT_TRUE(original.has_value()) << original.error().message();
            EXPECT_EQ(*original, LEAF_RESULT);
        }
        else
        {
            EXPECT_FALSE(hook.try_call<int>().has_value());
        }

        // Re-establish the exact owned patch. The reconciled backend flag makes the retry perform a real restore;
        // without it the backend's disabled fast path would leave these bytes live behind a false success.
        write_prologue_span(page, owned_patch);
        const Result<void> retried = hook.disable();
        ASSERT_TRUE(retried.has_value()) << retried.error().message();
        EXPECT_FALSE(hook.is_enabled());
        EXPECT_EQ(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before);
        EXPECT_EQ(disabled_events, 1u);
    }

    void expect_rollback_uncertainty_reconciled(dmk_test::ScratchPage &page, Result<Hook> installed,
                                                std::string_view name)
    {
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        const PrologueSpan pristine = read_prologue_span(page);
        const std::size_t armed_before = armed_population();
        std::size_t enabled_events = 0;
        auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [&enabled_events, name](const DetourModKit::diagnostics::HookLifecycleEvent &event)
            {
                if (event.name == name && event.transition == DetourModKit::diagnostics::HookTransition::Enabled)
                {
                    ++enabled_events;
                }
            });

        s_rollback_exception_stage = ToggleExceptionStage::AfterMutation;
        s_enable_witness_callbacks = 0;
        s_enable_confirmed_callbacks = 0;
        Result<void> enabled;
        {
            const HookEnableWitnessOverrideScope witness{&arm_rollback_exception_then_reject, page};
            const BackendDisableProbeScope probe{page, PostDisableWitness::Foreign};
            enabled = hook.enable();
        }

        ASSERT_FALSE(enabled.has_value());
        EXPECT_EQ(enabled.error().code, ErrorCode::DisableFailed);
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_EQ(s_enable_witness_callbacks, 1u);
        EXPECT_EQ(s_enable_confirmed_callbacks, 1u);
        EXPECT_TRUE(hook.is_enabled());
        EXPECT_EQ(armed_population(), armed_before + 1);
        EXPECT_EQ(enabled_events, 1u);

        const PrologueSpan owned_patch = s_owned_patch_before_override;
        write_prologue_span(page, owned_patch);
        const Result<void> retried = hook.disable();
        ASSERT_TRUE(retried.has_value()) << retried.error().message();
        EXPECT_FALSE(hook.is_enabled());
        EXPECT_EQ(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before);
    }

    void expect_unconfirmed_post_commit_enable_is_retained(dmk_test::ScratchPage &page, const char *name,
                                                           bool make_unreadable)
    {
        Result<Hook> installed = install_leaf(page, name);
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        const PrologueSpan pristine = read_prologue_span(page);
        const std::size_t armed_before = armed_population();
        std::size_t enabled_events = 0;
        auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [&enabled_events, name](const DetourModKit::diagnostics::HookLifecycleEvent &event)
            {
                if (event.name == name && event.transition == DetourModKit::diagnostics::HookTransition::Enabled)
                {
                    ++enabled_events;
                }
            });

        Result<void> enabled;
        PrologueSpan owned_patch{};
        bool protection_restored = true;
        s_enable_witness_callbacks = 0;
        s_enable_confirmed_callbacks = 0;
        {
            const BackendToggleExceptionScope exception{page.addr(0), ToggleExceptionStage::AfterMutation};
            const HookEnableWitnessOverrideScope witness{
                make_unreadable ? &make_unreadable_then_reject : &plant_foreign_then_reject, page};
            enabled = hook.enable();
            owned_patch = s_owned_patch_before_override;
            protection_restored = restore_witness_page_access();
        }

        ASSERT_TRUE(protection_restored);
        ASSERT_FALSE(enabled.has_value());
        EXPECT_EQ(enabled.error().code, ErrorCode::DisableFailed);
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_EQ(s_enable_witness_callbacks, 1u);
        EXPECT_EQ(s_enable_confirmed_callbacks, 1u);
        EXPECT_TRUE(hook.is_enabled());
        EXPECT_EQ(armed_population(), armed_before + 1);
        EXPECT_EQ(enabled_events, 1u);
        if (make_unreadable)
        {
            EXPECT_EQ(read_prologue_span(page), owned_patch);
            EXPECT_EQ(call_target(page), DETOUR_RESULT);
        }
        else
        {
            EXPECT_EQ(read_prologue(page), (std::array<std::uint8_t, 6>{0xE9, 0x7B, 0x00, 0x00, 0x00, 0x90}));
        }

        // The test resolves the simulated conflict explicitly, after proving DMK did not overwrite it implicitly.
        write_prologue_span(page, owned_patch);
        const Result<int> original = hook.try_call<int>();
        ASSERT_TRUE(original.has_value()) << original.error().message();
        EXPECT_EQ(*original, LEAF_RESULT);
        ASSERT_TRUE(hook.disable().has_value());
        EXPECT_EQ(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before);
    }

    void expect_rollback_exceptions_reconciled(dmk_test::ScratchPage &page, Result<Hook> installed, bool is_inline,
                                               std::string_view name)
    {
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        const PrologueSpan pristine = read_prologue_span(page);
        const std::size_t armed_before = armed_population();
        std::size_t enabled_events = 0;
        auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [&enabled_events, name](const DetourModKit::diagnostics::HookLifecycleEvent &event)
            {
                if (event.name == name && event.transition == DetourModKit::diagnostics::HookTransition::Enabled)
                {
                    ++enabled_events;
                }
            });

        Result<void> before_mutation;
        s_rollback_exception_stage = ToggleExceptionStage::BeforeMutation;
        s_enable_witness_callbacks = 0;
        s_enable_confirmed_callbacks = 0;
        {
            const HookEnableWitnessOverrideScope seam{&arm_rollback_exception_then_reject, page};
            before_mutation = hook.enable();
        }
        ASSERT_FALSE(before_mutation.has_value());
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_EQ(s_enable_witness_callbacks, 1u);
        EXPECT_EQ(s_enable_confirmed_callbacks, 1u);
        EXPECT_EQ(before_mutation.error().code, ErrorCode::DisableFailed);
        EXPECT_TRUE(hook.is_enabled());
        EXPECT_NE(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before + 1);
        EXPECT_EQ(enabled_events, 1u);
        if (is_inline)
        {
            EXPECT_EQ(call_target(page), DETOUR_RESULT);
            const Result<int> original = hook.try_call<int>();
            ASSERT_TRUE(original.has_value()) << original.error().message();
            EXPECT_EQ(*original, LEAF_RESULT);
        }
        else
        {
            EXPECT_FALSE(hook.try_call<int>().has_value());
        }
        ASSERT_TRUE(hook.disable().has_value());
        ASSERT_EQ(armed_population(), armed_before);

        Result<void> after_mutation;
        s_rollback_exception_stage = ToggleExceptionStage::AfterMutation;
        s_enable_witness_callbacks = 0;
        s_enable_confirmed_callbacks = 0;
        {
            const HookEnableWitnessOverrideScope seam{&arm_rollback_exception_then_reject, page};
            after_mutation = hook.enable();
        }
        ASSERT_FALSE(after_mutation.has_value());
        EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        EXPECT_EQ(s_enable_witness_callbacks, 1u);
        EXPECT_EQ(s_enable_confirmed_callbacks, 1u);
        EXPECT_EQ(after_mutation.error().code, ErrorCode::EnableFailed);
        EXPECT_FALSE(hook.is_enabled());
        EXPECT_EQ(read_prologue_span(page), pristine);
        EXPECT_EQ(armed_population(), armed_before);
        EXPECT_FALSE(hook.try_call<int>().has_value());
        EXPECT_EQ(enabled_events, 1u);

        ASSERT_TRUE(hook.enable().has_value());
        EXPECT_TRUE(hook.is_enabled());
        EXPECT_EQ(enabled_events, 2u);
        ASSERT_TRUE(hook.disable().has_value());
    }
#endif
} // namespace

#if defined(DMK_ENABLE_TEST_SEAMS)

TEST(HookTogglePublicationOrder, StateAndPopulationChangeBeforeCallGateUnlock)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "TogglePublicationOrder");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    const std::size_t active_before = armed_population();

    {
        const HookTogglePublicationProbeScope probe;
        ASSERT_TRUE(hook.enable().has_value());
    }
    EXPECT_EQ(s_toggle_publication.calls, 1U);
    EXPECT_TRUE(s_toggle_publication.armed);
    EXPECT_TRUE(s_toggle_publication.gate_owned);
    EXPECT_TRUE(s_toggle_publication.status_matches);
    EXPECT_TRUE(s_toggle_publication.callable_matches);
    EXPECT_EQ(s_toggle_publication.active, active_before + 1);

    {
        const HookTogglePublicationProbeScope probe;
        ASSERT_TRUE(hook.disable().has_value());
    }
    EXPECT_EQ(s_toggle_publication.calls, 1U);
    EXPECT_FALSE(s_toggle_publication.armed);
    EXPECT_TRUE(s_toggle_publication.gate_owned);
    EXPECT_TRUE(s_toggle_publication.status_matches);
    EXPECT_TRUE(s_toggle_publication.callable_matches);
    EXPECT_EQ(s_toggle_publication.active, active_before);
}

// The transaction wrote the jmp and then reported a failure. The patch is live, so publishing Disabled would leave the
// detour dispatching behind a handle that denies it and a call gate that never opens. Mutation: reverting the backend's
// `m_enabled = true` assignment below trap_threads restores the pre-fix behaviour and fails this.
TEST(HookBackendTransaction, EnableCommittedThenReportedFailurePublishesArmed)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    ASSERT_EQ(call_target(page), LEAF_RESULT);

    Result<Hook> installed = install_leaf(page, "EnableCommitFailure");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);

    // Consumers learn about this transition through the event stream, so it has to be observed here: publishing Active
    // while telling subscribers the opposite is invisible to every other assertion below.
    std::size_t enabled_events = 0;
    auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
        [&enabled_events](const DetourModKit::diagnostics::HookLifecycleEvent &event)
        {
            if (event.name == "EnableCommitFailure" && event.kind == DetourModKit::diagnostics::HookKind::Inline &&
                event.transition == DetourModKit::diagnostics::HookTransition::Enabled)
            {
                ++enabled_events;
            }
        });

    const std::size_t armed_before = armed_population();
    Result<void> enabled{};
    {
        const BackendReprotectFailureScope seam{page.addr(0)};
        enabled = hook.enable();
    }

    ASSERT_FALSE(enabled.has_value());
    EXPECT_EQ(enabled.error().code, ErrorCode::BackendFailed);
    // Every published surface agrees with the bytes: the hook is armed and the detour is reachable.
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(call_target(page), DETOUR_RESULT);
    EXPECT_EQ(armed_population(), armed_before + 1);
    EXPECT_TRUE(hook.original<LeafFn>() != nullptr);
    // original<>() reads the backend trampoline directly; try_call goes through the call gate, which is the surface a
    // detour actually chains on. A branch that published Active without opening the gate passes every check above.
    const Result<int> guarded_original = hook.try_call<int>();
    ASSERT_TRUE(guarded_original.has_value()) << guarded_original.error().message();
    EXPECT_EQ(*guarded_original, LEAF_RESULT);
    EXPECT_EQ(enabled_events, 1u);

    // The hook is genuinely armed, so an ordinary disable takes it back down.
    ASSERT_TRUE(hook.disable().has_value());
    EXPECT_EQ(call_target(page), LEAF_RESULT);
}

// The mirror: the transaction restored the prologue and then reported a failure. The target no longer redirects, so
// republishing Active would point the call gate at a trampoline nothing jumps to. Mutation: restoring the `&&`
// short-circuit in Hook::disable fails this. The backend's callback-side `m_enabled = false` assignment does NOT gate
// this case; it is owned by CommittedDisableFailureLeavesTheHookReArmable below.
TEST(HookBackendTransaction, DisableCommittedThenReportedFailurePublishesDisabled)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "DisableCommitFailure");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_TRUE(hook.enable().has_value());
    ASSERT_EQ(call_target(page), DETOUR_RESULT);

    // Subscribed after the arming enable, so only the disarm this case drives is counted.
    std::size_t disabled_events = 0;
    auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
        [&disabled_events](const DetourModKit::diagnostics::HookLifecycleEvent &event)
        {
            if (event.name == "DisableCommitFailure" && event.kind == DetourModKit::diagnostics::HookKind::Inline &&
                event.transition == DetourModKit::diagnostics::HookTransition::Disabled)
            {
                ++disabled_events;
            }
        });

    const std::size_t armed_before = armed_population();
    Result<void> disabled{};
    {
        const BackendReprotectFailureScope seam{page.addr(0)};
        disabled = hook.disable();
    }

    // The disarm took effect; the error reports the transaction outcome rather than hiding it.
    ASSERT_FALSE(disabled.has_value());
    EXPECT_EQ(disabled.error().code, ErrorCode::BackendFailed);
    EXPECT_FALSE(hook.is_enabled());
    EXPECT_EQ(call_target(page), LEAF_RESULT);
    EXPECT_EQ(armed_population(), armed_before - 1);
    // The gate closes with the state. Leaving it open would keep handing callers a trampoline the target no longer
    // jumps to, which none of the assertions above can distinguish from a correct disarm.
    EXPECT_FALSE(hook.try_call<int>().has_value());
    EXPECT_EQ(disabled_events, 1u);
}

// After a committed restore that reported failure, the hook must still be re-armable. DMK's own state is driven by the
// bytes and is already correct here, so what this pins is the BACKEND's flag: if it stays enabled over a restored
// target, the next backend enable() takes its "already enabled" fast path and returns success without patching
// anything, leaving the hook permanently unable to arm. Mutation: moving the backend's `m_enabled = false` assignment
// back below trap_threads fails this, and also fails the disable-exception cases, which re-arm through the same flag.
TEST(HookBackendTransaction, CommittedDisableFailureLeavesTheHookReArmable)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "DisableCommitReArm");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_TRUE(hook.enable().has_value());

    {
        const BackendReprotectFailureScope seam{page.addr(0)};
        EXPECT_FALSE(hook.disable().has_value());
    }
    ASSERT_FALSE(hook.is_enabled());
    ASSERT_EQ(call_target(page), LEAF_RESULT);

    // The seam is gone; an ordinary enable must arm the target again.
    const Result<void> rearmed = hook.enable();
    ASSERT_TRUE(rearmed.has_value()) << rearmed.error().message();
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(call_target(page), DETOUR_RESULT);
}

// A committed enable whose transaction failed must still tear down cleanly: the bytes are ours, so teardown restores
// them and frees the backend rather than pinning it.
TEST(HookBackendTransaction, CommittedEnableFailureStillTearsDownWithoutLeaking)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const std::array<std::uint8_t, 6> pristine = read_prologue(page);

    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    {
        Result<Hook> installed = install_leaf(page, "CommitFailureTeardown");
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook hook = std::move(*installed);
        {
            const BackendReprotectFailureScope seam{page.addr(0)};
            EXPECT_FALSE(hook.enable().has_value());
        }
        ASSERT_TRUE(hook.is_enabled());
    }

    EXPECT_EQ(read_prologue(page), pristine);
    EXPECT_EQ(DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
              leaks_before);
}

#endif // DMK_ENABLE_TEST_SEAMS

// A third party owns the prologue. The backend's disable copies its saved bytes back unconditionally, so DMK has to
// refuse BEFORE the call or the foreign patch is silently clobbered. Mutation: collapsing OwnedPatch and Foreign into
// one Patched state makes the foreign bytes read as ours and the refusal disappears.
TEST(HookBackendOwnership, ForeignPrologueIsNotOverwrittenByDisable)
{
    std::uintptr_t pinned_target = 0;
    {
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);

        std::array<std::uint8_t, 6> foreign{};
        const std::size_t leaks_before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
        {
            Result<Hook> installed = install_leaf(page, "ForeignDisable");
            ASSERT_TRUE(installed.has_value()) << installed.error().message();
            Hook hook = std::move(*installed);
            ASSERT_TRUE(hook.enable().has_value());

            plant_foreign_patch(page);
            foreign = read_prologue(page);

            const Result<void> disabled = hook.disable();
            ASSERT_FALSE(disabled.has_value());
            EXPECT_EQ(disabled.error().code, ErrorCode::DisableFailed);
            // The refusal happened before the backend ran, so the foreign bytes are exactly as they were left.
            EXPECT_EQ(read_prologue(page), foreign);
            // The hook never claimed a disarm it did not perform.
            EXPECT_TRUE(hook.is_enabled());
        }

        // Teardown must fail closed too: the target is not restorable, so the backend is pinned rather than freed, and
        // the foreign writer's bytes survive that as well.
        EXPECT_EQ(
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
            leaks_before + 1);
        EXPECT_EQ(read_prologue(page), foreign);
        pinned_target = page.addr();
        // The ledger keeps this address pinned for process life, so the fixture must not hand it back to the allocator.
        page.abandon();
    }

    MEMORY_BASIC_INFORMATION memory_info{};
    const SIZE_T queried =
        VirtualQuery(reinterpret_cast<const void *>(pinned_target), &memory_info, sizeof(memory_info));
    ASSERT_EQ(queried, sizeof(memory_info));
    EXPECT_EQ(memory_info.State, MEM_COMMIT) << "the pinned target reservation must survive fixture destruction";
    EXPECT_TRUE(is_target_hooked(Address{pinned_target}));
}

// The enable direction of the same rule: the backend emits its jmp over whatever is present, so a foreign prologue has
// to refuse the arm while the hook is still exactly as the caller left it.
TEST(HookBackendOwnership, ForeignPrologueIsNotOverwrittenByEnable)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "ForeignEnable");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);

    plant_foreign_patch(page);
    const std::array<std::uint8_t, 6> foreign = read_prologue(page);

    const Result<void> enabled = hook.enable();
    ASSERT_FALSE(enabled.has_value());
    EXPECT_EQ(enabled.error().code, ErrorCode::EnableFailed);
    EXPECT_EQ(read_prologue(page), foreign);
    EXPECT_FALSE(hook.is_enabled());

    // Restoring the prologue by hand makes the hook usable again: the refusal is a property of the bytes, not a latch.
    plant_leaf(page);
    EXPECT_TRUE(hook.enable().has_value());
    EXPECT_TRUE(hook.is_enabled());
}

TEST(HookBackendOwnership, DisabledInlineHookRejectsZeroedFirstEnable)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_zeroed_first_enable_is_refused(page, install_leaf(page, "ZeroedInlineFirstEnable"));
}

TEST(HookBackendOwnership, DisabledMidHookRejectsZeroedFirstEnable)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_zeroed_first_enable_is_refused(page, install_mid_leaf(page, "ZeroedMidFirstEnable"));
}

TEST(HookBackendRelease, CleanManagedDestructionAllocatesNothing)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    // ~Hook copies m_impl->name into a std::string BEFORE it restores the backend (src/hook.cpp), because the
    // post-restore warning and lifecycle event read a name whose storage the Impl owns. A name past the small-string
    // buffer therefore allocates inside the poisoned scope below and takes that copy's catch path, so the case would
    // prove the name-copy degradation rather than an allocation-free release. The short name is load-bearing.
    static constexpr char CLEAN_RELEASE_HOOK_NAME[] = "OOMFree";
    static_assert(sizeof(CLEAN_RELEASE_HOOK_NAME) <= 16,
                  "the clean-release hook name must fit the small-string buffer");
    Result<Hook> installed = install_leaf(page, CLEAN_RELEASE_HOOK_NAME);
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    std::optional<Hook> hook{std::move(*installed)};
    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);

    ASSERT_TRUE(hook->enable().has_value());
    ASSERT_EQ(call_target(page), DETOUR_RESULT);
    ASSERT_TRUE(hook->disable().has_value());
    ASSERT_EQ(call_target(page), LEAF_RESULT);

    {
        const dmk_test::AllocFailScope fail_allocations{0};
        hook.reset();
    }

    EXPECT_EQ(call_target(page), LEAF_RESULT);
    EXPECT_FALSE(is_target_hooked(Address{page.addr(0)}));
    EXPECT_EQ(DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
              leaks_before);
}

// The HookBackendOwnership cases above are deliberately outside every seam guard: they drive the refusal through the
// public API alone, so the ownership proofs survive a seam-free build. Only the exception cases below need a seam.
#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(HookBackendException, InlineEnableReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_enable_exceptions_reconciled(page, install_leaf(page, "InlineEnableException"), true,
                                        "InlineEnableException");
}

TEST(HookBackendException, MidEnableReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_enable_exceptions_reconciled(page, install_mid_leaf(page, "MidEnableException"), false,
                                        "MidEnableException");
}

TEST(HookBackendException, UnconfirmedPostCommitEnableRetainsConservativeActiveState)
{
    dmk_test::ScratchPage foreign_page;
    ASSERT_TRUE(foreign_page.ok());
    plant_leaf(foreign_page);
    expect_unconfirmed_post_commit_enable_is_retained(foreign_page, "PostCommitForeign", false);

    dmk_test::ScratchPage unreadable_page;
    ASSERT_TRUE(unreadable_page.ok());
    plant_leaf(unreadable_page);
    expect_unconfirmed_post_commit_enable_is_retained(unreadable_page, "PostCommitIndeterminate", true);
}

TEST(HookBackendException, InlineDisableReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_disable_exceptions_reconciled(page, install_leaf(page, "InlineDisableException"), true,
                                         "InlineDisableException");
}

TEST(HookBackendException, MidDisableReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_disable_exceptions_reconciled(page, install_mid_leaf(page, "MidDisableException"), false,
                                         "MidDisableException");
}

TEST(HookBackendException, InlinePostDisableForeignRetainsRecoverableActiveState)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_post_disable_uncertainty_reconciled(page, install_leaf(page, "InlineDisableForeign"), true,
                                               PostDisableWitness::Foreign, "InlineDisableForeign");
}

TEST(HookBackendException, MidPostDisableIndeterminateRetainsRecoverableActiveState)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_post_disable_uncertainty_reconciled(page, install_mid_leaf(page, "MidDisableIndeterminate"), false,
                                               PostDisableWitness::Indeterminate, "MidDisableIndeterminate");
}

TEST(HookBackendException, InlineRollbackReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_rollback_exceptions_reconciled(page, install_leaf(page, "InlineRollbackException"), true,
                                          "InlineRollbackException");
}

TEST(HookBackendException, MidRollbackReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_rollback_exceptions_reconciled(page, install_mid_leaf(page, "MidRollbackException"), false,
                                          "MidRollbackException");
}

TEST(HookBackendException, MidPostRollbackForeignRetainsRecoverableActiveState)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_rollback_uncertainty_reconciled(page, install_mid_leaf(page, "MidRollbackForeign"), "MidRollbackForeign");
}

TEST(HookBackendException, InlineTeardownReconcilesAfterMutationThrow)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_teardown_after_mutation_exception_reconciled(page, install_leaf(page, "InlineTeardownException"),
                                                        "InlineTeardownException");
}

TEST(HookBackendException, MidTeardownReconcilesAfterMutationThrow)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_teardown_after_mutation_exception_reconciled(page, install_mid_leaf(page, "MidTeardownException"),
                                                        "MidTeardownException");
}

TEST(HookBackendException, OriginalWitnessMakesPersistentTeardownThrowDestructionSafe)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "OriginalPersistentTeardownThrow");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    std::optional<Hook> hook{std::move(*installed)};
    const PrologueSpan pristine = read_prologue_span(page);
    const std::size_t armed_before = armed_population();
    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    ASSERT_TRUE(hook->enable().has_value());
    ASSERT_EQ(armed_population(), armed_before + 1);

    // Simulate an external restoration before teardown. The backend still reports enabled, so the caught throw must
    // be followed by logical-state reconciliation before its destructor can run under the still-armed seam.
    write_prologue_span(page, pristine);
    {
        const BackendToggleExceptionScope exception{page.addr(0), ToggleExceptionStage::BeforeMutation};
        hook.reset();
    }

    EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
    EXPECT_EQ(read_prologue_span(page), pristine);
    EXPECT_EQ(armed_population(), armed_before);
    EXPECT_FALSE(is_target_hooked(Address{page.addr(0)}));
    EXPECT_EQ(DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
              leaks_before);
}

TEST(HookBackendException, TeardownPinLoggingContainsRealAllocationFailure)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "TeardownPinLoggingAllocationFailure");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    std::optional<Hook> hook{std::move(*installed)};
    const std::size_t leaks_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    ASSERT_TRUE(hook->enable().has_value());

    {
        const BackendToggleExceptionScope exception{page.addr(0), ToggleExceptionStage::BeforeMutation};
        const dmk_test::AllocFailScope fail_allocations{0};
        hook.reset();
    }

    EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
    EXPECT_EQ(DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
              leaks_before + 1);
    EXPECT_TRUE(is_target_hooked(Address{page.addr(0)}));
    page.abandon();
}

// The third toggle site. enable() also disarms: when the arm lands but the witness cannot attribute the bytes, it runs
// a compensating disable() before it may publish Disabled. That disable copies this hook's saved prologue back
// unconditionally, exactly like the one Hook::disable() drives, so it needs the same ownership refusal or a writer who
// took the window between the patch and the witness has its bytes destroyed by the rollback. The other two ownership
// cases cannot see this: both refuse at the entry gate and never reach a backend call at all.
//
// Mutation: dropping the witness_permits_write guard on the rollback makes the saved prologue overwrite the foreign
// patch, so read_prologue() comes back as the original leaf and the error code becomes EnableFailed.
TEST(HookBackendOwnership, EnableRollbackDoesNotOverwriteForeignPrologue)
{
    std::uintptr_t pinned_target = 0;
    {
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);

        std::array<std::uint8_t, 6> foreign{};
        const std::size_t leaks_before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
        {
            Result<Hook> installed = install_leaf(page, "ForeignRollback");
            ASSERT_TRUE(installed.has_value()) << installed.error().message();
            Hook hook = std::move(*installed);

            Result<void> enabled;
            {
                const HookEnableWitnessOverrideScope scope(&plant_foreign_then_reject, page);
                enabled = hook.enable();
            }
            foreign = read_prologue(page);
            // The seam only runs once the backend's enable committed, so reaching a non-original prologue at all proves
            // the arm landed and the override fired; a vacuous run would still read the planted leaf here.
            EXPECT_EQ(foreign, (std::array<std::uint8_t, 6>{0xE9, 0x7B, 0x00, 0x00, 0x00, 0x90}));

            // The rollback was refused, so the foreign writer's bytes are still exactly what it wrote.
            ASSERT_FALSE(enabled.has_value());
            EXPECT_EQ(enabled.error().code, ErrorCode::DisableFailed);
            // Nothing proved this hook disarmed, so it keeps reporting the truthful active state and its trampoline
            // stays reachable for the caller to quiesce.
            EXPECT_TRUE(hook.is_enabled());
        }

        // Teardown sees the same foreign window and pins rather than restoring, so the bytes survive that too.
        EXPECT_EQ(
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
            leaks_before + 1);
        EXPECT_EQ(read_prologue(page), foreign);
        pinned_target = page.addr();
        // The ledger keeps this address pinned for process life, so the fixture must not hand it back to the allocator.
        page.abandon();
    }

    MEMORY_BASIC_INFORMATION memory_info{};
    const SIZE_T queried =
        VirtualQuery(reinterpret_cast<const void *>(pinned_target), &memory_info, sizeof(memory_info));
    ASSERT_EQ(queried, sizeof(memory_info));
    EXPECT_EQ(memory_info.State, MEM_COMMIT) << "the pinned target reservation must survive fixture destruction";
    EXPECT_TRUE(is_target_hooked(Address{pinned_target}));
}
#endif // DMK_ENABLE_TEST_SEAMS

namespace
{
    using DetourModKit::Subscription;
    using DetourModKit::diagnostics::HookLifecycleEvent;
    using DetourModKit::diagnostics::HookTransition;

    struct LifecycleNameProbe
    {
        std::string expected;
        std::optional<Hook> hook;
        std::size_t destroyed{0};
        std::size_t matches{0};
        std::size_t mismatches{0};
        // Runs before hook destruction. The rollback-failure case clears the toggle exception seam first.
        void (*before_destroy)() noexcept {nullptr};
        Subscription destroyer;
        Subscription comparer;
    };

    /**
     * @brief Installs the destroyer before the comparer for one transition.
     * @details Subscriber order makes hook destruction precede the name read.
     */
    void arm_lifecycle_name_probe(LifecycleNameProbe &probe, HookTransition transition)
    {
        probe.destroyer = DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [&probe, transition](const HookLifecycleEvent &event)
            {
                if (event.transition == transition && event.name == probe.expected && probe.hook.has_value())
                {
                    if (probe.before_destroy != nullptr)
                    {
                        probe.before_destroy();
                    }
                    probe.hook.reset();
                    ++probe.destroyed;
                }
            });
        probe.comparer = DetourModKit::diagnostics::hook_lifecycle().subscribe(
            [&probe, transition](const HookLifecycleEvent &event)
            {
                if (event.transition != transition)
                {
                    return;
                }
                // Copy the name after hook destruction. A stale view then reads freed Impl storage.
                const std::string copied{event.name};
                if (copied == probe.expected)
                {
                    ++probe.matches;
                }
                else
                {
                    ++probe.mismatches;
                }
            });
    }

    /// Returns a hook name beyond every supported small-string capacity.
    std::string long_hook_name(const char *suffix)
    {
        std::string name{"HookLifecycleName_0123456789012345678901234567890123456"};
        name += '_';
        name += suffix;
        return name;
    }
} // namespace

TEST(HookLifecycleName, NormalEnableEventNameSurvivesSubscriberDestroyingTheHook)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);

    LifecycleNameProbe probe;
    probe.expected = long_hook_name("NormalEnable");
    Result<Hook> installed = install_leaf(page, probe.expected.c_str());
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    probe.hook.emplace(std::move(*installed));
    arm_lifecycle_name_probe(probe, HookTransition::Enabled);

    const Result<void> enabled = probe.hook->enable();
    EXPECT_TRUE(enabled.has_value());

    EXPECT_EQ(probe.destroyed, 1u);
    EXPECT_EQ(probe.matches, 1u) << "the Enabled event name must stay readable after the hook is destroyed";
    EXPECT_EQ(probe.mismatches, 0u);
    EXPECT_FALSE(probe.hook.has_value());
    EXPECT_EQ(read_prologue_span(page), pristine);
}

TEST(HookLifecycleName, DisableEventNameSurvivesSubscriberDestroyingTheHook)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);

    LifecycleNameProbe probe;
    probe.expected = long_hook_name("Disable");
    Result<Hook> installed = install_leaf(page, probe.expected.c_str());
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    probe.hook.emplace(std::move(*installed));
    ASSERT_TRUE(probe.hook->enable().has_value());
    arm_lifecycle_name_probe(probe, HookTransition::Disabled);

    const Result<void> disabled = probe.hook->disable();
    EXPECT_TRUE(disabled.has_value());

    EXPECT_EQ(probe.destroyed, 1u);
    EXPECT_EQ(probe.matches, 1u) << "the Disabled event name must stay readable after the hook is destroyed";
    EXPECT_EQ(probe.mismatches, 0u);
    EXPECT_FALSE(probe.hook.has_value());
    EXPECT_EQ(read_prologue_span(page), pristine);
}

#if defined(DMK_ENABLE_TEST_SEAMS)

namespace
{
    void arm_lifecycle_name_copy_failure() noexcept
    {
        dmk_test::arm_alloc_failure(0);
    }

    class LifecycleNameCopyFailureScope
    {
    public:
        LifecycleNameCopyFailureScope() noexcept
        {
            DetourModKit::detail::g_hook_backend_disable_probe = &arm_lifecycle_name_copy_failure;
        }

        ~LifecycleNameCopyFailureScope() noexcept
        {
            DetourModKit::detail::g_hook_backend_disable_probe = nullptr;
            dmk_test::disarm_alloc_failure();
        }

        LifecycleNameCopyFailureScope(const LifecycleNameCopyFailureScope &) = delete;
        LifecycleNameCopyFailureScope &operator=(const LifecycleNameCopyFailureScope &) = delete;
        LifecycleNameCopyFailureScope(LifecycleNameCopyFailureScope &&) = delete;
        LifecycleNameCopyFailureScope &operator=(LifecycleNameCopyFailureScope &&) = delete;
    };
} // namespace

TEST(HookLifecycleName, AllocationFailurePublishesEmptyName)
{
    DMK_REQUIRE_PROXY_FREE_STL();

    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);

    const std::string name = long_hook_name("AllocationFailure");
    Result<Hook> installed = install_leaf(page, name.c_str());
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_TRUE(hook.enable().has_value());

    std::size_t disabled_events = 0;
    std::size_t empty_names = 0;
    auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
        [&](const HookLifecycleEvent &event)
        {
            if (event.transition == HookTransition::Disabled)
            {
                ++disabled_events;
                empty_names += event.name.empty() ? 1u : 0u;
            }
        });

    Result<void> disabled;
    {
        const LifecycleNameCopyFailureScope failure;
        disabled = hook.disable();
    }

    ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
    EXPECT_FALSE(hook.is_enabled());
    EXPECT_EQ(disabled_events, 1u);
    EXPECT_EQ(empty_names, 1u);
    EXPECT_EQ(read_prologue_span(page), pristine);
}

TEST(HookLifecycleName, CommittedFailureEnableEventNameSurvivesSubscriberDestroyingTheHook)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);

    LifecycleNameProbe probe;
    probe.expected = long_hook_name("CommittedFailureEnable");
    Result<Hook> installed = install_leaf(page, probe.expected.c_str());
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    probe.hook.emplace(std::move(*installed));
    arm_lifecycle_name_probe(probe, HookTransition::Enabled);

    Result<void> enabled{};
    {
        const BackendReprotectFailureScope seam{page.addr(0)};
        enabled = probe.hook->enable();
    }
    ASSERT_FALSE(enabled.has_value());
    EXPECT_EQ(enabled.error().code, ErrorCode::BackendFailed);

    EXPECT_EQ(probe.destroyed, 1u);
    EXPECT_EQ(probe.matches, 1u) << "the committed-failure Enabled event name must stay readable";
    EXPECT_EQ(probe.mismatches, 0u);
    EXPECT_FALSE(probe.hook.has_value());
    EXPECT_EQ(read_prologue_span(page), pristine);
}

TEST(HookLifecycleName, RollbackFailureEnableEventNameSurvivesSubscriberDestroyingTheHook)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);

    LifecycleNameProbe probe;
    probe.expected = long_hook_name("RollbackFailureEnable");
    Result<Hook> installed = install_leaf(page, probe.expected.c_str());
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    probe.hook.emplace(std::move(*installed));
    // The toggle-exception seam fires during rollback, and the witness override re-arms it on each enable witness.
    // Clear it before in-handler destruction so the Hook destructor can restore the target.
    probe.before_destroy = []() noexcept
    { DetourModKit::detail::set_backend_toggle_exception_for_test(nullptr, false); };
    arm_lifecycle_name_probe(probe, HookTransition::Enabled);

    Result<void> enabled{};
    s_rollback_exception_stage = ToggleExceptionStage::BeforeMutation;
    s_enable_witness_callbacks = 0;
    s_enable_confirmed_callbacks = 0;
    {
        const HookEnableWitnessOverrideScope seam{&arm_rollback_exception_then_reject, page};
        enabled = probe.hook->enable();
    }
    ASSERT_FALSE(enabled.has_value());
    EXPECT_EQ(enabled.error().code, ErrorCode::DisableFailed);
    EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);

    EXPECT_EQ(probe.destroyed, 1u);
    EXPECT_EQ(probe.matches, 1u) << "the rollback-failure Enabled event name must stay readable";
    EXPECT_EQ(probe.mismatches, 0u);
    EXPECT_FALSE(probe.hook.has_value());
    EXPECT_EQ(read_prologue_span(page), pristine);
}

#endif // DMK_ENABLE_TEST_SEAMS
