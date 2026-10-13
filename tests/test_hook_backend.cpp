/**
 * @file test_hook_backend.cpp
 * @brief Proofs for managed hook/backend transaction ownership and exception containment.
 *
 * The backend can report failure or throw before or after its mutation callback. Address-scoped seams prove that DMK
 * contains those exceptions, reconciles committed bytes, and preserves state across enable, disable, rollback, and
 * teardown. Ownership cases prove that emitted-patch provenance is required and that Foreign bytes are never
 * overwritten. Relay cases prove the aligned relay switch, and relay-cell cases prove the position a later generation
 * claims. Each throwing GoogleTest is discovered as a separate CTest child, so an exception escaping a noexcept
 * boundary fails the case as a process termination.
 */

#include <gtest/gtest.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <process.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <functional>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"

#include "fixtures/log_capture.hpp"
#include "fixtures/proof_section.hpp"
#include "fixtures/scratch_page.hpp"
#include "internal/diagnostics_population.hpp"
#include "test_alloc_probe.hpp"

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    void set_backend_reprotect_failure_target(void *target) noexcept;
    void set_backend_toggle_exception_for_test(void *target, bool after_mutation) noexcept;
    [[nodiscard]] std::size_t backend_toggle_exception_catches_for_test() noexcept;
    [[nodiscard]] std::size_t backend_trap_protect_calls_for_test() noexcept;
    enum class TrapTransactionOutcome : std::uint8_t
    {
        Restored,
        ReportedFailure,
        Threw,
    };
    [[nodiscard]] TrapTransactionOutcome drive_backend_trap_transaction_for_test(
        void *from,
        void *to,
        std::size_t len,
        const std::function<void()> &run_fn
    ) noexcept;
    struct BackendInstructionFlushObservation
    {
        void *address;
        std::size_t size;
        std::size_t protect_calls_before;
        bool succeeded;
    };
    void reset_backend_instruction_flush_trace_for_test() noexcept;
    void set_backend_instruction_flush_failure_call_for_test(std::size_t call) noexcept;
    [[nodiscard]] std::size_t backend_instruction_flush_trace_size_for_test() noexcept;
    [[nodiscard]] BackendInstructionFlushObservation
    backend_instruction_flush_trace_for_test(std::size_t index) noexcept;
    void force_backend_ff_hook_for_test(bool force) noexcept;
    [[nodiscard]] std::size_t backend_instruction_boundary_trace_size_for_test() noexcept;
    [[nodiscard]] std::array<std::size_t, 2> backend_instruction_boundary_trace_for_test(std::size_t index) noexcept;
    [[nodiscard]] std::uint8_t backend_last_inline_error_type_for_test() noexcept;
    void omit_backend_relay_cell_for_test(bool omit) noexcept;
    void set_backend_coordinator_refusal_for_test(unsigned refusal) noexcept;
    struct BackendCoordinatorCounts
    {
        std::size_t live{0};
        std::size_t retained{0};
        std::size_t vacant{0};
        std::size_t free{0};
    };
    [[nodiscard]] BackendCoordinatorCounts backend_coordinator_counts_for_test() noexcept;
    enum class BackendProbeKind : std::uint8_t
    {
        Inline,
        Mid,
        Routed,
    };
    enum class BackendProbeOperation : std::uint8_t
    {
        Enable,
        Disable,
        Bypass,
        Resume,
        Vacate,
        Reset,
        MoveAssign,
        RetainRoute,
    };
    struct BackendProbeState
    {
        bool valid{false};
        bool enabled{false};
        bool claimed{false};
        bool bypassed{false};
        void *trampoline{nullptr};
        void *relay_slot{nullptr};
        void *relay_cell{nullptr};
    };
    struct BackendProbe;
    [[nodiscard]] BackendProbe *create_backend_probe_for_test(
        BackendProbeKind kind,
        void *target,
        void *destination,
        std::string_view position_name
    ) noexcept;
    [[nodiscard]] bool drive_backend_probe_for_test(BackendProbe *probe, BackendProbeOperation operation) noexcept;
    [[nodiscard]] BackendProbeState backend_probe_state_for_test(const BackendProbe *probe) noexcept;
    void destroy_backend_probe_for_test(BackendProbe *probe) noexcept;
    extern bool (*g_hook_enable_witness_override)(bool) noexcept;
    extern void (*g_hook_backend_disable_probe)() noexcept;
    extern void (*g_hook_toggle_publication_probe)(bool, bool, bool, bool) noexcept;
    extern void (*g_vmt_before_capture_probe)() noexcept;
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
    using DetourModKit::hook::Options;
    using DetourModKit::hook::Prologue;

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
        return inline_at(
            InlineRequest{
                .name = name,
                .target = Address{page.addr(0)},
            },
            reinterpret_cast<void (*)()>(&detour_leaf)
        );
    }

    Result<Hook> install_mid_leaf(dmk_test::ScratchPage &page, const char *name)
    {
        return mid_at(
            MidRequest{
                .name = name,
                .target = Address{page.addr(0)},
            },
            &mid_detour
        );
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
        DetourModKit::detail::hook_population::read(
            s_toggle_publication.total,
            s_toggle_publication.active,
            s_toggle_publication.disabled
        );
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
            DetourModKit::detail::set_backend_toggle_exception_for_test(
                reinterpret_cast<void *>(target),
                stage == ToggleExceptionStage::AfterMutation
            );
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
    void expect_enable_exceptions_reconciled(
        dmk_test::ScratchPage &page,
        Result<Hook> installed,
        bool is_inline,
        std::string_view name
    )
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
            }
        );

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

    void expect_disable_exceptions_reconciled(
        dmk_test::ScratchPage &page,
        Result<Hook> installed,
        bool is_inline,
        std::string_view name
    )
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
            }
        );

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

    void expect_teardown_after_mutation_exception_reconciled(
        dmk_test::ScratchPage &page,
        Result<Hook> installed,
        std::string_view name
    )
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
            }
        );

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
            leaks_before
        );
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
        if (::VirtualProtect(
                s_witness_override_page->base(),
                dmk_test::ScratchPage::PAGE_SIZE,
                PAGE_NOACCESS,
                &previous
            ) != FALSE)
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
        if (::VirtualProtect(
                s_witness_override_page->base(),
                dmk_test::ScratchPage::PAGE_SIZE,
                s_witness_previous_protection,
                &ignored
            ) == FALSE)
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
            if (::VirtualProtect(
                    s_witness_override_page->base(),
                    dmk_test::ScratchPage::PAGE_SIZE,
                    PAGE_NOACCESS,
                    &previous
                ) != FALSE)
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
                s_rollback_exception_stage == ToggleExceptionStage::AfterMutation
            );
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

    void expect_post_disable_uncertainty_reconciled(
        dmk_test::ScratchPage &page,
        Result<Hook> installed,
        bool is_inline,
        PostDisableWitness witness,
        std::string_view name
    )
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
            }
        );

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

    void
    expect_rollback_uncertainty_reconciled(dmk_test::ScratchPage &page, Result<Hook> installed, std::string_view name)
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
            }
        );

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

    void expect_unconfirmed_post_commit_enable_is_retained(
        dmk_test::ScratchPage &page,
        const char *name,
        bool make_unreadable
    )
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
            }
        );

        Result<void> enabled;
        PrologueSpan owned_patch{};
        bool protection_restored = true;
        s_enable_witness_callbacks = 0;
        s_enable_confirmed_callbacks = 0;
        {
            const BackendToggleExceptionScope exception{page.addr(0), ToggleExceptionStage::AfterMutation};
            const HookEnableWitnessOverrideScope witness{
                make_unreadable ? &make_unreadable_then_reject : &plant_foreign_then_reject,
                page
            };
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

    void expect_rollback_exceptions_reconciled(
        dmk_test::ScratchPage &page,
        Result<Hook> installed,
        bool is_inline,
        std::string_view name
    )
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
            }
        );

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

TEST(HookBackendCacheFlush, GeneratedE9FfRouteAndMidRangesFlushBeforePublication)
{
    dmk_test::ScratchPage e9_page;
    ASSERT_TRUE(e9_page.ok());
    plant_leaf(e9_page);
    DetourModKit::detail::reset_backend_instruction_flush_trace_for_test();
    Result<Hook> e9_installed = install_leaf(e9_page, "CacheFlushE9");
    ASSERT_TRUE(e9_installed.has_value()) << e9_installed.error().message();
    Hook e9_hook = std::move(*e9_installed);
    ASSERT_EQ(DetourModKit::detail::backend_instruction_flush_trace_size_for_test(), 1U);
    const auto e9_flush = DetourModKit::detail::backend_instruction_flush_trace_for_test(0);
    EXPECT_EQ(e9_flush.address, reinterpret_cast<void *>(e9_hook.original<LeafFn>()));
    EXPECT_GT(e9_flush.size, 0U);
    EXPECT_TRUE(e9_flush.succeeded);

    dmk_test::ScratchPage ff_page;
    ASSERT_TRUE(ff_page.ok());
    plant_leaf(ff_page);
    DetourModKit::detail::reset_backend_instruction_flush_trace_for_test();
    DetourModKit::detail::force_backend_ff_hook_for_test(true);
    Result<Hook> ff_installed = install_leaf(ff_page, "CacheFlushFF");
    ASSERT_TRUE(ff_installed.has_value()) << ff_installed.error().message();
    Hook ff_hook = std::move(*ff_installed);
    ASSERT_EQ(DetourModKit::detail::backend_instruction_flush_trace_size_for_test(), 1U);
    const auto ff_flush = DetourModKit::detail::backend_instruction_flush_trace_for_test(0);
    EXPECT_EQ(ff_flush.address, reinterpret_cast<void *>(ff_hook.original<LeafFn>()));
    EXPECT_GT(ff_flush.size, e9_flush.size);
    EXPECT_TRUE(ff_flush.succeeded);

    dmk_test::ScratchPage mid_page;
    ASSERT_TRUE(mid_page.ok());
    plant_leaf(mid_page);
    DetourModKit::detail::reset_backend_instruction_flush_trace_for_test();
    Result<Hook> mid_installed = install_mid_leaf(mid_page, "CacheFlushMid");
    ASSERT_TRUE(mid_installed.has_value()) << mid_installed.error().message();
    ASSERT_EQ(DetourModKit::detail::backend_instruction_flush_trace_size_for_test(), 5U);
    for (std::size_t i = 0; i < 5; ++i)
    {
        const auto flush = DetourModKit::detail::backend_instruction_flush_trace_for_test(i);
        EXPECT_NE(flush.address, nullptr);
        EXPECT_GT(flush.size, 0U);
        EXPECT_TRUE(flush.succeeded);
    }
    EXPECT_EQ(
        DetourModKit::detail::backend_instruction_flush_trace_for_test(0).address,
        DetourModKit::detail::backend_instruction_flush_trace_for_test(2).address
    );
    EXPECT_EQ(
        DetourModKit::detail::backend_instruction_flush_trace_for_test(1).address,
        DetourModKit::detail::backend_instruction_flush_trace_for_test(3).address
    );
}

TEST(HookBackendCacheFlush, TargetCommitFlushesBeforeProtectionRestoreInBothDirections)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    Result<Hook> installed = install_leaf(page, "CacheFlushCommitOrder");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);

    const auto verify_commit = [&](const auto &toggle)
    {
        DetourModKit::detail::reset_backend_instruction_flush_trace_for_test();
        const std::size_t protects_before = DetourModKit::detail::backend_trap_protect_calls_for_test();
        ASSERT_TRUE(toggle().has_value());
        const std::size_t protects_after = DetourModKit::detail::backend_trap_protect_calls_for_test();
        ASSERT_EQ(DetourModKit::detail::backend_instruction_flush_trace_size_for_test(), 1U);
        const auto flush = DetourModKit::detail::backend_instruction_flush_trace_for_test(0);
        EXPECT_EQ(flush.address, reinterpret_cast<void *>(page.addr(0)));
        EXPECT_GT(flush.size, 0U);
        EXPECT_TRUE(flush.succeeded);
        EXPECT_GT(flush.protect_calls_before, protects_before);
        EXPECT_LT(flush.protect_calls_before, protects_after);
    };

    verify_commit([&hook] { return hook.enable(); });
    verify_commit([&hook] { return hook.disable(); });
}

TEST(HookBackendCacheFlush, GenerationFailureRefusesEveryExecutableRangeBeforePublication)
{
    const auto verify_refusal = [](const char *name, bool mid, bool force_ff, std::size_t failure_call)
    {
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);
        DetourModKit::detail::reset_backend_instruction_flush_trace_for_test();
        DetourModKit::detail::force_backend_ff_hook_for_test(force_ff);
        DetourModKit::detail::set_backend_instruction_flush_failure_call_for_test(failure_call);

        Result<Hook> installed = mid ? install_mid_leaf(page, name) : install_leaf(page, name);
        EXPECT_FALSE(installed.has_value());
        ASSERT_EQ(DetourModKit::detail::backend_instruction_flush_trace_size_for_test(), failure_call);
        for (std::size_t i = 0; i + 1 < failure_call; ++i)
        {
            EXPECT_TRUE(DetourModKit::detail::backend_instruction_flush_trace_for_test(i).succeeded);
        }
        EXPECT_FALSE(DetourModKit::detail::backend_instruction_flush_trace_for_test(failure_call - 1).succeeded);
        EXPECT_EQ(call_target(page), LEAF_RESULT);
    };

    verify_refusal("CacheFlushE9Failure", false, false, 1);
    verify_refusal("CacheFlushFFFailure", false, true, 1);
    verify_refusal("CacheFlushRouteFailure", true, false, 2);
    verify_refusal("CacheFlushContinuationFailure", true, false, 3);
    verify_refusal("CacheFlushContinuationExitFailure", true, false, 4);
    verify_refusal("CacheFlushMidFailure", true, false, 5);
}

TEST(HookBackendCacheFlush, RestoreFailureOutranksACommittedFlushFailure)
{
    dmk_test::ScratchPage flush_page;
    ASSERT_TRUE(flush_page.ok());
    plant_leaf(flush_page);
    Result<Hook> flush_installed = install_leaf(flush_page, "CacheFlushFailureType");
    ASSERT_TRUE(flush_installed.has_value()) << flush_installed.error().message();
    Hook flush_hook = std::move(*flush_installed);
    DetourModKit::detail::set_backend_instruction_flush_failure_call_for_test(1);
    EXPECT_FALSE(flush_hook.enable().has_value());
    const std::uint8_t flush_error_type = DetourModKit::detail::backend_last_inline_error_type_for_test();
    ASSERT_TRUE(flush_hook.is_enabled());
    DetourModKit::detail::set_backend_instruction_flush_failure_call_for_test(1);
    EXPECT_FALSE(flush_hook.disable().has_value());
    EXPECT_FALSE(flush_hook.is_enabled());
    EXPECT_EQ(call_target(flush_page), LEAF_RESULT);

    dmk_test::ScratchPage restore_page;
    ASSERT_TRUE(restore_page.ok());
    plant_leaf(restore_page);
    Result<Hook> restore_installed = install_leaf(restore_page, "CacheFlushRestorePrecedence");
    ASSERT_TRUE(restore_installed.has_value()) << restore_installed.error().message();
    Hook restore_hook = std::move(*restore_installed);
    DetourModKit::detail::set_backend_instruction_flush_failure_call_for_test(1);
    DetourModKit::detail::set_backend_reprotect_failure_target(reinterpret_cast<void *>(restore_page.addr(0)));
    EXPECT_FALSE(restore_hook.enable().has_value());
    DetourModKit::detail::set_backend_reprotect_failure_target(nullptr);
    const std::uint8_t combined_error_type = DetourModKit::detail::backend_last_inline_error_type_for_test();
    EXPECT_NE(combined_error_type, flush_error_type);
    EXPECT_TRUE(restore_hook.is_enabled());
    EXPECT_TRUE(restore_hook.disable().has_value());
}

TEST(HookBackendRelocation, TwoWidenedShortBranchesUseTheCompletedBoundaryMap)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0, {0xEB, 0x02, 0xEB, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3});

    Result<Hook> installed = inline_at(
        InlineRequest{
            .name = "TwoWidenedShortBranches",
            .target = Address{page.addr(0)},
            .options = Options{.prologue = Prologue::Relocate},
        },
        reinterpret_cast<void (*)()>(&detour_leaf)
    );
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_EQ(DetourModKit::detail::backend_instruction_boundary_trace_size_for_test(), 3U);
    EXPECT_EQ(DetourModKit::detail::backend_instruction_boundary_trace_for_test(0), (std::array<std::size_t, 2>{0, 0}));
    EXPECT_EQ(DetourModKit::detail::backend_instruction_boundary_trace_for_test(1), (std::array<std::size_t, 2>{2, 5}));
    EXPECT_EQ(
        DetourModKit::detail::backend_instruction_boundary_trace_for_test(2),
        (std::array<std::size_t, 2>{4, 10})
    );

    ASSERT_TRUE(hook.enable().has_value());
    EXPECT_EQ(call_target(page), DETOUR_RESULT);
    const Result<int> original = hook.try_call<int>();
    ASSERT_TRUE(original.has_value()) << original.error().message();
    EXPECT_EQ(*original, LEAF_RESULT);
    EXPECT_TRUE(hook.disable().has_value());
}

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
        }
    );

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
        }
    );

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
    EXPECT_EQ(
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
        leaks_before
    );
}

#endif // DMK_ENABLE_TEST_SEAMS

// A third party owns the prologue. The backend's disable copies its saved bytes back unconditionally, so the Active
// hook switches its relay off in place of a restore. Mutation: if OwnedPatch and Foreign merge into one Patched state,
// the foreign bytes read as ours, and the restore clobbers them.
TEST(HookBackendOwnership, ForeignPrologueIsNotOverwrittenByDisable)
{
    std::uintptr_t retired_target = 0;
    {
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);

        std::array<std::uint8_t, 6> foreign{};
        const std::size_t leaks_before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
        const std::size_t residue_before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookResidue);
        {
            Result<Hook> installed = install_leaf(page, "ForeignDisable");
            ASSERT_TRUE(installed.has_value()) << installed.error().message();
            Hook hook = std::move(*installed);
            ASSERT_TRUE(hook.enable().has_value());

            plant_foreign_patch(page);
            foreign = read_prologue(page);

            const Result<void> disabled = hook.disable();
            ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
            // The bypass wrote no target byte, so the foreign bytes are exactly as they were left.
            EXPECT_EQ(read_prologue(page), foreign);
            // The relay now sends every caller past the detour, so the hook reports the disarm.
            EXPECT_FALSE(hook.is_enabled());
        }

        // Teardown retires the bypassed hook in place of a restore. The foreign bytes survive, and the position books
        // HookResidue, not HookManager, because no path reaches the detour.
        EXPECT_EQ(
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
            leaks_before
        );
        EXPECT_EQ(
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookResidue),
            residue_before + 1
        );
        EXPECT_EQ(read_prologue(page), foreign);
        retired_target = page.addr();
        // The position stays in the target's chain for process life, so the fixture must not hand the page back.
        page.abandon();
    }

    MEMORY_BASIC_INFORMATION memory_info{};
    const SIZE_T queried =
        VirtualQuery(reinterpret_cast<const void *>(retired_target), &memory_info, sizeof(memory_info));
    ASSERT_EQ(queried, sizeof(memory_info));
    EXPECT_EQ(memory_info.State, MEM_COMMIT) << "the retired target reservation must survive fixture destruction";
    EXPECT_TRUE(is_target_hooked(Address{retired_target}));
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
    EXPECT_FALSE(enabled.has_value());
    if (!enabled)
    {
        EXPECT_EQ(enabled.error().code, ErrorCode::EnableFailed);
    }
    EXPECT_EQ(read_prologue(page), foreign);
    EXPECT_FALSE(hook.is_enabled());

    // Restoring the prologue by hand makes the hook usable again: the refusal is a property of the bytes, not a latch.
    plant_leaf(page);
    EXPECT_TRUE(hook.enable().has_value());
    EXPECT_TRUE(hook.is_enabled());
}

TEST(HookBackendOwnership, IdempotentEnableReconcilesOriginal)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "IdempotentEnableOriginal");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);

    const PrologueSpan pristine = read_prologue_span(page);
    const std::size_t armed_before = armed_population();
    ASSERT_TRUE(hook.enable().has_value());
    const PrologueSpan armed = read_prologue_span(page);
    ASSERT_NE(armed, pristine);
    ASSERT_EQ(call_target(page), DETOUR_RESULT);
    ASSERT_EQ(armed_population(), armed_before + 1);

    // Restore the saved prologue while the published state remains Active.
    write_prologue_span(page, pristine);
    ASSERT_EQ(call_target(page), LEAF_RESULT);

    std::size_t enabled_events = 0;
    std::size_t disabled_events = 0;
    const auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
        [&](const DetourModKit::diagnostics::HookLifecycleEvent &event)
        {
            if (event.name != "IdempotentEnableOriginal")
            {
                return;
            }
            enabled_events += event.transition == DetourModKit::diagnostics::HookTransition::Enabled ? 1u : 0u;
            disabled_events += event.transition == DetourModKit::diagnostics::HookTransition::Disabled ? 1u : 0u;
        }
    );
    const Result<void> again = hook.enable();
    ASSERT_TRUE(again.has_value()) << again.error().message();
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(read_prologue_span(page), armed);
    EXPECT_EQ(call_target(page), DETOUR_RESULT);
    const Result<int> original = hook.try_call<int>();
    ASSERT_TRUE(original.has_value()) << original.error().message();
    EXPECT_EQ(*original, LEAF_RESULT);
    EXPECT_EQ(enabled_events, 1u);
    EXPECT_EQ(disabled_events, 0u);
    EXPECT_EQ(armed_population(), armed_before + 1);

    ASSERT_TRUE(hook.disable().has_value());
    EXPECT_EQ(call_target(page), LEAF_RESULT);
    EXPECT_EQ(armed_population(), armed_before);
}

TEST(HookBackendOwnership, IdempotentDisableReconcilesOwnedPatch)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "IdempotentDisableOwnedPatch");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);

    const PrologueSpan pristine = read_prologue_span(page);
    const std::size_t armed_before = armed_population();
    ASSERT_TRUE(hook.enable().has_value());
    const PrologueSpan armed = read_prologue_span(page);
    ASSERT_NE(armed, pristine);
    ASSERT_TRUE(hook.disable().has_value());
    ASSERT_EQ(read_prologue_span(page), pristine);
    ASSERT_EQ(call_target(page), LEAF_RESULT);
    ASSERT_EQ(armed_population(), armed_before);

    // Restore this hook's exact patch while the published state remains Disabled.
    write_prologue_span(page, armed);

    std::size_t enabled_events = 0;
    std::size_t disabled_events = 0;
    const auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
        [&](const DetourModKit::diagnostics::HookLifecycleEvent &event)
        {
            if (event.name != "IdempotentDisableOwnedPatch")
            {
                return;
            }
            enabled_events += event.transition == DetourModKit::diagnostics::HookTransition::Enabled ? 1u : 0u;
            disabled_events += event.transition == DetourModKit::diagnostics::HookTransition::Disabled ? 1u : 0u;
        }
    );
    const Result<void> again = hook.disable();
    ASSERT_TRUE(again.has_value()) << again.error().message();
    EXPECT_FALSE(hook.is_enabled());
    EXPECT_EQ(read_prologue_span(page), pristine);
    EXPECT_EQ(call_target(page), LEAF_RESULT);
    EXPECT_EQ(armed_population(), armed_before);
    const Result<int> inactive = hook.try_call<int>();
    ASSERT_FALSE(inactive.has_value());
    EXPECT_EQ(inactive.error().code, ErrorCode::InvalidHookState);
    EXPECT_EQ(enabled_events, 0u);
    EXPECT_EQ(disabled_events, 1u);

    ASSERT_TRUE(hook.enable().has_value());
    EXPECT_EQ(call_target(page), DETOUR_RESULT);
    EXPECT_EQ(armed_population(), armed_before + 1);
}

TEST(HookBackendOwnership, IdempotentEnableRejectsForeignBytesFromActive)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "ActiveForeignEnable");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    const PrologueSpan pristine = read_prologue_span(page);
    const std::size_t armed_before = armed_population();
    ASSERT_TRUE(hook.enable().has_value());
    const PrologueSpan armed = read_prologue_span(page);

    std::size_t events = 0;
    const auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
        [&events](const DetourModKit::diagnostics::HookLifecycleEvent &event)
        {
            if (event.name == "ActiveForeignEnable")
            {
                ++events;
            }
        }
    );
    // Preserve the return at offset 5 because the trampoline resumes there.
    page.put(0, {0xE9, 0x7B, 0x00, 0x00, 0x00});
    const PrologueSpan foreign = read_prologue_span(page);

    const Result<void> enabled = hook.enable();
    EXPECT_FALSE(enabled.has_value());
    if (!enabled)
    {
        EXPECT_EQ(enabled.error().code, ErrorCode::EnableFailed);
    }
    EXPECT_EQ(read_prologue_span(page), foreign);
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(armed_population(), armed_before + 1);
    EXPECT_EQ(events, 0u);
    const Result<int> original = hook.try_call<int>();
    EXPECT_TRUE(original.has_value());
    if (original)
    {
        EXPECT_EQ(*original, LEAF_RESULT);
    }

    write_prologue_span(page, armed);
    ASSERT_TRUE(hook.disable().has_value());
    EXPECT_EQ(read_prologue_span(page), pristine);
    EXPECT_EQ(armed_population(), armed_before);
}

TEST(HookBackendOwnership, IdempotentDisableRejectsForeignBytesFromDisabled)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    Result<Hook> installed = install_leaf(page, "DisabledForeignDisable");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    const PrologueSpan pristine = read_prologue_span(page);
    const std::size_t armed_before = armed_population();
    std::size_t events = 0;
    const auto subscription = DetourModKit::diagnostics::hook_lifecycle().subscribe(
        [&events](const DetourModKit::diagnostics::HookLifecycleEvent &event)
        {
            if (event.name == "DisabledForeignDisable")
            {
                ++events;
            }
        }
    );
    plant_foreign_patch(page);
    const PrologueSpan foreign = read_prologue_span(page);

    const Result<void> disabled = hook.disable();
    EXPECT_FALSE(disabled.has_value());
    if (!disabled)
    {
        EXPECT_EQ(disabled.error().code, ErrorCode::DisableFailed);
    }
    EXPECT_EQ(read_prologue_span(page), foreign);
    EXPECT_FALSE(hook.is_enabled());
    EXPECT_EQ(armed_population(), armed_before);
    EXPECT_EQ(events, 0u);
    const Result<int> inactive = hook.try_call<int>();
    EXPECT_FALSE(inactive.has_value());
    if (!inactive)
    {
        EXPECT_EQ(inactive.error().code, ErrorCode::InvalidHookState);
    }

    write_prologue_span(page, pristine);
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
    static_assert(
        sizeof(CLEAN_RELEASE_HOOK_NAME) <= 16,
        "the clean-release hook name must fit the small-string buffer"
    );
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
    EXPECT_EQ(
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
        leaks_before
    );
}

// The HookBackendOwnership cases above sit outside every seam guard on purpose. They drive the ownership rule through
// the public API alone, so the ownership proofs survive a seam-free build. Only the exception cases below need a seam.
#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(HookBackendException, InlineEnableReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_enable_exceptions_reconciled(
        page,
        install_leaf(page, "InlineEnableException"),
        true,
        "InlineEnableException"
    );
}

TEST(HookBackendException, MidEnableReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_enable_exceptions_reconciled(
        page,
        install_mid_leaf(page, "MidEnableException"),
        false,
        "MidEnableException"
    );
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

    expect_disable_exceptions_reconciled(
        page,
        install_leaf(page, "InlineDisableException"),
        true,
        "InlineDisableException"
    );
}

TEST(HookBackendException, MidDisableReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_disable_exceptions_reconciled(
        page,
        install_mid_leaf(page, "MidDisableException"),
        false,
        "MidDisableException"
    );
}

TEST(HookBackendException, InlinePostDisableForeignRetainsRecoverableActiveState)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_post_disable_uncertainty_reconciled(
        page,
        install_leaf(page, "InlineDisableForeign"),
        true,
        PostDisableWitness::Foreign,
        "InlineDisableForeign"
    );
}

TEST(HookBackendException, MidPostDisableIndeterminateRetainsRecoverableActiveState)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_post_disable_uncertainty_reconciled(
        page,
        install_mid_leaf(page, "MidDisableIndeterminate"),
        false,
        PostDisableWitness::Indeterminate,
        "MidDisableIndeterminate"
    );
}

TEST(HookBackendException, InlineRollbackReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_rollback_exceptions_reconciled(
        page,
        install_leaf(page, "InlineRollbackException"),
        true,
        "InlineRollbackException"
    );
}

TEST(HookBackendException, MidRollbackReconcilesBeforeAndAfterMutationThrows)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_rollback_exceptions_reconciled(
        page,
        install_mid_leaf(page, "MidRollbackException"),
        false,
        "MidRollbackException"
    );
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

    expect_teardown_after_mutation_exception_reconciled(
        page,
        install_leaf(page, "InlineTeardownException"),
        "InlineTeardownException"
    );
}

TEST(HookBackendException, MidTeardownReconcilesAfterMutationThrow)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);

    expect_teardown_after_mutation_exception_reconciled(
        page,
        install_mid_leaf(page, "MidTeardownException"),
        "MidTeardownException"
    );
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
    EXPECT_EQ(
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
        leaks_before
    );
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
    EXPECT_EQ(
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
        leaks_before + 1
    );
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
    std::uintptr_t retired_target = 0;
    {
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);

        std::array<std::uint8_t, 6> foreign{};
        const std::size_t leaks_before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
        const std::size_t residue_before =
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookResidue);
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

        // Teardown sees the same foreign window and retires the hook by bypass in place of a restore, so the bytes
        // survive that too. The position books HookResidue, not HookManager.
        EXPECT_EQ(
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
            leaks_before
        );
        EXPECT_EQ(
            DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookResidue),
            residue_before + 1
        );
        EXPECT_EQ(read_prologue(page), foreign);
        retired_target = page.addr();
        // The position stays in the target's chain for process life, so the fixture must not hand the page back.
        page.abandon();
    }

    MEMORY_BASIC_INFORMATION memory_info{};
    const SIZE_T queried =
        VirtualQuery(reinterpret_cast<const void *>(retired_target), &memory_info, sizeof(memory_info));
    ASSERT_EQ(queried, sizeof(memory_info));
    EXPECT_EQ(memory_info.State, MEM_COMMIT) << "the retired target reservation must survive fixture destruction";
    EXPECT_TRUE(is_target_hooked(Address{retired_target}));
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
            }
        );
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
            }
        );
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
        }
    );

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

namespace
{
    /// In-module slot body for the VMT classification race: its page outlives the racing fixture DLL.
    int vmt_race_slot_zero_body() noexcept
    {
        return 7;
    }

    int vmt_race_detour(void *) noexcept
    {
        return 0;
    }

    /// RAII owner for a private on-disk copy of the fixture DLL, so this test controls the only load reference.
    class PrivateFixtureDll final
    {
    public:
        PrivateFixtureDll() = default;
        [[nodiscard]] bool load()
        {
            // The fixture lands beside the test executable, so anchor both the copy source and the private copy
            // there rather than in the current working directory.
            char exe_path[MAX_PATH]{};
            const DWORD length = ::GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
            if (length == 0 || length >= MAX_PATH)
            {
                return false;
            }
            std::string directory(exe_path, length);
            directory.erase(directory.find_last_of('\\') + 1);

            static int s_copy_counter = 0;
            char name[64]{};
            (void)std::snprintf(name, sizeof(name), "hook_target_lib_vmtrace_%d_%d.dll", _getpid(), s_copy_counter++);
            m_path = directory + name;
            if (::CopyFileA((directory + "hook_target_lib.dll").c_str(), m_path.c_str(), FALSE) == 0)
            {
                m_path.clear();
                return false;
            }
            m_handle = ::LoadLibraryA(m_path.c_str());
            return m_handle != nullptr;
        }

        [[nodiscard]] FARPROC symbol(const char *name) const noexcept { return ::GetProcAddress(m_handle, name); }

        [[nodiscard]] HMODULE release() noexcept
        {
            HMODULE handle = m_handle;
            m_handle = nullptr;
            return handle;
        }

        [[nodiscard]] bool make_header_unreadable() noexcept
        {
            SYSTEM_INFO sys_info{};
            ::GetSystemInfo(&sys_info);
            DWORD previous_protection = 0;
            if (::VirtualProtect(m_handle, sys_info.dwPageSize, PAGE_NOACCESS, &previous_protection) == 0)
            {
                return false;
            }
            m_page_size = sys_info.dwPageSize;
            m_previous_protection = previous_protection;
            m_header_unreadable = true;
            return true;
        }

        [[nodiscard]] bool restore_header() noexcept
        {
            if (!m_header_unreadable)
            {
                return true;
            }
            DWORD ignored = 0;
            if (::VirtualProtect(m_handle, m_page_size, m_previous_protection, &ignored) == 0)
            {
                return false;
            }
            m_header_unreadable = false;
            return true;
        }

        ~PrivateFixtureDll() noexcept
        {
            const bool header_readable = restore_header();
            if (header_readable && m_handle != nullptr)
            {
                (void)::FreeLibrary(m_handle);
            }
            if (!m_path.empty())
            {
                (void)::DeleteFileA(m_path.c_str());
            }
        }

        PrivateFixtureDll(const PrivateFixtureDll &) = delete;
        PrivateFixtureDll &operator=(const PrivateFixtureDll &) = delete;
        PrivateFixtureDll(PrivateFixtureDll &&) = delete;
        PrivateFixtureDll &operator=(PrivateFixtureDll &&) = delete;

    private:
        std::string m_path;
        HMODULE m_handle = nullptr;
        SIZE_T m_page_size = 0;
        DWORD m_previous_protection = 0;
        bool m_header_unreadable = false;
    };

    static_assert(!std::is_copy_constructible_v<PrivateFixtureDll>);
    static_assert(!std::is_move_constructible_v<PrivateFixtureDll>);

    HMODULE s_vmt_race_dll = nullptr;
    PrivateFixtureDll *s_vmt_header_fixture = nullptr;
    bool s_vmt_header_protection_changed = false;

    /// Models a foreign FreeLibrary landing between vmt_for's slot pre-count and its guarded capture.
    void unload_vmt_race_dll_before_capture() noexcept
    {
        if (s_vmt_race_dll != nullptr)
        {
            (void)::FreeLibrary(s_vmt_race_dll);
            s_vmt_race_dll = nullptr;
        }
    }

    void protect_vmt_race_header_before_capture() noexcept
    {
        s_vmt_header_protection_changed =
            s_vmt_header_fixture != nullptr && s_vmt_header_fixture->make_header_unreadable();
    }
} // namespace

// Module-lifetime race proof for VMT slot classification (B-66): a slot target's owning module unloads between the
// pre-count walk and the guarded capture. The clone-sizing walk must classify the dead slot from page state without
// faulting, and the published method_count must cover only the slots the clone actually carries, so no admissible
// index can reach an out-of-bounds backend slot write.
TEST(HookBackendVmtClassification, ModuleUnloadBetweenPrecountAndCaptureNormalizesTheSlotCount)
{
    PrivateFixtureDll dll;
    ASSERT_TRUE(dll.load()) << "private fixture DLL copy/load failed, error " << ::GetLastError();
    auto *dll_fn = reinterpret_cast<void *>(dll.symbol("compute_damage"));
    ASSERT_NE(dll_fn, nullptr);

    // Two header words cover the widest ABI RTTI prefix the capture reads; the trailing zero terminates the walk.
    std::array<std::uintptr_t, 5> vtable_storage{
        0,
        0,
        reinterpret_cast<std::uintptr_t>(&vmt_race_slot_zero_body),
        reinterpret_cast<std::uintptr_t>(dll_fn),
        0,
    };
    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(&vtable_storage[2])};
    const std::uintptr_t original_vptr = object.vptr;

    s_vmt_race_dll = dll.release();
    DetourModKit::detail::g_vmt_before_capture_probe = &unload_vmt_race_dll_before_capture;
    Result<DetourModKit::hook::VmtHook> cloned = DetourModKit::hook::vmt_for("VmtCaptureModuleUnloadRace", &object);
    DetourModKit::detail::g_vmt_before_capture_probe = nullptr;
    EXPECT_EQ(s_vmt_race_dll, nullptr) << "the unload probe did not fire";

    // The pre-count saw two executable slots; the clone walk saw the unmapped second slot and normalized to one.
    ASSERT_TRUE(cloned.has_value()) << cloned.error().message();
    {
        DetourModKit::hook::VmtHook vmt = std::move(*cloned);
        EXPECT_TRUE(vmt.hook_method(0, &vmt_race_detour).has_value());
        Result<void> past_count = vmt.hook_method(1, &vmt_race_detour);
        ASSERT_FALSE(past_count.has_value());
        EXPECT_EQ(past_count.error().code, ErrorCode::InvalidArg);
    }
    EXPECT_EQ(object.vptr, original_vptr) << "teardown must restore the seed object's vptr";
}

TEST(HookBackendVmtClassification, UnreadableHeaderBetweenPrecountAndCaptureAvoidsBackendParser)
{
    PrivateFixtureDll dll;
    ASSERT_TRUE(dll.load()) << "private fixture DLL copy/load failed, error " << ::GetLastError();
    auto *dll_fn = reinterpret_cast<void *>(dll.symbol("compute_damage"));
    ASSERT_NE(dll_fn, nullptr);

    std::array<std::uintptr_t, 5> vtable_storage{
        0,
        0,
        reinterpret_cast<std::uintptr_t>(&vmt_race_slot_zero_body),
        reinterpret_cast<std::uintptr_t>(dll_fn),
        0,
    };
    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(&vtable_storage[2])};
    const std::uintptr_t original_vptr = object.vptr;

    s_vmt_header_fixture = &dll;
    s_vmt_header_protection_changed = false;
    DetourModKit::detail::g_vmt_before_capture_probe = &protect_vmt_race_header_before_capture;
    Result<DetourModKit::hook::VmtHook> cloned = DetourModKit::hook::vmt_for("VmtCaptureUnreadableHeader", &object);
    DetourModKit::detail::g_vmt_before_capture_probe = nullptr;
    s_vmt_header_fixture = nullptr;
    const bool header_restored = dll.restore_header();

    ASSERT_TRUE(s_vmt_header_protection_changed) << "the header-protection probe did not arm";
    ASSERT_TRUE(header_restored) << "the fixture DLL header protection did not restore";
    ASSERT_TRUE(cloned.has_value()) << cloned.error().message();
    {
        DetourModKit::hook::VmtHook vmt = std::move(*cloned);
        EXPECT_TRUE(vmt.hook_method(0, &vmt_race_detour).has_value());
        EXPECT_TRUE(vmt.hook_method(1, &vmt_race_detour).has_value());
        Result<void> past_count = vmt.hook_method(2, &vmt_race_detour);
        ASSERT_FALSE(past_count.has_value());
        EXPECT_EQ(past_count.error().code, ErrorCode::InvalidArg);
    }
    EXPECT_EQ(object.vptr, original_vptr) << "teardown must restore the seed object's vptr";
}

#endif // DMK_ENABLE_TEST_SEAMS

// Exhaustion and unsupported relocation require distinct first-cause diagnostics.
namespace
{
    /// The range the backend's near allocation can reach from a target, clamped to the user address space.
    struct AllocationWindow
    {
        std::uintptr_t low{0};
        std::uintptr_t high{0};
        std::uintptr_t maximum{0};
        std::uintptr_t granule{0};
    };

    AllocationWindow allocation_window(std::uintptr_t target) noexcept
    {
        constexpr std::uintptr_t MAX_DISTANCE = 0x7FFF'FFFF;
        SYSTEM_INFO system_info{};
        GetSystemInfo(&system_info);
        const auto minimum = reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress);
        AllocationWindow window{};
        window.maximum = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);
        window.granule = system_info.dwAllocationGranularity;
        window.low = target - minimum > MAX_DISTANCE ? target - MAX_DISTANCE : minimum;
        window.high = window.maximum - target > MAX_DISTANCE ? target + MAX_DISTANCE : window.maximum;
        return window;
    }

    /**
     * @brief Counts the granule-aligned free starts in the window, which the backend's placement walk tests.
     * @details A final partial granule counts as one candidate.
     */
    std::size_t free_granules_in_window(const AllocationWindow &window) noexcept
    {
        std::size_t granules = 0;
        std::uintptr_t cursor = window.low;
        while (cursor < window.high)
        {
            MEMORY_BASIC_INFORMATION info{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info)) == 0)
            {
                break;
            }
            const std::uintptr_t region_end = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
            if (info.State == MEM_FREE)
            {
                const std::uintptr_t start = (cursor + window.granule - 1) & ~(window.granule - 1);
                const std::uintptr_t stop = region_end < window.high ? region_end : window.high;
                if (start < stop)
                {
                    granules += (stop - start + window.granule - 1) / window.granule;
                }
            }
            if (region_end <= cursor)
            {
                break;
            }
            cursor = region_end;
        }
        return granules;
    }

    /**
     * @brief Reserves every free granule the backend can place near a target, and releases them on scope exit.
     * @details One MEM_RESERVE per free range keeps the reservation count small. A range the OS refuses as one
     *          reservation is taken granule by granule so no usable sliver survives. The window is padded by two
     *          granules above, because the allocator tests only the aligned start of a candidate.
     */
    class WindowExhaustion
    {
    public:
        explicit WindowExhaustion(std::uintptr_t target)
        {
            AllocationWindow window = allocation_window(target);
            window.high =
                window.maximum - window.high > 2 * window.granule ? window.high + 2 * window.granule : window.maximum;
            std::uintptr_t cursor = window.low;
            while (cursor < window.high)
            {
                MEMORY_BASIC_INFORMATION info{};
                if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info)) == 0)
                {
                    break;
                }
                const std::uintptr_t region_end = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
                if (info.State == MEM_FREE)
                {
                    const std::uintptr_t start = (cursor + window.granule - 1) & ~(window.granule - 1);
                    const std::uintptr_t stop = region_end < window.high ? region_end : window.high;
                    if (start < stop)
                    {
                        reserve(start, stop, window.granule);
                    }
                }
                if (region_end <= cursor)
                {
                    break;
                }
                cursor = region_end;
            }
        }

        ~WindowExhaustion() noexcept
        {
            for (void *base : m_reservations)
            {
                VirtualFree(base, 0, MEM_RELEASE);
            }
        }

        WindowExhaustion(const WindowExhaustion &) = delete;
        WindowExhaustion &operator=(const WindowExhaustion &) = delete;
        WindowExhaustion(WindowExhaustion &&) = delete;
        WindowExhaustion &operator=(WindowExhaustion &&) = delete;

        [[nodiscard]] std::size_t count() const noexcept { return m_reservations.size(); }

    private:
        void reserve(std::uintptr_t start, std::uintptr_t stop, std::uintptr_t granule)
        {
            void *whole = VirtualAlloc(reinterpret_cast<void *>(start), stop - start, MEM_RESERVE, PAGE_NOACCESS);
            if (whole != nullptr)
            {
                m_reservations.push_back(whole);
                return;
            }
            for (std::uintptr_t candidate = start; candidate < stop; candidate += granule)
            {
                const std::uintptr_t size = stop - candidate < granule ? stop - candidate : granule;
                void *one = VirtualAlloc(reinterpret_cast<void *>(candidate), size, MEM_RESERVE, PAGE_NOACCESS);
                if (one != nullptr)
                {
                    m_reservations.push_back(one);
                }
            }
        }

        std::vector<void *> m_reservations;
    };

    /// Counts the committed private regions with an execute protection over the whole user address space.
    std::size_t private_executable_regions() noexcept
    {
        constexpr DWORD EXECUTE_MASK =
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        SYSTEM_INFO system_info{};
        GetSystemInfo(&system_info);
        const auto maximum = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);
        std::size_t regions = 0;
        std::uintptr_t cursor = 0;
        while (cursor < maximum)
        {
            MEMORY_BASIC_INFORMATION info{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info)) == 0)
            {
                break;
            }
            if (info.State == MEM_COMMIT && info.Type == MEM_PRIVATE && (info.Protect & EXECUTE_MASK) != 0)
            {
                ++regions;
            }
            const std::uintptr_t next = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
            if (next <= cursor)
            {
                break;
            }
            cursor = next;
        }
        return regions;
    }

    /// Plants `jmp short +3; mov rax, 1; ret`: the short jump lands inside the mov, so no trampoline can relocate it.
    void plant_interior_jump(dmk_test::ScratchPage &page) noexcept
    {
        page.put(0, {0xEB, 0x03, 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3});
    }

    std::size_t hook_manager_leaks() noexcept
    {
        return DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    }

    /// The prefix every toggle warning shares: the hook name and its zero-padded target address.
    std::string toggle_warning_prefix(const char *name, const dmk_test::ScratchPage &page)
    {
        return std::format("hook: '{}' at 0x{:016X} ", name, page.addr(0));
    }
} // namespace

TEST(HookBackendCreate, ExhaustedWindowNamesTheAllocatorRefusal)
{
    for (const bool interior_jump : {false, true})
    {
        SCOPED_TRACE(interior_jump);
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);
        if (interior_jump)
        {
            plant_interior_jump(page);
        }
        const std::size_t leaks_before = hook_manager_leaks();
        const std::size_t regions_before = private_executable_regions();

        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};
        std::optional<Result<Hook>> installed;
        {
            const WindowExhaustion exhausted{page.addr(0)};
            ASSERT_EQ(free_granules_in_window(allocation_window(page.addr(0))), 0u)
                << exhausted.count() << " reservations left a free granule in the window";
            installed.emplace(install_mid_leaf(page, "ExhaustedWindow"));
        }
        ASSERT_FALSE(installed->has_value()) << "the mid create found room in an exhausted window";
        EXPECT_EQ(installed->error().code, ErrorCode::BackendFailed);
        EXPECT_EQ(installed->error().detail, page.addr(0));

        const std::string text = capture.read_all();
        EXPECT_NE(text.find("hook::mid_at: backend create failed for 'ExhaustedWindow'"), std::string::npos) << text;
        EXPECT_NE(text.find("bad allocation (no free region within +/-2 GB of the target)"), std::string::npos) << text;
        EXPECT_EQ(text.find("allocator error"), std::string::npos) << text;

        // The failed create leaves nothing behind: no ledger record, no leak, and no committed arena.
        EXPECT_FALSE(is_target_hooked(Address{page.addr(0)}));
        EXPECT_EQ(hook_manager_leaks(), leaks_before);
        EXPECT_EQ(private_executable_regions(), regions_before);
    }
}

TEST(HookBackendCreate, InteriorShortJumpReportsTheFirstContentCheck)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_interior_jump(page);
    ASSERT_GT(free_granules_in_window(allocation_window(page.addr(0))), 0u) << "the window must not be exhausted";

    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};
    const Result<Hook> installed = install_mid_leaf(page, "InteriorShortJump");
    ASSERT_FALSE(installed.has_value()) << "the backend relocated a jump into an instruction interior";
    EXPECT_EQ(installed.error().code, ErrorCode::BackendFailed);

    const std::string text = capture.read_all();
    EXPECT_NE(text.find("hook::mid_at: backend create failed for 'InteriorShortJump'"), std::string::npos) << text;
    EXPECT_NE(text.find("unsupported instruction in trampoline"), std::string::npos) << text;
    EXPECT_EQ(text.find("no free region"), std::string::npos) << text;
    EXPECT_FALSE(is_target_hooked(Address{page.addr(0)}));
}

// The deferred toggle lines are the operator's only signal for a refused, reconciled, or bypassed toggle. These cases
// pin their text after the hook name and address.
TEST(HookToggleWarning, RefusedEnableNamesTheWitness)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    Result<Hook> installed = install_leaf(page, "WarnRefusedEnable");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    plant_foreign_patch(page);

    std::string text;
    {
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};
        const Result<void> enabled = hook.enable();
        ASSERT_FALSE(enabled.has_value());
        EXPECT_EQ(enabled.error().code, ErrorCode::EnableFailed);
        text = capture.read_all();
    }
    const std::string expected =
        toggle_warning_prefix("WarnRefusedEnable", page) + "refused enable: another writer owns the prologue.";
    EXPECT_NE(text.find(expected), std::string::npos) << text;

    // A hand restore of the prologue lets the disabled hook tear down without a pin.
    plant_leaf(page);
}

TEST(HookToggleWarning, ReconciledEnableNamesTheRetry)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    Result<Hook> installed = install_leaf(page, "WarnReconciledEnable");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    const PrologueSpan pristine = read_prologue_span(page);
    ASSERT_TRUE(hook.enable().has_value());
    write_prologue_span(page, pristine);

    std::string text;
    {
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};
        const Result<void> again = hook.enable();
        ASSERT_TRUE(again.has_value()) << again.error().message();
        text = capture.read_all();
    }
    const std::string expected = toggle_warning_prefix("WarnReconciledEnable", page) +
                                 "has original bytes under an active state. This enable retries the arm.";
    EXPECT_NE(text.find(expected), std::string::npos) << text;
    EXPECT_EQ(call_target(page), DETOUR_RESULT);
}

TEST(HookToggleWarning, BypassedDisableNamesTheWitness)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);
    const std::size_t pins_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    const std::size_t residue_before =
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookResidue);
    Result<Hook> installed = install_leaf(page, "WarnRefusedDisable");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    std::optional<Hook> hook{std::move(*installed)};
    ASSERT_TRUE(hook->enable().has_value());
    const PrologueSpan armed = read_prologue_span(page);
    plant_foreign_patch(page);

    // An Active hook over foreign bytes bypasses in place of the refusal. Its Info line names the witness.
    std::string text;
    {
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Info};
        const Result<void> disabled = hook->disable();
        ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
        text = capture.read_all();
    }
    const std::string expected = toggle_warning_prefix("WarnRefusedDisable", page) +
                                 "bypassed under a newer layer: another writer owns the prologue.";
    EXPECT_NE(text.find(expected), std::string::npos) << text;

    // A hand restore of this hook's exact patch makes the bypassed hook the owner again, so its disable restores the
    // target and teardown frees it.
    write_prologue_span(page, armed);
    EXPECT_TRUE(hook->disable().has_value());
    EXPECT_EQ(read_prologue_span(page), pristine) << "the second disable did not restore the target";
    EXPECT_FALSE(hook->is_enabled());
    hook.reset();
    EXPECT_EQ(
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager),
        pins_before
    );
    EXPECT_EQ(
        DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookResidue),
        residue_before
    );
    EXPECT_EQ(call_target(page), LEAF_RESULT);
}

TEST(HookToggleWarning, ReconciledDisableNamesTheRetry)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    Result<Hook> installed = install_leaf(page, "WarnReconciledDisable");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_TRUE(hook.enable().has_value());
    const PrologueSpan armed = read_prologue_span(page);
    ASSERT_TRUE(hook.disable().has_value());
    write_prologue_span(page, armed);

    std::string text;
    {
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};
        const Result<void> again = hook.disable();
        ASSERT_TRUE(again.has_value()) << again.error().message();
        text = capture.read_all();
    }
    const std::string expected = toggle_warning_prefix("WarnReconciledDisable", page) +
                                 "has owned bytes under a disabled state. This disable retries the restore.";
    EXPECT_NE(text.find(expected), std::string::npos) << text;
    EXPECT_EQ(call_target(page), LEAF_RESULT);
}

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace
{
    using VmtWindowFn = int (*)(void *, int, int);

    int vmt_window_detour(void *, int, int)
    {
        return 0;
    }
} // namespace

// A backend trap window holds a method page at PAGE_READWRITE under the process coordinator. The vmt_for slot walk
// classifies each slot's page through VirtualQuery, so a walk inside that window ends early and publishes a truncated
// clone. vmt_for holds the coordinator across the walk and the clone, so it cannot return before the window closes,
// and the clone then carries every slot.
TEST(HookBackendTrapWindow, VmtForWaitsForTheBackendTrapWindow)
{
    using namespace std::chrono_literals;
    dmk_test::ScratchPage method_page;
    ASSERT_TRUE(method_page.ok());
    plant_leaf(method_page);
    method_page.put(0x100, {0xC3, 0x90, 0x90, 0x90});
    method_page.put(0x140, {0xC3, 0x90, 0x90, 0x90});
    dmk_test::ScratchPage trampoline;
    ASSERT_TRUE(trampoline.ok());

    struct WindowVTable
    {
        void *rtti[2];
        void *methods[3];
    };
    WindowVTable table{};
    table.methods[0] = reinterpret_cast<void *>(method_page.addr(0x100));
    table.methods[1] = reinterpret_cast<void *>(method_page.addr(0x140));
    table.methods[2] = nullptr;
    void *vptr = &table.methods[0];

    std::atomic<bool> window_open{false};
    std::atomic<bool> create_attempted{false};
    std::atomic<bool> create_returned{false};
    std::atomic<bool> returned_inside_window{false};
    std::thread transaction(
        [&]
        {
            const DetourModKit::detail::TrapTransactionOutcome outcome =
                DetourModKit::detail::drive_backend_trap_transaction_for_test(
                    method_page.base(),
                    trampoline.base(),
                    6,
                    [&]
                    {
                        window_open.store(true, std::memory_order_release);
                        for (int i = 0; i < 2000 && !create_attempted.load(std::memory_order_acquire); ++i)
                        {
                            std::this_thread::sleep_for(1ms);
                        }
                        // The creating thread is inside vmt_for. A serialized walk cannot return before this window
                        // closes.
                        std::this_thread::sleep_for(100ms);
                        returned_inside_window.store(
                            create_returned.load(std::memory_order_acquire),
                            std::memory_order_release
                        );
                    }
                );
            EXPECT_EQ(outcome, DetourModKit::detail::TrapTransactionOutcome::Restored);
        }
    );
    while (!window_open.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }
    create_attempted.store(true, std::memory_order_release);
    Result<DetourModKit::hook::VmtHook> created = DetourModKit::hook::vmt_for("TrapWindowVmt", &vptr);
    create_returned.store(true, std::memory_order_release);
    transaction.join();

    EXPECT_FALSE(returned_inside_window.load(std::memory_order_acquire));
    ASSERT_TRUE(created.has_value()) << created.error().message();
    DetourModKit::hook::VmtHook hook = std::move(*created);
    ASSERT_TRUE(hook.hook_method(1, &vmt_window_detour).has_value());
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(hook.original<VmtWindowFn>(1)), method_page.addr(0x140));
}
#endif

namespace
{
    std::atomic<bool> s_parked_callee_reached{false};
    std::atomic<bool> s_parked_callee_release{false};
    std::atomic<int> s_parked_result{0};
    std::atomic<LeafFn> s_parked_original{nullptr};

    /// Parks its caller until the test releases it. The relocated call in the trampoline reaches it.
    DMK_TEST_NOINLINE int parked_callee() noexcept
    {
        s_parked_callee_reached.store(true, std::memory_order_release);
        while (!s_parked_callee_release.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        return LEAF_RESULT;
    }

    /// Chains into the trampoline, so the parked frame returns through the relocated call.
    DMK_TEST_NOINLINE int parked_detour() noexcept
    {
        return s_parked_original.load(std::memory_order_acquire)();
    }

    /// Plants `sub rsp, 0x28; call [rip+0xF6]; add rsp, 0x28; ret`. The call reads the callee address at offset 0x100.
    void plant_relocated_call(dmk_test::ScratchPage &page) noexcept
    {
        page.put(0, {0x48, 0x83, 0xEC, 0x28, 0xFF, 0x15, 0xF6, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3});
        const auto callee = reinterpret_cast<std::uintptr_t>(&parked_callee);
        std::memcpy(reinterpret_cast<void *>(page.addr(0x100)), &callee, sizeof(callee));
    }

    /**
     * @brief Calls a scratch target on its own thread. The callee parks until release_and_join().
     * @details The destructor releases and joins. abandon() leaves the thread parked for the process lifetime, so it
     *          never returns into a trampoline that a regressed teardown freed. The thread writes only globals.
     */
    class ParkedCaller
    {
    public:
        explicit ParkedCaller(std::uintptr_t target)
            : m_thread(
                  [target]
                  {
                      s_parked_result.store(
                          dmk_test::call_unfolded(reinterpret_cast<LeafFn>(target)),
                          std::memory_order_release
                      );
                  }
              )
        {
        }

        ~ParkedCaller() noexcept
        {
            if (m_thread.joinable())
            {
                (void)release_and_join();
            }
        }

        ParkedCaller(const ParkedCaller &) = delete;
        ParkedCaller &operator=(const ParkedCaller &) = delete;
        ParkedCaller(ParkedCaller &&) = delete;
        ParkedCaller &operator=(ParkedCaller &&) = delete;

        /// Releases the callee, joins, and returns the call result.
        [[nodiscard]] int release_and_join()
        {
            s_parked_callee_release.store(true, std::memory_order_release);
            m_thread.join();
            return s_parked_result.load(std::memory_order_acquire);
        }

        void abandon() noexcept { m_thread.detach(); }

    private:
        std::thread m_thread;
    };
} // namespace

// A top restore frees the trampoline only after an idle proof. A thread parked inside the callee of a relocated call
// returns into the trampoline, so teardown keeps the trampoline as HookResidue. It still releases the module
// reference, because the restored target reaches no image code.
TEST(HookBackendRelay, TrampolineFreeWaitsForAParkedThread)
{
    using namespace std::chrono_literals;
    using DetourModKit::diagnostics::intentional_leak_count;
    using DetourModKit::diagnostics::LeakSubsystem;
    using DetourModKit::diagnostics::module_pin_count;
    using DetourModKit::diagnostics::ModulePinReason;

    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_relocated_call(page);
    const PrologueSpan pristine = read_prologue_span(page);
    s_parked_callee_reached.store(false, std::memory_order_release);
    s_parked_callee_release.store(false, std::memory_order_release);
    s_parked_result.store(0, std::memory_order_release);

    const std::size_t pins_before = module_pin_count(ModulePinReason::Hook);
    const std::size_t leaks_before = intentional_leak_count(LeakSubsystem::HookManager);
    const std::size_t residue_before = intentional_leak_count(LeakSubsystem::HookResidue);
    std::optional<Hook> hook;
    {
        Result<Hook> installed = inline_at(
            InlineRequest{
                .name = "ParkedTrampoline",
                .target = Address{page.addr(0)},
            },
            reinterpret_cast<void (*)()>(&parked_detour)
        );
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        hook.emplace(std::move(*installed));
    }
    s_parked_original.store(hook->original<LeafFn>(), std::memory_order_release);
    ASSERT_TRUE(hook->enable().has_value());
    ASSERT_EQ(module_pin_count(ModulePinReason::Hook), pins_before + 1);

    ParkedCaller caller{page.addr(0)};
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (!s_parked_callee_reached.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_TRUE(s_parked_callee_reached.load(std::memory_order_acquire)) << "the caller never reached the callee";

    std::string text;
    {
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Info};
        hook.reset();
        text = capture.read_all();
    }
    const bool trampoline_kept = intentional_leak_count(LeakSubsystem::HookResidue) == residue_before + 1;
    if (!trampoline_kept)
    {
        // A freed trampoline must never run, so a regressed teardown leaves the caller parked.
        caller.abandon();
    }
    EXPECT_TRUE(trampoline_kept) << "the restore freed a trampoline that a parked thread returns into";
    EXPECT_EQ(intentional_leak_count(LeakSubsystem::HookManager), leaks_before);
    EXPECT_EQ(module_pin_count(ModulePinReason::Hook), pins_before);
    EXPECT_FALSE(is_target_hooked(Address{page.addr(0)}));
    EXPECT_EQ(read_prologue_span(page), pristine);
    const std::string expected = toggle_warning_prefix("ParkedTrampoline", page) +
                                 "restored its target and kept its trampoline: route idle proof refused.";
    EXPECT_NE(text.find(expected), std::string::npos) << text;

    if (trampoline_kept)
    {
        // The parked thread returns through the kept trampoline into the restored target.
        EXPECT_EQ(caller.release_and_join(), LEAF_RESULT);
        EXPECT_EQ(call_target(page), LEAF_RESULT);
    }
    s_parked_original.store(nullptr, std::memory_order_release);
    // The retained record names this target for process life, so the fixture must not hand the page back.
    page.abandon();
}

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace
{
    using DetourModKit::detail::BackendCoordinatorCounts;
    using DetourModKit::detail::BackendProbe;
    using DetourModKit::detail::BackendProbeKind;
    using DetourModKit::detail::BackendProbeOperation;
    using DetourModKit::detail::BackendProbeState;

    constexpr int SUCCESSOR_RESULT = 0x5EEE;
    constexpr int UPPER_BONUS = 0x100;
    constexpr std::uint64_t RELAY_CELL_OWNED = 1;
    constexpr std::uint64_t RELAY_CELL_VACANT = 2;
    constexpr std::uint16_t RELAY_CELL_LAYOUT = 1;
    constexpr std::uint64_t RELAY_CELL_SEAL = 0x59414C45524B4D44ULL;
    constexpr std::uint32_t ROUTE_LIVE = 0;
    constexpr std::uint32_t ROUTE_CLOSED = 2;
    constexpr unsigned COORDINATOR_UNAVAILABLE = 1;
    /// The near patch of the planted leaf covers `mov eax, 1`.
    constexpr std::size_t NEAR_PATCH_SIZE = 5;
    /// The far patch covers `FF 25 00000000` and the 8-byte relay address.
    constexpr std::size_t FAR_PATCH_SIZE = 14;
    constexpr std::array<std::uint8_t, 6> FAR_JUMP{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};

    /// The footer kinds of relay cell layout 1.
    enum class RelayCellKind : std::uint16_t
    {
        E9 = 1,
        FF = 2,
        Mid = 3,
        Routed = 4,
    };

    /// The relay cell body of layout 1. Other backend copies read this frozen format.
    struct RelayCellBody
    {
        std::uint64_t state;
        std::uint64_t identity;
        std::uint64_t target;
        std::uint64_t switch_word;
        std::uint64_t route_word;
        std::uint32_t original_size;
        std::uint32_t reserved;
        std::uint8_t original[32];
    };
    static_assert(sizeof(RelayCellBody) == 80);

    /// The 16-byte footer that ends every trampoline with a relay cell.
    struct RelayCellFooter
    {
        std::uint32_t body_offset;
        std::uint16_t layout;
        std::uint16_t kind;
        std::uint64_t seal;
    };
    static_assert(sizeof(RelayCellFooter) == 16);

    std::atomic<std::size_t> s_first_mid_calls{0};
    std::atomic<std::size_t> s_second_mid_calls{0};
    std::atomic<LeafFn> s_upper_original{nullptr};

    DMK_TEST_NOINLINE int successor_detour() noexcept
    {
        return SUCCESSOR_RESULT;
    }

    /// Chains into the newer trampoline, whose relocated jump reaches the lower relay.
    DMK_TEST_NOINLINE int upper_chaining_detour() noexcept
    {
        return s_upper_original.load(std::memory_order_acquire)() + UPPER_BONUS;
    }

    // The mid stub passes its context in the first argument register, so a pointer parameter matches its call.
    DMK_TEST_NOINLINE void first_mid_callback(void *) noexcept
    {
        s_first_mid_calls.fetch_add(1, std::memory_order_relaxed);
    }

    DMK_TEST_NOINLINE void second_mid_callback(void *) noexcept
    {
        s_second_mid_calls.fetch_add(1, std::memory_order_relaxed);
    }

    template <class Function> [[nodiscard]] void *code_address(Function *function) noexcept
    {
        return reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(function));
    }

    [[nodiscard]] std::uintptr_t address_of(const void *pointer) noexcept
    {
        return reinterpret_cast<std::uintptr_t>(pointer);
    }

    [[nodiscard]] std::uint64_t read_word(std::uintptr_t address) noexcept
    {
        std::uint64_t value = 0;
        std::memcpy(&value, reinterpret_cast<const void *>(address), sizeof(value));
        return value;
    }

    void write_word(std::uintptr_t address, std::uint64_t value) noexcept
    {
        std::memcpy(reinterpret_cast<void *>(address), &value, sizeof(value));
    }

    [[nodiscard]] std::uint32_t read_route_state(std::uintptr_t address) noexcept
    {
        std::uint32_t value = 0;
        std::memcpy(&value, reinterpret_cast<const void *>(address), sizeof(value));
        return value;
    }

    void write_route_state(std::uintptr_t address, std::uint32_t value) noexcept
    {
        std::memcpy(reinterpret_cast<void *>(address), &value, sizeof(value));
    }

    [[nodiscard]] RelayCellBody read_relay_cell(const void *cell) noexcept
    {
        RelayCellBody body{};
        std::memcpy(&body, cell, sizeof(body));
        return body;
    }

    void write_relay_cell(void *cell, const RelayCellBody &body) noexcept
    {
        std::memcpy(cell, &body, sizeof(body));
    }

    [[nodiscard]] RelayCellFooter read_footer(const std::uint8_t *footer_address) noexcept
    {
        RelayCellFooter footer{};
        std::memcpy(&footer, footer_address, sizeof(footer));
        return footer;
    }

    void write_footer(std::uint8_t *footer_address, const RelayCellFooter &footer) noexcept
    {
        std::memcpy(footer_address, &footer, sizeof(footer));
    }

    /**
     * @brief Returns the sealed footer after the cell body at @p cell, or nullptr when no candidate carries the seal.
     * @details Up to seven spare bytes separate the body from the footer that ends the allocation. The scan stops at
     *          the first sealed candidate, so it never reads past the allocation.
     */
    [[nodiscard]] std::uint8_t *find_relay_cell_footer(void *cell) noexcept
    {
        std::uint8_t *const body_end = static_cast<std::uint8_t *>(cell) + sizeof(RelayCellBody);
        for (std::size_t spare = 0; spare < alignof(std::uint64_t); ++spare)
        {
            std::uint8_t *const candidate = body_end + spare;
            const std::uintptr_t seal_address = address_of(candidate + offsetof(RelayCellFooter, seal));
            if (read_footer(candidate).seal == (RELAY_CELL_SEAL ^ seal_address))
            {
                return candidate;
            }
        }
        return nullptr;
    }

    /// The identity that a position claim derives from @p name: 64-bit FNV-1a, with 1 in place of 0.
    [[nodiscard]] constexpr std::uint64_t position_identity(std::string_view name) noexcept
    {
        std::uint64_t hash = 0xCBF29CE484222325ULL;
        for (const char character : name)
        {
            hash ^= static_cast<std::uint8_t>(character);
            hash *= 0x100000001B3ULL;
        }
        return hash != 0 ? hash : 1;
    }

    /// Returns the slot that the relay behind a near or far target patch reads, or 0 for any other shape.
    [[nodiscard]] std::uintptr_t relay_slot_from_target(std::uintptr_t target) noexcept
    {
        const auto *const bytes = reinterpret_cast<const std::uint8_t *>(target);
        std::uintptr_t relay = 0;
        if (bytes[0] == 0xE9)
        {
            std::int32_t displacement = 0;
            std::memcpy(&displacement, bytes + 1, sizeof(displacement));
            relay = target + 5 + static_cast<std::uintptr_t>(static_cast<std::intptr_t>(displacement));
        }
        else if (std::equal(FAR_JUMP.begin(), FAR_JUMP.end(), bytes, bytes + FAR_JUMP.size()))
        {
            relay = read_word(target + FAR_JUMP.size());
        }
        if (relay == 0)
        {
            return 0;
        }
        const auto *const relay_bytes = reinterpret_cast<const std::uint8_t *>(relay);
        if (relay_bytes[0] != 0xFF || relay_bytes[1] != 0x25)
        {
            return 0;
        }
        std::int32_t displacement = 0;
        std::memcpy(&displacement, relay_bytes + 2, sizeof(displacement));
        return relay + 6 + static_cast<std::uintptr_t>(static_cast<std::intptr_t>(displacement));
    }

    [[nodiscard]] std::vector<std::uint8_t> page_bytes(const dmk_test::ScratchPage &page)
    {
        const auto *const begin = static_cast<const std::uint8_t *>(page.base());
        return std::vector<std::uint8_t>(begin, begin + dmk_test::ScratchPage::PAGE_SIZE);
    }

    [[nodiscard]] const char *probe_kind_label(BackendProbeKind kind) noexcept
    {
        switch (kind)
        {
        case BackendProbeKind::Inline:
            return "inline";
        case BackendProbeKind::Mid:
            return "mid";
        case BackendProbeKind::Routed:
            return "routed";
        }
        return "unknown";
    }

    /// The destination of the first generation on a position: DETOUR_RESULT, or the first mid callback.
    [[nodiscard]] void *first_destination(BackendProbeKind kind) noexcept
    {
        return kind == BackendProbeKind::Mid ? code_address(&first_mid_callback) : code_address(&detour_leaf);
    }

    /// The destination of a successor generation: SUCCESSOR_RESULT, or the second mid callback.
    [[nodiscard]] void *second_destination(BackendProbeKind kind) noexcept
    {
        return kind == BackendProbeKind::Mid ? code_address(&second_mid_callback) : code_address(&successor_detour);
    }

    [[nodiscard]] BackendCoordinatorCounts coordinator_counts() noexcept
    {
        return DetourModKit::detail::backend_coordinator_counts_for_test();
    }

    [[nodiscard]] ::testing::AssertionResult
    counts_equal(const BackendCoordinatorCounts &actual, const BackendCoordinatorCounts &expected)
    {
        if (actual.live == expected.live && actual.retained == expected.retained && actual.vacant == expected.vacant &&
            actual.free == expected.free)
        {
            return ::testing::AssertionSuccess();
        }
        return ::testing::AssertionFailure()
               << "records (live, retained, vacant, free) are (" << actual.live << ", " << actual.retained << ", "
               << actual.vacant << ", " << actual.free << "), expected (" << expected.live << ", " << expected.retained
               << ", " << expected.vacant << ", " << expected.free << ")";
    }

    /// Owns one raw backend probe and destroys it through the backend destructor.
    class ProbeHandle
    {
    public:
        ProbeHandle() = default;
        explicit ProbeHandle(BackendProbe *probe) noexcept : m_probe(probe) {}
        ~ProbeHandle() noexcept { reset(); }

        ProbeHandle(ProbeHandle &&other) noexcept : m_probe(std::exchange(other.m_probe, nullptr)) {}
        ProbeHandle &operator=(ProbeHandle &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                m_probe = std::exchange(other.m_probe, nullptr);
            }
            return *this;
        }
        ProbeHandle(const ProbeHandle &) = delete;
        ProbeHandle &operator=(const ProbeHandle &) = delete;

        [[nodiscard]] explicit operator bool() const noexcept { return m_probe != nullptr; }

        [[nodiscard]] bool drive(BackendProbeOperation operation) const noexcept
        {
            return m_probe != nullptr && DetourModKit::detail::drive_backend_probe_for_test(m_probe, operation);
        }

        [[nodiscard]] BackendProbeState state() const noexcept
        {
            return m_probe != nullptr ? DetourModKit::detail::backend_probe_state_for_test(m_probe)
                                      : BackendProbeState{};
        }

        void reset() noexcept
        {
            if (m_probe != nullptr)
            {
                DetourModKit::detail::destroy_backend_probe_for_test(std::exchange(m_probe, nullptr));
            }
        }

    private:
        BackendProbe *m_probe{nullptr};
    };

    [[nodiscard]] ProbeHandle
    create_probe(BackendProbeKind kind, std::uintptr_t target, void *destination, std::string_view name) noexcept
    {
        return ProbeHandle{DetourModKit::detail::create_backend_probe_for_test(
            kind,
            reinterpret_cast<void *>(target),
            destination,
            name
        )};
    }

    /// Makes the next inline setup take its far path, and clears an unconsumed request at scope exit.
    class FarHookScope
    {
    public:
        explicit FarHookScope(bool use_far_path = true) noexcept
        {
            DetourModKit::detail::force_backend_ff_hook_for_test(use_far_path);
        }
        ~FarHookScope() noexcept { DetourModKit::detail::force_backend_ff_hook_for_test(false); }
        FarHookScope(const FarHookScope &) = delete;
        FarHookScope &operator=(const FarHookScope &) = delete;
        FarHookScope(FarHookScope &&) = delete;
        FarHookScope &operator=(FarHookScope &&) = delete;
    };

    /// Makes every setup in scope emit the earlier trampoline shape, which has no relay cell.
    class RelayCellOmissionScope
    {
    public:
        RelayCellOmissionScope() noexcept { DetourModKit::detail::omit_backend_relay_cell_for_test(true); }
        ~RelayCellOmissionScope() noexcept { DetourModKit::detail::omit_backend_relay_cell_for_test(false); }
        RelayCellOmissionScope(const RelayCellOmissionScope &) = delete;
        RelayCellOmissionScope &operator=(const RelayCellOmissionScope &) = delete;
        RelayCellOmissionScope(RelayCellOmissionScope &&) = delete;
        RelayCellOmissionScope &operator=(RelayCellOmissionScope &&) = delete;
    };

    /// Refuses the process coordinator for the scope.
    class CoordinatorRefusalScope
    {
    public:
        explicit CoordinatorRefusalScope(unsigned refusal) noexcept
        {
            DetourModKit::detail::set_backend_coordinator_refusal_for_test(refusal);
        }
        ~CoordinatorRefusalScope() noexcept { DetourModKit::detail::set_backend_coordinator_refusal_for_test(0); }
        CoordinatorRefusalScope(const CoordinatorRefusalScope &) = delete;
        CoordinatorRefusalScope &operator=(const CoordinatorRefusalScope &) = delete;
        CoordinatorRefusalScope(CoordinatorRefusalScope &&) = delete;
        CoordinatorRefusalScope &operator=(CoordinatorRefusalScope &&) = delete;
    };

    /**
     * @brief Commits one read-write page above @p floor and within 2 GB of it, and frees it at scope exit.
     * @details A 32-bit offset from any address at or below @p floor then reaches the page exactly.
     */
    class ReadWritePageAbove
    {
    public:
        explicit ReadWritePageAbove(std::uintptr_t floor) noexcept
        {
            constexpr std::uintptr_t MAX_DISTANCE = 0x7FFF'0000;
            SYSTEM_INFO system_info{};
            GetSystemInfo(&system_info);
            const std::uintptr_t granule = system_info.dwAllocationGranularity;
            for (std::uintptr_t candidate = (floor + granule) & ~(granule - 1);
                 m_base == nullptr && candidate - floor < MAX_DISTANCE;
                 candidate += granule)
            {
                m_base = VirtualAlloc(
                    reinterpret_cast<void *>(candidate),
                    dmk_test::ScratchPage::PAGE_SIZE,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE
                );
            }
        }
        ~ReadWritePageAbove() noexcept
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }
        ReadWritePageAbove(const ReadWritePageAbove &) = delete;
        ReadWritePageAbove &operator=(const ReadWritePageAbove &) = delete;
        ReadWritePageAbove(ReadWritePageAbove &&) = delete;
        ReadWritePageAbove &operator=(ReadWritePageAbove &&) = delete;

        /// The page start, or 0 when no granule above the floor was free.
        [[nodiscard]] std::uintptr_t address() const noexcept { return address_of(m_base); }

    private:
        void *m_base{nullptr};
    };

    /// Publishes the newer trampoline that upper_chaining_detour calls, and clears it at scope exit.
    class UpperOriginalScope
    {
    public:
        explicit UpperOriginalScope(void *trampoline) noexcept
        {
            s_upper_original.store(reinterpret_cast<LeafFn>(address_of(trampoline)), std::memory_order_release);
        }
        ~UpperOriginalScope() noexcept { s_upper_original.store(nullptr, std::memory_order_release); }
        UpperOriginalScope(const UpperOriginalScope &) = delete;
        UpperOriginalScope &operator=(const UpperOriginalScope &) = delete;
        UpperOriginalScope(UpperOriginalScope &&) = delete;
        UpperOriginalScope &operator=(UpperOriginalScope &&) = delete;
    };

    /// Calls one scratch target on several threads until stopped, and counts each result outside two allowed values.
    class TargetCallers
    {
    public:
        TargetCallers(std::uintptr_t target, int first, int second, std::size_t thread_count)
        {
            m_threads.reserve(thread_count);
            for (std::size_t index = 0; index < thread_count; ++index)
            {
                m_threads.emplace_back(
                    [this, target, first, second](std::stop_token stop_request) noexcept
                    {
                        const auto entry = reinterpret_cast<LeafFn>(target);
                        while (!stop_request.stop_requested())
                        {
                            const int result = dmk_test::call_unfolded(entry);
                            if (result != first && result != second)
                            {
                                m_unexpected.fetch_add(1, std::memory_order_relaxed);
                            }
                            m_calls.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                );
            }
        }

        TargetCallers(const TargetCallers &) = delete;
        TargetCallers &operator=(const TargetCallers &) = delete;
        TargetCallers(TargetCallers &&) = delete;
        TargetCallers &operator=(TargetCallers &&) = delete;

        /// Waits up to 10 seconds for @p minimum calls in total.
        [[nodiscard]] bool wait_for_calls(std::size_t minimum) const noexcept
        {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
            while (m_calls.load(std::memory_order_relaxed) < minimum)
            {
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    return false;
                }
                std::this_thread::yield();
            }
            return true;
        }

        void stop()
        {
            for (std::jthread &thread : m_threads)
            {
                thread.request_stop();
            }
            for (std::jthread &thread : m_threads)
            {
                if (thread.joinable())
                {
                    thread.join();
                }
            }
        }

        [[nodiscard]] std::size_t calls() const noexcept { return m_calls.load(std::memory_order_relaxed); }
        [[nodiscard]] std::size_t unexpected() const noexcept { return m_unexpected.load(std::memory_order_relaxed); }

    private:
        std::atomic<std::size_t> m_calls{0};
        std::atomic<std::size_t> m_unexpected{0};
        std::vector<std::jthread> m_threads;
    };

    /// One fresh position that its owner switched off and vacated for a same-name successor.
    struct VacantPosition
    {
        /// The owner state after the arm, before the vacate made the owner inert.
        BackendProbeState state;
        PrologueSpan armed;
    };

    /// Arms a fresh probe, switches it off, and vacates its position. The inert owner is destroyed on return.
    [[nodiscard]] std::optional<VacantPosition> vacate_fresh_position(
        BackendProbeKind kind,
        dmk_test::ScratchPage &page,
        void *destination,
        std::string_view name
    ) noexcept
    {
        ProbeHandle owner = create_probe(kind, page.addr(0), destination, name);
        if (!owner || !owner.drive(BackendProbeOperation::Enable))
        {
            return std::nullopt;
        }
        const VacantPosition position{owner.state(), read_prologue_span(page)};
        if (position.state.relay_cell == nullptr || !owner.drive(BackendProbeOperation::Bypass) ||
            !owner.drive(BackendProbeOperation::Vacate))
        {
            return std::nullopt;
        }
        return position;
    }

    enum class ClaimOutcome : std::uint8_t
    {
        CreateFailed,
        Fresh,
        Claimed,
    };

    /// Creates one successor probe, reports whether it claimed, and destroys it. A claim vacates the cell again.
    [[nodiscard]] ClaimOutcome
    claim_outcome(BackendProbeKind kind, std::uintptr_t target, std::string_view name) noexcept
    {
        const ProbeHandle successor = create_probe(kind, target, second_destination(kind), name);
        if (!successor)
        {
            return ClaimOutcome::CreateFailed;
        }
        return successor.state().claimed ? ClaimOutcome::Claimed : ClaimOutcome::Fresh;
    }

    /**
     * @brief Destroys fresh, never-armed probes on one target, newest first.
     * @details Only the newest record passes the arm check, so each pass arms, restores, and destroys the one probe
     *          whose Enable succeeds. An older probe destroyed first retains its record.
     */
    void destroy_newest_first(std::vector<ProbeHandle> &fresh_layers)
    {
        while (!fresh_layers.empty())
        {
            const auto newest = std::find_if(
                fresh_layers.begin(),
                fresh_layers.end(),
                [](const ProbeHandle &layer) { return layer.drive(BackendProbeOperation::Enable); }
            );
            ASSERT_NE(newest, fresh_layers.end()) << "no fresh layer passed the arm check";
            EXPECT_TRUE(newest->drive(BackendProbeOperation::Disable));
            fresh_layers.erase(newest);
        }
    }

    enum class RouteReached : std::uint8_t
    {
        None,
        First,
        Second,
        Unexpected,
    };

    /// Calls the target once and names the probe destination that ran.
    [[nodiscard]] RouteReached route_reached(BackendProbeKind kind, dmk_test::ScratchPage &page) noexcept
    {
        const std::size_t first_before = s_first_mid_calls.load(std::memory_order_relaxed);
        const std::size_t second_before = s_second_mid_calls.load(std::memory_order_relaxed);
        const int result = call_target(page);
        if (kind != BackendProbeKind::Mid)
        {
            return result == LEAF_RESULT        ? RouteReached::None
                   : result == DETOUR_RESULT    ? RouteReached::First
                   : result == SUCCESSOR_RESULT ? RouteReached::Second
                                                : RouteReached::Unexpected;
        }
        // A mid callback returns into the original code, so only the callback counters tell the paths apart.
        const bool first = s_first_mid_calls.load(std::memory_order_relaxed) != first_before;
        const bool second = s_second_mid_calls.load(std::memory_order_relaxed) != second_before;
        if (result != LEAF_RESULT || (first && second))
        {
            return RouteReached::Unexpected;
        }
        return first ? RouteReached::First : second ? RouteReached::Second : RouteReached::None;
    }
} // namespace

// An atomic retarget needs one aligned 8-byte word. Every path into the detour crosses that word, for the near and the
// far patch alike.
TEST(HookBackendRelay, SlotIsEightByteAligned)
{
    for (const bool use_far_path : {false, true})
    {
        SCOPED_TRACE(use_far_path ? "far" : "near");
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);

        std::optional<Result<Hook>> installed;
        {
            const FarHookScope far_hook{use_far_path};
            installed.emplace(install_leaf(page, use_far_path ? "RelaySlotFar" : "RelaySlotNear"));
        }
        ASSERT_TRUE(installed->has_value()) << installed->error().message();
        Hook hook = std::move(**installed);
        ASSERT_TRUE(hook.enable().has_value());

        const std::uintptr_t slot = relay_slot_from_target(page.addr(0));
        ASSERT_NE(slot, 0u) << "the target patch does not lead to an FF 25 relay";
        EXPECT_EQ(slot % alignof(std::uint64_t), 0u);
        EXPECT_EQ(read_word(slot), address_of(code_address(&detour_leaf)));
        EXPECT_EQ(call_target(page), DETOUR_RESULT);
        ASSERT_TRUE(hook.disable().has_value());
        EXPECT_EQ(call_target(page), LEAF_RESULT);
    }
}

// A lower layer switches its relay under a newer layer while callers run through both. A thread at the relay reads
// one aligned word, so every call reaches the old or the new destination, never a torn one.
TEST(HookBackendRelay, ConcurrentCallersSeeOnlyTheOldOrNewTarget)
{
    constexpr std::size_t CALLER_THREADS = 4;
    constexpr std::size_t SWITCH_ROUNDS = 50000;
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);
    {
        const ProbeHandle lower =
            create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&detour_leaf), "RelayStressLower");
        ASSERT_TRUE(lower);
        ASSERT_TRUE(lower.drive(BackendProbeOperation::Enable));
        const ProbeHandle upper = create_probe(
            BackendProbeKind::Inline,
            page.addr(0),
            code_address(&upper_chaining_detour),
            "RelayStressUpper"
        );
        ASSERT_TRUE(upper);
        const UpperOriginalScope chained{upper.state().trampoline};
        ASSERT_TRUE(upper.drive(BackendProbeOperation::Enable));
        ASSERT_EQ(call_target(page), DETOUR_RESULT + UPPER_BONUS);

        {
            TargetCallers callers{page.addr(0), LEAF_RESULT + UPPER_BONUS, DETOUR_RESULT + UPPER_BONUS, CALLER_THREADS};
            ASSERT_TRUE(callers.wait_for_calls(CALLER_THREADS * 16)) << "the callers never started";
            for (std::size_t round = 0; round < SWITCH_ROUNDS; ++round)
            {
                ASSERT_TRUE(lower.drive(BackendProbeOperation::Bypass));
                ASSERT_TRUE(lower.drive(BackendProbeOperation::Resume));
            }
            callers.stop();
            EXPECT_EQ(callers.unexpected(), 0u) << "of " << callers.calls() << " calls";
            EXPECT_GT(callers.calls(), CALLER_THREADS * 16);
        }

        ASSERT_TRUE(lower.drive(BackendProbeOperation::Bypass));
        EXPECT_EQ(call_target(page), LEAF_RESULT + UPPER_BONUS);
        ASSERT_TRUE(lower.drive(BackendProbeOperation::Resume));
        EXPECT_EQ(call_target(page), DETOUR_RESULT + UPPER_BONUS);
    }
    // The newer probe is destroyed first, so each restore runs as the top layer.
    EXPECT_EQ(read_prologue_span(page), pristine);
}

// The far patch jumps to a relay inside the trampoline. The target holds the relay address, never the detour, so its
// retarget point never lies in the target page.
TEST(HookBackendRelay, FarHookRoutesThroughItsRelay)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);

    ProbeHandle far_probe;
    {
        const FarHookScope far_hook;
        far_probe = create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&detour_leaf), "FarRelay");
    }
    ASSERT_TRUE(far_probe);
    ASSERT_TRUE(far_probe.drive(BackendProbeOperation::Enable));
    const BackendProbeState state = far_probe.state();
    ASSERT_NE(state.relay_slot, nullptr);

    const auto *const target = reinterpret_cast<const std::uint8_t *>(page.addr(0));
    EXPECT_TRUE(std::equal(FAR_JUMP.begin(), FAR_JUMP.end(), target, target + FAR_JUMP.size()));
    const std::uintptr_t relay = read_word(page.addr(FAR_JUMP.size()));
    EXPECT_NE(relay, address_of(code_address(&detour_leaf)));
    EXPECT_GE(relay, address_of(state.trampoline));
    EXPECT_LT(relay, address_of(state.relay_slot));
    EXPECT_EQ(relay_slot_from_target(page.addr(0)), address_of(state.relay_slot));
    EXPECT_EQ(read_word(address_of(state.relay_slot)), address_of(code_address(&detour_leaf)));
    EXPECT_EQ(call_target(page), DETOUR_RESULT);

    const PrologueSpan armed = read_prologue_span(page);
    ASSERT_TRUE(far_probe.drive(BackendProbeOperation::Bypass));
    EXPECT_EQ(call_target(page), LEAF_RESULT);
    EXPECT_EQ(read_prologue_span(page), armed);
    ASSERT_TRUE(far_probe.drive(BackendProbeOperation::Resume));
    EXPECT_EQ(call_target(page), DETOUR_RESULT);

    ASSERT_TRUE(far_probe.drive(BackendProbeOperation::Disable));
    EXPECT_EQ(read_prologue_span(page), pristine);
}

// A switch is one store into the relay slot. It writes no target byte, changes no page protection, and flushes no
// instruction cache.
TEST(HookBackendRelay, BypassWritesNoTargetByte)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const ProbeHandle probe =
        create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&detour_leaf), "BypassNoTargetWrite");
    ASSERT_TRUE(probe);
    ASSERT_TRUE(probe.drive(BackendProbeOperation::Enable));
    const BackendProbeState armed_state = probe.state();
    ASSERT_NE(armed_state.relay_slot, nullptr);
    const std::vector<std::uint8_t> armed = page_bytes(page);

    const auto expect_switch_without_write = [&](BackendProbeOperation operation, std::uint64_t slot_value, int result)
    {
        DetourModKit::detail::reset_backend_instruction_flush_trace_for_test();
        const std::size_t protects_before = DetourModKit::detail::backend_trap_protect_calls_for_test();
        ASSERT_TRUE(probe.drive(operation));
        EXPECT_EQ(DetourModKit::detail::backend_trap_protect_calls_for_test(), protects_before);
        EXPECT_EQ(DetourModKit::detail::backend_instruction_flush_trace_size_for_test(), 0u);
        EXPECT_EQ(page_bytes(page), armed);
        EXPECT_EQ(read_word(address_of(armed_state.relay_slot)), slot_value);
        EXPECT_EQ(call_target(page), result);
    };

    expect_switch_without_write(BackendProbeOperation::Bypass, address_of(armed_state.trampoline), LEAF_RESULT);
    EXPECT_TRUE(probe.state().bypassed);
    EXPECT_TRUE(probe.state().enabled);
    expect_switch_without_write(BackendProbeOperation::Resume, address_of(code_address(&detour_leaf)), DETOUR_RESULT);
    EXPECT_FALSE(probe.state().bypassed);
}

// Every emitted trampoline ends with a sealed relay cell that names its position: the near, far, mid, and routed
// kinds.
TEST(HookBackendRelayCell, FooterSealsEveryTrampolineKind)
{
    struct KindCase
    {
        const char *name;
        BackendProbeKind kind;
        bool use_far_path;
        RelayCellKind footer_kind;
        std::size_t window;
    };
    const std::array<KindCase, 4> cases{{
        {"RelayCellNear", BackendProbeKind::Inline, false, RelayCellKind::E9, NEAR_PATCH_SIZE},
        {"RelayCellFar", BackendProbeKind::Inline, true, RelayCellKind::FF, FAR_PATCH_SIZE},
        {"RelayCellMid", BackendProbeKind::Mid, false, RelayCellKind::Mid, NEAR_PATCH_SIZE},
        {"RelayCellRouted", BackendProbeKind::Routed, false, RelayCellKind::Routed, NEAR_PATCH_SIZE},
    }};
    for (const KindCase &kind_case : cases)
    {
        SCOPED_TRACE(kind_case.name);
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);
        const PrologueSpan pristine = read_prologue_span(page);
        void *const destination = first_destination(kind_case.kind);

        ProbeHandle probe;
        {
            const FarHookScope far_hook{kind_case.use_far_path};
            probe = create_probe(kind_case.kind, page.addr(0), destination, kind_case.name);
        }
        ASSERT_TRUE(probe);
        const BackendProbeState state = probe.state();
        ASSERT_NE(state.trampoline, nullptr);
        ASSERT_NE(state.relay_cell, nullptr);
        EXPECT_EQ(address_of(state.relay_cell) % alignof(std::uint64_t), 0u);

        const RelayCellBody body = read_relay_cell(state.relay_cell);
        EXPECT_EQ(body.state, RELAY_CELL_OWNED);
        EXPECT_EQ(body.identity, position_identity(kind_case.name));
        EXPECT_EQ(body.target, page.addr(0));
        ASSERT_EQ(body.original_size, kind_case.window);
        EXPECT_EQ(std::memcmp(body.original, pristine.data(), kind_case.window), 0);
        if (kind_case.kind == BackendProbeKind::Inline)
        {
            // The switch word is the relay slot, and the body follows it.
            EXPECT_EQ(body.switch_word, address_of(state.relay_slot));
            EXPECT_EQ(address_of(state.relay_cell), address_of(state.relay_slot) + sizeof(std::uint64_t));
            EXPECT_EQ(body.route_word, 0u);
        }
        else
        {
            // The switch word is the route state, and the route word holds this generation's destination.
            ASSERT_NE(body.switch_word, 0u);
            ASSERT_NE(body.route_word, 0u);
            EXPECT_EQ(read_word(body.route_word), address_of(destination));
        }

        const std::uint8_t *const footer_address = find_relay_cell_footer(state.relay_cell);
        ASSERT_NE(footer_address, nullptr) << "no sealed footer follows the cell body";
        const RelayCellFooter footer = read_footer(footer_address);
        EXPECT_EQ(footer.layout, RELAY_CELL_LAYOUT);
        EXPECT_EQ(footer.kind, static_cast<std::uint16_t>(kind_case.footer_kind));
        EXPECT_EQ(footer.body_offset, address_of(state.relay_cell) - address_of(state.trampoline));
    }
}

// A trampoline without a relay cell has the earlier shape. No seal ends it, so it cannot switch or vacate, and a
// same-name successor installs fresh on top of it.
TEST(HookBackendRelayCell, SealRejectsALegacyTrampoline)
{
    constexpr std::string_view NAME = "LegacyRelayCell";
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);

    ProbeHandle legacy;
    {
        const RelayCellOmissionScope omission;
        legacy = create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&detour_leaf), NAME);
    }
    ASSERT_TRUE(legacy);
    const BackendProbeState state = legacy.state();
    EXPECT_EQ(state.relay_cell, nullptr);
    ASSERT_NE(state.relay_slot, nullptr);
    ASSERT_TRUE(legacy.drive(BackendProbeOperation::Enable));
    EXPECT_EQ(call_target(page), DETOUR_RESULT);
    const PrologueSpan armed = read_prologue_span(page);

    // The earlier shape ends with its relay slot, so its last 16 bytes are relay code and data, never a seal.
    const std::uintptr_t allocation_end = address_of(state.relay_slot) + sizeof(std::uint64_t);
    const RelayCellFooter tail = read_footer(reinterpret_cast<const std::uint8_t *>(allocation_end - sizeof(tail)));
    EXPECT_NE(tail.seal, RELAY_CELL_SEAL ^ (allocation_end - sizeof(std::uint64_t)));
    EXPECT_FALSE(legacy.drive(BackendProbeOperation::Bypass));
    EXPECT_FALSE(legacy.drive(BackendProbeOperation::Vacate));
    EXPECT_FALSE(legacy.state().bypassed);
    EXPECT_EQ(call_target(page), DETOUR_RESULT);

    const BackendCoordinatorCounts counts_before = coordinator_counts();
    {
        const ProbeHandle successor =
            create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&successor_detour), NAME);
        ASSERT_TRUE(successor);
        EXPECT_FALSE(successor.state().claimed);
        // The seam scope ended, so the successor carries a cell of its own.
        EXPECT_NE(successor.state().relay_cell, nullptr);
        BackendCoordinatorCounts layered = counts_before;
        ++layered.live;
        --layered.free;
        EXPECT_TRUE(counts_equal(coordinator_counts(), layered));
    }
    EXPECT_TRUE(counts_equal(coordinator_counts(), counts_before));
    EXPECT_EQ(read_prologue_span(page), armed);

    legacy.reset();
    EXPECT_EQ(read_prologue_span(page), pristine);
}

// A vacate turns the cell Vacant and leaves the object inert. The record stays live, enabled, and unretained, and the
// target patch stays in the chain with its relay on the trampoline.
TEST(HookBackendRelayCell, VacateKeepsTheRecordLiveEnabledAndUnretained)
{
    constexpr std::string_view NAME = "VacateKeepsRecord";
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    ProbeHandle owner = create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&detour_leaf), NAME);
    ASSERT_TRUE(owner);
    const BackendProbeState created = owner.state();
    ASSERT_NE(created.relay_cell, nullptr);

    // A fresh hook owns a position only while its committed patch is switched off. An unarmed or a live relay refuses.
    ASSERT_TRUE(owner.drive(BackendProbeOperation::Bypass));
    EXPECT_FALSE(owner.drive(BackendProbeOperation::Vacate));
    ASSERT_TRUE(owner.drive(BackendProbeOperation::Enable));
    EXPECT_FALSE(owner.drive(BackendProbeOperation::Vacate));
    EXPECT_EQ(read_relay_cell(created.relay_cell).state, RELAY_CELL_OWNED);

    ASSERT_TRUE(owner.drive(BackendProbeOperation::Bypass));
    const PrologueSpan armed = read_prologue_span(page);
    const BackendCoordinatorCounts before = coordinator_counts();
    ASSERT_TRUE(owner.drive(BackendProbeOperation::Vacate));
    BackendCoordinatorCounts vacant_counts = before;
    ++vacant_counts.vacant;
    EXPECT_TRUE(counts_equal(coordinator_counts(), vacant_counts));
    EXPECT_EQ(read_relay_cell(created.relay_cell).state, RELAY_CELL_VACANT);
    const BackendProbeState vacated = owner.state();
    EXPECT_FALSE(vacated.valid);
    EXPECT_FALSE(vacated.enabled);
    EXPECT_EQ(vacated.relay_cell, nullptr);
    EXPECT_EQ(read_prologue_span(page), armed);
    EXPECT_EQ(read_word(address_of(created.relay_slot)), address_of(created.trampoline));
    EXPECT_EQ(call_target(page), LEAF_RESULT);

    // The inert object writes and frees nothing at destruction.
    owner.reset();
    EXPECT_TRUE(counts_equal(coordinator_counts(), vacant_counts));
    EXPECT_EQ(read_prologue_span(page), armed);
    EXPECT_EQ(call_target(page), LEAF_RESULT);

    // A claim accepts only an enabled, unretained record, so a same-name successor proves both flags.
    {
        const ProbeHandle successor =
            create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&successor_detour), NAME);
        ASSERT_TRUE(successor);
        EXPECT_TRUE(successor.state().claimed);
        EXPECT_EQ(successor.state().trampoline, created.trampoline);
    }
    EXPECT_TRUE(counts_equal(coordinator_counts(), vacant_counts));
    // The position stays in the target's chain for process life, so the fixture must not hand the page back.
    page.abandon();
}

// A claim adopts the vacated trampoline by one state change. It writes no target byte and no record, and the claimed
// object toggles by stores into the relay slot alone.
TEST(HookBackendRelayCell, ClaimWritesNoTargetByteAndNoRecord)
{
    constexpr std::string_view NAME = "ClaimNoWrite";
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const std::optional<VacantPosition> position =
        vacate_fresh_position(BackendProbeKind::Inline, page, code_address(&detour_leaf), NAME);
    ASSERT_TRUE(position.has_value());
    const BackendCoordinatorCounts vacant_counts = coordinator_counts();
    BackendCoordinatorCounts claimed_counts = vacant_counts;
    --claimed_counts.vacant;
    const std::vector<std::uint8_t> armed = page_bytes(page);

    DetourModKit::detail::reset_backend_instruction_flush_trace_for_test();
    const std::size_t protects_before = DetourModKit::detail::backend_trap_protect_calls_for_test();
    ProbeHandle successor = create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&successor_detour), NAME);
    ASSERT_TRUE(successor);
    const BackendProbeState state = successor.state();
    EXPECT_TRUE(state.claimed);
    EXPECT_FALSE(state.enabled);
    EXPECT_TRUE(state.bypassed);
    EXPECT_EQ(state.trampoline, position->state.trampoline);
    EXPECT_EQ(state.relay_slot, position->state.relay_slot);
    EXPECT_EQ(state.relay_cell, position->state.relay_cell);
    EXPECT_EQ(read_relay_cell(position->state.relay_cell).state, RELAY_CELL_OWNED);
    EXPECT_TRUE(counts_equal(coordinator_counts(), claimed_counts));
    EXPECT_EQ(page_bytes(page), armed);

    ASSERT_TRUE(successor.drive(BackendProbeOperation::Enable));
    EXPECT_EQ(call_target(page), SUCCESSOR_RESULT);
    ASSERT_TRUE(successor.drive(BackendProbeOperation::Disable));
    EXPECT_EQ(call_target(page), LEAF_RESULT);
    EXPECT_EQ(page_bytes(page), armed);
    EXPECT_TRUE(counts_equal(coordinator_counts(), claimed_counts));
    EXPECT_EQ(DetourModKit::detail::backend_trap_protect_calls_for_test(), protects_before);
    EXPECT_EQ(DetourModKit::detail::backend_instruction_flush_trace_size_for_test(), 0u);

    successor.reset();
    EXPECT_TRUE(counts_equal(coordinator_counts(), vacant_counts));
    EXPECT_EQ(page_bytes(page), armed);
    EXPECT_EQ(read_relay_cell(position->state.relay_cell).state, RELAY_CELL_VACANT);
    page.abandon();
}

// Each sub-case breaks one claim check and keeps every other check satisfied, sees a fresh install in place of the
// claim, and repairs the check. A control claim after each repair shows that the broken check alone refused.
TEST(HookBackendRelayCell, ClaimRefusesEachFailedPrecondition)
{
    constexpr std::string_view NAME = "ClaimRefusal";
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);
    const std::optional<VacantPosition> position =
        vacate_fresh_position(BackendProbeKind::Inline, page, code_address(&detour_leaf), NAME);
    ASSERT_TRUE(position.has_value());
    auto *const cell = static_cast<std::uint8_t *>(position->state.relay_cell);
    std::uint8_t *const footer_address = find_relay_cell_footer(cell);
    ASSERT_NE(footer_address, nullptr);
    const RelayCellBody body = read_relay_cell(cell);
    const RelayCellFooter footer = read_footer(footer_address);
    // The body, the spare bytes, and the footer run to the trampoline end.
    std::uint8_t *const trampoline_end = footer_address + sizeof(RelayCellFooter);
    const std::vector<std::uint8_t> cell_bytes(cell, trampoline_end);
    const std::uintptr_t slot = address_of(position->state.relay_slot);
    ASSERT_EQ(body.state, RELAY_CELL_VACANT);
    ASSERT_EQ(claim_outcome(BackendProbeKind::Inline, page.addr(0), NAME), ClaimOutcome::Claimed);

    const auto restore_cell = [&] { std::memcpy(cell, cell_bytes.data(), cell_bytes.size()); };
    const auto expect_refused_until_repaired = [&](const char *check, const auto &break_check, const auto &repair)
    {
        SCOPED_TRACE(check);
        break_check();
        EXPECT_EQ(claim_outcome(BackendProbeKind::Inline, page.addr(0), NAME), ClaimOutcome::Fresh);
        repair();
        EXPECT_EQ(claim_outcome(BackendProbeKind::Inline, page.addr(0), NAME), ClaimOutcome::Claimed);
    };

    {
        SCOPED_TRACE("the exact target");
        dmk_test::ScratchPage other_page;
        ASSERT_TRUE(other_page.ok());
        plant_leaf(other_page);
        EXPECT_EQ(claim_outcome(BackendProbeKind::Inline, other_page.addr(0), NAME), ClaimOutcome::Fresh);
    }
    {
        SCOPED_TRACE("the identity");
        EXPECT_EQ(claim_outcome(BackendProbeKind::Inline, page.addr(0), "ClaimRefusalOther"), ClaimOutcome::Fresh);
    }
    {
        SCOPED_TRACE("the requested kind");
        EXPECT_EQ(claim_outcome(BackendProbeKind::Mid, page.addr(0), NAME), ClaimOutcome::Fresh);
    }
    expect_refused_until_repaired(
        "the footer seal",
        [&]
        {
            RelayCellFooter broken = footer;
            broken.seal ^= 1;
            write_footer(footer_address, broken);
        },
        restore_cell
    );
    expect_refused_until_repaired(
        "the footer layout",
        [&]
        {
            RelayCellFooter broken = footer;
            broken.layout = static_cast<std::uint16_t>(RELAY_CELL_LAYOUT + 1);
            write_footer(footer_address, broken);
        },
        restore_cell
    );
    expect_refused_until_repaired(
        "the footer kind",
        [&]
        {
            RelayCellFooter broken = footer;
            broken.kind = static_cast<std::uint16_t>(RelayCellKind::Mid);
            write_footer(footer_address, broken);
        },
        restore_cell
    );
    // The allocator starts each trampoline at an even address, so the cell of the planted leaf leaves an odd spare gap
    // before the footer. One spare byte keeps the shifted body inside the bound check.
    ASSERT_GT(static_cast<std::size_t>(footer_address - cell), sizeof(RelayCellBody));
    expect_refused_until_repaired(
        "the aligned body",
        [&]
        {
            // A copy of the Vacant body one byte later satisfies every other check at the unaligned offset.
            RelayCellFooter broken = footer;
            ++broken.body_offset;
            write_footer(footer_address, broken);
            write_relay_cell(cell + 1, body);
        },
        restore_cell
    );
    expect_refused_until_repaired(
        "the Vacant state",
        [&]
        {
            RelayCellBody broken = body;
            broken.state = RELAY_CELL_OWNED;
            write_relay_cell(cell, broken);
        },
        restore_cell
    );
    expect_refused_until_repaired(
        "the body target",
        [&]
        {
            RelayCellBody broken = body;
            ++broken.target;
            write_relay_cell(cell, broken);
        },
        restore_cell
    );
    expect_refused_until_repaired(
        "the original size",
        [&]
        {
            RelayCellBody broken = body;
            ++broken.original_size;
            write_relay_cell(cell, broken);
        },
        restore_cell
    );
    // An aligned word past the trampoline end that holds the trampoline start satisfies every other switch check.
    const ReadWritePageAbove outside{address_of(trampoline_end)};
    ASSERT_NE(outside.address(), 0u) << "no free granule above the trampoline";
    write_word(outside.address(), address_of(position->state.trampoline));
    expect_refused_until_repaired(
        "the switch word range",
        [&]
        {
            RelayCellBody broken = body;
            broken.switch_word = outside.address();
            write_relay_cell(cell, broken);
        },
        restore_cell
    );
    expect_refused_until_repaired(
        "the switched-off relay",
        [&] { write_word(slot, address_of(code_address(&detour_leaf))); },
        [&] { write_word(slot, address_of(position->state.trampoline)); }
    );
    expect_refused_until_repaired(
        "the pristine target window",
        [&] { std::memcpy(page.base(), pristine.data(), body.original_size); },
        [&] { write_prologue_span(page, position->armed); }
    );

    {
        SCOPED_TRACE("the enabled record");
        constexpr std::string_view DISABLED_NAME = "ClaimRefusalDisabled";
        dmk_test::ScratchPage disabled_page;
        ASSERT_TRUE(disabled_page.ok());
        plant_leaf(disabled_page);
        const PrologueSpan disabled_pristine = read_prologue_span(disabled_page);
        const ProbeHandle owner =
            create_probe(BackendProbeKind::Inline, disabled_page.addr(0), code_address(&detour_leaf), DISABLED_NAME);
        ASSERT_TRUE(owner);
        ASSERT_TRUE(owner.drive(BackendProbeOperation::Enable));
        ASSERT_TRUE(owner.drive(BackendProbeOperation::Bypass));
        // The restore marks the record disabled and keeps the relay on the trampoline start.
        ASSERT_TRUE(owner.drive(BackendProbeOperation::Disable));
        void *const owner_cell = owner.state().relay_cell;
        ASSERT_NE(owner_cell, nullptr);
        const RelayCellBody owner_body = read_relay_cell(owner_cell);
        RelayCellBody vacant = owner_body;
        vacant.state = RELAY_CELL_VACANT;
        write_relay_cell(owner_cell, vacant);
        // A window that differs from the saved bytes leaves the disabled record as the only failed check.
        disabled_page.put(0, {0xB8, 0x02, 0x00, 0x00, 0x00});
        EXPECT_EQ(claim_outcome(BackendProbeKind::Inline, disabled_page.addr(0), DISABLED_NAME), ClaimOutcome::Fresh);
        write_prologue_span(disabled_page, disabled_pristine);
        write_relay_cell(owner_cell, owner_body);
    }
    {
        SCOPED_TRACE("the unretained record");
        constexpr std::string_view RETAINED_NAME = "ClaimRefusalRetained";
        dmk_test::ScratchPage retained_page;
        ASSERT_TRUE(retained_page.ok());
        plant_leaf(retained_page);
        {
            const ProbeHandle owner = create_probe(
                BackendProbeKind::Inline,
                retained_page.addr(0),
                code_address(&detour_leaf),
                RETAINED_NAME
            );
            ASSERT_TRUE(owner);
            ASSERT_TRUE(owner.drive(BackendProbeOperation::Enable));
            ASSERT_TRUE(owner.drive(BackendProbeOperation::Bypass));
            ASSERT_TRUE(owner.drive(BackendProbeOperation::RetainRoute));
            ASSERT_TRUE(owner.drive(BackendProbeOperation::Vacate));
        }
        EXPECT_EQ(claim_outcome(BackendProbeKind::Inline, retained_page.addr(0), RETAINED_NAME), ClaimOutcome::Fresh);
        retained_page.abandon();
    }
    {
        SCOPED_TRACE("the closed route");
        constexpr std::string_view ROUTED_NAME = "ClaimRefusalRouted";
        dmk_test::ScratchPage routed_page;
        ASSERT_TRUE(routed_page.ok());
        plant_leaf(routed_page);
        const std::optional<VacantPosition> routed =
            vacate_fresh_position(BackendProbeKind::Routed, routed_page, code_address(&detour_leaf), ROUTED_NAME);
        ASSERT_TRUE(routed.has_value());
        void *const routed_cell = routed->state.relay_cell;
        const RelayCellBody routed_body = read_relay_cell(routed_cell);
        ASSERT_EQ(read_route_state(routed_body.switch_word), ROUTE_CLOSED);

        write_route_state(routed_body.switch_word, ROUTE_LIVE);
        EXPECT_EQ(claim_outcome(BackendProbeKind::Routed, routed_page.addr(0), ROUTED_NAME), ClaimOutcome::Fresh);
        write_route_state(routed_body.switch_word, ROUTE_CLOSED);

        RelayCellBody broken = routed_body;
        broken.route_word += sizeof(std::uint64_t);
        write_relay_cell(routed_cell, broken);
        EXPECT_EQ(claim_outcome(BackendProbeKind::Routed, routed_page.addr(0), ROUTED_NAME), ClaimOutcome::Fresh);
        write_relay_cell(routed_cell, routed_body);

        EXPECT_EQ(claim_outcome(BackendProbeKind::Routed, routed_page.addr(0), ROUTED_NAME), ClaimOutcome::Claimed);
        routed_page.abandon();
    }

    EXPECT_EQ(read_relay_cell(cell).state, RELAY_CELL_VACANT);
    EXPECT_EQ(read_prologue_span(page), position->armed);
    page.abandon();
}

// Claimants race for one vacated cell. The claim runs under the process coordinator, so exactly one of them takes it,
// and every other one installs fresh on top.
TEST(HookBackendRelayCell, ConcurrentClaimsSucceedOnce)
{
    using namespace std::chrono_literals;
    constexpr std::size_t CLAIMANTS = 8;
    constexpr std::string_view NAME = "ConcurrentClaims";
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const std::optional<VacantPosition> position =
        vacate_fresh_position(BackendProbeKind::Inline, page, code_address(&detour_leaf), NAME);
    ASSERT_TRUE(position.has_value());
    const BackendCoordinatorCounts vacant_counts = coordinator_counts();

    std::array<BackendProbe *, CLAIMANTS> created{};
    bool started = false;
    {
        std::atomic<std::size_t> ready{0};
        std::atomic<bool> start{false};
        std::vector<std::jthread> threads;
        threads.reserve(CLAIMANTS);
        for (std::size_t index = 0; index < CLAIMANTS; ++index)
        {
            threads.emplace_back(
                [&created, &ready, &start, &page, index, NAME]
                {
                    ready.fetch_add(1, std::memory_order_acq_rel);
                    const auto deadline = std::chrono::steady_clock::now() + 10s;
                    while (!start.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
                    {
                        std::this_thread::yield();
                    }
                    created[index] = DetourModKit::detail::create_backend_probe_for_test(
                        BackendProbeKind::Inline,
                        reinterpret_cast<void *>(page.addr(0)),
                        code_address(&successor_detour),
                        NAME
                    );
                }
            );
        }
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (ready.load(std::memory_order_acquire) < CLAIMANTS && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::yield();
        }
        started = ready.load(std::memory_order_acquire) == CLAIMANTS;
        start.store(true, std::memory_order_release);
    }
    EXPECT_TRUE(started) << "the claimants did not reach the start barrier together";

    std::vector<ProbeHandle> claimed;
    std::vector<ProbeHandle> fresh_layers;
    for (BackendProbe *const probe : created)
    {
        ProbeHandle handle{probe};
        if (!handle)
        {
            continue;
        }
        if (handle.state().claimed)
        {
            claimed.push_back(std::move(handle));
        }
        else
        {
            fresh_layers.push_back(std::move(handle));
        }
    }
    EXPECT_EQ(claimed.size() + fresh_layers.size(), CLAIMANTS);
    ASSERT_EQ(claimed.size(), 1u);
    EXPECT_EQ(claimed.front().state().trampoline, position->state.trampoline);
    BackendCoordinatorCounts layered = vacant_counts;
    --layered.vacant;
    layered.live += fresh_layers.size();
    layered.free -= fresh_layers.size();
    EXPECT_TRUE(counts_equal(coordinator_counts(), layered));

    destroy_newest_first(fresh_layers);
    claimed.clear();
    EXPECT_TRUE(counts_equal(coordinator_counts(), vacant_counts));
    EXPECT_EQ(read_prologue_span(page), position->armed);
    page.abandon();
}

// Callers run through a vacated position while successors claim it, switch it on and off, and vacate it again. Every
// call reaches the trampoline or the successor's detour. The vacated detour never runs again.
TEST(HookBackendRelayCell, ConcurrentCallersDuringClaimSeeTrampolineOrDetour)
{
    constexpr std::size_t CALLER_THREADS = 4;
    constexpr std::size_t CLAIM_CYCLES = 256;
    constexpr std::string_view NAME = "CallersDuringClaim";
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const std::optional<VacantPosition> position =
        vacate_fresh_position(BackendProbeKind::Inline, page, code_address(&detour_leaf), NAME);
    ASSERT_TRUE(position.has_value());
    const BackendCoordinatorCounts vacant_counts = coordinator_counts();

    {
        TargetCallers callers{page.addr(0), LEAF_RESULT, SUCCESSOR_RESULT, CALLER_THREADS};
        ASSERT_TRUE(callers.wait_for_calls(CALLER_THREADS * 16)) << "the callers never started";
        for (std::size_t cycle = 0; cycle < CLAIM_CYCLES; ++cycle)
        {
            const ProbeHandle successor =
                create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&successor_detour), NAME);
            ASSERT_TRUE(successor);
            ASSERT_TRUE(successor.state().claimed) << "cycle " << cycle;
            ASSERT_TRUE(successor.drive(BackendProbeOperation::Enable));
            ASSERT_TRUE(successor.drive(BackendProbeOperation::Disable));
        }
        callers.stop();
        EXPECT_EQ(callers.unexpected(), 0u) << "of " << callers.calls() << " calls";
        EXPECT_GT(callers.calls(), CALLER_THREADS * 16);
    }

    EXPECT_TRUE(counts_equal(coordinator_counts(), vacant_counts));
    EXPECT_EQ(read_prologue_span(page), position->armed);
    page.abandon();
}

// A claimed object switches off and gives its position back on every teardown path. It writes no target byte and no
// record, and route retention leaves the record that it does not own unchanged.
TEST(HookBackendRelayCell, ClaimedObjectWritesNoRecordOnAnyTeardownPath)
{
    struct TeardownCase
    {
        const char *label;
        std::optional<BackendProbeOperation> operation;
    };
    const std::array<TeardownCase, 4> teardowns{{
        {"destroy", std::nullopt},
        {"reset", BackendProbeOperation::Reset},
        {"move assignment", BackendProbeOperation::MoveAssign},
        {"route retention", BackendProbeOperation::RetainRoute},
    }};
    for (const BackendProbeKind kind : {BackendProbeKind::Inline, BackendProbeKind::Routed, BackendProbeKind::Mid})
    {
        SCOPED_TRACE(probe_kind_label(kind));
        const std::string name = std::string{"ClaimedTeardown_"} + probe_kind_label(kind);
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);
        const std::optional<VacantPosition> position = vacate_fresh_position(kind, page, first_destination(kind), name);
        ASSERT_TRUE(position.has_value());
        const BackendCoordinatorCounts vacant_counts = coordinator_counts();
        BackendCoordinatorCounts claimed_counts = vacant_counts;
        --claimed_counts.vacant;
        const std::vector<std::uint8_t> armed = page_bytes(page);

        for (const TeardownCase &teardown : teardowns)
        {
            SCOPED_TRACE(teardown.label);
            ProbeHandle claimant = create_probe(kind, page.addr(0), second_destination(kind), name);
            ASSERT_TRUE(claimant);
            ASSERT_TRUE(claimant.state().claimed);
            ASSERT_TRUE(claimant.drive(BackendProbeOperation::Enable));
            EXPECT_TRUE(counts_equal(coordinator_counts(), claimed_counts));
            if (teardown.operation == BackendProbeOperation::RetainRoute)
            {
                ASSERT_TRUE(claimant.drive(BackendProbeOperation::RetainRoute));
                EXPECT_TRUE(counts_equal(coordinator_counts(), claimed_counts));
                EXPECT_TRUE(claimant.state().claimed);
                claimant.reset();
            }
            else if (teardown.operation.has_value())
            {
                ASSERT_TRUE(claimant.drive(*teardown.operation));
                EXPECT_FALSE(claimant.state().claimed);
            }
            else
            {
                claimant.reset();
            }
            EXPECT_TRUE(counts_equal(coordinator_counts(), vacant_counts));
            EXPECT_EQ(page_bytes(page), armed);
            EXPECT_EQ(read_relay_cell(position->state.relay_cell).state, RELAY_CELL_VACANT);
        }
        page.abandon();
    }
}

// A routed or mid claim writes its destination into the route word only while the route stays closed. A closed route
// reads no route word. Over an open route the claim is refused and writes nothing.
TEST(HookBackendRelayCell, RoutedClaimWritesTheRouteWordOnlyWhileClosed)
{
    for (const BackendProbeKind kind : {BackendProbeKind::Routed, BackendProbeKind::Mid})
    {
        SCOPED_TRACE(probe_kind_label(kind));
        const std::string name = std::string{"RouteWord_"} + probe_kind_label(kind);
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);

        ProbeHandle owner = create_probe(kind, page.addr(0), first_destination(kind), name);
        ASSERT_TRUE(owner);
        ASSERT_TRUE(owner.drive(BackendProbeOperation::Enable));
        void *const cell = owner.state().relay_cell;
        ASSERT_NE(cell, nullptr);
        const RelayCellBody body = read_relay_cell(cell);
        ASSERT_NE(body.switch_word, 0u);
        ASSERT_NE(body.route_word, 0u);
        EXPECT_EQ(read_route_state(body.switch_word), ROUTE_LIVE);
        EXPECT_EQ(read_word(body.route_word), address_of(first_destination(kind)));
        EXPECT_EQ(route_reached(kind, page), RouteReached::First);
        ASSERT_TRUE(owner.drive(BackendProbeOperation::Bypass));
        EXPECT_EQ(read_route_state(body.switch_word), ROUTE_CLOSED);
        EXPECT_EQ(route_reached(kind, page), RouteReached::None);
        ASSERT_TRUE(owner.drive(BackendProbeOperation::Vacate));
        owner.reset();

        write_route_state(body.switch_word, ROUTE_LIVE);
        EXPECT_EQ(claim_outcome(kind, page.addr(0), name), ClaimOutcome::Fresh);
        EXPECT_EQ(read_word(body.route_word), address_of(first_destination(kind)));
        write_route_state(body.switch_word, ROUTE_CLOSED);

        ProbeHandle successor = create_probe(kind, page.addr(0), second_destination(kind), name);
        ASSERT_TRUE(successor);
        ASSERT_TRUE(successor.state().claimed);
        EXPECT_EQ(read_word(body.route_word), address_of(second_destination(kind)));
        EXPECT_EQ(read_route_state(body.switch_word), ROUTE_CLOSED);
        EXPECT_EQ(route_reached(kind, page), RouteReached::None);
        ASSERT_TRUE(successor.drive(BackendProbeOperation::Enable));
        EXPECT_EQ(read_route_state(body.switch_word), ROUTE_LIVE);
        EXPECT_EQ(route_reached(kind, page), RouteReached::Second);
        ASSERT_TRUE(successor.drive(BackendProbeOperation::Disable));
        EXPECT_EQ(route_reached(kind, page), RouteReached::None);

        successor.reset();
        EXPECT_EQ(read_route_state(body.switch_word), ROUTE_CLOSED);
        EXPECT_EQ(read_relay_cell(cell).state, RELAY_CELL_VACANT);
        page.abandon();
    }
}

// A vacate that the coordinator refuses changes nothing: the cell stays Owned, and the object keeps its position for a
// later vacate. This holds for a fresh and for a claimed object.
TEST(HookBackendRelayCell, RefusedVacateLeavesTheCellOwned)
{
    constexpr std::string_view NAME = "RefusedVacate";
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    ProbeHandle owner = create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&detour_leaf), NAME);
    ASSERT_TRUE(owner);
    ASSERT_TRUE(owner.drive(BackendProbeOperation::Enable));
    ASSERT_TRUE(owner.drive(BackendProbeOperation::Bypass));
    const BackendProbeState armed_state = owner.state();
    ASSERT_NE(armed_state.relay_cell, nullptr);
    const BackendCoordinatorCounts owned_counts = coordinator_counts();

    {
        const CoordinatorRefusalScope refusal{COORDINATOR_UNAVAILABLE};
        EXPECT_FALSE(owner.drive(BackendProbeOperation::Vacate));
    }
    EXPECT_EQ(read_relay_cell(armed_state.relay_cell).state, RELAY_CELL_OWNED);
    const BackendProbeState refused_state = owner.state();
    EXPECT_TRUE(refused_state.valid);
    EXPECT_TRUE(refused_state.enabled);
    EXPECT_TRUE(refused_state.bypassed);
    EXPECT_EQ(refused_state.relay_cell, armed_state.relay_cell);
    EXPECT_TRUE(counts_equal(coordinator_counts(), owned_counts));
    // An Owned cell gives nothing to a same-name successor.
    EXPECT_EQ(claim_outcome(BackendProbeKind::Inline, page.addr(0), NAME), ClaimOutcome::Fresh);
    EXPECT_TRUE(counts_equal(coordinator_counts(), owned_counts));

    ASSERT_TRUE(owner.drive(BackendProbeOperation::Vacate));
    owner.reset();
    BackendCoordinatorCounts vacant_counts = owned_counts;
    ++vacant_counts.vacant;
    EXPECT_TRUE(counts_equal(coordinator_counts(), vacant_counts));

    ProbeHandle claimant = create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&successor_detour), NAME);
    ASSERT_TRUE(claimant);
    ASSERT_TRUE(claimant.state().claimed);
    {
        const CoordinatorRefusalScope refusal{COORDINATOR_UNAVAILABLE};
        EXPECT_FALSE(claimant.drive(BackendProbeOperation::Vacate));
    }
    EXPECT_EQ(read_relay_cell(armed_state.relay_cell).state, RELAY_CELL_OWNED);
    EXPECT_TRUE(claimant.state().claimed);

    // The destructor vacates once the coordinator answers again.
    claimant.reset();
    EXPECT_EQ(read_relay_cell(armed_state.relay_cell).state, RELAY_CELL_VACANT);
    EXPECT_TRUE(counts_equal(coordinator_counts(), vacant_counts));
    page.abandon();
}

// A restore that fails before any write keeps a bypassed route closed. The failed disable never reopens the route of a
// switched-off hook.
TEST(HookBackendRelay, FailedRestoreKeepsABypassedRouteClosed)
{
    for (const BackendProbeKind kind : {BackendProbeKind::Routed, BackendProbeKind::Mid})
    {
        SCOPED_TRACE(probe_kind_label(kind));
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        plant_leaf(page);
        const PrologueSpan pristine = read_prologue_span(page);
        ProbeHandle probe = create_probe(
            kind,
            page.addr(0),
            first_destination(kind),
            std::string{"FailedRestoreRoute_"} + probe_kind_label(kind)
        );
        ASSERT_TRUE(probe);
        ASSERT_TRUE(probe.drive(BackendProbeOperation::Enable));
        ASSERT_EQ(route_reached(kind, page), RouteReached::First);
        ASSERT_TRUE(probe.drive(BackendProbeOperation::Bypass));
        const PrologueSpan armed = read_prologue_span(page);

        {
            const BackendToggleExceptionScope seam{page.addr(0), ToggleExceptionStage::BeforeMutation};
            EXPECT_FALSE(probe.drive(BackendProbeOperation::Disable));
            EXPECT_EQ(DetourModKit::detail::backend_toggle_exception_catches_for_test(), 1u);
        }
        const BackendProbeState refused = probe.state();
        EXPECT_TRUE(refused.enabled);
        EXPECT_TRUE(refused.bypassed) << "the failed restore reopened the route";
        EXPECT_EQ(read_prologue_span(page), armed);
        EXPECT_EQ(route_reached(kind, page), RouteReached::None);

        ASSERT_TRUE(probe.drive(BackendProbeOperation::Disable));
        EXPECT_EQ(read_prologue_span(page), pristine);
        EXPECT_EQ(route_reached(kind, page), RouteReached::None);
    }
}

// A participant outside this kit's ledger owns a newer record on the target. The disable of the armed hook reaches the
// backend restore, the coordinator refuses it before any write, and the hook bypasses. Its Info line names the newer
// participant.
TEST(HookToggleWarning, CoordinatorRefusedDisableNamesTheNewerParticipant)
{
    dmk_test::ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_leaf(page);
    const PrologueSpan pristine = read_prologue_span(page);
    Result<Hook> installed = install_leaf(page, "WarnCoordinatorDisable");
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    Hook hook = std::move(*installed);
    ASSERT_TRUE(hook.enable().has_value());
    const PrologueSpan armed = read_prologue_span(page);

    // The probe never arms, so it writes no target byte and the hook keeps its own patch as the witness.
    ProbeHandle newer =
        create_probe(BackendProbeKind::Inline, page.addr(0), code_address(&successor_detour), "WarnCoordinatorNewer");
    ASSERT_TRUE(newer);
    ASSERT_FALSE(newer.state().claimed);
    ASSERT_EQ(read_prologue_span(page), armed);

    std::string text;
    {
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Info};
        const Result<void> disabled = hook.disable();
        ASSERT_TRUE(disabled.has_value()) << disabled.error().message();
        text = capture.read_all();
    }
    const std::string expected = toggle_warning_prefix("WarnCoordinatorDisable", page) +
                                 "bypassed under a newer layer: a newer participant owns the target.";
    EXPECT_NE(text.find(expected), std::string::npos) << text;
    EXPECT_FALSE(hook.is_enabled());
    EXPECT_EQ(read_prologue_span(page), armed) << "the refused restore wrote the target";
    EXPECT_EQ(call_target(page), LEAF_RESULT) << "the bypassed detour still ran";

    // The probe holds the newest record, so it goes first. The bypassed hook is then the top layer over its own patch,
    // and its next disable restores the target.
    newer.reset();
    const Result<void> restored = hook.disable();
    ASSERT_TRUE(restored.has_value()) << restored.error().message();
    EXPECT_FALSE(hook.is_enabled());
    EXPECT_EQ(read_prologue_span(page), pristine) << "the second disable did not restore";
    EXPECT_EQ(call_target(page), LEAF_RESULT);
}
#endif // DMK_ENABLE_TEST_SEAMS
