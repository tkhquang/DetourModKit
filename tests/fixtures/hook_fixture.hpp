#ifndef DETOURMODKIT_TESTS_FIXTURES_HOOK_FIXTURE_HPP
#define DETOURMODKIT_TESTS_FIXTURES_HOOK_FIXTURE_HPP

/**
 * @file hook_fixture.hpp
 * @brief The hook targets and test helpers that several hook test files share.
 * @details hook_fixture.cpp defines each target that this header declares. docs/design/testing.md owns the rule under
 *          "A split suite shares one fixture header".
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/hook.hpp"
#include "internal/hook_publication.hpp"
#include "fixtures/proof_section.hpp"
#include "fixtures/scratch_page.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

namespace dmk_test::hook_fixture
{
    using DetourModKit::Address;
    using DetourModKit::Result;
    using DetourModKit::hook::Hook;
    using DetourModKit::hook::inline_at;
    using DetourModKit::hook::InlineRequest;
    using DetourModKit::hook::is_target_hooked;
    using DetourModKit::hook::VmtHook;
    using dmk_test::call_unfolded;

    DMK_PROOF_TARGET int echo(int x);
    DMK_PROOF_TARGET int real_hook_target_add(int a, int b);
    DMK_PROOF_TARGET int real_hook_target_mul(int a, int b);
    DMK_PROOF_TARGET int leak_target_inline(int x);
    DMK_PROOF_TARGET int leak_target_disengaged(int x);
    DMK_PROOF_TARGET int leak_target_layered(int a, int b);
    DMK_PROOF_TARGET int leak_target_ledger_sync(int a, int b);
    DMK_PROOF_TARGET int leak_target_retained_id(int a, int b);
    DMK_PROOF_TARGET int leak_target_retained_newer(int a, int b);
    DMK_PROOF_TARGET int leak_target_retained_conflict(int a, int b);
    DMK_PROOF_TARGET int leak_target_release_booked(int a, int b);
    DMK_PROOF_TARGET int leak_target_release_disabled(int a, int b);
    DMK_PROOF_TARGET int leak_target_retained_strict(int a, int b);
    DMK_PROOF_TARGET int ledger_commit_failure_target(int a, int b);

    inline std::atomic<int> s_real_detour_calls{0};

    DMK_TEST_NOINLINE inline int real_hook_detour_add(int a, int b)
    {
        s_real_detour_calls.fetch_add(1, std::memory_order_relaxed);
        return a + b + 1000;
    }

    using EchoFn = int (*)(int);

    /** @brief Adds a distinct marker while the trampoline retains the unmodified result. */
    inline int echo_detour(int x)
    {
        return x + 100;
    }

    /** @brief Uses the integer address boundary because a function pointer does not convert to void*. */
    template <class Fn> [[nodiscard]] Address addr_of(Fn *fn) noexcept
    {
        return Address{reinterpret_cast<std::uintptr_t>(fn)};
    }

    /// Copies the first bytes of a function's entry, the span an inline patch overwrites.
    template <class Fn> [[nodiscard]] std::array<std::uint8_t, 16> entry_bytes(Fn *fn) noexcept
    {
        std::array<std::uint8_t, 16> bytes{};
        std::memcpy(bytes.data(), reinterpret_cast<const void *>(fn), bytes.size());
        return bytes;
    }

    /// A pin whose detour stays reachable books here.
    [[nodiscard]] inline std::size_t hook_manager_leaks() noexcept
    {
        return DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookManager);
    }

    /// A retired layer that keeps backend storage while no path reaches its detour books here.
    [[nodiscard]] inline std::size_t hook_residue_leaks() noexcept
    {
        return DetourModKit::diagnostics::intentional_leak_count(DetourModKit::diagnostics::LeakSubsystem::HookResidue);
    }

    // Synthetic prologue targets live on a dmk_test::ScratchPage, not in a static array. scratch_page.hpp owns the
    // reason.
    inline void noop_detour() noexcept {}

    inline constexpr int LEADING_CALL_CALLEE_VALUE = 0x00C0FFEE;
    inline constexpr int LEADING_CALL_DETOUR_VALUE = 0x00BADA55;

    inline int leading_call_detour() noexcept
    {
        return LEADING_CALL_DETOUR_VALUE;
    }

    inline Result<Hook> try_install_at(std::uintptr_t target, const char *name)
    {
        return inline_at(
            InlineRequest{
                .name = name,
                .target = Address{target},
            },
            reinterpret_cast<void (*)()>(&noop_detour)
        );
    }

    /**
     * @brief Plants `mov eax, 1; ret` at offset zero with enough space for either patch form.
     * @param page The executable page that owns the target.
     */
    inline void plant_leaf_function(dmk_test::ScratchPage &page) noexcept
    {
        page.put(0, {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3});
        FlushInstructionCache(GetCurrentProcess(), page.base(), dmk_test::ScratchPage::PAGE_SIZE);
    }

    /**
     * @brief Returns a scratch page with no inherited ledger record.
     * @details Retention prevents address reuse from a rejected page. A ledger-free address isolates foreign-JMP
     *          classification from the earlier same-kit check.
     * @param retained Owns every candidate, including rejected pages. The returned pointer needs this owner to stay
     * live.
     * @return The first ledger-free page, or nullptr after allocation failure or 16 inherited records.
     */
    inline dmk_test::ScratchPage *
    acquire_ledger_free_page(std::vector<std::unique_ptr<dmk_test::ScratchPage>> &retained)
    {
        for (int attempt = 0; attempt < 16; ++attempt)
        {
            auto candidate = std::make_unique<dmk_test::ScratchPage>();
            if (!candidate->ok())
            {
                return nullptr;
            }
            const bool inherited_record = is_target_hooked(Address{candidate->addr(0)});
            dmk_test::ScratchPage *const raw = candidate.get();
            retained.push_back(std::move(candidate));
            if (!inherited_record)
            {
                return raw;
            }
        }
        return nullptr;
    }

    class VmtTestInterface
    {
    public:
        virtual ~VmtTestInterface() = default;
        virtual int compute(int a, int b) = 0;
        virtual int transform(int x) = 0;
    };

    class VmtTestTarget : public VmtTestInterface
    {
    public:
        int compute(int a, int b) override { return a + b; }
        int transform(int x) override { return x * 2; }
    };

// The Win64 method ABI passes this in rcx. Slot indices exclude the ABI header but include destructor entries.
// MinGW emits complete and deleting destructor slots before compute. MSVC emits one slot, so its method indices
// differ by one.
#if defined(_MSC_VER)
    inline constexpr std::size_t VMT_COMPUTE_INDEX = 1;
    inline constexpr std::size_t VMT_TRANSFORM_INDEX = 2;
#else
    inline constexpr std::size_t VMT_COMPUTE_INDEX = 2;
    inline constexpr std::size_t VMT_TRANSFORM_INDEX = 3;
#endif

    using VmtComputeFn = int (*)(void *self, int a, int b);

    // The detours reach the original virtual method through the handle, so the fixtures publish the live VmtHook* the
    // way the inline-hook detours publish their Hook*. A null handle means "unhooked", so the detour falls back to a
    // plain marker rather than dereferencing a stale pointer.
    inline VmtHook *s_method_vmt = nullptr;

    class MethodVmtScope
    {
    public:
        explicit MethodVmtScope(VmtHook &hook) noexcept;

        ~MethodVmtScope() noexcept;

        MethodVmtScope(const MethodVmtScope &) = delete;
        MethodVmtScope &operator=(const MethodVmtScope &) = delete;
        MethodVmtScope(MethodVmtScope &&) = delete;
        MethodVmtScope &operator=(MethodVmtScope &&) = delete;

    private:
        VmtHook *m_previous;
    };

    inline MethodVmtScope::MethodVmtScope(VmtHook &hook) noexcept : m_previous(s_method_vmt)
    {
        s_method_vmt = &hook;
    }

    inline MethodVmtScope::~MethodVmtScope() noexcept
    {
        s_method_vmt = m_previous;
    }

    // Hooked compute: original(this, a, b) + 1000.
    inline int vmt_detour_compute(void *self, int a, int b)
    {
        if (s_method_vmt == nullptr)
        {
            return -1;
        }
        const VmtComputeFn original = s_method_vmt->original<VmtComputeFn>(VMT_COMPUTE_INDEX);
        if (original == nullptr)
        {
            return -1;
        }
        return original(self, a, b) + 1000;
    }

    /** @brief Forces vtable dispatch through a noinline base-pointer boundary. */
    DMK_TEST_NOINLINE inline int dispatch_compute(VmtTestInterface *object, int a, int b)
    {
        return object->compute(a, b);
    }

} // namespace dmk_test::hook_fixture

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    extern void (*g_hook_publish_probe)(HookPublishStep);

    // Mirrors src/internal/hook_backend.hpp, which this binary cannot include because it names the backend headers.
    enum class CountedDrainStage : std::uint8_t
    {
        AfterFirstPass,
        BetweenCounterReads,
        AfterCounterReads,
    };

    extern void (*g_counted_drain_probe)(CountedDrainStage) noexcept;
#endif
} // namespace DetourModKit::detail

namespace dmk_test::hook_fixture
{
    class HookPublishProbeScope
    {
    public:
        explicit HookPublishProbeScope(void (*probe)(DetourModKit::detail::HookPublishStep)) noexcept
            : m_previous_probe(DetourModKit::detail::g_hook_publish_probe)
        {
            DetourModKit::detail::g_hook_publish_probe = probe;
        }
        ~HookPublishProbeScope() noexcept { DetourModKit::detail::g_hook_publish_probe = m_previous_probe; }
        HookPublishProbeScope(const HookPublishProbeScope &) = delete;
        HookPublishProbeScope &operator=(const HookPublishProbeScope &) = delete;

    private:
        void (*m_previous_probe)(DetourModKit::detail::HookPublishStep){nullptr};
    };

#if defined(DMK_ENABLE_TEST_SEAMS)
    /// Installs @p probe as the counted drain probe for the scope and restores the prior probe.
    class CountedDrainProbeScope
    {
    public:
        explicit CountedDrainProbeScope(void (*probe)(DetourModKit::detail::CountedDrainStage) noexcept) noexcept
            : m_previous(DetourModKit::detail::g_counted_drain_probe)
        {
            DetourModKit::detail::g_counted_drain_probe = probe;
        }
        ~CountedDrainProbeScope() noexcept { DetourModKit::detail::g_counted_drain_probe = m_previous; }
        CountedDrainProbeScope(const CountedDrainProbeScope &) = delete;
        CountedDrainProbeScope &operator=(const CountedDrainProbeScope &) = delete;
        CountedDrainProbeScope(CountedDrainProbeScope &&) = delete;
        CountedDrainProbeScope &operator=(CountedDrainProbeScope &&) = delete;

    private:
        void (*m_previous)(DetourModKit::detail::CountedDrainStage) noexcept;
    };
#endif

    // Offsets are spaced well past the longest body so no case can decode into its neighbour. The page is prefilled
    // 0xCC, which also terminates the slot walk at the first unwritten offset.
    struct SlotBodyPage
    {
        dmk_test::ScratchPage page;

        static constexpr std::size_t INT3 = 0x000;
        static constexpr std::size_t RET = 0x040;
        static constexpr std::size_t PROLOGUE = 0x080;

        SlotBodyPage() noexcept
        {
            if (!page.ok())
            {
                return;
            }
            page.put(INT3, {0xCC, 0xCC, 0xC3, 0x90});
            page.put(RET, {0xC3, 0x90, 0x90, 0x90});
            // First byte 0x48 (REX.W prefix opening a standard x64 prologue, here sub rsp, 0x28): the decoder must
            // classify the slot as a function body.
            page.put(PROLOGUE, {0x48, 0x83, 0xEC, 0x28, 0xC3, 0x90, 0x90, 0x90});
        }

        [[nodiscard]] void *at(std::size_t offset) const noexcept
        {
            return reinterpret_cast<void *>(page.addr(offset));
        }
    };

    /** @brief Shares immutable body bytes across cases without repeated page allocations. */
    inline const SlotBodyPage &slot_bodies()
    {
        static const SlotBodyPage bodies;
        return bodies;
    }

} // namespace dmk_test::hook_fixture

namespace dmk_test::hook_fixture
{
    /// The bound of every wait on a parked call, so a failed premise cannot wedge the shared unit binary.
    inline constexpr std::chrono::seconds PARK_BOUND{10};
    /// The delta that @ref parked_detour adds to the result of its trampoline.
    inline constexpr int PARKED_DELTA = 0x40000;

    /// The state of one parked detour. Each Case value of @ref park_signals belongs to one test case of the binary.
    struct ParkSignals
    {
        std::atomic<bool> armed{false};
        std::atomic<bool> reached{false};
        std::atomic<bool> released{false};
        /// The function that the detour forwards to, usually its trampoline.
        std::atomic<EchoFn> next{nullptr};
    };

    template <int Case> inline ParkSignals park_signals{};

    /**
     * @brief A counted detour whose next armed call waits inside the detour until its release or @ref PARK_BOUND.
     * @details Every other call forwards at once. The result adds @ref PARKED_DELTA to the result of the trampoline.
     */
    template <int Case> int parked_detour(int value) noexcept
    {
        ParkSignals &signals = park_signals<Case>;
        if (signals.armed.exchange(false, std::memory_order_acq_rel))
        {
            signals.reached.store(true, std::memory_order_release);
            const auto deadline = std::chrono::steady_clock::now() + PARK_BOUND;
            while (!signals.released.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::yield();
            }
        }
        return call_unfolded(signals.next.load(std::memory_order_acquire), value) + PARKED_DELTA;
    }

    /**
     * @brief Runs one call of a hooked target on its own thread, and the armed @ref parked_detour parks the call.
     * @details The destructor releases the call and joins the thread on every exit path.
     */
    class ParkedCall
    {
    public:
        ParkedCall(ParkSignals &signals, EchoFn target, int value) : m_signals(signals)
        {
            m_signals.reached.store(false, std::memory_order_release);
            m_signals.released.store(false, std::memory_order_release);
            m_signals.armed.store(true, std::memory_order_release);
            m_thread = std::jthread([this, target, value]
                                    { m_result.store(call_unfolded(target, value), std::memory_order_release); });
        }

        ~ParkedCall() noexcept { m_signals.released.store(true, std::memory_order_release); }

        ParkedCall(const ParkedCall &) = delete;
        ParkedCall &operator=(const ParkedCall &) = delete;
        ParkedCall(ParkedCall &&) = delete;
        ParkedCall &operator=(ParkedCall &&) = delete;

        /// Waits up to @ref PARK_BOUND for the call to reach the detour and reports whether it did.
        [[nodiscard]] bool wait_until_parked() const noexcept
        {
            const auto deadline = std::chrono::steady_clock::now() + PARK_BOUND;
            while (!m_signals.reached.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
            return m_signals.reached.load(std::memory_order_acquire);
        }

        /// Releases the call, joins its thread, and returns the result of the call.
        int release_and_join()
        {
            m_signals.released.store(true, std::memory_order_release);
            if (m_thread.joinable())
            {
                m_thread.join();
            }
            return m_result.load(std::memory_order_acquire);
        }

    private:
        ParkSignals &m_signals;
        std::atomic<int> m_result{0};
        // Declared last, so the member teardown joins the thread before the result goes away.
        std::jthread m_thread;
    };

    /**
     * @brief A thread that never runs. It starts suspended with its instruction pointer at one address.
     * @details An idle pass reads the context of each thread, so the thread stands for a call stopped at that address.
     *          The destructor terminates it.
     */
    class SuspendedThreadAt
    {
    public:
        explicit SuspendedThreadAt(void *address) noexcept
        {
            m_thread = CreateThread(nullptr, 0, &never_runs, nullptr, CREATE_SUSPENDED, nullptr);
            if (m_thread == nullptr)
            {
                return;
            }
            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(m_thread, &context) == FALSE)
            {
                return;
            }
            context.Rip = reinterpret_cast<DWORD64>(address);
            if (SetThreadContext(m_thread, &context) == FALSE)
            {
                return;
            }
            CONTEXT check{};
            check.ContextFlags = CONTEXT_CONTROL;
            m_ready = GetThreadContext(m_thread, &check) != FALSE && check.Rip == context.Rip;
        }

        ~SuspendedThreadAt() noexcept { terminate(); }

        SuspendedThreadAt(const SuspendedThreadAt &) = delete;
        SuspendedThreadAt &operator=(const SuspendedThreadAt &) = delete;
        SuspendedThreadAt(SuspendedThreadAt &&) = delete;
        SuspendedThreadAt &operator=(SuspendedThreadAt &&) = delete;

        /// Reports whether the thread exists with the requested instruction pointer.
        [[nodiscard]] bool ready() const noexcept { return m_ready; }

        /// Ends the thread before it runs.
        void terminate() noexcept
        {
            if (m_thread == nullptr)
            {
                return;
            }
            (void)TerminateThread(m_thread, 0);
            (void)WaitForSingleObject(m_thread, static_cast<DWORD>(PARK_BOUND.count() * 1000));
            (void)CloseHandle(m_thread);
            m_thread = nullptr;
        }

    private:
        static DWORD WINAPI never_runs(void *) noexcept { return 0; }

        HANDLE m_thread{nullptr};
        bool m_ready{false};
    };
} // namespace dmk_test::hook_fixture

#endif // DETOURMODKIT_TESTS_FIXTURES_HOOK_FIXTURE_HPP
