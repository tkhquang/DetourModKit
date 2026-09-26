/**
 * @file test_trap_protect.cpp
 * @brief Verifies per-region restoration in backend protection transactions.
 */

#include <gtest/gtest.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "DetourModKit/address.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <thread>

// The backend bridge header src/internal/hook_backend.hpp is a confined backend island
// (scripts/check_header_hygiene.py). Its <safetyhook.hpp> include does not reach test TUs, so this TU redeclares the
// seams it drives.
namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
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
    [[nodiscard]] std::size_t backend_trap_protect_calls_for_test() noexcept;
    void set_backend_trap_change_failure_target_for_test(void *segment_address) noexcept;
    void set_backend_trap_segment_restore_failure_target_for_test(void *segment_address) noexcept;
    [[nodiscard]] std::size_t backend_trap_restore_trace_size_for_test() noexcept;
    [[nodiscard]] void *backend_trap_restore_trace_address_for_test(std::size_t index) noexcept;
    [[nodiscard]] void *backend_non_executable_transaction_marker_for_test() noexcept;
#endif
} // namespace DetourModKit::detail

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace
{
    using DetourModKit::detail::TrapTransactionOutcome;

    constexpr std::size_t PAGE = 0x1000;
    constexpr std::size_t PATCH_LEN = 6;

    [[nodiscard]] DWORD protection_of(const void *address) noexcept
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQuery(address, &mbi, sizeof(mbi)) != sizeof(mbi))
        {
            return 0;
        }
        return mbi.Protect;
    }

    class TwoRegionReservation
    {
    public:
        TwoRegionReservation() noexcept
        {
            m_base = static_cast<std::uint8_t *>(::VirtualAlloc(nullptr, 2 * PAGE, MEM_RESERVE, PAGE_NOACCESS));
            if (m_base == nullptr)
            {
                return;
            }
            const bool committed = ::VirtualAlloc(m_base, PAGE, MEM_COMMIT, PAGE_EXECUTE_READWRITE) != nullptr &&
                                   ::VirtualAlloc(m_base + PAGE, PAGE, MEM_COMMIT, PAGE_EXECUTE_READWRITE) != nullptr;
            if (!committed)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
                m_base = nullptr;
                return;
            }
            std::uint8_t *const seam = m_base + PAGE - (PATCH_LEN - 1);
            const std::uint8_t prologue[PATCH_LEN] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
            std::memcpy(seam, prologue, PATCH_LEN);

            DWORD previous = 0;
            m_ok = ::VirtualProtect(m_base, PAGE, PAGE_EXECUTE_READ, &previous) != FALSE;
        }

        ~TwoRegionReservation() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        TwoRegionReservation(const TwoRegionReservation &) = delete;
        TwoRegionReservation &operator=(const TwoRegionReservation &) = delete;
        TwoRegionReservation(TwoRegionReservation &&) = delete;
        TwoRegionReservation &operator=(TwoRegionReservation &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_ok; }
        [[nodiscard]] std::uint8_t *first_page() const noexcept { return m_base; }
        [[nodiscard]] std::uint8_t *second_page() const noexcept { return m_base + PAGE; }
        [[nodiscard]] std::uint8_t *straddle() const noexcept { return m_base + PAGE - (PATCH_LEN - 1); }

    private:
        std::uint8_t *m_base = nullptr;
        bool m_ok = false;
    };

    class ScratchTrampoline
    {
    public:
        ScratchTrampoline() noexcept
        {
            m_base = static_cast<std::uint8_t *>(
                ::VirtualAlloc(nullptr, PAGE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            );
        }
        ~ScratchTrampoline() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }
        ScratchTrampoline(const ScratchTrampoline &) = delete;
        ScratchTrampoline &operator=(const ScratchTrampoline &) = delete;
        ScratchTrampoline(ScratchTrampoline &&) = delete;
        ScratchTrampoline &operator=(ScratchTrampoline &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uint8_t *base() const noexcept { return m_base; }

    private:
        std::uint8_t *m_base = nullptr;
    };

    struct SeamGuard
    {
        ~SeamGuard() noexcept
        {
            DetourModKit::detail::set_backend_trap_change_failure_target_for_test(nullptr);
            DetourModKit::detail::set_backend_trap_segment_restore_failure_target_for_test(nullptr);
        }
    };

    [[nodiscard]] std::array<std::uint8_t *, 3>
    ordered_segment_starts(const TwoRegionReservation &span, const ScratchTrampoline &trampoline) noexcept
    {
        std::array<std::uint8_t *, 3> starts{span.first_page(), span.second_page(), trampoline.base()};
        std::ranges::sort(starts, std::less<std::uint8_t *>{});
        return starts;
    }

    [[nodiscard]] DWORD original_protection(
        const TwoRegionReservation &span,
        const ScratchTrampoline &trampoline,
        const std::uint8_t *address
    ) noexcept
    {
        if (address == span.first_page())
        {
            return PAGE_EXECUTE_READ;
        }
        if (address == span.second_page() || address == trampoline.base())
        {
            return PAGE_EXECUTE_READWRITE;
        }
        return 0;
    }
} // namespace

TEST(TrapProtect, RestoresEachCrossedRegionToItsOwnPriorProtection)
{
    TwoRegionReservation span;
    ASSERT_TRUE(span.ok());
    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    const SeamGuard guard;

    ASSERT_EQ(protection_of(span.first_page()), static_cast<DWORD>(PAGE_EXECUTE_READ));
    ASSERT_EQ(protection_of(span.second_page()), static_cast<DWORD>(PAGE_EXECUTE_READWRITE));

    const TrapTransactionOutcome outcome = DetourModKit::detail::drive_backend_trap_transaction_for_test(
        span.straddle(),
        trampoline.base(),
        PATCH_LEN,
        [&]
        {
            EXPECT_EQ(protection_of(span.first_page()), static_cast<DWORD>(PAGE_READWRITE));
            EXPECT_EQ(protection_of(span.second_page()), static_cast<DWORD>(PAGE_READWRITE));
            EXPECT_EQ(protection_of(trampoline.base()), static_cast<DWORD>(PAGE_READWRITE));
        }
    );

    EXPECT_EQ(outcome, TrapTransactionOutcome::Restored);
    EXPECT_EQ(protection_of(span.first_page()), static_cast<DWORD>(PAGE_EXECUTE_READ));
    EXPECT_EQ(protection_of(span.second_page()), static_cast<DWORD>(PAGE_EXECUTE_READWRITE));
    EXPECT_EQ(protection_of(trampoline.base()), static_cast<DWORD>(PAGE_EXECUTE_READWRITE));
}

TEST(TrapProtect, ThrownBodyStillRestoresEachCrossedRegion)
{
    TwoRegionReservation span;
    ASSERT_TRUE(span.ok());
    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    const SeamGuard guard;

    const TrapTransactionOutcome outcome = DetourModKit::detail::drive_backend_trap_transaction_for_test(
        span.straddle(),
        trampoline.base(),
        PATCH_LEN,
        [] { throw std::runtime_error{"transaction body"}; }
    );

    EXPECT_EQ(outcome, TrapTransactionOutcome::Threw);
    EXPECT_EQ(protection_of(span.first_page()), static_cast<DWORD>(PAGE_EXECUTE_READ));
    EXPECT_EQ(protection_of(span.second_page()), static_cast<DWORD>(PAGE_EXECUTE_READWRITE));
    EXPECT_EQ(protection_of(trampoline.base()), static_cast<DWORD>(PAGE_EXECUTE_READWRITE));
}

TEST(TrapProtect, LaterChangeFailureRollsBackEarlierSegment)
{
    TwoRegionReservation span;
    ASSERT_TRUE(span.ok());
    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    const SeamGuard guard;

    const auto starts = ordered_segment_starts(span, trampoline);
    DetourModKit::detail::set_backend_trap_change_failure_target_for_test(starts[2]);
    const TrapTransactionOutcome outcome = DetourModKit::detail::drive_backend_trap_transaction_for_test(
        span.straddle(),
        trampoline.base(),
        PATCH_LEN,
        [] {}
    );

    EXPECT_EQ(outcome, TrapTransactionOutcome::ReportedFailure);
    ASSERT_EQ(DetourModKit::detail::backend_trap_restore_trace_size_for_test(), 2U);
    EXPECT_EQ(DetourModKit::detail::backend_trap_restore_trace_address_for_test(0), starts[1]);
    EXPECT_EQ(DetourModKit::detail::backend_trap_restore_trace_address_for_test(1), starts[0]);
    EXPECT_EQ(protection_of(span.first_page()), static_cast<DWORD>(PAGE_EXECUTE_READ));
    EXPECT_EQ(protection_of(span.second_page()), static_cast<DWORD>(PAGE_EXECUTE_READWRITE));
    EXPECT_EQ(protection_of(trampoline.base()), static_cast<DWORD>(PAGE_EXECUTE_READWRITE));
}

TEST(TrapProtect, RestoreFailureTakesPriorityAndLaterRestoresContinue)
{
    TwoRegionReservation span;
    ASSERT_TRUE(span.ok());
    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    const SeamGuard guard;

    const auto starts = ordered_segment_starts(span, trampoline);
    DetourModKit::detail::set_backend_trap_segment_restore_failure_target_for_test(starts[1]);
    const TrapTransactionOutcome outcome = DetourModKit::detail::drive_backend_trap_transaction_for_test(
        span.straddle(),
        trampoline.base(),
        PATCH_LEN,
        [] { throw std::runtime_error{"transaction body"}; }
    );

    EXPECT_EQ(outcome, TrapTransactionOutcome::ReportedFailure);
    ASSERT_EQ(DetourModKit::detail::backend_trap_restore_trace_size_for_test(), 3U);
    EXPECT_EQ(DetourModKit::detail::backend_trap_restore_trace_address_for_test(0), starts[2]);
    EXPECT_EQ(DetourModKit::detail::backend_trap_restore_trace_address_for_test(1), starts[1]);
    EXPECT_EQ(DetourModKit::detail::backend_trap_restore_trace_address_for_test(2), starts[0]);
    EXPECT_EQ(protection_of(starts[2]), original_protection(span, trampoline, starts[2]));
    EXPECT_EQ(protection_of(starts[1]), static_cast<DWORD>(PAGE_READWRITE));
    EXPECT_EQ(protection_of(starts[0]), original_protection(span, trampoline, starts[0]));
}

TEST(TrapProtect, KeepsVirtualProtectPageExecutableWhenItIsTheDestination)
{
    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    const SeamGuard guard;

    auto *const virtual_protect = reinterpret_cast<std::uint8_t *>(&::VirtualProtect);
    const DWORD original = protection_of(virtual_protect);
    ASSERT_NE(original, 0U);

    constexpr DWORD executable_mask =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    const TrapTransactionOutcome outcome = DetourModKit::detail::drive_backend_trap_transaction_for_test(
        trampoline.base(),
        virtual_protect,
        1,
        [&] { EXPECT_NE(protection_of(virtual_protect) & executable_mask, 0U); }
    );

    EXPECT_EQ(outcome, TrapTransactionOutcome::Restored);
    EXPECT_EQ(protection_of(virtual_protect), original);
}

TEST(TrapProtect, SharedPageChangesAndRestoresOnce)
{
    TwoRegionReservation span;
    ASSERT_TRUE(span.ok());
    const SeamGuard guard;

    const std::size_t calls_before = DetourModKit::detail::backend_trap_protect_calls_for_test();
    const TrapTransactionOutcome outcome = DetourModKit::detail::drive_backend_trap_transaction_for_test(
        span.first_page() + 32,
        span.first_page() + 64,
        PATCH_LEN,
        [] {}
    );
    const std::size_t calls_after = DetourModKit::detail::backend_trap_protect_calls_for_test();

    EXPECT_EQ(outcome, TrapTransactionOutcome::Restored);
    EXPECT_EQ(calls_after - calls_before, 2U);
    EXPECT_EQ(protection_of(span.first_page()), static_cast<DWORD>(PAGE_EXECUTE_READ));
}

TEST(TrapProtect, RefusesMultiBytePatchWhenTheTransactionCodePageMustStayExecutable)
{
    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    const SeamGuard guard;
    void *const marker = DetourModKit::detail::backend_non_executable_transaction_marker_for_test();
    ASSERT_NE(marker, nullptr);

    bool mutation_ran = false;
    const std::size_t calls_before = DetourModKit::detail::backend_trap_protect_calls_for_test();
    const TrapTransactionOutcome outcome = DetourModKit::detail::drive_backend_trap_transaction_for_test(
        marker,
        trampoline.base(),
        PATCH_LEN,
        [&] { mutation_ran = true; }
    );
    const std::size_t calls_after = DetourModKit::detail::backend_trap_protect_calls_for_test();

    EXPECT_EQ(outcome, TrapTransactionOutcome::ReportedFailure);
    EXPECT_FALSE(mutation_ran);
    EXPECT_EQ(calls_after, calls_before);
}

TEST(TrapProtect, PreservesSingleByteTransactionOnTheRequiredCodePage)
{
    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    const SeamGuard guard;
    void *const marker = DetourModKit::detail::backend_non_executable_transaction_marker_for_test();
    ASSERT_NE(marker, nullptr);

    bool mutation_ran = false;
    const TrapTransactionOutcome outcome = DetourModKit::detail::drive_backend_trap_transaction_for_test(
        marker,
        trampoline.base(),
        1,
        [&] { mutation_ran = true; }
    );

    EXPECT_EQ(outcome, TrapTransactionOutcome::Restored);
    EXPECT_TRUE(mutation_ran);
}

TEST(TrapProtect, RefusesMultiBytePatchOnTheWindowFlushCodePages)
{
    // The backend guards the addresses its own dllimport thunks resolve to: the real kernel32 exports. Taking
    // &FlushInstructionCache in this TU yields a local jump thunk on a different page, so the guarded address is
    // resolved by name to match what trap_threads holds in required_code.
    HMODULE const kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(kernel32, nullptr);
    void *const flush_code = reinterpret_cast<void *>(::GetProcAddress(kernel32, "FlushInstructionCache"));
    void *const process_code = reinterpret_cast<void *>(::GetProcAddress(kernel32, "GetCurrentProcess"));
    ASSERT_NE(flush_code, nullptr);
    ASSERT_NE(process_code, nullptr);

    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    const SeamGuard guard;

    for (void *const window_code : {flush_code, process_code})
    {
        bool mutation_ran = false;
        const std::size_t calls_before = DetourModKit::detail::backend_trap_protect_calls_for_test();
        const TrapTransactionOutcome outcome = DetourModKit::detail::drive_backend_trap_transaction_for_test(
            window_code,
            trampoline.base(),
            PATCH_LEN,
            [&] { mutation_ran = true; }
        );
        const std::size_t calls_after = DetourModKit::detail::backend_trap_protect_calls_for_test();

        EXPECT_EQ(outcome, TrapTransactionOutcome::ReportedFailure);
        EXPECT_FALSE(mutation_ran);
        EXPECT_EQ(calls_after, calls_before);
    }
}

namespace
{
    // Opens one backend trap window over @p span and @p trampoline on a second thread. The window waits for the
    // caller's attempt flag, stays open for a further 100 ms, and records whether the caller returned meanwhile.
    class TrapWindow
    {
    public:
        TrapWindow(const TwoRegionReservation &span, const ScratchTrampoline &trampoline)
            : m_thread(
                  [this, &span, &trampoline]
                  {
                      using namespace std::chrono_literals;
                      const TrapTransactionOutcome outcome =
                          DetourModKit::detail::drive_backend_trap_transaction_for_test(
                              span.straddle(),
                              trampoline.base(),
                              PATCH_LEN,
                              [this]
                              {
                                  m_open.store(true, std::memory_order_release);
                                  for (int i = 0; i < 2000 && !m_attempted.load(std::memory_order_acquire); ++i)
                                  {
                                      std::this_thread::sleep_for(1ms);
                                  }
                                  std::this_thread::sleep_for(100ms);
                                  m_returned_inside.store(
                                      m_returned.load(std::memory_order_acquire),
                                      std::memory_order_release
                                  );
                              }
                          );
                      m_restored = outcome == TrapTransactionOutcome::Restored;
                  }
              )
        {
            while (!m_open.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        }

        ~TrapWindow() noexcept
        {
            if (m_thread.joinable())
            {
                m_thread.join();
            }
        }

        TrapWindow(const TrapWindow &) = delete;
        TrapWindow &operator=(const TrapWindow &) = delete;

        /// Runs @p operation while the window is open and joins the window afterwards.
        template <class Operation> auto run(Operation &&operation)
        {
            m_attempted.store(true, std::memory_order_release);
            auto result = operation();
            m_returned.store(true, std::memory_order_release);
            m_thread.join();
            return result;
        }

        [[nodiscard]] bool returned_inside_window() const noexcept
        {
            return m_returned_inside.load(std::memory_order_acquire);
        }

        [[nodiscard]] bool restored() const noexcept { return m_restored; }

    private:
        std::atomic<bool> m_open{false};
        std::atomic<bool> m_attempted{false};
        std::atomic<bool> m_returned{false};
        std::atomic<bool> m_returned_inside{false};
        bool m_restored{false};
        std::thread m_thread;
    };
} // namespace

// A backend trap window holds its pages at PAGE_READWRITE under the process coordinator. A protection capture inside
// that window records the transient value as the original (`[B-18]`). Its restore then leaves the page non-executable
// after the backend restores the real protection. The capture must wait for the window to close.
TEST(TrapProtect, ProtectGuardWaitsForTheBackendTrapWindow)
{
    TwoRegionReservation span;
    ASSERT_TRUE(span.ok());
    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    const SeamGuard guard;

    TrapWindow window(span, trampoline);
    DetourModKit::Result<DetourModKit::memory::ProtectGuard> made = window.run(
        [&]
        {
            return DetourModKit::memory::ProtectGuard::make(
                DetourModKit::Region{DetourModKit::Address{span.first_page()}, PAGE},
                DetourModKit::Prot::RW
            );
        }
    );
    EXPECT_TRUE(window.restored());
    EXPECT_FALSE(window.returned_inside_window());
    ASSERT_TRUE(made.has_value()) << made.error().message();
    EXPECT_EQ(protection_of(span.first_page()), static_cast<DWORD>(PAGE_READWRITE));
    {
        const DetourModKit::memory::ProtectGuard release = std::move(*made);
    }
    EXPECT_EQ(protection_of(span.first_page()), static_cast<DWORD>(PAGE_EXECUTE_READ));
}

// The patch_code slow path changes protection through the same capture. Its target is a page outside the window, so
// the guarded fast path faults and the slow path meets the coordinator that the window holds.
TEST(TrapProtect, PatchCodeSlowPathWaitsForTheBackendTrapWindow)
{
    TwoRegionReservation span;
    ASSERT_TRUE(span.ok());
    ScratchTrampoline trampoline;
    ASSERT_TRUE(trampoline.ok());
    ScratchTrampoline target;
    ASSERT_TRUE(target.ok());
    DWORD previous = 0;
    ASSERT_NE(::VirtualProtect(target.base(), PAGE, PAGE_EXECUTE_READ, &previous), FALSE);
    const SeamGuard guard;

    TrapWindow window(span, trampoline);
    const DetourModKit::Result<void> patched = window.run(
        [&]
        {
            const std::array<std::byte, 1> ret{std::byte{0xC3}};
            return DetourModKit::memory::patch_code(DetourModKit::Address{target.base()}, ret);
        }
    );
    EXPECT_TRUE(window.restored());
    EXPECT_FALSE(window.returned_inside_window());
    ASSERT_TRUE(patched.has_value()) << patched.error().message();
    EXPECT_EQ(*target.base(), 0xC3);
    EXPECT_EQ(protection_of(target.base()), static_cast<DWORD>(PAGE_EXECUTE_READ));
}
#endif // DMK_ENABLE_TEST_SEAMS
