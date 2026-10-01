#include "internal/xinput_raw_scope.hpp"
#include "test_alloc_probe.hpp"

#include <gtest/gtest.h>
#include <windows.h>

#include <atomic>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cwchar>
#include <limits>
#include <memory>
#include <string_view>
#include <thread>

namespace
{
    using DetourModKit::detail::XInputConsumeScope;
    using DetourModKit::detail::XInputRawScope;
    using DetourModKit::detail::XInputRawScopeFailure;

    const auto s_close_handle = [](void *handle) noexcept -> void { ::CloseHandle(handle); };
    using NativeHandle = std::unique_ptr<void, decltype(s_close_handle)>;

    void run_scope_case_in_fresh_process(const wchar_t *filter)
    {
        std::array<wchar_t, 4096> executable{};
        ASSERT_NE(::GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size())), 0u);
        std::array<wchar_t, 8192> command{};
        ASSERT_GT(
            std::swprintf(command.data(), command.size(), L"\"%ls\" --gtest_filter=%ls", executable.data(), filter),
            0
        );
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        ASSERT_TRUE(
            ::CreateProcessW(
                nullptr,
                command.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &startup,
                &process
            )
        );
        const NativeHandle process_handle{process.hProcess, s_close_handle};
        const NativeHandle thread_handle{process.hThread, s_close_handle};
        const DWORD waited = ::WaitForSingleObject(process_handle.get(), 15000);
        if (waited != WAIT_OBJECT_0)
        {
            ::TerminateProcess(process_handle.get(), 1);
            ::WaitForSingleObject(process_handle.get(), 1000);
        }
        ASSERT_EQ(waited, static_cast<DWORD>(WAIT_OBJECT_0));
        DWORD exit_code = 1;
        ASSERT_TRUE(::GetExitCodeProcess(process_handle.get(), &exit_code));
        EXPECT_EQ(exit_code, 0u);
    }

    void run_current_scope_case_in_fresh_process()
    {
        const auto *const info = ::testing::UnitTest::GetInstance()->current_test_info();
        ASSERT_NE(info, nullptr);
        std::array<wchar_t, 512> filter{};
        std::size_t length = 0;
        const auto append = [&filter, &length](const char *text) -> void
        {
            for (; *text != '\0'; ++text)
            {
                ASSERT_LT(length + 1, filter.size());
                filter[length++] = static_cast<wchar_t>(static_cast<unsigned char>(*text));
            }
        };
        append(info->test_suite_name());
        ASSERT_LT(length + 1, filter.size());
        filter[length++] = L'.';
        append(info->name());
        run_scope_case_in_fresh_process(filter.data());
    }

    [[nodiscard]] bool delegate_scope_case_if_owned()
    {
        using namespace DetourModKit::detail;
        const DWORD raw_index = xinput_raw_scope_index_for_test();
        if (raw_index == TLS_OUT_OF_INDEXES)
        {
            return false;
        }
        const auto *const info = ::testing::UnitTest::GetInstance()->current_test_info();
        const auto raw_filter = GTEST_FLAG_GET(filter);
        const std::string_view filter{raw_filter};
        const std::string_view suite{info->test_suite_name()};
        const std::string_view name{info->name()};
        if (filter.size() == suite.size() + name.size() + 1 && filter.starts_with(suite) &&
            filter[suite.size()] == '.' && filter.ends_with(name))
        {
            ADD_FAILURE() << "A fresh scope proof process starts without an XInput TLS owner";
            return true;
        }
        const DWORD identity_index = xinput_consume_identity_index_for_test();
        const DWORD metadata_index = xinput_consume_metadata_index_for_test();
        const auto owners = xinput_raw_scope_owners_for_test();
        const auto descriptor = xinput_raw_scope_descriptor_for_test();
        const bool healthy = xinput_consume_context_healthy();
        void *const raw_value = ::TlsGetValue(raw_index);
        void *const identity_value = ::TlsGetValue(identity_index);
        void *const metadata_value = ::TlsGetValue(metadata_index);
        run_current_scope_case_in_fresh_process();
        EXPECT_EQ(xinput_raw_scope_index_for_test(), raw_index);
        EXPECT_EQ(xinput_consume_identity_index_for_test(), identity_index);
        EXPECT_EQ(xinput_consume_metadata_index_for_test(), metadata_index);
        EXPECT_EQ(xinput_raw_scope_owners_for_test(), owners);
        EXPECT_EQ(xinput_raw_scope_descriptor_for_test(), descriptor);
        EXPECT_EQ(xinput_consume_context_healthy(), healthy);
        EXPECT_EQ(::TlsGetValue(raw_index), raw_value);
        EXPECT_EQ(::TlsGetValue(identity_index), identity_value);
        EXPECT_EQ(::TlsGetValue(metadata_index), metadata_value);
        return true;
    }

    /** @brief Balances one successful owner registration. */
    class RawOwner
    {
    public:
        RawOwner() noexcept : m_reserved(DetourModKit::detail::acquire_xinput_raw_scope_owner()) {}
        ~RawOwner() noexcept { reset(); }
        RawOwner(const RawOwner &) = delete;
        RawOwner &operator=(const RawOwner &) = delete;
        RawOwner(RawOwner &&) = delete;
        RawOwner &operator=(RawOwner &&) = delete;

        [[nodiscard]] bool reserved() const noexcept { return m_reserved; }

        void reset() noexcept
        {
            if (m_reserved)
            {
                DetourModKit::detail::release_xinput_raw_scope_owner();
                m_reserved = false;
            }
        }

    private:
        bool m_reserved;
    };

    /** @brief Clears a thread-specific fault when its test span ends. */
    class RawFailure
    {
    public:
        explicit RawFailure(XInputRawScopeFailure failure) noexcept
            : m_registered(DetourModKit::detail::set_xinput_raw_scope_failure_for_test(failure))
        {
        }
        ~RawFailure() noexcept
        {
            (void)DetourModKit::detail::set_xinput_raw_scope_failure_for_test(XInputRawScopeFailure::None);
        }
        RawFailure(const RawFailure &) = delete;
        RawFailure &operator=(const RawFailure &) = delete;
        RawFailure(RawFailure &&) = delete;
        RawFailure &operator=(RawFailure &&) = delete;

        [[nodiscard]] bool registered() const noexcept { return m_registered; }

    private:
        bool m_registered;
    };
} // namespace

TEST(XInputRawScopeTest, NestedDepthPreservesLastErrorWithoutAllocations)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    {
        XInputRawScope warm;
        ASSERT_TRUE(warm.admitted());
        ASSERT_TRUE(warm.finish());
    }

    constexpr DWORD sentinel = 0xA11CE;
    constexpr DWORD provider_error = 0xBEE;
    ::SetLastError(sentinel);
    const long long allocations = dmk_test::thread_new_calls();
    bool outer_entered = false;
    bool inner_entered = false;
    bool inner_restored = false;
    bool outer_restored = false;
    bool errors_preserved = true;
    bool depths_correct = true;
    {
        XInputRawScope outer;
        outer_entered = outer.admitted();
        errors_preserved = ::GetLastError() == sentinel;
        depths_correct =
            DetourModKit::detail::xinput_raw_scope_depth_for_test() == 1 && DetourModKit::detail::is_xinput_raw_call();
        {
            XInputRawScope inner;
            inner_entered = inner.admitted();
            depths_correct = depths_correct && DetourModKit::detail::xinput_raw_scope_depth_for_test() == 2;
            ::SetLastError(provider_error);
            inner_restored = inner.finish();
            errors_preserved = errors_preserved && ::GetLastError() == provider_error;
            depths_correct = depths_correct && DetourModKit::detail::xinput_raw_scope_depth_for_test() == 1;
        }
        outer_restored = outer.finish();
        errors_preserved = errors_preserved && ::GetLastError() == provider_error;
        depths_correct = depths_correct && !DetourModKit::detail::is_xinput_raw_call();
    }
    const long long after = dmk_test::thread_new_calls();
    EXPECT_TRUE(outer_entered);
    EXPECT_TRUE(inner_entered);
    EXPECT_TRUE(inner_restored);
    EXPECT_TRUE(outer_restored);
    EXPECT_TRUE(errors_preserved);
    EXPECT_TRUE(depths_correct);
    EXPECT_EQ(after, allocations);
    EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 0);
}

TEST(XInputRawScopeTest, RawDepthStaysSpecificToTheCallingThread)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    XInputRawScope outer;
    ASSERT_TRUE(outer.admitted());
    std::atomic<bool> worker_passed{false};
    std::thread worker(
        [&worker_passed]() noexcept -> void
        {
            const bool initially_raw = DetourModKit::detail::is_xinput_raw_call();
            XInputRawScope local;
            const bool entered = local.admitted() && DetourModKit::detail::is_xinput_raw_call() &&
                                 DetourModKit::detail::xinput_raw_scope_depth_for_test() == 1;
            const bool restored = local.finish() && !DetourModKit::detail::is_xinput_raw_call();
            worker_passed.store(!initially_raw && entered && restored, std::memory_order_release);
        }
    );
    worker.join();
    EXPECT_TRUE(worker_passed.load(std::memory_order_acquire));
    EXPECT_TRUE(DetourModKit::detail::is_xinput_raw_call());
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_depth_for_test(), 1);
    EXPECT_TRUE(outer.finish());
}

TEST(XInputRawScopeTest, EntryStoreFailureRefusesTheSampleAndBalancesItsLease)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    const RawFailure failure{XInputRawScopeFailure::EntryStore};
    ASSERT_TRUE(failure.registered());
    constexpr DWORD sentinel = 0xF00D;
    ::SetLastError(sentinel);
    const XInputRawScope scope;
    EXPECT_FALSE(scope.admitted());
    EXPECT_EQ(::GetLastError(), sentinel);
    EXPECT_FALSE(DetourModKit::detail::is_xinput_raw_call());
    EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 0);
}

TEST(XInputRawScopeTest, FailedNestedEntryPreservesTheOuterDepth)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    XInputRawScope outer;
    ASSERT_TRUE(outer.admitted());
    {
        const RawFailure failure{XInputRawScopeFailure::EntryStore};
        ASSERT_TRUE(failure.registered());
        const XInputRawScope inner;
        EXPECT_FALSE(inner.admitted());
        EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_depth_for_test(), 1);
        EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 1);
    }
    EXPECT_TRUE(outer.finish());
    EXPECT_FALSE(DetourModKit::detail::is_xinput_raw_call());
}

TEST(XInputRawScopeTest, RestoreFailureReportsFailureAndRetainsNoPointer)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    const DWORD index = DetourModKit::detail::xinput_raw_scope_index_for_test();
    XInputRawScope scope;
    ASSERT_TRUE(scope.admitted());
    {
        const RawFailure failure{XInputRawScopeFailure::Restore};
        ASSERT_TRUE(failure.registered());
        constexpr DWORD provider_error = 0xC0DE;
        ::SetLastError(provider_error);
        EXPECT_FALSE(scope.finish());
        EXPECT_EQ(::GetLastError(), provider_error);
        EXPECT_FALSE(scope.finish());
        EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 0);
        EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_depth_for_test(), 1);
    }
    EXPECT_TRUE(::TlsSetValue(index, nullptr));
    EXPECT_FALSE(DetourModKit::detail::is_xinput_raw_call());
}

TEST(XInputRawScopeTest, FinalOwnerReturnsTheIndexAndRestartReusesTheDescriptor)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    ASSERT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), TLS_OUT_OF_INDEXES);
    RawOwner first;
    ASSERT_TRUE(first.reserved());
    const DWORD index = DetourModKit::detail::xinput_raw_scope_index_for_test();
    const std::array<DWORD, 3> released_indices{
        index,
        DetourModKit::detail::xinput_consume_identity_index_for_test(),
        DetourModKit::detail::xinput_consume_metadata_index_for_test(),
    };
    const auto descriptor = DetourModKit::detail::xinput_raw_scope_descriptor_for_test();
    RawOwner second;
    ASSERT_TRUE(second.reserved());
    first.reset();
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), index);
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_owners_for_test(), 1);
    second.reset();
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), TLS_OUT_OF_INDEXES);
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_owners_for_test(), 0);

    std::array<DWORD, 3> foreign_indices{};
    for (auto &foreign_index : foreign_indices)
    {
        foreign_index = ::TlsAlloc();
        ASSERT_NE(foreign_index, TLS_OUT_OF_INDEXES);
    }
    EXPECT_EQ(foreign_indices, released_indices);
    const DWORD foreign = foreign_indices[0];
    int sentinel = 7;
    const bool stored = ::TlsSetValue(foreign, &sentinel) != FALSE;
    {
        const RawOwner restarted;
        EXPECT_TRUE(restarted.reserved());
        EXPECT_NE(DetourModKit::detail::xinput_raw_scope_index_for_test(), foreign);
        EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_descriptor_for_test(), descriptor);
        EXPECT_EQ(::TlsGetValue(foreign), &sentinel);
    }
    EXPECT_TRUE(stored);
    EXPECT_EQ(foreign, index);
    for (const DWORD foreign_index : foreign_indices)
    {
        EXPECT_TRUE(::TlsFree(foreign_index));
    }
}

TEST(XInputRawScopeTest, AFinalReleaseRetainsTheIndexAcrossAnActiveScope)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    const DWORD index = DetourModKit::detail::xinput_raw_scope_index_for_test();
    XInputRawScope scope;
    ASSERT_TRUE(scope.admitted());
    owner.reset();
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), index);
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_owners_for_test(), 1);
    const XInputRawScope refused;
    EXPECT_FALSE(refused.admitted());
    EXPECT_TRUE(scope.finish());
    RawOwner recovered;
    ASSERT_TRUE(recovered.reserved());
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), index);
    recovered.reset();
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), TLS_OUT_OF_INDEXES);
}

TEST(XInputRawScopeTest, ReservationFailurePublishesNoOwnerOrIndex)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    ASSERT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), TLS_OUT_OF_INDEXES);
    const RawFailure failure{XInputRawScopeFailure::Reservation};
    ASSERT_TRUE(failure.registered());
    DWORD error = ERROR_SUCCESS;
    EXPECT_FALSE(DetourModKit::detail::acquire_xinput_raw_scope_owner(&error));
    EXPECT_EQ(error, ERROR_NOT_ENOUGH_MEMORY);
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_owners_for_test(), 0);
    const XInputRawScope scope;
    EXPECT_FALSE(scope.admitted());
}

TEST(XInputRawScopeTest, DescriptorInitializationFailurePublishesNoIndex)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    ASSERT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), TLS_OUT_OF_INDEXES);
    const RawFailure failure{XInputRawScopeFailure::DescriptorInit};
    ASSERT_TRUE(failure.registered());
    DWORD error = ERROR_SUCCESS;
    EXPECT_FALSE(DetourModKit::detail::acquire_xinput_raw_scope_owner(&error));
    EXPECT_EQ(error, ERROR_NOT_ENOUGH_MEMORY);
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), TLS_OUT_OF_INDEXES);
}

TEST(XInputRawScopeTest, AnIncompatibleDescriptorVersionRefusesAdmission)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    {
        const RawOwner initialized;
        ASSERT_TRUE(initialized.reserved());
    }
    const RawFailure failure{XInputRawScopeFailure::DescriptorVersion};
    ASSERT_TRUE(failure.registered());
    DWORD error = ERROR_SUCCESS;
    EXPECT_FALSE(DetourModKit::detail::acquire_xinput_raw_scope_owner(&error));
    EXPECT_EQ(error, ERROR_INVALID_DATA);
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), TLS_OUT_OF_INDEXES);
}

TEST(XInputRawScopeTest, DepthOverflowRefusesTheSample)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    const DWORD index = DetourModKit::detail::xinput_raw_scope_index_for_test();
    ASSERT_TRUE(::TlsSetValue(index, reinterpret_cast<void *>(std::numeric_limits<std::uintptr_t>::max())));
    const XInputRawScope scope;
    EXPECT_FALSE(scope.admitted());
    EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 0);
    EXPECT_TRUE(::TlsSetValue(index, nullptr));
}

TEST(XInputConsumeScopeTest, LowestOriginalButtonsSurviveNestedMasksWithoutAllocations)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD state = 0;
    {
        XInputConsumeScope warm{0, &state};
        ASSERT_TRUE(warm.admitted());
        WORD original = 0;
        ASSERT_TRUE(warm.original_buttons(0, original));
        ASSERT_TRUE(warm.finish());
    }
    constexpr WORD raw_buttons = 0x1100;
    constexpr DWORD provider_error = 0xD00D;
    bool correct = true;
    const long long allocations = dmk_test::thread_new_calls();
    {
        XInputConsumeScope upper{0, &state};
        correct = upper.admitted();
        {
            XInputConsumeScope lower{0, &state};
            correct = correct && lower.admitted();
            state = raw_buttons;
            ::SetLastError(provider_error);
            WORD original = 0;
            correct = correct && lower.original_buttons(state, original) && original == raw_buttons &&
                      lower.finish(static_cast<WORD>(state & ~0x0100));
            state &= static_cast<WORD>(~0x0100);
        }
        WORD original = 0;
        correct = correct && upper.original_buttons(state, original) && original == raw_buttons && upper.finish();
        if ((original & raw_buttons) == raw_buttons)
        {
            state &= static_cast<WORD>(~0x1000);
        }
        correct = correct && ::GetLastError() == provider_error;
    }
    const long long after = dmk_test::thread_new_calls();
    EXPECT_TRUE(correct);
    EXPECT_EQ(state, 0);
    EXPECT_EQ(after, allocations);
    EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 0);
    EXPECT_EQ(::TlsGetValue(DetourModKit::detail::xinput_consume_identity_index_for_test()), nullptr);
    EXPECT_EQ(::TlsGetValue(DetourModKit::detail::xinput_consume_metadata_index_for_test()), nullptr);
}

TEST(XInputConsumeScopeTest, DifferentUsersAndStateAddressesRestoreTheOuterOriginal)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD first_state = 0;
    WORD second_state = 0;
    XInputConsumeScope outer{0, &first_state};
    ASSERT_TRUE(outer.admitted());
    WORD original = 0;
    ASSERT_TRUE(outer.original_buttons(0x1100, original));
    for (DWORD user = 1; user < 4; ++user)
    {
        XInputConsumeScope different_user{user, &first_state};
        ASSERT_TRUE(different_user.admitted());
        ASSERT_TRUE(different_user.original_buttons(0x2200, original));
        EXPECT_EQ(original, 0x2200);
        ASSERT_TRUE(different_user.finish());
    }
    ASSERT_TRUE(outer.original_buttons(0x1100, original));
    EXPECT_EQ(original, 0x1100);
    {
        XInputConsumeScope different_state{0, &second_state};
        ASSERT_TRUE(different_state.admitted());
        ASSERT_TRUE(different_state.original_buttons(0x3300, original));
        EXPECT_EQ(original, 0x3300);
        ASSERT_TRUE(different_state.finish());
    }
    ASSERT_TRUE(outer.original_buttons(0x1100, original));
    EXPECT_EQ(original, 0x1100);
    EXPECT_TRUE(outer.finish());
    {
        XInputConsumeScope reused_address{0, &first_state};
        ASSERT_TRUE(reused_address.admitted());
        ASSERT_TRUE(reused_address.original_buttons(0x4400, original));
        EXPECT_EQ(original, 0x4400);
    }
}

TEST(XInputConsumeScopeTest, InvalidUsersRefuseWithoutPoisoningAnActiveContext)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD state = 0;
    XInputConsumeScope outer{0, &state};
    ASSERT_TRUE(outer.admitted());
    WORD original = 0;
    ASSERT_TRUE(outer.original_buttons(0x1100, original));
    const std::array<DWORD, 2> users{
        4,
        0xFFFFFFFFu,
    };
    for (const DWORD user : users)
    {
        ::SetLastError(0xA00A);
        XInputConsumeScope refused{user, &state};
        EXPECT_FALSE(refused.admitted());
        EXPECT_EQ(::GetLastError(), 0xA00Au);
        original = 0xCAFE;
        EXPECT_FALSE(refused.original_buttons(0x2200, original));
        EXPECT_EQ(original, 0xCAFE);
        EXPECT_TRUE(DetourModKit::detail::xinput_consume_context_healthy());
        EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 1);
    }
    EXPECT_TRUE(outer.original_buttons(0x1100, original));
    EXPECT_EQ(original, 0x1100);
    EXPECT_TRUE(outer.finish());
}

TEST(XInputConsumeScopeTest, ProposedReturnsKeepTheOriginalAcrossSeveralMasks)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD state = 0;
    XInputConsumeScope outer{0, &state};
    ASSERT_TRUE(outer.admitted());
    XInputConsumeScope middle{0, &state};
    ASSERT_TRUE(middle.admitted());
    WORD original = 0;
    {
        XInputConsumeScope lowest{0, &state};
        ASSERT_TRUE(lowest.admitted());
        ASSERT_TRUE(lowest.original_buttons(0x3100, original));
        ASSERT_TRUE(lowest.finish(0x3000));
    }
    ASSERT_TRUE(middle.original_buttons(0x3000, original));
    EXPECT_EQ(original, 0x3100);
    ASSERT_TRUE(middle.finish(0x2000));
    ASSERT_TRUE(outer.original_buttons(0x2000, original));
    EXPECT_EQ(original, 0x3100);
    EXPECT_TRUE(outer.finish(0x2000));
}

TEST(XInputConsumeScopeTest, VisibleForeignRewriteReseedsTheOriginalWithoutPoison)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD state = 0;
    XInputConsumeScope outer{0, &state};
    ASSERT_TRUE(outer.admitted());
    WORD original = 0;
    {
        XInputConsumeScope lower{0, &state};
        ASSERT_TRUE(lower.admitted());
        ASSERT_TRUE(lower.original_buttons(0x1100, original));
        ASSERT_TRUE(lower.finish(0x1000));
    }
    ASSERT_TRUE(outer.original_buttons(0x2000, original));
    EXPECT_EQ(original, 0x2000);
    EXPECT_TRUE(DetourModKit::detail::xinput_consume_context_healthy());
    EXPECT_TRUE(outer.finish(0x2000));
}

TEST(XInputConsumeScopeTest, AnAlreadyClearedForeignBitProducesNoRewriteEvidence)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD state = 0;
    XInputConsumeScope outer{0, &state};
    ASSERT_TRUE(outer.admitted());
    WORD original = 0;
    {
        XInputConsumeScope lower{0, &state};
        ASSERT_TRUE(lower.admitted());
        ASSERT_TRUE(lower.original_buttons(0x1100, original));
        ASSERT_TRUE(lower.finish(0x1000));
    }
    state = 0x1000;
    state &= static_cast<WORD>(~0x0100);
    ASSERT_TRUE(outer.original_buttons(state, original));
    EXPECT_EQ(original, 0x1100);
    EXPECT_TRUE(outer.finish(state));
}

TEST(XInputConsumeScopeTest, DepthOverflowRefusesWithoutChangingTheSharedContext)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD state = 0;
    const DWORD identity_index = DetourModKit::detail::xinput_consume_identity_index_for_test();
    const DWORD metadata_index = DetourModKit::detail::xinput_consume_metadata_index_for_test();
    constexpr std::uintptr_t max_depth = (std::uintptr_t{1} << 29) - 1;
    constexpr std::uintptr_t metadata = (max_depth << 33) | (std::uintptr_t{1} << 32) | 0x10001100;
    ASSERT_TRUE(::TlsSetValue(identity_index, &state));
    ASSERT_TRUE(::TlsSetValue(metadata_index, reinterpret_cast<void *>(metadata)));
    const XInputConsumeScope refused{0, &state};
    EXPECT_FALSE(refused.admitted());
    EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 0);
    EXPECT_TRUE(DetourModKit::detail::xinput_consume_context_healthy());
    EXPECT_EQ(::TlsGetValue(identity_index), &state);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(::TlsGetValue(metadata_index)), metadata);
    EXPECT_TRUE(::TlsSetValue(identity_index, nullptr));
    EXPECT_TRUE(::TlsSetValue(metadata_index, nullptr));
}

TEST(XInputConsumeScopeTest, SharedIndicesKeepThreadOriginalsIndependent)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD state = 0;
    XInputConsumeScope outer{0, &state};
    ASSERT_TRUE(outer.admitted());
    WORD original = 0;
    ASSERT_TRUE(outer.original_buttons(0x1100, original));
    std::atomic<bool> worker_passed{false};
    std::thread worker(
        [&worker_passed, &state]() noexcept -> void
        {
            XInputConsumeScope scope{0, &state};
            WORD worker_original = 0;
            const bool passed = scope.admitted() && scope.original_buttons(0x2200, worker_original) &&
                                worker_original == 0x2200 && scope.finish();
            worker_passed.store(passed, std::memory_order_release);
        }
    );
    worker.join();
    EXPECT_TRUE(worker_passed.load(std::memory_order_acquire));
    ASSERT_TRUE(outer.original_buttons(0x1100, original));
    EXPECT_EQ(original, 0x1100);
    EXPECT_TRUE(outer.finish());
}

TEST(XInputConsumeScopeTest, PartialReservationReturnsEveryIndexBeforePublication)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const std::array failures{
        XInputRawScopeFailure::IdentityReservation,
        XInputRawScopeFailure::MetadataReservation,
    };
    for (const auto failure : failures)
    {
        std::array<DWORD, 3> available{};
        for (auto &index : available)
        {
            index = ::TlsAlloc();
            ASSERT_NE(index, TLS_OUT_OF_INDEXES);
        }
        for (const DWORD index : available)
        {
            ASSERT_TRUE(::TlsFree(index));
        }
        {
            const RawFailure refusal{failure};
            ASSERT_TRUE(refusal.registered());
            DWORD error = ERROR_SUCCESS;
            EXPECT_FALSE(DetourModKit::detail::acquire_xinput_raw_scope_owner(&error));
            EXPECT_EQ(error, ERROR_NOT_ENOUGH_MEMORY);
            EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), TLS_OUT_OF_INDEXES);
            EXPECT_EQ(DetourModKit::detail::xinput_consume_identity_index_for_test(), TLS_OUT_OF_INDEXES);
            EXPECT_EQ(DetourModKit::detail::xinput_consume_metadata_index_for_test(), TLS_OUT_OF_INDEXES);
            EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_owners_for_test(), 0);
        }
        std::array<DWORD, 3> returned{};
        for (auto &index : returned)
        {
            index = ::TlsAlloc();
            ASSERT_NE(index, TLS_OUT_OF_INDEXES);
        }
        EXPECT_EQ(returned, available);
        for (const DWORD index : returned)
        {
            EXPECT_TRUE(::TlsFree(index));
        }
        const RawOwner recovered;
        EXPECT_TRUE(recovered.reserved());
        EXPECT_TRUE(DetourModKit::detail::xinput_consume_context_healthy());
    }
}

TEST(XInputConsumeScopeTest, EntryAndRollbackFaultsPoisonEveryThreadUntilFinalRetirement)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const std::array failures{
        XInputRawScopeFailure::ConsumeEntryIdentity,
        XInputRawScopeFailure::ConsumeEntryMetadata,
        XInputRawScopeFailure::ConsumeEntryRollback,
    };
    for (const auto failure : failures)
    {
        RawOwner owner;
        ASSERT_TRUE(owner.reserved());
        WORD outer_state = 0;
        WORD inner_state = 0;
        XInputConsumeScope outer{0, &outer_state};
        ASSERT_TRUE(outer.admitted());
        WORD original = 0;
        ASSERT_TRUE(outer.original_buttons(0x1100, original));
        const DWORD identity_index = DetourModKit::detail::xinput_consume_identity_index_for_test();
        const DWORD metadata_index = DetourModKit::detail::xinput_consume_metadata_index_for_test();
        void *const previous_identity = ::TlsGetValue(identity_index);
        void *const previous_metadata = ::TlsGetValue(metadata_index);
        {
            const RawFailure refusal{failure};
            ASSERT_TRUE(refusal.registered());
            ::SetLastError(0xA00A);
            XInputConsumeScope refused{1, &inner_state};
            EXPECT_FALSE(refused.admitted());
            EXPECT_FALSE(refused.finish());
            EXPECT_FALSE(refused.finish());
            EXPECT_EQ(::GetLastError(), 0xA00Au);
            EXPECT_FALSE(DetourModKit::detail::xinput_consume_context_healthy());
            if (failure != XInputRawScopeFailure::ConsumeEntryRollback)
            {
                EXPECT_EQ(::TlsGetValue(identity_index), previous_identity);
                EXPECT_EQ(::TlsGetValue(metadata_index), previous_metadata);
            }
        }
        original = 0xCAFE;
        EXPECT_FALSE(outer.original_buttons(0x1100, original));
        EXPECT_EQ(original, 0xCAFE);
        std::atomic<bool> refused_on_peer{false};
        std::thread peer(
            [&refused_on_peer, &inner_state]() noexcept -> void
            {
                const XInputConsumeScope scope{0, &inner_state};
                refused_on_peer.store(!scope.admitted(), std::memory_order_release);
            }
        );
        peer.join();
        EXPECT_TRUE(refused_on_peer.load(std::memory_order_acquire));
        EXPECT_FALSE(outer.finish());
        EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 0);
        RawOwner second_owner;
        ASSERT_TRUE(second_owner.reserved());
        owner.reset();
        EXPECT_FALSE(DetourModKit::detail::xinput_consume_context_healthy());
        second_owner.reset();
        const RawOwner restarted;
        ASSERT_TRUE(restarted.reserved());
        EXPECT_TRUE(DetourModKit::detail::xinput_consume_context_healthy());
        XInputConsumeScope clean{0, &outer_state};
        ASSERT_TRUE(clean.admitted());
        ASSERT_TRUE(clean.original_buttons(0x2200, original));
        EXPECT_EQ(original, 0x2200);
        EXPECT_TRUE(clean.finish());
    }
}

TEST(XInputConsumeScopeTest, CaptureAndRestoreFaultsRefuseMasksAndBalanceLeases)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const std::array failures{
        XInputRawScopeFailure::ConsumeOriginalStore,
        XInputRawScopeFailure::ConsumeRestoreIdentity,
        XInputRawScopeFailure::ConsumeRestoreMetadata,
    };
    for (const auto failure : failures)
    {
        const RawOwner owner;
        ASSERT_TRUE(owner.reserved());
        WORD state = 0;
        XInputConsumeScope scope{0, &state};
        ASSERT_TRUE(scope.admitted());
        const RawFailure refusal{failure};
        ASSERT_TRUE(refusal.registered());
        WORD original = 0xCAFE;
        ::SetLastError(0xD00D);
        const bool captured = scope.original_buttons(0x1100, original);
        EXPECT_EQ(captured, failure != XInputRawScopeFailure::ConsumeOriginalStore);
        EXPECT_EQ(original, failure == XInputRawScopeFailure::ConsumeOriginalStore ? 0xCAFE : 0x1100);
        EXPECT_FALSE(scope.finish());
        EXPECT_FALSE(scope.finish());
        EXPECT_EQ(::GetLastError(), 0xD00Du);
        EXPECT_FALSE(DetourModKit::detail::xinput_consume_context_healthy());
        EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 0);
        const XInputConsumeScope refused{0, &state};
        EXPECT_FALSE(refused.admitted());
    }
}

TEST(XInputConsumeScopeTest, FinalReleaseRetainsAllIndicesAcrossAnActiveConsumeScope)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD state = 0;
    XInputConsumeScope scope{0, &state};
    ASSERT_TRUE(scope.admitted());
    const DWORD identity_index = DetourModKit::detail::xinput_consume_identity_index_for_test();
    const DWORD metadata_index = DetourModKit::detail::xinput_consume_metadata_index_for_test();
    owner.reset();
    EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 1);
    EXPECT_EQ(DetourModKit::detail::xinput_consume_identity_index_for_test(), identity_index);
    EXPECT_EQ(DetourModKit::detail::xinput_consume_metadata_index_for_test(), metadata_index);
    const XInputConsumeScope refused{0, &state};
    EXPECT_FALSE(refused.admitted());
    WORD original = 0;
    EXPECT_TRUE(scope.original_buttons(0x1100, original));
    EXPECT_TRUE(scope.finish());
    RawOwner recovered;
    ASSERT_TRUE(recovered.reserved());
    recovered.reset();
    EXPECT_EQ(DetourModKit::detail::xinput_consume_identity_index_for_test(), TLS_OUT_OF_INDEXES);
    EXPECT_EQ(DetourModKit::detail::xinput_consume_metadata_index_for_test(), TLS_OUT_OF_INDEXES);
}

TEST(XInputConsumeScopeTest, ChildFaultProofPreservesTheLiveParentOwner)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    const RawOwner owner;
    ASSERT_TRUE(owner.reserved());
    WORD state = 0;
    XInputConsumeScope scope{0, &state};
    ASSERT_TRUE(scope.admitted());
    WORD original = 0;
    ASSERT_TRUE(scope.original_buttons(0x1100, original));
    const DWORD raw_index = DetourModKit::detail::xinput_raw_scope_index_for_test();
    const DWORD identity_index = DetourModKit::detail::xinput_consume_identity_index_for_test();
    const DWORD metadata_index = DetourModKit::detail::xinput_consume_metadata_index_for_test();
    const auto owners = DetourModKit::detail::xinput_raw_scope_owners_for_test();
    run_scope_case_in_fresh_process(L"XInputConsumeScopeTest.CaptureAndRestoreFaultsRefuseMasksAndBalanceLeases");
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), raw_index);
    EXPECT_EQ(DetourModKit::detail::xinput_consume_identity_index_for_test(), identity_index);
    EXPECT_EQ(DetourModKit::detail::xinput_consume_metadata_index_for_test(), metadata_index);
    EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_owners_for_test(), owners);
    EXPECT_TRUE(DetourModKit::detail::xinput_consume_context_healthy());
    EXPECT_EQ(DetourModKit::detail::active_xinput_raw_scopes(), 1);
    original = 0;
    EXPECT_TRUE(scope.original_buttons(0x1100, original));
    EXPECT_EQ(original, 0x1100);
    EXPECT_TRUE(scope.finish());
}

TEST(XInputRawScopeTest, MalformedProcessDescriptorsRefuseBeforeTLSReservation)
{
    if (delegate_scope_case_if_owned())
    {
        return;
    }
    constexpr const char *filter = "XInputRawScopeTest.MalformedProcessDescriptorsRefuseBeforeTLSReservation";
    const auto unmap_view = [](void *view) noexcept -> void { ::UnmapViewOfFile(view); };
    using MappedView = std::unique_ptr<void, decltype(unmap_view)>;
    if (GTEST_FLAG_GET(filter) != filter)
    {
        run_current_scope_case_in_fresh_process();
        return;
    }

    FILETIME created{}, exited{}, kernel{}, user{};
    ASSERT_TRUE(::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user));
    std::array<wchar_t, 128> mutex_name{};
    std::array<wchar_t, 128> mapping_name{};
    ASSERT_GT(
        std::swprintf(
            mutex_name.data(),
            mutex_name.size(),
            L"Local\\DMK.XInputRaw.%lu.%08lx%08lx.Lock",
            ::GetCurrentProcessId(),
            created.dwHighDateTime,
            created.dwLowDateTime
        ),
        0
    );
    ASSERT_GT(
        std::swprintf(
            mapping_name.data(),
            mapping_name.size(),
            L"Local\\DMK.XInputRaw.%lu.%08lx%08lx.Data",
            ::GetCurrentProcessId(),
            created.dwHighDateTime,
            created.dwLowDateTime
        ),
        0
    );
    constexpr DWORD descriptor_bytes = 80;
    constexpr std::uint64_t magic = 0x444D4B5849524157ULL;
    const NativeHandle mutex{::CreateMutexW(nullptr, FALSE, mutex_name.data()), s_close_handle};
    const NativeHandle mapping{
        ::CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, descriptor_bytes, mapping_name.data()),
        s_close_handle
    };
    const NativeHandle unrelated{
        ::CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, descriptor_bytes, nullptr),
        s_close_handle
    };
    ASSERT_NE(mutex.get(), nullptr);
    ASSERT_NE(mapping.get(), nullptr);
    ASSERT_NE(unrelated.get(), nullptr);
    const MappedView mapped{::MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, descriptor_bytes), unmap_view};
    const MappedView other{::MapViewOfFile(unrelated.get(), FILE_MAP_ALL_ACCESS, 0, 0, descriptor_bytes), unmap_view};
    ASSERT_NE(mapped.get(), nullptr);
    ASSERT_NE(other.get(), nullptr);
    auto *const words = static_cast<std::uint64_t *>(mapped.get());
    const std::array<std::uint64_t, 10> header{
        magic,
        (static_cast<std::uint64_t>(descriptor_bytes) << 32) | 3,
        reinterpret_cast<std::uintptr_t>(mapped.get()),
        reinterpret_cast<std::uintptr_t>(mutex.get()),
        reinterpret_cast<std::uintptr_t>(mapping.get()),
        0,
        TLS_OUT_OF_INDEXES,
        0,
        (static_cast<std::uint64_t>(TLS_OUT_OF_INDEXES) << 32) | TLS_OUT_OF_INDEXES,
        0,
    };
    std::copy(header.begin(), header.end(), static_cast<std::uint64_t *>(other.get()));
    DWORD error = ERROR_SUCCESS;
    for (int i = 0; i < 6; ++i)
    {
        std::copy(header.begin(), header.end(), words);
        switch (i)
        {
        case 0:
            words[0] = 0;
            break;
        case 1:
            words[1] = (static_cast<std::uint64_t>(descriptor_bytes) << 32) | 4;
            break;
        case 2:
            words[1] = (static_cast<std::uint64_t>(descriptor_bytes + 8) << 32) | 3;
            break;
        case 3:
            words[2] = 0;
            break;
        case 4:
            words[2] = reinterpret_cast<std::uintptr_t>(other.get());
            break;
        case 5:
            words[2] = reinterpret_cast<std::uintptr_t>(other.get());
            static_cast<std::uint64_t *>(other.get())[5] = 1;
            break;
        }
        ASSERT_FALSE(DetourModKit::detail::acquire_xinput_raw_scope_owner(&error)) << i;
        EXPECT_EQ(error, ERROR_INVALID_DATA) << i;
        EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_index_for_test(), TLS_OUT_OF_INDEXES) << i;
        EXPECT_EQ(DetourModKit::detail::xinput_raw_scope_descriptor_for_test(), 0u) << i;
    }
}
