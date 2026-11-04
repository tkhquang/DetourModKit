#ifndef DETOURMODKIT_TEST_CHILD_PROCESS_HPP
#define DETOURMODKIT_TEST_CHILD_PROCESS_HPP

#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <cwchar>
#include <memory>

namespace dmk_test
{
    /// The deadline of a child case. The parent terminates a child that misses it and fails.
    inline constexpr DWORD CHILD_CASE_DEADLINE_MS = 15000;

    /**
     * @brief Runs the case @p filter of this test binary in a new process and expects it to exit 0 by the deadline.
     * @details Disabled cases run too, so a case that a parent owns can stay out of the normal run. A proof that
     *          suspends every thread of its process needs this shape: the parent deadline is the only watchdog that
     *          a suspended holder cannot also stop.
     */
    inline void run_case_in_child(const wchar_t *filter)
    {
        const auto close_handle = [](void *handle) noexcept -> void { ::CloseHandle(handle); };
        using NativeHandle = std::unique_ptr<void, decltype(close_handle)>;

        std::array<wchar_t, 4096> executable{};
        ASSERT_NE(::GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size())), 0u);
        std::array<wchar_t, 8192> command{};
        ASSERT_GT(
            std::swprintf(
                command.data(),
                command.size(),
                L"\"%ls\" --gtest_also_run_disabled_tests --gtest_filter=%ls",
                executable.data(),
                filter
            ),
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
        const NativeHandle process_handle{process.hProcess, close_handle};
        const NativeHandle thread_handle{process.hThread, close_handle};
        const DWORD waited = ::WaitForSingleObject(process_handle.get(), CHILD_CASE_DEADLINE_MS);
        if (waited != WAIT_OBJECT_0)
        {
            ::TerminateProcess(process_handle.get(), 1);
            ::WaitForSingleObject(process_handle.get(), 1000);
        }
        ASSERT_EQ(waited, static_cast<DWORD>(WAIT_OBJECT_0)) << "the child case missed its deadline";
        DWORD exit_code = 1;
        ASSERT_TRUE(::GetExitCodeProcess(process_handle.get(), &exit_code));
        EXPECT_EQ(exit_code, 0u);
    }
} // namespace dmk_test

#endif // DETOURMODKIT_TEST_CHILD_PROCESS_HPP
