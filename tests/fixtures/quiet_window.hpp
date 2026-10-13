#ifndef DETOURMODKIT_TEST_QUIET_WINDOW_HPP
#define DETOURMODKIT_TEST_QUIET_WINDOW_HPP

#include <windows.h>

namespace dmk_test
{
    /**
     * @brief Creates a visible ownerless top-level window that a desktop user never sees or loses focus to.
     * @details The window never activates, has no taskbar button, and sits off-screen at the bottom of the z-order.
     *          SetWindowPos shows it, because the first ShowWindow call of a process can take its show command from
     *          the launcher's STARTUPINFO and activate the window. Every input proof drives focus through its test
     *          seams, so none needs the window in the foreground.
     * @return The window, or nullptr when no window station is available.
     */
    [[nodiscard]] inline HWND create_quiet_window(const wchar_t *class_name, const wchar_t *title) noexcept
    {
        const HWND window = ::CreateWindowExW(
            WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            class_name,
            title,
            WS_OVERLAPPEDWINDOW,
            -32000,
            -32000,
            200,
            150,
            nullptr,
            nullptr,
            ::GetModuleHandleW(nullptr),
            nullptr
        );
        if (window != nullptr)
        {
            ::SetWindowPos(window, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        }
        return window;
    }
} // namespace dmk_test

#endif // DETOURMODKIT_TEST_QUIET_WINDOW_HPP
