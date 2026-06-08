/**
 * @file input_intercept.cpp
 * @brief Implementation of the internal active-input layer (input_intercept.hpp).
 *
 * Owns the XInputGetState inline hook and the window-procedure subclass that
 * back gamepad passthrough suppression and mouse-wheel capture for InputPoller.
 */

#include "input_intercept.hpp"
#include "platform.hpp"

#include "safetyhook.hpp"

#include <atomic>
#include <cstdint>
#include <utility>

namespace DetourModKit::detail
{
    namespace
    {
        /// XInput export resides in one of these DLLs depending on the game/runtime.
        constexpr const wchar_t *s_xinput_dll_names[] = {
            L"xinput1_4.dll",
            L"xinput1_3.dll",
            L"xinput9_1_0.dll",
            L"xinput1_2.dll",
            L"xinput1_1.dll",
        };

        /// Undocumented ordinal that exports XInputGetStateEx (reports the Guide button).
        constexpr WORD s_xinput_get_state_ex_ordinal = 100;

        /// How long a published suppression mask stays valid without a refresh.
        /// Set above the maximum allowed poll interval (MAX_POLL_INTERVAL) so a
        /// healthy poll thread at any configured rate keeps the mask continuously
        /// alive, while still bounding a stalled poll thread so it cannot latch the
        /// game's input off indefinitely. Twice the largest poll interval leaves
        /// headroom for a slow cycle's own body to run before the deadline lapses.
        constexpr uint64_t s_suppress_ttl_ms = 2000;

        // --- XInput interception state ---

        safetyhook::InlineHook s_xinput_hook;
        safetyhook::InlineHook s_xinput_ex_hook;
        std::atomic<XInputGetStateFn> s_xinput_original{nullptr};
        std::atomic<XInputGetStateFn> s_xinput_ex_original{nullptr};
        std::atomic<bool> s_xinput_installed{false};
        std::atomic<int> s_bound_user_index{0};
        std::atomic<uint16_t> s_suppress_mask{0};
        std::atomic<uint64_t> s_suppress_deadline_ms{0};

        // --- Mouse-wheel capture state ---

        std::array<std::atomic<int>, 4> s_wheel_count{};
        std::atomic<bool> s_wheel_consume{false};
        std::atomic<HWND> s_hwnd{nullptr};
        std::atomic<LONG_PTR> s_prev_wndproc{0};
        std::atomic<bool> s_wndproc_installed{false};

        /**
         * @brief Clears the suppressed button bits from a game-bound XINPUT_STATE.
         * @details Only the bound controller index is masked. dwPacketNumber and
         *          the success return are left untouched so the game still sees a
         *          connected, advancing controller (faking a disconnect would
         *          trigger pause/reconnect UI). A time-to-live guard drops the mask
         *          if the poll thread stopped refreshing it.
         */
        void apply_suppress(XINPUT_STATE *state, DWORD user_index) noexcept
        {
            if (state == nullptr)
            {
                return;
            }
            if (static_cast<int>(user_index) != s_bound_user_index.load(std::memory_order_relaxed))
            {
                return;
            }
            const uint16_t mask = s_suppress_mask.load(std::memory_order_acquire);
            if (mask == 0)
            {
                return;
            }
            // Relaxed is sufficient for the deadline read: publish_gamepad_suppress
            // writes it before the release store on s_suppress_mask, so the acquire
            // load of the mask above already established the happens-before. A
            // non-zero mask is therefore never paired with a stale (pre-refresh)
            // deadline.
            if (GetTickCount64() >= s_suppress_deadline_ms.load(std::memory_order_relaxed))
            {
                return;
            }
            state->Gamepad.wButtons =
                static_cast<WORD>(state->Gamepad.wButtons & static_cast<WORD>(~mask));
        }

        DWORD WINAPI xinput_get_state_detour(DWORD user_index, XINPUT_STATE *state) noexcept
        {
            const XInputGetStateFn original = s_xinput_original.load(std::memory_order_acquire);
            const DWORD result = (original != nullptr)
                                     ? original(user_index, state)
                                     : ERROR_DEVICE_NOT_CONNECTED;
            if (result == ERROR_SUCCESS)
            {
                apply_suppress(state, user_index);
            }
            return result;
        }

        DWORD WINAPI xinput_get_state_ex_detour(DWORD user_index, XINPUT_STATE *state) noexcept
        {
            const XInputGetStateFn original = s_xinput_ex_original.load(std::memory_order_acquire);
            const DWORD result = (original != nullptr)
                                     ? original(user_index, state)
                                     : ERROR_DEVICE_NOT_CONNECTED;
            if (result == ERROR_SUCCESS)
            {
                apply_suppress(state, user_index);
            }
            return result;
        }

        LRESULT CALLBACK wndproc_detour(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) noexcept
        {
            const WNDPROC prev =
                reinterpret_cast<WNDPROC>(s_prev_wndproc.load(std::memory_order_acquire));

            switch (msg)
            {
            case WM_MOUSEWHEEL:
            {
                // GET_WHEEL_DELTA_WPARAM is a signed short: positive scrolls the
                // wheel forward (up/away from the user), negative backward (down).
                const int delta = GET_WHEEL_DELTA_WPARAM(wparam);
                if (delta > 0)
                {
                    s_wheel_count[0].fetch_add(1, std::memory_order_relaxed); // Up
                }
                else if (delta < 0)
                {
                    s_wheel_count[1].fetch_add(1, std::memory_order_relaxed); // Down
                }
                if (s_wheel_consume.load(std::memory_order_relaxed))
                {
                    return 0;
                }
                break;
            }
            case WM_MOUSEHWHEEL:
            {
                // Horizontal wheel sign is opposite the vertical intuition:
                // positive tilts right, negative left.
                const int delta = GET_WHEEL_DELTA_WPARAM(wparam);
                if (delta > 0)
                {
                    s_wheel_count[3].fetch_add(1, std::memory_order_relaxed); // Right
                }
                else if (delta < 0)
                {
                    s_wheel_count[2].fetch_add(1, std::memory_order_relaxed); // Left
                }
                if (s_wheel_consume.load(std::memory_order_relaxed))
                {
                    return 0;
                }
                break;
            }
            case WM_NCDESTROY:
                // The window is being destroyed and its window-long storage is
                // about to be invalidated. Drop all tracked subclass state and mark
                // the subclass uninstalled so a later poll cycle re-subclasses the
                // next game window: an engine that recreates its window on a
                // fullscreen/display-mode switch would otherwise leave the new
                // window unhooked, because install_wndproc short-circuits while
                // s_wndproc_installed stays true. The forward at the bottom of this
                // function uses the local prev copy captured above, so clearing
                // s_prev_wndproc here does not affect this invocation's own forward.
                // Store the installed flag last so a poll thread observing it false
                // (acquire) also sees the cleared handle and predecessor.
                s_hwnd.store(nullptr, std::memory_order_release);
                s_prev_wndproc.store(0, std::memory_order_release);
                s_wndproc_installed.store(false, std::memory_order_release);
                break;
            default:
                break;
            }

            if (prev != nullptr)
            {
                return CallWindowProcW(prev, hwnd, msg, wparam, lparam);
            }
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }

        BOOL CALLBACK find_window_proc(HWND hwnd, LPARAM lparam) noexcept
        {
            auto *out = reinterpret_cast<HWND *>(lparam);
            DWORD window_pid = 0;
            GetWindowThreadProcessId(hwnd, &window_pid);
            // Accept the first visible, top-level (owner-less) window belonging to
            // this process. The owner check filters tool/splash windows; visibility
            // filters message-only and hidden helper windows.
            if (window_pid != GetCurrentProcessId() || !IsWindowVisible(hwnd) ||
                GetWindow(hwnd, GW_OWNER) != nullptr)
            {
                return TRUE; // keep enumerating
            }
            *out = hwnd;
            return FALSE; // stop
        }

        HWND find_game_window() noexcept
        {
            HWND result = nullptr;
            EnumWindows(&find_window_proc, reinterpret_cast<LPARAM>(&result));
            if (result != nullptr)
            {
                return result;
            }
            // Fallback: the foreground window if it belongs to this process.
            const HWND foreground = GetForegroundWindow();
            if (foreground != nullptr)
            {
                DWORD pid = 0;
                GetWindowThreadProcessId(foreground, &pid);
                if (pid == GetCurrentProcessId())
                {
                    return foreground;
                }
            }
            return nullptr;
        }

        void uninstall_wndproc() noexcept
        {
            if (!s_wndproc_installed.load(std::memory_order_acquire))
            {
                return;
            }
            const HWND hwnd = s_hwnd.load(std::memory_order_acquire);
            if (hwnd == nullptr || !IsWindow(hwnd))
            {
                // The window was already destroyed (WM_NCDESTROY cleared the
                // handle, or it is otherwise gone); the subclass went with it.
                s_hwnd.store(nullptr, std::memory_order_release);
                s_prev_wndproc.store(0, std::memory_order_release);
                s_wndproc_installed.store(false, std::memory_order_release);
                return;
            }

            const WNDPROC current =
                reinterpret_cast<WNDPROC>(GetWindowLongPtrW(hwnd, GWLP_WNDPROC));
            if (current == &wndproc_detour)
            {
                // Still the top of the chain: restoring the saved procedure is safe.
                SetWindowLongPtrW(hwnd, GWLP_WNDPROC, s_prev_wndproc.load(std::memory_order_acquire));
                s_hwnd.store(nullptr, std::memory_order_release);
                s_prev_wndproc.store(0, std::memory_order_release);
                s_wndproc_installed.store(false, std::memory_order_release);
                return;
            }

            // Another subclass layered on top of ours. Restoring here would clobber
            // that mod's procedure, so leave our detour installed: it only forwards
            // to s_prev_wndproc (kept intact) and is inert once wheel bindings are
            // gone. Pin the module so the detour's code stays mapped even if this
            // DLL is later unloaded, and keep s_wndproc_installed true so a later
            // install does not stack a duplicate detour onto the chain.
            pin_current_module();
        }
    } // anonymous namespace

    uint8_t step_wheel_pulse(WheelPulseState &state) noexcept
    {
        uint8_t mask = 0;
        for (int dir = 0; dir < 4; ++dir)
        {
            if (state.pulsing[dir])
            {
                // Force one low cycle after a pulse so the edge detector re-arms.
                state.pulsing[dir] = false;
            }
            else if (state.pending[dir] > 0)
            {
                --state.pending[dir];
                mask = static_cast<uint8_t>(mask | (1u << dir));
                state.pulsing[dir] = true;
            }
        }
        return mask;
    }

    uint16_t step_gamepad_suppress(GamepadSuppressState &state,
                                   uint16_t owned_now,
                                   uint16_t true_buttons,
                                   uint64_t now_ms,
                                   uint64_t grace_ms) noexcept
    {
        // Sentinel deadline meaning "actively held, not yet releasing".
        constexpr uint64_t held_sentinel = UINT64_MAX;

        uint16_t mask = 0;
        const uint16_t relevant = static_cast<uint16_t>(state.armed | owned_now);
        for (int bit = 0; bit < 16; ++bit)
        {
            const uint16_t m = static_cast<uint16_t>(1u << bit);
            if ((relevant & m) == 0)
            {
                continue;
            }
            const bool phys_down = (true_buttons & m) != 0;
            const bool owned = (owned_now & m) != 0;

            if (owned || ((state.armed & m) != 0 && phys_down))
            {
                // Actively held: a chord claims it now, or the trigger button is
                // still physically down after the modifier was released. Keep
                // suppressing and cancel any in-progress release grace.
                state.armed = static_cast<uint16_t>(state.armed | m);
                state.deadline_ms[static_cast<size_t>(bit)] = held_sentinel;
                mask = static_cast<uint16_t>(mask | m);
            }
            else if ((state.armed & m) != 0)
            {
                // Armed but the physical button is up: run the release grace so a
                // trailing bare-trigger frame cannot leak to the game.
                if (state.deadline_ms[static_cast<size_t>(bit)] == held_sentinel)
                {
                    state.deadline_ms[static_cast<size_t>(bit)] = now_ms + grace_ms;
                }
                if (now_ms < state.deadline_ms[static_cast<size_t>(bit)])
                {
                    mask = static_cast<uint16_t>(mask | m);
                }
                else
                {
                    state.armed = static_cast<uint16_t>(state.armed & static_cast<uint16_t>(~m));
                    state.deadline_ms[static_cast<size_t>(bit)] = 0;
                }
            }
        }
        return mask;
    }

    bool install_xinput(int user_index) noexcept
    {
        s_bound_user_index.store(user_index, std::memory_order_relaxed);
        if (s_xinput_installed.load(std::memory_order_acquire))
        {
            return true;
        }

        HMODULE module = nullptr;
        for (const wchar_t *name : s_xinput_dll_names)
        {
            module = GetModuleHandleW(name);
            if (module != nullptr)
            {
                break;
            }
        }
        if (module == nullptr)
        {
            return false; // XInput not loaded yet; the poll loop retries.
        }

        auto *get_state = reinterpret_cast<void *>(GetProcAddress(module, "XInputGetState"));
        if (get_state == nullptr)
        {
            return false;
        }

        auto allocator = safetyhook::Allocator::global();
        // Create the hook disabled so the trampoline exists before the prologue is
        // patched: publish the original (trampoline) pointer first, then enable.
        // If the detour went live before the store, a game thread entering it in
        // that window would read a null original and wrongly report
        // ERROR_DEVICE_NOT_CONNECTED -- a transient fake disconnect for a frame.
        auto hook = safetyhook::InlineHook::create(
            allocator, get_state, reinterpret_cast<void *>(&xinput_get_state_detour),
            safetyhook::InlineHook::StartDisabled);
        if (!hook)
        {
            return false;
        }
        s_xinput_hook = std::move(hook.value());
        s_xinput_original.store(s_xinput_hook.original<XInputGetStateFn>(), std::memory_order_release);
        if (!s_xinput_hook.enable())
        {
            s_xinput_original.store(nullptr, std::memory_order_release);
            s_xinput_hook = {};
            return false;
        }

        // XInputGetStateEx (ordinal 100) carries the Guide button; a game that
        // polls it would otherwise bypass the mask. Hook it too when present; its
        // absence is not an error. Skip it when a proxy/shim xinput DLL aliases the
        // ordinal to the same code address as XInputGetState: that address is
        // already covered, and a second inline hook on one prologue would capture
        // the first hook's jmp as its "original" and corrupt the trampoline chain.
        auto *get_state_ex = reinterpret_cast<void *>(
            GetProcAddress(module, MAKEINTRESOURCEA(s_xinput_get_state_ex_ordinal)));
        if (get_state_ex != nullptr && get_state_ex != get_state)
        {
            auto ex_hook = safetyhook::InlineHook::create(
                allocator, get_state_ex, reinterpret_cast<void *>(&xinput_get_state_ex_detour),
                safetyhook::InlineHook::StartDisabled);
            if (ex_hook)
            {
                s_xinput_ex_hook = std::move(ex_hook.value());
                s_xinput_ex_original.store(s_xinput_ex_hook.original<XInputGetStateFn>(),
                                           std::memory_order_release);
                if (!s_xinput_ex_hook.enable())
                {
                    s_xinput_ex_original.store(nullptr, std::memory_order_release);
                    s_xinput_ex_hook = {};
                }
            }
        }

        s_xinput_installed.store(true, std::memory_order_release);
        return true;
    }

    bool xinput_installed() noexcept
    {
        return s_xinput_installed.load(std::memory_order_acquire);
    }

    XInputGetStateFn xinput_trampoline() noexcept
    {
        return s_xinput_original.load(std::memory_order_acquire);
    }

    void publish_gamepad_suppress(uint16_t suppress_bits) noexcept
    {
        // Write the deadline before the mask (release on the mask). A detour that
        // observes the new mask with acquire is then guaranteed to also observe
        // the refreshed deadline, so a fresh mask is never paired with a stale
        // (already-expired) deadline.
        s_suppress_deadline_ms.store(GetTickCount64() + s_suppress_ttl_ms, std::memory_order_relaxed);
        s_suppress_mask.store(suppress_bits, std::memory_order_release);
    }

    bool install_wndproc() noexcept
    {
        if (s_wndproc_installed.load(std::memory_order_acquire))
        {
            return true;
        }
        const HWND hwnd = find_game_window();
        if (hwnd == nullptr)
        {
            return false; // window not available yet; the poll loop retries.
        }

        // Publish the predecessor procedure and target window before the detour
        // goes live. SetWindowLongPtrW makes wndproc_detour reachable from the
        // window's own message thread the instant it returns; if the predecessor
        // were stored only afterwards, a message dispatched in that gap would read
        // a zero s_prev_wndproc and route to DefWindowProcW instead of the game's
        // real procedure. A top-level window always has a non-null WNDPROC, so a
        // zero read here means the slot is not readable yet. install_wndproc runs
        // only on the single poll thread, so no concurrent install can invalidate
        // this predecessor between the read and the swap below.
        const LONG_PTR current = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
        if (current == 0)
        {
            return false;
        }
        s_prev_wndproc.store(current, std::memory_order_release);
        s_hwnd.store(hwnd, std::memory_order_release);

        // SetWindowLongPtr returns the previous value, or 0 on failure. Disambiguate
        // a genuine zero predecessor from an error via GetLastError.
        SetLastError(0);
        const LONG_PTR prev =
            SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&wndproc_detour));
        if (prev == 0 && GetLastError() != 0)
        {
            // Swap failed: roll back the published predecessor so no stale handle
            // survives a failed install.
            s_hwnd.store(nullptr, std::memory_order_release);
            s_prev_wndproc.store(0, std::memory_order_release);
            return false;
        }
        s_wndproc_installed.store(true, std::memory_order_release);
        return true;
    }

    bool wndproc_installed() noexcept
    {
        return s_wndproc_installed.load(std::memory_order_acquire);
    }

    std::array<int, 4> take_wheel_counts() noexcept
    {
        std::array<int, 4> out{};
        for (int dir = 0; dir < 4; ++dir)
        {
            out[static_cast<size_t>(dir)] =
                s_wheel_count[static_cast<size_t>(dir)].exchange(0, std::memory_order_relaxed);
        }
        return out;
    }

    void set_wheel_consume(bool consume) noexcept
    {
        s_wheel_consume.store(consume, std::memory_order_relaxed);
    }

    void uninstall() noexcept
    {
        // Stop masking before removing the hooks. The poll thread is already
        // stopped when this runs, so no further publishes can occur.
        s_suppress_mask.store(0, std::memory_order_release);
        s_wheel_consume.store(false, std::memory_order_relaxed);

        uninstall_wndproc();

        // Destroying the safetyhook objects rewrites the patched prologue pages and,
        // under a transient vectored exception handler, relocates the instruction
        // pointer of any thread caught mid-prologue (no thread is suspended). The
        // poll thread (the sole reader of the trampolines via xinput_trampoline())
        // is already joined, so clearing the saved pointers afterwards races nothing.
        s_xinput_ex_hook = {};
        s_xinput_hook = {};
        s_xinput_ex_original.store(nullptr, std::memory_order_release);
        s_xinput_original.store(nullptr, std::memory_order_release);
        s_xinput_installed.store(false, std::memory_order_release);
    }

} // namespace DetourModKit::detail
