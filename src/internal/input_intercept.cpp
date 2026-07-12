/**
 * @file input_intercept.cpp
 * @brief Implementation of the internal active-input layer (input_intercept.hpp).
 *
 * Owns the XInputGetState inline hook and the window-procedure subclass that back gamepad passthrough suppression and
 * mouse-wheel capture for InputPoller.
 */

#include "input_intercept.hpp"
#include "platform.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"

#include "safetyhook.hpp"

#include <atomic>
#include <cstdint>
#include <new>
#include <thread>
#include <utility>

namespace DetourModKit::detail
{
    namespace
    {
        /// XInput export resides in one of these DLLs depending on the game/runtime.
        constexpr const wchar_t *XINPUT_DLL_NAMES[] = {
            L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll", L"xinput1_2.dll", L"xinput1_1.dll",
        };

        /// Undocumented ordinal that exports XInputGetStateEx (reports the Guide button).
        constexpr WORD XINPUT_GET_STATE_EX_ORDINAL = 100;

        /**
         * @brief How long a published suppression mask stays valid without a refresh.
         * @details Set above the maximum allowed poll interval (MAX_POLL_INTERVAL) so a healthy poll thread at any
         *          configured rate keeps the mask continuously alive, while still bounding a stalled poll thread so it
         *          cannot latch the game's input off indefinitely. Twice the largest poll interval leaves headroom for
         *          a slow cycle's own body to run before the deadline lapses.
         */
        constexpr uint64_t SUPPRESS_TTL_MS = 2000;

        // XInput interception state

        safetyhook::InlineHook s_xinput_hook;
        safetyhook::InlineHook s_xinput_ex_hook;
        std::atomic<XInputGetStateFn> s_xinput_original{nullptr};
        std::atomic<XInputGetStateFn> s_xinput_ex_original{nullptr};
        std::atomic<bool> s_xinput_installed{false};
        // True after an uninstall timeout forced the XInput hooks to become process-lifetime detours. The hook objects
        // live in a leaked heap cell and the detours keep forwarding through s_xinput_original even while logical
        // interception is disarmed, so the game keeps seeing real controller state after shutdown. A later Input start
        // re-arms logical interception by flipping s_xinput_installed back on instead of layering another hook over the
        // permanent one.
        std::atomic<bool> s_xinput_permanent_detour{false};
        // One-shot diagnostics latches: a failed InlineHook::enable() is otherwise swallowed silently, so surface each
        // failure the first time it happens and stay quiet afterwards (install_xinput is retried every poll cycle, so
        // an un-latched warning would spam the sink). uninstall() clears both so a later hot-reload re-arm can warn
        // again.
        std::atomic<bool> s_xinput_enable_warned{false};
        std::atomic<bool> s_xinput_ex_enable_warned{false};
        std::atomic<int> s_bound_user_index{0};
        std::atomic<uint16_t> s_suppress_mask{0};
        std::atomic<uint64_t> s_suppress_deadline_ms{0};

        // Count of game threads currently executing inside an XInput detour body. uninstall() first retires the
        // published trampoline pointers, then drains this to zero before destroying the hook objects, so no thread that
        // already copied a trampoline keeps running through memory the hook owns. SafetyHook still relocates a thread
        // caught mid-prologue during removal, so this is defense-in-depth that shrinks the window rather than the sole
        // guarantee; the poll thread (our other trampoline reader) is already joined by then.
        std::atomic<int> s_xinput_inflight{0};

        /**
         * @brief RAII marker for a game thread executing an XInput detour body.
         * @details Increment-on-entry / decrement-on-exit so uninstall() can observe when no detour is in flight. This
         *          counter and the published trampoline pointer form a Dekker-style mutual-exclusion pair: the detour
         *          increments the counter and then loads the trampoline, while uninstall() retires the trampoline
         *          (stores null) and then drains the counter. That is a store-then-load-of-a-different-location pattern
         *          on both sides, and the one reordering acquire/release does NOT forbid is exactly StoreLoad -- so with
         *          acquire/release the CPU may let the detour observe the still-non-null trampoline before its increment
         *          is visible to the drain, letting uninstall() see a zero count and free a trampoline the detour is
         *          about to run through (a use-after-free the SafetyHook mid-prologue relocation does not cover). Only a
         *          total order over the four operations forbids that interleaving, so the increment here, the detour's
         *          trampoline load, uninstall()'s retire store, and its drain load are all seq_cst. On x86-64 (the sole
         *          target) this costs nothing beyond the existing atomics: the increment is already a locked RMW (a full
         *          barrier) and a seq_cst load is a plain MOV. The decrement stays release: it is not part of the
         *          StoreLoad pair, it only has to publish the detour body's completion to the seq_cst drain load.
         *          Trivial and noexcept so it never perturbs the hot per-frame detour path.
         */
        struct InflightGuard
        {
            InflightGuard() noexcept { s_xinput_inflight.fetch_add(1, std::memory_order_seq_cst); }
            ~InflightGuard() noexcept { s_xinput_inflight.fetch_sub(1, std::memory_order_release); }
            InflightGuard(const InflightGuard &) = delete;
            InflightGuard &operator=(const InflightGuard &) = delete;
            InflightGuard(InflightGuard &&) = delete;
            InflightGuard &operator=(InflightGuard &&) = delete;
        };

        // Consume rule list (detour-side chord evaluation)
        //
        // A binding rebuild publishes one rule per detour-evaluable consume chord;
        // the XInput detour reads the list against the exact button snapshot the game is about to read. Each rule is
        // packed into a single atomic word so a reader never sees a torn rule, and the array plus its count sit behind
        // a seqlock (s_consume_rules_seq: even = stable, odd = mid-update) so the detour gets an all-or-nothing
        // snapshot of the whole list without locking. Single writer: whichever thread mutates the bindings, serialized
        // by
        // InputPoller::m_bindings_rw_mutex held in write mode while recompute_modifier_caches_locked / clear_bindings
        // publish. This is not the poll thread, which only takes a shared lock and never writes or reads this list.
        // Many readers: the game's XInput caller threads via the detour.
        std::array<std::atomic<uint64_t>, MAX_GAMEPAD_CONSUME_RULES> s_consume_rules{};
        std::atomic<uint32_t> s_consume_rule_count{0};
        std::atomic<uint32_t> s_consume_rules_seq{0};

        // Gate for detour-side rule masking, driven every poll cycle. The published rule list and its time-to-live
        // survive focus changes, so without this gate apply_suppress would keep masking the foreground game's input
        // while the mod is unfocused. The poll loop sets it true only while focused and connected, mirroring how the
        // reactive mask is cleared and how the per-direction wheel-consume mask is gated.
        std::atomic<bool> s_rule_suppress_enabled{false};

        /**
         * @brief Packs a rule into one word: modifier (bits 0-15), forbidden (16-31), trigger (32-47).
         * @details Three 16-bit masks fit a uint64 with room to spare, so a rule is published and read as a single
         *          atomic store/load.
         */
        constexpr uint64_t pack_consume_rule(const GamepadConsumeRule &rule) noexcept
        {
            return static_cast<uint64_t>(rule.modifier_mask) | (static_cast<uint64_t>(rule.forbidden_mask) << 16) |
                   (static_cast<uint64_t>(rule.trigger_mask) << 32);
        }

        /// Inverse of pack_consume_rule.
        constexpr GamepadConsumeRule unpack_consume_rule(uint64_t packed) noexcept
        {
            return GamepadConsumeRule{static_cast<uint16_t>(packed & 0xFFFFu),
                                      static_cast<uint16_t>((packed >> 16) & 0xFFFFu),
                                      static_cast<uint16_t>((packed >> 32) & 0xFFFFu)};
        }

        // Mouse-wheel capture state

        std::array<std::atomic<int>, 4> s_wheel_count{};
        // Per-direction wheel-swallow mask (WheelDirection bits), refreshed every poll cycle. Paired with a TTL so a
        // stalled poll thread stops swallowing and the game regains its wheel. A chord such as "Ctrl+WheelUp" must not
        // eat a bare WheelDown or an unmodified WheelUp.
        std::atomic<uint8_t> s_wheel_consume_mask{0};
        std::atomic<uint64_t> s_wheel_consume_deadline_ms{0};
        std::atomic<HWND> s_hwnd{nullptr};
        std::atomic<LONG_PTR> s_prev_wndproc{0};
        std::atomic<bool> s_wndproc_installed{false};
        // Set once install_wndproc has taken the never-released module reference that keeps wndproc_detour's code
        // mapped; the acquire precedes the subclass swap so the detour is never reachable without its keepalive.
        // WM_NCDESTROY re-arms installation for a re-created game window, so without this flag every window generation
        // would take -- and leak -- another reference. Only the poll thread touches it; relaxed ordering suffices.
        std::atomic<bool> s_wndproc_ref_taken{false};

        [[nodiscard]] HMODULE acquire_module_ref_containing_address(const void *address) noexcept
        {
            if (address == nullptr)
            {
                return nullptr;
            }

            HMODULE module = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(address),
                                    &module))
            {
                return nullptr;
            }
            return module;
        }

        /**
         * @brief Saturating single-notch increment for a per-direction wheel counter.
         * @details Uses a compare/exchange loop so every writer sees the current slot value before incrementing. The
         *          slot never exceeds MAX_WHEEL_NOTCHES, even if a foreign subclass or nested message dispatch
         *          re-enters the procedure. A concurrent drain-to-zero only lowers the value. This is the last line of
         *          defense for the idle-accretion case -- after the last wheel binding is removed the poll loop stops
         *          draining (take_wheel_counts is gated on live wheel bindings) yet the subclass stays installed to
         *          shutdown, so an unbounded fetch_add would eventually wrap a signed int.
         */
        void bump_wheel_notch(std::atomic<int> &slot) noexcept
        {
            int current = slot.load(std::memory_order_relaxed);
            while (
                current < MAX_WHEEL_NOTCHES &&
                !slot.compare_exchange_weak(current, current + 1, std::memory_order_relaxed, std::memory_order_relaxed))
            {
            }
        }

        /**
         * @brief Reports whether the detour should swallow a wheel message of the given direction this instant.
         * @details Reads the poll-published per-direction mask and its time-to-live. The acquire load of the mask also
         *          orders the relaxed deadline read: publish_wheel_consume writes the deadline before the release store
         *          on the mask, so observing a set direction bit guarantees observing its refreshed deadline. A lapsed
         *          deadline (stalled poll thread) forwards the message so the game is never latched out of its wheel.
         * @param direction_bit A single WheelDirection bit for the message's direction.
         */
        bool wheel_direction_consumed(uint8_t direction_bit) noexcept
        {
            if ((s_wheel_consume_mask.load(std::memory_order_acquire) & direction_bit) == 0)
            {
                return false;
            }
            return GetTickCount64() < s_wheel_consume_deadline_ms.load(std::memory_order_relaxed);
        }

        /**
         * @brief Clears the suppressed button bits from a game-bound XINPUT_STATE.
         * @details Only the bound controller index is masked. dwPacketNumber and the success return are left untouched
         *          so the game still sees a connected, advancing controller (faking a disconnect would trigger
         *          pause/reconnect UI). The cleared bits are the union of two sources:
         *          the reactive mask the poll thread publishes (which carries the trailing-edge consume-until-release
         *          latch) and the consume rules evaluated here against the exact buttons the game is about to read
         *          (which close the leading-edge window the poll-published mask trails by up to one cycle). A
         *          time-to-live guard drops all masking if the poll thread stopped refreshing it.
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
            // Acquire the reactive mask first. This load also orders the relaxed deadline read below:
            // publish_gamepad_suppress writes the deadline before the release store on s_suppress_mask, so the acquire
            // here establishes the happens-before even when the mask reads as 0.
            const uint16_t reactive = s_suppress_mask.load(std::memory_order_acquire);

            // raw is the true, unmasked state: this detour runs after the trampoline call. Evaluating the published
            // chord rules against it masks a chord whose modifier and trigger were pressed inside one poll interval on
            // the very frame the game reads it, rather than a cycle later. The focus gate suppresses this evaluation
            // when the host window is unfocused or the controller is gone: the rule list and its deadline both survive
            // those transitions, so the detour must not keep masking the foreground game's input (the reactive mask is
            // already cleared by the poll loop on focus loss).
            const uint16_t raw = state->Gamepad.wButtons;
            const uint16_t rule_mask =
                s_rule_suppress_enabled.load(std::memory_order_relaxed) ? evaluate_published_consume_rules(raw) : 0;
            const uint16_t mask = static_cast<uint16_t>(reactive | rule_mask);
            if (mask == 0)
            {
                return;
            }
            // The reactive mask and the rule list are both refreshed only while the poll thread is alive: rules exist
            // only when consume gamepad bindings do, and that is exactly when publish_gamepad_suppress refreshes this
            // deadline every cycle. A stalled poll thread therefore lets the deadline lapse and all masking stops, so
            // the game regains its input rather than latching off.
            if (GetTickCount64() >= s_suppress_deadline_ms.load(std::memory_order_relaxed))
            {
                return;
            }
            state->Gamepad.wButtons = static_cast<WORD>(raw & static_cast<WORD>(~mask));
        }

        DWORD WINAPI xinput_get_state_detour(DWORD user_index, XINPUT_STATE *state) noexcept
        {
            const InflightGuard inflight;
            // seq_cst: this load and the InflightGuard increment above form the detour side of the Dekker drain pair
            // (see InflightGuard). It must join the same total order as uninstall()'s retire store so a zeroed count
            // over there implies a null trampoline over here.
            const XInputGetStateFn original = s_xinput_original.load(std::memory_order_seq_cst);
            const DWORD result = (original != nullptr) ? original(user_index, state) : ERROR_DEVICE_NOT_CONNECTED;
            if (result == ERROR_SUCCESS)
            {
                apply_suppress(state, user_index);
            }
            return result;
        }

        DWORD WINAPI xinput_get_state_ex_detour(DWORD user_index, XINPUT_STATE *state) noexcept
        {
            const InflightGuard inflight;
            // seq_cst for the same Dekker-pair reason as xinput_get_state_detour above.
            const XInputGetStateFn original = s_xinput_ex_original.load(std::memory_order_seq_cst);
            const DWORD result = (original != nullptr) ? original(user_index, state) : ERROR_DEVICE_NOT_CONNECTED;
            if (result == ERROR_SUCCESS)
            {
                apply_suppress(state, user_index);
            }
            return result;
        }

        LRESULT CALLBACK wndproc_detour(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) noexcept
        {
            const WNDPROC prev = reinterpret_cast<WNDPROC>(s_prev_wndproc.load(std::memory_order_acquire));

            switch (msg)
            {
            case WM_MOUSEWHEEL:
            {
                // GET_WHEEL_DELTA_WPARAM is a signed short: positive scrolls the wheel forward (up/away from the user),
                // negative backward (down). Each message is exactly one direction, so latch that direction's notch and
                // swallow the message only when a consume binding currently owns that same direction -- a
                // "Ctrl+WheelUp" binding must not eat a bare WheelDown or an unmodified WheelUp.
                const int delta = GET_WHEEL_DELTA_WPARAM(wparam);
                if (delta > 0)
                {
                    bump_wheel_notch(s_wheel_count[0]); // Up
                    if (wheel_direction_consumed(wheel_direction_bit(WheelDirection::Up)))
                    {
                        return 0;
                    }
                }
                else if (delta < 0)
                {
                    bump_wheel_notch(s_wheel_count[1]); // Down
                    if (wheel_direction_consumed(wheel_direction_bit(WheelDirection::Down)))
                    {
                        return 0;
                    }
                }
                break;
            }
            case WM_MOUSEHWHEEL:
            {
                // Horizontal wheel sign is opposite the vertical intuition: positive tilts right, negative left. Same
                // per-direction latch-and-swallow as the vertical wheel.
                const int delta = GET_WHEEL_DELTA_WPARAM(wparam);
                if (delta > 0)
                {
                    bump_wheel_notch(s_wheel_count[3]); // Right
                    if (wheel_direction_consumed(wheel_direction_bit(WheelDirection::Right)))
                    {
                        return 0;
                    }
                }
                else if (delta < 0)
                {
                    bump_wheel_notch(s_wheel_count[2]); // Left
                    if (wheel_direction_consumed(wheel_direction_bit(WheelDirection::Left)))
                    {
                        return 0;
                    }
                }
                break;
            }
            case WM_NCDESTROY:
                // The window is being destroyed and its window-long storage is about to be invalidated. Drop all
                // tracked subclass state and mark the subclass uninstalled so a later poll cycle re-subclasses the next
                // game window: an engine that recreates its window on a fullscreen/display-mode switch would otherwise
                // leave the new window unhooked, because install_wndproc short-circuits while s_wndproc_installed stays
                // true. The forward at the bottom of this function uses the local prev copy captured above, so clearing
                // s_prev_wndproc here does not affect this invocation's own forward. Store the installed flag last so a
                // poll thread observing it false (acquire) also sees the cleared handle and predecessor.
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
            // Accept the first visible, top-level (owner-less) window belonging to this process. The owner check
            // filters tool/splash windows; visibility filters message-only and hidden helper windows.
            if (window_pid != GetCurrentProcessId() || !IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr)
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
                // The window was already destroyed (WM_NCDESTROY cleared the handle, or it is otherwise gone); the
                // subclass went with it.
                s_hwnd.store(nullptr, std::memory_order_release);
                s_prev_wndproc.store(0, std::memory_order_release);
                s_wndproc_installed.store(false, std::memory_order_release);
                return;
            }

            const WNDPROC current = reinterpret_cast<WNDPROC>(GetWindowLongPtrW(hwnd, GWLP_WNDPROC));
            if (current == &wndproc_detour)
            {
                // Still the top of the chain: restore the saved procedure so no FUTURE dispatch enters the detour.
                // The restore does not synchronize with a frame already inside wndproc_detour (SetWindowLongPtrW only
                // redirects dispatches that have not started; a modal size/move loop can hold an in-flight frame for
                // as long as the user drags the title bar), which is why the module reference taken at install time is
                // never released: that frame's return path stays mapped even if the host unloads this DLL right after
                // this teardown.
                SetWindowLongPtrW(hwnd, GWLP_WNDPROC, s_prev_wndproc.load(std::memory_order_acquire));
                // Deliberately leave s_prev_wndproc pointing at the real procedure. An in-flight wndproc_detour frame
                // on the window thread loads it at the top of the detour and forwards to it; zeroing it here would race
                // that frame and make it route the message to DefWindowProcW instead of the game's own procedure,
                // silently dropping e.g. WM_CLOSE / WM_ACTIVATE at every interception teardown. The detour is no longer
                // in the chain after the restore above, so no NEW frame enters, and a later install_wndproc overwrites
                // this value before re-subclassing -- so leaving it set is both safe and correct.
                s_hwnd.store(nullptr, std::memory_order_release);
                s_wndproc_installed.store(false, std::memory_order_release);
                return;
            }

            // Another subclass layered on top of ours. Restoring here would clobber that mod's procedure, so leave our
            // detour installed: it only forwards to s_prev_wndproc (kept intact) and is inert once wheel bindings are
            // gone. Its code stays mapped regardless -- install_wndproc took a never-released module reference when
            // the subclass first went live. Keep s_wndproc_installed true so a later install does not stack a
            // duplicate detour onto the chain.
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

    void add_wheel_notches(WheelPulseState &state, const std::array<int, 4> &taken) noexcept
    {
        for (size_t dir = 0; dir < 4; ++dir)
        {
            const int add = taken[dir] > 0 ? taken[dir] : 0;
            // pending is in [0, MAX_WHEEL_PENDING] by induction, so room is non-negative. Compare against room before
            // adding so a large burst saturates rather than overflowing the int sum.
            const int room = MAX_WHEEL_PENDING - state.pending[dir];
            state.pending[dir] = (add >= room) ? MAX_WHEEL_PENDING : state.pending[dir] + add;
        }
    }

    uint16_t step_gamepad_suppress(GamepadSuppressState &state, uint16_t owned_now, uint16_t true_buttons,
                                   uint64_t now_ms, uint64_t grace_ms) noexcept
    {
        // Sentinel deadline meaning "actively held, not yet releasing".
        constexpr uint64_t held_sentinel = UINT64_MAX;

        uint16_t mask = 0;
        const uint16_t relevant = static_cast<uint16_t>(state.armed | owned_now);
        for (int bit = 0; bit < 16; ++bit)
        {
            const uint16_t bit_mask = static_cast<uint16_t>(1u << bit);
            if ((relevant & bit_mask) == 0)
            {
                continue;
            }
            const bool phys_down = (true_buttons & bit_mask) != 0;
            const bool owned = (owned_now & bit_mask) != 0;

            if (owned || ((state.armed & bit_mask) != 0 && phys_down))
            {
                // Actively held: a chord claims it now, or the trigger button is still physically down after the
                // modifier was released. Keep suppressing and cancel any in-progress release grace.
                state.armed = static_cast<uint16_t>(state.armed | bit_mask);
                state.deadline_ms[static_cast<size_t>(bit)] = held_sentinel;
                mask = static_cast<uint16_t>(mask | bit_mask);
            }
            else if ((state.armed & bit_mask) != 0)
            {
                // Armed but the physical button is up: run the release grace so a trailing bare-trigger frame cannot
                // leak to the game.
                if (state.deadline_ms[static_cast<size_t>(bit)] == held_sentinel)
                {
                    state.deadline_ms[static_cast<size_t>(bit)] = now_ms + grace_ms;
                }
                if (now_ms < state.deadline_ms[static_cast<size_t>(bit)])
                {
                    mask = static_cast<uint16_t>(mask | bit_mask);
                }
                else
                {
                    state.armed = static_cast<uint16_t>(state.armed & static_cast<uint16_t>(~bit_mask));
                    state.deadline_ms[static_cast<size_t>(bit)] = 0;
                }
            }
        }
        return mask;
    }

    uint16_t evaluate_consume_rules(uint16_t true_buttons, const GamepadConsumeRule *rules, std::size_t count) noexcept
    {
        uint16_t mask = 0;
        for (std::size_t i = 0; i < count; ++i)
        {
            const GamepadConsumeRule &rule = rules[i];
            // Every modifier bit held and no forbidden bit held: the exact decision the poll loop makes (chord
            // modifiers satisfied and the strict-match check passes), evaluated against the snapshot the game is about
            // to read. A forbidden bit is a known modifier that belongs to a different chord, so holding one means this
            // chord is not the active gesture.
            if ((true_buttons & rule.modifier_mask) == rule.modifier_mask && (true_buttons & rule.forbidden_mask) == 0)
            {
                mask = static_cast<uint16_t>(mask | rule.trigger_mask);
            }
        }
        return mask;
    }

    void publish_gamepad_consume_rules(const GamepadConsumeRule *rules, std::size_t count) noexcept
    {
        // A list larger than the detour can hold publishes nothing rather than a silent subset: the reactive mask still
        // covers the held-modifier case, so only the simultaneous-press protection is dropped for that (pathological)
        // binding set, and the detour never evaluates a partial list.
        if (count > MAX_GAMEPAD_CONSUME_RULES)
        {
            count = 0;
        }
        // Seqlock write (single writer). The odd sequence brackets the update so a concurrent detour read sees the
        // whole new list or skips the frame. The release fence after the odd store keeps the rule stores from being
        // observed before the bracket opens; the release store of the even sequence publishes the finished list to the
        // detour's acquire load.
        const uint32_t seq = s_consume_rules_seq.load(std::memory_order_relaxed);
        s_consume_rules_seq.store(seq + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        for (std::size_t i = 0; i < count; ++i)
        {
            s_consume_rules[i].store(pack_consume_rule(rules[i]), std::memory_order_relaxed);
        }
        s_consume_rule_count.store(static_cast<uint32_t>(count), std::memory_order_relaxed);
        s_consume_rules_seq.store(seq + 2, std::memory_order_release);
    }

    uint16_t evaluate_published_consume_rules(uint16_t true_buttons) noexcept
    {
        // Seqlock read, single attempt (no spin): an odd sequence means the writer is mid-update, and a change across
        // the copy means the snapshot tore. In either case skip rule masking for this frame (the reactive mask still
        // applies); the next game poll, microseconds later, gets the settled list. Rules change only on a binding
        // rebuild, so a torn read is rare and never coincides with steady gameplay input.
        const uint32_t seq_before = s_consume_rules_seq.load(std::memory_order_acquire);
        if ((seq_before & 1u) != 0)
        {
            return 0;
        }
        uint32_t count = s_consume_rule_count.load(std::memory_order_relaxed);
        if (count > MAX_GAMEPAD_CONSUME_RULES)
        {
            count = MAX_GAMEPAD_CONSUME_RULES;
        }
        std::array<GamepadConsumeRule, MAX_GAMEPAD_CONSUME_RULES> snapshot{};
        for (uint32_t i = 0; i < count; ++i)
        {
            snapshot[i] = unpack_consume_rule(s_consume_rules[i].load(std::memory_order_relaxed));
        }
        // Order the rule loads above before the sequence re-read below, so a writer that updated mid-copy is always
        // detected.
        std::atomic_thread_fence(std::memory_order_acquire);
        if (s_consume_rules_seq.load(std::memory_order_relaxed) != seq_before)
        {
            return 0;
        }
        return evaluate_consume_rules(true_buttons, snapshot.data(), count);
    }

    void set_gamepad_rule_suppress_enabled(bool enabled) noexcept
    {
        s_rule_suppress_enabled.store(enabled, std::memory_order_relaxed);
    }

    bool install_xinput(int user_index) noexcept
    {
        s_bound_user_index.store(user_index, std::memory_order_relaxed);
        if (s_xinput_permanent_detour.load(std::memory_order_acquire))
        {
            const bool ready = s_xinput_original.load(std::memory_order_seq_cst) != nullptr;
            s_xinput_installed.store(ready, std::memory_order_release);
            return ready;
        }
        if (s_xinput_installed.load(std::memory_order_acquire))
        {
            return true;
        }

        HMODULE module = nullptr;
        for (const wchar_t *name : XINPUT_DLL_NAMES)
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
        // If the detour went live before the store, a game thread entering it in that window would read a null original
        // and wrongly report
        // ERROR_DEVICE_NOT_CONNECTED -- a transient fake disconnect for a frame.
        auto hook =
            safetyhook::InlineHook::create(allocator, get_state, reinterpret_cast<void *>(&xinput_get_state_detour),
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
            if (!s_xinput_enable_warned.exchange(true, std::memory_order_relaxed))
            {
                (void)log().try_log(
                    LogLevel::Warning,
                    "InputIntercept: XInputGetState hook created but enable() failed; gamepad input interception is "
                    "inactive. The poll loop will retry.");
            }
            return false;
        }

        // XInputGetStateEx (ordinal 100) carries the Guide button; a game that polls it would otherwise bypass the
        // mask. Hook it too when present; its absence is not an error. Skip it when a proxy/shim xinput DLL aliases the
        // ordinal to the same code address as XInputGetState: that address is already covered, and a second inline hook
        // on one prologue would capture the first hook's jmp as its "original" and corrupt the trampoline chain.
        auto *get_state_ex =
            reinterpret_cast<void *>(GetProcAddress(module, MAKEINTRESOURCEA(XINPUT_GET_STATE_EX_ORDINAL)));
        if (get_state_ex != nullptr && get_state_ex != get_state)
        {
            auto ex_hook = safetyhook::InlineHook::create(allocator, get_state_ex,
                                                          reinterpret_cast<void *>(&xinput_get_state_ex_detour),
                                                          safetyhook::InlineHook::StartDisabled);
            if (ex_hook)
            {
                s_xinput_ex_hook = std::move(ex_hook.value());
                s_xinput_ex_original.store(s_xinput_ex_hook.original<XInputGetStateFn>(), std::memory_order_release);
                if (!s_xinput_ex_hook.enable())
                {
                    s_xinput_ex_original.store(nullptr, std::memory_order_release);
                    s_xinput_ex_hook = {};
                    if (!s_xinput_ex_enable_warned.exchange(true, std::memory_order_relaxed))
                    {
                        (void)log().try_log(
                            LogLevel::Warning,
                            "InputIntercept: XInputGetStateEx (ordinal 100) hook created but enable() failed; the "
                            "Guide button will not be masked. Primary XInput interception remains active.");
                    }
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
        if (!s_xinput_installed.load(std::memory_order_acquire))
        {
            return nullptr;
        }
        return s_xinput_original.load(std::memory_order_acquire);
    }

    void publish_gamepad_suppress(uint16_t suppress_bits) noexcept
    {
        // Write the deadline before the mask (release on the mask). A detour that observes the new mask with acquire is
        // then guaranteed to also observe the refreshed deadline, so a fresh mask is never paired with a stale
        // (already-expired) deadline.
        s_suppress_deadline_ms.store(GetTickCount64() + SUPPRESS_TTL_MS, std::memory_order_relaxed);
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

        // Take the permanent keepalive BEFORE the detour becomes reachable. Once SetWindowLongPtrW publishes
        // wndproc_detour, no later restore can sever that reachability: a restore only redirects future dispatches, so
        // a frame already inside the detour (a modal size/move loop holds one for as long as the user drags the title
        // bar) survives it and eventually returns through this module's code. The module must therefore stay mapped
        // for the rest of the process from the moment the subclass first goes live -- and if the reference cannot be
        // taken, fail closed and let the poll loop retry rather than publish a detour whose code pages nothing keeps
        // mapped. One reference covers every window generation (WM_NCDESTROY re-arms installation for a re-created
        // window); the once-flag is set as soon as the acquire succeeds, so a failed swap below cannot double-acquire
        // on its retry. This runs on the poll thread, off the loader lock, while the module is fully live.
        if (!s_wndproc_ref_taken.load(std::memory_order_relaxed))
        {
            if (acquire_module_ref() == nullptr)
            {
                return false;
            }
            s_wndproc_ref_taken.store(true, std::memory_order_relaxed);
            DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Input);
        }

        // Publish the predecessor procedure and target window before the detour goes live. SetWindowLongPtrW makes
        // wndproc_detour reachable from the window's own message thread the instant it returns; if the predecessor were
        // stored only afterwards, a message dispatched in that gap would read a zero s_prev_wndproc and route to
        // DefWindowProcW instead of the game's real procedure. A top-level window always has a non-null WNDPROC, so a
        // zero read here means the slot is not readable yet. install_wndproc runs only on the single poll thread, so
        // DMK never races its own install here; a foreign subclasser that installs in the gap between this read and the
        // swap is reconciled from SetWindowLongPtrW's returned predecessor below.
        const LONG_PTR current = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
        if (current == 0)
        {
            return false;
        }
        s_prev_wndproc.store(current, std::memory_order_release);
        s_hwnd.store(hwnd, std::memory_order_release);

        // SetWindowLongPtr returns the previous value, or 0 on failure. Disambiguate a genuine zero predecessor from an
        // error via GetLastError.
        SetLastError(0);
        const LONG_PTR prev = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&wndproc_detour));
        if (prev == 0 && GetLastError() != 0)
        {
            // Swap failed: roll back the published predecessor so no stale handle survives a failed install.
            s_hwnd.store(nullptr, std::memory_order_release);
            s_prev_wndproc.store(0, std::memory_order_release);
            return false;
        }

        // SetWindowLongPtrW returns the WNDPROC it actually displaced. If a foreign subclasser installed itself in the
        // gap between our GetWindowLongPtrW read and this swap, that returned procedure -- not the predecessor we read
        // and published -- is the real next link in the chain. Adopt and republish it so wndproc_detour forwards to the
        // procedure that was on top at swap time, keeping the subclass chain intact rather than silently dropping the
        // foreign subclasser. The release store pairs with the detour's acquire load of s_prev_wndproc. A genuine zero
        // predecessor was already rejected as a failure above, so a non-zero mismatch is the only adoption case.
        if (prev != 0 && prev != current)
        {
            s_prev_wndproc.store(prev, std::memory_order_release);
        }

        // Drain any notches the wndproc detour latched while no binding owned the wheel. uninstall() drops the consume
        // flag but leaves the detour live (it may stay layered under a foreign subclass), so it keeps incrementing
        // s_wheel_count between an unbind and this re-arm. Without this reset the first take_wheel_counts() after a
        // re-bind would replay that stale backlog as a burst of phantom notches. This is a fresh-install transition
        // (the idempotent already-installed path returned above), so resetting here cannot discard counts a live
        // binding is about to consume.
        for (auto &count : s_wheel_count)
        {
            count.store(0, std::memory_order_relaxed);
        }

        s_wndproc_installed.store(true, std::memory_order_release);
        return true;
    }

    bool wndproc_installed() noexcept
    {
        return s_wndproc_installed.load(std::memory_order_acquire);
    }

    LONG_PTR wndproc_saved_procedure() noexcept
    {
        return s_prev_wndproc.load(std::memory_order_acquire);
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

    void seed_wheel_notches_for_test(const std::array<int, 4> &notches) noexcept
    {
        for (size_t dir = 0; dir < s_wheel_count.size(); ++dir)
        {
            // Saturate to the same ceiling the detour's bump_wheel_notch enforces, so a seeded backlog can never place
            // the counters in a state the real write site could not produce.
            int n = notches[dir];
            if (n < 0)
            {
                n = 0;
            }
            else if (n > MAX_WHEEL_NOTCHES)
            {
                n = MAX_WHEEL_NOTCHES;
            }
            s_wheel_count[dir].store(n, std::memory_order_relaxed);
        }
    }

    void publish_wheel_consume(uint8_t direction_mask) noexcept
    {
        // Refresh the deadline before the release store on the mask (only when arming a non-zero mask), so a detour
        // observing a set direction bit with acquire is guaranteed to also observe the fresh deadline. A zero mask
        // needs no deadline: the detour checks the direction bit first and forwards immediately when it is clear, so
        // skipping the clock read on the common all-forward path costs nothing and keeps the disarm cheap.
        if (direction_mask != 0)
        {
            s_wheel_consume_deadline_ms.store(GetTickCount64() + SUPPRESS_TTL_MS, std::memory_order_relaxed);
        }
        s_wheel_consume_mask.store(direction_mask, std::memory_order_release);
    }

    void uninstall() noexcept
    {
        // Stop masking before removing the hooks, with single-atomic stores only. Clearing the reactive mask stops
        // reactive masking and clearing the rule gate stops rule masking. Do NOT seqlock-publish an empty rule list
        // here:
        // that is a multi-step write, and a concurrent binding mutation (set_consume
        // / add_binding, serialized on InputPoller::m_bindings_rw_mutex) is a documented thread-safe call that could
        // race a second writer and tear the list. The published list is left as is; it is inert once the hooks are gone
        // and the gate is false, the binding-clear path already empties it under the lock, and a later install
        // republishes before re-enabling the gate.
        s_suppress_mask.store(0, std::memory_order_release);
        s_rule_suppress_enabled.store(false, std::memory_order_relaxed);
        s_wheel_consume_mask.store(0, std::memory_order_release);

        uninstall_wndproc();

        if (s_xinput_permanent_detour.load(std::memory_order_acquire))
        {
            // A prior timeout made the XInput detours permanent. There is no static hook handle left to restore, and
            // retiring the trampoline pointer would turn the still-installed detour into a fake disconnect. Treat this
            // call as a logical disarm only: masks are already clear, and the detour keeps forwarding through the
            // original so the game regains its controller input.
            s_xinput_installed.store(false, std::memory_order_release);
            s_xinput_enable_warned.store(false, std::memory_order_relaxed);
            s_xinput_ex_enable_warned.store(false, std::memory_order_relaxed);
            return;
        }

        // Retire the published trampoline pointers before draining. A game thread that already copied one keeps the
        // in-flight counter non-zero until it leaves; a late entrant after this point sees nullptr and returns a closed
        // result instead of taking a pointer into the hook object that teardown is about to destroy. These retire
        // stores are seq_cst so they and the drain load below join the same total order as the detour's increment and
        // trampoline load: without that, StoreLoad reordering could let this thread read a zero count while a detour
        // still holds a non-null trampoline (see InflightGuard).
        s_xinput_ex_original.store(nullptr, std::memory_order_seq_cst);
        s_xinput_original.store(nullptr, std::memory_order_seq_cst);

        // Quiesce XInput detours that might already have copied a trampoline before destroying the hook objects. The
        // poll thread is already joined, so the only remaining callers are the game's own XInput threads. SafetyHook
        // additionally relocates a thread caught mid-prologue during removal, so this drain shrinks the window rather
        // than being the sole guarantee. Use a short wall-clock bound instead of a yield count: a hot game thread can
        // keep entering the detour after the trampoline pointers are retired, and teardown must still make progress.
        constexpr uint64_t XINPUT_QUIESCE_TIMEOUT_MS = 10;
        const uint64_t quiesce_deadline_ms = GetTickCount64() + XINPUT_QUIESCE_TIMEOUT_MS;
        while (s_xinput_inflight.load(std::memory_order_seq_cst) != 0 && GetTickCount64() < quiesce_deadline_ms)
        {
            std::this_thread::yield();
        }

        const int still_inflight = s_xinput_inflight.load(std::memory_order_seq_cst);
        if (still_inflight != 0)
        {
            // Leak-on-timeout, never free-on-timeout. The bounded drain expired with game threads still executing a
            // detour body: a hot game thread can keep re-entering XInputGetState faster than a 10 ms quiesce can ever
            // observe zero. Destroying the InlineHook objects now frees the trampoline memory one of those threads is
            // still running through -- a use-after-free. Move the two hooks into a heap cell that is never freed
            // instead, so their trampolines stay mapped for the rest of the process. Promote both required keepalives
            // before publishing that state: one reference pins this module's detour code, and one pins the XInput
            // module whose patched prologue remains live. This is the same leak-on-purpose discipline Hook::~Hook and
            // StoppableWorker (under the loader lock) use; the 10 ms bound is unchanged, only the free is replaced with
            // a leak so teardown still makes progress.
            struct LeakedXInputHooks
            {
                safetyhook::InlineHook primary;
                safetyhook::InlineHook ex;
            };
            const HMODULE self_ref = DetourModKit::detail::acquire_module_ref();
            const HMODULE xinput_ref =
                (self_ref != nullptr) ? acquire_module_ref_containing_address(s_xinput_hook.target()) : nullptr;
            auto *leaked = (xinput_ref != nullptr)
                               ? new (std::nothrow)
                                     LeakedXInputHooks{std::move(s_xinput_hook), std::move(s_xinput_ex_hook)}
                               : nullptr;
            if (leaked != nullptr)
            {
                // Republish the trampoline pointers so the now-permanent detours forward through the original again.
                // Between the retire stores above and this point -- the 10 ms drain plus this leak-cell allocation --
                // the detours are live but read a null trampoline, so XInput polls in that transition window return
                // ERROR_DEVICE_NOT_CONNECTED. Retiring before the drain is the use-after-free guard: a late detour
                // entrant must read null, never a pointer into a hook object that teardown might still destroy. The
                // trampoline therefore cannot be republished until the leak commits and destruction is off the table;
                // republishing before the drain would reopen that UAF. The transition occurs only when the hooks first
                // become permanent. Later uninstall() calls take the permanent-detour disarm path above and leave the
                // trampoline published.
                s_xinput_original.store(leaked->primary.original<XInputGetStateFn>(), std::memory_order_seq_cst);
                s_xinput_ex_original.store(leaked->ex ? leaked->ex.original<XInputGetStateFn>() : nullptr,
                                           std::memory_order_seq_cst);
                s_xinput_permanent_detour.store(true, std::memory_order_release);
                s_xinput_installed.store(false, std::memory_order_release);
                DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Input);
                (void)log().try_log(LogLevel::Warning,
                                    "XInput interception: {} game thread(s) still inside a detour after a {} ms "
                                    "quiesce; leaked the hook trampolines instead of freeing them to stay memory-safe.",
                                    still_inflight, XINPUT_QUIESCE_TIMEOUT_MS);
                s_xinput_enable_warned.store(false, std::memory_order_relaxed);
                s_xinput_ex_enable_warned.store(false, std::memory_order_relaxed);
                return;
            }
            if (xinput_ref != nullptr)
            {
                DetourModKit::detail::release_module_ref(xinput_ref);
            }
            if (self_ref != nullptr)
            {
                DetourModKit::detail::release_module_ref(self_ref);
            }

            // The leak-cell allocation or one of the keepalive acquisitions failed under pressure, so the non-freeing
            // option is gone. Fall back to destroying in place: the retired trampoline pointers and best-effort drain
            // above already shrank the window, and SafetyHook relocates a thread caught mid-prologue during removal, so
            // this is the least-bad remaining choice rather than a fresh hazard.
            s_xinput_ex_hook = {};
            s_xinput_hook = {};
        }
        else
        {
            // Fully drained: no thread is inside a detour. Destroying the safetyhook objects rewrites the patched
            // prologue pages and, under a transient vectored exception handler, relocates the instruction pointer of
            // any thread caught mid-prologue (no thread is suspended). The saved trampoline pointers were cleared
            // before the drain above, so late detour entrants no longer acquire trampoline memory owned by these hook
            // objects.
            s_xinput_ex_hook = {};
            s_xinput_hook = {};
        }
        s_xinput_installed.store(false, std::memory_order_release);
        // Re-arm the enable()-failure latches so a fresh install after a hot-reload can warn again.
        s_xinput_enable_warned.store(false, std::memory_order_relaxed);
        s_xinput_ex_enable_warned.store(false, std::memory_order_relaxed);
    }

} // namespace DetourModKit::detail
