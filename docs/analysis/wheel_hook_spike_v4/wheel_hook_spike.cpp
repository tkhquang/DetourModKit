// PR-15 Stage 0 semantic spike: thread-scoped WH_GETMESSAGE wheel capture.
//
// Standalone harness. It edits no production source. It proves or refutes the message-hook semantics that the PR-15
// production architecture assumes (rollout plan, section "PR-15", Stage 0 cases 2 to 7 and 9, plus the synthetic half
// of case 1). Cases 1 (real game pump) and 8 (gameoverlayrenderer64) need a live game session and stay open in the
// analysis record.
//
// The resident hook below implements the planned production message-hook behavior:
//   - Process only HC_ACTION wheel messages.
//   - Fold and count on PM_REMOVE only.
//   - On PM_NOREMOVE, observe without changing counters or remainders.
//   - Save the original fields, write WM_NULL before CallNextHookEx, re-assert WM_NULL after it returns.
//   - Call CallNextHookEx exactly once.
// The fold arithmetic replicates src/internal/input_intercept.cpp accumulate_wheel_remainder: total = prior + delta;
// notches = total / WHEEL_DELTA (truncation toward zero); remainder = total % WHEEL_DELTA. Direction mapping: vertical
// positive = Up, vertical negative = Down, horizontal positive = Right, horizontal negative = Left. The production
// (epoch, owned) tagging is lease state machinery, not message semantics, and is out of spike scope.
//
// Build (Debug, both toolchains):
//   MinGW: g++ -std=c++23 -g -O0 -Wall -Wextra wheel_hook_spike.cpp -o wheel_hook_spike.exe -luser32
//   MSVC:  cl /std:c++latest /EHsc /W4 /Zi wheel_hook_spike.cpp user32.lib
//
// Output: TAP-style "ok"/"not ok" lines plus per-case event traces. Exit code 0 only when every non-skipped gate
// passes.

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

namespace
{
    // Event log.

    enum class Src : int
    {
        NewerHook,
        ResidentHook,
        OlderHook,
        Pump,    // message as retrieved by the pump, after the whole hook chain
        WndProc, // message as received by a window procedure
        Note,    // orchestrator or pump annotation
    };

    const char *src_name(Src s)
    {
        switch (s)
        {
        case Src::NewerHook:
            return "newer";
        case Src::ResidentHook:
            return "resident";
        case Src::OlderHook:
            return "older";
        case Src::Pump:
            return "pump";
        case Src::WndProc:
            return "wndproc";
        default:
            return "note";
        }
    }

    struct Event
    {
        int seq;
        Src src;
        DWORD tid;
        HWND hwnd;
        UINT msg;
        int delta;    // signed wheel delta when applicable, else 0
        UINT removal; // PM_REMOVE / PM_NOREMOVE for hook events, 2 = not a hook event
        const char *note;
    };

    constexpr UINT kNotAHookEvent = 2;

    std::mutex g_log_mutex;
    std::vector<Event> g_log;
    std::atomic<int> g_seq{0};

    void log_event(Src src, HWND hwnd, UINT msg, int delta, UINT removal, const char *note = "")
    {
        const std::lock_guard<std::mutex> lock(g_log_mutex);
        g_log.push_back(Event{g_seq.fetch_add(1), src, GetCurrentThreadId(), hwnd, msg, delta, removal, note});
    }

    std::vector<Event> snapshot_log()
    {
        const std::lock_guard<std::mutex> lock(g_log_mutex);
        return g_log;
    }

    void clear_log()
    {
        const std::lock_guard<std::mutex> lock(g_log_mutex);
        g_log.clear();
    }

    void dump_log(const char *case_name)
    {
        const std::vector<Event> events = snapshot_log();
        std::printf("# trace %s (%zu events)\n", case_name, events.size());
        for (const Event &e : events)
        {
            std::printf(
                "#   %4d %-8s tid=%5lu hwnd=%p msg=0x%04X delta=%+d %s %s\n",
                e.seq,
                src_name(e.src),
                static_cast<unsigned long>(e.tid),
                static_cast<void *>(e.hwnd),
                e.msg,
                e.delta,
                e.removal == PM_REMOVE ? "REMOVE" : (e.removal == PM_NOREMOVE ? "NOREMOVE" : "-"),
                e.note
            );
        }
    }

    // TAP state.

    int g_test_index = 0;
    int g_failures = 0;

    void check(bool ok, const char *what)
    {
        ++g_test_index;
        if (!ok)
        {
            ++g_failures;
        }
        std::printf("%s %d - %s\n", ok ? "ok" : "not ok", g_test_index, what);
    }

    void skip(const char *what)
    {
        ++g_test_index;
        std::printf("ok %d - # SKIP %s\n", g_test_index, what);
    }

    // Resident data plane.

    constexpr int kWheelDelta = WHEEL_DELTA;

    struct DataPlane
    {
        std::atomic<int> remainder_v{0};
        std::atomic<int> remainder_h{0};
        // Index: 0 Up, 1 Down, 2 Left, 3 Right. Matches the production s_wheel_count layout.
        std::atomic<int> counts[4]{};
        std::atomic<bool> consume{false};

        void reset()
        {
            remainder_v.store(0);
            remainder_h.store(0);
            for (auto &c : counts)
            {
                c.store(0);
            }
            consume.store(false);
        }
    };

    DataPlane g_plane;

    // Folds one delta exactly as accumulate_wheel_remainder does, single-pump-thread variant.
    int fold_delta(std::atomic<int> &slot, int delta)
    {
        const int prior = slot.load(std::memory_order_relaxed);
        const int total = prior + delta;
        const int notches = total / kWheelDelta;
        slot.store(total % kWheelDelta, std::memory_order_relaxed);
        return notches;
    }

    void count_notches(bool horizontal, int notches)
    {
        if (notches > 0)
        {
            g_plane.counts[horizontal ? 3 : 0].fetch_add(notches);
        }
        else if (notches < 0)
        {
            g_plane.counts[horizontal ? 2 : 1].fetch_add(-notches);
        }
    }

    // Hook callbacks.

    // Probe behavior toggles for cases 3b and 7.
    std::atomic<bool> g_older_rewrites_back{false};  // older hook restores the wheel after the resident consumed
    std::atomic<bool> g_newer_rewrites_after{false}; // newer hook rewrites the wheel after CallNextHookEx returns
    std::atomic<bool> g_newer_mutates_noremove{false};

    // Up-count observed by the filter scripts at their phase boundary (case 4).
    std::atomic<int> g_filtered_phase_up_count{-1};

    struct SavedWheel
    {
        UINT msg;
        WPARAM wp;
        LPARAM lp;
    };
    thread_local SavedWheel t_saved{};

    bool is_wheel(UINT msg)
    {
        return msg == WM_MOUSEWHEEL || msg == WM_MOUSEHWHEEL;
    }

    int wheel_delta_of(const MSG &m)
    {
        return static_cast<short>(HIWORD(m.wParam));
    }

    LRESULT CALLBACK resident_hook(int code, WPARAM wp, LPARAM lp)
    {
        if (code != HC_ACTION)
        {
            return CallNextHookEx(nullptr, code, wp, lp);
        }
        MSG *m = reinterpret_cast<MSG *>(lp);
        if (!is_wheel(m->message))
        {
            return CallNextHookEx(nullptr, code, wp, lp);
        }
        const bool horizontal = m->message == WM_MOUSEHWHEEL;
        const int delta = wheel_delta_of(*m);
        log_event(Src::ResidentHook, m->hwnd, m->message, delta, static_cast<UINT>(wp));
        if (wp != PM_REMOVE)
        {
            // PM_NOREMOVE: observe only. No counter, remainder, or message change.
            return CallNextHookEx(nullptr, code, wp, lp);
        }
        const int notches = fold_delta(horizontal ? g_plane.remainder_h : g_plane.remainder_v, delta);
        count_notches(horizontal, notches);
        if (!g_plane.consume.load())
        {
            return CallNextHookEx(nullptr, code, wp, lp);
        }
        // Consume: save, blank, forward once, re-assert.
        t_saved = SavedWheel{m->message, m->wParam, m->lParam};
        m->message = WM_NULL;
        m->wParam = 0;
        m->lParam = 0;
        const LRESULT r = CallNextHookEx(nullptr, code, wp, lp);
        m->message = WM_NULL;
        m->wParam = 0;
        m->lParam = 0;
        return r;
    }

    LRESULT CALLBACK newer_hook(int code, WPARAM wp, LPARAM lp)
    {
        if (code != HC_ACTION)
        {
            return CallNextHookEx(nullptr, code, wp, lp);
        }
        MSG *m = reinterpret_cast<MSG *>(lp);
        const bool wheel = is_wheel(m->message);
        const SavedWheel original{m->message, m->wParam, m->lParam};
        if (wheel)
        {
            log_event(Src::NewerHook, m->hwnd, m->message, wheel_delta_of(*m), static_cast<UINT>(wp));
        }
        if (wheel && wp == PM_NOREMOVE && g_newer_mutates_noremove.load())
        {
            // Deliberate NOREMOVE mutation. The queued copy must stay intact for the later PM_REMOVE.
            m->message = WM_NULL;
            m->wParam = 0;
            m->lParam = 0;
        }
        const LRESULT r = CallNextHookEx(nullptr, code, wp, lp);
        if (wheel && wp == PM_REMOVE && g_newer_rewrites_after.load())
        {
            // Newest-first chain order: this runs after the resident hook returned. The resident cannot
            // guard against it. This is the documented best-effort boundary.
            m->message = original.msg;
            m->wParam = original.wp;
            m->lParam = original.lp;
            log_event(
                Src::NewerHook,
                m->hwnd,
                original.msg,
                static_cast<short>(HIWORD(original.wp)),
                static_cast<UINT>(wp),
                "rewrote-after-return"
            );
        }
        return r;
    }

    LRESULT CALLBACK older_hook(int code, WPARAM wp, LPARAM lp)
    {
        if (code != HC_ACTION)
        {
            return CallNextHookEx(nullptr, code, wp, lp);
        }
        MSG *m = reinterpret_cast<MSG *>(lp);
        // Record what arrives here. After a resident consume this must already read WM_NULL.
        if (is_wheel(m->message) || m->message == WM_NULL)
        {
            log_event(
                Src::OlderHook,
                m->hwnd,
                m->message,
                is_wheel(m->message) ? wheel_delta_of(*m) : 0,
                static_cast<UINT>(wp)
            );
        }
        if (m->message == WM_NULL && wp == PM_REMOVE && g_older_rewrites_back.load() && t_saved.msg != 0)
        {
            // Runs inside the resident CallNextHookEx. The resident re-assert must win over this rewrite.
            m->message = t_saved.msg;
            m->wParam = t_saved.wp;
            m->lParam = t_saved.lp;
            log_event(Src::OlderHook, m->hwnd, t_saved.msg, 0, static_cast<UINT>(wp), "rewrote-inside-chain");
        }
        return CallNextHookEx(nullptr, code, wp, lp);
    }

    // Pump threads.

    constexpr UINT WM_APP_SENTINEL = WM_APP + 1;
    constexpr UINT WM_APP_SEND_WHEEL_TO_CHILD = WM_APP + 2;
    constexpr UINT WM_APP_RECREATE_ROOT = WM_APP + 3;
    constexpr UINT WM_APP_QUIT = WM_APP + 4;

    enum class Script : int
    {
        Classic,     // GetMessage / TranslateMessage / DispatchMessage
        NoRemove5,   // five PM_NOREMOVE peeks before every GetMessage
        FilterKeys,  // phase A: PM_REMOVE peeks filtered to the key range; phase B: unfiltered drain
        FilterWheel, // phase A: PM_REMOVE peeks filtered to WM_MOUSEWHEEL only; phase B: unfiltered drain
    };

    struct Pump
    {
        Script script = Script::Classic;
        bool with_window_set = false; // also create child, owned popup, unrelated top-level
        std::thread thread;
        DWORD tid = 0;
        HWND root = nullptr;
        HWND child = nullptr;
        HWND popup = nullptr;
        HWND unrelated = nullptr;
        HANDLE ready = nullptr;    // window set created, pump entering its loop
        HANDLE go = nullptr;       // orchestrator finished queueing, scripted phases can start
        HANDLE quiesced = nullptr; // sentinel dispatched or recreation done (auto-reset)
        std::atomic<bool> quit_seen{false};
    };

    LRESULT CALLBACK spike_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        Pump *pump = reinterpret_cast<Pump *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (msg)
        {
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
            log_event(Src::WndProc, hwnd, msg, static_cast<short>(HIWORD(wp)), kNotAHookEvent);
            // Fall through to DefWindowProc so the documented parent propagation, if any, occurs.
            break;
        case WM_NULL:
            log_event(Src::WndProc, hwnd, msg, 0, kNotAHookEvent);
            break;
        case WM_APP_SENTINEL:
            if (pump != nullptr)
            {
                SetEvent(pump->quiesced);
            }
            return 0;
        case WM_APP_SEND_WHEEL_TO_CHILD:
            if (pump != nullptr && pump->child != nullptr)
            {
                log_event(Src::Note, hwnd, msg, 0, kNotAHookEvent, "in-thread SendMessage wheel to child");
                SendMessageW(pump->child, WM_MOUSEWHEEL, MAKEWPARAM(0, static_cast<WORD>(120)), 0);
            }
            return 0;
        case WM_APP_QUIT:
            if (pump != nullptr)
            {
                pump->quit_seen.store(true);
            }
            PostQuitMessage(0);
            return 0;
        default:
            break;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }

    const wchar_t *ensure_window_class()
    {
        static const wchar_t *name = L"DmkWheelSpikeWindow";
        static bool registered = false;
        if (!registered)
        {
            WNDCLASSW wc{};
            wc.lpfnWndProc = &spike_wndproc;
            wc.hInstance = GetModuleHandleW(nullptr);
            wc.lpszClassName = name;
            RegisterClassW(&wc);
            registered = true;
        }
        return name;
    }

    HWND make_window(Pump *pump, const wchar_t *title, DWORD style, HWND parent_or_owner)
    {
        const HWND hwnd = CreateWindowExW(
            0,
            ensure_window_class(),
            title,
            style,
            0,
            0,
            320,
            240,
            parent_or_owner,
            nullptr,
            GetModuleHandleW(nullptr),
            nullptr
        );
        if (hwnd != nullptr)
        {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pump));
        }
        return hwnd;
    }

    void record_retrieved(const MSG &m, const char *note = "")
    {
        if (is_wheel(m.message) || m.message == WM_NULL)
        {
            log_event(Src::Pump, m.hwnd, m.message, is_wheel(m.message) ? wheel_delta_of(m) : 0, kNotAHookEvent, note);
        }
    }

    void pump_body(Pump *pump)
    {
        pump->tid = GetCurrentThreadId();
        pump->root = make_window(pump, L"spike-root", WS_OVERLAPPEDWINDOW, nullptr);
        if (pump->with_window_set)
        {
            pump->child = make_window(pump, L"spike-child", WS_CHILD | WS_VISIBLE, pump->root);
            pump->popup = make_window(pump, L"spike-popup", WS_POPUP, pump->root);
            pump->unrelated = make_window(pump, L"spike-unrelated", WS_OVERLAPPEDWINDOW, nullptr);
            SetFocus(pump->child);
        }
        SetEvent(pump->ready);

        MSG m{};
        switch (pump->script)
        {
        case Script::Classic:
            while (GetMessageW(&m, nullptr, 0, 0) > 0)
            {
                record_retrieved(m);
                if (m.message == WM_APP_RECREATE_ROOT)
                {
                    DestroyWindow(pump->root);
                    pump->root = make_window(pump, L"spike-root-2", WS_OVERLAPPEDWINDOW, nullptr);
                    log_event(Src::Note, pump->root, 0, 0, kNotAHookEvent, "root recreated on the same thread");
                    SetEvent(pump->quiesced);
                    continue;
                }
                TranslateMessage(&m);
                DispatchMessageW(&m);
            }
            break;
        case Script::NoRemove5:
            // The orchestrator queues the wheel before it signals `go`, so the five probes see it.
            // A MsgWaitForMultipleObjects variant of this loop deadlocked: an unfiltered PM_NOREMOVE
            // peek marks the whole queue checked, and QS_ALLINPUT then never wakes for a message that
            // was already queued behind the peeked one. That observation feeds the case 4 starvation
            // analysis. The GetMessage-driven form below has no such stale-input window.
            WaitForSingleObject(pump->go, 10000);
            while (true)
            {
                MSG probe{};
                for (int i = 0; i < 5; ++i)
                {
                    if (PeekMessageW(&probe, nullptr, 0, 0, PM_NOREMOVE) != 0)
                    {
                        record_retrieved(probe, "noremove-probe");
                    }
                }
                if (GetMessageW(&m, nullptr, 0, 0) <= 0)
                {
                    break;
                }
                record_retrieved(m, "after-probes");
                TranslateMessage(&m);
                DispatchMessageW(&m);
            }
            break;
        case Script::FilterKeys:
        case Script::FilterWheel:
        {
            WaitForSingleObject(pump->go, 10000);
            const UINT lo = pump->script == Script::FilterKeys ? WM_KEYFIRST : WM_MOUSEWHEEL;
            const UINT hi = pump->script == Script::FilterKeys ? WM_KEYLAST : WM_MOUSEWHEEL;
            int filtered_hits = 0;
            for (int i = 0; i < 10; ++i)
            {
                if (PeekMessageW(&m, nullptr, lo, hi, PM_REMOVE) != 0)
                {
                    ++filtered_hits;
                    record_retrieved(m, "filtered-remove");
                    if (is_wheel(m.message) || m.message == WM_NULL)
                    {
                        DispatchMessageW(&m);
                    }
                }
            }
            std::printf(
                "# %s: filtered phase retrieved %d message(s)\n",
                pump->script == Script::FilterKeys ? "filter-keys" : "filter-wheel",
                filtered_hits
            );
            // Deterministic phase-boundary snapshot: the orchestrator reads this instead of racing a sleep
            // against the unfiltered drain below.
            g_filtered_phase_up_count.store(g_plane.counts[0].load());
            while (GetMessageW(&m, nullptr, 0, 0) > 0)
            {
                record_retrieved(m, "unfiltered-drain");
                TranslateMessage(&m);
                DispatchMessageW(&m);
            }
            break;
        }
        }

        if (pump->root != nullptr && IsWindow(pump->root))
        {
            DestroyWindow(pump->root);
        }
        if (pump->popup != nullptr && IsWindow(pump->popup))
        {
            DestroyWindow(pump->popup);
        }
        if (pump->unrelated != nullptr && IsWindow(pump->unrelated))
        {
            DestroyWindow(pump->unrelated);
        }
    }

    Pump *start_pump(Script script, bool with_window_set = false)
    {
        Pump *pump = new Pump();
        pump->script = script;
        pump->with_window_set = with_window_set;
        pump->ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        pump->go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        pump->quiesced = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        pump->thread = std::thread(pump_body, pump);
        WaitForSingleObject(pump->ready, 10000);
        return pump;
    }

    // Quiesce: the sentinel is posted last, so its dispatch proves every earlier posted message was retrieved.
    bool quiesce(Pump *pump)
    {
        PostMessageW(pump->root, WM_APP_SENTINEL, 0, 0);
        return WaitForSingleObject(pump->quiesced, 10000) == WAIT_OBJECT_0;
    }

    void finish_pump(Pump *pump)
    {
        PostMessageW(pump->root, WM_APP_QUIT, 0, 0);
        // Bounded join: one stuck pump must fail its own case, not strand the whole spike.
        const HANDLE th = OpenThread(SYNCHRONIZE, FALSE, pump->tid);
        const DWORD waited = th != nullptr ? WaitForSingleObject(th, 15000) : WAIT_FAILED;
        if (th != nullptr)
        {
            CloseHandle(th);
        }
        if (waited != WAIT_OBJECT_0)
        {
            std::printf(
                "# finish_pump: pump tid=%lu did not exit in 15 s, detaching\n",
                static_cast<unsigned long>(pump->tid)
            );
            pump->thread.detach();
            return; // leak the Pump and its events deliberately, the process is about to report anyway
        }
        pump->thread.join();
        CloseHandle(pump->ready);
        CloseHandle(pump->go);
        CloseHandle(pump->quiesced);
        delete pump;
    }

    void post_wheel(HWND hwnd, bool horizontal, int delta)
    {
        PostMessageW(
            hwnd,
            horizontal ? WM_MOUSEHWHEEL : WM_MOUSEWHEEL,
            MAKEWPARAM(0, static_cast<WORD>(static_cast<short>(delta))),
            0
        );
    }

    HHOOK hook_thread(HOOKPROC proc, DWORD tid)
    {
        // hMod == nullptr with a same-process target thread. This matches the planned host architecture.
        return SetWindowsHookExW(WH_GETMESSAGE, proc, nullptr, tid);
    }

    // Log queries.

    int count_events(const std::vector<Event> &events, Src src, UINT msg, UINT removal)
    {
        int n = 0;
        for (const Event &e : events)
        {
            if (e.src == src && e.msg == msg && (removal == kNotAHookEvent || e.removal == removal))
            {
                ++n;
            }
        }
        return n;
    }

    int counts(int idx)
    {
        return g_plane.counts[idx].load();
    }

    void reset_case()
    {
        clear_log();
        g_plane.reset();
        g_older_rewrites_back.store(false);
        g_newer_rewrites_after.store(false);
        g_newer_mutates_noremove.store(false);
        g_filtered_phase_up_count.store(-1);
    }

    // Cases.

    // Case 1 (synthetic half): vertical and horizontal capture through a GetMessage/Dispatch pump.
    void case1_capture_baseline()
    {
        std::printf("# enter case1_capture_baseline\n");
        reset_case();
        Pump *pump = start_pump(Script::Classic);
        const HHOOK hook = hook_thread(&resident_hook, pump->tid);
        check(hook != nullptr, "case1: thread-scoped WH_GETMESSAGE installs with hMod == nullptr");
        for (int i = 0; i < 3; ++i)
        {
            post_wheel(pump->root, false, 120);
        }
        post_wheel(pump->root, false, -120);
        post_wheel(pump->root, true, 120);
        post_wheel(pump->root, true, 120);
        post_wheel(pump->root, true, -120);
        check(quiesce(pump), "case1: pump quiesced");
        check(
            counts(0) == 3 && counts(1) == 1 && counts(3) == 2 && counts(2) == 1,
            "case1: four-direction counts Up=3 Down=1 Right=2 Left=1"
        );
        const std::vector<Event> events = snapshot_log();
        check(
            count_events(events, Src::ResidentHook, WM_MOUSEWHEEL, PM_REMOVE) == 4,
            "case1: hook saw each vertical message exactly once with PM_REMOVE"
        );
        check(
            count_events(events, Src::ResidentHook, WM_MOUSEHWHEEL, PM_REMOVE) == 3,
            "case1: hook saw each horizontal message exactly once with PM_REMOVE"
        );
        check(
            count_events(events, Src::WndProc, WM_MOUSEWHEEL, kNotAHookEvent) >= 4,
            "case1: consume off, the window procedure still received the vertical wheel messages"
        );
        UnhookWindowsHookEx(hook);
        finish_pump(pump);
        dump_log("case1");
    }

    // Case 2: partial-delta folding and reversal cancellation, replicated fold arithmetic.
    void case2_partial_folding()
    {
        std::printf("# enter case2_partial_folding\n");
        reset_case();
        Pump *pump = start_pump(Script::Classic);
        const HHOOK hook = hook_thread(&resident_hook, pump->tid);
        // Vertical: 40+40+40 = one Up. 60-60 = nothing. 80+50 = one Up, remainder 10. 10-130 = one Down, rem 0.
        for (const int d : {40, 40, 40, 60, -60, 80, 50, -130})
        {
            post_wheel(pump->root, false, d);
        }
        // Horizontal: 30*4 = one Right. Then -120 = one Left.
        for (const int d : {30, 30, 30, 30, -120})
        {
            post_wheel(pump->root, true, d);
        }
        check(quiesce(pump), "case2: pump quiesced");
        check(counts(0) == 2 && counts(1) == 1, "case2: vertical folds Up=2 Down=1 from partial deltas");
        check(counts(3) == 1 && counts(2) == 1, "case2: horizontal folds Right=1 Left=1 from partial deltas");
        check(
            g_plane.remainder_v.load() == 0 && g_plane.remainder_h.load() == 0,
            "case2: both remainders returned to zero"
        );
        UnhookWindowsHookEx(hook);
        finish_pump(pump);
        dump_log("case2");
    }

    // Case 3: repeated PM_NOREMOVE peeks count nothing; the eventual removal counts exactly once.
    void case3_noremove_semantics()
    {
        std::printf("# enter case3_noremove_semantics\n");
        reset_case();
        Pump *pump = start_pump(Script::NoRemove5);
        const HHOOK hook = hook_thread(&resident_hook, pump->tid);
        post_wheel(pump->root, false, 120);
        SetEvent(pump->go);
        check(quiesce(pump), "case3: pump quiesced");
        const std::vector<Event> events = snapshot_log();
        const int noremove = count_events(events, Src::ResidentHook, WM_MOUSEWHEEL, PM_NOREMOVE);
        const int removes = count_events(events, Src::ResidentHook, WM_MOUSEWHEEL, PM_REMOVE);
        check(noremove >= 5, "case3: hook fired for repeated PM_NOREMOVE peeks");
        check(removes == 1, "case3: hook fired exactly once with PM_REMOVE");
        check(counts(0) == 1, "case3: counter advanced exactly once");
        UnhookWindowsHookEx(hook);
        finish_pump(pump);
        dump_log("case3");
    }

    // Case 3 extension: a NOREMOVE-time mutation must not corrupt the queued copy.
    void case3b_noremove_mutation_isolated()
    {
        std::printf("# enter case3b_noremove_mutation_isolated\n");
        reset_case();
        g_newer_mutates_noremove.store(true);
        Pump *pump = start_pump(Script::NoRemove5);
        const HHOOK resident = hook_thread(&resident_hook, pump->tid);
        const HHOOK newer = hook_thread(&newer_hook, pump->tid);
        post_wheel(pump->root, false, 120);
        SetEvent(pump->go);
        check(quiesce(pump), "case3b: pump quiesced");
        check(counts(0) == 1, "case3b: NOREMOVE-time mutation left the queued copy intact, removal counted once");
        UnhookWindowsHookEx(newer);
        UnhookWindowsHookEx(resident);
        finish_pump(pump);
        dump_log("case3b");
    }

    // Case 4: filtered peek loops. A non-matching filter must not retrieve or count the wheel and must not
    // starve the matching traffic. A wheel-range filter retrieves and counts it.
    void case4_filtered_peeks()
    {
        std::printf("# enter case4_filtered_peeks\n");
        reset_case();
        {
            Pump *pump = start_pump(Script::FilterKeys);
            const HHOOK hook = hook_thread(&resident_hook, pump->tid);
            post_wheel(pump->root, false, 120);
            PostMessageW(pump->root, WM_KEYDOWN, 'A', 0);
            PostMessageW(pump->root, WM_KEYUP, 'A', 0);
            SetEvent(pump->go);
            check(quiesce(pump), "case4a: pump quiesced");
            check(
                g_filtered_phase_up_count.load() == 0,
                "case4a: key-range filtered peeks did not count the queued wheel"
            );
            check(counts(0) == 1, "case4a: the unfiltered drain then counted the wheel exactly once");
            const std::vector<Event> events = snapshot_log();
            check(
                count_events(events, Src::ResidentHook, WM_MOUSEWHEEL, PM_REMOVE) == 1,
                "case4a: hook saw exactly one wheel removal overall"
            );
            UnhookWindowsHookEx(hook);
            finish_pump(pump);
            dump_log("case4a");
        }
        reset_case();
        {
            Pump *pump = start_pump(Script::FilterWheel);
            const HHOOK hook = hook_thread(&resident_hook, pump->tid);
            PostMessageW(pump->root, WM_KEYDOWN, 'B', 0);
            post_wheel(pump->root, false, 120);
            SetEvent(pump->go);
            check(quiesce(pump), "case4b: pump quiesced");
            check(counts(0) == 1, "case4b: a wheel-range filtered PM_REMOVE peek counted the wheel once");
            UnhookWindowsHookEx(hook);
            finish_pump(pump);
            dump_log("case4b");
        }
    }

    // Case 5: root, focused child, owned popup, unrelated top-level on one thread. The thread hook sees
    // every queue delivery. Root-ancestor resolution gives the filter policy its inputs.
    void case5_window_set()
    {
        std::printf("# enter case5_window_set\n");
        reset_case();
        Pump *pump = start_pump(Script::Classic, true);
        const HHOOK hook = hook_thread(&resident_hook, pump->tid);
        post_wheel(pump->root, false, 120);
        post_wheel(pump->child, false, 120);
        post_wheel(pump->popup, false, 120);
        post_wheel(pump->unrelated, false, 120);
        check(quiesce(pump), "case5: pump quiesced");
        const std::vector<Event> events = snapshot_log();
        int seen_root = 0;
        int seen_child = 0;
        int seen_popup = 0;
        int seen_unrelated = 0;
        for (const Event &e : events)
        {
            if (e.src == Src::ResidentHook && e.removal == PM_REMOVE && e.msg == WM_MOUSEWHEEL)
            {
                if (e.hwnd == pump->root)
                {
                    ++seen_root;
                }
                else if (e.hwnd == pump->child)
                {
                    ++seen_child;
                }
                else if (e.hwnd == pump->popup)
                {
                    ++seen_popup;
                }
                else if (e.hwnd == pump->unrelated)
                {
                    ++seen_unrelated;
                }
            }
        }
        check(
            seen_root == 1 && seen_child == 1 && seen_popup == 1 && seen_unrelated == 1,
            "case5: the thread hook observed queue delivery to all four windows"
        );
        const bool child_roots_to_root = GetAncestor(pump->child, GA_ROOT) == pump->root;
        const bool popup_is_own_root = GetAncestor(pump->popup, GA_ROOT) == pump->popup;
        const bool unrelated_is_own_root = GetAncestor(pump->unrelated, GA_ROOT) == pump->unrelated;
        check(
            child_roots_to_root && popup_is_own_root && unrelated_is_own_root,
            "case5: GA_ROOT maps child->root, popup->popup, unrelated->unrelated for the filter policy"
        );
        UnhookWindowsHookEx(hook);
        finish_pump(pump);
        dump_log("case5");
    }

    // Case 6: PostMessage vs SendMessage vs parent propagation. WH_GETMESSAGE sees queue retrieval only.
    void case6_delivery_paths()
    {
        std::printf("# enter case6_delivery_paths\n");
        reset_case();
        Pump *pump = start_pump(Script::Classic, true);
        const HHOOK hook = hook_thread(&resident_hook, pump->tid);

        // Posted to the focused child: retrieved through the queue, then DefWindowProc propagation follows.
        post_wheel(pump->child, false, 120);
        check(quiesce(pump), "case6: pump quiesced after the posted wheel");
        std::vector<Event> events = snapshot_log();
        const int hook_hits_posted = count_events(events, Src::ResidentHook, WM_MOUSEWHEEL, PM_REMOVE);
        const int wndproc_wheel_hits = count_events(events, Src::WndProc, WM_MOUSEWHEEL, kNotAHookEvent);
        check(hook_hits_posted == 1, "case6: the posted child wheel produced exactly one hook removal event");
        std::printf(
            "# case6: wndproc wheel observations after one posted child wheel: %d "
            "(a second observation is DefWindowProc parent propagation, invisible to the hook)\n",
            wndproc_wheel_hits
        );

        // In-thread SendMessage: direct call, never retrieved, the hook must not fire.
        clear_log();
        PostMessageW(pump->root, WM_APP_SEND_WHEEL_TO_CHILD, 0, 0);
        check(quiesce(pump), "case6: pump quiesced after the in-thread SendMessage command");
        events = snapshot_log();
        check(
            count_events(events, Src::ResidentHook, WM_MOUSEWHEEL, kNotAHookEvent) == 0,
            "case6: an in-thread SendMessage wheel never reached the WH_GETMESSAGE hook"
        );
        check(
            count_events(events, Src::WndProc, WM_MOUSEWHEEL, kNotAHookEvent) >= 1,
            "case6: the same SendMessage wheel did reach the window procedure"
        );

        // Cross-thread SendMessage: delivered during message-wait processing, still not a retrieval.
        clear_log();
        DWORD_PTR send_result = 0;
        const LRESULT sent =
            SendMessageTimeoutW(pump->child, WM_MOUSEWHEEL, MAKEWPARAM(0, 120), 0, SMTO_NORMAL, 5000, &send_result);
        check(sent != 0, "case6: the cross-thread SendMessage completed");
        check(quiesce(pump), "case6: pump quiesced after the cross-thread SendMessage");
        events = snapshot_log();
        check(
            count_events(events, Src::ResidentHook, WM_MOUSEWHEEL, kNotAHookEvent) == 0,
            "case6: a cross-thread SendMessage wheel never reached the WH_GETMESSAGE hook"
        );
        check(
            count_events(events, Src::WndProc, WM_MOUSEWHEEL, kNotAHookEvent) >= 1,
            "case6: the same cross-thread wheel did reach the window procedure"
        );
        UnhookWindowsHookEx(hook);
        finish_pump(pump);
        dump_log("case6-final-phase");
    }

    // Case 7: deterministic older and newer hooks prove chain order, consume mutation order, and the
    // best-effort boundary.
    void case7_hook_chain()
    {
        std::printf("# enter case7_hook_chain\n");
        // Phase A: chain order and the consume path against an older rewriter.
        reset_case();
        Pump *pump = start_pump(Script::Classic);
        const HHOOK older = hook_thread(&older_hook, pump->tid);
        const HHOOK resident = hook_thread(&resident_hook, pump->tid);
        const HHOOK newer = hook_thread(&newer_hook, pump->tid);
        g_plane.consume.store(true);
        g_older_rewrites_back.store(true);
        post_wheel(pump->root, false, 120);
        check(quiesce(pump), "case7a: pump quiesced");
        std::vector<Event> events = snapshot_log();
        int newer_seq = -1;
        int resident_seq = -1;
        int older_seq = -1;
        int pump_null_seq = -1;
        int pump_wheel_seq = -1;
        bool older_saw_null = false;
        for (const Event &e : events)
        {
            if (e.src == Src::NewerHook && e.msg == WM_MOUSEWHEEL && e.removal == PM_REMOVE && newer_seq < 0)
            {
                newer_seq = e.seq;
            }
            if (e.src == Src::ResidentHook && e.msg == WM_MOUSEWHEEL && e.removal == PM_REMOVE && resident_seq < 0)
            {
                resident_seq = e.seq;
            }
            if (e.src == Src::OlderHook && e.removal == PM_REMOVE && older_seq < 0)
            {
                older_seq = e.seq;
            }
            if (e.src == Src::OlderHook && e.msg == WM_NULL)
            {
                older_saw_null = true;
            }
            if (e.src == Src::Pump && e.msg == WM_NULL && pump_null_seq < 0)
            {
                pump_null_seq = e.seq;
            }
            if (e.src == Src::Pump && e.msg == WM_MOUSEWHEEL && pump_wheel_seq < 0)
            {
                pump_wheel_seq = e.seq;
            }
        }
        check(
            newer_seq >= 0 && resident_seq > newer_seq && older_seq > resident_seq,
            "case7a: chain order is newest first: newer -> resident -> older"
        );
        check(older_saw_null, "case7a: the older hook received WM_NULL after the resident consume");
        check(
            pump_null_seq >= 0 && pump_wheel_seq < 0,
            "case7a: the re-assert defeated the older rewrite, the pump retrieved WM_NULL"
        );
        check(counts(0) == 1, "case7a: the consumed wheel still counted once");
        dump_log("case7a");

        // Phase B: a newer hook rewrites after the resident returned. Best effort by design.
        clear_log();
        g_plane.reset();
        g_plane.consume.store(true);
        g_older_rewrites_back.store(false);
        g_newer_rewrites_after.store(true);
        post_wheel(pump->root, false, 120);
        check(quiesce(pump), "case7b: pump quiesced");
        events = snapshot_log();
        bool pump_saw_wheel = false;
        for (const Event &e : events)
        {
            if (e.src == Src::Pump && e.msg == WM_MOUSEWHEEL)
            {
                pump_saw_wheel = true;
            }
        }
        check(
            pump_saw_wheel,
            "case7b: a newer hook rewrote the message after the resident returned, the consume is best effort"
        );
        UnhookWindowsHookEx(newer);
        UnhookWindowsHookEx(resident);
        UnhookWindowsHookEx(older);
        finish_pump(pump);
        dump_log("case7b");
    }

    // Case 9: thread migration, same-thread window recreation, and target-thread exit.
    void case9_thread_identity()
    {
        std::printf("# enter case9_thread_identity\n");
        // 9a: migrate the hook from thread 1 to thread 2 with no overlap and no double count.
        reset_case();
        Pump *p1 = start_pump(Script::Classic);
        Pump *p2 = start_pump(Script::Classic);
        HHOOK hook = hook_thread(&resident_hook, p1->tid);
        post_wheel(p1->root, false, 120);
        check(quiesce(p1), "case9a: thread 1 quiesced while hooked");
        check(counts(0) == 1, "case9a: thread 1 wheel counted while hooked");
        check(UnhookWindowsHookEx(hook) != 0, "case9a: unhook from thread 1 succeeded");
        hook = hook_thread(&resident_hook, p2->tid);
        check(hook != nullptr, "case9a: remount on thread 2 succeeded");
        post_wheel(p1->root, false, 120); // unhooked thread: must not count
        post_wheel(p2->root, false, 120); // hooked thread: must count
        check(quiesce(p1) && quiesce(p2), "case9a: both threads quiesced");
        check(counts(0) == 2, "case9a: exactly one new count came from thread 2, none from unhooked thread 1");
        const std::vector<Event> events = snapshot_log();
        int hook_events_on_t1 = 0;
        for (const Event &e : events)
        {
            if (e.src == Src::ResidentHook && e.tid == p1->tid && e.removal == PM_REMOVE)
            {
                ++hook_events_on_t1;
            }
        }
        check(hook_events_on_t1 == 1, "case9a: thread 1 produced no hook event after its unhook");
        dump_log("case9a");

        // 9b: same-thread window recreation. The thread hook needs no remount.
        clear_log();
        g_plane.reset();
        PostMessageW(p2->root, WM_APP_RECREATE_ROOT, 0, 0);
        check(WaitForSingleObject(p2->quiesced, 10000) == WAIT_OBJECT_0, "case9b: root recreated");
        post_wheel(p2->root, false, 120);
        check(quiesce(p2), "case9b: recreated-window pump quiesced");
        check(counts(0) == 1, "case9b: the thread hook captured the recreated window without a remount");
        dump_log("case9b");

        // 9c: target-thread exit with the hook still installed.
        finish_pump(p1);
        const HWND dead_root = p2->root;
        finish_pump(p2); // thread 2 exits while `hook` is still installed on it
        const BOOL unhook_after_exit = UnhookWindowsHookEx(hook);
        const DWORD unhook_error = unhook_after_exit != 0 ? 0 : GetLastError();
        std::printf(
            "# case9c: UnhookWindowsHookEx after target-thread exit returned %ld (GetLastError=%lu)\n",
            static_cast<long>(unhook_after_exit),
            static_cast<unsigned long>(unhook_error)
        );
        check(true, "case9c: unhook after target-thread exit recorded (cleanup only, result above)");
        const BOOL post_to_dead = PostMessageW(dead_root, WM_MOUSEWHEEL, MAKEWPARAM(0, 120), 0);
        check(post_to_dead == 0, "case9c: posting to the dead thread's window fails closed");
    }
} // namespace

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    // Watchdog: a hung pump must not hang the whole spike. The exit code 3 marks a watchdog abort.
    std::thread(
        []
        {
            Sleep(180000);
            std::printf("# WATCHDOG: spike exceeded 180 s, aborting\n");
            ExitProcess(3);
        }
    ).detach();

    // Host identity for the analysis record.
    using RtlGetVersionFn = LONG(WINAPI *)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW osv{};
    osv.dwOSVersionInfoSize = sizeof(osv);
    if (const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll"))
    {
        if (const auto fn =
                reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void *>(GetProcAddress(ntdll, "RtlGetVersion"))))
        {
            fn(&osv);
        }
    }
    std::printf(
        "# wheel_hook_spike: Windows %lu.%lu build %lu\n",
        osv.dwMajorVersion,
        osv.dwMinorVersion,
        osv.dwBuildNumber
    );
#if defined(_MSC_VER) && !defined(__GNUC__)
    std::printf("# toolchain: MSVC %d\n", _MSC_VER);
#elif defined(__GNUC__)
    std::printf("# toolchain: GCC %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif

    case1_capture_baseline();
    case2_partial_folding();
    case3_noremove_semantics();
    case3b_noremove_mutation_isolated();
    case4_filtered_peeks();
    case5_window_set();
    case6_delivery_paths();
    case7_hook_chain();
    case9_thread_identity();

    skip("case1 real-game half: requires a live game message pump");
    skip("case8: requires the game with gameoverlayrenderer64 present");

    std::printf("1..%d\n", g_test_index);
    std::printf(
        "# result: %s (%d checks, %d failures)\n",
        g_failures == 0 ? "GREEN (deterministic gates)" : "RED",
        g_test_index,
        g_failures
    );
    return g_failures == 0 ? 0 : 1;
}
