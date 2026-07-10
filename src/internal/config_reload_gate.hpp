#ifndef DETOURMODKIT_INTERNAL_CONFIG_RELOAD_GATE_HPP
#define DETOURMODKIT_INTERNAL_CONFIG_RELOAD_GATE_HPP

/**
 * @file internal/config_reload_gate.hpp
 * @brief Cross-TU control for quiescing background config reloads before a Logic DLL unload.
 * @details The config module drives reloads from two DMK-owned worker threads: the auto-reload watcher's debounced
 *          callback and the hotkey reload servicer. Both run consumer code -- registered setters and the user
 *          on_reload callback -- that lives in the (hot-reloadable) Logic DLL, not in DMK's own module. The counted
 *          module reference each worker holds keeps DMK's code pages mapped, but it does NOT keep the consumer's pages
 *          mapped. On a DllMain-detach unload the watcher/servicer are detached rather than joined, so a reload pass
 *          that flushes after unload would call setters / the callback into pages the loader has already reclaimed.
 *
 *          This gate closes that window. on_logic_dll_unload* latches background reloads off so no new pass starts,
 *          then waits (bounded) for any pass that was already running consumer code to finish before it returns and
 *          lets the caller unmap the Logic DLL. A fresh config lifecycle (a new load() after a prior unload) re-arms
 *          the gate. The primitives themselves (the latch and the in-flight counter) live in config.cpp next to the
 *          reload machinery; this header is only the seam the session/unload TU reaches them through.
 */

#include <chrono>

namespace DetourModKit::config::detail
{
    /**
     * @brief Latches background reloads (watcher callback + hotkey servicer) off for a Logic DLL unload.
     * @details Idempotent and noexcept. After this returns, a background reload pass that has not yet begun running
     *          consumer code is dropped at its entry gate; a pass already in flight is unaffected here and must be
     *          awaited with @ref await_reloads_quiesced. Set this BEFORE stopping the watcher/servicer so their final
     *          flush observes the disabled gate.
     */
    void disable_reloads_for_unload() noexcept;

    /**
     * @brief Bounded wait for any in-flight background reload pass to finish running consumer code.
     * @param timeout Upper bound on the wait. On expiry the caller proceeds best-effort (a genuinely wedged setter --
     *        one blocked on the loader lock the unload thread may hold -- must not be allowed to hang the unload).
     * @return true if the in-flight count reached zero within @p timeout; false on timeout.
     * @details Call after @ref disable_reloads_for_unload and after the watcher/servicer workers have been stopped, so
     *          no new pass can raise the count again. noexcept; only yields and reads an atomic.
     */
    [[nodiscard]] bool await_reloads_quiesced(std::chrono::milliseconds timeout) noexcept;

    /**
     * @brief Re-arms background reloads for a fresh config lifecycle (called from load()).
     * @details Clears the unload latch so a Logic DLL loaded after a prior unload-and-latch can reload again.
     *          Idempotent and noexcept; leaves the in-flight counter untouched (it is self-balancing -- every
     *          increment has a matching decrement -- so a straggler pass from a prior lifecycle still completes its
     *          own bookkeeping).
     */
    void rearm_reloads() noexcept;
} // namespace DetourModKit::config::detail

#endif // DETOURMODKIT_INTERNAL_CONFIG_RELOAD_GATE_HPP
