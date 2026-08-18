#ifndef DETOURMODKIT_INTERNAL_CONFIG_RELOAD_GATE_HPP
#define DETOURMODKIT_INTERNAL_CONFIG_RELOAD_GATE_HPP

/**
 * @file internal/config_reload_gate.hpp
 * @brief Cross-TU control for quiescing background config reloads before a Logic DLL unload.
 * @details The config module drives reloads from two DMK-owned worker threads: the auto-reload watcher's debounced
 *          callback and the hotkey reload servicer. Both run consumer code (registered setters and the user
 *          on_reload callback) that lives in the (hot-reloadable) Logic DLL, not in DMK's own module. The counted
 *          module reference each worker holds keeps DMK's code pages mapped, but it does NOT keep the consumer's pages
 *          mapped. On a DllMain-detach unload the watcher/servicer are detached rather than joined, so a reload pass
 *          that flushes after unload would call setters / the callback into pages the loader has already reclaimed.
 *
 *          This gate closes that window. Typed Logic-DLL preparation latches background reloads off so no new pass
 *          starts, requests worker stop without joining, and authorizes unmapping only after every admitted pass and
 *          worker body exits and their callable storage is destroyed. A fresh config lifecycle (a new load() after a
 *          prior unload) re-arms the gate. The primitives themselves live in src/internal/config_reload.cpp next to
 *          the reload lifecycle state. This header is only the seam the session TU reaches them through.
 */

#include <chrono>

namespace DetourModKit::config::detail
{
    /**
     * @enum ReloadDrainStatus
     * @brief Typed outcome of an off-loader-lock background-reload drain.
     */
    enum class ReloadDrainStatus
    {
        /// Stop was requested, or all workers and reload callbacks have exited and their callable storage was cleared.
        Ready,
        /// The deadline expired before the workers or callback bodies exited.
        TimedOut,
        /// The caller is a reload setter, watcher callback, or reload-servicer callback.
        SelfDelivery,
        /// Another control thread owns the drain transaction.
        InProgress
    };

    /**
     * @brief Latches background reloads (watcher callback + hotkey servicer) off for a Logic DLL unload.
     * @details Idempotent and noexcept. After this returns, a background reload pass that has not yet begun running
     *          consumer code is dropped at its entry gate; a pass already in flight is unaffected here and must be
     *          awaited by the typed drain. Set this BEFORE stopping the watcher/servicer so their final
     *          flush observes the disabled gate.
     */
    void disable_reloads_for_unload() noexcept;

    /**
     * @brief Closes reload admission and requests watcher and servicer stop without joining.
     * @return Ready when the request was accepted, SelfDelivery when the caller cannot drain itself, or InProgress
     *         when another control thread already owns the transaction. Call finish_reload_drain only after Ready.
     */
    [[nodiscard]] ReloadDrainStatus begin_reload_drain() noexcept;

    /**
     * @brief Waits to @p deadline for reload bodies and worker bodies to exit, then joins and clears callback storage.
     * @return Ready only after no registered setter, user reload callback, or worker callable remains; TimedOut
     *         otherwise.
     * @note Call only after begin_reload_drain() returned Ready.
     */
    [[nodiscard]] ReloadDrainStatus finish_reload_drain(std::chrono::steady_clock::time_point deadline) noexcept;

#if defined(DMK_ENABLE_TEST_SEAMS)
    /// Waits only for the background-reload body count, without stopping or destroying workers.
    [[nodiscard]] bool await_reloads_quiesced_for_test(std::chrono::milliseconds timeout) noexcept;
#endif

    /**
     * @brief Re-arms background reloads for a fresh config lifecycle (called from load()).
     * @details Clears the unload latch so a Logic DLL loaded after a prior unload-and-latch can reload again.
     *          Clearing a SET latch marks an unload-then-reload boundary and advances the lifecycle epoch, so a
     *          stale callback from the unloaded prior lifecycle is dropped even though the latch is now clear again;
     *          an ordinary re-load within one lifecycle (latch already clear) does not advance the epoch. Idempotent
     *          and noexcept. It leaves the in-flight counter untouched. That counter is self-balancing, because every
     *          increment has a matching decrement, so a straggler pass from a prior lifecycle still completes its own
     *          bookkeeping.
     */
    void rearm_reloads() noexcept;
} // namespace DetourModKit::config::detail

#endif // DETOURMODKIT_INTERNAL_CONFIG_RELOAD_GATE_HPP
