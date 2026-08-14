/**
 * @file config_reload.cpp
 * @brief This TU owns the reload control plane: the pass lock, the background-reload lifecycle gate, and the drain.
 *
 * The data-plane pass lives in config.cpp and the watcher control plane in config_watch.cpp. Both reach this state
 * through internal/config_reload_lifecycle.hpp. The session TU reaches the drain through
 * internal/config_reload_gate.hpp.
 */

#include "internal/config_reload_gate.hpp"
#include "internal/config_reload_lifecycle.hpp"
#include "internal/config_watch_control.hpp"

#include "DetourModKit/config.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>

namespace DetourModKit
{
    namespace config
    {
        namespace
        {
            // Serializes an entire reload/load pass (read + content-hash decision + deferred-setter application).
            // Setters run after the config mutex is released, so this separate lock prevents stale pass reorder.
            // Two reload drivers can otherwise advance the cached hash before an older pass applies its stale snapshot.
            std::mutex &get_reload_apply_mutex()
            {
                static std::mutex s_mtx;
                return s_mtx;
            }

            // This thread-local marker detects pass-lock re-entry without publication of a cross-thread owner id.
            bool &reload_apply_lock_slot() noexcept
            {
                thread_local bool s_held = false;
                return s_held;
            }

            // The background-reload gate stops new passes through its latch and tracks an active pass through the
            // in-flight count. Bit zero is the unload latch. The other even bits form the lifecycle epoch. Together
            // they make an unload/rearm transition atomic, so no callback can observe a clear latch with the previous
            // epoch. See internal/config_reload_gate.hpp.
            inline constexpr std::uint64_t RELOADS_DISABLED_BIT = 1;

            std::atomic<std::uint64_t> &reload_lifecycle_state() noexcept
            {
                static std::atomic<std::uint64_t> s_state{0};
                return s_state;
            }

            std::atomic<bool> &reload_drain_active() noexcept
            {
                static std::atomic<bool> s_active{false};
                return s_active;
            }

            // Counts background reload passes that execute consumer code. Safe-drain finalization reads this count
            // after the latch store.
            std::atomic<int> &reload_in_flight_count() noexcept
            {
                static std::atomic<int> s_in_flight{0};
                return s_in_flight;
            }

            bool reloads_quiesced_now() noexcept
            {
                return reload_in_flight_count().load(std::memory_order_seq_cst) == 0;
            }
        } // anonymous namespace

        namespace detail
        {
            ReloadApplyLock::ReloadApplyLock()
            {
                if (reload_apply_lock_slot())
                {
                    // Same-thread re-entry causes a self-deadlock. Do NOT lock. Leave disengaged.
                    return;
                }
                m_lock = std::unique_lock<std::mutex>(get_reload_apply_mutex());
                reload_apply_lock_slot() = true;
                m_engaged = true;
            }

            ReloadApplyLock::~ReloadApplyLock() noexcept
            {
                unlock();
            }

            void ReloadApplyLock::unlock() noexcept
            {
                if (m_engaged && m_lock.owns_lock())
                {
                    reload_apply_lock_slot() = false;
                    m_lock.unlock();
                }
            }

            bool reload_apply_lock_held_by_current_thread() noexcept
            {
                return reload_apply_lock_slot();
            }

            std::uint64_t current_reload_lifecycle_epoch() noexcept
            {
                return reload_lifecycle_state().load(std::memory_order_seq_cst) & ~RELOADS_DISABLED_BIT;
            }

            bool background_reloads_disabled() noexcept
            {
                return (reload_lifecycle_state().load(std::memory_order_seq_cst) & RELOADS_DISABLED_BIT) != 0;
            }

            BackgroundReloadGuard::BackgroundReloadGuard(std::uint64_t expected_epoch) noexcept
                : m_expected_epoch(expected_epoch)
            {
                if (!lifecycle_current())
                {
                    return;
                }
                reload_in_flight_count().fetch_add(1, std::memory_order_seq_cst);
                if (!lifecycle_current())
                {
                    // The unload state changed between the first check and admission. Back out.
                    reload_in_flight_count().fetch_sub(1, std::memory_order_seq_cst);
                    return;
                }
                m_engaged = true;
            }

            BackgroundReloadGuard::~BackgroundReloadGuard() noexcept
            {
                if (m_engaged)
                {
                    reload_in_flight_count().fetch_sub(1, std::memory_order_seq_cst);
                }
            }

            bool BackgroundReloadGuard::current() const noexcept
            {
                return m_engaged && lifecycle_current();
            }

            bool BackgroundReloadGuard::lifecycle_current() const noexcept
            {
                return reload_lifecycle_state().load(std::memory_order_seq_cst) == m_expected_epoch;
            }

            void disable_reloads_for_unload() noexcept
            {
                reload_lifecycle_state().fetch_or(RELOADS_DISABLED_BIT, std::memory_order_seq_cst);
            }

            ReloadDrainStatus begin_reload_drain() noexcept
            {
                if (reload_apply_lock_slot())
                {
                    return ReloadDrainStatus::SelfDelivery;
                }

                bool expected = false;
                if (!reload_drain_active().compare_exchange_strong(expected, true, std::memory_order_seq_cst))
                {
                    return ReloadDrainStatus::InProgress;
                }
                disable_reloads_for_unload();

                // Never wait for the control-plane lock here: finish_reload_drain owns the caller's deadline, and
                // the disabled lifecycle latch already prevents worker entry into consumer code.
                switch (request_watch_stops_for_drain())
                {
                case WatchStopPoke::SelfDelivery:
                    reload_drain_active().store(false, std::memory_order_seq_cst);
                    return ReloadDrainStatus::SelfDelivery;
                case WatchStopPoke::LockBusy:
                case WatchStopPoke::Requested:
                    break;
                }
                return ReloadDrainStatus::Ready;
            }

            ReloadDrainStatus finish_reload_drain(std::chrono::steady_clock::time_point deadline) noexcept
            {
                WatchTeardown teardown;
                while (true)
                {
                    const WatchDrainState state = try_detach_watch_control(&reloads_quiesced_now, teardown);
                    if (state == WatchDrainState::SelfDelivery)
                    {
                        // Control-mutex contention can hide this identity from begin_reload_drain.
                        reload_drain_active().store(false, std::memory_order_seq_cst);
                        return ReloadDrainStatus::SelfDelivery;
                    }
                    if (state == WatchDrainState::Detached)
                    {
                        break;
                    }
                    if (std::chrono::steady_clock::now() >= deadline)
                    {
                        reload_drain_active().store(false, std::memory_order_seq_cst);
                        return ReloadDrainStatus::TimedOut;
                    }
                    std::this_thread::yield();
                }

                if (teardown.watcher)
                {
                    teardown.watcher->stop();
                    teardown.watcher.reset();
                }
                dispose_reload_hotkey_guards(teardown.guards);
                teardown.servicer.reset();
                teardown.callback = nullptr;
                config::clear();
                reload_drain_active().store(false, std::memory_order_seq_cst);
                return ReloadDrainStatus::Ready;
            }

#if defined(DMK_ENABLE_TEST_SEAMS)
            bool await_reloads_quiesced_for_test(std::chrono::milliseconds timeout) noexcept
            {
                const auto deadline = std::chrono::steady_clock::now() + timeout;
                while (reload_in_flight_count().load(std::memory_order_seq_cst) != 0)
                {
                    if (std::chrono::steady_clock::now() >= deadline)
                    {
                        return false;
                    }
                    std::this_thread::yield();
                }
                return true;
            }
#endif

            void rearm_reloads() noexcept
            {
                if (reload_drain_active().load(std::memory_order_seq_cst))
                {
                    return;
                }
                // Advance the epoch and clear a set latch in one compare-exchange. An ordinary load while already
                // enabled changes nothing. The in-flight count balances its own admitted older passes.
                std::uint64_t state = reload_lifecycle_state().load(std::memory_order_seq_cst);
                while ((state & RELOADS_DISABLED_BIT) != 0)
                {
                    const std::uint64_t next_epoch = state + 1;
                    if (reload_lifecycle_state().compare_exchange_weak(state, next_epoch, std::memory_order_seq_cst))
                    {
                        return;
                    }
                }
            }
        } // namespace detail
    } // namespace config
} // namespace DetourModKit
