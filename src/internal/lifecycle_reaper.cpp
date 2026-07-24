/**
 * @file internal/lifecycle_reaper.cpp
 * @brief Process-lifetime reaper thread that joins self-retiring workers off their own thread.
 */

#include "lifecycle_reaper.hpp"

#include "DetourModKit/diagnostics.hpp"
#include "platform.hpp"

#include <atomic>
#include <condition_variable>
#include <list>
#include <mutex>
#include <new>
#include <thread>
#include <utility>

namespace DetourModKit::detail
{
    namespace
    {
        // Exactly one parcel form is populated: a worker thread plus module reference, an erased owner, or a
        // shared-owner reference to drop.
        struct Parcel
        {
            std::unique_ptr<std::jthread> thread;
            std::shared_ptr<void> shared_owner;
            SharedOwnerRetire retire_shared{nullptr};
            void *module_ref{nullptr};
            void *owner{nullptr};
            void (*destroy)(void *) noexcept {nullptr};

            void clear() noexcept
            {
                thread.reset();
                shared_owner.reset();
                retire_shared = nullptr;
                module_ref = nullptr;
                owner = nullptr;
                destroy = nullptr;
            }
        };

        // Queue nodes reserved while allocation still works, so a retirement requested under host OOM -- the case the
        // whole facility exists for -- still reaches the reaper. Recycled nodes return to the reserve, so the depth
        // bounds concurrent in-flight retirements, not total ones.
        constexpr std::size_t RESERVED_PARCELS = 8;

        // Process-lifetime, never destroyed. Leaking the heap cell keeps the reaper thread out of a
        // static-destruction join under the loader lock, and lets a background thread run library code
        // (owner destructors) safely against a held module reference.
        class Reaper
        {
        public:
            Reaper() noexcept
            {
                // A permanent worker requires a permanent module reference before its code can run.
                const HMODULE self_ref = acquire_module_ref();
                if (self_ref == nullptr)
                {
                    return;
                }
                try
                {
                    for (std::size_t i = 0; i < RESERVED_PARCELS; ++i)
                    {
                        m_free.emplace_back();
                    }
                    m_thread = std::thread([this]() noexcept { run(); });
                    // The reaper has process lifetime, so its matching module reference intentionally does too: the
                    // success path never releases self_ref.
                    m_accepting.store(true, std::memory_order_release);
                }
                catch (...)
                {
                    release_module_ref(self_ref);
                }
            }

            Reaper(const Reaper &) = delete;
            Reaper &operator=(const Reaper &) = delete;

            // A failed enqueue leaves the parcel untouched so its caller can take the retain-and-detach path.
            [[nodiscard]] bool enqueue(Parcel &&parcel) noexcept
            {
                if (!m_accepting.load(std::memory_order_acquire))
                {
                    return false;
                }
                try
                {
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        if (!m_accepting.load(std::memory_order_relaxed))
                        {
                            return false;
                        }
                        if (m_free.empty())
                        {
                            m_queue.push_back(std::move(parcel));
                        }
                        else
                        {
                            // Splicing a reserved node cannot allocate, which is what lets a retirement requested
                            // while every allocation fails still be queued.
                            m_free.front() = std::move(parcel);
                            m_queue.splice(m_queue.end(), m_free, m_free.begin());
                        }
                    }
                    m_cv.notify_one();
                    return true;
                }
                catch (...)
                {
                    // A self-retiring owner is queued immediately after its worker. Permanently stop accepting
                    // after one failure so that a detached worker can never be followed by queued owner destruction.
                    m_accepting.store(false, std::memory_order_release);
                    return false;
                }
            }

        private:
            void run() noexcept
            {
                for (;;)
                {
                    std::list<Parcel>::iterator parcel;
                    {
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_cv.wait(lock, [this] { return !m_queue.empty(); });
                        parcel = m_queue.begin();
                    }
                    // Owner destruction may block on its worker join, so it must not hold the queue mutex.
                    const bool retired = process(*parcel);
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        if (retired)
                        {
                            // Recycle rather than erase so the allocation-free reserve refills itself.
                            parcel->clear();
                            m_free.splice(m_free.end(), m_queue, parcel);
                        }
                        else
                        {
                            // Splice reuses the queue node and cannot allocate. This is where a retirement that could
                            // not be completed stays reachable: a still-joinable thread whose std::jthread destructor
                            // would otherwise terminate the host, or an owner whose rundown the callback refused and
                            // which therefore must not be released.
                            m_abandoned.splice(m_abandoned.end(), m_queue, parcel);
                        }
                    }
                }
            }

            [[nodiscard]] static bool process(Parcel &parcel) noexcept
            {
                if (parcel.destroy != nullptr)
                {
                    parcel.destroy(parcel.owner);
                    return true;
                }
                if (parcel.shared_owner)
                {
                    // Complete the worker rundown while the owner is still alive. Beginning its destructor before the
                    // join would let the worker body access an object whose lifetime had already ended. A parcel with
                    // no callback cannot be run down at all, so retain it rather than release an owner whose body may
                    // still be running; reap_shared_owner refuses that case, so this is the second line of defence.
                    if (parcel.retire_shared == nullptr || !parcel.retire_shared(parcel.shared_owner.get()))
                    {
                        return false;
                    }
                    // Drop here, not in the recycling step: the last release may run the owner's destructor, and the
                    // queue mutex is held during recycling.
                    parcel.shared_owner.reset();
                    return true;
                }
                try
                {
                    if (parcel.thread != nullptr && parcel.thread->joinable())
                    {
                        parcel.thread->join();
                    }
                    if (parcel.module_ref != nullptr)
                    {
                        release_module_ref(static_cast<HMODULE>(parcel.module_ref));
                    }
                    return true;
                }
                catch (...)
                {
                    // Completion is uncertain. Detach if possible and retain the module reference so no running
                    // instruction can outlive its code pages.
                    try
                    {
                        if (parcel.thread != nullptr && parcel.thread->joinable())
                        {
                            parcel.thread->detach();
                        }
                    }
                    catch (...)
                    {
                    }
                    DetourModKit::diagnostics::record_intentional_leak(
                        DetourModKit::diagnostics::LeakSubsystem::Worker);
                    return parcel.thread == nullptr || !parcel.thread->joinable();
                }
            }

            std::mutex m_mutex;
            std::condition_variable m_cv;
            std::list<Parcel> m_queue;
            std::list<Parcel> m_free;
            std::list<Parcel> m_abandoned;
            std::thread m_thread;
            std::atomic<bool> m_accepting{false};
        };

        Reaper *reaper_instance() noexcept
        {
            // Static destruction cannot safely join this permanent worker under the loader lock.
            static Reaper *const s_reaper = new (std::nothrow) Reaper();
            return s_reaper;
        }
    } // namespace

    void reap_worker_thread(std::unique_ptr<std::jthread> thread, void *module_ref) noexcept
    {
        Parcel parcel;
        parcel.thread = std::move(thread);
        parcel.module_ref = module_ref;

        if (Reaper *reaper = reaper_instance(); reaper != nullptr && reaper->enqueue(std::move(parcel)))
        {
            return;
        }

        // Retain the module reference if the running body cannot be queued for a safe off-thread join.
        // enqueue consumes `parcel` only when it returns true; every false path above leaves it intact, and this
        // fallback tolerates even a moved-from parcel (a null thread skips the detach below).
        try
        {
            // NOLINTNEXTLINE(bugprone-use-after-move)
            if (parcel.thread != nullptr && parcel.thread->joinable())
            {
                parcel.thread->detach();
            }
        }
        catch (...)
        {
            // Retain a still-joinable jthread so its destructor cannot terminate the host.
            (void)parcel.thread.release();
        }
        DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Worker);
    }

    bool reap_shared_owner(std::shared_ptr<void> &owner, SharedOwnerRetire retire) noexcept
    {
        if (!owner)
        {
            return true;
        }

        if (retire == nullptr)
        {
            // The reaper cannot run down a worker it has no callback for, and releasing the reference anyway would
            // destroy an owner whose body may still be running. Refuse at the door so the caller's own retention takes
            // over, rather than queuing a parcel that could only be abandoned.
            return false;
        }

        Parcel parcel;
        parcel.shared_owner = owner;
        parcel.retire_shared = retire;

        Reaper *const reaper = reaper_instance();
        if (reaper != nullptr && reaper->enqueue(std::move(parcel)))
        {
            owner.reset();
            return true;
        }

        // A failed enqueue leaves the parcel populated. Drop the reaper's copy -- never the last one, since the caller
        // still holds theirs -- and report the failure so the caller can abandon its own into permanent storage.
        // NOLINTNEXTLINE(bugprone-use-after-move)
        parcel.shared_owner.reset();
        return false;
    }

    void reaper_detail::reap_owner_erased(void *owner, void (*destroy)(void *) noexcept) noexcept
    {
        Parcel parcel;
        parcel.owner = owner;
        parcel.destroy = destroy;

        if (Reaper *reaper = reaper_instance(); reaper != nullptr && reaper->enqueue(std::move(parcel)))
        {
            return;
        }

        // Destruction on the calling worker would self-join, so failed queuing deliberately retains the owner.
        DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Worker);
    }
} // namespace DetourModKit::detail
