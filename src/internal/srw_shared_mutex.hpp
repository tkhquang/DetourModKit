#ifndef DETOURMODKIT_SRW_SHARED_MUTEX_HPP
#define DETOURMODKIT_SRW_SHARED_MUTEX_HPP

#include <cstddef>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @class SrwSharedMutex
         * @brief Shared mutex backed by Windows SRWLOCK.
         * @details Provides the BasicLockable and SharedLockable operations used by std::unique_lock and
         *          std::shared_lock without including Windows headers from DetourModKit public headers. Exists
         *          because std::shared_mutex cannot back these locks on every supported toolchain:
         *          MinGW/winpthreads' pthread_rwlock_t corrupts internal state under high reader contention,
         *          causing assertion failures in lock_shared(), while SRWLOCK is lock-free in the uncontended case
         *          and does not suffer from that bug. Use this for DetourModKit reader/writer locks that guard
         *          runtime state. Prefer std::mutex when no shared-reader path is needed.
         */
        class SrwSharedMutex
        {
        public:
            /// Creates an unlocked reader/writer lock.
            SrwSharedMutex() noexcept;

            /// Trivially destructible: SRWLOCK has no teardown API, so releasing the storage ends its lifetime.
            ~SrwSharedMutex() noexcept = default;

            SrwSharedMutex(const SrwSharedMutex &) = delete;
            SrwSharedMutex &operator=(const SrwSharedMutex &) = delete;
            SrwSharedMutex(SrwSharedMutex &&) = delete;
            SrwSharedMutex &operator=(SrwSharedMutex &&) = delete;

            /// Acquires exclusive ownership, blocking until the lock is available.
            void lock() noexcept;

            /// Attempts to acquire exclusive ownership without blocking.
            [[nodiscard]] bool try_lock() noexcept;

            /// Releases exclusive ownership held by the current thread.
            void unlock() noexcept;

            /// Acquires shared ownership, blocking until the lock is available.
            void lock_shared() noexcept;

            /// Attempts to acquire shared ownership without blocking.
            [[nodiscard]] bool try_lock_shared() noexcept;

            /// Releases shared ownership held by the current thread.
            void unlock_shared() noexcept;

        private:
            static constexpr std::size_t SRW_STORAGE_BYTES = sizeof(void *);

            alignas(void *) std::byte m_srw_storage[SRW_STORAGE_BYTES]{};
        };
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_SRW_SHARED_MUTEX_HPP
