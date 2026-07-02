#include "internal/srw_shared_mutex.hpp"

#include <windows.h>
#include <new>
#include <type_traits>

namespace DetourModKit
{
    namespace detail
    {
        static_assert(sizeof(SrwSharedMutex) == sizeof(SRWLOCK));
        static_assert(alignof(SrwSharedMutex) == alignof(SRWLOCK));
        // The defaulted destructor never runs ~SRWLOCK on the placement-new'd object; that is only correct while
        // SRWLOCK stays trivially destructible (releasing the storage then legally ends its lifetime).
        static_assert(std::is_trivially_destructible_v<SRWLOCK>);

        namespace
        {
            /**
             * @brief Converts SrwSharedMutex opaque storage back to the native Windows lock.
             * @details std::launder is required: the byte array only provides storage for the SRWLOCK created by
             *          placement new in the constructor, and an array element is not pointer-interconvertible with
             *          the object nested in it, so the bare reinterpret_cast would still designate the byte element.
             * @param storage Storage owned by a live SrwSharedMutex instance.
             * @return Pointer to the SRWLOCK object living in the byte buffer.
             */
            [[nodiscard]] SRWLOCK *native_lock(std::byte *storage) noexcept
            {
                return std::launder(reinterpret_cast<SRWLOCK *>(storage));
            }
        } // namespace

        SrwSharedMutex::SrwSharedMutex() noexcept
        {
            auto *lock = ::new (static_cast<void *>(m_srw_storage)) SRWLOCK{};
            InitializeSRWLock(lock);
        }

        void SrwSharedMutex::lock() noexcept
        {
            AcquireSRWLockExclusive(native_lock(m_srw_storage));
        }

        bool SrwSharedMutex::try_lock() noexcept
        {
            return TryAcquireSRWLockExclusive(native_lock(m_srw_storage)) != 0;
        }

        void SrwSharedMutex::unlock() noexcept
        {
            ReleaseSRWLockExclusive(native_lock(m_srw_storage));
        }

        void SrwSharedMutex::lock_shared() noexcept
        {
            AcquireSRWLockShared(native_lock(m_srw_storage));
        }

        bool SrwSharedMutex::try_lock_shared() noexcept
        {
            return TryAcquireSRWLockShared(native_lock(m_srw_storage)) != 0;
        }

        void SrwSharedMutex::unlock_shared() noexcept
        {
            ReleaseSRWLockShared(native_lock(m_srw_storage));
        }
    } // namespace detail
} // namespace DetourModKit
