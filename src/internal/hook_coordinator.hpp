#ifndef DETOURMODKIT_INTERNAL_HOOK_COORDINATOR_HPP
#define DETOURMODKIT_INTERNAL_HOOK_COORDINATOR_HPP

/**
 * @file internal/hook_coordinator.hpp
 * @brief Backend-free hold on the process route coordinator for translation units outside the hook island.
 * @details The backend serializes every patch transaction, including its trap window, through one process
 *          coordinator. A `VirtualQuery` snapshot of a code page taken outside that coordinator can record the
 *          transient trap protection (`[B-18]`, `[B-66]`). src/hook.cpp defines the hold, so this header names no
 *          backend type.
 */

#include <cstddef>

namespace DetourModKit::detail
{
    /**
     * @class BackendCoordinatorHold
     * @brief RAII acquisition of the backend process coordinator with the backend's bounded wait.
     * @details The owning thread acquires again without a wait. A refused hold reports false and holds nothing.
     */
    class BackendCoordinatorHold
    {
    public:
        BackendCoordinatorHold() noexcept;
        ~BackendCoordinatorHold() noexcept;
        BackendCoordinatorHold(const BackendCoordinatorHold &) = delete;
        BackendCoordinatorHold &operator=(const BackendCoordinatorHold &) = delete;

        /// True while this object holds the coordinator.
        [[nodiscard]] explicit operator bool() const noexcept { return m_held; }

        /// Releases the coordinator before scope exit. A second call is a no-op.
        void release() noexcept;

        /// Bytes reserved for the backend object. src/hook.cpp asserts the backend's size and alignment against it.
        static constexpr std::size_t STORAGE_BYTES = 2 * sizeof(void *);

    private:
        alignas(void *) unsigned char m_storage[STORAGE_BYTES]{};
        bool m_constructed{false};
        bool m_held{false};
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_HOOK_COORDINATOR_HPP
