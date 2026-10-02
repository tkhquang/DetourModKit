#ifndef DETOURMODKIT_TEST_TLS_ALLOCATION_FAILURE_HPP
#define DETOURMODKIT_TEST_TLS_ALLOCATION_FAILURE_HPP

namespace dmk_lifecycle
{
    /**
     * @brief Refuses TLS allocations through the proof executable's import cell.
     * @details System DLLs retain their real allocator. Each proof owns one failure window.
     */
    class TlsAllocationFailure
    {
    public:
        /** @brief Opens the allocation failure window. */
        TlsAllocationFailure() noexcept;
        /** @brief Restores the native allocator. */
        ~TlsAllocationFailure() noexcept;
        TlsAllocationFailure(const TlsAllocationFailure &) = delete;
        TlsAllocationFailure &operator=(const TlsAllocationFailure &) = delete;
        TlsAllocationFailure(TlsAllocationFailure &&) = delete;
        TlsAllocationFailure &operator=(TlsAllocationFailure &&) = delete;

        /** @brief Verifies import refusal and native TLS use on a new host thread. */
        [[nodiscard]] bool isolated() const noexcept;
        /** @brief Closes the allocation failure window before owner retirement. */
        void restore() noexcept;
    };
} // namespace dmk_lifecycle

#endif // DETOURMODKIT_TEST_TLS_ALLOCATION_FAILURE_HPP
