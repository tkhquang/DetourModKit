#ifndef DETOURMODKIT_TEST_TLS_ALLOCATION_FAILURE_HPP
#define DETOURMODKIT_TEST_TLS_ALLOCATION_FAILURE_HPP

#include <cstddef>
#include <cstdint>

namespace dmk_lifecycle
{
    /** @brief Copies the proof executable's TLS ownership and return counts. */
    struct TlsAllocationSnapshot
    {
        /** @brief The count of owned indices. */
        std::size_t live{};
        /** @brief The count of successful allocations. */
        std::size_t allocations{};
        /** @brief The count of successful returns. */
        std::size_t frees{};
        /** @brief True when every return matches an owned allocation. */
        bool valid{};

        /** @brief Compares ownership and native operation counts. */
        bool operator==(const TlsAllocationSnapshot &) const noexcept = default;
    };

    /** @brief Reads the image ledger without a process-wide TLS census. */
    [[nodiscard]] TlsAllocationSnapshot tls_allocation_snapshot() noexcept;

    /** @brief Reports whether the image ledger owns the specified index. */
    [[nodiscard]] bool tls_index_is_owned(std::uint32_t index) noexcept;

    /** @brief Owns a native TLS index outside the proof executable's import ledger. */
    class NativeTlsOwner
    {
    public:
        /** @brief Reserves an index through the native export. */
        NativeTlsOwner() noexcept;
        /** @brief Returns the native index. */
        ~NativeTlsOwner() noexcept;
        NativeTlsOwner(const NativeTlsOwner &) = delete;
        NativeTlsOwner &operator=(const NativeTlsOwner &) = delete;
        NativeTlsOwner(NativeTlsOwner &&) = delete;
        NativeTlsOwner &operator=(NativeTlsOwner &&) = delete;

        /** @brief Reports whether the native reservation succeeded. */
        [[nodiscard]] bool reserved() const noexcept;
        /** @brief Returns the owned native index. */
        [[nodiscard]] std::uint32_t index() const noexcept;
        /** @brief Returns the index and reports native success. */
        [[nodiscard]] bool reset() noexcept;

    private:
        std::uint32_t m_index{0xFFFFFFFFu};
    };

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
