#ifndef DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_TLS_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_TLS_HPP

#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>

namespace staged_gen
{
    /**
     * @brief Records TLS ownership for one linked image.
     * @details Import wrappers record successful Win32 allocations and frees. Host storage outlives every mapped copy.
     */
    struct TlsLedger
    {
        static constexpr std::size_t INDEX_COUNT = 1088;
        SRWLOCK transaction_lock = SRWLOCK_INIT;
        std::array<std::atomic<bool>, INDEX_COUNT> owned{};
        std::atomic<std::size_t> live{0};
        std::atomic<std::size_t> allocations{0};
        std::atomic<std::size_t> frees{0};
        std::atomic<bool> invalid{false};
    };

    /** @brief Serializes the native TLS operation and its ledger update across index reuse. */
    class TlsLedgerTransaction
    {
    public:
        /** @brief Acquires the ledger's native lock without runtime TLS or allocation. */
        explicit TlsLedgerTransaction(TlsLedger &ledger) noexcept : m_ledger{ledger}
        {
            AcquireSRWLockExclusive(&m_ledger.transaction_lock);
        }

        /** @brief Releases the ledger lock. */
        ~TlsLedgerTransaction() noexcept { ReleaseSRWLockExclusive(&m_ledger.transaction_lock); }
        TlsLedgerTransaction(const TlsLedgerTransaction &) = delete;
        TlsLedgerTransaction &operator=(const TlsLedgerTransaction &) = delete;
        TlsLedgerTransaction(TlsLedgerTransaction &&) = delete;
        TlsLedgerTransaction &operator=(TlsLedgerTransaction &&) = delete;

    private:
        TlsLedger &m_ledger;
    };

    /** @brief Records one successful native allocation through the image's import cell. */
    inline void claim_tls_index(TlsLedger &ledger, std::size_t index) noexcept
    {
        if (index >= ledger.owned.size() || ledger.owned[index].exchange(true, std::memory_order_relaxed))
        {
            ledger.invalid.store(true, std::memory_order_relaxed);
            return;
        }
        ledger.live.fetch_add(1, std::memory_order_relaxed);
        ledger.allocations.fetch_add(1, std::memory_order_relaxed);
    }

    /** @brief Records one successful native return through the image's import cell. */
    inline void release_tls_index(TlsLedger &ledger, std::size_t index) noexcept
    {
        if (index >= ledger.owned.size() || !ledger.owned[index].exchange(false, std::memory_order_relaxed))
        {
            ledger.invalid.store(true, std::memory_order_relaxed);
            return;
        }
        ledger.live.fetch_sub(1, std::memory_order_relaxed);
        ledger.frees.fetch_add(1, std::memory_order_relaxed);
    }

    /**
     * @brief Binds host storage before Init and transfers allocations from static initialization.
     */
    using BindTlsLedgerFn = void (*)(TlsLedger *) noexcept;
} // namespace staged_gen

#endif // DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_TLS_HPP
