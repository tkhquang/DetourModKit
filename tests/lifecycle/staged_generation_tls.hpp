#ifndef DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_TLS_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_TLS_HPP

#include <array>
#include <atomic>
#include <cstddef>

namespace staged_gen
{
    /**
     * @brief Host storage for TLS ownership across loaded and unmapped generations.
     * @details Import wrappers record successful Win32 allocations and frees. The host outlives every mapped copy.
     */
    struct TlsLedger
    {
        static constexpr std::size_t INDEX_COUNT = 1088;
        std::array<std::atomic<bool>, INDEX_COUNT> owned{};
        std::atomic<std::size_t> live{0};
        std::atomic<bool> invalid{false};
    };

    /**
     * @brief Binds host storage before Init and transfers allocations from static initialization.
     */
    using BindTlsLedgerFn = void (*)(TlsLedger *) noexcept;
} // namespace staged_gen

#endif // DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_TLS_HPP
