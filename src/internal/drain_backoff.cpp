/**
 * @file internal/drain_backoff.cpp
 * @brief Defines the drain-backoff escalation seam counters.
 */

#include "drain_backoff.hpp"

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    std::atomic<std::uint64_t> g_drain_backoff_yields{0};
    std::atomic<std::uint64_t> g_drain_backoff_sleeps{0};
} // namespace DetourModKit::detail
#endif
