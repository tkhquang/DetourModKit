#ifndef DETOURMODKIT_INTERNAL_SCAN_FAULT_SEAM_HPP
#define DETOURMODKIT_INTERNAL_SCAN_FAULT_SEAM_HPP

/**
 * @file internal/scan_fault_seam.hpp
 * @brief Test-only injection point that raises one access fault at a chosen address inside a guarded scanner body.
 * @details The scanner's region sweep and string-xref window sweep run their foreign reads inside a fault guard that
 *          declares an exact span. Whether that guard screens the FAULTING ADDRESS, or merely the exception class, is
 *          not observable from outside: a fault at an address the span does not cover must reach the host's handlers,
 *          and the only way to drive one is from inside the guarded frame. This seam is that driver. The whole header
 *          is behind DMK_ENABLE_TEST_SEAMS, so a shipping archive carries neither the storage nor the fire site.
 */

#if defined(DMK_ENABLE_TEST_SEAMS)

#include <atomic>
#include <cstdint>

namespace DetourModKit
{
    namespace detail
    {
        /// Address the page-gated region sweep's guarded body reads once, or 0 when disarmed.
        inline std::atomic<std::uintptr_t> g_scan_region_fault_for_test{0};

        /// Address the string-xref narrow window body reads once, or 0 when disarmed.
        inline std::atomic<std::uintptr_t> g_scan_window_fault_for_test{0};

        /// Test callback invoked immediately before the narrow-window seam reads its armed address.
        using ScanFaultPreparationForTest = void (*)(std::uintptr_t) noexcept;

        /// Optional preparation that can reprotect the armed window address after the production gate has accepted it.
        inline std::atomic<ScanFaultPreparationForTest> g_scan_window_fault_preparation_for_test{nullptr};

        /**
         * @brief Reads @p slot's armed address once through a volatile lvalue, then disarms the slot.
         * @param slot The armed-address storage to consume.
         * @param preparation Optional one-shot callback invoked before the read.
         * @details Disarming before the access keeps a swept region that is visited more than once from raising a
         *          second fault the proof's oracle would not expect. The read is volatile so no optimizer may drop the
         *          dereference that is the entire point of the seam.
         */
        inline void fire_scan_fault_seam_for_test(
            std::atomic<std::uintptr_t> &slot,
            std::atomic<ScanFaultPreparationForTest> *preparation = nullptr
        ) noexcept
        {
            const std::uintptr_t address = slot.exchange(0, std::memory_order_acq_rel);
            if (address == 0)
            {
                return;
            }
            if (preparation != nullptr)
            {
                const ScanFaultPreparationForTest callback = preparation->exchange(nullptr, std::memory_order_acq_rel);
                if (callback != nullptr)
                {
                    callback(address);
                }
            }
            const auto *const probe = reinterpret_cast<volatile const std::uint8_t *>(address);
            (void)*probe;
        }
    } // namespace detail
} // namespace DetourModKit

#endif // DMK_ENABLE_TEST_SEAMS

#endif // DETOURMODKIT_INTERNAL_SCAN_FAULT_SEAM_HPP
