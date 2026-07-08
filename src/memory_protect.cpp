/**
 * @file memory_protect.cpp
 * @brief Implementation of memory::ProtectGuard, the move-only RAII page-protection change.
 *
 * The guard captures a region's prior protection at construction and restores it on destruction, factoring the
 * VirtualProtect dance out of any caller that patches or writes a region repeatedly. The captured base / size /
 * old-protection live in the pimpl Impl defined here so the public header carries no Win32 type, and the special
 * members are defined here (not defaulted in the header) because the unique_ptr<Impl> needs Impl complete to destroy
 * and move.
 */

#include "DetourModKit/memory.hpp"
#include "internal/memory_guarded.hpp"

#include <windows.h>

#include <cstdint>
#include <memory>
#include <new>
#include <utility>

namespace DetourModKit
{
    namespace memory
    {
        // The per-region protection helpers live in DetourModKit::detail; pull them in with using-declarations so the
        // ProtectGuard::Impl definition and make()/restore paths can name them unqualified.
        using DetourModKit::detail::MAX_PROTECTION_SEGMENTS;
        using DetourModKit::detail::protect_across_regions;
        using DetourModKit::detail::ProtectionSegment;
        using DetourModKit::detail::restore_across_regions;

        namespace
        {
            /**
             * @brief Maps a backend-neutral Prot flag set onto the Win32 PAGE_* constant with the matching rights.
             * @details Windows has no write-without-read protection, so a Prot carrying W (with or without R) maps to a
             *          read/write page: a write right always implies a read right on this platform. Execute rights pick
             *          the PAGE_EXECUTE_* family so a code page keeps execution across the guard.
             */
            [[nodiscard]] DWORD prot_to_win32(Prot protection) noexcept
            {
                const bool readable = (protection & Prot::R) != Prot::None;
                const bool writable = (protection & Prot::W) != Prot::None;
                const bool executable = (protection & Prot::X) != Prot::None;

                if (executable)
                {
                    if (writable)
                        return PAGE_EXECUTE_READWRITE;
                    if (readable)
                        return PAGE_EXECUTE_READ;
                    return PAGE_EXECUTE;
                }
                if (writable)
                    return PAGE_READWRITE;
                if (readable)
                    return PAGE_READONLY;
                return PAGE_NOACCESS;
            }
        } // namespace

        // The captured protection state. Kept in the .cpp so the installed header never names a Win32 type. The
        // guarded span may cross a protection seam, so the original protection of each VirtualQuery region it covers is
        // captured separately and restored per region -- restoring the whole span to one value would flatten an
        // executable region adjacent to a read-only seam. The segment array is embedded (not heap-grown) so make() can
        // keep its allocate-before-protect discipline: the storage exists before any VirtualProtect runs.
        struct ProtectGuard::Impl
        {
            ProtectionSegment segments[MAX_PROTECTION_SEGMENTS];
            std::size_t segment_count = 0;
            // The whole guarded span, retained for the cache invalidation that follows every change / restore.
            std::uintptr_t base = 0;
            std::size_t size = 0;
        };

        ProtectGuard::ProtectGuard() noexcept = default;

        ProtectGuard::ProtectGuard(ProtectGuard &&other) noexcept : m_impl(std::move(other.m_impl)) {}

        ProtectGuard &ProtectGuard::operator=(ProtectGuard &&other) noexcept
        {
            if (this != &other)
            {
                // Restore this guard's own region before adopting the other's, so reassigning never silently abandons a
                // protection change this guard still owned.
                if (m_impl)
                {
                    std::uint32_t restore_error = 0;
                    (void)restore_across_regions(m_impl->segments, m_impl->segment_count, restore_error);
                    // The restore changed protection, so drop any cached snapshot of the range taken while the guard
                    // held it writable, matching the invalidation write_bytes and make() perform on a protection
                    // change.
                    invalidate_range(Region{Address{m_impl->base}, m_impl->size});
                }
                m_impl = std::move(other.m_impl);
            }
            return *this;
        }

        ProtectGuard::~ProtectGuard() noexcept
        {
            if (!m_impl)
            {
                return;
            }
            // Best-effort restore: a destructor cannot report failure, and a guard whose restore fails leaves the page
            // in the changed protection, which a caller that needs the result should detect by re-applying explicitly.
            std::uint32_t restore_error = 0;
            (void)restore_across_regions(m_impl->segments, m_impl->segment_count, restore_error);
            // The protection just changed back, so a cached snapshot taken while the page was writable is now stale;
            // drop the range so a later is_readable / is_writable re-queries the restored protection.
            invalidate_range(Region{Address{m_impl->base}, m_impl->size});
        }

        ProtectGuard::operator bool() const noexcept
        {
            return static_cast<bool>(m_impl);
        }

        void ProtectGuard::release() noexcept
        {
            // Drop the captured state without restoring, leaving the changed protection in place permanently.
            m_impl.reset();
        }

        Result<ProtectGuard> ProtectGuard::make(Region region, Prot protection) noexcept
        {
            // An empty region (null base or zero size) has no pages to protect; fail closed rather than issue a
            // VirtualProtect on a degenerate range.
            if (!region.base || region.size == 0)
            {
                return std::unexpected(
                    Error{ErrorCode::ProtectionChangeFailed, "memory::ProtectGuard::make", region.base.raw(), 0});
            }

            // Allocate the capture state before changing protection. If this throws (OOM), the guard fails with no
            // protection change to leak; the reverse order -- VirtualProtect then allocate -- would strand the region
            // in the changed protection with no guard to restore it if the allocation threw. make() is noexcept, so the
            // bad_alloc is caught and reported as an error rather than propagating out of the factory. The embedded
            // segment array means the per-region walk below writes into already-allocated storage, so no allocation
            // happens between the first VirtualProtect and the guard being armed.
            std::unique_ptr<Impl> impl;
            try
            {
                impl = std::make_unique<Impl>();
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(
                    Error{ErrorCode::OutOfMemory, "memory::ProtectGuard::make", region.base.raw(), 0});
            }

            // Change every protection region the span covers, capturing each region's own prior protection so the
            // restore is exact. A span crossing more than MAX_PROTECTION_SEGMENTS regions, or a VirtualQuery /
            // VirtualProtect failure, fails closed here with everything already changed rolled back.
            std::uint32_t os_error = 0;
            const std::size_t segment_count = protect_across_regions(
                region.base.raw(), region.size, prot_to_win32(protection), impl->segments, MAX_PROTECTION_SEGMENTS,
                os_error);
            if (segment_count == 0)
            {
                return std::unexpected(Error{ErrorCode::ProtectionChangeFailed, "memory::ProtectGuard::make",
                                             region.base.raw(), os_error});
            }

            impl->segment_count = segment_count;
            impl->base = region.base.raw();
            impl->size = region.size;

            // The page protection just changed, so any cached snapshot for this range is stale; drop it so a later
            // is_readable / is_writable re-queries, mirroring write_bytes' invalidate on its protection-changing path.
            invalidate_range(region);

            ProtectGuard guard;
            guard.m_impl = std::move(impl);
            return guard;
        }
    } // namespace memory
} // namespace DetourModKit
