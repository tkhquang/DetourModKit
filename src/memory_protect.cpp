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

#include <windows.h>

#include <memory>
#include <utility>

namespace DetourModKit
{
    namespace memory
    {
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

        // The captured protection state. Kept in the .cpp so the installed header never names a Win32 type.
        struct ProtectGuard::Impl
        {
            std::uintptr_t base = 0;
            std::size_t size = 0;
            DWORD old_protection = 0;
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
                    DWORD restored_from = 0;
                    VirtualProtect(reinterpret_cast<LPVOID>(m_impl->base), m_impl->size, m_impl->old_protection,
                                   &restored_from);
                }
                m_impl = std::move(other.m_impl);
            }
            return *this;
        }

        ProtectGuard::~ProtectGuard()
        {
            if (!m_impl)
            {
                return;
            }
            // Best-effort restore: a destructor cannot report failure, and a guard whose restore fails leaves the page
            // in the changed protection, which a caller that needs the result should detect by re-applying explicitly.
            DWORD restored_from = 0;
            VirtualProtect(reinterpret_cast<LPVOID>(m_impl->base), m_impl->size, m_impl->old_protection,
                           &restored_from);
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

        Result<ProtectGuard> ProtectGuard::make(Region region, Prot protection)
        {
            // An empty region (null base or zero size) has no pages to protect; fail closed rather than issue a
            // VirtualProtect on a degenerate range.
            if (!region.base || region.size == 0)
            {
                return std::unexpected(
                    Error{ErrorCode::ProtectionChangeFailed, "memory::ProtectGuard::make", region.base.raw(), 0});
            }

            DWORD old_protection = 0;
            if (!VirtualProtect(region.base.ptr<void>(), region.size, prot_to_win32(protection), &old_protection))
            {
                return std::unexpected(Error{ErrorCode::ProtectionChangeFailed, "memory::ProtectGuard::make",
                                             region.base.raw(), static_cast<std::uint32_t>(GetLastError())});
            }

            ProtectGuard guard;
            guard.m_impl = std::make_unique<Impl>();
            guard.m_impl->base = region.base.raw();
            guard.m_impl->size = region.size;
            guard.m_impl->old_protection = old_protection;
            return guard;
        }
    } // namespace memory
} // namespace DetourModKit
