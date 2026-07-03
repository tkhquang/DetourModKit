#ifndef DETOURMODKIT_TEST_FAULT_INJECTION_HPP
#define DETOURMODKIT_TEST_FAULT_INJECTION_HPP

// Reusable Win32 page-fault fixtures for DetourModKit's guarded-memory fault-containment tests. They build the
// "must fault" preconditions the guarded read/write primitives are supposed to survive: a committed PAGE_NOACCESS page
// that deterministically faults any access, and a committed page pinned to a chosen protection whose bytes a
// slow-path write must not corrupt and whose protection a fault path must restore.
//
// These fixtures are authored to run through the standalone-link fault runner (scripts/run_fault_tests.sh), not the
// in-tree tests/test_*.cpp glob. Fault fixtures live in tests/fault/ so adding one does not force the main test target
// through a CMake reconfigure and heavy relink.

#include <cstddef>
#include <cstdint>
#include <cstring>

// The whole fixture body is Windows-only (VirtualAlloc / VirtualProtect / VirtualQuery). The library targets Win64
// only, so this header is only ever compiled on Windows, but per the header-cleanliness rule the Windows-only content
// is still guarded so a non-Windows toolchain sees an empty header rather than a hard include error.
#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace dmk_test
{
    /**
     * @brief The x86-64 base page size.
     * @details Every fixture allocates one page: a single page is enough to fault on, and keeping the allocation
     *          minimal keeps the intentionally-leaked NoAccessPage cost negligible.
     */
    inline constexpr std::size_t PAGE_BYTES = 0x1000;

    /**
     * @brief A committed PAGE_NOACCESS page that is intentionally NEVER released for the process lifetime.
     * @details Any read or write into the page raises an access violation deterministically -- exactly the hardware
     *          fault a guarded primitive must contain instead of letting the host terminate. The page is leaked ON
     *          PURPOSE: if it were freed, its virtual address could be recycled by a later allocation, and a subsequent
     *          fault test expecting a fault at that address would instead touch live memory and silently pass. Leaking
     *          one page per fault test is trivial (the suite is a short-lived process that exits immediately after),
     *          and it removes the recycled-VA flake entirely.
     */
    class NoAccessPage
    {
    public:
        NoAccessPage() noexcept
            : m_base(static_cast<std::byte *>(
                  ::VirtualAlloc(nullptr, PAGE_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS)))
        {
        }

        // No destructor: the page is deliberately never freed (see the class note). Copying would double the leak and
        // is meaningless, so it is deleted.
        NoAccessPage(const NoAccessPage &) = delete;
        NoAccessPage &operator=(const NoAccessPage &) = delete;
        NoAccessPage(NoAccessPage &&) = delete;
        NoAccessPage &operator=(NoAccessPage &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::byte *data() const noexcept { return m_base; }
        [[nodiscard]] std::uintptr_t addr() const noexcept { return reinterpret_cast<std::uintptr_t>(m_base); }

    private:
        std::byte *m_base;
    };

    /**
     * @brief A committed page filled with a known byte and pinned to a chosen protection (PAGE_READONLY /
     *        PAGE_EXECUTE_READ / ...), freed on destruction.
     * @details Unlike @ref NoAccessPage, a test never relies on THIS page faulting after the test finishes, so
     *          recycling its virtual address is harmless and it is a normal RAII allocation. It serves as a write
     *          target whose original protection a slow-path write must restore, and whose known fill a fault path must
     *          leave unmodified. If the requested protection cannot be pinned the page is released and @ref ok reports
     *          false, so a test never runs against a page in the wrong state.
     */
    class ProtectedPage
    {
    public:
        explicit ProtectedPage(DWORD protection, std::uint8_t fill = 0x00) noexcept
            : m_base(static_cast<std::byte *>(
                  ::VirtualAlloc(nullptr, PAGE_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
        {
            if (m_base == nullptr)
            {
                return;
            }
            std::memset(m_base, fill, PAGE_BYTES);
            DWORD previous = 0;
            if (::VirtualProtect(m_base, PAGE_BYTES, protection, &previous) == FALSE)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
                m_base = nullptr;
            }
        }

        ~ProtectedPage() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        ProtectedPage(const ProtectedPage &) = delete;
        ProtectedPage &operator=(const ProtectedPage &) = delete;
        ProtectedPage(ProtectedPage &&) = delete;
        ProtectedPage &operator=(ProtectedPage &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uintptr_t addr() const noexcept { return reinterpret_cast<std::uintptr_t>(m_base); }

        /**
         * @brief The page's CURRENT protection via VirtualQuery, so a test can assert a fault path restored it.
         * @return The MEMORY_BASIC_INFORMATION::Protect value, or 0 if the query failed.
         */
        [[nodiscard]] DWORD current_protection() const noexcept
        {
            if (m_base == nullptr)
            {
                return 0;
            }
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(m_base, &mbi, sizeof(mbi)) == 0)
            {
                return 0;
            }
            return mbi.Protect;
        }

        /**
         * @brief Reads one byte of the page directly.
         * @param off Offset within the page.
         * @return The byte at @p off, or 0 if the fixture is not initialized or @p off is outside the page.
         * @details Valid only for readable protections (PAGE_READONLY / *_READ*), which is every protection these
         *          fixtures pin. The page is never PAGE_NOACCESS, so this read never faults.
         */
        [[nodiscard]] std::uint8_t byte_at(std::size_t off) const noexcept
        {
            if (m_base == nullptr || off >= PAGE_BYTES)
            {
                return 0;
            }
            return static_cast<std::uint8_t>(m_base[off]);
        }

    private:
        std::byte *m_base{nullptr};
    };
} // namespace dmk_test

#endif // _WIN32

#endif // DETOURMODKIT_TEST_FAULT_INJECTION_HPP
