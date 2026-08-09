#ifndef DETOURMODKIT_TEST_FAULT_INJECTION_HPP
#define DETOURMODKIT_TEST_FAULT_INJECTION_HPP

// Reusable Win32 page fixtures for DetourModKit's fault-containment proofs: the "must fault" preconditions a guarded
// primitive is supposed to survive, and the scannable pages a scanner proof drives. They are toolchain-neutral -- the
// hosts in tests/fault/ decide which fault mechanism (MSVC frame-based SEH or the MinGW vectored guard) they exercise.
//
// These fixtures belong to tests/fault/ and its standalone runner (scripts/run_fault_tests.sh), not the in-tree
// tests/test_*.cpp glob: adding one there would force a CONFIGURE_DEPENDS reconfigure and a heavy relink of the main
// test target.

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

    /**
     * @brief A committed, zero-filled PAGE_EXECUTE_READWRITE page usable as a synthetic module image.
     * @details PAGE_EXECUTE_READWRITE satisfies both the readable and the executable page masks, so one page can host
     *          a literal the readable sweep must find and the instruction bytes the executable sweep must decode.
     *          VirtualAlloc zero-fills, and 0x00 neither continues a planted string nor starts a RIP-relative load,
     *          so unwritten bytes are inert.
     */
    class ExecutablePage
    {
    public:
        ExecutablePage() noexcept
            : m_base(static_cast<std::byte *>(
                  ::VirtualAlloc(nullptr, PAGE_BYTES, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
        {
        }

        ~ExecutablePage() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        ExecutablePage(const ExecutablePage &) = delete;
        ExecutablePage &operator=(const ExecutablePage &) = delete;
        ExecutablePage(ExecutablePage &&) = delete;
        ExecutablePage &operator=(ExecutablePage &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uintptr_t addr() const noexcept { return reinterpret_cast<std::uintptr_t>(m_base); }
        [[nodiscard]] std::uintptr_t addr(std::size_t off) const noexcept { return addr() + off; }

        /// Copies @p n bytes of @p data into the page at @p off; a span past the page end is dropped.
        void write(std::size_t off, const void *data, std::size_t n) noexcept
        {
            if (m_base == nullptr || off > PAGE_BYTES || n > PAGE_BYTES - off)
            {
                return;
            }
            std::memcpy(m_base + off, data, n);
        }

        /**
         * @brief Plants `REX.W 8D 05 <disp32>` (lea rax, [rip+disp32]) at @p instr_off targeting @p target_off.
         * @param instr_off Offset of the seven-byte instruction.
         * @param target_off Offset the computed RIP-relative target must land on.
         */
        void plant_rip_lea(std::size_t instr_off, std::size_t target_off) noexcept
        {
            // PAGE_BYTES - 7, not instr_off + 7: the sum wraps for an instr_off near SIZE_MAX and would let a wild
            // offset past the gate and into m_base + instr_off. Same non-wrapping form as the write() bound above.
            static_assert(PAGE_BYTES > 7, "the seven-byte instruction must fit in a page for the bound below to hold");
            if (m_base == nullptr || instr_off > PAGE_BYTES - 7 || target_off >= PAGE_BYTES)
            {
                return;
            }
            std::byte *const p = m_base + instr_off;
            p[0] = std::byte{0x48};
            p[1] = std::byte{0x8D};
            p[2] = std::byte{0x05};
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 7);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(addr(target_off)) - next);
            std::memcpy(p + 3, &disp, sizeof(disp));
        }

    private:
        std::byte *m_base;
    };
} // namespace dmk_test

#endif // _WIN32

#endif // DETOURMODKIT_TEST_FAULT_INJECTION_HPP
