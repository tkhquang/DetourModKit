#ifndef DETOURMODKIT_TESTS_FIXTURES_SCRATCH_PAGE_HPP
#define DETOURMODKIT_TESTS_FIXTURES_SCRATCH_PAGE_HPP

/**
 * @file scratch_page.hpp
 * @brief A committed executable scratch page for tests that must plant bytes where DMK's code-only gates accept them.
 *
 * Several DMK gates key on the execute bit -- the scanner's executable page class, and the hook pre-flight's steal
 * window -- so a test that plants synthetic instruction bytes in a static array cannot reach them: a const array lands
 * in read-only data and a mutable one in read-write data, and both are refused before the code under test runs. Tests
 * may decode, patch, or execute the planted bytes.
 */

#include "DetourModKit/region.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>

namespace dmk_test
{
    /**
     * @brief One committed PAGE_EXECUTE_READWRITE page, filled with 0xCC and freed on destruction.
     * @details Fills with int3 so any offset not explicitly planted is an obvious breakpoint rather than zeroes that
     *          decode as a valid instruction. A page this process inline-hooked may be freed once the hook is torn
     *          down: the backend's execution trap is scoped to one patch transaction, so a released address carries
     *          nothing over to whoever allocates it next.
     */
    class ScratchPage
    {
    public:
        static constexpr std::size_t PAGE_SIZE = 0x1000;

        ScratchPage() noexcept
        {
            m_base = VirtualAlloc(nullptr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (m_base != nullptr)
            {
                std::memset(m_base, 0xCC, PAGE_SIZE);
            }
        }

        ~ScratchPage() noexcept
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        ScratchPage(const ScratchPage &) = delete;
        ScratchPage &operator=(const ScratchPage &) = delete;
        ScratchPage(ScratchPage &&) = delete;
        ScratchPage &operator=(ScratchPage &&) = delete;

        /// Whether the page was committed; a false here means the test cannot run, not that it failed.
        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        /// Writes @p bytes at @p offset. The caller keeps the write within @ref PAGE_SIZE.
        void put(std::size_t offset, std::initializer_list<std::uint8_t> bytes) noexcept
        {
            auto *destination = static_cast<std::uint8_t *>(m_base);
            std::size_t i = 0;
            for (const std::uint8_t b : bytes)
            {
                destination[offset + i++] = b;
            }
        }

        [[nodiscard]] std::uintptr_t addr(std::size_t offset = 0) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base) + offset;
        }

        [[nodiscard]] void *base() const noexcept { return m_base; }

        [[nodiscard]] DetourModKit::Region range() const noexcept
        {
            return DetourModKit::Region{DetourModKit::Address{addr()}, PAGE_SIZE};
        }

    private:
        void *m_base{nullptr};
    };
} // namespace dmk_test

#endif // DETOURMODKIT_TESTS_FIXTURES_SCRATCH_PAGE_HPP
