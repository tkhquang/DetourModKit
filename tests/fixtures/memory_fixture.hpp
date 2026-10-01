#ifndef DETOURMODKIT_TESTS_FIXTURES_MEMORY_FIXTURE_HPP
#define DETOURMODKIT_TESTS_FIXTURES_MEMORY_FIXTURE_HPP

/**
 * @file memory_fixture.hpp
 * @brief The MemoryTest fixture and the Region and page-protection helpers that several memory test files share.
 * @details MemoryTest has one definition here, outside any anonymous namespace. docs/design/testing.md owns this rule.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"

#include <gtest/gtest.h>
#include <windows.h>

#include <cstddef>
#include <cstdint>

namespace dmk_test::memory_fixture
{
    using DetourModKit::Address;
    using DetourModKit::Region;
    namespace memory = DetourModKit::memory;

    /** @brief Preserves pointer-shaped fixture inputs as Region values. */

    inline Region region_of(const void *p, std::size_t n) noexcept
    {
        return Region{Address{const_cast<void *>(p)}, n};
    }
    inline Region region_of(std::uintptr_t p, std::size_t n) noexcept
    {
        return Region{Address{p}, n};
    }

    inline bool is_readable(const void *p, std::size_t n) noexcept
    {
        return memory::is_readable(region_of(p, n));
    }
    inline bool is_writable(const void *p, std::size_t n) noexcept
    {
        return memory::is_writable(region_of(p, n));
    }

    class MemoryTest : public ::testing::Test
    {
    protected:
        void SetUp() override { (void)memory::init_cache(); }

        void TearDown() override { memory::shutdown_cache(); }
    };

    /** @brief Returns the current page protection, or zero after a failed VirtualQuery. */
    [[nodiscard]] inline DWORD current_page_protection(const void *address) noexcept
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
        {
            return 0;
        }
        return mbi.Protect;
    }

} // namespace dmk_test::memory_fixture

#endif // DETOURMODKIT_TESTS_FIXTURES_MEMORY_FIXTURE_HPP
