// T-FASTSTRING: the fast-string straddling-store matrix behind DMK's hard "nothing was written" guarantee.
//
// x86-64 lets the `rep movsb` body of copy_with_fault_progress retire its stores out of order, so a fault on the FIRST
// destination byte can in principle coexist with committed stores to later, writable bytes. Both guarded stores
// (the MSVC __try arm and the MinGW vectored arm of src/internal/memory_guarded.cpp) classify on nothing more than
// `fault_address == address`, so NotWritten, and the ErrorCode::WriteFaulted that memory::write_bytes surfaces from
// it, are truthful only while that allowance is never taken. This matrix pins the observed behavior against CPU and
// toolchain drift. It is one microarchitecture's evidence, not an SDM guarantee: a red here is a signal to re-derive
// the classification on this host, not automatically a DMK defect.
//
// A fault the span filter refuses to claim is not contained and terminates the host, so reaching any assertion below
// is itself the evidence that no fault escaped the filter.
//
// These live outside the in-tree tests/test_*.cpp glob on purpose: fault fixtures are compiled and run by
// scripts/run_fault_tests.sh against a configured tree, not by the main test target.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <vector>

#include "internal/memory_guarded.hpp"

#include "fault_injection.hpp"

using namespace DetourModKit;

namespace
{
    using DetourModKit::detail::GuardedWriteStatus;

    // Every width is above the fixed-width switch in copy_with_fault_progress, so each one reaches the `rep movsb`
    // body the fast-string allowance applies to. The narrow widths straddle the SIMD-sized steps a wide copy takes.
    constexpr std::size_t SPANS[] = {9, 16, 17, 63, 64, 65, 128, 257, 1024, 4095, 4096, 8192, 65536, 262144};
    constexpr std::size_t MAX_SPAN = SPANS[std::size(SPANS) - 1];

    // Byte counts of the destination that land on the blocked page. 1 and 7 sit inside a page so the copy starts
    // mid-page; PAGE_BYTES starts the copy at the page base, which is the aligned case a wide body handles first.
    constexpr std::size_t BLOCKED_PREFIXES[] = {1, 7, dmk_test::PAGE_BYTES};

    // Writable bytes ahead of the seam, and how far past it the span reaches.
    constexpr std::size_t SEAM_PREFIXES[] = {128, 2048, 3072};
    constexpr std::size_t SEAM_OVERRUNS[] = {64, dmk_test::PAGE_BYTES};

    // Both protections raise the same access violation for a store, and both are reached through different kernel
    // paths, so a classification that holds for only one is a real gap.
    constexpr DWORD PROTECTIONS[] = {PAGE_NOACCESS, PAGE_READONLY};

    // The allowance is a permission, not a schedule, so one pass can miss a reordering a later pass performs. Four
    // passes per layout keeps the matrix a cheap permanent gate. The exhaustive hundred-iteration sweep that first
    // established the invariant is recorded in the roadmap and is not re-run here.
    constexpr int PASSES = 4;

    constexpr std::uint8_t SENTINEL = 0xA5;
    constexpr std::uint8_t SOURCE_FILL = 0x5C;

    /**
     * @brief One reusable committed region whose pages are re-seeded and re-blocked per layout.
     * @details Every layout seeds the whole region writable and refills it, then blocks exactly one page, so no layout
     *          can inherit another's bytes or another's protection and read a stale pass as a fresh one.
     */
    class StraddleRegion
    {
    public:
        explicit StraddleRegion(std::size_t bytes) noexcept
            : m_bytes(bytes),
              m_base(static_cast<std::byte *>(::VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
        {
        }

        ~StraddleRegion() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        StraddleRegion(const StraddleRegion &) = delete;
        StraddleRegion &operator=(const StraddleRegion &) = delete;
        StraddleRegion(StraddleRegion &&) = delete;
        StraddleRegion &operator=(StraddleRegion &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uintptr_t addr_of(std::size_t offset) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base) + offset;
        }

        /// Make every page writable again and refill it with @ref SENTINEL.
        [[nodiscard]] bool seed() noexcept
        {
            DWORD previous = 0;
            if (::VirtualProtect(m_base, m_bytes, PAGE_READWRITE, &previous) == FALSE)
            {
                return false;
            }
            std::memset(m_base, SENTINEL, m_bytes);
            return true;
        }

        /// Pin one page to @p protection so any store into it faults deterministically.
        [[nodiscard]] bool block(std::size_t page_offset, DWORD protection) noexcept
        {
            DWORD previous = 0;
            return ::VirtualProtect(m_base + page_offset, dmk_test::PAGE_BYTES, protection, &previous) != FALSE;
        }

        /**
         * @brief Count bytes in [@p offset, @p offset + @p count) that do not hold @p value.
         * @warning The caller must name a range that is still writable. A read of the blocked page faults the test
         *          itself, which is the harness bug the first round of this proof recorded.
         */
        [[nodiscard]] std::size_t count_not_equal(std::size_t offset, std::size_t count,
                                                  std::uint8_t value) const noexcept
        {
            std::size_t bad = 0;
            for (std::size_t i = 0; i < count; ++i)
            {
                if (static_cast<std::uint8_t>(m_base[offset + i]) != value)
                {
                    ++bad;
                }
            }
            return bad;
        }

    private:
        std::size_t m_bytes;
        std::byte *m_base;
    };
} // namespace

// A destination whose first byte lies on a blocked page must report NotWritten and must leave every writable byte of
// the span untouched. A single committed tail byte makes NotWritten, and the WriteFaulted a caller acts on, a lie:
// the caller restores nothing while the target carries a partial patch.
TEST(FastStringStraddle, BlockedFirstByteReportsNotWrittenAndCommitsNoTailByte)
{
    // [blocked page][writable tail]. A destination at PAGE_BYTES - prefix puts exactly `prefix` bytes on the blocked
    // page, so the widest span still ends inside the allocation.
    StraddleRegion region(dmk_test::PAGE_BYTES + MAX_SPAN);
    ASSERT_TRUE(region.ok()) << "VirtualAlloc failed to set up the straddle region";

    const std::vector<std::byte> source(MAX_SPAN, std::byte{SOURCE_FILL});

    for (const DWORD protection : PROTECTIONS)
    {
        for (const std::size_t prefix : BLOCKED_PREFIXES)
        {
            for (const std::size_t span : SPANS)
            {
                const std::size_t destination_offset = dmk_test::PAGE_BYTES - prefix;
                const std::size_t tail = span > prefix ? span - prefix : 0;

                for (int pass = 0; pass < PASSES; ++pass)
                {
                    ASSERT_TRUE(region.seed());
                    ASSERT_TRUE(region.block(0, protection));

                    const GuardedWriteStatus status =
                        detail::guarded_write_bytes(region.addr_of(destination_offset), source.data(), span);

                    ASSERT_EQ(status, GuardedWriteStatus::NotWritten)
                        << "protection=" << protection << " blocked prefix=" << prefix << " span=" << span
                        << " pass=" << pass;
                    ASSERT_EQ(region.count_not_equal(dmk_test::PAGE_BYTES, tail, SENTINEL), 0u)
                        << "a store committed past the faulting first byte: protection=" << protection
                        << " blocked prefix=" << prefix << " span=" << span << " pass=" << pass;
                }
            }
        }
    }
}

// The complement. A span that faults after progress must report MayBePartial, and the writable prefix ahead of the
// seam must be fully committed. That prefix is what makes MayBePartial conservative rather than merely vague, and it
// is the half a caller's own restore path has to cover.
TEST(FastStringStraddle, MidSpanSeamReportsMayBePartialWithTheFullPrefixCommitted)
{
    // [writable page][blocked page]. Every seam prefix is under one page, so the seam is always the second page base.
    StraddleRegion region(2 * dmk_test::PAGE_BYTES);
    ASSERT_TRUE(region.ok()) << "VirtualAlloc failed to set up the seam region";

    const std::vector<std::byte> source(2 * dmk_test::PAGE_BYTES, std::byte{SOURCE_FILL});

    for (const DWORD protection : PROTECTIONS)
    {
        for (const std::size_t prefix : SEAM_PREFIXES)
        {
            for (const std::size_t overrun : SEAM_OVERRUNS)
            {
                const std::size_t destination_offset = dmk_test::PAGE_BYTES - prefix;

                for (int pass = 0; pass < PASSES; ++pass)
                {
                    ASSERT_TRUE(region.seed());
                    ASSERT_TRUE(region.block(dmk_test::PAGE_BYTES, protection));

                    const GuardedWriteStatus status = detail::guarded_write_bytes(region.addr_of(destination_offset),
                                                                                  source.data(), prefix + overrun);

                    ASSERT_EQ(status, GuardedWriteStatus::MayBePartial)
                        << "protection=" << protection << " seam prefix=" << prefix << " overrun=" << overrun
                        << " pass=" << pass;
                    ASSERT_EQ(region.count_not_equal(destination_offset, prefix, SOURCE_FILL), 0u)
                        << "the writable prefix ahead of the seam was not fully committed: protection=" << protection
                        << " seam prefix=" << prefix << " overrun=" << overrun << " pass=" << pass;
                }
            }
        }
    }
}
