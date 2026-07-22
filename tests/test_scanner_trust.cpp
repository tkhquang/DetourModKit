#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <random>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include "internal/scan_exclusions.hpp"
#include "internal/scan_engine.hpp"
#include "internal/scan_pages.hpp"

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    extern void (*g_scan_after_byte_sweep_test_hook)() noexcept;
} // namespace DetourModKit::detail
#endif

using namespace DetourModKit;

namespace
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    std::uint8_t *s_duplicate_to_remove = nullptr;
    std::size_t s_duplicate_size = 0;

    void remove_duplicate_after_byte_sweep() noexcept
    {
        if (s_duplicate_to_remove != nullptr)
        {
            std::memset(s_duplicate_to_remove, 0, s_duplicate_size);
        }
    }

    class ScanSweepHookGuard
    {
    public:
        ScanSweepHookGuard(std::uint8_t *duplicate, std::size_t size) noexcept
        {
            s_duplicate_to_remove = duplicate;
            s_duplicate_size = size;
            DetourModKit::detail::g_scan_after_byte_sweep_test_hook = &remove_duplicate_after_byte_sweep;
        }

        ~ScanSweepHookGuard() noexcept
        {
            DetourModKit::detail::g_scan_after_byte_sweep_test_hook = nullptr;
            s_duplicate_to_remove = nullptr;
            s_duplicate_size = 0;
        }

        ScanSweepHookGuard(const ScanSweepHookGuard &) = delete;
        ScanSweepHookGuard &operator=(const ScanSweepHookGuard &) = delete;
        ScanSweepHookGuard(ScanSweepHookGuard &&) = delete;
        ScanSweepHookGuard &operator=(ScanSweepHookGuard &&) = delete;
    };
#endif

    struct PatternDestroyer
    {
        void operator()(scan::Pattern *pattern) const noexcept { std::destroy_at(pattern); }
    };

    // A 32-byte needle drawn at runtime so it cannot pre-exist anywhere in the process: the only copies in memory are
    // the ones this test creates. That is what makes "the scan found the query's own storage" the ONLY explanation for
    // a whole-process readable hit, rather than a plausible coincidence with real image bytes.
    std::array<std::uint8_t, 32> make_unique_needle(std::uint32_t salt)
    {
        std::mt19937 engine(0xD37Du ^ salt);
        std::uniform_int_distribution<int> byte_values(1, 255);
        std::array<std::uint8_t, 32> needle{};
        for (std::uint8_t &value : needle)
        {
            value = static_cast<std::uint8_t>(byte_values(engine));
        }
        return needle;
    }

    std::string to_aob(const std::uint8_t *bytes, std::size_t count)
    {
        static constexpr char hex_digits[] = "0123456789ABCDEF";
        std::string aob;
        aob.reserve(count * 3);
        for (std::size_t i = 0; i < count; ++i)
        {
            aob.push_back(hex_digits[bytes[i] >> 4]);
            aob.push_back(hex_digits[bytes[i] & 0x0F]);
            if (i + 1 < count)
            {
                aob.push_back(' ');
            }
        }
        return aob;
    }

    // A committed page the test owns, used as a precisely named scan scope.
    class OwnedPage
    {
    public:
        explicit OwnedPage(DWORD protection = PAGE_READWRITE)
        {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            m_size = si.dwPageSize;
            m_base = static_cast<std::uint8_t *>(VirtualAlloc(nullptr, m_size, MEM_COMMIT | MEM_RESERVE, protection));
        }

        ~OwnedPage() noexcept
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        OwnedPage(const OwnedPage &) = delete;
        OwnedPage &operator=(const OwnedPage &) = delete;
        OwnedPage(OwnedPage &&) = delete;
        OwnedPage &operator=(OwnedPage &&) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uint8_t *bytes() noexcept { return m_base; }
        [[nodiscard]] std::size_t size() const noexcept { return m_size; }
        [[nodiscard]] Region range() const noexcept
        {
            return Region{Address{reinterpret_cast<std::uintptr_t>(m_base)}, m_size};
        }

    private:
        std::uint8_t *m_base = nullptr;
        std::size_t m_size = 0;
    };
} // namespace

TEST(ScannerTrustProof, ExclusionsCoalesceBridgedSpansBeforeCapacityCheck)
{
    detail::ScanExclusions exclusions;
    exclusions.add(0x1000, 0x10);
    exclusions.add(0x1020, 0x10);
    exclusions.add(0x1010, 0x10);
    for (std::size_t i = 0; i < detail::ScanExclusions::MAX_SPANS - 1; ++i)
    {
        exclusions.add(0x2000 + i * 0x20, 0x10);
    }
    EXPECT_FALSE(exclusions.overflowed());
    EXPECT_TRUE(exclusions.overlaps(0x1000, 0x1030));

    // The set is now exactly full. A span that merges into an existing entry consumes no slot, so it must still be
    // accepted: hoisting the capacity check ahead of the merge loop would latch overflow here and discard it.
    exclusions.add(0x1030, 0x10);
    EXPECT_FALSE(exclusions.overflowed());
    EXPECT_TRUE(exclusions.overlaps(0x1035, 0x1036));

    exclusions.add(0x8000, 0x10);
    EXPECT_TRUE(exclusions.overflowed());

    detail::ScanExclusions wrapping;
    wrapping.add(UINTPTR_MAX - 3, 8);
    EXPECT_TRUE(wrapping.overflowed());
}

// A whole-process readable sweep reads the pages the caller's own copies of the query bytes live on, and DMK cannot
// enumerate a caller-retained copy. It must refuse to answer rather than hand back an address that may be the needle's
// own storage. The runtime-generated needle makes a coincidental image match negligible.
TEST(ScannerTrustProof, WholeProcessReadableScanCannotAuthorizeQueryOwnedMatch)
{
    const auto needle = make_unique_needle(1);
    const auto pattern = scan::Pattern::compile(to_aob(needle.data(), needle.size()));
    ASSERT_TRUE(pattern.has_value());

    const auto result = scan::scan(*pattern, Region::whole_process(), 1, scan::Pages::Readable);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NotAuthoritative);
}

// The refusal is specific to the page class that can hold query material. Query bytes are data, and no DMK query
// representation is placed on an execute-readable page, so whole-process EXECUTABLE discovery stays available. A
// planted executable fixture is the positive control: the executable sweep must still find real code.
TEST(ScannerTrustProof, WholeProcessExecutableDiscoveryStaysAvailable)
{
    const auto needle = make_unique_needle(2);
    OwnedPage code(PAGE_EXECUTE_READWRITE);
    ASSERT_TRUE(code.ok());
    std::memcpy(code.bytes() + 0x80, needle.data(), needle.size());

    const auto pattern = scan::Pattern::compile(to_aob(needle.data(), needle.size()));
    ASSERT_TRUE(pattern.has_value());

    const auto result = scan::scan(*pattern, Region::whole_process(), 1, scan::Pages::Executable);
    ASSERT_TRUE(result.has_value()) << DetourModKit::to_string(result.error().code);
    EXPECT_EQ(result->raw(), reinterpret_cast<std::uintptr_t>(code.bytes() + 0x80));
}

// Declaring the caller's copies is the documented way to make a whole-process readable scan answerable: DMK excludes
// what it owns, the caller declares what it owns. The declaration is what lifts the refusal, and a declared span must
// never be the address the scan reports.
//
// What this case deliberately does NOT claim is that the plant is then the FIRST match. A whole-process readable sweep
// also reads abandoned stack frames, and the byte-identical residue a returned-by-value buffer leaves behind there is
// not a live object any API can enumerate. That residue is exactly why the contract is "declare your copies to lift the
// refusal", not "declare your copies and the scan becomes exact"; the in-scope companion case below pins the exclusion
// arithmetic itself, where no such residue can exist.
TEST(ScannerTrustProof, DeclaredExclusionsRestoreWholeProcessReadableAuthority)
{
    const auto needle = make_unique_needle(3);
    OwnedPage data;
    ASSERT_TRUE(data.ok());
    std::memcpy(data.bytes() + 0x200, needle.data(), needle.size());

    // A retained caller-side copy that is NOT the target.
    std::vector<std::uint8_t> retained(needle.begin(), needle.end());

    const auto pattern = scan::Pattern::compile(to_aob(needle.data(), needle.size()));
    ASSERT_TRUE(pattern.has_value());

    const Region declared[] = {
        Region{Address{reinterpret_cast<std::uintptr_t>(retained.data())}, retained.size()},
        Region{Address{reinterpret_cast<std::uintptr_t>(needle.data())}, needle.size()},
    };

    // Without the declaration the same scan is refused outright, so the declaration is what changes the outcome.
    const auto refused = scan::scan(*pattern, Region::whole_process(), 1, scan::Pages::Readable);
    ASSERT_FALSE(refused.has_value());
    ASSERT_EQ(refused.error().code, ErrorCode::NotAuthoritative);

    const auto result = scan::scan(*pattern, Region::whole_process(), declared, 1, scan::Pages::Readable);
    ASSERT_TRUE(result.has_value()) << DetourModKit::to_string(result.error().code);
    for (const Region &span : declared)
    {
        EXPECT_FALSE(result->raw() >= span.base.raw() && result->raw() < span.base.raw() + span.size)
            << "the scan reported a span the caller declared as its own query storage";
    }
}

// A scope the caller named precisely stays usable without any declaration: one allocation is exactly "search this
// buffer", not "search whatever is mapped". This is the boundary that keeps the authority gate from turning every
// readable scan of a caller-owned buffer into a refusal.
TEST(ScannerTrustProof, SingleAllocationScopeStaysAuthoritative)
{
    const auto needle = make_unique_needle(4);
    OwnedPage page;
    ASSERT_TRUE(page.ok());
    std::memcpy(page.bytes() + 0x40, needle.data(), needle.size());

    const auto pattern = scan::Pattern::compile(to_aob(needle.data(), needle.size()));
    ASSERT_TRUE(pattern.has_value());

    const auto result = scan::scan(*pattern, page.range(), 1, scan::Pages::Readable);
    ASSERT_TRUE(result.has_value()) << DetourModKit::to_string(result.error().code);
    EXPECT_EQ(result->raw(), reinterpret_cast<std::uintptr_t>(page.bytes() + 0x40));
}

// The engine's floor guarantee is independent of scope and caller declarations: a scan never reports the compiled
// pattern's own buffers or the value Pattern's own storage. The query object is deliberately placed inside the scanned
// scope, and the scan must still resolve to the separate plant alone.
TEST(ScannerTrustProof, QueryStorageInsideTheScopeIsNeverCounted)
{
    const auto needle = make_unique_needle(5);
    OwnedPage page;
    ASSERT_TRUE(page.ok());

    const auto compiled = scan::Pattern::compile(to_aob(needle.data(), needle.size()));
    ASSERT_TRUE(compiled.has_value());
    void *storage = page.bytes() + 0x100;
    std::size_t storage_size = 0x500;
    ASSERT_NE(std::align(alignof(scan::Pattern), sizeof(scan::Pattern), storage, storage_size), nullptr);
    std::unique_ptr<scan::Pattern, PatternDestroyer> pattern{
        std::construct_at(static_cast<scan::Pattern *>(storage), *compiled)};
    std::memcpy(page.bytes() + 0x800, needle.data(), needle.size());

    const auto first = scan::scan(*pattern, page.range(), 1, scan::Pages::Readable);
    ASSERT_TRUE(first.has_value()) << DetourModKit::to_string(first.error().code);
    EXPECT_EQ(first->raw(), reinterpret_cast<std::uintptr_t>(page.bytes() + 0x800));

    const auto second = scan::scan(*pattern, page.range(), 2, scan::Pages::Readable);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::NoMatch);
}

// Mask-shaped query material: an all-wildcard-adjacent pattern whose literal bytes are 0xFF matches the mask buffer the
// engine builds beside the byte buffer. Excluding only the byte buffer would leave the mask reachable, so a readable
// sweep could return the engine's own mask storage.
TEST(ScannerTrustProof, EngineMaskStorageIsNeverReturned)
{
    std::string aob;
    for (std::size_t i = 0; i < 128; ++i)
    {
        aob += (i == 0) ? "FF" : " FF";
    }
    const auto pattern = detail::parse_aob(aob);
    ASSERT_TRUE(pattern.has_value());

    // Scan exactly the engine's all-0xFF mask buffer. Engine-owned exclusions apply below the public authority gate, so
    // the buffer cannot report itself as the match.
    const std::uintptr_t mask_base = reinterpret_cast<std::uintptr_t>(pattern->mask.data());
    const detail::ModuleSpan mask_range{mask_base, mask_base + pattern->mask.size()};
    const detail::MatchResult result =
        detail::scan_module_readable(*pattern, mask_range, detail::ScanQuery{.occurrence = 1});
    EXPECT_EQ(result.match, nullptr);
}

// The caller-declared half of the exclusion contract, which the engine floor guarantee above cannot cover: a copy the
// CALLER owns inside the scanned scope must stop being an occurrence once it is declared, and must be one while it is
// not. Both directions are asserted, so removing add_regions from the scan path fails this.
TEST(ScannerTrustProof, DeclaredExclusionsAreHonouredInsideTheScope)
{
    const auto needle = make_unique_needle(8);
    OwnedPage page;
    ASSERT_TRUE(page.ok());
    std::memcpy(page.bytes() + 0x40, needle.data(), needle.size());
    std::memcpy(page.bytes() + 0x800, needle.data(), needle.size());

    const auto pattern = scan::Pattern::compile(to_aob(needle.data(), needle.size()));
    ASSERT_TRUE(pattern.has_value());

    // Undeclared, the caller's copy is an ordinary second occurrence.
    const auto undeclared = scan::scan(*pattern, page.range(), 2, scan::Pages::Readable);
    ASSERT_TRUE(undeclared.has_value()) << DetourModKit::to_string(undeclared.error().code);
    EXPECT_EQ(undeclared->raw(), reinterpret_cast<std::uintptr_t>(page.bytes() + 0x800));

    const Region declared[] = {
        Region{Address{reinterpret_cast<std::uintptr_t>(page.bytes() + 0x800)}, needle.size()},
    };
    const auto first = scan::scan(*pattern, page.range(), declared, 1, scan::Pages::Readable);
    ASSERT_TRUE(first.has_value()) << DetourModKit::to_string(first.error().code);
    EXPECT_EQ(first->raw(), reinterpret_cast<std::uintptr_t>(page.bytes() + 0x40));

    const auto second = scan::scan(*pattern, page.range(), declared, 2, scan::Pages::Readable);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::NoMatch);
}

// The occurrence cap must not wrap when a caller asks for the last representable occurrence while also requesting the
// beyond-count: SIZE_MAX has no representable target + 1, so the cap has to saturate at target rather than wrap to
// zero and trip on the first counted match. The count is the observable, so it is what this asserts.
TEST(ScannerTrustProof, MaximumOccurrenceDoesNotWrapTheCountCap)
{
    const auto needle = make_unique_needle(9);
    OwnedPage page;
    ASSERT_TRUE(page.ok());
    std::memcpy(page.bytes() + 0x40, needle.data(), needle.size());
    std::memcpy(page.bytes() + 0x400, needle.data(), needle.size());
    std::memcpy(page.bytes() + 0x800, needle.data(), needle.size());

    const auto pattern = detail::parse_aob(to_aob(needle.data(), needle.size()));
    ASSERT_TRUE(pattern.has_value());

    const auto base = reinterpret_cast<std::uintptr_t>(page.bytes());
    const detail::ModuleSpan range{base, base + page.size()};
    const detail::MatchResult result = detail::scan_module_readable(
        *pattern, range,
        detail::ScanQuery{.occurrence = std::numeric_limits<std::size_t>::max(), .count_beyond = true});
    EXPECT_EQ(result.match, nullptr);
    EXPECT_EQ(result.count, 3u);
    EXPECT_FALSE(result.truncated());
}

// The ladder resolver applies the same rule: its Candidate array and owned literals are query material, and an
// unconfined readable scope makes every tier unprovable, so the request is refused before any candidate is graded.
TEST(ScannerTrustProof, ResolveRefusesUnconfinedReadableScope)
{
    const auto needle = make_unique_needle(6);
    const auto pattern = scan::Pattern::compile(to_aob(needle.data(), needle.size()));
    ASSERT_TRUE(pattern.has_value());

    const scan::Candidate ladder[] = {scan::Candidate::direct("unconfined", *pattern)};
    scan::ScanRequest request{};
    request.ladder = ladder;
    request.label = "trust-proof";
    request.scope = Region::whole_process();
    request.pages = scan::Pages::Readable;

    const auto hit = scan::resolve(request);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NotAuthoritative);

    // The executable page class stays usable for the same ladder, so discovery is narrowed, not removed.
    request.pages = scan::Pages::Executable;
    const auto executable_hit = scan::resolve(request);
    ASSERT_FALSE(executable_hit.has_value());
    EXPECT_EQ(executable_hit.error().code, ErrorCode::NoMatch);
}

#if defined(DMK_ENABLE_TEST_SEAMS)
// The combined sweep must retain its observed ambiguity even if the duplicate disappears immediately after traversal.
// Re-reading memory for a separate uniqueness decision would combine observations from incompatible memory states.
TEST(ScannerTrustProof, MutationAfterCombinedSweepCannotUpgradeAmbiguousResult)
{
    const auto needle = make_unique_needle(7);
    OwnedPage page(PAGE_EXECUTE_READWRITE);
    ASSERT_TRUE(page.ok());
    std::memcpy(page.bytes() + 0x40, needle.data(), needle.size());

    const auto pattern = scan::Pattern::compile(to_aob(needle.data(), needle.size()));
    ASSERT_TRUE(pattern.has_value());
    const scan::Candidate ladder[] = {scan::Candidate::direct("mutating", *pattern)};
    scan::ScanRequest request{};
    request.ladder = ladder;
    request.label = "live-mutation";
    request.scope = page.range();
    request.pages = scan::Pages::Executable;
    request.require_unique = true;

    std::memcpy(page.bytes() + 0x800, needle.data(), needle.size());
    {
        ScanSweepHookGuard hook_guard(page.bytes() + 0x800, needle.size());
        const auto ambiguous = scan::resolve(request);
        ASSERT_FALSE(ambiguous.has_value());
        EXPECT_EQ(ambiguous.error().code, ErrorCode::NoMatch);
    }
    for (std::size_t i = 0; i < needle.size(); ++i)
    {
        EXPECT_EQ(page.bytes()[0x800 + i], 0);
    }

    const auto unique_hit = scan::resolve(request);
    ASSERT_TRUE(unique_hit.has_value()) << DetourModKit::to_string(unique_hit.error().code);
    EXPECT_EQ(unique_hit->address.raw(), reinterpret_cast<std::uintptr_t>(page.bytes() + 0x40));
}
#endif

// A truncated sweep proved nothing about the bytes it never visited, so it must not be reported as a clean miss, and
// its two causes must stay distinguishable: an over-broad bounded-jump pattern is the caller's signature problem, while
// a skipped faulted region is a concurrent unmap of the scanned range.
TEST(ScannerTrustProof, BudgetExhaustionIsNotReportedAsNoMatch)
{
    OwnedPage page;
    ASSERT_TRUE(page.ok());
    std::memset(page.bytes(), 0x00, page.size());
    page.bytes()[0] = 0xA5; // an anchor whose whole reachable range holds no 0xFF, so the extension burns the budget

    const auto pattern = scan::Pattern::compile(
        "A5 [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] ?? [0-255] FF");
    ASSERT_TRUE(pattern.has_value());

    const auto result = scan::scan(*pattern, page.range(), 1, scan::Pages::Readable);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::BudgetExceeded);

    const scan::Candidate ladder[] = {scan::Candidate::direct("budget", *pattern)};
    const scan::ScanRequest request{
        .ladder = ladder,
        .label = "budget",
        .scope = page.range(),
        .pages = scan::Pages::Readable,
    };
    const auto resolved = scan::resolve(request);
    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error().code, ErrorCode::BudgetExceeded);

    // A pattern that genuinely is not present, over the same scope, still reports the ordinary miss, so BudgetExceeded
    // is not simply what this scope always returns.
    const auto absent = scan::Pattern::compile("11 22 33 44 55 66 77 88 99 AA BB CC DD EE");
    ASSERT_TRUE(absent.has_value());
    const auto missing = scan::scan(*absent, page.range(), 1, scan::Pages::Readable);
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, ErrorCode::NoMatch);
}
