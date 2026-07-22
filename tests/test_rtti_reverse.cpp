#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>

#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"

namespace memory = DetourModKit::memory;
namespace rtti = DetourModKit::rtti;
using DetourModKit::Address;
using DetourModKit::Region;

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    extern std::uint64_t (*g_rtti_resolve_clock_override)() noexcept;
    extern std::uint64_t (*g_rtti_image_generation_override)(std::uintptr_t address) noexcept;
    extern Region (*g_rtti_module_region_override)(Address address) noexcept;
#endif
} // namespace DetourModKit::detail

namespace
{
    // Synthetic MSVC x64 RTTI layout offsets, mirroring the dissector fixture in test_rtti_dissect.cpp. Chosen so the
    // COL, TypeDescriptor, and vtable storage live apart from each other and from page boundaries.
    constexpr std::size_t REV_BUF_SIZE = 4096;
    constexpr std::size_t REV_COL_OFFSET = 256;
    constexpr std::size_t REV_TD_OFFSET = REV_COL_OFFSET + 24; // COL is 24 bytes
    constexpr std::size_t REV_TD_NAME_OFFSET = REV_TD_OFFSET + 16;
    constexpr std::size_t REV_COL_PTR_OFFSET = 2048; // the vtable[-1] meta-slot
    constexpr std::size_t REV_VTABLE_OFFSET = REV_COL_PTR_OFFSET + 8;

    // Static pool in the test executable's data segment so memory::module_of resolves every synthetic vtable
    // back to the test exe's PE range, which the shared prelude's bound check requires. Reset between tests. Sized to
    // hold one full MAX_REVERSE_MATCHES (64) saturation set plus the small fixtures every other case builds.
    constexpr std::size_t REV_POOL_FIXTURES = 64;
    alignas(8) std::array<std::byte, REV_BUF_SIZE * REV_POOL_FIXTURES> s_rev_pool{};
    std::size_t s_rev_used = 0;

    void rev_reset() noexcept
    {
        s_rev_used = 0;
        std::memset(s_rev_pool.data(), 0, s_rev_pool.size());
    }

    template <typename T> void rev_write(std::byte *buf, std::size_t off, const T &value) noexcept
    {
        std::memcpy(buf + off, &value, sizeof(T));
    }

    // Builds one synthetic COL/TypeDescriptor/vtable carrying @p name at sub-object offset @p col_offset, and returns
    // the synthetic vtable address. RVAs are computed against the test exe image base so the prelude accepts them.
    [[nodiscard]] std::uintptr_t build_synth(std::string_view name, std::uint32_t col_offset) noexcept
    {
        if (s_rev_used + REV_BUF_SIZE > s_rev_pool.size())
        {
            return 0;
        }
        std::byte *buf = s_rev_pool.data() + s_rev_used;
        s_rev_used += REV_BUF_SIZE;
        std::memset(buf, 0, REV_BUF_SIZE);

        const std::uintptr_t exe_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const std::uintptr_t buf_base = reinterpret_cast<std::uintptr_t>(buf);

        // The synthetic RVAs are (buffer - image base), which underflows if the data segment ever sits below the image
        // base; bail rather than emit a wrapped RVA that would later look like a resolve failure.
        if (buf_base < exe_base)
        {
            return 0;
        }
        const std::uintptr_t buf_rva = buf_base - exe_base;

        rev_write<std::uint32_t>(buf, REV_COL_OFFSET + 0, 1);          // signature (x64)
        rev_write<std::uint32_t>(buf, REV_COL_OFFSET + 4, col_offset); // offset in complete object
        rev_write<std::uint32_t>(buf, REV_COL_OFFSET + 8, 0);          // cd_offset
        rev_write<std::uint32_t>(buf, REV_COL_OFFSET + 12,
                                 static_cast<std::uint32_t>(buf_rva + REV_TD_OFFSET)); // p_type_descriptor
        rev_write<std::uint32_t>(buf, REV_COL_OFFSET + 16, 0);                         // p_class_descriptor
        rev_write<std::uint32_t>(buf, REV_COL_OFFSET + 20,
                                 static_cast<std::uint32_t>(buf_rva + REV_COL_OFFSET)); // p_self

        const std::size_t max_name = REV_COL_PTR_OFFSET - REV_TD_NAME_OFFSET - 1;
        const std::size_t name_len = name.size() < max_name ? name.size() : max_name;
        std::memcpy(buf + REV_TD_NAME_OFFSET, name.data(), name_len);
        buf[REV_TD_NAME_OFFSET + name_len] = std::byte{0};

        const std::uintptr_t col_addr = buf_base + REV_COL_OFFSET;
        rev_write<std::uintptr_t>(buf, REV_COL_PTR_OFFSET, col_addr);

        return buf_base + REV_VTABLE_OFFSET;
    }

    // The pool sub-range written so far, used as a tight search scope. It is not a
    // PE image, so collect_rtti_scan_ranges' header parse fails and the resolver sweeps exactly this range;
    // resolve_col_site still validates every hit against the real owning module. This keeps the unit tests fast and
    // deterministic instead of sweeping the whole multi-megabyte test executable.
    [[nodiscard]] Region pool_range() noexcept
    {
        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(s_rev_pool.data());
        return Region{Address{base}, s_rev_used};
    }

    // Writes a fresh pool slice whose only in-scope qword is a meta-slot pointing back into the slice, so the sweep's
    // mod.contains() pre-filter accepts it, but the pointed-to location is not a signature-1 COL. This forces the
    // shared resolve_col_site prelude to run and reject the candidate; an all-zero buffer would be dropped by the
    // pre-filter before validation and would not prove the predicate uses the shared COL checks.
    [[nodiscard]] Region build_in_range_decoy() noexcept
    {
        if (s_rev_used + REV_BUF_SIZE > s_rev_pool.size())
        {
            return Region{};
        }
        std::byte *buf = s_rev_pool.data() + s_rev_used;
        s_rev_used += REV_BUF_SIZE;
        std::memset(buf, 0, REV_BUF_SIZE);
        const std::uintptr_t buf_base = reinterpret_cast<std::uintptr_t>(buf);
        // The meta-slot points at an in-range, zeroed location. The pre-filter passes, then resolve_col_site rejects
        // it at the x64 COL signature check.
        rev_write<std::uintptr_t>(buf, REV_COL_PTR_OFFSET, buf_base + REV_COL_OFFSET);
        return Region{Address{buf_base}, REV_BUF_SIZE};
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    std::atomic<std::uint64_t> s_fake_clock_ms{0};

    std::uint64_t fake_clock() noexcept
    {
        return s_fake_clock_ms.load(std::memory_order_relaxed);
    }

    struct RttiClockScope
    {
        RttiClockScope() noexcept { DetourModKit::detail::g_rtti_resolve_clock_override = &fake_clock; }
        ~RttiClockScope() noexcept { DetourModKit::detail::g_rtti_resolve_clock_override = nullptr; }
        RttiClockScope(const RttiClockScope &) = delete;
        RttiClockScope &operator=(const RttiClockScope &) = delete;
    };
#endif
} // anonymous namespace

class RttiReverseTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        (void)memory::init_cache();
        rev_reset();
    }

    void TearDown() override { memory::shutdown_cache(); }
};

TEST_F(RttiReverseTest, SingleInheritanceResolvesPrimaryVtable)
{
    const std::uintptr_t vt = build_synth(".?AVRevSingle@@", 0);
    ASSERT_NE(vt, 0u);

    const auto found = rtti::vtable_for_type(".?AVRevSingle@@", pool_range());
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->raw(), vt);

    // Round-trip invariant: the reverse result must satisfy the forward check.
    EXPECT_TRUE(rtti::vtable_is_type(*found, ".?AVRevSingle@@"));

    Address all[4] = {};
    const std::size_t n = rtti::vtables_for_type(".?AVRevSingle@@", all, 4, pool_range());
    EXPECT_EQ(n, 1u);
    EXPECT_EQ(all[0].raw(), vt);
}

TEST_F(RttiReverseTest, MultipleInheritanceReturnsAllSubObjectVtables)
{
    // One mangled name, two sub-object COLs at different offsets: the primary (offset 0) and a secondary base (offset
    // 0x10).
    const std::uintptr_t primary = build_synth(".?AVRevMulti@@", 0);
    const std::uintptr_t secondary = build_synth(".?AVRevMulti@@", 0x10);
    ASSERT_NE(primary, 0u);
    ASSERT_NE(secondary, 0u);

    // The singular resolver returns only the offset==0 primary.
    const auto found = rtti::vtable_for_type(".?AVRevMulti@@", pool_range());
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->raw(), primary);

    // The plural resolver returns both, primary (offset 0) first.
    Address all[4] = {};
    const std::size_t n = rtti::vtables_for_type(".?AVRevMulti@@", all, 4, pool_range());
    ASSERT_EQ(n, 2u);
    EXPECT_EQ(all[0].raw(), primary);
    EXPECT_EQ(all[1].raw(), secondary);
}

TEST_F(RttiReverseTest, AmbiguousPrimaryFailsClosed)
{
    // Two distinct offset==0 vtables with the same name (a type linked into the image twice): the singular resolver
    // must fail closed, not pick one.
    ASSERT_NE(build_synth(".?AVRevDup@@", 0), 0u);
    ASSERT_NE(build_synth(".?AVRevDup@@", 0), 0u);

    EXPECT_FALSE(rtti::vtable_for_type(".?AVRevDup@@", pool_range()).has_value());

    // The plural form still reports both distinct matches.
    Address all[4] = {};
    const std::size_t n = rtti::vtables_for_type(".?AVRevDup@@", all, 4, pool_range());
    EXPECT_EQ(n, 2u);
}

TEST_F(RttiReverseTest, PrimaryFailsClosedWhenMatchCollectorSaturates)
{
    // Saturate the reverse-scan match collector. MAX_REVERSE_MATCHES (64, internal to rtti.cpp) distinct vtables share
    // one name: a single primary (COL.offset 0) plus enough distinct secondary sub-objects to fill the cap. Because the
    // collector truncated at the cap, a second distinct primary could exist beyond it that the in-collection uniqueness
    // check never saw, so the singular resolver must fail closed rather than hand back the one primary it happened to
    // collect. AmbiguousPrimaryFailsClosed covers the in-collection ambiguity; this pins the truncated-scan case.
    constexpr std::size_t cap = 64;                     // == MAX_REVERSE_MATCHES in rtti.cpp
    ASSERT_NE(build_synth(".?AVRevSaturate@@", 0), 0u); // the lone primary the collector does see
    for (std::size_t i = 1; i < cap; ++i)
    {
        // Distinct secondary sub-object vtables (COL.offset != 0), each at a unique address, so all dedupe-distinct and
        // the collector fills to exactly the cap.
        ASSERT_NE(build_synth(".?AVRevSaturate@@", 0x10), 0u);
    }

    EXPECT_FALSE(rtti::vtable_for_type(".?AVRevSaturate@@", pool_range()).has_value());

    // The plural form does not fail closed -- it is inherently multi-valued -- and reports the saturated count (capped
    // at MAX_REVERSE_MATCHES) so a caller can detect the truncation itself.
    Address all[cap] = {};
    EXPECT_EQ(rtti::vtables_for_type(".?AVRevSaturate@@", all, cap, pool_range()), cap);
}

TEST_F(RttiReverseTest, UnknownNameReturnsNullopt)
{
    ASSERT_NE(build_synth(".?AVRevPresent@@", 0), 0u);

    EXPECT_FALSE(rtti::vtable_for_type(".?AVRevAbsent@@", pool_range()).has_value());
    Address all[4] = {};
    EXPECT_EQ(rtti::vtables_for_type(".?AVRevAbsent@@", all, 4, pool_range()), 0u);
}

TEST_F(RttiReverseTest, InvalidRangeReturnsNullopt)
{
    ASSERT_NE(build_synth(".?AVRevInvalid@@", 0), 0u);

    const Region invalid{}; // base == size == 0 => empty range
    EXPECT_FALSE(rtti::vtable_for_type(".?AVRevInvalid@@", invalid).has_value());
    Address all[4] = {};
    EXPECT_EQ(rtti::vtables_for_type(".?AVRevInvalid@@", all, 4, invalid), 0u);
}

TEST_F(RttiReverseTest, VtablesForTypeCountOnlyWithNullOut)
{
    ASSERT_NE(build_synth(".?AVRevCount@@", 0), 0u);
    ASSERT_NE(build_synth(".?AVRevCount@@", 0x08), 0u);

    // A count-only query (null buffer, zero capacity) returns the total without writing anything.
    EXPECT_EQ(rtti::vtables_for_type(".?AVRevCount@@", nullptr, 0, pool_range()), 2u);
}

TEST_F(RttiReverseTest, TypeIdentityCachesAndMatches)
{
    const std::uintptr_t vt = build_synth(".?AVRevIdentity@@", 0);
    ASSERT_NE(vt, 0u);

    rtti::TypeIdentity id(".?AVRevIdentity@@", pool_range());
    const auto v1 = id.vtable();
    ASSERT_TRUE(v1.has_value());
    EXPECT_EQ(v1->raw(), vt);

    // Second call takes the warm-cache path and yields the same result.
    EXPECT_EQ(id.vtable(), v1);

    EXPECT_TRUE(id.matches(Address{vt}));
    EXPECT_FALSE(id.matches(Address{vt + 8})); // a different address is not this type
}

TEST_F(RttiReverseTest, TypeIdentityUnresolvedNeverMatches)
{
    rtti::TypeIdentity id(".?AVRevNeverThere@@", pool_range());
    EXPECT_FALSE(id.vtable().has_value());
    EXPECT_FALSE(id.matches(Address{0x1000}));
}

TEST_F(RttiReverseTest, TypeIdentityFailedResolveRetriesWhenTypeAppearsLater)
{
    // A failed resolve must not latch permanently: the owning module may map the type later (a DLL loads, or a patch
    // finishes relocating the vtable). Scope the identity to the whole pool, miss while the type is absent, then build
    // the synth and confirm a later call resolves rather than staying wedged on the earlier miss. The re-sweep is
    // throttled, so advance the controllable clock past the cooldown before the retry: the retry capability is
    // preserved, it is just rate-limited rather than every-frame.
    RttiClockScope clock_scope;
    s_fake_clock_ms.store(1000);

    const std::uintptr_t pool_base = reinterpret_cast<std::uintptr_t>(s_rev_pool.data());
    const Region full_pool{Address{pool_base}, s_rev_pool.size()};

    rtti::TypeIdentity id(".?AVRevLateBind@@", full_pool);
    EXPECT_FALSE(id.vtable().has_value());

    const std::uintptr_t vt = build_synth(".?AVRevLateBind@@", 0);
    ASSERT_NE(vt, 0u);

    // Advance well past any reasonable cooldown so the next call re-sweeps instead of skipping. A large jump keeps this
    // test independent of the exact internal cooldown constant.
    s_fake_clock_ms.store(1000 + 1'000'000);

    const auto resolved = id.vtable();
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->raw(), vt);

    // The successful resolve now latches: the warm path returns the same value (and no longer consults the clock).
    EXPECT_EQ(id.vtable(), resolved);
}

TEST_F(RttiReverseTest, TypeIdentityUnresolvedReSweepThrottledWithinCooldown)
{
    // The re-sweep throttle removes the per-frame cliff of a TypeIdentity polled for an absent type: after a miss the
    // whole-module sweep is skipped until a cooldown elapses. Prove the sweep is actually skipped -- make the type
    // present after the miss without advancing the clock, and confirm the next call still reports unresolved. Without
    // the throttle that call would resolve the now-present type. Advancing past the cooldown then resolves it,
    // confirming the retry capability survives the throttle.
    RttiClockScope clock_scope;
    s_fake_clock_ms.store(5000);

    const std::uintptr_t pool_base = reinterpret_cast<std::uintptr_t>(s_rev_pool.data());
    const Region full_pool{Address{pool_base}, s_rev_pool.size()};

    rtti::TypeIdentity id(".?AVRevThrottle@@", full_pool);
    EXPECT_FALSE(id.vtable().has_value()); // miss at t=5000, records the attempt time

    const std::uintptr_t vt = build_synth(".?AVRevThrottle@@", 0);
    ASSERT_NE(vt, 0u);

    // Same clock reading: the re-sweep is throttled, so the now-present type is not observed yet.
    EXPECT_FALSE(id.vtable().has_value());

    // Past the cooldown: the sweep runs again and finds it.
    s_fake_clock_ms.store(5000 + 1'000'000);
    const auto resolved = id.vtable();
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->raw(), vt);
}

TEST_F(RttiReverseTest, FindsFixtureViaHostModuleSectionWalk)
{
    // Resolve against the real host EXE range so collect_rtti_scan_ranges parses actual PE section headers and sweeps
    // the test exe's data section, where the static fixture pool lives. This exercises the PE-walk path that the
    // tight-range tests deliberately bypass for speed.
    const std::uintptr_t vt = build_synth(".?AVRevHostWalk@@", 0);
    ASSERT_NE(vt, 0u);

    const auto host = Region::host();
    ASSERT_TRUE(host.size != 0);
    ASSERT_TRUE(host.contains(Address{vt}));

    const auto found = rtti::vtable_for_type(".?AVRevHostWalk@@", host);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->raw(), vt);
}

TEST_F(RttiReverseTest, VtablesForTypeTruncatesButReportsFullCount)
{
    const std::uintptr_t primary = build_synth(".?AVRevTrunc@@", 0);
    const std::uintptr_t secondary = build_synth(".?AVRevTrunc@@", 0x10);
    ASSERT_NE(primary, 0u);
    ASSERT_NE(secondary, 0u);

    // out_cap (1) is smaller than the number of matches (2): the return value reports the full count so the caller can
    // detect truncation, and the single written slot is the primary (offset 0 sorts first).
    Address all[1] = {};
    const std::size_t n = rtti::vtables_for_type(".?AVRevTrunc@@", all, 1, pool_range());
    EXPECT_EQ(n, 2u);
    EXPECT_EQ(all[0].raw(), primary);
}

TEST_F(RttiReverseTest, TypeIdentityOwnsNameAcceptsAnyStringSource)
{
    // TypeIdentity owns its name: the constructor takes a std::string_view and copies it into an internal
    // std::string, so nothing borrowed can dangle. Every string source is therefore safe to construct from -- a literal
    // (const char*), a std::string_view, a long-lived std::string lvalue, and even a std::string temporary (its
    // contents are copied before it dies).
    static_assert(std::is_constructible_v<rtti::TypeIdentity, std::string &&>,
                  "a std::string temporary must construct (its contents are copied into the owned name)");
    static_assert(std::is_constructible_v<rtti::TypeIdentity, const char *>,
                  "a string literal (const char*) must construct");
    static_assert(std::is_constructible_v<rtti::TypeIdentity, std::string_view>, "a std::string_view must construct");
    static_assert(std::is_constructible_v<rtti::TypeIdentity, std::string &>,
                  "a long-lived std::string lvalue must construct");
    SUCCEED();
}

TEST_F(RttiReverseTest, TypeIdentityOwnedNameSurvivesSourceDestruction)
{
    const std::uintptr_t vt = build_synth(".?AVRevOwned@@", 0x00);
    ASSERT_NE(vt, 0u);

    // Build the identity from a TEMPORARY std::string, then let that source string die BEFORE resolving. TypeIdentity
    // copies the name into owned storage, so the later resolve reads the owned copy; had it kept a borrowed
    // string_view, this would read the freed (SSO stack) storage and mis-resolve. The handle is non-movable, so it is
    // constructed in place inside the optional.
    std::optional<rtti::TypeIdentity> identity;
    {
        std::string transient = ".?AVRevOwned@@";
        identity.emplace(std::string_view(transient), pool_range());
    } // transient destroyed here; its storage is now free
    ASSERT_TRUE(identity.has_value());

    const auto resolved = identity->vtable();
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->raw(), vt);
    EXPECT_TRUE(identity->matches(Address{vt}));
}

TEST_F(RttiReverseTest, VtablesForTypeOrdersByColOffset)
{
    // Plant the sub-objects in non-ascending COL.offset discovery order (the pool lays them out by allocation address)
    // so the ascending-offset sort must actually reorder them.
    const std::uintptr_t vt20 = build_synth(".?AVRevOrder@@", 0x20);
    const std::uintptr_t vt00 = build_synth(".?AVRevOrder@@", 0x00);
    const std::uintptr_t vt10 = build_synth(".?AVRevOrder@@", 0x10);
    ASSERT_NE(vt20, 0u);
    ASSERT_NE(vt00, 0u);
    ASSERT_NE(vt10, 0u);

    Address all[4] = {};
    const std::size_t n = rtti::vtables_for_type(".?AVRevOrder@@", all, 4, pool_range());
    ASSERT_EQ(n, 3u);
    EXPECT_EQ(all[0].raw(), vt00); // offset 0x00
    EXPECT_EQ(all[1].raw(), vt10); // offset 0x10
    EXPECT_EQ(all[2].raw(), vt20); // offset 0x20
}

TEST_F(RttiReverseTest, RegionHasRttiReportsTrueWhenColResolvesEvenIfNameMisses)
{
    // A resolvable COL is present under a different name than the query. vtable_for_type misses, but region_has_rtti
    // reports that the scope still contains RTTI records.
    ASSERT_NE(build_synth(".?AVRegionPresent@@", 0), 0u);

    EXPECT_FALSE(rtti::vtable_for_type(".?AVRegionAbsent@@", pool_range()).has_value());
    EXPECT_TRUE(rtti::region_has_rtti(pool_range()));
}

TEST_F(RttiReverseTest, RegionHasRttiRejectsInRangeNonColPointer)
{
    // The scope holds an in-range meta-slot that passes the sweep's mod.contains() pre-filter but does not address a
    // signature-1 COL, so resolve_col_site runs and rejects it. A zeroed buffer would not exercise that validation
    // path because mod.contains(0) would fail before resolve_col_site is called.
    const Region decoy = build_in_range_decoy();
    ASSERT_NE(decoy.size, 0u);

    EXPECT_FALSE(rtti::region_has_rtti(decoy));
}

TEST_F(RttiReverseTest, RegionHasRttiReturnsFalseOnInvalidRegion)
{
    // An empty / unmapped Region yields an invalid ModuleSpan; region_has_rtti fails closed to false rather than
    // sweeping a bogus range, so a caller that passes a range it could not resolve still gets the raw-byte fallback
    // signal.
    EXPECT_FALSE(rtti::region_has_rtti(Region{}));
}

TEST_F(RttiReverseTest, RegionHasRttiScansHostPeSections)
{
    // Exercises the real PE path (collect_rtti_scan_ranges header parse + section loop), not the pool fallback that
    // every other case above takes. The verdict is ABI-correct on either toolchain: the MSVC C++ ABI lays down
    // RTTICompleteObjectLocators the walker reads, so an MSVC-built test exe (its polymorphic gtest types) carries at
    // least one; the Itanium ABI (MinGW/GCC) emits type_info instead, which is not a signature-1 COL, so a MinGW-built
    // exe genuinely holds zero MSVC RTTI records. Both branches drive the PE parse and section sweep.
#if defined(_MSC_VER)
    EXPECT_TRUE(rtti::region_has_rtti(Region::host()));
#else
    EXPECT_FALSE(rtti::region_has_rtti(Region::host()));
#endif
}

// A reverse-RTTI sweep that could not read every section header or every page must report the gap and must not
// authorize a unique or absent verdict from the partial result. TypeIdentity keys its warm cache on the resolving
// module's image generation and exposes invalidate() so a same-base remap drops a stale resolve.

namespace
{
    constexpr std::size_t PAGE = 0x1000;

    // Advances the pool cursor to the next page boundary so the following build_synth lands a whole 4 KiB record on one
    // page, which a test can flip to PAGE_NOACCESS to hide the record from the sweep. Returns that page-aligned
    // address.
    [[nodiscard]] std::uintptr_t rev_page_align_cursor() noexcept
    {
        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(s_rev_pool.data());
        const std::uintptr_t cur = base + s_rev_used;
        const std::uintptr_t aligned = (cur + (PAGE - 1)) & ~static_cast<std::uintptr_t>(PAGE - 1);
        s_rev_used = static_cast<std::size_t>(aligned - base);
        return aligned;
    }

    // RAII: flips one already-committed, page-aligned address to PAGE_NOACCESS and restores its prior protection on
    // scope exit. The reverse sweep's guarded read faults on it (contained on both toolchains) and reports Incomplete;
    // restoring on exit keeps the shared static pool usable by the next test.
    class ScopedNoAccess
    {
    public:
        explicit ScopedNoAccess(std::uintptr_t page_addr) noexcept : m_addr(page_addr)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<void *>(page_addr), &mbi, sizeof(mbi)) == sizeof(mbi))
            {
                m_prev = mbi.Protect;
                m_ok = VirtualProtect(reinterpret_cast<void *>(page_addr), PAGE, PAGE_NOACCESS, &m_prev) != 0;
            }
        }
        ~ScopedNoAccess() noexcept
        {
            if (m_ok)
            {
                DWORD ignored = 0;
                (void)VirtualProtect(reinterpret_cast<void *>(m_addr), PAGE, m_prev, &ignored);
            }
        }
        [[nodiscard]] bool ok() const noexcept { return m_ok; }
        ScopedNoAccess(const ScopedNoAccess &) = delete;
        ScopedNoAccess &operator=(const ScopedNoAccess &) = delete;

    private:
        std::uintptr_t m_addr;
        DWORD m_prev = PAGE_READWRITE;
        bool m_ok = false;
    };

    // A synthetic PE image (DOS + NT64 header + section table) in a VirtualAlloc'd region. It is NOT a loaded module,
    // so no COL validates -- the point is that collect_rtti_scan_ranges parses the header/section table straight from
    // the base, so a faulted section header (page 1 flipped NOACCESS) or a section count over the range cap sets the
    // traversal completeness regardless of whether any record resolves.
    class SynthPe
    {
    public:
        explicit SynthPe(std::size_t pages) noexcept
        {
            m_size = pages * PAGE;
            m_base = static_cast<std::byte *>(VirtualAlloc(nullptr, m_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (!m_base)
                m_size = 0;
        }
        ~SynthPe() noexcept
        {
            if (m_base)
            {
                DWORD old = 0;
                (void)VirtualProtect(m_base, m_size, PAGE_READWRITE, &old);
                (void)VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }
        SynthPe(const SynthPe &) = delete;
        SynthPe &operator=(const SynthPe &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uintptr_t base() const noexcept { return reinterpret_cast<std::uintptr_t>(m_base); }
        [[nodiscard]] Region range() const noexcept { return Region{Address{base()}, m_size}; }

        template <typename T> void put(std::size_t off, const T &value) noexcept
        {
            std::memcpy(m_base + off, &value, sizeof(T));
        }

        void protect_page(std::size_t page_index, DWORD prot) noexcept
        {
            DWORD old = 0;
            (void)VirtualProtect(m_base + page_index * PAGE, PAGE, prot, &old);
        }

    private:
        std::byte *m_base = nullptr;
        std::size_t m_size = 0;
    };

    // Writes a DOS+NT header and @p num_sections readable, non-executable section headers (each with a valid in-range
    // extent, so every one qualifies for the reverse scan) into @p pe, with the NT header at @p e_lfanew. Returns the
    // file offset of the section table.
    std::size_t write_synth_pe(SynthPe &pe, std::uint16_t num_sections, std::uint32_t e_lfanew) noexcept
    {
        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = static_cast<LONG>(e_lfanew);
        pe.put(0, dos);

        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = num_sections;
        nt.FileHeader.SizeOfOptionalHeader = static_cast<std::uint16_t>(sizeof(IMAGE_OPTIONAL_HEADER64));
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        pe.put(e_lfanew, nt);

        const std::size_t sec_table =
            e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + sizeof(IMAGE_OPTIONAL_HEADER64);
        for (std::uint16_t i = 0; i < num_sections; ++i)
        {
            IMAGE_SECTION_HEADER sh{};
            sh.Characteristics = IMAGE_SCN_MEM_READ; // readable, non-executable, non-discardable => qualifies
            sh.VirtualAddress = 0x100;               // a valid in-range extent [base+0x100, base+0x180)
            sh.Misc.VirtualSize = 0x80;
            pe.put(sec_table + static_cast<std::size_t>(i) * sizeof(IMAGE_SECTION_HEADER), sh);
        }
        return sec_table;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    std::atomic<std::uint64_t> s_fake_image_gen_first{0};
    std::atomic<std::uint64_t> s_fake_image_gen_later{0};
    std::atomic<std::uint32_t> s_fake_image_gen_calls{0};
    Region s_fake_module_region{};

    std::uint64_t fake_image_gen(std::uintptr_t) noexcept
    {
        const std::uint32_t call = s_fake_image_gen_calls.fetch_add(1, std::memory_order_relaxed);
        return (call == 0 ? s_fake_image_gen_first : s_fake_image_gen_later).load(std::memory_order_relaxed);
    }

    Region fake_module_region(Address) noexcept
    {
        return s_fake_module_region;
    }

    struct ScopedImageGen
    {
        explicit ScopedImageGen(std::uint64_t value) noexcept
        {
            set(value);
            DetourModKit::detail::g_rtti_image_generation_override = &fake_image_gen;
        }
        ~ScopedImageGen() noexcept { DetourModKit::detail::g_rtti_image_generation_override = nullptr; }
        void set(std::uint64_t value) noexcept
        {
            s_fake_image_gen_first.store(value, std::memory_order_relaxed);
            s_fake_image_gen_later.store(value, std::memory_order_relaxed);
            s_fake_image_gen_calls.store(0, std::memory_order_relaxed);
        }
        void transition(std::uint64_t first, std::uint64_t later) noexcept
        {
            s_fake_image_gen_first.store(first, std::memory_order_relaxed);
            s_fake_image_gen_later.store(later, std::memory_order_relaxed);
            s_fake_image_gen_calls.store(0, std::memory_order_relaxed);
        }
        ScopedImageGen(const ScopedImageGen &) = delete;
        ScopedImageGen &operator=(const ScopedImageGen &) = delete;
    };

    struct ScopedModuleRegion
    {
        explicit ScopedModuleRegion(Region region) noexcept
        {
            s_fake_module_region = region;
            DetourModKit::detail::g_rtti_module_region_override = &fake_module_region;
        }
        ~ScopedModuleRegion() noexcept { DetourModKit::detail::g_rtti_module_region_override = nullptr; }
        void set(Region region) noexcept { s_fake_module_region = region; }
        ScopedModuleRegion(const ScopedModuleRegion &) = delete;
        ScopedModuleRegion &operator=(const ScopedModuleRegion &) = delete;
    };
#endif
} // anonymous namespace

class RttiReverseProof : public ::testing::Test
{
protected:
    void SetUp() override
    {
        (void)memory::init_cache();
        rev_reset();
    }
    void TearDown() override { memory::shutdown_cache(); }
};

TEST_F(RttiReverseProof, IncompleteSectionOrPageTraversalCannotAuthorizeVerdict)
{
    // Primary A is on a readable page; duplicate primary B is on a page that can be made inaccessible. A complete
    // sweep sees both and reports the name ambiguous; a sweep that cannot read B's page sees
    // only A and must NOT report A as the unique primary, because a second primary hides in the region it could not
    // read.
    const std::uintptr_t a = build_synth(".?AVRevIncomplete@@", 0);
    ASSERT_NE(a, 0u);

    const std::uintptr_t b_page = rev_page_align_cursor();
    const std::uintptr_t b = build_synth(".?AVRevIncomplete@@", 0); // a second, distinct primary of the same name
    ASSERT_NE(b, 0u);
    ASSERT_EQ(b_page, b & ~static_cast<std::uintptr_t>(PAGE - 1)); // B's whole record sits on the aligned page

    const Region scope = pool_range();

    // Control: every page readable. The sweep is Complete, sees BOTH primaries, and fails closed on AMBIGUITY --
    // proving B is a real, resolvable duplicate primary that a complete sweep catches.
    {
        Address out[4] = {};
        const rtti::VtablesResult complete = rtti::vtables_for_type_checked(".?AVRevIncomplete@@", out, 4, scope);
        EXPECT_EQ(complete.completeness, rtti::Traversal::Complete);
        EXPECT_EQ(complete.count, 2u);
        EXPECT_FALSE(rtti::vtable_for_type(".?AVRevIncomplete@@", scope).has_value());
    }

    // Hide B: its page is unreadable, so the sweep sees only A. It must report Incomplete, and vtable_for_type must
    // fail closed rather than hand back A as the unique primary from a sweep that could not read where the second one
    // lives.
    {
        ScopedNoAccess hide(b_page);
        ASSERT_TRUE(hide.ok());

        Address out[4] = {};
        const rtti::VtablesResult partial = rtti::vtables_for_type_checked(".?AVRevIncomplete@@", out, 4, scope);
        EXPECT_EQ(partial.completeness, rtti::Traversal::Incomplete);
        EXPECT_EQ(partial.count, 1u); // only A was visible

        EXPECT_FALSE(rtti::vtable_for_type(".?AVRevIncomplete@@", scope).has_value());
    }
}

TEST_F(RttiReverseProof, SectionHeaderFaultAfterValidPrefixReportsIncomplete)
{
    // A synthetic 2-section PE whose FIRST section header is readable (a valid prefix) and whose SECOND lives on a page
    // flipped to PAGE_NOACCESS. collect_rtti_scan_ranges must fault on the second header and report the enumeration
    // Incomplete rather than returning the positive prefix as an authoritative range set.
    SynthPe pe(2);
    ASSERT_TRUE(pe.ok());
    // e_lfanew places the section table at 0xFD8: section header 0 ends exactly at the page boundary (0x1000) and
    // section header 1 begins on page 1.
    const std::uint32_t e_lfanew = static_cast<std::uint32_t>(
        0xFD8u - (offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + sizeof(IMAGE_OPTIONAL_HEADER64)));
    const std::size_t sec_table = write_synth_pe(pe, 2, e_lfanew);
    ASSERT_EQ(sec_table, 0xFD8u);
    pe.protect_page(1, PAGE_NOACCESS);

    // The region probe must return Incomplete, not an authoritative Absent: the sweep could not finish, so absence
    // cannot be concluded even though no record resolves in a non-module image.
    EXPECT_EQ(rtti::region_rtti_presence(pe.range()), rtti::RttiPresence::Incomplete);

    Address out[4] = {};
    const rtti::VtablesResult r = rtti::vtables_for_type_checked(".?AVWhatever@@", out, 4, pe.range());
    EXPECT_EQ(r.completeness, rtti::Traversal::Incomplete);

    pe.protect_page(1, PAGE_READWRITE); // restore before the region is freed
}

TEST_F(RttiReverseProof, SaturatedSectionScanReportsSaturated)
{
    // A synthetic PE with more qualifying sections than the internal range buffer holds (MAX_RTTI_SCAN_RANGES == 32).
    // collect must report Saturated rather than silently dropping the overflow and treating the sweep as authoritative.
    SynthPe pe(2);
    ASSERT_TRUE(pe.ok());
    write_synth_pe(pe, 40, 0x40); // 40 readable sections; the section table fits on page 0

    EXPECT_EQ(rtti::region_rtti_presence(pe.range()), rtti::RttiPresence::Incomplete); // Saturated => not authoritative

    Address out[4] = {};
    const rtti::VtablesResult r = rtti::vtables_for_type_checked(".?AVAnything@@", out, 4, pe.range());
    EXPECT_EQ(r.completeness, rtti::Traversal::Saturated);
}

TEST_F(RttiReverseProof, InvalidSectionExtentReportsIncomplete)
{
    SynthPe pe(2);
    ASSERT_TRUE(pe.ok());
    const std::size_t section_table = write_synth_pe(pe, 1, 0x40);

    IMAGE_SECTION_HEADER section{};
    section.Characteristics = IMAGE_SCN_MEM_READ;
    section.VirtualAddress = static_cast<DWORD>(pe.range().size + PAGE);
    section.Misc.VirtualSize = 0x80;
    pe.put(section_table, section);

    Address out[1] = {};
    const rtti::VtablesResult result = rtti::vtables_for_type_checked(".?AVOutside@@", out, 1, pe.range());
    EXPECT_EQ(result.completeness, rtti::Traversal::Incomplete);
    EXPECT_EQ(rtti::region_rtti_presence(pe.range()), rtti::RttiPresence::Incomplete);
}

TEST_F(RttiReverseProof, InvalidRegionReportsIncomplete)
{
    Address out[1] = {};
    const rtti::VtablesResult result = rtti::vtables_for_type_checked(".?AVInvalid@@", out, 1, Region{});
    EXPECT_EQ(result.completeness, rtti::Traversal::Incomplete);
    EXPECT_EQ(result.count, 0u);
    EXPECT_EQ(rtti::region_rtti_presence(Region{}), rtti::RttiPresence::Incomplete);
}

TEST_F(RttiReverseProof, CompleteSweepStillAuthorizesUniqueAndAbsent)
{
    // The completeness gate must not over-fire: a fully readable sweep still resolves a unique primary and still
    // reports an authoritative absence for a records-free scope.
    const std::uintptr_t vt = build_synth(".?AVRevComplete@@", 0);
    ASSERT_NE(vt, 0u);
    const Region scope = pool_range();

    Address out[4] = {};
    const rtti::VtablesResult r = rtti::vtables_for_type_checked(".?AVRevComplete@@", out, 4, scope);
    EXPECT_EQ(r.completeness, rtti::Traversal::Complete);
    EXPECT_EQ(r.count, 1u);

    const auto found = rtti::vtable_for_type(".?AVRevComplete@@", scope);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->raw(), vt);
    EXPECT_EQ(rtti::region_rtti_presence(scope), rtti::RttiPresence::Present);

    // A readable scope with an in-range non-COL decoy holds no resolvable record: a complete sweep => authoritative
    // Absent, distinct from the Incomplete a truncated sweep returns.
    const Region decoy = build_in_range_decoy();
    ASSERT_NE(decoy.size, 0u);
    EXPECT_EQ(rtti::region_rtti_presence(decoy), rtti::RttiPresence::Absent);
}

TEST_F(RttiReverseProof, ImageGenerationIdentifiesModuleAndRejectsNonModule)
{
    // A module-backed address carries a nonzero, stable generation; a private (non-module) allocation carries 0.
    const Address host_addr{reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr))};
    const std::uint64_t host_gen = rtti::image_generation(host_addr);
    EXPECT_NE(host_gen, 0u);
    EXPECT_EQ(host_gen, rtti::image_generation(host_addr)); // stable across calls

    void *priv = VirtualAlloc(nullptr, PAGE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(priv, nullptr);
    EXPECT_EQ(rtti::image_generation(Address{reinterpret_cast<std::uintptr_t>(priv)}), 0u);
    (void)VirtualFree(priv, 0, MEM_RELEASE);
}

TEST_F(RttiReverseProof, TypeIdentityInvalidateForcesColdReResolve)
{
    // invalidate() drops the cached success so the next call re-resolves against current memory. The pool lives in the
    // test-exe module, whose generation does not change, so the warm cache is otherwise sticky -- exactly the case
    // invalidate() exists for.
    const std::uintptr_t vt1 = build_synth(".?AVRevInval@@", 0);
    ASSERT_NE(vt1, 0u);
    rtti::TypeIdentity id(".?AVRevInval@@", pool_range());
    ASSERT_TRUE(id.vtable().has_value());
    EXPECT_EQ(id.vtable()->raw(), vt1);

    // Wipe the record. Without invalidate the warm cache keeps returning vt1 (the module generation is unchanged).
    rev_reset();
    ASSERT_TRUE(id.vtable().has_value());
    EXPECT_EQ(id.vtable()->raw(), vt1);

    id.invalidate();
    EXPECT_FALSE(id.vtable().has_value()); // cache dropped => a fresh resolve misses the wiped record
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST_F(RttiReverseProof, TypeIdentityDropsWarmCacheOnGenerationChange)
{
    // Simulate a same-base remap: image_generation returns 1111, the identity resolves and stamps it; after the
    // generation changes to 2222, the next warm call must drop the stale cache and re-resolve against current memory
    // rather than keep matching the old vtable.
    ScopedImageGen gen(1111);

    const std::uintptr_t vt1 = build_synth(".?AVRevRemap@@", 0);
    ASSERT_NE(vt1, 0u);
    rtti::TypeIdentity id(".?AVRevRemap@@", pool_range());
    ASSERT_TRUE(id.vtable().has_value());
    EXPECT_EQ(id.vtable()->raw(), vt1); // resolved, stamped generation 1111

    // Wipe the record: a re-resolve would now miss. A warm cache that does not re-validate keeps returning vt1.
    rev_reset();

    // An unchanged generation keeps the cached value.
    ASSERT_TRUE(id.vtable().has_value());
    EXPECT_EQ(id.vtable()->raw(), vt1);

    // A same-base generation change is observed immediately; current memory no longer holds the record.
    gen.set(2222);
    EXPECT_FALSE(id.vtable().has_value());
}

TEST_F(RttiReverseProof, TypeIdentityRefreshesTrackedModuleExtent)
{
    ScopedImageGen generation(1111);

    const std::uintptr_t old_vtable = build_synth(".?AVRevExtent@@", 0);
    ASSERT_NE(old_vtable, 0u);
    ScopedModuleRegion module(pool_range());
    rtti::TypeIdentity identity(".?AVRevExtent@@", pool_range());
    ASSERT_EQ(identity.vtable(), Address{old_vtable});

    rev_reset();
    ASSERT_NE(build_in_range_decoy().size, 0u);
    const std::uintptr_t current_vtable = build_synth(".?AVRevExtent@@", 0);
    ASSERT_NE(current_vtable, 0u);
    ASSERT_NE(current_vtable, old_vtable);
    module.set(pool_range());
    generation.set(2222);

    ASSERT_EQ(identity.vtable(), Address{current_vtable});
}

TEST_F(RttiReverseProof, TypeIdentityDoesNotPublishAcrossGenerationTransition)
{
    RttiClockScope clock;
    s_fake_clock_ms.store(1000);
    ScopedImageGen generation(1111);
    const std::uintptr_t vtable = build_synth(".?AVRevTransactional@@", 0);
    ASSERT_NE(vtable, 0u);

    generation.transition(1111, 2222);
    rtti::TypeIdentity identity(".?AVRevTransactional@@", pool_range());
    EXPECT_FALSE(identity.vtable().has_value());

    generation.set(2222);
    s_fake_clock_ms.store(1000 + 1'000'000);
    ASSERT_EQ(identity.vtable(), Address{vtable});
}
#endif
