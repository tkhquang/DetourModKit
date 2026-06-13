#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"

namespace Memory = DetourModKit::Memory;
namespace Rtti = DetourModKit::Rtti;

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

    // Static pool in the test executable's data segment so Memory::module_range_for resolves every synthetic vtable
    // back to the test exe's PE range, which the shared prelude's bound check requires. Reset between tests. Sized to
    // hold one full MAX_REVERSE_MATCHES (64) saturation set plus the small fixtures every other case builds.
    constexpr std::size_t REV_POOL_FIXTURES = 64;
    alignas(8) std::array<std::byte, REV_BUF_SIZE * REV_POOL_FIXTURES> s_rev_pool{};
    std::size_t s_rev_used = 0;

    void rev_reset() noexcept
    {
        s_rev_used = 0;
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
    [[nodiscard]] Memory::ModuleRange pool_range() noexcept
    {
        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(s_rev_pool.data());
        return Memory::ModuleRange{base, base + s_rev_used};
    }
} // anonymous namespace

class RttiReverseTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        (void)Memory::init_cache();
        rev_reset();
    }

    void TearDown() override { Memory::shutdown_cache(); }
};

TEST_F(RttiReverseTest, SingleInheritanceResolvesPrimaryVtable)
{
    const std::uintptr_t vt = build_synth(".?AVRevSingle@@", 0);
    ASSERT_NE(vt, 0u);

    const auto found = Rtti::vtable_for_type(".?AVRevSingle@@", pool_range());
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(*found, vt);

    // Round-trip invariant: the reverse result must satisfy the forward check.
    EXPECT_TRUE(Rtti::vtable_is_type(*found, ".?AVRevSingle@@"));

    std::uintptr_t all[4] = {};
    const std::size_t n = Rtti::vtables_for_type(".?AVRevSingle@@", all, 4, pool_range());
    EXPECT_EQ(n, 1u);
    EXPECT_EQ(all[0], vt);
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
    const auto found = Rtti::vtable_for_type(".?AVRevMulti@@", pool_range());
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(*found, primary);

    // The plural resolver returns both, primary (offset 0) first.
    std::uintptr_t all[4] = {};
    const std::size_t n = Rtti::vtables_for_type(".?AVRevMulti@@", all, 4, pool_range());
    ASSERT_EQ(n, 2u);
    EXPECT_EQ(all[0], primary);
    EXPECT_EQ(all[1], secondary);
}

TEST_F(RttiReverseTest, AmbiguousPrimaryFailsClosed)
{
    // Two distinct offset==0 vtables with the same name (a type linked into the image twice): the singular resolver
    // must fail closed, not pick one.
    ASSERT_NE(build_synth(".?AVRevDup@@", 0), 0u);
    ASSERT_NE(build_synth(".?AVRevDup@@", 0), 0u);

    EXPECT_FALSE(Rtti::vtable_for_type(".?AVRevDup@@", pool_range()).has_value());

    // The plural form still reports both distinct matches.
    std::uintptr_t all[4] = {};
    const std::size_t n = Rtti::vtables_for_type(".?AVRevDup@@", all, 4, pool_range());
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

    EXPECT_FALSE(Rtti::vtable_for_type(".?AVRevSaturate@@", pool_range()).has_value());

    // The plural form does not fail closed -- it is inherently multi-valued -- and reports the saturated count (capped
    // at MAX_REVERSE_MATCHES) so a caller can detect the truncation itself.
    std::uintptr_t all[cap] = {};
    EXPECT_EQ(Rtti::vtables_for_type(".?AVRevSaturate@@", all, cap, pool_range()), cap);
}

TEST_F(RttiReverseTest, UnknownNameReturnsNullopt)
{
    ASSERT_NE(build_synth(".?AVRevPresent@@", 0), 0u);

    EXPECT_FALSE(Rtti::vtable_for_type(".?AVRevAbsent@@", pool_range()).has_value());
    std::uintptr_t all[4] = {};
    EXPECT_EQ(Rtti::vtables_for_type(".?AVRevAbsent@@", all, 4, pool_range()), 0u);
}

TEST_F(RttiReverseTest, InvalidRangeReturnsNullopt)
{
    ASSERT_NE(build_synth(".?AVRevInvalid@@", 0), 0u);

    const Memory::ModuleRange invalid{}; // base == end == 0 => valid() is false
    EXPECT_FALSE(Rtti::vtable_for_type(".?AVRevInvalid@@", invalid).has_value());
    std::uintptr_t all[4] = {};
    EXPECT_EQ(Rtti::vtables_for_type(".?AVRevInvalid@@", all, 4, invalid), 0u);
}

TEST_F(RttiReverseTest, VtablesForTypeCountOnlyWithNullOut)
{
    ASSERT_NE(build_synth(".?AVRevCount@@", 0), 0u);
    ASSERT_NE(build_synth(".?AVRevCount@@", 0x08), 0u);

    // A count-only query (null buffer, zero capacity) returns the total without writing anything.
    EXPECT_EQ(Rtti::vtables_for_type(".?AVRevCount@@", nullptr, 0, pool_range()), 2u);
}

TEST_F(RttiReverseTest, TypeIdentityCachesAndMatches)
{
    const std::uintptr_t vt = build_synth(".?AVRevIdentity@@", 0);
    ASSERT_NE(vt, 0u);

    Rtti::TypeIdentity id(".?AVRevIdentity@@", pool_range());
    const auto v1 = id.vtable();
    ASSERT_TRUE(v1.has_value());
    EXPECT_EQ(*v1, vt);

    // Second call takes the warm-cache path and yields the same result.
    EXPECT_EQ(id.vtable(), v1);

    EXPECT_TRUE(id.matches(vt));
    EXPECT_FALSE(id.matches(vt + 8)); // a different address is not this type
}

TEST_F(RttiReverseTest, TypeIdentityUnresolvedNeverMatches)
{
    Rtti::TypeIdentity id(".?AVRevNeverThere@@", pool_range());
    EXPECT_FALSE(id.vtable().has_value());
    EXPECT_FALSE(id.matches(0x1000));
}

TEST_F(RttiReverseTest, FindsFixtureViaHostModuleSectionWalk)
{
    // Resolve against the real host EXE range so collect_rtti_scan_ranges parses actual PE section headers and sweeps
    // the test exe's data section, where the static fixture pool lives. This exercises the PE-walk path that the
    // tight-range tests deliberately bypass for speed.
    const std::uintptr_t vt = build_synth(".?AVRevHostWalk@@", 0);
    ASSERT_NE(vt, 0u);

    const auto host = Memory::host_module_range();
    ASSERT_TRUE(host.valid());
    ASSERT_TRUE(Memory::contains(host, vt));

    const auto found = Rtti::vtable_for_type(".?AVRevHostWalk@@", host);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(*found, vt);
}

TEST_F(RttiReverseTest, VtablesForTypeTruncatesButReportsFullCount)
{
    const std::uintptr_t primary = build_synth(".?AVRevTrunc@@", 0);
    const std::uintptr_t secondary = build_synth(".?AVRevTrunc@@", 0x10);
    ASSERT_NE(primary, 0u);
    ASSERT_NE(secondary, 0u);

    // out_cap (1) is smaller than the number of matches (2): the return value reports the full count so the caller can
    // detect truncation, and the single written slot is the primary (offset 0 sorts first).
    std::uintptr_t all[1] = {};
    const std::size_t n = Rtti::vtables_for_type(".?AVRevTrunc@@", all, 1, pool_range());
    EXPECT_EQ(n, 2u);
    EXPECT_EQ(all[0], primary);
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

    std::uintptr_t all[4] = {};
    const std::size_t n = Rtti::vtables_for_type(".?AVRevOrder@@", all, 4, pool_range());
    ASSERT_EQ(n, 3u);
    EXPECT_EQ(all[0], vt00); // offset 0x00
    EXPECT_EQ(all[1], vt10); // offset 0x10
    EXPECT_EQ(all[2], vt20); // offset 0x20
}
