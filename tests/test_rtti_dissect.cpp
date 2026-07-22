#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"
#include "DetourModKit/rtti_dissect.hpp"

#include "internal/rtti_shared.hpp"

#include "test_alloc_probe.hpp"

namespace memory = DetourModKit::memory;
namespace rtti = DetourModKit::rtti;
namespace dmk = DetourModKit;
using DetourModKit::Address;
using DetourModKit::ErrorCode;

static_assert(static_cast<std::uint8_t>(rtti::Indirection::PointerToObject) == 0);
static_assert(static_cast<std::uint8_t>(rtti::Indirection::ObjectBase) == 1);
static_assert(static_cast<std::uint8_t>(rtti::Indirection::Any) == 2);
static_assert(static_cast<std::uint8_t>(rtti::Indirection::CompleteObject) == 3);

namespace
{
    // Per-fixture layout offsets shared by every SyntheticVtable instance. Picked so the COL, TypeDescriptor, and
    // vtable storage live well apart from each other and from 4 KiB page boundaries. Mirrors the layout used by
    // test_rtti.cpp; the dissector consumes the same prelude as the walker.
    constexpr std::size_t SYN_BUF_SIZE = 4096;
    constexpr std::size_t SYN_COL_OFFSET = 256;
    constexpr std::size_t SYN_TD_OFFSET = SYN_COL_OFFSET + 24; // COL is 24 bytes
    constexpr std::size_t SYN_TD_NAME_OFFSET = SYN_TD_OFFSET + 16;
    constexpr std::size_t SYN_COL_PTR_OFFSET = 2048;
    constexpr std::size_t SYN_VTABLE_OFFSET = SYN_COL_PTR_OFFSET + 8;

    // Static buffer pool for SyntheticVtable storage. Living in the test executable's data segment ensures
    // memory::module_of resolves every synthetic vtable back to the test exe's PE range, which the prelude's
    // bound-check guard requires. The pool is reset between tests.
    constexpr std::size_t SYN_POOL_FIXTURES = 32;
    constexpr std::size_t SYN_POOL_SIZE = SYN_BUF_SIZE * SYN_POOL_FIXTURES;
    alignas(8) std::array<std::byte, SYN_POOL_SIZE> s_syn_pool{};
    std::size_t s_syn_offset = 0;

    [[nodiscard]] std::byte *syn_alloc() noexcept
    {
        if (s_syn_offset + SYN_BUF_SIZE > s_syn_pool.size())
        {
            return nullptr;
        }
        std::byte *p = s_syn_pool.data() + s_syn_offset;
        s_syn_offset += SYN_BUF_SIZE;
        std::memset(p, 0, SYN_BUF_SIZE);
        return p;
    }

    void syn_reset() noexcept
    {
        s_syn_offset = 0;
    }

    /**
     * @class SyntheticVtable
     * @brief In-memory MSVC x64 RTTI layout for testing the dissector.
     * @details Identical shape to the forward-walker fixture: a vtable whose qword at offset -8 points to an
     *          RTTICompleteObjectLocator whose pTypeDescriptor RVA leads to a TypeDescriptor carrying the requested
     *          mangled name. RVAs are computed against the test exe's image base so the prelude's module bound-check
     *          accepts them.
     */
    class SyntheticVtable
    {
    public:
        explicit SyntheticVtable(std::string_view mangled_name)
        {
            m_buf = syn_alloc();
            EXPECT_NE(m_buf, nullptr) << "SyntheticVtable pool exhausted; raise SYN_POOL_FIXTURES";
            if (!m_buf)
            {
                return;
            }

            const HMODULE exe = GetModuleHandleW(nullptr);
            EXPECT_NE(exe, nullptr);
            const std::uintptr_t exe_base = reinterpret_cast<std::uintptr_t>(exe);
            const std::uintptr_t buf_base = reinterpret_cast<std::uintptr_t>(m_buf);

            // The synthetic RVAs are computed as (buffer - image base), which underflows if the data segment ever sits
            // below the image base. Flag the violated precondition and stop (mirroring the m_buf guard above; a fatal
            // ASSERT cannot return from a constructor) so a wrapped RVA never surfaces later as a misleading resolve
            // failure.
            EXPECT_GE(buf_base, exe_base);
            if (buf_base < exe_base)
            {
                return;
            }
            const std::uintptr_t buf_rva = buf_base - exe_base;

            const std::uint32_t signature = 1; // x64 layout with pSelf RVA
            const std::uint32_t col_field = 0;
            const std::uint32_t cd_offset = 0;
            const std::uint32_t td_rva = static_cast<std::uint32_t>(buf_rva + SYN_TD_OFFSET);
            const std::uint32_t class_desc_rva = 0;
            const std::uint32_t self_rva = static_cast<std::uint32_t>(buf_rva + SYN_COL_OFFSET);

            write_at(SYN_COL_OFFSET + 0, signature);
            write_at(SYN_COL_OFFSET + 4, col_field);
            write_at(SYN_COL_OFFSET + 8, cd_offset);
            write_at(SYN_COL_OFFSET + 12, td_rva);
            write_at(SYN_COL_OFFSET + 16, class_desc_rva);
            write_at(SYN_COL_OFFSET + 20, self_rva);

            const std::size_t max_name = SYN_COL_PTR_OFFSET - SYN_TD_NAME_OFFSET - 1;
            const std::size_t name_len = std::min(mangled_name.size(), max_name);
            std::memcpy(m_buf + SYN_TD_NAME_OFFSET, mangled_name.data(), name_len);
            m_buf[SYN_TD_NAME_OFFSET + name_len] = std::byte{0};

            const std::uintptr_t col_addr = buf_base + SYN_COL_OFFSET;
            write_at(SYN_COL_PTR_OFFSET, col_addr);

            m_vtable_addr = buf_base + SYN_VTABLE_OFFSET;
        }

        SyntheticVtable(const SyntheticVtable &) = delete;
        SyntheticVtable &operator=(const SyntheticVtable &) = delete;

        [[nodiscard]] std::uintptr_t vtable() const noexcept { return m_vtable_addr; }

        /// Address of the synthetic COL (what identify_pointee_type reports as col_addr).
        [[nodiscard]] std::uintptr_t col_addr() const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_buf) + SYN_COL_OFFSET;
        }

        /// Address of the synthetic TypeDescriptor (reported as td_addr).
        [[nodiscard]] std::uintptr_t td_addr() const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_buf) + SYN_TD_OFFSET;
        }

        /// Address of the synthetic mangled-name buffer (reported as name_addr).
        [[nodiscard]] std::uintptr_t name_addr() const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_buf) + SYN_TD_NAME_OFFSET;
        }

        /// Overwrites COL.offset (+0x04), the vtable's offset in the complete object.
        void set_col_offset(std::uint32_t value) noexcept { write_at(SYN_COL_OFFSET + 4, value); }

        /// Overwrites COL.p_type_descriptor with @p rva for poisoned-input tests.
        void poison_type_descriptor_rva(std::uint32_t rva) noexcept { write_at(SYN_COL_OFFSET + 12, rva); }

        /// Overwrites COL.p_self with @p rva for poisoned-input tests.
        void poison_self_rva(std::uint32_t rva) noexcept { write_at(SYN_COL_OFFSET + 20, rva); }

    private:
        template <typename T> void write_at(std::size_t offset, const T &value) noexcept
        {
            static_assert(std::is_trivially_copyable_v<T>);
            std::memcpy(m_buf + offset, &value, sizeof(T));
        }

        std::byte *m_buf = nullptr;
        std::uintptr_t m_vtable_addr = 0;
    };
} // anonymous namespace

class RttiDissectTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        (void)memory::init_cache();
        syn_reset();
    }

    void TearDown() override
    {
        memory::shutdown_cache();
        for (void *p : m_heap_pages)
        {
            VirtualFree(p, 0, MEM_RELEASE);
        }
        m_heap_pages.clear();
    }

    // Allocates a committed page OUTSIDE every module range and writes @p vtable_addr as the object's first qword,
    // returning the object base. Exercises the pointer-to-object branch with a pointee that does not live in any PE
    // image (the cross-region / cross-DLL resolvability case).
    [[nodiscard]] std::uintptr_t syn_heap_object(std::uintptr_t vtable_addr)
    {
        void *p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        EXPECT_NE(p, nullptr);
        if (p)
        {
            m_heap_pages.push_back(p);
            std::memcpy(p, &vtable_addr, sizeof(vtable_addr));
        }
        return reinterpret_cast<std::uintptr_t>(p);
    }

    // Returns an address that is committed-then-freed, so a read of it faults.
    [[nodiscard]] static std::uintptr_t unmapped_addr()
    {
        void *p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        EXPECT_NE(p, nullptr);
        VirtualFree(p, 0, MEM_RELEASE);
        return reinterpret_cast<std::uintptr_t>(p);
    }

private:
    std::vector<void *> m_heap_pages;
};

// L1 identify_pointee_type

TEST_F(RttiDissectTest, Identify_DirectObjectBase)
{
    SyntheticVtable v(".?AVDirect@@");
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    rtti::PointeeType pt;
    ASSERT_TRUE(rtti::identify_pointee_type(Address{slot_addr}, pt));
    EXPECT_FALSE(pt.was_pointer);
    // Direct contract: object base is the slot ADDRESS, vtable is the value.
    EXPECT_EQ(pt.object_base.raw(), slot_addr);
    EXPECT_EQ(pt.vtable.raw(), v.vtable());
    EXPECT_EQ(pt.pointer_value.raw(), v.vtable());
    EXPECT_EQ(pt.name(), ".?AVDirect@@");
}

TEST_F(RttiDissectTest, Identify_PointerToObject)
{
    SyntheticVtable v(".?AVHeapObj@@");
    const std::uintptr_t obj = syn_heap_object(v.vtable());
    ASSERT_NE(obj, 0u);

    std::array<std::uintptr_t, 1> slot{obj};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    rtti::PointeeType pt;
    ASSERT_TRUE(rtti::identify_pointee_type(Address{slot_addr}, pt));
    EXPECT_TRUE(pt.was_pointer);
    // Pointer-to-object contract: object base is the pointee value.
    EXPECT_EQ(pt.object_base.raw(), obj);
    EXPECT_EQ(pt.pointer_value.raw(), obj);
    EXPECT_EQ(pt.vtable.raw(), v.vtable());
    EXPECT_EQ(pt.name(), ".?AVHeapObj@@");
}

TEST_F(RttiDissectTest, Identify_NonzeroColOffsetRecoversCompleteObject)
{
    SyntheticVtable v(".?AVSub@@");
    v.set_col_offset(0x10);
    const std::uintptr_t obj = syn_heap_object(v.vtable());
    ASSERT_NE(obj, 0u);

    std::array<std::uintptr_t, 1> slot{obj};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    rtti::PointeeType pt;
    ASSERT_TRUE(rtti::identify_pointee_type(Address{slot_addr}, pt));
    EXPECT_EQ(pt.col_offset, 0x10u);
    EXPECT_EQ(pt.complete_obj.raw(), obj - 0x10);
}

TEST_F(RttiDissectTest, Identify_DirectObjectNonzeroColOffsetRecoversCompleteObject)
{
    // The direct-object branch sets object_base to the slot ADDRESS, a distinct code path from the pointer-to-object
    // branch above. Confirm the complete object is recovered as slot_addr - col_offset there too.
    SyntheticVtable v(".?AVDirectSub@@");
    v.set_col_offset(0x20);
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    rtti::PointeeType pt;
    ASSERT_TRUE(rtti::identify_pointee_type(Address{slot_addr}, pt));
    EXPECT_FALSE(pt.was_pointer);
    EXPECT_EQ(pt.object_base.raw(), slot_addr);
    EXPECT_EQ(pt.col_offset, 0x20u);
    EXPECT_EQ(pt.complete_obj.raw(), slot_addr - 0x20);
}

TEST_F(RttiDissectTest, Identify_ExposesColTdAndNameAddresses)
{
    // The col_addr / td_addr / name_addr coordinates are part of the public introspection surface; pin them to the
    // fixture's known layout so a regression in the prelude wiring is caught here.
    SyntheticVtable v(".?AVCoords@@");
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    rtti::PointeeType pt;
    ASSERT_TRUE(rtti::identify_pointee_type(Address{slot_addr}, pt));
    EXPECT_EQ(pt.col_addr.raw(), v.col_addr());
    EXPECT_EQ(pt.td_addr.raw(), v.td_addr());
    EXPECT_EQ(pt.name_addr.raw(), v.name_addr());
}

TEST_F(RttiDissectTest, Identify_RejectsPoisonedTypeDescriptorRva)
{
    SyntheticVtable v(".?AVValid@@");
    v.poison_type_descriptor_rva(0x7FFFFFFFu);
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    rtti::PointeeType pt;
    EXPECT_FALSE(rtti::identify_pointee_type(Address{slot_addr}, pt));
}

TEST_F(RttiDissectTest, Identify_RejectsPoisonedSelfRva)
{
    SyntheticVtable v(".?AVValid@@");
    v.poison_self_rva(1);
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    rtti::PointeeType pt;
    EXPECT_FALSE(rtti::identify_pointee_type(Address{slot_addr}, pt));
}

TEST_F(RttiDissectTest, Identify_RejectsNullAndLowSlot)
{
    rtti::PointeeType pt;
    EXPECT_FALSE(rtti::identify_pointee_type(Address{}, pt));
    EXPECT_FALSE(rtti::identify_pointee_type(Address{0x100}, pt));
}

TEST_F(RttiDissectTest, Identify_RejectsUnreadableSlotAddress)
{
    const std::uintptr_t gone = unmapped_addr();
    // Guard the precondition: if the committed-then-freed allocation ever failed, gone would be 0 and this would
    // silently exercise the null-slot guard instead of the unmapped-read path. unmapped_addr returns a value, so the
    // fatal assert lives here rather than inside the helper.
    ASSERT_NE(gone, 0u);
    rtti::PointeeType pt;
    EXPECT_FALSE(rtti::identify_pointee_type(Address{gone}, pt));
}

TEST_F(RttiDissectTest, Identify_RejectsGarbageSlotValue)
{
    // Slot holds a plausible-but-unresolvable pointer: neither a pointer to an object with a valid COL nor a vtable in
    // any module.
    std::array<std::uintptr_t, 1> slot{0xDEADBEEFu};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    rtti::PointeeType pt;
    EXPECT_FALSE(rtti::identify_pointee_type(Address{slot_addr}, pt));
}

// L1 identify_pointee_type_or (RTTI fallback composition)

TEST_F(RttiDissectTest, IdentifyTyped_ResolvesAndMatchesBool)
{
    // The typed primitive must resolve the same slot the bool primitive does and report the same identification, since
    // the bool form is exactly has_value() over the typed core.
    SyntheticVtable v(".?AVTyped@@");
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    rtti::PointeeType pt;
    const auto typed = rtti::identify_pointee_typed(Address{slot_addr}, pt);
    ASSERT_TRUE(typed.has_value());

    rtti::PointeeType pt2;
    EXPECT_TRUE(rtti::identify_pointee_type(Address{slot_addr}, pt2));
    EXPECT_EQ(pt.name(), pt2.name());
    EXPECT_EQ(pt.name(), ".?AVTyped@@");
}

TEST_F(RttiDissectTest, IdentifyTyped_ErrorMatrix)
{
    rtti::PointeeType pt;

    // Null and below-floor slot addresses are rejected before any read.
    const auto null_slot = rtti::identify_pointee_typed(Address{}, pt);
    ASSERT_FALSE(null_slot.has_value());
    EXPECT_EQ(null_slot.error().code, ErrorCode::BadSlotAddress);

    const auto low_slot = rtti::identify_pointee_typed(Address{0x100}, pt);
    ASSERT_FALSE(low_slot.has_value());
    EXPECT_EQ(low_slot.error().code, ErrorCode::BadSlotAddress);

    // A committed-then-freed page faults on read.
    const std::uintptr_t gone = unmapped_addr();
    ASSERT_NE(gone, 0u);
    const auto unreadable = rtti::identify_pointee_typed(Address{gone}, pt);
    ASSERT_FALSE(unreadable.has_value());
    EXPECT_EQ(unreadable.error().code, ErrorCode::UnreadableSlot);

    // A readable slot holding a plausible-but-unresolvable pointer resolves to no RTTI type.
    std::array<std::uintptr_t, 1> garbage{0xDEADBEEFu};
    const std::uintptr_t garbage_addr = reinterpret_cast<std::uintptr_t>(garbage.data());
    const auto no_rtti = rtti::identify_pointee_typed(Address{garbage_addr}, pt);
    ASSERT_FALSE(no_rtti.has_value());
    EXPECT_EQ(no_rtti.error().code, ErrorCode::NoRtti);
}

TEST_F(RttiDissectTest, IdentifyOr_PrimaryWinsNoFallbackProbed)
{
    // A resolving primary short-circuits the fold, so the garbage fallback is never selected and out holds the primary.
    SyntheticVtable primary(".?AVPrimary@@");
    std::array<std::uintptr_t, 1> primary_slot{primary.vtable()};
    const std::uintptr_t primary_addr = reinterpret_cast<std::uintptr_t>(primary_slot.data());

    std::array<std::uintptr_t, 1> garbage{0xDEADBEEFu};
    const std::uintptr_t garbage_addr = reinterpret_cast<std::uintptr_t>(garbage.data());

    rtti::PointeeType pt;
    const auto result = rtti::identify_pointee_type_or(Address{primary_addr}, pt, Address{garbage_addr});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(pt.name(), ".?AVPrimary@@");
}

TEST_F(RttiDissectTest, IdentifyOr_FirstFallbackResolves)
{
    // A failing primary falls through to the fallbacks; the fold short-circuits at the FIRST resolving fallback, so the
    // second (also valid) fallback never overwrites out.
    std::array<std::uintptr_t, 1> primary_slot{0xDEADBEEFu};
    const std::uintptr_t primary_addr = reinterpret_cast<std::uintptr_t>(primary_slot.data());

    SyntheticVtable first_good(".?AVFirstGood@@");
    std::array<std::uintptr_t, 1> first_slot{first_good.vtable()};
    const std::uintptr_t first_addr = reinterpret_cast<std::uintptr_t>(first_slot.data());

    SyntheticVtable second_good(".?AVSecondGood@@");
    std::array<std::uintptr_t, 1> second_slot{second_good.vtable()};
    const std::uintptr_t second_addr = reinterpret_cast<std::uintptr_t>(second_slot.data());

    rtti::PointeeType pt;
    const auto result =
        rtti::identify_pointee_type_or(Address{primary_addr}, pt, Address{first_addr}, Address{second_addr});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(pt.name(), ".?AVFirstGood@@");
}

TEST_F(RttiDissectTest, IdentifyOr_AllFailPreservesFirstError)
{
    // The load-bearing contract: when every candidate fails, the cascade returns the FIRST (primary's) error, not a
    // fallback's. The primary is unmapped (UnreadableSlot) while every fallback is a NoRtti garbage slot, so the two
    // error kinds are distinguishable and the preserved error must be the primary's.
    const std::uintptr_t primary_addr = unmapped_addr();
    ASSERT_NE(primary_addr, 0u);

    std::array<std::uintptr_t, 1> garbage_a{0xDEADBEEFu};
    std::array<std::uintptr_t, 1> garbage_b{0xDEADBEEFu};
    const std::uintptr_t garbage_a_addr = reinterpret_cast<std::uintptr_t>(garbage_a.data());
    const std::uintptr_t garbage_b_addr = reinterpret_cast<std::uintptr_t>(garbage_b.data());

    rtti::PointeeType pt;
    const auto result =
        rtti::identify_pointee_type_or(Address{primary_addr}, pt, Address{garbage_a_addr}, Address{garbage_b_addr});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::UnreadableSlot);
}

TEST_F(RttiDissectTest, IdentifyOr_NoFallbacksDegradesToPrimary)
{
    // With zero fallbacks the cascade is just the primary probe: a failing primary surfaces its own error, a resolving
    // primary returns a value.
    std::array<std::uintptr_t, 1> garbage{0xDEADBEEFu};
    const std::uintptr_t garbage_addr = reinterpret_cast<std::uintptr_t>(garbage.data());

    rtti::PointeeType pt;
    const auto miss = rtti::identify_pointee_type_or(Address{garbage_addr}, pt);
    ASSERT_FALSE(miss.has_value());
    EXPECT_EQ(miss.error().code, ErrorCode::NoRtti);

    SyntheticVtable v(".?AVNoFallback@@");
    std::array<std::uintptr_t, 1> good_slot{v.vtable()};
    const std::uintptr_t good_addr = reinterpret_cast<std::uintptr_t>(good_slot.data());
    const auto hit = rtti::identify_pointee_type_or(Address{good_addr}, pt);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(pt.name(), ".?AVNoFallback@@");
}

TEST_F(RttiDissectTest, IdentifyOr_AllFailResetsOutToDefault)
{
    // A prior success leaves out fully populated; a later all-fail cascade must wipe out back to a default-constructed
    // PointeeType, so a caller that ignores the error never reads a stale name/vtable from the earlier resolve.
    SyntheticVtable prior(".?AVPriorResolve@@");
    std::array<std::uintptr_t, 1> prior_slot{prior.vtable()};
    const std::uintptr_t prior_addr = reinterpret_cast<std::uintptr_t>(prior_slot.data());

    rtti::PointeeType pt;
    const auto first = rtti::identify_pointee_type_or(Address{prior_addr}, pt);
    ASSERT_TRUE(first.has_value());
    ASSERT_FALSE(pt.name().empty());
    ASSERT_NE(pt.vtable.raw(), 0u);

    std::array<std::uintptr_t, 1> garbage_a{0xDEADBEEFu};
    std::array<std::uintptr_t, 1> garbage_b{0xDEADBEEFu};
    const std::uintptr_t garbage_a_addr = reinterpret_cast<std::uintptr_t>(garbage_a.data());
    const std::uintptr_t garbage_b_addr = reinterpret_cast<std::uintptr_t>(garbage_b.data());

    const auto miss = rtti::identify_pointee_type_or(Address{garbage_a_addr}, pt, Address{garbage_b_addr});
    ASSERT_FALSE(miss.has_value());

    // out is the value-initialized default, not the prior success.
    EXPECT_TRUE(pt.name().empty());
    EXPECT_EQ(pt.name_len, 0u);
    EXPECT_EQ(pt.vtable.raw(), 0u);
    EXPECT_EQ(pt.col_addr.raw(), 0u);
    EXPECT_EQ(pt.object_base.raw(), 0u);
    EXPECT_EQ(pt.pointer_value.raw(), 0u);
    EXPECT_FALSE(pt.was_pointer);
}

TEST_F(RttiDissectTest, Identify_ErrorStringsAreDistinct)
{
    // The identify error codes use DetourModKit::ErrorCode; to_string(ErrorCode) supplies the human-readable
    // rendering. Preserve the "distinct, non-empty strings" coverage over the three identify codes.
    const auto bad_slot = dmk::to_string(ErrorCode::BadSlotAddress);
    const auto unreadable = dmk::to_string(ErrorCode::UnreadableSlot);
    const auto no_rtti = dmk::to_string(ErrorCode::NoRtti);

    EXPECT_FALSE(bad_slot.empty());
    EXPECT_FALSE(unreadable.empty());
    EXPECT_FALSE(no_rtti.empty());

    EXPECT_NE(bad_slot, unreadable);
    EXPECT_NE(unreadable, no_rtti);
    EXPECT_NE(bad_slot, no_rtti);
}

// L2 reverse_scan_block

TEST_F(RttiDissectTest, ScanBlock_LabelsOnlyRealSlots)
{
    SyntheticVtable direct(".?AVBlockDirect@@");
    SyntheticVtable pointed(".?AVBlockPointed@@");
    const std::uintptr_t obj = syn_heap_object(pointed.vtable());
    ASSERT_NE(obj, 0u);

    std::array<std::uintptr_t, 5> block{
        0,               // garbage null
        direct.vtable(), // direct object base
        0x20000,         // unresolvable
        obj,             // pointer-to-object
        0,               // garbage null
    };
    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(block.data());

    std::vector<rtti::LabeledSlot> out;
    const std::size_t added = rtti::reverse_scan_block(Address{start}, block.size(), out);
    ASSERT_EQ(added, 2u);
    ASSERT_EQ(out.size(), 2u);

    EXPECT_EQ(out[0].slot_index, 1u);
    EXPECT_FALSE(out[0].type.was_pointer);
    EXPECT_EQ(out[0].type.name(), ".?AVBlockDirect@@");

    EXPECT_EQ(out[1].slot_index, 3u);
    EXPECT_TRUE(out[1].type.was_pointer);
    EXPECT_EQ(out[1].type.name(), ".?AVBlockPointed@@");
}

TEST_F(RttiDissectTest, ScanBlock_AppendsToExistingVector)
{
    SyntheticVtable v(".?AVAppend@@");
    std::array<std::uintptr_t, 1> block{v.vtable()};
    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(block.data());

    std::vector<rtti::LabeledSlot> out;
    out.emplace_back();
    const std::size_t added = rtti::reverse_scan_block(Address{start}, block.size(), out);
    EXPECT_EQ(added, 1u);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(out[1].type.name(), ".?AVAppend@@");
}

TEST_F(RttiDissectTest, ScanBlock_OverflowingCountRejected)
{
    std::vector<rtti::LabeledSlot> out;
    EXPECT_EQ(rtti::reverse_scan_block(Address{0x10000}, SIZE_MAX, out, 16), 0u);
    EXPECT_TRUE(out.empty());
}

TEST_F(RttiDissectTest, ScanBlock_CustomStrideLabelsInterleaved)
{
    SyntheticVtable a(".?AVStrideA@@");
    SyntheticVtable b(".?AVStrideB@@");
    SyntheticVtable c(".?AVStrideC@@");

    // Layout: { vtable, filler, vtable, filler, vtable, filler }; a 16-byte
    // stride means only every other qword is a probed slot.
    std::array<std::uintptr_t, 6> block{
        a.vtable(), 0xAAAAAAAAu, b.vtable(), 0xBBBBBBBBu, c.vtable(), 0xCCCCCCCCu,
    };
    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(block.data());

    std::vector<rtti::LabeledSlot> out;
    const std::size_t added = rtti::reverse_scan_block(Address{start}, 3, out, 16);
    ASSERT_EQ(added, 3u);
    ASSERT_EQ(out.size(), 3u);

    EXPECT_EQ(out[0].slot_index, 0u);
    EXPECT_EQ(out[0].slot_addr.raw(), start);
    EXPECT_EQ(out[0].type.name(), ".?AVStrideA@@");

    EXPECT_EQ(out[1].slot_index, 1u);
    EXPECT_EQ(out[1].slot_addr.raw(), start + 16);
    EXPECT_EQ(out[1].type.name(), ".?AVStrideB@@");

    EXPECT_EQ(out[2].slot_index, 2u);
    EXPECT_EQ(out[2].slot_addr.raw(), start + 32);
    EXPECT_EQ(out[2].type.name(), ".?AVStrideC@@");
}

TEST_F(RttiDissectTest, ScanBlockBytes_DividesByStride)
{
    SyntheticVtable a(".?AVByteA@@");
    SyntheticVtable b(".?AVByteB@@");
    std::array<std::uintptr_t, 2> block{a.vtable(), b.vtable()};
    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(block.data());

    std::vector<rtti::LabeledSlot> out;
    const std::size_t added = rtti::reverse_scan_block_bytes(Address{start}, 2 * sizeof(std::uintptr_t), out);
    EXPECT_EQ(added, 2u);
}

TEST_F(RttiDissectTest, ScanBlockBytes_ZeroStrideTreatedAsPointerSize)
{
    SyntheticVtable a(".?AVByteZeroA@@");
    SyntheticVtable b(".?AVByteZeroB@@");
    std::array<std::uintptr_t, 2> block{a.vtable(), b.vtable()};
    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(block.data());

    // The byte overload normalizes stride 0 to sizeof(uintptr_t) before the
    // byte_len / stride division, so a zero stride must not divide by zero;
    // 16 bytes then resolves to two slots.
    std::vector<rtti::LabeledSlot> out;
    const std::size_t added = rtti::reverse_scan_block_bytes(Address{start}, 2 * sizeof(std::uintptr_t), out, 0);
    EXPECT_EQ(added, 2u);
}

// L3 heal_landmark

namespace
{
    // A struct-shaped buffer of pointer-sized fields, plus helpers to place a pointer-to-object or a direct vtable at a
    // byte offset. The buffer is zero so every unplaced slot resolves to nothing.
    struct SynStruct
    {
        std::array<std::uintptr_t, 96> fields{};

        [[nodiscard]] std::uintptr_t base() const noexcept { return reinterpret_cast<std::uintptr_t>(fields.data()); }

        void put(std::size_t byte_off, std::uintptr_t value) noexcept
        {
            std::memcpy(reinterpret_cast<std::byte *>(base()) + byte_off, &value, sizeof(value));
        }
    };

    // Assert a heal / fingerprint Result carries a BadDescriptor error WITHOUT tripping std::expected::error()'s
    // has_value() == false precondition when the call unexpectedly succeeds: ASSERT_FALSE returns from this helper
    // (not the test), so the error() read is skipped and a regression reports a clean failure rather than UB.
    template <typename R> void expect_bad_descriptor(const R &result)
    {
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::BadDescriptor);
    }
} // anonymous namespace

TEST_F(RttiDissectTest, Heal_NoDriftHealsToNominalAndIgnoresSameTypedNeighbor)
{
    SyntheticVtable t(".?AVHealT@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, syn_heap_object(t.vtable()));
    // A same-typed neighbour inside the window must NOT trip Ambiguous because the nominal-first short-circuit returns
    // before any window scan.
    st.put(nominal + 0x08, syn_heap_object(t.vtable()));

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVHealT@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal));
    EXPECT_TRUE(hit->was_pointer);
}

TEST_F(RttiDissectTest, Heal_PositiveDrift)
{
    SyntheticVtable t(".?AVDriftPos@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal + 0x10, syn_heap_object(t.vtable()));

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVDriftPos@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal + 0x10));
}

TEST_F(RttiDissectTest, Heal_NegativeDrift)
{
    SyntheticVtable t(".?AVDriftNeg@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal - 0x08, syn_heap_object(t.vtable()));

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVDriftNeg@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal - 0x08));
}

TEST_F(RttiDissectTest, Heal_RecoversWhenNominalHoldsWrongTypedObject)
{
    // The realistic post-patch failure: the nominal slot now resolves to a
    // DIFFERENT (stale) type because another field shifted into it, and the expected field moved a few bytes away. A
    // read at the old offset would see the wrong object; heal must reject the wrong-typed nominal slot (the
    // short-circuit only fires on an exact-type match) and recover the expected type at the drifted offset.
    SyntheticVtable expected(".?AVHealExpected@@");
    SyntheticVtable stale(".?AVHealStale@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, syn_heap_object(stale.vtable()));           // what a stale read now sees
    st.put(nominal + 0x10, syn_heap_object(expected.vtable())); // where the field actually moved

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVHealExpected@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal + 0x10));
    EXPECT_EQ(hit->vtable.raw(), expected.vtable());
    EXPECT_TRUE(hit->was_pointer);
}

TEST_F(RttiDissectTest, Heal_ChainedHealAcrossTwoStructsWithNonUniformDrift)
{
    // Two pointer links live in DIFFERENT structs and drift by DIFFERENT amounts, so no single uniform delta fits the
    // whole chain (the case solve_fingerprint cannot handle): the outer struct's typed-object pointer shifts +0x30,
    // while the pointed-to object's own downstream pointer shifts
    // +0x08. Each link is healed independently and the first heal's resolved object (object_addr) roots the second
    // heal, confirming object_addr is a usable next-base. The absolute offsets are chosen to keep the window scans
    // inside the buffers; the differing per-struct deltas are the point.
    SyntheticVtable outer_vt(".?AVChainOuterTarget@@");
    SyntheticVtable inner_vt(".?AVChainInnerTarget@@");

    // The inner object, with its downstream pointer drifted from 0xD0 to 0xD8.
    const std::uintptr_t inner_obj = syn_heap_object(outer_vt.vtable());
    const std::uintptr_t leaf_obj = syn_heap_object(inner_vt.vtable());
    ASSERT_NE(inner_obj, 0u);
    ASSERT_NE(leaf_obj, 0u);
    std::memcpy(reinterpret_cast<std::byte *>(inner_obj) + 0xD8, &leaf_obj, sizeof(leaf_obj));

    // The outer struct, with its typed-object pointer drifted from 0x80 to 0xB0.
    SynStruct outer;
    outer.put(0xB0, inner_obj);

    // Link 1: heal outer -> inner (+0x30, a 6-ring scan) against the outer base.
    const rtti::Landmark lm_outer{
        .base = Address{outer.base()},
        .nominal_offset = 0x80,
        .expected_mangled = ".?AVChainOuterTarget@@",
    };
    const auto hit_outer = rtti::heal_landmark(lm_outer);
    ASSERT_TRUE(hit_outer.has_value());
    EXPECT_EQ(hit_outer->healed_offset, 0xB0);
    EXPECT_TRUE(hit_outer->was_pointer);
    // object_addr must be the resolved pointee so it can root the next heal.
    EXPECT_EQ(hit_outer->object_addr.raw(), inner_obj);

    // Link 2: heal inner -> leaf (+0x08) rooted at link 1's object_addr.
    const rtti::Landmark lm_inner{
        .base = hit_outer->object_addr,
        .nominal_offset = 0xD0,
        .expected_mangled = ".?AVChainInnerTarget@@",
    };
    const auto hit_inner = rtti::heal_landmark(lm_inner);
    ASSERT_TRUE(hit_inner.has_value());
    EXPECT_EQ(hit_inner->healed_offset, 0xD8);
    EXPECT_EQ(hit_inner->object_addr.raw(), leaf_obj);
}

TEST_F(RttiDissectTest, Heal_NoMatchWhenTypeAbsent)
{
    SyntheticVtable other(".?AVHealOther@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, syn_heap_object(other.vtable()));

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVHealMissing@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::HealNoMatch);
}

TEST_F(RttiDissectTest, Heal_NearestWinsOverFarNeighbor)
{
    SyntheticVtable t(".?AVNearest@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal + 0x08, syn_heap_object(t.vtable())); // near
    st.put(nominal + 0x20, syn_heap_object(t.vtable())); // far

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVNearest@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal + 0x08));
}

TEST_F(RttiDissectTest, Heal_EquidistantTieIsAmbiguous)
{
    SyntheticVtable t(".?AVTie@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal - 0x08, syn_heap_object(t.vtable()));
    st.put(nominal + 0x08, syn_heap_object(t.vtable()));

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVTie@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::HealAmbiguous);
}

TEST_F(RttiDissectTest, Heal_WindowEdgeInclusive)
{
    SyntheticVtable t(".?AVEdge@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal + 0x40, syn_heap_object(t.vtable())); // exactly +window

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .window = 0x40,
        .expected_mangled = ".?AVEdge@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal + 0x40));
}

TEST_F(RttiDissectTest, Heal_WindowEdgeExclusiveBeyond)
{
    SyntheticVtable t(".?AVBeyond@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal + 0x48, syn_heap_object(t.vtable())); // window + stride

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .window = 0x40,
        .expected_mangled = ".?AVBeyond@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::HealNoMatch);
}

TEST_F(RttiDissectTest, Heal_ExactMangledDiscriminationRejectsSuperstring)
{
    SyntheticVtable foobar(".?AVFooBar@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, syn_heap_object(foobar.vtable()));

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVFoo@@",
    };

    const auto hit = rtti::heal_landmark(lm);
    EXPECT_FALSE(hit.has_value());
}

TEST_F(RttiDissectTest, Heal_ShapeFilterPointerVsObjectVsAny)
{
    SyntheticVtable t(".?AVShape@@");
    const std::size_t nominal = 0x80;

    // A direct object base at the nominal slot.
    SynStruct direct;
    direct.put(nominal, t.vtable());

    // A pointer-to-object at the nominal slot.
    SynStruct pointed;
    pointed.put(nominal, syn_heap_object(t.vtable()));

    const auto lm_for = [&](std::uintptr_t base, rtti::Indirection ind) noexcept
    {
        return rtti::Landmark{
            .base = Address{base},
            .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
            .expected_mangled = ".?AVShape@@",
            .indirection = ind,
        };
    };

    // ObjectBase matches the direct slot, rejects the pointer slot.
    EXPECT_TRUE(rtti::heal_landmark(lm_for(direct.base(), rtti::Indirection::ObjectBase)).has_value());
    EXPECT_FALSE(rtti::heal_landmark(lm_for(pointed.base(), rtti::Indirection::ObjectBase)).has_value());

    // PointerToObject matches the pointer slot, rejects the direct slot.
    EXPECT_TRUE(rtti::heal_landmark(lm_for(pointed.base(), rtti::Indirection::PointerToObject)).has_value());
    EXPECT_FALSE(rtti::heal_landmark(lm_for(direct.base(), rtti::Indirection::PointerToObject)).has_value());

    // CompleteObject matches the direct primary subobject only, not a pointer-shaped slot.
    EXPECT_TRUE(rtti::heal_landmark(lm_for(direct.base(), rtti::Indirection::CompleteObject)).has_value());
    EXPECT_FALSE(rtti::heal_landmark(lm_for(pointed.base(), rtti::Indirection::CompleteObject)).has_value());

    // Any matches either.
    EXPECT_TRUE(rtti::heal_landmark(lm_for(direct.base(), rtti::Indirection::Any)).has_value());
    EXPECT_TRUE(rtti::heal_landmark(lm_for(pointed.base(), rtti::Indirection::Any)).has_value());
}

TEST_F(RttiDissectTest, Heal_CompleteObjectRejectsSecondaryVtableObjectBaseAccepts)
{
    // A multiple-inheritance secondary base: a direct object base whose vtable carries a nonzero COL.offset but whose
    // COL still names the complete type. ObjectBase accepts it (the silent off-by-a-subobject hazard) and surfaces the
    // subobject delta via HealHit::col_offset; CompleteObject rejects it because a secondary base is never the complete
    // object.
    SyntheticVtable secondary(".?AVMISecondary@@");
    secondary.set_col_offset(0x08);
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, secondary.vtable());

    const auto lm_with = [&](rtti::Indirection ind) noexcept
    {
        return rtti::Landmark{
            .base = Address{st.base()},
            .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
            .expected_mangled = ".?AVMISecondary@@",
            .indirection = ind,
        };
    };

    // ObjectBase latches the secondary slot and heals to it; col_offset reports the subobject delta.
    const auto as_object = rtti::heal_landmark(lm_with(rtti::Indirection::ObjectBase));
    ASSERT_TRUE(as_object.has_value());
    EXPECT_EQ(as_object->healed_offset, static_cast<std::ptrdiff_t>(nominal));
    EXPECT_FALSE(as_object->was_pointer);
    EXPECT_EQ(as_object->col_offset, 0x08u);

    // CompleteObject refuses the secondary subobject and, with nothing else in the window, fails closed.
    const auto as_complete = rtti::heal_landmark(lm_with(rtti::Indirection::CompleteObject));
    ASSERT_FALSE(as_complete.has_value());
    EXPECT_EQ(as_complete.error().code, ErrorCode::HealNoMatch);
}

TEST_F(RttiDissectTest, Heal_CompleteObjectMatchesPrimarySubobject)
{
    // The primary subobject of the complete object: a direct object base with COL.offset == 0. CompleteObject heals it
    // exactly as ObjectBase would and reports col_offset == 0.
    SyntheticVtable primary(".?AVMIPrimary@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, primary.vtable());

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVMIPrimary@@",
        .indirection = rtti::Indirection::CompleteObject,
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal));
    EXPECT_FALSE(hit->was_pointer);
    EXPECT_EQ(hit->col_offset, 0u);
}

TEST_F(RttiDissectTest, Heal_CompleteObjectAvoidsSilentSecondaryShortCircuit)
{
    // The real correctness trap. An upstream member removal shifts the embedded object down by 8 bytes, so its
    // secondary vtable now sits exactly on the old nominal offset while the true primary base (the complete object)
    // sits 8 bytes earlier. Both vtables' COLs name the same complete type.
    //
    // ObjectBase short-circuits on the nominal secondary slot and reports "no drift" (delta 0) while pointing 8 bytes
    // into the object -- a silent, confidently-wrong heal. CompleteObject rejects the secondary at the nominal slot and
    // scans on to recover the true primary base at nominal - 8.
    SyntheticVtable secondary(".?AVMITrap@@");
    secondary.set_col_offset(0x08);
    SyntheticVtable primary(".?AVMITrap@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, secondary.vtable());      // secondary landed on the old offset
    st.put(nominal - 0x08, primary.vtable()); // the true complete-object base, one subobject earlier

    const auto lm_with = [&](rtti::Indirection ind) noexcept
    {
        return rtti::Landmark{
            .base = Address{st.base()},
            .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
            .expected_mangled = ".?AVMITrap@@",
            .indirection = ind,
        };
    };

    // The trap: ObjectBase heals to the nominal secondary, off by the subobject delta (col_offset flags it).
    const auto as_object = rtti::heal_landmark(lm_with(rtti::Indirection::ObjectBase));
    ASSERT_TRUE(as_object.has_value());
    EXPECT_EQ(as_object->healed_offset, static_cast<std::ptrdiff_t>(nominal));
    EXPECT_EQ(as_object->col_offset, 0x08u);

    // The fix: CompleteObject recovers the true complete-object base.
    const auto as_complete = rtti::heal_landmark(lm_with(rtti::Indirection::CompleteObject));
    ASSERT_TRUE(as_complete.has_value());
    EXPECT_EQ(as_complete->healed_offset, static_cast<std::ptrdiff_t>(nominal - 0x08));
    EXPECT_EQ(as_complete->col_offset, 0u);
}

TEST_F(RttiDissectTest, Heal_BadDescriptorMatrix)
{
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, syn_heap_object(SyntheticVtable(".?AVBad@@").vtable()));
    const std::uintptr_t base = st.base();

    // Low base.
    expect_bad_descriptor(rtti::heal_landmark({.base = Address{0x100}, .expected_mangled = ".?AVBad@@"}));

    // Empty expected name.
    expect_bad_descriptor(rtti::heal_landmark({.base = Address{base}, .expected_mangled = ""}));

    // Oversized expected name.
    const std::string huge(rtti::MAX_TYPE_NAME_LEN + 1, 'X');
    expect_bad_descriptor(rtti::heal_landmark({.base = Address{base}, .expected_mangled = huge}));

    // Expected name of exactly MAX_TYPE_NAME_LEN: the guard is size() >=
    // MAX_TYPE_NAME_LEN, so this length is the first rejected one (pins the boundary against an off-by-one that would
    // let it through).
    const std::string at_cap(rtti::MAX_TYPE_NAME_LEN, 'X');
    expect_bad_descriptor(rtti::heal_landmark({.base = Address{base}, .expected_mangled = at_cap}));

    // Window over the hard cap.
    expect_bad_descriptor(rtti::heal_landmark({.base = Address{base},
                                               .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
                                               .window = rtti::MAX_HEAL_WINDOW + 1,
                                               .expected_mangled = ".?AVBad@@"}));

    // Unknown indirection enumerator.
    expect_bad_descriptor(rtti::heal_landmark({.base = Address{base},
                                               .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
                                               .expected_mangled = ".?AVBad@@",
                                               .indirection = static_cast<rtti::Indirection>(99)}));

    // nominal_offset drives the address out of the user-mode window.
    expect_bad_descriptor(rtti::heal_landmark({.base = Address{base},
                                               .nominal_offset = -static_cast<std::ptrdiff_t>(base),
                                               .expected_mangled = ".?AVBad@@"}));
}

TEST_F(RttiDissectTest, Heal_AllocatesNothing)
{
    SyntheticVtable t(".?AVNoAlloc@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    // Place the match off the nominal slot so the measured call runs the full window scan (the multi-probe,
    // syscall-heavy path) rather than the nominal-first short-circuit. That scan is where the "allocates nothing"
    // contract is most at risk, so it is the path worth measuring.
    st.put(nominal + 0x10, syn_heap_object(t.vtable()));

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVNoAlloc@@",
    };

    // Warm the module-range cache so its one-time per-module insert does not count against the measured call;
    // heal_landmark itself must not allocate.
    (void)rtti::heal_landmark(lm);

    const long long before = dmk_test::thread_new_calls();
    const auto hit = rtti::heal_landmark(lm);
    const long long after = dmk_test::thread_new_calls();

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal + 0x10));
    EXPECT_EQ(after - before, 0);
}

TEST_F(RttiDissectTest, Heal_ZeroStrideTreatedAsPointerSize)
{
    SyntheticVtable t(".?AVZeroStride@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal + 0x08, syn_heap_object(t.vtable()));

    const rtti::Landmark lm{
        .base = Address{st.base()},
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVZeroStride@@",
        .stride = 0,
    };

    const auto hit = rtti::heal_landmark(lm);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal + 0x08));
}

TEST_F(RttiDissectTest, Heal_ErrorStringsAreDistinct)
{
    // The heal error codes use DetourModKit::ErrorCode; to_string(ErrorCode) supplies the human-readable
    // rendering. Preserve the "distinct, non-empty strings" coverage over the three heal codes.
    const auto bad_descriptor = dmk::to_string(ErrorCode::BadDescriptor);
    const auto no_match = dmk::to_string(ErrorCode::HealNoMatch);
    const auto ambiguous = dmk::to_string(ErrorCode::HealAmbiguous);

    EXPECT_FALSE(bad_descriptor.empty());
    EXPECT_FALSE(no_match.empty());
    EXPECT_FALSE(ambiguous.empty());

    EXPECT_NE(bad_descriptor, no_match);
    EXPECT_NE(no_match, ambiguous);
    EXPECT_NE(bad_descriptor, ambiguous);
}

// L4 solve_fingerprint

namespace
{
    // Builds the three-field rigid template A/B/C used by several L4 tests.
    struct FpTypes
    {
        SyntheticVtable a{".?AVFpA@@"};
        SyntheticVtable b{".?AVFpB@@"};
        SyntheticVtable c{".?AVFpC@@"};
    };

    constexpr std::size_t FP_OA = 0x40;
    constexpr std::size_t FP_OB = 0x60;
    constexpr std::size_t FP_OC = 0x80;
    constexpr std::size_t FP_OD = 0xA0;

    [[nodiscard]] std::array<rtti::Landmark, 3> fp_required(std::uintptr_t base)
    {
        return {
            rtti::Landmark{.base = Address{base}, .nominal_offset = FP_OA, .expected_mangled = ".?AVFpA@@"},
            rtti::Landmark{.base = Address{base}, .nominal_offset = FP_OB, .expected_mangled = ".?AVFpB@@"},
            rtti::Landmark{.base = Address{base}, .nominal_offset = FP_OC, .expected_mangled = ".?AVFpC@@"},
        };
    }
} // anonymous namespace

TEST_F(RttiDissectTest, Fingerprint_ZeroDrift)
{
    FpTypes ty;
    SynStruct st;
    st.put(FP_OA, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC, syn_heap_object(ty.c.vtable()));

    const auto fp = fp_required(st.base());
    const auto hit = rtti::solve_fingerprint(Address{st.base()}, fp, 0x20);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->delta, 0);
    EXPECT_EQ(hit->matched, 3u);
    EXPECT_EQ(hit->optional_matched, 0u);
}

TEST_F(RttiDissectTest, Fingerprint_UniformDrift)
{
    FpTypes ty;
    SynStruct st;
    st.put(FP_OA + 0x10, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB + 0x10, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC + 0x10, syn_heap_object(ty.c.vtable()));

    const auto fp = fp_required(st.base());
    const auto hit = rtti::solve_fingerprint(Address{st.base()}, fp, 0x20);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->delta, 0x10);
    EXPECT_EQ(hit->matched, 3u);
}

TEST_F(RttiDissectTest, Fingerprint_NonRigidIsNoMatch)
{
    FpTypes ty;
    SynStruct st;
    st.put(FP_OA + 0x10, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB + 0x08, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC, syn_heap_object(ty.c.vtable()));

    const auto fp = fp_required(st.base());
    const auto hit = rtti::solve_fingerprint(Address{st.base()}, fp, 0x20);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::HealNoMatch);
}

TEST_F(RttiDissectTest, Fingerprint_ZeroDriftWinsTieAgainstSecondCopy)
{
    FpTypes ty;
    SyntheticVtable d(".?AVFpD@@");
    SynStruct st;
    // Original template at delta 0 (the caller's anchor).
    st.put(FP_OA, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC, syn_heap_object(ty.c.vtable()));
    // A full copy at delta +0x10 (a sibling in memory, e.g. array element 1).
    st.put(FP_OA + 0x10, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB + 0x10, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC + 0x10, syn_heap_object(ty.c.vtable()));

    // The zero-drift delta satisfies every required landmark, so it wins the tie against the +0x10 copy outright: the
    // object is exactly where the caller anchored, so this is the no-drift reading (and it resolves an array of
    // same-typed objects to element 0 rather than refusing because element 1 matches equally).
    const auto fp3 = fp_required(st.base());
    const auto solved = rtti::solve_fingerprint(Address{st.base()}, fp3, 0x20);
    ASSERT_TRUE(solved.has_value());
    EXPECT_EQ(solved->delta, 0);
    EXPECT_EQ(solved->matched, 3u);
    EXPECT_EQ(solved->optional_matched, 0u);

    // An optional landmark present only at the delta-0 copy raises its score; the outcome is still delta 0.
    st.put(FP_OD, syn_heap_object(d.vtable()));
    std::array<rtti::Landmark, 4> fp4{
        fp3[0],
        fp3[1],
        fp3[2],
        rtti::Landmark{
            .base = Address{st.base()}, .nominal_offset = FP_OD, .expected_mangled = ".?AVFpD@@", .required = false},
    };
    const auto scored = rtti::solve_fingerprint(Address{st.base()}, fp4, 0x20);
    ASSERT_TRUE(scored.has_value());
    EXPECT_EQ(scored->delta, 0);
    EXPECT_EQ(scored->matched, 3u);
    EXPECT_EQ(scored->optional_matched, 1u);
}

// The zero-drift carve-out is scoped to the anchor: a tie between two nonzero deltas (neither at the caller's anchor)
// remains genuinely ambiguous and fails closed, so the anchor-honouring rule above does not weaken ambiguity
// detection when the anchor itself does not validate.
TEST_F(RttiDissectTest, Fingerprint_TieBetweenTwoNonZeroDeltasIsAmbiguous)
{
    FpTypes ty;
    SynStruct st;
    // No object at delta 0 (FP_OA/FP_OB/FP_OC are empty), so the anchor does not validate. A full copy sits at both
    // delta +0x08 and delta +0x10, so exactly two nonzero deltas satisfy every required landmark and tie on optionals.
    st.put(FP_OA + 0x08, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB + 0x08, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC + 0x08, syn_heap_object(ty.c.vtable()));
    st.put(FP_OA + 0x10, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB + 0x10, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC + 0x10, syn_heap_object(ty.c.vtable()));

    const auto fp = fp_required(st.base());
    const auto tied = rtti::solve_fingerprint(Address{st.base()}, fp, 0x20);
    ASSERT_FALSE(tied.has_value());
    EXPECT_EQ(tied.error().code, ErrorCode::HealAmbiguous);
}

TEST_F(RttiDissectTest, Fingerprint_SingleLandmarkMatchesHeal)
{
    SyntheticVtable a(".?AVFpSolo@@");
    SynStruct st;
    st.put(FP_OA + 0x08, syn_heap_object(a.vtable()));

    const std::array<rtti::Landmark, 1> fp{
        rtti::Landmark{.base = Address{st.base()}, .nominal_offset = FP_OA, .expected_mangled = ".?AVFpSolo@@"},
    };
    const auto solved = rtti::solve_fingerprint(Address{st.base()}, fp, 0x20);
    ASSERT_TRUE(solved.has_value());
    EXPECT_EQ(solved->delta, 0x08);

    const auto healed = rtti::heal_landmark(fp[0]);
    ASSERT_TRUE(healed.has_value());
    // The fingerprint delta is the drift; the heal offset is the absolute field offset. They agree once the nominal
    // offset is removed.
    EXPECT_EQ(healed->healed_offset - static_cast<std::ptrdiff_t>(FP_OA), solved->delta);
}

TEST_F(RttiDissectTest, Fingerprint_DuplicateOffsetIsBadDescriptor)
{
    // Two required landmarks that share a nominal_offset probe the same shifted slot. Counting both would inflate the
    // corroboration score and report stronger agreement than the template actually provides, so a duplicate offset is
    // a malformed template and must fail before any memory is probed.
    FpTypes ty;
    SynStruct st;
    st.put(FP_OA, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC, syn_heap_object(ty.c.vtable()));

    const std::array<rtti::Landmark, 4> with_dup{
        rtti::Landmark{.base = Address{st.base()}, .nominal_offset = FP_OA, .expected_mangled = ".?AVFpA@@"},
        rtti::Landmark{.base = Address{st.base()}, .nominal_offset = FP_OB, .expected_mangled = ".?AVFpB@@"},
        rtti::Landmark{.base = Address{st.base()}, .nominal_offset = FP_OC, .expected_mangled = ".?AVFpC@@"},
        rtti::Landmark{.base = Address{st.base()}, .nominal_offset = FP_OA, .expected_mangled = ".?AVFpA@@"},
    };
    const auto hit = rtti::solve_fingerprint(Address{st.base()}, with_dup, 0x20);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::BadDescriptor);
}

TEST_F(RttiDissectTest, Fingerprint_AllocatesNothing)
{
    // solve_fingerprint documents an allocation-free contract; like the heal path it reuses one stack PointeeType and
    // never grows a container. Drive a uniform-drift solve (every required landmark probed at the shifted offset) and
    // assert the measured call adds no counted allocation.
    FpTypes ty;
    SynStruct st;
    st.put(FP_OA + 0x10, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB + 0x10, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC + 0x10, syn_heap_object(ty.c.vtable()));

    const auto fp = fp_required(st.base());

    // Warm the module-range cache so its one-time per-module insert is not attributed to the measured call.
    (void)rtti::solve_fingerprint(Address{st.base()}, fp, 0x20);

    const long long before = dmk_test::thread_new_calls();
    const auto hit = rtti::solve_fingerprint(Address{st.base()}, fp, 0x20);
    const long long after = dmk_test::thread_new_calls();

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->delta, 0x10);
    EXPECT_EQ(after - before, 0);
}

TEST_F(RttiDissectTest, Fingerprint_CapGuards)
{
    SynStruct st;
    const std::uintptr_t base = st.base();

    // Empty span.
    expect_bad_descriptor(rtti::solve_fingerprint(Address{base}, std::span<const rtti::Landmark>{}, 0x20));

    // Low base.
    expect_bad_descriptor(rtti::solve_fingerprint(Address{0x100}, fp_required(0x100), 0x20));

    // Window over the hard cap.
    expect_bad_descriptor(rtti::solve_fingerprint(Address{base}, fp_required(base), rtti::MAX_HEAL_WINDOW + 1));

    // Over the landmark cap.
    std::array<rtti::Landmark, rtti::MAX_FINGERPRINT_LANDMARKS + 1> too_many{};
    for (auto &lm : too_many)
    {
        lm.base = Address{base};
        lm.expected_mangled = ".?AVCap@@";
    }
    expect_bad_descriptor(rtti::solve_fingerprint(Address{base}, too_many, 0x20));

    // Every landmark optional: nothing to anchor on.
    std::array<rtti::Landmark, 2> all_optional{
        rtti::Landmark{
            .base = Address{base}, .nominal_offset = FP_OA, .expected_mangled = ".?AVCap@@", .required = false},
        rtti::Landmark{
            .base = Address{base}, .nominal_offset = FP_OB, .expected_mangled = ".?AVCap@@", .required = false},
    };
    expect_bad_descriptor(rtti::solve_fingerprint(Address{base}, all_optional, 0x20));
}

// heal_report (drift telemetry)

TEST_F(RttiDissectTest, HealReport_RecordsNoDriftAndPositiveDrift)
{
    SyntheticVtable a(".?AVReportA@@");
    SyntheticVtable b(".?AVReportB@@");
    SynStruct st;
    const std::size_t off_a = 0x40;
    const std::size_t off_b = 0x80;
    st.put(off_a, syn_heap_object(a.vtable()));        // stays put: delta 0
    st.put(off_b + 0x10, syn_heap_object(b.vtable())); // drifted +0x10

    const rtti::Landmark lms[] = {
        {.base = Address{st.base()},
         .nominal_offset = static_cast<std::ptrdiff_t>(off_a),
         .expected_mangled = ".?AVReportA@@"},
        {.base = Address{st.base()},
         .nominal_offset = static_cast<std::ptrdiff_t>(off_b),
         .expected_mangled = ".?AVReportB@@"},
    };

    rtti::DriftEntry report[2];
    const std::size_t n = rtti::heal_report(lms, report);
    ASSERT_EQ(n, 2u);

    EXPECT_TRUE(report[0].ok);
    EXPECT_EQ(report[0].name, ".?AVReportA@@");
    EXPECT_EQ(report[0].nominal_offset, static_cast<std::ptrdiff_t>(off_a));
    EXPECT_EQ(report[0].healed_offset, static_cast<std::ptrdiff_t>(off_a));
    EXPECT_EQ(report[0].delta, 0);

    EXPECT_TRUE(report[1].ok);
    EXPECT_EQ(report[1].delta, static_cast<std::ptrdiff_t>(0x10));
    EXPECT_EQ(report[1].healed_offset, static_cast<std::ptrdiff_t>(off_b + 0x10));
}

TEST_F(RttiDissectTest, HealReport_RecordsTypedFailure)
{
    SynStruct st; // nothing of the expected type anywhere in the window
    const rtti::Landmark lms[] = {
        {.base = Address{st.base()}, .nominal_offset = 0x40, .expected_mangled = ".?AVReportMissing@@"},
    };

    // Pre-seed the output with stale values to prove a failed entry is reset and never exposes a reused buffer's prior
    // contents.
    rtti::DriftEntry report[1];
    report[0].healed_offset = 0x7777;
    report[0].delta = 0x1234;
    report[0].ok = true;

    const std::size_t n = rtti::heal_report(lms, report);
    ASSERT_EQ(n, 1u);
    EXPECT_FALSE(report[0].ok);
    EXPECT_EQ(report[0].error, ErrorCode::HealNoMatch);
    EXPECT_EQ(report[0].name, ".?AVReportMissing@@");
    EXPECT_EQ(report[0].nominal_offset, 0x40); // populated regardless of success
    EXPECT_EQ(report[0].healed_offset, 0);     // reset, not the stale 0x7777
    EXPECT_EQ(report[0].delta, 0);             // reset, not the stale 0x1234
}

TEST_F(RttiDissectTest, HealReport_RespectsOutputCapacity)
{
    SyntheticVtable a(".?AVCapReport@@");
    SynStruct st;
    st.put(0x40, syn_heap_object(a.vtable()));

    const rtti::Landmark lms[] = {
        {.base = Address{st.base()}, .nominal_offset = 0x40, .expected_mangled = ".?AVCapReport@@"},
        {.base = Address{st.base()}, .nominal_offset = 0x40, .expected_mangled = ".?AVCapReport@@"},
        {.base = Address{st.base()}, .nominal_offset = 0x40, .expected_mangled = ".?AVCapReport@@"},
    };

    rtti::DriftEntry report[2]; // smaller than the landmark set
    const std::size_t n = rtti::heal_report(lms, report);
    EXPECT_EQ(n, 2u); // min(landmarks.size(), out.size())

    // The written entries must be real heals, not just a returned count.
    EXPECT_TRUE(report[0].ok);
    EXPECT_TRUE(report[1].ok);
    EXPECT_EQ(report[0].name, ".?AVCapReport@@");
}

// The signed offset/delta arithmetic the heal path uses must be defined for every value, including the PTRDIFF_MIN
// negation (undefined for the naive (delta < 0) ? -delta : delta) and a subtraction whose true result leaves the
// ptrdiff_t range. The helpers are consumed by warn_drift_once, heal_into, note_drift, and heal_report; proving them at
// compile time is the strongest available guard on a platform with no UBSan.
TEST(RttiSignedArith, PtrdiffMagnitudeIsDefinedAtExtremes)
{
    using rtti::detail::ptrdiff_magnitude;
    static_assert(ptrdiff_magnitude(0) == 0U);
    static_assert(ptrdiff_magnitude(1) == 1U);
    static_assert(ptrdiff_magnitude(-1) == 1U);
    static_assert(ptrdiff_magnitude(PTRDIFF_MAX) == static_cast<std::uint64_t>(PTRDIFF_MAX));
    // PTRDIFF_MIN's magnitude is not representable in a ptrdiff_t (this is the -delta UB the helper replaces); as an
    // unsigned value it is exactly 2^63.
    static_assert(ptrdiff_magnitude(PTRDIFF_MIN) == (std::uint64_t{1} << 63));
    EXPECT_EQ(ptrdiff_magnitude(PTRDIFF_MIN), std::uint64_t{1} << 63);
    EXPECT_EQ(ptrdiff_magnitude(-1234), 1234U);
}

TEST(RttiSignedArith, SaturatingSubPreservesExtremeDriftSeverity)
{
    using rtti::detail::saturating_sub;
    static_assert(saturating_sub(5, 3) == 2);
    static_assert(saturating_sub(3, 5) == -2);
    static_assert(saturating_sub(PTRDIFF_MAX, PTRDIFF_MIN) == PTRDIFF_MAX);
    static_assert(saturating_sub(PTRDIFF_MIN, PTRDIFF_MAX) == PTRDIFF_MIN);
    EXPECT_EQ(saturating_sub(PTRDIFF_MAX, PTRDIFF_MIN), PTRDIFF_MAX);
    EXPECT_EQ(saturating_sub(PTRDIFF_MIN, PTRDIFF_MAX), PTRDIFF_MIN);
}

TEST(RttiSignedArith, AddressOffsetIsDefinedAtExtremes)
{
    using rtti::detail::address_offset;
    static_assert(address_offset(100, 80) == 20);
    static_assert(address_offset(80, 100) == -20);
    static_assert(address_offset(UINTPTR_MAX, 0) == PTRDIFF_MAX);
    static_assert(address_offset(0, UINTPTR_MAX) == PTRDIFF_MIN);
}

TEST(RttiSignedArith, ExtremeNominalOffsetsFailBeforeMemoryAccess)
{
    for (const std::ptrdiff_t offset : {PTRDIFF_MIN, PTRDIFF_MAX})
    {
        const rtti::Landmark landmark{
            .base = Address{0x10000}, .nominal_offset = offset, .expected_mangled = ".?AVExtreme@@"};
        const auto result = rtti::heal_landmark(landmark);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, DetourModKit::ErrorCode::BadDescriptor);
    }
}
