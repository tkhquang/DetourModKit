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

namespace Memory = DetourModKit::Memory;
namespace Rtti = DetourModKit::Rtti;

namespace
{
    // Counts every throwing global operator new across the whole test binary. Only read across a narrow window (the
    // heal-allocation test) where the module-range cache is already warm, so unrelated allocations elsewhere in the
    // process do not perturb the measured delta. Constant-initialised so it is zero before any dynamic initialisation
    // that might allocate.
    std::atomic<long long> s_new_calls{0};
} // anonymous namespace

// Replace the throwing global new/delete with malloc/free plus a counter. The aligned (std::align_val_t) forms are
// deliberately left at their defaults, so over-aligned allocations stay on the runtime's own consistent new/delete pair
// and never cross-free against these.
void *operator new(std::size_t size)
{
    if (size == 0)
    {
        size = 1;
    }
    void *p = std::malloc(size);
    if (!p)
    {
        throw std::bad_alloc{};
    }
    s_new_calls.fetch_add(1, std::memory_order_relaxed);
    return p;
}

void *operator new[](std::size_t size)
{
    return operator new(size);
}
void operator delete(void *p) noexcept
{
    std::free(p);
}
void operator delete(void *p, std::size_t) noexcept
{
    std::free(p);
}
void operator delete[](void *p) noexcept
{
    std::free(p);
}
void operator delete[](void *p, std::size_t) noexcept
{
    std::free(p);
}

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
    // Memory::module_range_for resolves every synthetic vtable back to the test exe's PE range, which the prelude's
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
        (void)Memory::init_cache();
        syn_reset();
    }

    void TearDown() override
    {
        Memory::shutdown_cache();
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

// --- L1 identify_pointee_type ---

TEST_F(RttiDissectTest, Identify_DirectObjectBase)
{
    SyntheticVtable v(".?AVDirect@@");
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    Rtti::PointeeType pt;
    ASSERT_TRUE(Rtti::identify_pointee_type(slot_addr, pt));
    EXPECT_FALSE(pt.was_pointer);
    // Direct contract: object base is the slot ADDRESS, vtable is the value.
    EXPECT_EQ(pt.object_base, slot_addr);
    EXPECT_EQ(pt.vtable, v.vtable());
    EXPECT_EQ(pt.pointer_value, v.vtable());
    EXPECT_EQ(pt.name(), ".?AVDirect@@");
}

TEST_F(RttiDissectTest, Identify_PointerToObject)
{
    SyntheticVtable v(".?AVHeapObj@@");
    const std::uintptr_t obj = syn_heap_object(v.vtable());
    ASSERT_NE(obj, 0u);

    std::array<std::uintptr_t, 1> slot{obj};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    Rtti::PointeeType pt;
    ASSERT_TRUE(Rtti::identify_pointee_type(slot_addr, pt));
    EXPECT_TRUE(pt.was_pointer);
    // Pointer-to-object contract: object base is the pointee value.
    EXPECT_EQ(pt.object_base, obj);
    EXPECT_EQ(pt.pointer_value, obj);
    EXPECT_EQ(pt.vtable, v.vtable());
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

    Rtti::PointeeType pt;
    ASSERT_TRUE(Rtti::identify_pointee_type(slot_addr, pt));
    EXPECT_EQ(pt.col_offset, 0x10u);
    EXPECT_EQ(pt.complete_obj, obj - 0x10);
}

TEST_F(RttiDissectTest, Identify_DirectObjectNonzeroColOffsetRecoversCompleteObject)
{
    // The direct-object branch sets object_base to the slot ADDRESS, a distinct code path from the pointer-to-object
    // branch above. Confirm the complete object is recovered as slot_addr - col_offset there too.
    SyntheticVtable v(".?AVDirectSub@@");
    v.set_col_offset(0x20);
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    Rtti::PointeeType pt;
    ASSERT_TRUE(Rtti::identify_pointee_type(slot_addr, pt));
    EXPECT_FALSE(pt.was_pointer);
    EXPECT_EQ(pt.object_base, slot_addr);
    EXPECT_EQ(pt.col_offset, 0x20u);
    EXPECT_EQ(pt.complete_obj, slot_addr - 0x20);
}

TEST_F(RttiDissectTest, Identify_ExposesColTdAndNameAddresses)
{
    // The col_addr / td_addr / name_addr coordinates are part of the public introspection surface; pin them to the
    // fixture's known layout so a regression in the prelude wiring is caught here.
    SyntheticVtable v(".?AVCoords@@");
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    Rtti::PointeeType pt;
    ASSERT_TRUE(Rtti::identify_pointee_type(slot_addr, pt));
    EXPECT_EQ(pt.col_addr, v.col_addr());
    EXPECT_EQ(pt.td_addr, v.td_addr());
    EXPECT_EQ(pt.name_addr, v.name_addr());
}

TEST_F(RttiDissectTest, Identify_RejectsPoisonedTypeDescriptorRva)
{
    SyntheticVtable v(".?AVValid@@");
    v.poison_type_descriptor_rva(0x7FFFFFFFu);
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    Rtti::PointeeType pt;
    EXPECT_FALSE(Rtti::identify_pointee_type(slot_addr, pt));
}

TEST_F(RttiDissectTest, Identify_RejectsPoisonedSelfRva)
{
    SyntheticVtable v(".?AVValid@@");
    v.poison_self_rva(1);
    std::array<std::uintptr_t, 1> slot{v.vtable()};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    Rtti::PointeeType pt;
    EXPECT_FALSE(Rtti::identify_pointee_type(slot_addr, pt));
}

TEST_F(RttiDissectTest, Identify_RejectsNullAndLowSlot)
{
    Rtti::PointeeType pt;
    EXPECT_FALSE(Rtti::identify_pointee_type(0, pt));
    EXPECT_FALSE(Rtti::identify_pointee_type(0x100, pt));
}

TEST_F(RttiDissectTest, Identify_RejectsUnreadableSlotAddress)
{
    const std::uintptr_t gone = unmapped_addr();
    // Guard the precondition: if the committed-then-freed allocation ever failed, gone would be 0 and this would
    // silently exercise the null-slot guard instead of the unmapped-read path. unmapped_addr returns a value, so the
    // fatal assert lives here rather than inside the helper.
    ASSERT_NE(gone, 0u);
    Rtti::PointeeType pt;
    EXPECT_FALSE(Rtti::identify_pointee_type(gone, pt));
}

TEST_F(RttiDissectTest, Identify_RejectsGarbageSlotValue)
{
    // Slot holds a plausible-but-unresolvable pointer: neither a pointer to an object with a valid COL nor a vtable in
    // any module.
    std::array<std::uintptr_t, 1> slot{0xDEADBEEFu};
    const std::uintptr_t slot_addr = reinterpret_cast<std::uintptr_t>(slot.data());

    Rtti::PointeeType pt;
    EXPECT_FALSE(Rtti::identify_pointee_type(slot_addr, pt));
}

// --- L2 reverse_scan_block ---

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

    std::vector<Rtti::LabeledSlot> out;
    const std::size_t added = Rtti::reverse_scan_block(start, block.size(), out);
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

    std::vector<Rtti::LabeledSlot> out;
    out.emplace_back();
    const std::size_t added = Rtti::reverse_scan_block(start, block.size(), out);
    EXPECT_EQ(added, 1u);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(out[1].type.name(), ".?AVAppend@@");
}

TEST_F(RttiDissectTest, ScanBlock_OverflowingCountRejected)
{
    std::vector<Rtti::LabeledSlot> out;
    EXPECT_EQ(Rtti::reverse_scan_block(0x10000, SIZE_MAX, out, 16), 0u);
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

    std::vector<Rtti::LabeledSlot> out;
    const std::size_t added = Rtti::reverse_scan_block(start, 3, out, 16);
    ASSERT_EQ(added, 3u);
    ASSERT_EQ(out.size(), 3u);

    EXPECT_EQ(out[0].slot_index, 0u);
    EXPECT_EQ(out[0].slot_addr, start);
    EXPECT_EQ(out[0].type.name(), ".?AVStrideA@@");

    EXPECT_EQ(out[1].slot_index, 1u);
    EXPECT_EQ(out[1].slot_addr, start + 16);
    EXPECT_EQ(out[1].type.name(), ".?AVStrideB@@");

    EXPECT_EQ(out[2].slot_index, 2u);
    EXPECT_EQ(out[2].slot_addr, start + 32);
    EXPECT_EQ(out[2].type.name(), ".?AVStrideC@@");
}

TEST_F(RttiDissectTest, ScanBlockBytes_DividesByStride)
{
    SyntheticVtable a(".?AVByteA@@");
    SyntheticVtable b(".?AVByteB@@");
    std::array<std::uintptr_t, 2> block{a.vtable(), b.vtable()};
    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(block.data());

    std::vector<Rtti::LabeledSlot> out;
    const std::size_t added = Rtti::reverse_scan_block_bytes(start, 2 * sizeof(std::uintptr_t), out);
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
    std::vector<Rtti::LabeledSlot> out;
    const std::size_t added = Rtti::reverse_scan_block_bytes(start, 2 * sizeof(std::uintptr_t), out, 0);
    EXPECT_EQ(added, 2u);
}

// --- L3 heal_landmark / heal_offset ---

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

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVHealT@@",
    };

    const auto hit = Rtti::heal_landmark(lm);
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

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVDriftPos@@",
    };

    const auto off = Rtti::heal_offset(lm);
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(*off, static_cast<std::ptrdiff_t>(nominal + 0x10));
}

TEST_F(RttiDissectTest, Heal_NegativeDrift)
{
    SyntheticVtable t(".?AVDriftNeg@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal - 0x08, syn_heap_object(t.vtable()));

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVDriftNeg@@",
    };

    const auto off = Rtti::heal_offset(lm);
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(*off, static_cast<std::ptrdiff_t>(nominal - 0x08));
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

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVHealExpected@@",
    };

    const auto hit = Rtti::heal_landmark(lm);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal + 0x10));
    EXPECT_EQ(hit->vtable, expected.vtable());
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
    const Rtti::Landmark lm_outer{
        .base = outer.base(),
        .nominal_offset = 0x80,
        .expected_mangled = ".?AVChainOuterTarget@@",
    };
    const auto hit_outer = Rtti::heal_landmark(lm_outer);
    ASSERT_TRUE(hit_outer.has_value());
    EXPECT_EQ(hit_outer->healed_offset, 0xB0);
    EXPECT_TRUE(hit_outer->was_pointer);
    // object_addr must be the resolved pointee so it can root the next heal.
    EXPECT_EQ(hit_outer->object_addr, inner_obj);

    // Link 2: heal inner -> leaf (+0x08) rooted at link 1's object_addr.
    const Rtti::Landmark lm_inner{
        .base = hit_outer->object_addr,
        .nominal_offset = 0xD0,
        .expected_mangled = ".?AVChainInnerTarget@@",
    };
    const auto hit_inner = Rtti::heal_landmark(lm_inner);
    ASSERT_TRUE(hit_inner.has_value());
    EXPECT_EQ(hit_inner->healed_offset, 0xD8);
    EXPECT_EQ(hit_inner->object_addr, leaf_obj);
}

TEST_F(RttiDissectTest, Heal_NoMatchWhenTypeAbsent)
{
    SyntheticVtable other(".?AVHealOther@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, syn_heap_object(other.vtable()));

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVHealMissing@@",
    };

    const auto hit = Rtti::heal_landmark(lm);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error(), Rtti::HealError::NoMatch);
}

TEST_F(RttiDissectTest, Heal_NearestWinsOverFarNeighbor)
{
    SyntheticVtable t(".?AVNearest@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal + 0x08, syn_heap_object(t.vtable())); // near
    st.put(nominal + 0x20, syn_heap_object(t.vtable())); // far

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVNearest@@",
    };

    const auto off = Rtti::heal_offset(lm);
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(*off, static_cast<std::ptrdiff_t>(nominal + 0x08));
}

TEST_F(RttiDissectTest, Heal_EquidistantTieIsAmbiguous)
{
    SyntheticVtable t(".?AVTie@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal - 0x08, syn_heap_object(t.vtable()));
    st.put(nominal + 0x08, syn_heap_object(t.vtable()));

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVTie@@",
    };

    const auto hit = Rtti::heal_landmark(lm);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error(), Rtti::HealError::Ambiguous);
}

TEST_F(RttiDissectTest, Heal_WindowEdgeInclusive)
{
    SyntheticVtable t(".?AVEdge@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal + 0x40, syn_heap_object(t.vtable())); // exactly +window

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .window = 0x40,
        .expected_mangled = ".?AVEdge@@",
    };

    const auto off = Rtti::heal_offset(lm);
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(*off, static_cast<std::ptrdiff_t>(nominal + 0x40));
}

TEST_F(RttiDissectTest, Heal_WindowEdgeExclusiveBeyond)
{
    SyntheticVtable t(".?AVBeyond@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal + 0x48, syn_heap_object(t.vtable())); // window + stride

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .window = 0x40,
        .expected_mangled = ".?AVBeyond@@",
    };

    const auto hit = Rtti::heal_landmark(lm);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error(), Rtti::HealError::NoMatch);
}

TEST_F(RttiDissectTest, Heal_ExactMangledDiscriminationRejectsSuperstring)
{
    SyntheticVtable foobar(".?AVFooBar@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, syn_heap_object(foobar.vtable()));

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVFoo@@",
    };

    const auto hit = Rtti::heal_landmark(lm);
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

    const auto lm_for = [&](std::uintptr_t base, Rtti::Indirection ind) noexcept
    {
        return Rtti::Landmark{
            .base = base,
            .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
            .expected_mangled = ".?AVShape@@",
            .indirection = ind,
        };
    };

    // ObjectBase matches the direct slot, rejects the pointer slot.
    EXPECT_TRUE(Rtti::heal_landmark(lm_for(direct.base(), Rtti::Indirection::ObjectBase)).has_value());
    EXPECT_FALSE(Rtti::heal_landmark(lm_for(pointed.base(), Rtti::Indirection::ObjectBase)).has_value());

    // PointerToObject matches the pointer slot, rejects the direct slot.
    EXPECT_TRUE(Rtti::heal_landmark(lm_for(pointed.base(), Rtti::Indirection::PointerToObject)).has_value());
    EXPECT_FALSE(Rtti::heal_landmark(lm_for(direct.base(), Rtti::Indirection::PointerToObject)).has_value());

    // Any matches either.
    EXPECT_TRUE(Rtti::heal_landmark(lm_for(direct.base(), Rtti::Indirection::Any)).has_value());
    EXPECT_TRUE(Rtti::heal_landmark(lm_for(pointed.base(), Rtti::Indirection::Any)).has_value());
}

TEST_F(RttiDissectTest, Heal_BadDescriptorMatrix)
{
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, syn_heap_object(SyntheticVtable(".?AVBad@@").vtable()));
    const std::uintptr_t base = st.base();

    // Low base.
    EXPECT_EQ(Rtti::heal_landmark({.base = 0x100, .expected_mangled = ".?AVBad@@"}).error(),
              Rtti::HealError::BadDescriptor);

    // Empty expected name.
    EXPECT_EQ(Rtti::heal_landmark({.base = base, .expected_mangled = ""}).error(), Rtti::HealError::BadDescriptor);

    // Oversized expected name.
    const std::string huge(Rtti::MAX_TYPE_NAME_LEN + 1, 'X');
    EXPECT_EQ(Rtti::heal_landmark({.base = base, .expected_mangled = huge}).error(), Rtti::HealError::BadDescriptor);

    // Expected name of exactly MAX_TYPE_NAME_LEN: the guard is size() >=
    // MAX_TYPE_NAME_LEN, so this length is the first rejected one (pins the boundary against an off-by-one that would
    // let it through).
    const std::string at_cap(Rtti::MAX_TYPE_NAME_LEN, 'X');
    EXPECT_EQ(Rtti::heal_landmark({.base = base, .expected_mangled = at_cap}).error(), Rtti::HealError::BadDescriptor);

    // Window over the hard cap.
    EXPECT_EQ(Rtti::heal_landmark({.base = base,
                                   .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
                                   .window = Rtti::MAX_HEAL_WINDOW + 1,
                                   .expected_mangled = ".?AVBad@@"})
                  .error(),
              Rtti::HealError::BadDescriptor);

    // Unknown indirection enumerator.
    EXPECT_EQ(Rtti::heal_landmark({.base = base,
                                   .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
                                   .expected_mangled = ".?AVBad@@",
                                   .indirection = static_cast<Rtti::Indirection>(99)})
                  .error(),
              Rtti::HealError::BadDescriptor);

    // nominal_offset drives the address out of the user-mode window.
    EXPECT_EQ(Rtti::heal_landmark(
                  {.base = base, .nominal_offset = -static_cast<std::ptrdiff_t>(base), .expected_mangled = ".?AVBad@@"})
                  .error(),
              Rtti::HealError::BadDescriptor);
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

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVNoAlloc@@",
    };

    // Warm the module-range cache so its one-time per-module insert does not count against the measured call;
    // heal_landmark itself must not allocate.
    (void)Rtti::heal_landmark(lm);

    const long long before = s_new_calls.load(std::memory_order_relaxed);
    const auto hit = Rtti::heal_landmark(lm);
    const long long after = s_new_calls.load(std::memory_order_relaxed);

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->healed_offset, static_cast<std::ptrdiff_t>(nominal + 0x10));
    EXPECT_EQ(after - before, 0);
}

TEST_F(RttiDissectTest, HealOffset_ReturnsNulloptOnFailure)
{
    // heal_offset collapses any heal_landmark error to std::nullopt.
    SyntheticVtable other(".?AVHealOffOther@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal, syn_heap_object(other.vtable()));

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVHealOffMissing@@",
    };

    EXPECT_FALSE(Rtti::heal_offset(lm).has_value());
}

TEST_F(RttiDissectTest, Heal_ZeroStrideTreatedAsPointerSize)
{
    SyntheticVtable t(".?AVZeroStride@@");
    SynStruct st;
    const std::size_t nominal = 0x80;
    st.put(nominal + 0x08, syn_heap_object(t.vtable()));

    const Rtti::Landmark lm{
        .base = st.base(),
        .nominal_offset = static_cast<std::ptrdiff_t>(nominal),
        .expected_mangled = ".?AVZeroStride@@",
        .stride = 0,
    };

    const auto off = Rtti::heal_offset(lm);
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(*off, static_cast<std::ptrdiff_t>(nominal + 0x08));
}

TEST_F(RttiDissectTest, Heal_ErrorStringsAreDistinct)
{
    EXPECT_NE(Rtti::heal_error_to_string(Rtti::HealError::BadDescriptor),
              Rtti::heal_error_to_string(Rtti::HealError::NoMatch));
    EXPECT_NE(Rtti::heal_error_to_string(Rtti::HealError::NoMatch),
              Rtti::heal_error_to_string(Rtti::HealError::Ambiguous));
    EXPECT_FALSE(Rtti::heal_error_to_string(Rtti::HealError::Ambiguous).empty());
}

// --- L4 solve_fingerprint ---

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

    [[nodiscard]] std::array<Rtti::Landmark, 3> fp_required(std::uintptr_t base)
    {
        return {
            Rtti::Landmark{.base = base, .nominal_offset = FP_OA, .expected_mangled = ".?AVFpA@@"},
            Rtti::Landmark{.base = base, .nominal_offset = FP_OB, .expected_mangled = ".?AVFpB@@"},
            Rtti::Landmark{.base = base, .nominal_offset = FP_OC, .expected_mangled = ".?AVFpC@@"},
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
    const auto hit = Rtti::solve_fingerprint(st.base(), fp, 0x20);
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
    const auto hit = Rtti::solve_fingerprint(st.base(), fp, 0x20);
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
    const auto hit = Rtti::solve_fingerprint(st.base(), fp, 0x20);
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error(), Rtti::HealError::NoMatch);
}

TEST_F(RttiDissectTest, Fingerprint_SecondCopyIsAmbiguousAndOptionalBreaksTie)
{
    FpTypes ty;
    SyntheticVtable d(".?AVFpD@@");
    SynStruct st;
    // Original template at delta 0.
    st.put(FP_OA, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC, syn_heap_object(ty.c.vtable()));
    // A full copy at delta +0x10.
    st.put(FP_OA + 0x10, syn_heap_object(ty.a.vtable()));
    st.put(FP_OB + 0x10, syn_heap_object(ty.b.vtable()));
    st.put(FP_OC + 0x10, syn_heap_object(ty.c.vtable()));

    const auto fp3 = fp_required(st.base());
    const auto tied = Rtti::solve_fingerprint(st.base(), fp3, 0x20);
    ASSERT_FALSE(tied.has_value());
    EXPECT_EQ(tied.error(), Rtti::HealError::Ambiguous);

    // An optional landmark present only at the delta-0 copy breaks the tie.
    st.put(FP_OD, syn_heap_object(d.vtable()));
    std::array<Rtti::Landmark, 4> fp4{
        fp3[0],
        fp3[1],
        fp3[2],
        Rtti::Landmark{.base = st.base(), .nominal_offset = FP_OD, .expected_mangled = ".?AVFpD@@", .required = false},
    };
    const auto broken = Rtti::solve_fingerprint(st.base(), fp4, 0x20);
    ASSERT_TRUE(broken.has_value());
    EXPECT_EQ(broken->delta, 0);
    EXPECT_EQ(broken->matched, 3u);
    EXPECT_EQ(broken->optional_matched, 1u);
}

TEST_F(RttiDissectTest, Fingerprint_SingleLandmarkMatchesHeal)
{
    SyntheticVtable a(".?AVFpSolo@@");
    SynStruct st;
    st.put(FP_OA + 0x08, syn_heap_object(a.vtable()));

    const std::array<Rtti::Landmark, 1> fp{
        Rtti::Landmark{.base = st.base(), .nominal_offset = FP_OA, .expected_mangled = ".?AVFpSolo@@"},
    };
    const auto solved = Rtti::solve_fingerprint(st.base(), fp, 0x20);
    ASSERT_TRUE(solved.has_value());
    EXPECT_EQ(solved->delta, 0x08);

    const auto healed = Rtti::heal_landmark(fp[0]);
    ASSERT_TRUE(healed.has_value());
    // The fingerprint delta is the drift; the heal offset is the absolute field offset. They agree once the nominal
    // offset is removed.
    EXPECT_EQ(healed->healed_offset - static_cast<std::ptrdiff_t>(FP_OA), solved->delta);
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
    (void)Rtti::solve_fingerprint(st.base(), fp, 0x20);

    const long long before = s_new_calls.load(std::memory_order_relaxed);
    const auto hit = Rtti::solve_fingerprint(st.base(), fp, 0x20);
    const long long after = s_new_calls.load(std::memory_order_relaxed);

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->delta, 0x10);
    EXPECT_EQ(after - before, 0);
}

TEST_F(RttiDissectTest, Fingerprint_CapGuards)
{
    SynStruct st;
    const std::uintptr_t base = st.base();

    // Empty span.
    EXPECT_EQ(Rtti::solve_fingerprint(base, std::span<const Rtti::Landmark>{}, 0x20).error(),
              Rtti::HealError::BadDescriptor);

    // Low base.
    EXPECT_EQ(Rtti::solve_fingerprint(0x100, fp_required(0x100), 0x20).error(), Rtti::HealError::BadDescriptor);

    // Window over the hard cap.
    EXPECT_EQ(Rtti::solve_fingerprint(base, fp_required(base), Rtti::MAX_HEAL_WINDOW + 1).error(),
              Rtti::HealError::BadDescriptor);

    // Over the landmark cap.
    std::array<Rtti::Landmark, Rtti::MAX_FINGERPRINT_LANDMARKS + 1> too_many{};
    for (auto &lm : too_many)
    {
        lm.base = base;
        lm.expected_mangled = ".?AVCap@@";
    }
    EXPECT_EQ(Rtti::solve_fingerprint(base, too_many, 0x20).error(), Rtti::HealError::BadDescriptor);

    // Every landmark optional: nothing to anchor on.
    std::array<Rtti::Landmark, 2> all_optional{
        Rtti::Landmark{.base = base, .nominal_offset = FP_OA, .expected_mangled = ".?AVCap@@", .required = false},
        Rtti::Landmark{.base = base, .nominal_offset = FP_OB, .expected_mangled = ".?AVCap@@", .required = false},
    };
    EXPECT_EQ(Rtti::solve_fingerprint(base, all_optional, 0x20).error(), Rtti::HealError::BadDescriptor);
}

// --- heal_report (drift telemetry) ---

TEST_F(RttiDissectTest, HealReport_RecordsNoDriftAndPositiveDrift)
{
    SyntheticVtable a(".?AVReportA@@");
    SyntheticVtable b(".?AVReportB@@");
    SynStruct st;
    const std::size_t off_a = 0x40;
    const std::size_t off_b = 0x80;
    st.put(off_a, syn_heap_object(a.vtable()));        // stays put: delta 0
    st.put(off_b + 0x10, syn_heap_object(b.vtable())); // drifted +0x10

    const Rtti::Landmark lms[] = {
        {.base = st.base(), .nominal_offset = static_cast<std::ptrdiff_t>(off_a), .expected_mangled = ".?AVReportA@@"},
        {.base = st.base(), .nominal_offset = static_cast<std::ptrdiff_t>(off_b), .expected_mangled = ".?AVReportB@@"},
    };

    Rtti::DriftEntry report[2];
    const std::size_t n = Rtti::heal_report(lms, report);
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
    const Rtti::Landmark lms[] = {
        {.base = st.base(), .nominal_offset = 0x40, .expected_mangled = ".?AVReportMissing@@"},
    };

    // Pre-seed the output with stale values to prove a failed entry is reset and never exposes a reused buffer's prior
    // contents.
    Rtti::DriftEntry report[1];
    report[0].healed_offset = 0x7777;
    report[0].delta = 0x1234;
    report[0].ok = true;

    const std::size_t n = Rtti::heal_report(lms, report);
    ASSERT_EQ(n, 1u);
    EXPECT_FALSE(report[0].ok);
    EXPECT_EQ(report[0].error, Rtti::HealError::NoMatch);
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

    const Rtti::Landmark lms[] = {
        {.base = st.base(), .nominal_offset = 0x40, .expected_mangled = ".?AVCapReport@@"},
        {.base = st.base(), .nominal_offset = 0x40, .expected_mangled = ".?AVCapReport@@"},
        {.base = st.base(), .nominal_offset = 0x40, .expected_mangled = ".?AVCapReport@@"},
    };

    Rtti::DriftEntry report[2]; // smaller than the landmark set
    const std::size_t n = Rtti::heal_report(lms, report);
    EXPECT_EQ(n, 2u); // min(landmarks.size(), out.size())

    // The written entries must be real heals, not just a returned count.
    EXPECT_TRUE(report[0].ok);
    EXPECT_TRUE(report[1].ok);
    EXPECT_EQ(report[0].name, ".?AVCapReport@@");
}
