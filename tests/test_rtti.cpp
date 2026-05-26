#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"

namespace Memory = DetourModKit::Memory;
namespace Rtti = DetourModKit::Rtti;

namespace
{
    // Per-fixture layout offsets shared by every SyntheticVtable instance.
    // Picked so the COL, TypeDescriptor, and vtable storage live well apart
    // from each other and from 4 KiB page boundaries.
    constexpr std::size_t SYN_BUF_SIZE = 4096;
    constexpr std::size_t SYN_COL_OFFSET = 256;
    constexpr std::size_t SYN_TD_OFFSET = SYN_COL_OFFSET + 24; // COL is 24 bytes
    constexpr std::size_t SYN_TD_NAME_OFFSET = SYN_TD_OFFSET + 16;
    constexpr std::size_t SYN_COL_PTR_OFFSET = 2048;
    constexpr std::size_t SYN_VTABLE_OFFSET = SYN_COL_PTR_OFFSET + 8;

    // Static buffer pool for SyntheticVtable storage. Living in the test
    // executable's data segment ensures Memory::module_range_for resolves
    // every synthetic address back to the test exe's PE range, which is
    // required by the RTTI walker's bound-check guard. The pool is sized
    // for up to 16 fixtures per test; RttiTest::SetUp resets the offset
    // between tests so the pool never grows unbounded.
    constexpr std::size_t SYN_POOL_FIXTURES = 16;
    constexpr std::size_t SYN_POOL_SIZE = SYN_BUF_SIZE * SYN_POOL_FIXTURES;
    alignas(8) std::array<std::byte, SYN_POOL_SIZE> g_syn_pool{};
    std::size_t g_syn_offset = 0;

    [[nodiscard]] std::byte *syn_alloc() noexcept
    {
        if (g_syn_offset + SYN_BUF_SIZE > g_syn_pool.size())
            return nullptr;
        std::byte *p = g_syn_pool.data() + g_syn_offset;
        g_syn_offset += SYN_BUF_SIZE;
        std::memset(p, 0, SYN_BUF_SIZE);
        return p;
    }

    void syn_reset() noexcept { g_syn_offset = 0; }

    /**
     * @class SyntheticVtable
     * @brief In-memory MSVC x64 RTTI layout for testing Rtti primitives.
     * @details Builds a buffer (allocated from a process-wide pool that
     *          lives in the test executable's data segment) that exposes
     *          the same shape the Rtti walker expects against a real game
     *          image: a vtable whose qword at offset -8 points to an
     *          RTTICompleteObjectLocator whose pTypeDescriptor RVA leads
     *          to a TypeDescriptor whose name field contains the requested
     *          mangled string. RVAs are computed relative to the test
     *          executable's image base so the walker's bound-check guard
     *          (module_range_for + contains) accepts them.
     */
    class SyntheticVtable
    {
    public:
        explicit SyntheticVtable(std::string_view mangled_name)
        {
            m_buf = syn_alloc();
            // syn_alloc returns nullptr when the pool is exhausted. Use
            // gtest assertion machinery so a test that overflows the pool
            // fails loudly instead of silently constructing a malformed
            // fixture.
            EXPECT_NE(m_buf, nullptr) << "SyntheticVtable pool exhausted; raise SYN_POOL_FIXTURES";
            if (!m_buf)
                return;

            const HMODULE exe = GetModuleHandleW(nullptr);
            EXPECT_NE(exe, nullptr);
            const std::uintptr_t exe_base = reinterpret_cast<std::uintptr_t>(exe);
            const std::uintptr_t buf_base = reinterpret_cast<std::uintptr_t>(m_buf);

            // The pool is a static in the test exe, so buf_base lies inside
            // the test exe's PE image and the offset fits in a 32-bit RVA.
            EXPECT_GE(buf_base, exe_base);
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

            // TypeDescriptor: pVFTable (8) + spare (8) + zero-terminated
            // mangled name. The name length is bounded by the available
            // space between SYN_TD_NAME_OFFSET and SYN_COL_PTR_OFFSET so
            // it cannot overrun the buffer.
            const std::size_t max_name = SYN_COL_PTR_OFFSET - SYN_TD_NAME_OFFSET - 1;
            const std::size_t name_len = std::min(mangled_name.size(), max_name);
            std::memcpy(m_buf + SYN_TD_NAME_OFFSET, mangled_name.data(), name_len);
            m_buf[SYN_TD_NAME_OFFSET + name_len] = std::byte{0};

            // COL pointer at vtable - 8.
            const std::uintptr_t col_addr = buf_base + SYN_COL_OFFSET;
            write_at(SYN_COL_PTR_OFFSET, col_addr);

            m_vtable_addr = buf_base + SYN_VTABLE_OFFSET;
        }

        SyntheticVtable(const SyntheticVtable &) = delete;
        SyntheticVtable &operator=(const SyntheticVtable &) = delete;

        [[nodiscard]] std::uintptr_t vtable() const noexcept { return m_vtable_addr; }

        /// Overwrites COL.p_type_descriptor with @p rva for poisoned-input tests.
        void poison_type_descriptor_rva(std::uint32_t rva) noexcept
        {
            write_at(SYN_COL_OFFSET + 12, rva);
        }

        /// Overwrites COL.p_self with @p rva for poisoned-input tests.
        void poison_self_rva(std::uint32_t rva) noexcept
        {
            write_at(SYN_COL_OFFSET + 20, rva);
        }

    private:
        template <typename T>
        void write_at(std::size_t offset, const T &value) noexcept
        {
            static_assert(std::is_trivially_copyable_v<T>);
            std::memcpy(m_buf + offset, &value, sizeof(T));
        }

        std::byte *m_buf = nullptr;
        std::uintptr_t m_vtable_addr = 0;
    };

    /**
     * @class SyntheticObject
     * @brief An object whose first qword is a synthetic vtable address.
     * @details Mimics a real polymorphic instance for find_in_pointer_table
     *          tests: the object's first qword is read as the vtable
     *          pointer, which then drives the RTTI walk through
     *          SyntheticVtable.
     */
    class SyntheticObject
    {
    public:
        explicit SyntheticObject(std::uintptr_t vtable_addr) noexcept
            : m_vtable(vtable_addr)
        {
        }

        [[nodiscard]] std::uintptr_t address() const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(this);
        }

    private:
        std::uintptr_t m_vtable;
    };
}

class RttiTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        (void)Memory::init_cache();
        syn_reset();
    }
    void TearDown() override { Memory::shutdown_cache(); }
};

// --- type_name_of ---

TEST_F(RttiTest, TypeNameOf_BasicSyntheticName)
{
    SyntheticVtable v(".?AVMyClass@ns@@");
    auto name = Rtti::type_name_of(v.vtable());
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(*name, ".?AVMyClass@ns@@");
}

TEST_F(RttiTest, TypeNameOf_EmptyName)
{
    SyntheticVtable v("");
    auto name = Rtti::type_name_of(v.vtable());
    // An empty name is a zero-byte read; read_name_seh returns 0 written.
    EXPECT_FALSE(name.has_value());
}

TEST_F(RttiTest, TypeNameOf_LongName)
{
    const std::string long_name(200, 'A');
    SyntheticVtable v(long_name);
    auto name = Rtti::type_name_of(v.vtable());
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(*name, long_name);
}

TEST_F(RttiTest, TypeNameOf_TruncatesAtMaxLen)
{
    const std::string long_name(300, 'B');
    SyntheticVtable v(long_name);
    auto name = Rtti::type_name_of(v.vtable(), 64);
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(name->size(), 64u);
    EXPECT_EQ(*name, std::string(64, 'B'));
}

TEST_F(RttiTest, TypeNameOf_NullVtableRejected)
{
    EXPECT_FALSE(Rtti::type_name_of(0).has_value());
}

TEST_F(RttiTest, TypeNameOf_LowVtableRejected)
{
    EXPECT_FALSE(Rtti::type_name_of(0x100).has_value());
}

TEST_F(RttiTest, TypeNameOf_ZeroMaxLenUsesDefault)
{
    SyntheticVtable v(".?AVDefaultLen@@");
    auto name = Rtti::type_name_of(v.vtable(), 0);
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(*name, ".?AVDefaultLen@@");
}

// --- type_name_into ---

TEST_F(RttiTest, TypeNameInto_WritesNulTerminatedName)
{
    SyntheticVtable v(".?AVBuffer@@");
    char out[64] = {0};
    const std::size_t written = Rtti::type_name_into(v.vtable(), out, sizeof(out));
    EXPECT_EQ(written, 12u);
    EXPECT_STREQ(out, ".?AVBuffer@@");
}

TEST_F(RttiTest, TypeNameInto_NullBufferReturnsZero)
{
    SyntheticVtable v(".?AVNullBuf@@");
    EXPECT_EQ(Rtti::type_name_into(v.vtable(), nullptr, 64), 0u);
}

TEST_F(RttiTest, TypeNameInto_ZeroLenReturnsZero)
{
    SyntheticVtable v(".?AVZeroLen@@");
    char out[1] = {'X'};
    EXPECT_EQ(Rtti::type_name_into(v.vtable(), out, 0), 0u);
    EXPECT_EQ(out[0], 'X');
}

TEST_F(RttiTest, TypeNameInto_TruncatesAndNulTerminates)
{
    SyntheticVtable v("ABCDEFGH");
    char out[5] = {0};
    const std::size_t written = Rtti::type_name_into(v.vtable(), out, sizeof(out));
    EXPECT_EQ(written, 4u);
    EXPECT_STREQ(out, "ABCD");
}

TEST_F(RttiTest, TypeNameInto_FailureClearsBuffer)
{
    char out[16];
    std::memset(out, 'Z', sizeof(out));
    EXPECT_EQ(Rtti::type_name_into(0, out, sizeof(out)), 0u);
    EXPECT_EQ(out[0], '\0');
}

// --- vtable_is_type ---

TEST_F(RttiTest, VtableIsType_ExactMatch)
{
    SyntheticVtable v(".?AVExact@@");
    EXPECT_TRUE(Rtti::vtable_is_type(v.vtable(), ".?AVExact@@"));
}

TEST_F(RttiTest, VtableIsType_MismatchReturnsFalse)
{
    SyntheticVtable v(".?AVOne@@");
    EXPECT_FALSE(Rtti::vtable_is_type(v.vtable(), ".?AVTwo@@"));
}

TEST_F(RttiTest, VtableIsType_RejectsProperPrefix)
{
    SyntheticVtable v(".?AVFullName@@");
    EXPECT_FALSE(Rtti::vtable_is_type(v.vtable(), ".?AVFull"));
}

TEST_F(RttiTest, VtableIsType_RejectsProperSuffix)
{
    SyntheticVtable v(".?AVMyClass@@");
    EXPECT_FALSE(Rtti::vtable_is_type(v.vtable(), "MyClass@@"));
}

TEST_F(RttiTest, VtableIsType_EmptyExpectedRejected)
{
    SyntheticVtable v(".?AVSomething@@");
    EXPECT_FALSE(Rtti::vtable_is_type(v.vtable(), ""));
}

TEST_F(RttiTest, VtableIsType_NullVtableRejected)
{
    EXPECT_FALSE(Rtti::vtable_is_type(0, ".?AVAnything@@"));
}

TEST_F(RttiTest, VtableIsType_LowVtableRejected)
{
    EXPECT_FALSE(Rtti::vtable_is_type(0x100, ".?AVAnything@@"));
}

TEST_F(RttiTest, VtableIsType_OversizedExpectedRejected)
{
    SyntheticVtable v(".?AVSize@@");
    const std::string huge(Rtti::MAX_TYPE_NAME_LEN + 1, 'X');
    EXPECT_FALSE(Rtti::vtable_is_type(v.vtable(), huge));
}

// --- find_in_pointer_table ---

TEST_F(RttiTest, FindInTable_HitsFirstMatchingSlot)
{
    SyntheticVtable target(".?AVTarget@@");
    SyntheticVtable other(".?AVOther@@");

    SyntheticObject obj_other_a(other.vtable());
    SyntheticObject obj_target(target.vtable());
    SyntheticObject obj_other_b(other.vtable());

    std::array<std::uintptr_t, 3> table{
        obj_other_a.address(),
        obj_target.address(),
        obj_other_b.address(),
    };

    auto hit = Rtti::find_in_pointer_table(
        reinterpret_cast<std::uintptr_t>(table.data()),
        table.size(),
        ".?AVTarget@@");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, obj_target.address());
}

TEST_F(RttiTest, FindInTable_NoMatchReturnsNullopt)
{
    SyntheticVtable other(".?AVOther@@");
    SyntheticObject obj_a(other.vtable());
    SyntheticObject obj_b(other.vtable());

    std::array<std::uintptr_t, 2> table{obj_a.address(), obj_b.address()};

    auto hit = Rtti::find_in_pointer_table(
        reinterpret_cast<std::uintptr_t>(table.data()),
        table.size(),
        ".?AVMissing@@");
    EXPECT_FALSE(hit.has_value());
}

TEST_F(RttiTest, FindInTable_SkipsNullSlots)
{
    SyntheticVtable target(".?AVNullSkip@@");
    SyntheticObject obj(target.vtable());

    std::array<std::uintptr_t, 4> table{0, 0, obj.address(), 0};

    auto hit = Rtti::find_in_pointer_table(
        reinterpret_cast<std::uintptr_t>(table.data()),
        table.size(),
        ".?AVNullSkip@@");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, obj.address());
}

TEST_F(RttiTest, FindInTable_SkipsLowAddressSlots)
{
    SyntheticVtable target(".?AVLowSkip@@");
    SyntheticObject obj(target.vtable());

    std::array<std::uintptr_t, 3> table{0x100, 0x200, obj.address()};

    auto hit = Rtti::find_in_pointer_table(
        reinterpret_cast<std::uintptr_t>(table.data()),
        table.size(),
        ".?AVLowSkip@@");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, obj.address());
}

TEST_F(RttiTest, FindInTable_CachePopulatedOnFirstHit)
{
    SyntheticVtable target(".?AVCacheTest@@");
    SyntheticObject obj(target.vtable());

    std::array<std::uintptr_t, 1> table{obj.address()};

    std::atomic<std::uintptr_t> cache{0};
    auto hit = Rtti::find_in_pointer_table(
        reinterpret_cast<std::uintptr_t>(table.data()),
        table.size(),
        ".?AVCacheTest@@",
        &cache);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(cache.load(), target.vtable());
}

TEST_F(RttiTest, FindInTable_WarmCacheSkipsRttiWalk)
{
    SyntheticVtable target(".?AVWarm@@");
    SyntheticVtable other(".?AVOther@@");
    SyntheticObject obj_other(other.vtable());
    SyntheticObject obj_target(target.vtable());

    std::array<std::uintptr_t, 2> table{obj_other.address(), obj_target.address()};

    // Pre-seed the cache with the target vtable; the warm path is now active.
    std::atomic<std::uintptr_t> cache{target.vtable()};
    auto hit = Rtti::find_in_pointer_table(
        reinterpret_cast<std::uintptr_t>(table.data()),
        table.size(),
        ".?AVWarm@@",
        &cache);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, obj_target.address());
}

TEST_F(RttiTest, FindInTable_WarmCacheRejectsForeignVtables)
{
    SyntheticVtable wrong(".?AVWrong@@");
    SyntheticObject obj(wrong.vtable());

    std::array<std::uintptr_t, 1> table{obj.address()};

    // Cache points at an entirely unrelated vtable address. The single slot
    // does not match the cached vtable, so the warm path returns nullopt
    // without ever invoking the RTTI walker.
    std::atomic<std::uintptr_t> cache{0xDEADBEEFCAFEULL};
    auto hit = Rtti::find_in_pointer_table(
        reinterpret_cast<std::uintptr_t>(table.data()),
        table.size(),
        ".?AVWrong@@",
        &cache);
    EXPECT_FALSE(hit.has_value());
}

TEST_F(RttiTest, FindInTable_NullTableRejected)
{
    EXPECT_FALSE(Rtti::find_in_pointer_table(0, 4, ".?AVNull@@").has_value());
}

TEST_F(RttiTest, FindInTable_ZeroSlotsRejected)
{
    SyntheticVtable v(".?AVZero@@");
    SyntheticObject obj(v.vtable());
    std::array<std::uintptr_t, 1> table{obj.address()};

    EXPECT_FALSE(Rtti::find_in_pointer_table(
                     reinterpret_cast<std::uintptr_t>(table.data()), 0, ".?AVZero@@")
                     .has_value());
}

TEST_F(RttiTest, FindInTable_EmptyExpectedRejected)
{
    SyntheticVtable v(".?AVEmpty@@");
    SyntheticObject obj(v.vtable());
    std::array<std::uintptr_t, 1> table{obj.address()};

    EXPECT_FALSE(Rtti::find_in_pointer_table(
                     reinterpret_cast<std::uintptr_t>(table.data()), table.size(), "")
                     .has_value());
}

TEST_F(RttiTest, FindInTable_CustomStrideSkipsInterleavedMetadata)
{
    SyntheticVtable target(".?AVStride@@");
    SyntheticObject obj(target.vtable());

    // Table is { ptr, metadata, ptr, metadata, ... }; stride is 16 bytes
    // and only every other qword is a real object pointer.
    std::array<std::uintptr_t, 4> table{obj.address(), 0xAAAAAAAAu, obj.address(), 0xBBBBBBBBu};

    auto hit = Rtti::find_in_pointer_table(
        reinterpret_cast<std::uintptr_t>(table.data()),
        2,
        ".?AVStride@@",
        nullptr,
        16);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, obj.address());
}

TEST_F(RttiTest, FindInTable_ZeroStrideDefaultsToQword)
{
    SyntheticVtable target(".?AVZeroStride@@");
    SyntheticObject obj(target.vtable());

    std::array<std::uintptr_t, 1> table{obj.address()};

    auto hit = Rtti::find_in_pointer_table(
        reinterpret_cast<std::uintptr_t>(table.data()),
        table.size(),
        ".?AVZeroStride@@",
        nullptr,
        0);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, obj.address());
}

TEST_F(RttiTest, FindInTable_OverflowingRangeRejected)
{
    // (table + slot_count * stride) wraps; should be treated as invalid.
    EXPECT_FALSE(Rtti::find_in_pointer_table(
                     UINTPTR_MAX - 8, 4, ".?AVAnything@@", nullptr, 16)
                     .has_value());
}

// --- Bound-check guards against poisoned RTTI fields ---

TEST_F(RttiTest, ResolveRejectsPoisonedTypeDescriptorRva)
{
    // A bogus type-descriptor RVA places the computed name buffer outside
    // the test executable's module range; the walker must reject the read
    // rather than dereference whatever address the bogus RVA produces.
    SyntheticVtable v(".?AVValid@@");
    v.poison_type_descriptor_rva(0x7FFFFFFFu);

    EXPECT_FALSE(Rtti::type_name_of(v.vtable()).has_value());
    EXPECT_FALSE(Rtti::vtable_is_type(v.vtable(), ".?AVValid@@"));

    char buf[64];
    std::memset(buf, 'Z', sizeof(buf));
    EXPECT_EQ(Rtti::type_name_into(v.vtable(), buf, sizeof(buf)), 0u);
    EXPECT_EQ(buf[0], '\0');
}

TEST_F(RttiTest, ResolveRejectsPoisonedSelfRva)
{
    // A bogus pSelf recovers an image base that does not match the
    // loader-reported module base; the walker must reject rather than
    // trust the recovered base. self_rva == 1 makes
    // recovered = col_addr - 1, which never equals mod_range.base.
    SyntheticVtable v(".?AVValid@@");
    v.poison_self_rva(1);

    EXPECT_FALSE(Rtti::type_name_of(v.vtable()).has_value());
    EXPECT_FALSE(Rtti::vtable_is_type(v.vtable(), ".?AVValid@@"));
}

TEST_F(RttiTest, ResolveRejectsHeapAllocatedVtable)
{
    // A vtable whose address is not in any loaded module (here, a heap
    // allocation) must be rejected at the module_range_for step.
    auto buf = std::make_unique<std::array<std::uintptr_t, 4>>();
    (*buf)[0] = 0; (*buf)[1] = 0; (*buf)[2] = 0; (*buf)[3] = 0;
    const std::uintptr_t fake_vt = reinterpret_cast<std::uintptr_t>(buf->data() + 2);

    EXPECT_FALSE(Rtti::type_name_of(fake_vt).has_value());
    EXPECT_FALSE(Rtti::vtable_is_type(fake_vt, ".?AVAnything@@"));
}

// --- Default values / constants ---

TEST(RttiConstantsTest, Defaults)
{
    static_assert(Rtti::DEFAULT_TYPE_NAME_MAX > 0);
    static_assert(Rtti::MAX_TYPE_NAME_LEN > Rtti::DEFAULT_TYPE_NAME_MAX);
}
