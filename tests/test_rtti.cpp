#include <gtest/gtest.h>

#include <algorithm>
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

#include "internal/rtti_shared.hpp"

namespace memory = DetourModKit::memory;
namespace rtti = DetourModKit::rtti;
using DetourModKit::Address;

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    extern std::uint64_t (*g_rtti_image_generation_override)(std::uintptr_t address) noexcept;
#endif
} // namespace DetourModKit::detail

namespace
{
    // Per-fixture layout offsets shared by every SyntheticVtable instance. Picked so the COL, TypeDescriptor, and
    // vtable storage live well apart from each other and from 4 KiB page boundaries.
    constexpr std::size_t SYN_BUF_SIZE = 4096;
    constexpr std::size_t SYN_COL_OFFSET = 256;
    constexpr std::size_t SYN_TD_OFFSET = SYN_COL_OFFSET + 24; // COL is 24 bytes
    constexpr std::size_t SYN_TD_NAME_OFFSET = SYN_TD_OFFSET + 16;
    constexpr std::size_t SYN_COL_PTR_OFFSET = 2048;
    constexpr std::size_t SYN_VTABLE_OFFSET = SYN_COL_PTR_OFFSET + 8;

    // Static buffer pool for SyntheticVtable storage. Living in the test executable's data segment ensures
    // memory::module_of resolves every synthetic address back to the test exe's PE range, which is required by
    // the RTTI walker's bound-check guard. The pool is sized for up to 16 fixtures per test; RttiTest::SetUp resets the
    // offset between tests so the pool never grows unbounded.
    constexpr std::size_t SYN_POOL_FIXTURES = 16;
    constexpr std::size_t SYN_POOL_SIZE = SYN_BUF_SIZE * SYN_POOL_FIXTURES;
    alignas(8) std::array<std::byte, SYN_POOL_SIZE> s_syn_pool{};
    std::size_t s_syn_offset = 0;

    [[nodiscard]] std::byte *syn_alloc() noexcept
    {
        if (s_syn_offset + SYN_BUF_SIZE > s_syn_pool.size())
            return nullptr;
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
     * @brief In-memory MSVC x64 RTTI layout for testing Rtti primitives.
     * @details Builds a buffer (allocated from a process-wide pool that lives in the test executable's data segment)
     *          that exposes the same shape the Rtti walker expects against a real game
     *          image: a vtable whose qword at offset -8 points to an
     *          RTTICompleteObjectLocator whose pTypeDescriptor RVA leads to a TypeDescriptor whose name field contains
     *          the requested mangled string. RVAs are computed relative to the test executable's image base so the
     *          walker's bound-check guard (module_range_for + contains) accepts them.
     */
    class SyntheticVtable
    {
    public:
        explicit SyntheticVtable(std::string_view mangled_name)
        {
            m_buf = syn_alloc();
            // syn_alloc returns nullptr when the pool is exhausted. Use gtest assertion machinery so a test that
            // overflows the pool fails loudly instead of silently constructing a malformed fixture.
            EXPECT_NE(m_buf, nullptr) << "SyntheticVtable pool exhausted; raise SYN_POOL_FIXTURES";
            if (!m_buf)
                return;

            const HMODULE exe = GetModuleHandleW(nullptr);
            EXPECT_NE(exe, nullptr);
            const std::uintptr_t exe_base = reinterpret_cast<std::uintptr_t>(exe);
            const std::uintptr_t buf_base = reinterpret_cast<std::uintptr_t>(m_buf);

            // The pool is a static in the test exe, so buf_base lies inside the test exe's PE image and the offset fits
            // in a 32-bit RVA.
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
            // mangled name. The name length is bounded by the available space between SYN_TD_NAME_OFFSET and
            // SYN_COL_PTR_OFFSET so it cannot overrun the buffer.
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
        void poison_type_descriptor_rva(std::uint32_t rva) noexcept { write_at(SYN_COL_OFFSET + 12, rva); }

        /// Overwrites COL.p_self with @p rva for poisoned-input tests.
        void poison_self_rva(std::uint32_t rva) noexcept { write_at(SYN_COL_OFFSET + 20, rva); }

        /// Replaces the name prefix with nonzero bytes and omits a terminator for the requested span.
        void make_name_non_terminated(std::size_t span) noexcept
        {
            const std::size_t capacity = SYN_COL_PTR_OFFSET - SYN_TD_NAME_OFFSET;
            std::memset(m_buf + SYN_TD_NAME_OFFSET, 'X', std::min(span, capacity));
        }

        void overwrite_name(std::string_view name) noexcept
        {
            const std::size_t capacity = SYN_COL_PTR_OFFSET - SYN_TD_NAME_OFFSET;
            std::memset(m_buf + SYN_TD_NAME_OFFSET, 0, capacity);
            std::memcpy(m_buf + SYN_TD_NAME_OFFSET, name.data(), std::min(name.size(), capacity - 1));
        }

    private:
        template <typename T> void write_at(std::size_t offset, const T &value) noexcept
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
        explicit SyntheticObject(std::uintptr_t vtable_addr) noexcept : m_vtable(vtable_addr) {}

        [[nodiscard]] std::uintptr_t address() const noexcept { return reinterpret_cast<std::uintptr_t>(this); }

    private:
        std::uintptr_t m_vtable;
    };

#if defined(DMK_ENABLE_TEST_SEAMS)
    std::atomic<std::uint64_t> s_pointer_image_generation{0};

    std::uint64_t pointer_image_generation(std::uintptr_t) noexcept
    {
        return s_pointer_image_generation.load(std::memory_order_relaxed);
    }

    class ScopedPointerImageGeneration
    {
    public:
        explicit ScopedPointerImageGeneration(std::uint64_t generation) noexcept
        {
            set(generation);
            DetourModKit::detail::g_rtti_image_generation_override = &pointer_image_generation;
        }
        ~ScopedPointerImageGeneration() noexcept { DetourModKit::detail::g_rtti_image_generation_override = nullptr; }
        void set(std::uint64_t generation) noexcept
        {
            s_pointer_image_generation.store(generation, std::memory_order_relaxed);
        }
        ScopedPointerImageGeneration(const ScopedPointerImageGeneration &) = delete;
        ScopedPointerImageGeneration &operator=(const ScopedPointerImageGeneration &) = delete;
    };
#endif
} // anonymous namespace

class RttiTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        (void)memory::init_cache();
        syn_reset();
    }
    void TearDown() override { memory::shutdown_cache(); }
};

// type_name_of

TEST_F(RttiTest, TypeNameOf_BasicSyntheticName)
{
    SyntheticVtable v(".?AVMyClass@ns@@");
    auto name = rtti::type_name_of(Address{v.vtable()});
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(*name, ".?AVMyClass@ns@@");
}

TEST_F(RttiTest, TypeNameOf_EmptyName)
{
    SyntheticVtable v("");
    auto name = rtti::type_name_of(Address{v.vtable()});
    // An empty name is a zero-byte read; read_name_seh returns 0 written.
    EXPECT_FALSE(name.has_value());
}

TEST_F(RttiTest, TypeNameOf_LongName)
{
    const std::string long_name(200, 'A');
    SyntheticVtable v(long_name);
    auto name = rtti::type_name_of(Address{v.vtable()});
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(*name, long_name);
}

TEST_F(RttiTest, TypeNameOf_TruncatesAtMaxLen)
{
    const std::string long_name(300, 'B');
    SyntheticVtable v(long_name);
    auto name = rtti::type_name_of(Address{v.vtable()}, 64);
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(name->size(), 64u);
    EXPECT_EQ(*name, std::string(64, 'B'));
}

// read_name_seh must clamp the name copy to the owning module's end so a mangled name that lacks a NUL before the
// module boundary (a forged or edge-of-module TypeDescriptor) is truncated at the boundary rather than read forward
// into an adjacent mapped image (which would surface another module's bytes as a confident type name). This drives the
// internal helper directly with an injected module_end because a synthetic vtable always resolves mid-module, so the
// boundary geometry cannot be built through the public API.
TEST_F(RttiTest, ReadNameSehClampsToModuleEnd)
{
    // Eight 'A's followed by a NUL; the rest of the (zero-initialized) buffer is readable so an unclamped read would
    // reach the terminator at offset 8.
    static char buffer[64];
    std::memset(buffer, 0, sizeof(buffer));
    std::memset(buffer, 'A', 8);
    const auto addr = reinterpret_cast<std::uintptr_t>(buffer);

    // A module_end at addr + 4 forces the copy to stop at 4 bytes, before the NUL at offset 8.
    char clamped_out[64] = {};
    const std::size_t clamped = rtti::detail::read_name_seh(addr, clamped_out, sizeof(clamped_out), addr + 4);
    EXPECT_EQ(clamped, 4u) << "the read must stop at module_end, not run forward to the terminator";
    EXPECT_EQ(std::string_view(clamped_out, clamped), "AAAA");

    // A module_end well past the terminator reads the whole NUL-terminated name (8 bytes), proving the clamp only
    // binds at the boundary and does not truncate an in-module name.
    char full_out[64] = {};
    const std::size_t full = rtti::detail::read_name_seh(addr, full_out, sizeof(full_out), addr + sizeof(buffer));
    EXPECT_EQ(full, 8u);
    EXPECT_EQ(std::string_view(full_out, full), "AAAAAAAA");

    // A zero module_end means "no bound supplied": only the length caps apply, so the full name is read.
    char unbounded_out[64] = {};
    const std::size_t unbounded = rtti::detail::read_name_seh(addr, unbounded_out, sizeof(unbounded_out), 0);
    EXPECT_EQ(unbounded, 8u);

    // A nonzero module_end at or below the name address is a degenerate/forged bound (no in-module byte); fail closed.
    char invalid_bound_out[64] = {};
    const std::size_t invalid_bound =
        rtti::detail::read_name_seh(addr, invalid_bound_out, sizeof(invalid_bound_out), addr);
    EXPECT_EQ(invalid_bound, 0u);
}

TEST_F(RttiTest, TypeNameOf_NullVtableRejected)
{
    EXPECT_FALSE(rtti::type_name_of(Address{}).has_value());
}

TEST_F(RttiTest, TypeNameOf_LowVtableRejected)
{
    EXPECT_FALSE(rtti::type_name_of(Address{0x100}).has_value());
}

TEST_F(RttiTest, TypeNameOf_ZeroMaxLenUsesDefault)
{
    SyntheticVtable v(".?AVDefaultLen@@");
    auto name = rtti::type_name_of(Address{v.vtable()}, 0);
    ASSERT_TRUE(name.has_value());
    EXPECT_EQ(*name, ".?AVDefaultLen@@");
}

// type_name_into

TEST_F(RttiTest, TypeNameInto_WritesNulTerminatedName)
{
    SyntheticVtable v(".?AVBuffer@@");
    char out[64] = {0};
    const std::size_t written = rtti::type_name_into(Address{v.vtable()}, out, sizeof(out));
    EXPECT_EQ(written, 12u);
    EXPECT_STREQ(out, ".?AVBuffer@@");
}

TEST_F(RttiTest, TypeNameInto_NullBufferReturnsZero)
{
    SyntheticVtable v(".?AVNullBuf@@");
    EXPECT_EQ(rtti::type_name_into(Address{v.vtable()}, nullptr, 64), 0u);
}

TEST_F(RttiTest, TypeNameInto_ZeroLenReturnsZero)
{
    SyntheticVtable v(".?AVZeroLen@@");
    char out[1] = {'X'};
    EXPECT_EQ(rtti::type_name_into(Address{v.vtable()}, out, 0), 0u);
    EXPECT_EQ(out[0], 'X');
}

TEST_F(RttiTest, TypeNameInto_TruncatesAndNulTerminates)
{
    SyntheticVtable v("ABCDEFGH");
    char out[5] = {0};
    const std::size_t written = rtti::type_name_into(Address{v.vtable()}, out, sizeof(out));
    EXPECT_EQ(written, 4u);
    EXPECT_STREQ(out, "ABCD");
}

TEST_F(RttiTest, TypeNameInto_FailureClearsBuffer)
{
    char out[16];
    std::memset(out, 'Z', sizeof(out));
    EXPECT_EQ(rtti::type_name_into(Address{}, out, sizeof(out)), 0u);
    EXPECT_EQ(out[0], '\0');
}

// vtable_is_type

TEST_F(RttiTest, VtableIsType_ExactMatch)
{
    SyntheticVtable v(".?AVExact@@");
    EXPECT_TRUE(rtti::vtable_is_type(Address{v.vtable()}, ".?AVExact@@"));
}

TEST_F(RttiTest, VtableIsType_MismatchReturnsFalse)
{
    SyntheticVtable v(".?AVOne@@");
    EXPECT_FALSE(rtti::vtable_is_type(Address{v.vtable()}, ".?AVTwo@@"));
}

TEST_F(RttiTest, VtableIsType_RejectsProperPrefix)
{
    SyntheticVtable v(".?AVFullName@@");
    EXPECT_FALSE(rtti::vtable_is_type(Address{v.vtable()}, ".?AVFull"));
}

TEST_F(RttiTest, VtableIsType_RejectsProperSuffix)
{
    SyntheticVtable v(".?AVMyClass@@");
    EXPECT_FALSE(rtti::vtable_is_type(Address{v.vtable()}, "MyClass@@"));
}

TEST_F(RttiTest, VtableIsType_EmptyExpectedRejected)
{
    SyntheticVtable v(".?AVSomething@@");
    EXPECT_FALSE(rtti::vtable_is_type(Address{v.vtable()}, ""));
}

TEST_F(RttiTest, VtableIsType_NullVtableRejected)
{
    EXPECT_FALSE(rtti::vtable_is_type(Address{}, ".?AVAnything@@"));
}

TEST_F(RttiTest, VtableIsType_LowVtableRejected)
{
    EXPECT_FALSE(rtti::vtable_is_type(Address{0x100}, ".?AVAnything@@"));
}

TEST_F(RttiTest, VtableIsType_OversizedExpectedRejected)
{
    SyntheticVtable v(".?AVSize@@");
    const std::string huge(rtti::MAX_TYPE_NAME_LEN + 1, 'X');
    EXPECT_FALSE(rtti::vtable_is_type(Address{v.vtable()}, huge));
}

// find_in_pointer_table

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

    auto hit = rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                           ".?AVTarget@@");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->raw(), obj_target.address());
}

TEST_F(RttiTest, FindInTable_NoMatchReturnsNullopt)
{
    SyntheticVtable other(".?AVOther@@");
    SyntheticObject obj_a(other.vtable());
    SyntheticObject obj_b(other.vtable());

    std::array<std::uintptr_t, 2> table{obj_a.address(), obj_b.address()};

    auto hit = rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                           ".?AVMissing@@");
    EXPECT_FALSE(hit.has_value());
}

TEST_F(RttiTest, FindInTable_SkipsNullSlots)
{
    SyntheticVtable target(".?AVNullSkip@@");
    SyntheticObject obj(target.vtable());

    std::array<std::uintptr_t, 4> table{0, 0, obj.address(), 0};

    auto hit = rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                           ".?AVNullSkip@@");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->raw(), obj.address());
}

TEST_F(RttiTest, FindInTable_SkipsLowAddressSlots)
{
    SyntheticVtable target(".?AVLowSkip@@");
    SyntheticObject obj(target.vtable());

    std::array<std::uintptr_t, 3> table{0x100, 0x200, obj.address()};

    auto hit = rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                           ".?AVLowSkip@@");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->raw(), obj.address());
}

TEST_F(RttiTest, FindInTable_CachePopulatedOnFirstHit)
{
    SyntheticVtable target(".?AVCacheTest@@");
    SyntheticObject obj(target.vtable());

    std::array<std::uintptr_t, 1> table{obj.address()};

    std::atomic<Address> cache{Address{}};
    auto hit = rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                           ".?AVCacheTest@@", &cache);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(cache.load().raw(), target.vtable());
}

TEST_F(RttiTest, FindInTable_WarmCacheSkipsRttiWalk)
{
    SyntheticVtable target(".?AVWarm@@");
    SyntheticVtable other(".?AVOther@@");
    SyntheticObject obj_other(other.vtable());
    SyntheticObject obj_target(target.vtable());

    std::array<std::uintptr_t, 2> table{obj_other.address(), obj_target.address()};

    // Pre-seed the cache with the target vtable; the warm path is now active.
    std::atomic<Address> cache{Address{target.vtable()}};
    auto hit = rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                           ".?AVWarm@@", &cache);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->raw(), obj_target.address());
}

TEST_F(RttiTest, FindInTable_StaleWarmCacheFallsBackAndRefreshes)
{
    SyntheticVtable target(".?AVRefreshed@@");
    SyntheticObject obj(target.vtable());

    std::array<std::uintptr_t, 1> table{obj.address()};

    std::atomic<Address> cache{Address{0xDEADBEEFCAFEULL}};
    auto hit = rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                           ".?AVRefreshed@@", &cache);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->raw(), obj.address());
    EXPECT_EQ(cache.load(std::memory_order_relaxed).raw(), target.vtable());
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST_F(RttiTest, FindInTable_GenerationCacheRejectsSameAddressReplacement)
{
    ScopedPointerImageGeneration generation(101);
    SyntheticVtable original(".?AVOriginal@@");
    SyntheticObject first_object(original.vtable());
    std::array<std::uintptr_t, 1> table{first_object.address()};
    rtti::PointerTableCache cache;

    ASSERT_TRUE(rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                            ".?AVOriginal@@", cache)
                    .has_value());

    original.overwrite_name(".?AVReplacement@@");
    generation.set(202);
    EXPECT_FALSE(rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                             ".?AVOriginal@@", cache)
                     .has_value());

    SyntheticVtable current(".?AVOriginal@@");
    SyntheticObject current_object(current.vtable());
    table[0] = current_object.address();
    generation.set(303);
    ASSERT_TRUE(rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                            ".?AVOriginal@@", cache)
                    .has_value());

    cache.reset();
    current.overwrite_name(".?AVReplacement@@");
    EXPECT_FALSE(rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                             ".?AVOriginal@@", cache)
                     .has_value());
}
#endif

TEST_F(RttiTest, FindInTable_NullTableRejected)
{
    EXPECT_FALSE(rtti::find_in_pointer_table(Address{}, 4, ".?AVNull@@").has_value());
}

TEST_F(RttiTest, FindInTable_ZeroSlotsRejected)
{
    SyntheticVtable v(".?AVZero@@");
    SyntheticObject obj(v.vtable());
    std::array<std::uintptr_t, 1> table{obj.address()};

    EXPECT_FALSE(rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, 0, ".?AVZero@@")
                     .has_value());
}

TEST_F(RttiTest, FindInTable_EmptyExpectedRejected)
{
    SyntheticVtable v(".?AVEmpty@@");
    SyntheticObject obj(v.vtable());
    std::array<std::uintptr_t, 1> table{obj.address()};

    EXPECT_FALSE(rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(), "")
                     .has_value());
}

TEST_F(RttiTest, FindInTable_CustomStrideSkipsInterleavedMetadata)
{
    SyntheticVtable target(".?AVStride@@");
    SyntheticObject obj(target.vtable());

    // Table is { ptr, metadata, ptr, metadata, ... }; stride is 16 bytes and only every other qword is a real object
    // pointer.
    std::array<std::uintptr_t, 4> table{obj.address(), 0xAAAAAAAAu, obj.address(), 0xBBBBBBBBu};

    auto hit = rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, 2, ".?AVStride@@",
                                           nullptr, 16);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->raw(), obj.address());
}

TEST_F(RttiTest, FindInTable_ZeroStrideDefaultsToQword)
{
    SyntheticVtable target(".?AVZeroStride@@");
    SyntheticObject obj(target.vtable());

    std::array<std::uintptr_t, 1> table{obj.address()};

    auto hit = rtti::find_in_pointer_table(Address{reinterpret_cast<std::uintptr_t>(table.data())}, table.size(),
                                           ".?AVZeroStride@@", nullptr, 0);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->raw(), obj.address());
}

TEST_F(RttiTest, FindInTable_OverflowingRangeRejected)
{
    // (table + slot_count * stride) wraps; should be treated as invalid.
    EXPECT_FALSE(rtti::find_in_pointer_table(Address{UINTPTR_MAX - 8}, 4, ".?AVAnything@@", nullptr, 16).has_value());
}

// Bound-check guards against poisoned RTTI fields

TEST_F(RttiTest, ResolveRejectsPoisonedTypeDescriptorRva)
{
    // A bogus type-descriptor RVA places the computed name buffer outside the test executable's module range; the
    // walker must reject the read rather than dereference whatever address the bogus RVA produces.
    SyntheticVtable v(".?AVValid@@");
    v.poison_type_descriptor_rva(0x7FFFFFFFu);

    EXPECT_FALSE(rtti::type_name_of(Address{v.vtable()}).has_value());
    EXPECT_FALSE(rtti::vtable_is_type(Address{v.vtable()}, ".?AVValid@@"));

    char buf[64];
    std::memset(buf, 'Z', sizeof(buf));
    EXPECT_EQ(rtti::type_name_into(Address{v.vtable()}, buf, sizeof(buf)), 0u);
    EXPECT_EQ(buf[0], '\0');
}

TEST_F(RttiTest, ResolveRejectsPoisonedSelfRva)
{
    // A bogus pSelf recovers an image base that does not match the loader-reported module base; the walker must reject
    // rather than trust the recovered base. self_rva == 1 makes recovered = col_addr - 1, which never equals
    // mod_range.base.
    SyntheticVtable v(".?AVValid@@");
    v.poison_self_rva(1);

    EXPECT_FALSE(rtti::type_name_of(Address{v.vtable()}).has_value());
    EXPECT_FALSE(rtti::vtable_is_type(Address{v.vtable()}, ".?AVValid@@"));
}

TEST_F(RttiTest, ResolveRejectsHeapAllocatedVtable)
{
    // A vtable whose address is not in any loaded module (here, a heap allocation) must be rejected at the
    // module_range_for step.
    auto buf = std::make_unique<std::array<std::uintptr_t, 4>>();
    (*buf)[0] = 0;
    (*buf)[1] = 0;
    (*buf)[2] = 0;
    (*buf)[3] = 0;
    const std::uintptr_t fake_vt = reinterpret_cast<std::uintptr_t>(buf->data() + 2);

    EXPECT_FALSE(rtti::type_name_of(Address{fake_vt}).has_value());
    EXPECT_FALSE(rtti::vtable_is_type(Address{fake_vt}, ".?AVAnything@@"));
}

// Default values / constants

TEST(RttiConstantsTest, Defaults)
{
    static_assert(rtti::DEFAULT_TYPE_NAME_MAX > 0);
    static_assert(rtti::MAX_TYPE_NAME_LEN > rtti::DEFAULT_TYPE_NAME_MAX);
}

// type_name_checked -- distinguishes a complete name from a truncated prefix, which type_name_into cannot (it returns
// the capacity in both cases, so a caller comparing for identity could match a proper prefix of a longer name against a
// shorter expected name).

TEST_F(RttiTest, TypeNameChecked_ReportsOkForCompleteName)
{
    SyntheticVtable v(".?AVChecked@@");
    char out[64] = {};
    const rtti::NameRead r = rtti::type_name_checked(Address{v.vtable()}, out, sizeof(out));
    EXPECT_EQ(r.status, rtti::NameStatus::Ok);
    EXPECT_EQ(r.written, std::strlen(".?AVChecked@@"));
    EXPECT_STREQ(out, ".?AVChecked@@");
}

TEST_F(RttiTest, TypeNameChecked_ReportsTruncatedWhenBufferTooSmall)
{
    SyntheticVtable v(".?AVCheckedLongName@@");
    char out[8] = {}; // capacity 7 chars + NUL, far shorter than the name
    const rtti::NameRead r = rtti::type_name_checked(Address{v.vtable()}, out, sizeof(out));
    EXPECT_EQ(r.status, rtti::NameStatus::Truncated) << "a name longer than the buffer must not read as Ok";
    EXPECT_EQ(r.written, sizeof(out) - 1);
    EXPECT_EQ(std::string_view(out, r.written), std::string_view(".?AVChe")); // a proper prefix
    EXPECT_EQ(out[sizeof(out) - 1], '\0');                                    // still NUL-terminated
}

TEST_F(RttiTest, TypeNameChecked_OneByteBufferReportsTruncated)
{
    SyntheticVtable v(".?AVOneByte@@");
    char out[1] = {'x'};
    const rtti::NameRead result = rtti::type_name_checked(Address{v.vtable()}, out, sizeof(out));
    EXPECT_EQ(result.status, rtti::NameStatus::Truncated);
    EXPECT_EQ(result.written, 0u);
    EXPECT_EQ(out[0], '\0');
}

TEST_F(RttiTest, TypeNameChecked_NonTerminatedNameAtHardCapReportsTruncated)
{
    SyntheticVtable v("placeholder");
    v.make_name_non_terminated(rtti::MAX_TYPE_NAME_LEN + 1);
    std::array<char, rtti::MAX_TYPE_NAME_LEN + 1> out{};
    const rtti::NameRead result = rtti::type_name_checked(Address{v.vtable()}, out.data(), out.size());
    EXPECT_EQ(result.status, rtti::NameStatus::Truncated);
    EXPECT_EQ(result.written, rtti::MAX_TYPE_NAME_LEN);
    EXPECT_EQ(out.back(), '\0');
}

TEST_F(RttiTest, TypeNameChecked_ExactFitReportsOk)
{
    // A name that exactly fills the buffer capacity (out_len - 1) is complete, not truncated: the byte after the copy
    // is the terminator. type_name_into cannot tell this from a real truncation (both return the capacity); this must.
    SyntheticVtable v("ABCDEFG"); // 7 characters
    char out[8] = {};             // capacity exactly 7 + NUL
    const rtti::NameRead r = rtti::type_name_checked(Address{v.vtable()}, out, sizeof(out));
    EXPECT_EQ(r.status, rtti::NameStatus::Ok);
    EXPECT_EQ(r.written, 7u);
    EXPECT_STREQ(out, "ABCDEFG");
}

TEST_F(RttiTest, TypeNameChecked_ReportsFailedOnBadVtable)
{
    char out[64] = {'x'};
    const rtti::NameRead r = rtti::type_name_checked(Address{0x100}, out, sizeof(out));
    EXPECT_EQ(r.status, rtti::NameStatus::Failed);
    EXPECT_EQ(r.written, 0u);
    EXPECT_EQ(out[0], '\0'); // failure clears the buffer
}
