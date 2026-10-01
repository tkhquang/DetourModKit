#include "DetourModKit/address.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/memory.hpp"

// White-box engine seams for the vectored-handler / fault-isolation tests.
#include "internal/memory_fault.hpp"
#include "internal/memory_guarded.hpp"

#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <thread>
#include <vector>
#include "fixtures/memory_fixture.hpp"
using namespace dmk_test::memory_fixture;

namespace representation_read
{
    enum class FixedEnum : std::uint8_t
    {
        A = 0,
        B = 1
    };

    struct Vec3i
    {
        int x;
        int y;
        int z;
    };

    struct Padded
    {
        char c;
        int i;
    };

    struct BoolCarrier
    {
        bool enabled;
        int value;
    };

    struct Sample
    {
        std::uint32_t a;
        std::uint32_t b;
        std::uint64_t c;
    };
} // namespace representation_read

namespace DetourModKit::detail
{
    template <> struct enable_representation_safe_aggregate<::representation_read::Vec3i> : std::true_type
    {
    };

    template <> struct enable_representation_safe_aggregate<::representation_read::Sample> : std::true_type
    {
    };
} // namespace DetourModKit::detail

namespace representation_read
{
    template <class T>
    concept GuardedReadable = requires(DetourModKit::Address address) { DetourModKit::memory::read<T>(address); };

    template <class T>
    concept UncheckedReadable =
        requires(DetourModKit::Address address) { DetourModKit::memory::unchecked::read<T>(address); };

    template <class T>
    concept EngineReadable = requires(std::uintptr_t address) { DetourModKit::detail::guarded_read<T>(address); };
} // namespace representation_read

using namespace DetourModKit;

namespace
{
    /** @brief Adapts guarded byte reads to the Boolean result that these fixtures expect. */
    inline bool read_bytes(std::uintptr_t addr, void *out, std::size_t n) noexcept
    {
        if (out == nullptr && n != 0)
        {
            return false;
        }
        return memory::read_into(Address{addr}, std::span<std::byte>{static_cast<std::byte *>(out), n}).has_value();
    }

    // Guarded "read pointer, 0 on fault": the v3 read_ptr_unsafe contract.
    inline std::uintptr_t guarded_ptr_or_zero(std::uintptr_t base, std::ptrdiff_t off) noexcept
    {
        return memory::read<std::uintptr_t>(Address{base}.offset(off)).value_or(0);
    }

    // The adapter screens source and result around unchecked::read. Invalid pointer values return zero while the
    // success path still uses the raw read.
    inline std::uintptr_t screened_unchecked_ptr(
        std::uintptr_t base,
        std::ptrdiff_t off,
        std::uintptr_t min_valid = memory::USERSPACE_PTR_MIN
    ) noexcept
    {
        const std::uintptr_t source = base + static_cast<std::uintptr_t>(off);
        // The unguarded source needs an exclusive min_valid floor. The ceiling rejects kernel and non-canonical
        // addresses before dereference.
        if (source <= min_valid || source >= memory::USERSPACE_PTR_MAX)
        {
            return 0;
        }
        const std::uintptr_t value = memory::unchecked::read<std::uintptr_t>(Address{source});
        // The loaded pointer receives the same exclusive window. An invalid link cannot propagate into a later hop.
        return (value > min_valid && value < memory::USERSPACE_PTR_MAX) ? value : 0;
    }
} // namespace

TEST(MemoryErrorTest, ErrorToString)
{
    EXPECT_FALSE(to_string(ErrorCode::NullTargetAddress).empty());
    EXPECT_FALSE(to_string(ErrorCode::NullSourceBytes).empty());
    EXPECT_FALSE(to_string(ErrorCode::ProtectionChangeFailed).empty());
    EXPECT_FALSE(to_string(ErrorCode::ProtectionRestoreFailed).empty());
    EXPECT_FALSE(to_string(ErrorCode::SizeTooLarge).empty());
    EXPECT_FALSE(to_string(static_cast<ErrorCode>(999)).empty());
}

// read<T> and the read<T>(addr).value_or(0) guarded-pointer idiom

TEST_F(MemoryTest, ReadPtrUnsafe_ValidPointer)
{
    uintptr_t value = 0xDEADBEEF;
    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0xDEADBEEF);
}

TEST_F(MemoryTest, ReadPtrUnsafe_WithOffset)
{
    uintptr_t values[2] = {0x11111111, 0x22222222};
    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(values), sizeof(uintptr_t));
    EXPECT_EQ(result, 0x22222222);
}

TEST_F(MemoryTest, ReadPtrUnsafe_NullAddress)
{
    uintptr_t result = guarded_ptr_or_zero(0, 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnsafe_InvalidAddress)
{
    uintptr_t result = guarded_ptr_or_zero(0xDEAD, 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnsafe_FreedMemory)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uintptr_t *>(mem) = 0xCAFEBABE;
    VirtualFree(mem, 0, MEM_RELEASE);

    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(mem), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnsafe_HeapAllocation)
{
    auto buffer = std::make_unique<uintptr_t>(0xABCD1234);
    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(buffer.get()), 0);
    EXPECT_EQ(result, 0xABCD1234);
}

TEST_F(MemoryTest, ReadPtrUnsafe_NoAccessPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(mem, nullptr);

    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(mem), 0);
    EXPECT_EQ(result, 0u);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReadPtrUnsafe_GuardPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uintptr_t *>(mem) = 0x12345678;

    DWORD old_protect;
    VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect);

    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(mem), 0);
    // MSVC SEH catches the guard-page exception and returns 0. MinGW's vectored fault handler swallows the same
    // STATUS_GUARD_PAGE_VIOLATION and returns 0.
    EXPECT_EQ(result, 0u);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReadPtrUnsafe_ReadOnlyPage)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uintptr_t *>(mem) = 0xFEEDFACE;

    DWORD old_protect;
    VirtualProtect(mem, 4096, PAGE_READONLY, &old_protect);

    uintptr_t result = guarded_ptr_or_zero(reinterpret_cast<uintptr_t>(mem), 0);
    EXPECT_EQ(result, 0xFEEDFACE);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ReadPtrUnsafe_NegativeOffset)
{
    uintptr_t values[3] = {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC};
    uintptr_t base = reinterpret_cast<uintptr_t>(&values[2]);
    uintptr_t result = guarded_ptr_or_zero(base, -static_cast<ptrdiff_t>(sizeof(uintptr_t)));
    EXPECT_EQ(result, 0xBBBBBBBB);
}

// Window screen (is_plausible_ptr) plus the raw unchecked::read

TEST_F(MemoryTest, ReadPtrUnchecked_ValidHighPointer)
{
    uintptr_t value = 0x00007FF700000000;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0x00007FF700000000);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsNullValue)
{
    uintptr_t value = 0;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsLowPointer)
{
    uintptr_t value = 0x1000;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsBoundaryValue)
{
    // The result gate floor is EXCLUSIVE at min_valid (0x10000), so a loaded value exactly at the floor is rejected.
    uintptr_t value = 0x10000;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_AcceptsAboveBoundary)
{
    uintptr_t value = 0x10001;
    EXPECT_TRUE(memory::is_plausible_ptr(Address{value}));
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0);
    EXPECT_EQ(result, 0x10001);
}

TEST_F(MemoryTest, ReadPtrUnchecked_WithOffset)
{
    uintptr_t values[2] = {0x1000, 0x00007FF700001234};
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(values), sizeof(uintptr_t));
    EXPECT_EQ(result, 0x00007FF700001234);
}

TEST_F(MemoryTest, ReadPtrUnchecked_CustomThreshold)
{
    uintptr_t value = 0x500;
    EXPECT_EQ(screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0, 0x1000), 0u);
    EXPECT_EQ(screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0, 0x100), 0x500);
}

TEST_F(MemoryTest, ReadPtrUnchecked_ZeroThreshold)
{
    uintptr_t value = 1;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&value), 0, 0);
    EXPECT_EQ(result, 1u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_SourceInLowAddressRange)
{
    uintptr_t base = 0x100;
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = screened_unchecked_ptr(base, offset, min_valid);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_SourceAtMinValid)
{
    uintptr_t base = 0x10000;
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = screened_unchecked_ptr(base, offset, min_valid);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_ValidSourceLowResult)
{
    uintptr_t low_value = 0x100;
    uintptr_t base = reinterpret_cast<uintptr_t>(&low_value);
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = screened_unchecked_ptr(base, offset, min_valid);
    EXPECT_EQ(result, 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_ValidSourceValidResult)
{
    uintptr_t high_value = 0x7FFE0000;
    uintptr_t base = reinterpret_cast<uintptr_t>(&high_value);
    ptrdiff_t offset = 0;
    uintptr_t min_valid = 0x10000;

    uintptr_t result = screened_unchecked_ptr(base, offset, min_valid);
    EXPECT_EQ(result, high_value);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsKernelRangeSource)
{
    // A kernel-range source is rejected by the upper-bound guard before any dereference (early return), so this is safe
    // to call with a non-readable base.
    const uintptr_t base = 0xFFFF800000000000ULL;
    EXPECT_FALSE(memory::is_plausible_ptr(Address{base}));
    EXPECT_EQ(screened_unchecked_ptr(base, 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsSourceAtCeiling)
{
    // USERSPACE_PTR_MAX is the exclusive ceiling. A source at that address must fail before dereference.
    EXPECT_FALSE(memory::is_plausible_ptr(Address{memory::USERSPACE_PTR_MAX}));
    EXPECT_EQ(screened_unchecked_ptr(memory::USERSPACE_PTR_MAX, 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsSourceOffsetCrossingCeiling)
{
    // The range guard rejects both the ceiling and pointer wraparound.
    const uintptr_t base = memory::USERSPACE_PTR_MAX - 0x100;
    EXPECT_EQ(screened_unchecked_ptr(base, 0x100), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsKernelRangeResult)
{
    // The result guard must reject a kernel pointer even when the source passes its guard.
    uintptr_t kernel_value = 0xFFFF800000000000ULL;
    EXPECT_EQ(screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&kernel_value), 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_RejectsResultAtCeiling)
{
    uintptr_t ceiling_value = memory::USERSPACE_PTR_MAX;
    EXPECT_EQ(screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&ceiling_value), 0), 0u);
}

TEST_F(MemoryTest, ReadPtrUnchecked_AcceptsResultJustBelowCeiling)
{
    uintptr_t high_value = memory::USERSPACE_PTR_MAX - 1;
    uintptr_t result = screened_unchecked_ptr(reinterpret_cast<uintptr_t>(&high_value), 0);
    EXPECT_EQ(result, high_value);
}

TEST_F(MemoryTest, ReadPtrUnsafe_AfterCachePrime)
{
    uintptr_t value = 0xDEADBEEF;
    auto addr = reinterpret_cast<uintptr_t>(&value);

    // The cache remains primed, but read uses the guard directly. This distinguishes a valid cached scope from a
    // cache-dependent byte read.
    EXPECT_TRUE(is_readable(&value, sizeof(uintptr_t)));

    uintptr_t result = guarded_ptr_or_zero(addr, 0);
    EXPECT_EQ(result, value);
}

TEST(MemoryErrorTest, MemoryErrorToString_IsNoexcept)
{
    static_assert(noexcept(to_string(ErrorCode::NullTargetAddress)));
}

// read_into

TEST_F(MemoryTest, SehReadBytes_ValidStackBuffer)
{
    const uint64_t source = 0xCAFEBABEDEADBEEFULL;
    auto value = memory::read<uint64_t>(Address{reinterpret_cast<uintptr_t>(&source)});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, source);
}

TEST_F(MemoryTest, SehReadBytes_ZeroBytesIsNoOp)
{
    char dst = 'X';
    EXPECT_TRUE(read_bytes(0x1000, &dst, 0));
    EXPECT_EQ(dst, 'X');
}

TEST_F(MemoryTest, SehReadBytes_NullOutRejected)
{
    const uint32_t source = 0xDEADC0DE;
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(&source), nullptr, sizeof(source)));
}

TEST_F(MemoryTest, SehReadBytes_LowAddressRejected)
{
    uint32_t out = 0xAAAAAAAA;
    EXPECT_FALSE(read_bytes(0x100, &out, sizeof(out)));
    EXPECT_FALSE(read_bytes(0xFFFF, &out, sizeof(out)));
}

TEST_F(MemoryTest, SehReadBytes_AddressWraparoundRejected)
{
    uint64_t out = 0;
    const uintptr_t near_max = UINTPTR_MAX - 8;
    EXPECT_FALSE(read_bytes(near_max, &out, 64));
}

TEST_F(MemoryTest, SehReadBytes_FreedMemoryReturnsFalse)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uint64_t *>(mem) = 0x1122334455667788ULL;
    VirtualFree(mem, 0, MEM_RELEASE);

    uint64_t out = 0;
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(mem), &out, sizeof(out)));
}

TEST_F(MemoryTest, SehReadBytes_NoAccessReturnsFalse)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(mem, nullptr);

    uint64_t out = 0;
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(mem), &out, sizeof(out)));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, SehReadBytes_GuardPageReturnsFalse)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uint64_t *>(mem) = 0x42;

    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old_protect));

    uint64_t out = 0;
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(mem), &out, sizeof(out)));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, SehReadBytes_LargeRangePartialUnmapped)
{
    // The read crosses from a committed page into unmapped memory and must fail.
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::vector<uint8_t> buf(8192, 0);
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(mem), buf.data(), buf.size()));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// read<T>

TEST_F(MemoryTest, SehRead_Uintptr)
{
    const uintptr_t source = 0xFEEDFACEBADDCAFEULL;
    auto value = memory::read<uintptr_t>(Address{reinterpret_cast<uintptr_t>(&source)});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, source);
}

TEST_F(MemoryTest, SehRead_Uint32)
{
    const uint32_t source = 0xABCDEF01u;
    auto value = memory::read<uint32_t>(Address{reinterpret_cast<uintptr_t>(&source)});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, source);
}

TEST_F(MemoryTest, SehRead_Struct)
{
    using representation_read::Sample;

    static_assert(std::is_trivially_copyable_v<Sample>);
    const Sample source{0x11111111u, 0x22222222u, 0x3333333344444444ULL};

    auto value = memory::read<Sample>(Address{reinterpret_cast<uintptr_t>(&source)});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(value->a, source.a);
    EXPECT_EQ(value->b, source.b);
    EXPECT_EQ(value->c, source.c);
}

TEST_F(MemoryTest, SehRead_NullAddressReturnsNullopt)
{
    auto value = memory::read<uint64_t>(Address{static_cast<std::uintptr_t>(0)});
    EXPECT_FALSE(value.has_value());
}

TEST_F(MemoryTest, SehRead_LowAddressReturnsNullopt)
{
    auto value = memory::read<uint64_t>(Address{static_cast<std::uintptr_t>(0x100)});
    EXPECT_FALSE(value.has_value());
}

TEST_F(MemoryTest, SehRead_FreedMemoryReturnsNullopt)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *reinterpret_cast<uint64_t *>(mem) = 0xDEADBEEFu;
    VirtualFree(mem, 0, MEM_RELEASE);

    auto value = memory::read<uint64_t>(Address{reinterpret_cast<uintptr_t>(mem)});
    EXPECT_FALSE(value.has_value());
}

// EXCEPTION_IN_PAGE_ERROR represents a failed file-backed page access. The shared predicate must contain it alongside
// access and guard faults.
TEST(MemoryGuardedReadFault, AcceptsForeignReadFaultsAndRejectsOthers)
{
    using detail::is_guarded_read_fault;

    // The three codes a guarded probe owns. Spelled via the Windows macros here to prove the predicate's literals match
    // the platform values.
    static_assert(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_ACCESS_VIOLATION)));
    static_assert(is_guarded_read_fault(static_cast<unsigned long>(STATUS_GUARD_PAGE_VIOLATION)));
    static_assert(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_IN_PAGE_ERROR)));

    EXPECT_TRUE(is_guarded_read_fault(0xC0000005ul)); // EXCEPTION_ACCESS_VIOLATION
    EXPECT_TRUE(is_guarded_read_fault(0x80000001ul)); // STATUS_GUARD_PAGE_VIOLATION
    EXPECT_TRUE(is_guarded_read_fault(0xC0000006ul)); // EXCEPTION_IN_PAGE_ERROR

    // Codes that did not originate from the probe's own read must continue the search.
    EXPECT_FALSE(is_guarded_read_fault(0ul));
    EXPECT_FALSE(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_BREAKPOINT)));          // 0x80000003
    EXPECT_FALSE(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_ILLEGAL_INSTRUCTION))); // 0xC000001D
    EXPECT_FALSE(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_STACK_OVERFLOW)));      // 0xC00000FD
    EXPECT_FALSE(is_guarded_read_fault(static_cast<unsigned long>(EXCEPTION_INT_DIVIDE_BY_ZERO)));  // 0xC0000094
}

// The odd-offset pointer must round-trip through memcpy. An aligned typed dereference cannot explain that success.
TEST_F(MemoryTest, ReadPtrUnsafeReadsMisalignedPointer)
{
    void *region = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);

    auto *base = static_cast<std::uint8_t *>(region);
    constexpr std::uintptr_t SENTINEL = 0xDEADBEEFCAFEF00Dull;
    constexpr ptrdiff_t MISALIGNED_OFFSET = 1; // deliberately not a multiple of alignof(uintptr_t)
    std::memcpy(base + MISALIGNED_OFFSET, &SENTINEL, sizeof(SENTINEL));

    const std::uintptr_t value = guarded_ptr_or_zero(reinterpret_cast<std::uintptr_t>(base), MISALIGNED_OFFSET);
    EXPECT_EQ(value, SENTINEL);

    // An unmapped low address still fails closed to 0 (the fault is swallowed, not propagated).
    EXPECT_EQ(guarded_ptr_or_zero(0, 0), 0u);

    VirtualFree(region, 0, MEM_RELEASE);
}

// A reserved page has no committed storage. MinGW must contain its read fault through VEH, and MSVC through __except.
TEST_F(MemoryTest, SehReadBytes_ReservedUncommittedReturnsFalse)
{
    void *reserved = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(reserved, nullptr);

    uint64_t out = 0;
    EXPECT_FALSE(read_bytes(reinterpret_cast<uintptr_t>(reserved), &out, sizeof(out)));

    VirtualFree(reserved, 0, MEM_RELEASE);
}

// With the cache reporting a page readable, an external reprotect to PAGE_NOACCESS must not crash a subsequent
// guarded read. The guarded read must ignore stale protection data and fail closed through the same "0 on fault"
// contract on both toolchains.
TEST_F(MemoryTest, ReadPtrUnsafeSurvivesStaleCacheReprotect)
{
    void *region = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(region, nullptr);
    const uintptr_t addr = reinterpret_cast<uintptr_t>(region);
    *reinterpret_cast<uintptr_t *>(region) = 0xABCDEF0123456789ULL;

    // Prime the cache so the region is recorded as readable.
    EXPECT_TRUE(is_readable(region, sizeof(uintptr_t)));
    EXPECT_EQ(guarded_ptr_or_zero(addr, 0), 0xABCDEF0123456789ULL);

    // The cache stays stale after reprotection. A cache-trusting read reaches the inaccessible page.
    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(region, 4096, PAGE_NOACCESS, &old_protect), 0);

    // The fault is swallowed and reported as the pointer-read failure value.
    EXPECT_EQ(guarded_ptr_or_zero(addr, 0), 0u);

    VirtualProtect(region, 4096, old_protect, &old_protect);
    VirtualFree(region, 0, MEM_RELEASE);
}

namespace
{
    // The unrelated consumer VEH declines every fault. It cannot interfere with the guarded read.
    LONG CALLBACK consumer_passthrough_veh(PEXCEPTION_POINTERS)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
} // namespace

// Both VEH registration orders must coexist with guarded reads. On MSVC, the consumer passes faults through to the
// frame __except handler.
TEST_F(MemoryTest, VectoredHandlerCoexistsWithConsumerHandler)
{
    // Committed PAGE_NOACCESS, never a released VA: a released range can be remapped by a concurrent
    // allocation before the read. See GuardedReadsAreThreadIsolatedUnderConcurrency.
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(mem, nullptr);
    const uintptr_t bad_addr = reinterpret_cast<uintptr_t>(mem);

    const uint64_t live = 0x1122334455667788ULL;

    auto exercise = [&]()
    {
        uint64_t out = 0;
        EXPECT_FALSE(detail::guarded_read_bytes(bad_addr, &out, sizeof(out)));
        EXPECT_EQ(guarded_ptr_or_zero(bad_addr, 0), 0u);
        out = 0;
        EXPECT_TRUE(detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(&live), &out, sizeof(out)));
        EXPECT_EQ(out, live);
    };

    // Ordering 1: consumer handler registered before DMK performs (and lazily installs) its own guarded read.
    void *consumer = AddVectoredExceptionHandler(1, consumer_passthrough_veh);
    ASSERT_NE(consumer, nullptr);
    exercise();
    RemoveVectoredExceptionHandler(consumer);

    // Register the consumer before the existing DMK handler for the second order.
    consumer = AddVectoredExceptionHandler(1, consumer_passthrough_veh);
    ASSERT_NE(consumer, nullptr);
    exercise();
    RemoveVectoredExceptionHandler(consumer);

    VirtualFree(mem, 0, MEM_RELEASE);
}

// The MinGW span filter must reject wrap before access. MSVC contains the fault through __try. Both low and wrapped
// sources return zero.
TEST_F(MemoryTest, ReadPtrUnsafeWraparoundAndLowAddressReturnZero)
{
    // The eight-byte span crosses the top of the address space.
    EXPECT_EQ(guarded_ptr_or_zero(UINTPTR_MAX - 3, 0), 0u);

    // Below the user-mode floor.
    EXPECT_EQ(guarded_ptr_or_zero(0x100, 0), 0u);

    // The negative offset underflows to a high unmapped address and must return zero.
    EXPECT_EQ(guarded_ptr_or_zero(0x20000, -static_cast<ptrdiff_t>(0x30000)), 0u);
}

// Mixed valid and faulted reads exercise each thread's guard slot. The white-box guarded_read_bytes path must preserve
// isolation.
TEST_F(MemoryTest, GuardedReadsAreThreadIsolatedUnderConcurrency)
{
    void *good = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(good, nullptr);
    constexpr uintptr_t SENTINEL = 0x5151515151515151ULL;
    *reinterpret_cast<uintptr_t *>(good) = SENTINEL;

    // The committed PAGE_NOACCESS allocation stays live through the reader joins. Thread creation cannot recycle its
    // address into readable memory.
    void *unreadable = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(unreadable, nullptr);

    std::atomic<bool> all_correct{true};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (int i = 0; i < 1000; ++i)
                {
                    if (t % 2 == 0)
                    {
                        uintptr_t v = 0;
                        if (!detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(good), &v, sizeof(v)) ||
                            v != SENTINEL)
                            all_correct.store(false, std::memory_order_relaxed);
                    }
                    else
                    {
                        uintptr_t v = 0;
                        if (detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(unreadable), &v, sizeof(v)))
                            all_correct.store(false, std::memory_order_relaxed);
                    }
                }
            }
        );
    }
    for (auto &th : threads)
        th.join();

    EXPECT_TRUE(all_correct.load());
    VirtualFree(unreadable, 0, MEM_RELEASE);
    VirtualFree(good, 0, MEM_RELEASE);
}

// MinGW shutdown drains guarded reads before handler removal. On MSVC, the same stress checks guard and cache
// concurrency without a VEH.
TEST_F(MemoryTest, GuardedReadsSurviveConcurrentShutdown)
{
    void *good = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(good, nullptr);
    constexpr uintptr_t SENTINEL = 0xA5A5A5A5A5A5A5A5ULL;
    *reinterpret_cast<uintptr_t *>(good) = SENTINEL;

    // The committed PAGE_NOACCESS page stays allocated until teardown. A released address can become readable during
    // thread creation and invalidate the fault premise.
    void *unreadable = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(unreadable, nullptr);

    std::atomic<bool> stop{false};
    std::atomic<int> seen_good{0};
    std::atomic<int> seen_fault{0};
    std::vector<std::thread> readers;
    for (int t = 0; t < 3; ++t)
    {
        readers.emplace_back(
            [&, t]()
            {
                void *const target = (t % 2) ? unreadable : good;
                while (!stop.load(std::memory_order_acquire))
                {
                    uintptr_t v = 0;
                    const bool ok = detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(target), &v, sizeof(v));
                    if (target == good)
                    {
                        if (ok && v == SENTINEL)
                            seen_good.fetch_add(1, std::memory_order_relaxed);
                    }
                    else if (!ok)
                    {
                        seen_fault.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
        );
    }

    // Both success and fault paths must enter before teardown. This handshake prevents an empty in-flight drain.
    while (seen_good.load(std::memory_order_acquire) == 0 || seen_fault.load(std::memory_order_acquire) == 0)
        std::this_thread::yield();

    for (int round = 0; round < 12; ++round)
    {
        memory::shutdown_cache();
        (void)memory::init_cache();
    }

    stop.store(true, std::memory_order_release);
    for (auto &th : readers)
        th.join();

    uintptr_t final_value = 0;
    EXPECT_TRUE(detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(good), &final_value, sizeof(final_value)));
    EXPECT_EQ(final_value, SENTINEL);
    VirtualFree(unreadable, 0, MEM_RELEASE);
    VirtualFree(good, 0, MEM_RELEASE);
}

namespace
{
    std::atomic<void *> g_recover_page{nullptr};
    std::atomic<int> g_recover_hits{0};

    /** @brief Recovers the sentinel fault through reprotection and instruction retry after DMK declines it. */
    LONG CALLBACK recover_noaccess_veh(PEXCEPTION_POINTERS info)
    {
        void *const page = g_recover_page.load(std::memory_order_acquire);
        const EXCEPTION_RECORD *const rec = info->ExceptionRecord;
        if (page != nullptr && rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2)
        {
            const uintptr_t fault = static_cast<uintptr_t>(rec->ExceptionInformation[1]);
            const uintptr_t base = reinterpret_cast<uintptr_t>(page);
            if (fault >= base && fault < base + 4096)
            {
                DWORD old_protect = 0;
                VirtualProtect(page, 4096, PAGE_READWRITE, &old_protect);
                g_recover_hits.fetch_add(1, std::memory_order_relaxed);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
} // namespace

// The worker never arms a DMK guard. Its consumer handler must recover the fault without a DMK claim. MSVC reaches the
// consumer directly.
TEST_F(MemoryTest, UnarmedThreadFaultIsPassedThroughNotClaimed)
{
    // Arm and disarm DMK's handler on this thread so it is installed for the process.
    uint64_t probe_src = 0xC3C3C3C3C3C3C3C3ULL;
    uint64_t probe_out = 0;
    ASSERT_TRUE(detail::guarded_read_bytes(reinterpret_cast<uintptr_t>(&probe_src), &probe_out, sizeof(probe_out)));

    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(page, nullptr);
    g_recover_page.store(page, std::memory_order_release);
    g_recover_hits.store(0, std::memory_order_release);

    // Last in the list, so DMK's first-in-list handler sees the fault first and must decline it.
    void *consumer = AddVectoredExceptionHandler(0, recover_noaccess_veh);
    ASSERT_NE(consumer, nullptr);

    std::atomic<uint32_t> observed{0xFFFFFFFFu};
    std::thread worker(
        [&]()
        {
            volatile uint32_t *const p = reinterpret_cast<volatile uint32_t *>(page);
            // The consumer handler makes the faulted page readable, then retries the instruction.
            observed.store(*p, std::memory_order_release);
        }
    );
    worker.join();

    RemoveVectoredExceptionHandler(consumer);
    g_recover_page.store(nullptr, std::memory_order_release);

    // The unarmed-thread fault reached the consumer, proving DMK passed it through.
    EXPECT_GE(g_recover_hits.load(), 1);

    // The recommitted page reads as zero.
    EXPECT_EQ(observed.load(), 0u);
    VirtualFree(page, 0, MEM_RELEASE);
}

// unchecked::read returns the value of a known local.
TEST_F(MemoryTest, UncheckedRead_HappyPathOnKnownLocal)
{
    const uint64_t value = 0x0123456789ABCDEFull;
    const uint64_t got = memory::unchecked::read<uint64_t>(Address{reinterpret_cast<uintptr_t>(&value)});
    EXPECT_EQ(got, value);
}

// to_string(ErrorCode::ReadFaulted) returns its exact enumerator name.
TEST(MemoryErrorTest, ToString_ReadFaulted)
{
    EXPECT_EQ(to_string(ErrorCode::ReadFaulted), "ReadFaulted");
}

// The OS consumes PAGE_GUARD on fault dispatch. The guarded read must restore that fence so a retry faults again.
TEST_F(MemoryTest, GuardedRead_GuardPageRearmedFailsClosedOnRetry)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    *static_cast<uint32_t *>(mem) = 0xFEEDFACEu;
    DWORD old = 0;
    ASSERT_TRUE(VirtualProtect(mem, 4096, PAGE_READWRITE | PAGE_GUARD, &old));

    const Address addr{mem};
    // The first read fails closed. The handler restores the guard that the OS cleared.
    EXPECT_FALSE(memory::read<uint32_t>(addr).has_value());
    EXPECT_NE(current_page_protection(mem) & PAGE_GUARD, 0u);
    EXPECT_FALSE(memory::read<uint32_t>(addr).has_value());
    EXPECT_NE(current_page_protection(mem) & PAGE_GUARD, 0u);

    // Clear the guard before freeing so nothing else faults on it.
    DWORD cleared = 0;
    VirtualProtect(mem, 4096, PAGE_READWRITE, &cleared);
    VirtualFree(mem, 0, MEM_RELEASE);
}

// A cross-page read reports the first inaccessible source address, not merely the span's starting address.
TEST_F(MemoryTest, GuardedReadReportsFaultingAddress)
{
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    const std::size_t page_size = system_info.dwPageSize;

    auto *memory_base =
        static_cast<std::byte *>(VirtualAlloc(nullptr, page_size * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    ASSERT_NE(memory_base, nullptr);
    std::memset(memory_base, 0x5A, page_size);

    DWORD old_protection = 0;
    ASSERT_TRUE(VirtualProtect(memory_base + page_size, page_size, PAGE_NOACCESS, &old_protection));

    const auto guard_page = reinterpret_cast<std::uintptr_t>(memory_base + page_size);

    std::array<std::byte, 8> output{};
    volatile std::uintptr_t fault_address = 0;
    EXPECT_FALSE(
        detail::guarded_read_bytes(
            reinterpret_cast<std::uintptr_t>(memory_base + page_size - 4),
            output.data(),
            output.size(),
            &fault_address
        )
    );
    EXPECT_EQ(fault_address, guard_page);

    const Result<void> public_read =
        memory::read_into(Address{memory_base + page_size - 4}, std::span<std::byte>{output});
    ASSERT_FALSE(public_read.has_value());
    EXPECT_EQ(public_read.error().code, ErrorCode::ReadFaulted);
    EXPECT_EQ(public_read.error().detail, guard_page);

    // Different span starts cross the same fault boundary. The one-byte and four-byte overlaps must report that
    // boundary.
    std::array<std::byte, 2> straddle{};
    const Result<void> straddle_read =
        memory::read_into(Address{memory_base + page_size - 1}, std::span<std::byte>{straddle});
    ASSERT_FALSE(straddle_read.has_value());
    EXPECT_EQ(straddle_read.error().detail, guard_page);

    // MSVC can fault inside the inaccessible page after a vectorized copy. MinGW rep movsb faults at the boundary. Both
    // addresses stay inside the requested span beyond its readable prefix.
    std::array<std::byte, 128> wide{};
    const auto wide_start = reinterpret_cast<std::uintptr_t>(memory_base + page_size - 64);
    const Result<void> wide_read = memory::read_into(Address{memory_base + page_size - 64}, std::span<std::byte>{wide});
    ASSERT_FALSE(wide_read.has_value());
    EXPECT_GE(wide_read.error().detail, guard_page);
    EXPECT_LT(wide_read.error().detail, wide_start + wide.size());

    // A span fully inside the readable first page still succeeds, so the guard is not rejecting the whole allocation.
    std::array<std::byte, 8> readable{};
    EXPECT_TRUE(memory::read_into(Address{memory_base + page_size - 8}, std::span<std::byte>{readable}).has_value());

    (void)VirtualFree(memory_base, 0, MEM_RELEASE);
}

// A refusal before access reports the requested start because no fault byte exists. This control distinguishes
// rejection from an exact cross-page fault.
TEST_F(MemoryTest, ReadIntoRejectedSpansReportTheRequestedStart)
{
    std::array<std::byte, 8> output{};
    constexpr std::uintptr_t untouched_fault_sentinel = 0xC0DEC0DE;

    // Below USERSPACE_PTR_MIN: refused with no access at all.
    constexpr std::uintptr_t low_address = 0x100;
    volatile std::uintptr_t low_fault_probe = untouched_fault_sentinel;
    EXPECT_FALSE(detail::guarded_read_bytes(low_address, output.data(), output.size(), &low_fault_probe));
    EXPECT_EQ(static_cast<std::uintptr_t>(low_fault_probe), untouched_fault_sentinel);
    const Result<void> low_read = memory::read_into(Address{low_address}, std::span<std::byte>{output});
    ASSERT_FALSE(low_read.has_value());
    EXPECT_EQ(low_read.error().code, ErrorCode::ReadFaulted);
    EXPECT_EQ(low_read.error().detail, low_address);

    // A span whose end wraps the address space: refused before any access.
    const std::uintptr_t wrapping_address = UINTPTR_MAX - 2;
    volatile std::uintptr_t wrapping_fault_probe = untouched_fault_sentinel;
    EXPECT_FALSE(detail::guarded_read_bytes(wrapping_address, output.data(), output.size(), &wrapping_fault_probe));
    EXPECT_EQ(static_cast<std::uintptr_t>(wrapping_fault_probe), untouched_fault_sentinel);
    const Result<void> wrapping_read = memory::read_into(Address{wrapping_address}, std::span<std::byte>{output});
    ASSERT_FALSE(wrapping_read.has_value());
    EXPECT_EQ(wrapping_read.error().code, ErrorCode::ReadFaulted);
    EXPECT_EQ(wrapping_read.error().detail, wrapping_address);

    // The span end exceeds USERSPACE_PTR_MAX without wrap. The fault-slot sentinel distinguishes range refusal from a
    // failed copy at the unmapped start.
    const std::uintptr_t over_ceiling_address = memory::USERSPACE_PTR_MAX - 2;
    volatile std::uintptr_t over_ceiling_fault_probe = untouched_fault_sentinel;
    EXPECT_FALSE(
        detail::guarded_read_bytes(over_ceiling_address, output.data(), output.size(), &over_ceiling_fault_probe)
    );
    EXPECT_EQ(static_cast<std::uintptr_t>(over_ceiling_fault_probe), untouched_fault_sentinel);
    const Result<void> over_ceiling_read =
        memory::read_into(Address{over_ceiling_address}, std::span<std::byte>{output});
    ASSERT_FALSE(over_ceiling_read.has_value());
    EXPECT_EQ(over_ceiling_read.error().code, ErrorCode::ReadFaulted);
    EXPECT_EQ(over_ceiling_read.error().detail, over_ceiling_address);

    // An empty span is a success no-op, so it produces no address at all.
    EXPECT_TRUE(memory::read_into(Address{low_address}, std::span<std::byte>{}).has_value());
}

namespace
{
    // Raw typed reads must exclude bool because most byte patterns are not valid bool representations.
    static_assert(
        !representation_read::GuardedReadable<bool>,
        "memory::read<bool> must be ill-formed; decode via read_bool"
    );
    static_assert(!representation_read::UncheckedReadable<bool>, "memory::unchecked::read<bool> must be ill-formed");
    static_assert(!representation_read::EngineReadable<bool>, "detail::guarded_read<bool> must be ill-formed");
    static_assert(!representation_read::GuardedReadable<bool[4]>, "memory::read<bool[4]> must be ill-formed");
    static_assert(!detail::is_representation_safe_v<bool>);
    static_assert(
        representation_read::GuardedReadable<int> && representation_read::UncheckedReadable<int> &&
        representation_read::EngineReadable<int>
    );
    static_assert(representation_read::GuardedReadable<unsigned char> && representation_read::GuardedReadable<float>);
    static_assert(representation_read::GuardedReadable<void *> && representation_read::GuardedReadable<std::uintptr_t>);
    static_assert(
        representation_read::GuardedReadable<representation_read::FixedEnum> &&
        representation_read::GuardedReadable<std::byte>
    );
    static_assert(representation_read::GuardedReadable<std::array<std::byte, 8>>);
    static_assert(
        representation_read::GuardedReadable<representation_read::Vec3i> &&
        representation_read::UncheckedReadable<representation_read::Vec3i> &&
        representation_read::EngineReadable<representation_read::Vec3i>
    );
    static_assert(
        !representation_read::GuardedReadable<representation_read::Padded> &&
        !representation_read::UncheckedReadable<representation_read::Padded> &&
        !representation_read::EngineReadable<representation_read::Padded>
    );
    static_assert(
        !representation_read::GuardedReadable<representation_read::BoolCarrier> &&
        !representation_read::UncheckedReadable<representation_read::BoolCarrier> &&
        !representation_read::EngineReadable<representation_read::BoolCarrier>
    );

    // read_bool validates the byte before forming the bool.
    TEST_F(MemoryTest, MemoryRepresentationProof_InvalidForeignBoolNeverConstructsT)
    {
        constexpr std::array<std::uint8_t, 4> raw{0x00, 0x01, 0x02, 0xFF};

        const Result<bool> zero = memory::read_bool(Address{&raw[0]});
        ASSERT_TRUE(zero.has_value());
        EXPECT_FALSE(*zero);

        const Result<bool> one = memory::read_bool(Address{&raw[1]});
        ASSERT_TRUE(one.has_value());
        EXPECT_TRUE(*one);

        const Result<bool> two = memory::read_bool(Address{&raw[2]});
        ASSERT_FALSE(two.has_value());
        EXPECT_EQ(two.error().code, ErrorCode::InvalidRepresentation);

        const Result<bool> max = memory::read_bool(Address{&raw[3]});
        ASSERT_FALSE(max.has_value());
        EXPECT_EQ(max.error().code, ErrorCode::InvalidRepresentation);

        // A read fault propagates as ReadFaulted, distinct from InvalidRepresentation.
        void *const reserved = VirtualAlloc(nullptr, 0x1000, MEM_RESERVE, PAGE_NOACCESS);
        ASSERT_NE(reserved, nullptr);
        const Result<bool> faulted = memory::read_bool(Address{reserved});
        EXPECT_FALSE(faulted.has_value());
        EXPECT_EQ(faulted.error().code, ErrorCode::ReadFaulted);
        VirtualFree(reserved, 0, MEM_RELEASE);
    }

    // A complete foreign span must remain below the user-space ceiling.
    TEST_F(MemoryTest, MemoryFaultProof_RangeAtOrAcrossUserSpaceCeilingFailsClosed)
    {
        std::array<std::byte, 8> buffer{};

        const Result<void> at_ceiling = memory::read_into(Address{memory::USERSPACE_PTR_MAX}, buffer);
        ASSERT_FALSE(at_ceiling.has_value());
        EXPECT_EQ(at_ceiling.error().code, ErrorCode::ReadFaulted);

        const Result<void> across = memory::read_into(Address{memory::USERSPACE_PTR_MAX - 4}, buffer);
        ASSERT_FALSE(across.has_value());
        EXPECT_EQ(across.error().code, ErrorCode::ReadFaulted);

        // A zero-length range at the ceiling is a success no-op (nothing is read).
        EXPECT_TRUE(memory::read_into(Address{memory::USERSPACE_PTR_MAX}, std::span<std::byte>{}).has_value());

        // An ordinary in-window read succeeds.
        constexpr std::uint64_t value = 0xDEADBEEFCAFEF00DULL;
        const Result<std::uint64_t> ok = memory::read<std::uint64_t>(Address{&value});
        ASSERT_TRUE(ok.has_value());
        EXPECT_EQ(*ok, value);

        // A write across the ceiling must return WriteFaulted before any byte moves.
        const Result<void> write_ceiling =
            memory::write_in_place(Address{memory::USERSPACE_PTR_MAX - 4}, std::span<const std::byte>{buffer});
        ASSERT_FALSE(write_ceiling.has_value());
        EXPECT_EQ(write_ceiling.error().code, ErrorCode::WriteFaulted);
    }

    // A signed pointer-chain offset must not wrap into a plausible leaf.
    TEST_F(MemoryTest, MemoryWalkProof_SignedOffsetWrapFailsClosed)
    {
        constexpr std::array<std::ptrdiff_t, 1> offsets{static_cast<std::ptrdiff_t>(64)};
        const Result<Address> wrapped = memory::walk(Address{UINTPTR_MAX - 8}, offsets);
        ASSERT_FALSE(wrapped.has_value());
        EXPECT_EQ(wrapped.error().code, ErrorCode::ReadFaulted);
    }

    // A non-wrapping final leaf that lands outside the user-mode window is still rejected, not returned as a success.
    TEST_F(MemoryTest, MemoryWalkProof_LeafOutsideUserSpaceFailsClosed)
    {
        // A negative final offset lands the leaf below USERSPACE_PTR_MIN without wrapping.
        constexpr std::array<std::ptrdiff_t, 1> below{-static_cast<std::ptrdiff_t>(0x20000)};
        const Result<Address> under = memory::walk(Address{0x21000}, below);
        ASSERT_FALSE(under.has_value());
        EXPECT_EQ(under.error().code, ErrorCode::ReadFaulted);

        // A positive final offset lands the leaf at the ceiling (USERSPACE_PTR_MAX) without wrapping.
        constexpr std::array<std::ptrdiff_t, 1> above{static_cast<std::ptrdiff_t>(0x1000)};
        const Result<Address> over = memory::walk(Address{memory::USERSPACE_PTR_MAX - 0x1000}, above);
        ASSERT_FALSE(over.has_value());
        EXPECT_EQ(over.error().code, ErrorCode::ReadFaulted);
    }

    // The source is readable, but the destination is PAGE_NOACCESS. That fault lies outside the declared source span
    // and must escape.
    void attempt_out_of_range_fault()
    {
        constexpr std::uint64_t source = 0;
        void *const bad = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
        std::span<std::byte> out{static_cast<std::byte *>(bad), sizeof(std::uint64_t)};
        (void)memory::read_into(Address{&source}, out);
    }

    // The range filter must not swallow an unrelated access violation.
    TEST(MemoryRangeFilterDeathProof, FaultOutsideDeclaredRangeIsNotSwallowed)
    {
        GTEST_FLAG_SET(death_test_style, "threadsafe");
        EXPECT_DEATH(attempt_out_of_range_fault(), "");
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    void attempt_guard_rearm_failure()
    {
        void *const page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (page == nullptr)
        {
            return;
        }

        DWORD previous = 0;
        if (VirtualProtect(page, 0x1000, PAGE_READWRITE | PAGE_GUARD, &previous) == 0)
        {
            (void)VirtualFree(page, 0, MEM_RELEASE);
            return;
        }

        detail::set_guard_rearm_failure_seam(true);
        std::byte out{};
        (void)memory::read_into(Address{page}, std::span<std::byte>{&out, 1});
        detail::set_guard_rearm_failure_seam(false);
        (void)VirtualFree(page, 0, MEM_RELEASE);
    }

    TEST(MemoryRangeFilterDeathProof, GuardRearmFailureContinuesExceptionSearch)
    {
        GTEST_FLAG_SET(death_test_style, "threadsafe");
        EXPECT_DEATH(attempt_guard_rearm_failure(), "");
    }
#endif // DMK_ENABLE_TEST_SEAMS
} // namespace
