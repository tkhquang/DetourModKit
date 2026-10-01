#include "DetourModKit/address.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"

// White-box engine seams for the overlap observation and the write, patch, and protection fault proofs.
#include "internal/memory_guarded.hpp"

// Deterministic thread-local out-of-memory injection for the ProtectGuard allocation-failure test.
#include "test_alloc_probe.hpp"

#include <gtest/gtest.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include "fixtures/memory_fixture.hpp"
using namespace dmk_test::memory_fixture;

using namespace DetourModKit;

TEST_F(MemoryTest, write_bytes)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {
        std::byte{0x48},
        std::byte{0x8B},
        std::byte{0x05},
        std::byte{0x12},
        std::byte{0x34},
        std::byte{0x56},
        std::byte{0x78}
    };

    auto result = memory::write_bytes(Address{target.data()}, std::span<const std::byte>{source});
    EXPECT_TRUE(result.has_value());

    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[i], source[i]);
    }
}

TEST_F(MemoryTest, write_bytes_NullTarget)
{
    std::vector<std::byte> source = {std::byte{0x90}, std::byte{0x90}};

    auto result = memory::write_bytes(Address{nullptr}, std::span<const std::byte>{source});
    EXPECT_FALSE(result.has_value());
}

// Pins the header's null-before-empty precedence: the null-target check runs before the empty-span no-op, so a
// null target with an empty span is NullTargetAddress, not success.
TEST_F(MemoryTest, write_bytes_NullTargetEmptySpanIsNullTargetAddress)
{
    auto result = memory::write_bytes(Address{nullptr}, std::span<const std::byte>{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullTargetAddress);
}

// The patch_code half of the same null-before-empty precedence pin.
TEST_F(MemoryTest, PatchCode_NullTargetEmptySpanIsNullTargetAddress)
{
    auto result = memory::patch_code(Address{nullptr}, std::span<const std::byte>{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullTargetAddress);
}

TEST_F(MemoryTest, write_bytes_NullSource)
{
    std::vector<std::byte> target(16, std::byte{0x00});

    auto result = memory::write_bytes(
        Address{target.data()},
        std::span<const std::byte>{static_cast<const std::byte *>(nullptr), 10}
    );
    EXPECT_FALSE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_ZeroSize)
{
    std::vector<std::byte> target(16, std::byte{0x00});
    std::vector<std::byte> source = {std::byte{0x90}};

    auto result = memory::write_bytes(Address{target.data()}, std::span<const std::byte>{source.data(), 0});
    EXPECT_TRUE(result.has_value());
}

TEST_F(MemoryTest, write_bytes_Large)
{
    std::vector<std::byte> target(1024, std::byte{0x00});
    std::vector<std::byte> source(512, std::byte{0xCC});

    auto result = memory::write_bytes(Address{target.data()}, std::span<const std::byte>{source});
    EXPECT_TRUE(result.has_value());

    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[i], source[i]);
    }

    for (size_t i = source.size(); i < target.size(); ++i)
    {
        EXPECT_EQ(target[i], std::byte{0x00});
    }
}

TEST_F(MemoryTest, write_bytes_DataIntegrity)
{
    std::vector<std::byte> target(64);
    for (size_t i = 0; i < target.size(); ++i)
    {
        target[i] = std::byte{static_cast<uint8_t>(i)};
    }

    std::vector<std::byte> source = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    auto result = memory::write_bytes(Address{target.data() + 10}, std::span<const std::byte>{source});
    EXPECT_TRUE(result.has_value());

    for (size_t i = 0; i < 10; ++i)
    {
        EXPECT_EQ(target[i], std::byte{static_cast<uint8_t>(i)});
    }

    for (size_t i = 0; i < source.size(); ++i)
    {
        EXPECT_EQ(target[10 + i], source[i]);
    }

    for (size_t i = 14; i < target.size(); ++i)
    {
        EXPECT_EQ(target[i], std::byte{static_cast<uint8_t>(i)});
    }
}

TEST_F(MemoryTest, write_bytes_ErrorTypes)
{
    std::byte source[] = {std::byte{0x90}};

    auto r1 = memory::write_bytes(Address{nullptr}, std::span<const std::byte>{source, 1});
    EXPECT_FALSE(r1.has_value());
    EXPECT_EQ(r1.error().code, ErrorCode::NullTargetAddress);

    std::byte target[1] = {std::byte{0}};
    auto r2 =
        memory::write_bytes(Address{target}, std::span<const std::byte>{static_cast<const std::byte *>(nullptr), 1});
    EXPECT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error().code, ErrorCode::NullSourceBytes);
}

TEST_F(MemoryTest, write_bytes_SizeTooLarge)
{
    std::byte target[1] = {std::byte{0x00}};
    std::byte source[1] = {std::byte{0x90}};

    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, memory::MAX_WRITE_SIZE + 1});
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::SizeTooLarge);
}

TEST_F(MemoryTest, write_bytes_ZeroBytes)
{
    std::byte target[4] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
    std::byte source[1] = {std::byte{0x00}};

    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, 0});
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0xAA});
}

TEST_F(MemoryTest, write_bytes_Success)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);
    std::byte source[] = {std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, 3});
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0x90});
    EXPECT_EQ(target[1], std::byte{0x90});
    EXPECT_EQ(target[2], std::byte{0x90});

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, write_bytes_PageReadOnly)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);
    std::byte source[] = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    // v4 write_bytes auto-unprotects a read-only page, so the write SUCCEEDS and the bytes change.
    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, sizeof(source)});
    EXPECT_TRUE(result.has_value());

    if (result.has_value())
    {
        EXPECT_EQ(target[0], std::byte{0xDE});
        EXPECT_EQ(target[1], std::byte{0xAD});
        EXPECT_EQ(target[2], std::byte{0xBE});
        EXPECT_EQ(target[3], std::byte{0xEF});
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteBytesInvalidatesCache)
{
    memory::shutdown_cache();
    (void)memory::init_cache(32, 60000, 4);

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte *target = reinterpret_cast<std::byte *>(mem);

    EXPECT_TRUE(is_readable(target, 64));
    EXPECT_TRUE(is_writable(target, 64));

    std::byte source[] = {std::byte{0x90}, std::byte{0x91}, std::byte{0x92}};
    auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source, sizeof(source)});
    EXPECT_TRUE(result.has_value());

    EXPECT_TRUE(is_readable(target, 64));
    EXPECT_TRUE(is_writable(target, 64));

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteBytesToReadOnlyMemory_ExercisesVirtualProtect)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    std::byte data[] = {std::byte{0xDE}, std::byte{0xAD}};
    auto result =
        memory::write_bytes(Address{static_cast<std::byte *>(mem)}, std::span<const std::byte>{data, sizeof(data)});

    if (result.has_value())
    {
        EXPECT_EQ(std::memcmp(mem, data, sizeof(data)), 0);
    }
    else
    {
        EXPECT_EQ(result.error().code, ErrorCode::ProtectionChangeFailed);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteBytesToExecuteReadPage_ExercisesFlushCache)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);

    std::byte data[] = {std::byte{0x90}, std::byte{0x90}, std::byte{0xC3}};
    auto result =
        memory::write_bytes(Address{static_cast<std::byte *>(mem)}, std::span<const std::byte>{data, sizeof(data)});
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(std::memcmp(mem, data, sizeof(data)), 0);

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteBytesInvalidatesAndRevalidates)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);

    // Prime the cache
    EXPECT_TRUE(is_readable(mem, 4));

    // Write invalidates cached region
    std::byte data[] = {std::byte{0xAA}, std::byte{0xBB}};
    auto result =
        memory::write_bytes(Address{static_cast<std::byte *>(mem)}, std::span<const std::byte>{data, sizeof(data)});
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(is_readable(mem, 4));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// The guarded writes target already-writable data. These fixtures need neither a protection transition nor
// instruction-cache maintenance.

TEST_F(MemoryTest, SehWrite_TypedRoundTripsToLocal)
{
    uint64_t target = 0;
    const uint64_t expected = 0x1122334455667788ull;

    EXPECT_TRUE(memory::write<uint64_t>(Address{reinterpret_cast<uintptr_t>(&target)}, expected).has_value());
    EXPECT_EQ(target, expected);

    // Read it back through the guarded read primitive to confirm the byte image matches.
    const auto value = memory::read<uint64_t>(Address{reinterpret_cast<uintptr_t>(&target)});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, expected);
}

TEST_F(MemoryTest, SehWriteBytes_RoundTripsToHeap)
{
    auto buffer = std::make_unique<std::byte[]>(16);
    std::memset(buffer.get(), 0, 16);
    const std::byte source[] = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};

    EXPECT_TRUE(
        memory::write_bytes(Address{buffer.get()}, std::span<const std::byte>{source, sizeof(source)}).has_value()
    );

    for (size_t i = 0; i < sizeof(source); ++i)
    {
        EXPECT_EQ(buffer[i], source[i]);
    }
    // Bytes beyond the written span are untouched.
    EXPECT_EQ(buffer[sizeof(source)], std::byte{0x00});
}

TEST_F(MemoryTest, SehWriteBytes_ZeroBytesIsNoOpSuccess)
{
    uint64_t target = 0xFEEDFACEull;
    const uint64_t source = 0x0;

    // Zero-byte write is a no-op success that leaves the target unchanged.
    EXPECT_TRUE(
        memory::write_bytes(
            Address{reinterpret_cast<uintptr_t>(&target)},
            std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), 0}
        )
            .has_value()
    );
    EXPECT_EQ(target, 0xFEEDFACEull);
}

TEST_F(MemoryTest, SehWriteBytes_NullSourceReturnsFalse)
{
    uint64_t target = 0xFEEDFACEull;

    // nullptr source is rejected without a write.
    EXPECT_FALSE(
        memory::write_bytes(
            Address{reinterpret_cast<uintptr_t>(&target)},
            std::span<const std::byte>{static_cast<const std::byte *>(nullptr), sizeof(target)}
        )
            .has_value()
    );
    EXPECT_EQ(target, 0xFEEDFACEull);
}

TEST_F(MemoryTest, SehWriteBytes_LowAddressReturnsFalse)
{
    const uint32_t source = 0x11223344u;

    // An address below 0x10000 (the Windows reserved low range) is rejected without a write and must not crash.
    EXPECT_FALSE(
        memory::write_bytes(
            Address{static_cast<uintptr_t>(0x100)},
            std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)}
        )
            .has_value()
    );
}

// BEHAVIOR FLIP (v3 -> v4): v4 write_bytes auto-unprotects, so a write into a committed PAGE_READONLY page now SUCCEEDS
// and the bytes change, where v3 fails-closed. The page is held until TearDown via the local scope so a released VA
// cannot be remapped and the result stays deterministic.
TEST_F(MemoryTest, WriteBytes_ReadOnlyPageUnprotectsAndSucceeds)
{
    // A page seeded as PAGE_READWRITE so we can plant a known sentinel, then flipped to PAGE_READONLY before the write.
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);

    constexpr uint32_t SENTINEL = 0xA5A5A5A5u;
    *reinterpret_cast<uint32_t *>(page) = SENTINEL;

    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(page, 4096, PAGE_READONLY, &old_protect), 0);

    const uint32_t source = 0xDEADBEEFu;
    // The guarded write takes the slow path: change protection to writable, copy, restore. It SUCCEEDS.
    auto result = memory::write_bytes(
        Address{page},
        std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)}
    );
    EXPECT_TRUE(result.has_value());

    // The byte image changed to the new value.
    EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), source);

    VirtualFree(page, 0, MEM_RELEASE);
}

// The committed PAGE_NOACCESS page permits VirtualProtect, so write_bytes can use its protection fallback. Unmapped
// pages cannot support that fallback.
TEST_F(MemoryTest, WriteBytes_NoAccessPageUnprotectsAndSucceeds)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(page, nullptr);

    const uint32_t source = 0xDEADBEEFu;
    auto result = memory::write_bytes(
        Address{page},
        std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)}
    );
    EXPECT_TRUE(result.has_value());

    // Read the bytes back (the page is writable post-restore-to-NOACCESS only on the page itself, so verify via a
    // temporary reprotect to readable).
    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(page, 4096, PAGE_READWRITE, &old_protect), 0);
    EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), source);

    VirtualFree(page, 0, MEM_RELEASE);
}

// write_in_place cannot re-protect a target. These cases distinguish it from the write_bytes fallback.
TEST_F(MemoryTest, WriteInPlace_WritableTargetSucceeds)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);

    const uint32_t source = 0xDEADBEEFu;
    auto result = memory::write_in_place(
        Address{page},
        std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)}
    );
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), source);

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteInPlace_ReadOnlyPageFailsClosedWithoutUnprotecting)
{
    // The capability that distinguishes write_in_place from write_bytes: a read-only target is REJECTED and the bytes
    // are left untouched (no silent unprotect-and-write).
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(page, nullptr);

    constexpr uint32_t SENTINEL = 0xA5A5A5A5u;
    *reinterpret_cast<uint32_t *>(page) = SENTINEL;

    DWORD old_protect = 0;
    ASSERT_NE(VirtualProtect(page, 4096, PAGE_READONLY, &old_protect), 0);

    const uint32_t source = 0xDEADBEEFu;
    auto result = memory::write_in_place(
        Address{page},
        std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)}
    );
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::WriteFaulted);

    // Reprotect to readable and confirm the sentinel is intact: the write never landed.
    ASSERT_NE(VirtualProtect(page, 4096, PAGE_READWRITE, &old_protect), 0);
    EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), SENTINEL);

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteInPlace_NoAccessPageFailsClosed)
{
    // Contrast with WriteBytes_NoAccessPageUnprotectsAndSucceeds: write_in_place changes no protection, so a committed
    // no-access page is rejected rather than reprotected and written.
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_NE(page, nullptr);

    const uint32_t source = 0xDEADBEEFu;
    auto result = memory::write_in_place(
        Address{page},
        std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)}
    );
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::WriteFaulted);

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, WriteInPlace_TypedRoundTripsToWritableLocal)
{
    uint64_t target = 0;
    const uint64_t value = 0x0123456789ABCDEFull;
    auto result = memory::write_in_place(Address{&target}, value);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(target, value);
}

TEST_F(MemoryTest, WriteInPlace_NullTargetReturnsError)
{
    const uint32_t source = 0;
    auto result = memory::write_in_place(
        Address{},
        std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), sizeof(source)}
    );
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullTargetAddress);
}

TEST_F(MemoryTest, WriteInPlace_NullSourceReturnsError)
{
    uint32_t target = 0;
    auto result = memory::write_in_place(
        Address{&target},
        std::span<const std::byte>{static_cast<const std::byte *>(nullptr), 4}
    );
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullSourceBytes);
}

TEST_F(MemoryTest, WriteInPlace_ZeroBytesIsNoOpSuccess)
{
    uint32_t target = 0x11111111u;
    auto result = memory::write_in_place(Address{&target}, std::span<const std::byte>{});
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(target, 0x11111111u);
}

// The write_in_place half of the null-before-empty pair test (see write_bytes_NullTargetEmptySpanIsNullTargetAddress).
TEST_F(MemoryTest, WriteInPlace_NullTargetEmptySpanIsNullTargetAddress)
{
    auto result = memory::write_in_place(Address{nullptr}, std::span<const std::byte>{});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NullTargetAddress);
}

// ProtectGuard lifecycle.
TEST_F(MemoryTest, ProtectGuard_MakeOnReadOnlyPageSucceedsAndRestores)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(page, nullptr);

    {
        auto guard = memory::ProtectGuard::make(Region{Address{page}, 4096}, Prot::RW);
        ASSERT_TRUE(guard.has_value());
        EXPECT_TRUE(static_cast<bool>(*guard));

        // While the guard is armed the page is writable: a plain store does not fault.
        *reinterpret_cast<uint32_t *>(page) = 0xC0FFEEu;
        EXPECT_EQ(*reinterpret_cast<uint32_t *>(page), 0xC0FFEEu);
    } // guard destructor restores PAGE_READONLY here

    // After restoration the page is read-only again: is_writable must report false.
    EXPECT_FALSE(is_writable(page, 4));

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ProtectGuard_MoveOnlyMovedFromIsFalsy)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(page, nullptr);

    auto made = memory::ProtectGuard::make(Region{Address{page}, 4096}, Prot::RW);
    ASSERT_TRUE(made.has_value());

    memory::ProtectGuard original = std::move(*made);
    EXPECT_TRUE(static_cast<bool>(original));

    memory::ProtectGuard moved = std::move(original);
    // The moved-from guard must remain inert.
    EXPECT_FALSE(static_cast<bool>(original));
    EXPECT_TRUE(static_cast<bool>(moved));

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ProtectGuard_ReleaseLeavesProtectionChanged)
{
    void *page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(page, nullptr);

    {
        auto guard = memory::ProtectGuard::make(Region{Address{page}, 4096}, Prot::RW);
        ASSERT_TRUE(guard.has_value());
        EXPECT_TRUE(static_cast<bool>(*guard));
        guard->release();
        // After release() the guard is disarmed and the destructor will NOT restore the original protection.
        EXPECT_FALSE(static_cast<bool>(*guard));
    }

    // Protection was left changed to RW, so the page is still writable after the guard's scope ended.
    EXPECT_TRUE(is_writable(page, 4));

    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_F(MemoryTest, ProtectGuard_MakeOnEmptyRegionFails)
{
    auto guard = memory::ProtectGuard::make(Region{}, Prot::RW);
    ASSERT_FALSE(guard.has_value());
    EXPECT_EQ(guard.error().code, ErrorCode::ProtectionChangeFailed);
}

// The guarded slow copy starts with PAGE_READONLY. Its success must restore that same protection.
TEST_F(MemoryTest, WriteBytes_ReadOnlyPageRestoresProtectionAfterSlowPath)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);
    auto *target = static_cast<std::byte *>(mem);

    const std::array<std::byte, 4> source{std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
    const auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(target[0], std::byte{0x11});
    EXPECT_EQ(target[3], std::byte{0x44});

    // The captured original protection is restored after the guarded copy: the page is read-only again.
    EXPECT_EQ(current_page_protection(mem), static_cast<DWORD>(PAGE_READONLY));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// The executable page starts at PAGE_EXECUTE_READ. The slow path must restore that protection after its temporary write
// access.
TEST_F(MemoryTest, WriteBytes_ExecutablePageRestoresExecuteProtection)
{
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    ASSERT_NE(mem, nullptr);
    auto *target = static_cast<std::byte *>(mem);

    const std::array<std::byte, 3> source{std::byte{0x90}, std::byte{0x90}, std::byte{0xC3}};
    const auto result = memory::write_bytes(Address{target}, std::span<const std::byte>{source});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(target[2], std::byte{0xC3});

    EXPECT_EQ(current_page_protection(mem), static_cast<DWORD>(PAGE_EXECUTE_READ));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// write_in_place rejects an oversized span with SizeTooLarge, matching write_bytes' cap. The source pointer is never
// dereferenced (the cap is checked before any copy), so an obviously-wrong length is a clean rejection.
TEST_F(MemoryTest, WriteInPlace_SizeTooLarge)
{
    std::array<std::byte, 16> target{};
    const std::byte source_byte{0xAB};
    const auto result = memory::write_in_place(
        Address{target.data()},
        std::span<const std::byte>{&source_byte, memory::MAX_WRITE_SIZE + 1}
    );
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::SizeTooLarge);
}

// T-OVERLAP: every public byte-copy surface refuses a caller span that intersects its target range, in either
// direction, before any byte moves. Exact alias, both partial directions, a disjoint control, and address-wrap
// rejection run per affected API. See ErrorCode::OverlappingRanges for the contract.

namespace
{
    // One 32-byte writable arena serves every overlap case. Distinct bytes expose any copy that precedes rejection.
    struct OverlapArena
    {
        OverlapArena() noexcept
        {
            for (std::size_t i = 0; i < bytes.size(); ++i)
            {
                bytes[i] = static_cast<std::byte>(i + 1);
            }
        }

        alignas(16) std::array<std::byte, 32> bytes{};
        [[nodiscard]] std::byte *at(std::size_t index) noexcept { return bytes.data() + index; }
    };

    class GuardedAccessObservationScope final
    {
    public:
        GuardedAccessObservationScope() noexcept { DetourModKit::detail::reset_guarded_access_observation_for_test(); }
        ~GuardedAccessObservationScope() noexcept { DetourModKit::detail::stop_guarded_access_observation_for_test(); }
        GuardedAccessObservationScope(const GuardedAccessObservationScope &) = delete;
        GuardedAccessObservationScope &operator=(const GuardedAccessObservationScope &) = delete;
        GuardedAccessObservationScope(GuardedAccessObservationScope &&) = delete;
        GuardedAccessObservationScope &operator=(GuardedAccessObservationScope &&) = delete;
    };

    template <typename Operation>
    void expect_overlap_rejected_without_access(
        OverlapArena &arena,
        const char *where,
        std::uintptr_t target,
        Operation operation
    )
    {
        const auto before = arena.bytes;
        const GuardedAccessObservationScope observation_scope;
        DetourModKit::detail::reset_instruction_flush_observation_for_test();

        const Result<void> result = operation();
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::OverlappingRanges);
        EXPECT_STREQ(result.error().where, where);
        EXPECT_EQ(result.error().detail, target);

        const auto access = DetourModKit::detail::guarded_access_observation_for_test();
        EXPECT_EQ(access.read_calls, 0u);
        EXPECT_EQ(access.write_calls, 0u);
        EXPECT_EQ(access.protection_calls, 0u);
        EXPECT_EQ(DetourModKit::detail::instruction_flush_observation_for_test().call_count, 0u);
        EXPECT_EQ(arena.bytes, before);
    }
} // namespace

TEST_F(MemoryTest, Overlap_ReadInto_RejectsAliasAndBothPartials)
{
    OverlapArena arena;
    // Exact alias.
    expect_overlap_rejected_without_access(
        arena,
        "memory::read_into",
        reinterpret_cast<std::uintptr_t>(arena.at(0)),
        [&] { return memory::read_into(Address{arena.at(0)}, std::span<std::byte>{arena.at(0), 8}); }
    );
    // Destination begins inside the source range.
    expect_overlap_rejected_without_access(
        arena,
        "memory::read_into",
        reinterpret_cast<std::uintptr_t>(arena.at(0)),
        [&] { return memory::read_into(Address{arena.at(0)}, std::span<std::byte>{arena.at(4), 8}); }
    );
    // Source begins inside the destination range.
    expect_overlap_rejected_without_access(
        arena,
        "memory::read_into",
        reinterpret_cast<std::uintptr_t>(arena.at(4)),
        [&] { return memory::read_into(Address{arena.at(4)}, std::span<std::byte>{arena.at(0), 8}); }
    );
    // Half-open adjacency is disjoint and must succeed.
    arena.bytes[0] = std::byte{0x5A};
    auto disjoint = memory::read_into(Address{arena.at(0)}, std::span<std::byte>{arena.at(8), 8});
    ASSERT_TRUE(disjoint.has_value());
    EXPECT_EQ(arena.bytes[8], std::byte{0x5A});
}

TEST_F(MemoryTest, Overlap_WriteBytes_RejectsAliasAndBothPartials)
{
    OverlapArena arena;
    expect_overlap_rejected_without_access(
        arena,
        "memory::write_bytes",
        reinterpret_cast<std::uintptr_t>(arena.at(0)),
        [&] { return memory::write_bytes(Address{arena.at(0)}, std::span<const std::byte>{arena.at(0), 8}); }
    );
    expect_overlap_rejected_without_access(
        arena,
        "memory::write_bytes",
        reinterpret_cast<std::uintptr_t>(arena.at(0)),
        [&] { return memory::write_bytes(Address{arena.at(0)}, std::span<const std::byte>{arena.at(4), 8}); }
    );
    expect_overlap_rejected_without_access(
        arena,
        "memory::write_bytes",
        reinterpret_cast<std::uintptr_t>(arena.at(4)),
        [&] { return memory::write_bytes(Address{arena.at(4)}, std::span<const std::byte>{arena.at(0), 8}); }
    );
    arena.bytes[8] = std::byte{0x77};
    auto disjoint = memory::write_bytes(Address{arena.at(0)}, std::span<const std::byte>{arena.at(8), 8});
    ASSERT_TRUE(disjoint.has_value());
    EXPECT_EQ(arena.bytes[0], std::byte{0x77});
}

TEST_F(MemoryTest, Overlap_WriteInPlace_RejectsAliasAndBothPartials)
{
    OverlapArena arena;
    expect_overlap_rejected_without_access(
        arena,
        "memory::write_in_place",
        reinterpret_cast<std::uintptr_t>(arena.at(0)),
        [&] { return memory::write_in_place(Address{arena.at(0)}, std::span<const std::byte>{arena.at(0), 8}); }
    );
    expect_overlap_rejected_without_access(
        arena,
        "memory::write_in_place",
        reinterpret_cast<std::uintptr_t>(arena.at(0)),
        [&] { return memory::write_in_place(Address{arena.at(0)}, std::span<const std::byte>{arena.at(4), 8}); }
    );
    expect_overlap_rejected_without_access(
        arena,
        "memory::write_in_place",
        reinterpret_cast<std::uintptr_t>(arena.at(4)),
        [&] { return memory::write_in_place(Address{arena.at(4)}, std::span<const std::byte>{arena.at(0), 8}); }
    );
    arena.bytes[8] = std::byte{0x33};
    auto disjoint = memory::write_in_place(Address{arena.at(0)}, std::span<const std::byte>{arena.at(8), 8});
    ASSERT_TRUE(disjoint.has_value());
    EXPECT_EQ(arena.bytes[0], std::byte{0x33});
}

TEST_F(MemoryTest, Overlap_PatchCode_RejectsAliasAndBothPartials)
{
    OverlapArena arena;
    expect_overlap_rejected_without_access(
        arena,
        "memory::patch_code",
        reinterpret_cast<std::uintptr_t>(arena.at(0)),
        [&] { return memory::patch_code(Address{arena.at(0)}, std::span<const std::byte>{arena.at(0), 8}); }
    );
    expect_overlap_rejected_without_access(
        arena,
        "memory::patch_code",
        reinterpret_cast<std::uintptr_t>(arena.at(0)),
        [&] { return memory::patch_code(Address{arena.at(0)}, std::span<const std::byte>{arena.at(4), 8}); }
    );
    expect_overlap_rejected_without_access(
        arena,
        "memory::patch_code",
        reinterpret_cast<std::uintptr_t>(arena.at(4)),
        [&] { return memory::patch_code(Address{arena.at(4)}, std::span<const std::byte>{arena.at(0), 8}); }
    );
    arena.bytes[8] = std::byte{0xC3};
    auto disjoint = memory::patch_code(Address{arena.at(0)}, std::span<const std::byte>{arena.at(8), 8});
    ASSERT_TRUE(disjoint.has_value());
    EXPECT_EQ(arena.bytes[0], std::byte{0xC3});
}

TEST_F(MemoryTest, Overlap_EmptyPatchAliasIsANoOp)
{
    OverlapArena arena;
    const auto before = arena.bytes;
    const GuardedAccessObservationScope observation_scope;
    DetourModKit::detail::reset_instruction_flush_observation_for_test();

    const auto result =
        memory::patch_code(Address{arena.at(0)}, std::span<const std::byte>{arena.at(0), std::size_t{0}});
    ASSERT_TRUE(result.has_value());
    const auto access = DetourModKit::detail::guarded_access_observation_for_test();
    EXPECT_EQ(access.read_calls, 0u);
    EXPECT_EQ(access.write_calls, 0u);
    EXPECT_EQ(access.protection_calls, 0u);
    EXPECT_EQ(DetourModKit::detail::instruction_flush_observation_for_test().call_count, 0u);
    EXPECT_EQ(arena.bytes, before);
}

TEST_F(MemoryTest, Overlap_WrapAddressesStayFailClosed)
{
    // This runtime case proves the engine rejects a target whose end crosses the address-space boundary. The adjacent
    // compile-time assertions in memory_access.cpp separately discriminate the overlap predicate from endpoint sums.
    OverlapArena arena;
    const Address wrap_target{std::numeric_limits<std::uintptr_t>::max() - 3};

    auto read_result = memory::read_into(wrap_target, std::span<std::byte>{arena.at(0), 8});
    ASSERT_FALSE(read_result.has_value());
    EXPECT_EQ(read_result.error().code, ErrorCode::ReadFaulted);

    auto write_result = memory::write_bytes(wrap_target, std::span<const std::byte>{arena.at(0), 8});
    ASSERT_FALSE(write_result.has_value());
    EXPECT_NE(write_result.error().code, ErrorCode::OverlappingRanges);

    auto in_place_result = memory::write_in_place(wrap_target, std::span<const std::byte>{arena.at(0), 8});
    ASSERT_FALSE(in_place_result.has_value());
    EXPECT_NE(in_place_result.error().code, ErrorCode::OverlappingRanges);

    auto patch_result = memory::patch_code(wrap_target, std::span<const std::byte>{arena.at(0), 8});
    ASSERT_FALSE(patch_result.has_value());
    EXPECT_NE(patch_result.error().code, ErrorCode::OverlappingRanges);
}

// ProtectGuard::make allocates before any protection change. The injected failure must report OutOfMemory with the
// original protection intact.
TEST_F(MemoryTest, ProtectGuard_BadAllocDoesNotLeakProtection)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    bool has_value = true;
    ErrorCode code = ErrorCode::ProtectionChangeFailed; // sentinel distinct from the expected OutOfMemory
    {
        // The first failed allocation is the make() pimpl. GoogleTest macros allocate, so none can run inside the
        // poisoned window.
        dmk_test::AllocFailScope fail{0};
        auto guard = memory::ProtectGuard::make(Region{Address{mem}, 4096}, Prot::RW);
        has_value = guard.has_value();
        if (!has_value)
        {
            code = guard.error().code;
        }
    }

    EXPECT_FALSE(has_value);
    EXPECT_EQ(code, ErrorCode::OutOfMemory);
    // The protection change never ran, so the page is still read-only: no leaked PAGE_READWRITE.
    EXPECT_EQ(current_page_protection(mem), static_cast<DWORD>(PAGE_READONLY));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// ProtectGuard::make and ~ProtectGuard each invalidate the protection cache for the guarded span, so a stale
// is_writable snapshot cannot survive the protection change or its restoration.
TEST_F(MemoryTest, ProtectGuard_MakeAndDestroyInvalidateCache)
{
    memory::shutdown_cache();
    ASSERT_TRUE(memory::init_cache(16, 60000));

    void *mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem, nullptr);

    // Prime the cache: the read-only page caches "not writable".
    EXPECT_FALSE(is_writable(mem, 1));

    {
        auto guard = memory::ProtectGuard::make(Region{Address{mem}, 4096}, Prot::RW);
        ASSERT_TRUE(guard.has_value());
        // make() dropped the stale entry, so a re-query sees the now-writable page rather than the cached "no".
        EXPECT_TRUE(is_writable(mem, 1));
    }

    // ~ProtectGuard restored PAGE_READONLY and invalidated again, so is_writable re-queries and sees read-only.
    EXPECT_FALSE(is_writable(mem, 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// Move assignment restores the destination's region before it adopts the source. Neither protection change can lose its
// owner.
TEST_F(MemoryTest, ProtectGuard_MoveAssignRestoresReplacedRegion)
{
    void *mem1 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    void *mem2 = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ASSERT_NE(mem1, nullptr);
    ASSERT_NE(mem2, nullptr);

    auto r1 = memory::ProtectGuard::make(Region{Address{mem1}, 4096}, Prot::RW);
    auto r2 = memory::ProtectGuard::make(Region{Address{mem2}, 4096}, Prot::RW);
    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(current_page_protection(mem1), static_cast<DWORD>(PAGE_READWRITE));
    EXPECT_EQ(current_page_protection(mem2), static_cast<DWORD>(PAGE_READWRITE));

    {
        memory::ProtectGuard g1 = std::move(*r1);
        memory::ProtectGuard g2 = std::move(*r2);

        // Move-assign: g1 restores its own region (mem1 -> read-only) before adopting g2's (mem2 stays writable).
        g1 = std::move(g2);
        EXPECT_EQ(current_page_protection(mem1), static_cast<DWORD>(PAGE_READONLY));
        EXPECT_EQ(current_page_protection(mem2), static_cast<DWORD>(PAGE_READWRITE));
    } // g1 (now owning mem2) restores mem2 -> read-only on destruction

    EXPECT_EQ(current_page_protection(mem1), static_cast<DWORD>(PAGE_READONLY));
    EXPECT_EQ(current_page_protection(mem2), static_cast<DWORD>(PAGE_READONLY));

    VirtualFree(mem1, 0, MEM_RELEASE);
    VirtualFree(mem2, 0, MEM_RELEASE);
}

// A view carries a pointer and length rather than target bytes. The typed overload must refuse that object
// representation.
namespace
{
    template <class Arg>
    concept WriteCallable = requires(Address a, Arg v) { memory::write(a, v); };
    template <class Arg>
    concept WriteInPlaceCallable = requires(Address a, Arg v) { memory::write_in_place(a, v); };
    // An explicit template argument leaves only the typed template as a candidate, so this tests its constraint alone.
    template <class Arg>
    concept TypedWriteInPlaceCallable = requires(Address a, const Arg &v) { memory::write_in_place<Arg>(a, v); };

    using ByteSubrange = std::ranges::subrange<std::byte *>;
    using ByteArrayRef = std::ranges::ref_view<std::byte[4]>;

    // write has no view sink at all, so every non-owning view is intentionally not callable through it.
    static_assert(!WriteCallable<std::span<std::byte>>, "write(addr, span<byte>) must be ill-formed; use write_bytes");
    static_assert(!WriteCallable<std::span<const std::byte>>, "write(addr, span<const byte>) must be ill-formed");
    static_assert(!WriteCallable<std::span<int>>, "write(addr, span<int>) must be ill-formed, not a scalar bit-copy");
    static_assert(!WriteCallable<std::string_view>, "write(addr, string_view) must be ill-formed");
    static_assert(!WriteCallable<std::wstring_view>, "write(addr, wstring_view) must be ill-formed");
    static_assert(!WriteCallable<std::initializer_list<std::byte>>, "write(addr, initializer_list) must be ill-formed");
    static_assert(!WriteCallable<ByteSubrange>, "write(addr, subrange) must be ill-formed");
    static_assert(!WriteCallable<ByteArrayRef>, "write(addr, ref_view) must be ill-formed");
    // A genuine trivially-copyable value still binds the typed template.
    static_assert(WriteCallable<int>, "write(addr, value) must remain valid");
    static_assert(WriteCallable<std::array<std::byte, 4>>, "write(addr, array-of-bytes) is a value, not a span");

    // The typed write_in_place template rejects the same set. A byte range view still reaches the byte-span sink
    // through its implicit span conversion (WriteInPlace_ByteRangeViewsWriteViewedBytes).
    static_assert(!TypedWriteInPlaceCallable<std::initializer_list<std::byte>>);
    static_assert(!TypedWriteInPlaceCallable<ByteSubrange>);
    static_assert(!TypedWriteInPlaceCallable<ByteArrayRef>);
    static_assert(!TypedWriteInPlaceCallable<std::wstring_view>);
    static_assert(TypedWriteInPlaceCallable<int>);
    static_assert(TypedWriteInPlaceCallable<std::array<std::byte, 4>>);

    // The trait covers owning_view too, and no owning container or array.
    static_assert(detail::is_non_owning_view_v<std::span<const std::byte, 4>>);
    static_assert(detail::is_non_owning_view_v<std::ranges::owning_view<std::vector<std::byte>>>);
    static_assert(!detail::is_non_owning_view_v<std::vector<std::byte>>);
    static_assert(!detail::is_non_owning_view_v<std::string>);
    static_assert(!detail::is_non_owning_view_v<std::byte[4]>);

    // Byte spans reach the byte-span sink. Non-byte spans and string_view must fail the typed constraint instead of
    // copy their view representation.
    static_assert(WriteInPlaceCallable<std::span<std::byte>>, "write_in_place(addr, span<byte>) must select the sink");
    static_assert(WriteInPlaceCallable<std::span<const std::byte>>);
    static_assert(!WriteInPlaceCallable<std::span<int>>, "write_in_place(addr, span<int>) must be ill-formed");
    static_assert(!WriteInPlaceCallable<std::string_view>, "write_in_place(addr, string_view) must be ill-formed");
    static_assert(WriteInPlaceCallable<int>, "write_in_place(addr, value) must remain valid");

    // Explicit const std::span<std::byte> reaches remove_cvref_t in the overload constraint. Deduction cannot reach
    // that cv-qualified path, and the non-template byte-span overload is excluded.
    template <class Arg>
    concept WriteInPlaceExplicitCallable =
        requires(Address a, std::span<std::byte> v) { memory::write_in_place<Arg>(a, v); };
    static_assert(
        !WriteInPlaceExplicitCallable<const std::span<std::byte>>,
        "write_in_place<const std::span<std::byte>> must be ill-formed via remove_cvref_t normalization"
    );

    // Explicit template arguments can carry cv/ref qualifiers. remove_cvref_t must expose the underlying view to the
    // overload constraint.
    static_assert(
        !detail::is_non_owning_view_v<const std::span<std::byte>>,
        "the bare trait does not see through const, so the constraint must normalize the type"
    );
    static_assert(
        detail::is_non_owning_view_v<std::remove_cvref_t<const std::span<std::byte>>>,
        "the normalization the constraints apply recognizes a const byte span"
    );
    static_assert(
        detail::is_non_owning_view_v<std::remove_cvref_t<std::span<int> &>>,
        "the normalization also strips a reference qualifier and matches any element type"
    );
    static_assert(detail::is_non_owning_view_v<std::string_view>, "a string_view is a non-owning view");
    static_assert(!detail::is_non_owning_view_v<int>, "a scalar is not a non-owning view");
} // namespace

TEST_F(MemoryTest, WriteInPlace_MutableByteSpanWritesViewedBytes)
{
    std::array<std::byte, 8> target{};
    std::array<std::byte, 4> source{std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

    const auto result = memory::write_in_place(Address{target.data()}, std::span<std::byte>{source});
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(target[0], std::byte{0x11});
    EXPECT_EQ(target[1], std::byte{0x22});
    EXPECT_EQ(target[2], std::byte{0x33});
    EXPECT_EQ(target[3], std::byte{0x44});
    EXPECT_EQ(target[4], std::byte{0x00});
}

// A subrange or ref_view over bytes converts to the byte-span sink, so the target receives the viewed bytes. A typed
// match stores the view object instead: two pointers for the subrange, one for the ref_view.
TEST_F(MemoryTest, WriteInPlace_ByteRangeViewsWriteViewedBytes)
{
    std::byte source[4] = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
    const std::array<std::byte, 4> expected{std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};

    std::array<std::byte, 32> subrange_target{};
    ASSERT_TRUE(
        memory::write_in_place(Address{subrange_target.data()}, ByteSubrange{std::begin(source), std::end(source)})
            .has_value()
    );
    std::array<std::byte, 32> ref_target{};
    ASSERT_TRUE(memory::write_in_place(Address{ref_target.data()}, ByteArrayRef{source}).has_value());

    for (const std::array<std::byte, 32> *target : {&subrange_target, &ref_target})
    {
        EXPECT_TRUE(std::equal(expected.begin(), expected.end(), target->begin()));
        EXPECT_TRUE(
            std::all_of(target->begin() + 4, target->end(), [](std::byte value) { return value == std::byte{}; })
        );
    }
}

// The guard spans adjacent read-only and executable regions. Each region must regain its own protection.
TEST_F(MemoryTest, ProtectGuard_MultiRegionRestoresEachRegionsOwnProtection)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;

    auto *base = static_cast<std::byte *>(VirtualAlloc(nullptr, 2 * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);
    DWORD old = 0;
    ASSERT_TRUE(VirtualProtect(base, page, PAGE_READONLY, &old));
    ASSERT_TRUE(VirtualProtect(base + page, page, PAGE_EXECUTE_READ, &old));

    {
        // One guard spanning both differently-protected regions makes the whole span writable.
        auto guard = memory::ProtectGuard::make(Region{Address{base}, 2 * page}, Prot::RW);
        ASSERT_TRUE(guard.has_value());
        EXPECT_EQ(current_page_protection(base), static_cast<DWORD>(PAGE_READWRITE));
        EXPECT_EQ(current_page_protection(base + page), static_cast<DWORD>(PAGE_READWRITE));
        // Both regions are writable while the guard is armed: a plain store faults neither.
        base[0] = std::byte{0x5A};
        base[page] = std::byte{0xA5};
    } // guard destructor restores each region to its own captured protection

    EXPECT_EQ(current_page_protection(base), static_cast<DWORD>(PAGE_READONLY));
    EXPECT_EQ(current_page_protection(base + page), static_cast<DWORD>(PAGE_EXECUTE_READ));

    VirtualFree(base, 0, MEM_RELEASE);
}

// The cross-region write restores each prior protection separately. A uniform page cannot expose an executable tail
// flattened to PAGE_READONLY.
TEST_F(MemoryTest, WriteBytes_AcrossProtectionSeamRestoresEachRegion)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;

    auto *base = static_cast<std::byte *>(VirtualAlloc(nullptr, 2 * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);
    DWORD old = 0;
    ASSERT_TRUE(VirtualProtect(base, page, PAGE_READONLY, &old));
    ASSERT_TRUE(VirtualProtect(base + page, page, PAGE_EXECUTE_READ, &old));

    // Straddle the seam: two bytes in the read-only page's tail, two in the executable page's head.
    const std::size_t split = page - 2;
    const std::array<std::byte, 4> source{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    const auto result = memory::write_bytes(Address{base + split}, std::span<const std::byte>{source});
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(base[split + 0], std::byte{0xDE});
    EXPECT_EQ(base[split + 1], std::byte{0xAD}); // last byte of the read-only page
    EXPECT_EQ(base[page + 0], std::byte{0xBE});  // first byte of the executable page
    EXPECT_EQ(base[page + 1], std::byte{0xEF});

    // Each region is restored to its OWN protection, not a single flattened value.
    EXPECT_EQ(current_page_protection(base), static_cast<DWORD>(PAGE_READONLY));
    EXPECT_EQ(current_page_protection(base + page), static_cast<DWORD>(PAGE_EXECUTE_READ));

    DWORD cleared = 0;
    VirtualProtect(base, 2 * page, PAGE_READWRITE, &cleared);
    VirtualFree(base, 0, MEM_RELEASE);
}

// Alternating page protections create distinct VirtualQuery regions beyond MAX_PROTECTION_SEGMENTS. ProtectGuard::make
// must refuse and restore every page that it already changed.
TEST_F(MemoryTest, ProtectGuard_OverSegmentCapFailsClosedAndRollsBack)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;
    constexpr std::size_t page_count = 96; // comfortably past MAX_PROTECTION_SEGMENTS (64)

    auto *base =
        static_cast<std::byte *>(VirtualAlloc(nullptr, page_count * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(base, nullptr);

    // Alternate protections so adjacent pages stay in separate regions.
    const auto protection_of = [](std::size_t i) -> DWORD
    { return (i % 2 == 0) ? static_cast<DWORD>(PAGE_READONLY) : static_cast<DWORD>(PAGE_EXECUTE_READ); };
    for (std::size_t i = 0; i < page_count; ++i)
    {
        DWORD old = 0;
        ASSERT_TRUE(VirtualProtect(base + i * page, page, protection_of(i), &old));
    }

    // One guard over the whole multi-region span exceeds the segment cap and must fail closed.
    auto guard = memory::ProtectGuard::make(Region{Address{base}, page_count * page}, Prot::RW);
    EXPECT_FALSE(guard.has_value());

    // Rollback must restore each original protection.
    for (std::size_t i = 0; i < page_count; ++i)
    {
        EXPECT_EQ(current_page_protection(base + i * page), protection_of(i));
    }

    DWORD cleared = 0;
    VirtualProtect(base, page_count * page, PAGE_READWRITE, &cleared);
    VirtualFree(base, 0, MEM_RELEASE);
}

namespace
{
    // Non-LIFO teardown must still restore the original protection.
    TEST_F(MemoryTest, MemoryProtectionProof_ReversedTeardownOfOverlappingGuardsRestoresOriginal)
    {
        void *const page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(page, nullptr);
        const Region region{Address{page}, 0x1000};

        auto guard_a = memory::ProtectGuard::make(region, Prot::RW);
        ASSERT_TRUE(guard_a.has_value());
        auto guard_b = memory::ProtectGuard::make(region, Prot::RW);
        ASSERT_TRUE(guard_b.has_value());

        MEMORY_BASIC_INFORMATION mbi{};

        // Release the FIRST-created guard first. The page must stay writable because guard B still holds it changed.
        ASSERT_TRUE(guard_a->restore().has_value());
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READWRITE));

        // Release the last holder: the page returns to its OUTERMOST original (read-only), not guard B's temporary.
        ASSERT_TRUE(guard_b->restore().has_value());
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READONLY));

        VirtualFree(page, 0, MEM_RELEASE);
    }

    TEST_F(MemoryTest, MemoryProtectionProof_InnerGuardRestoresSurvivingGuardsProtection)
    {
        void *const page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(page, nullptr);
        const Region region{Address{page}, 0x1000};

        auto outer = memory::ProtectGuard::make(region, Prot::RW);
        ASSERT_TRUE(outer.has_value());
        auto inner = memory::ProtectGuard::make(region, Prot::R | Prot::X);
        ASSERT_TRUE(inner.has_value());

        MEMORY_BASIC_INFORMATION mbi{};
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_EXECUTE_READ));

        ASSERT_TRUE(inner->restore().has_value());
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READWRITE));

        ASSERT_TRUE(outer->restore().has_value());
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READONLY));
        VirtualFree(page, 0, MEM_RELEASE);
    }

    // A released guard must not leave a phantom ledger entry behind.
    TEST_F(MemoryTest, MemoryProtectionProof_ReleaseDoesNotPoisonLaterGuard)
    {
        void *const page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(page, nullptr);
        const Region region{Address{page}, 0x1000};
        MEMORY_BASIC_INFORMATION mbi{};

        {
            auto released = memory::ProtectGuard::make(region, Prot::RW);
            ASSERT_TRUE(released.has_value());
            released->release(); // The writable page must lose its ledger record.
        }
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READWRITE)) << "release() keeps the change";

        // The released guard contributes no depth. The next guard restores its PAGE_READWRITE baseline.
        {
            auto second = memory::ProtectGuard::make(region, Prot::RWX);
            ASSERT_TRUE(second.has_value());
            EXPECT_TRUE(second->restore().has_value());
        }
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READWRITE));
        VirtualFree(page, 0, MEM_RELEASE);
    }

    // Concurrent overlapping transactions must restore the original after the final release.
    TEST_F(MemoryTest, MemoryProtectionProof_ConcurrentOverlappingGuardsRestoreOriginal)
    {
        void *const page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(page, nullptr);
        const Region region{Address{page}, 0x1000};

        std::atomic<bool> go{false};
        std::atomic<int> failures{0};
        std::vector<std::thread> threads;
        for (int t = 0; t < 4; ++t)
        {
            threads.emplace_back(
                [&, t]
                {
                    const std::size_t offset = static_cast<std::size_t>(t);
                    auto *const bytes = static_cast<volatile unsigned char *>(page);
                    while (!go.load(std::memory_order_acquire))
                    {
                        std::this_thread::yield();
                    }
                    for (int i = 0; i < 300; ++i)
                    {
                        auto guard = memory::ProtectGuard::make(region, Prot::RW);
                        if (!guard.has_value())
                        {
                            failures.fetch_add(1, std::memory_order_relaxed);
                            continue;
                        }
                        bytes[offset] = static_cast<unsigned char>(i);
                        const Result<void> restored = guard->restore();
                        if (!restored.has_value())
                        {
                            failures.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                }
            );
        }
        go.store(true, std::memory_order_release);
        for (std::thread &thread : threads)
        {
            thread.join();
        }
        EXPECT_EQ(failures.load(), 0);

        MEMORY_BASIC_INFORMATION mbi{};
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READONLY));
        VirtualFree(page, 0, MEM_RELEASE);
    }

    // A writable-to-no-access straddle reports the modified prefix honestly.
    TEST_F(MemoryTest, MemoryWriteProof_WritableToUnmappedStraddleReportsPartial)
    {
        std::byte *const base =
            static_cast<std::byte *>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        ASSERT_NE(base, nullptr);
        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(base + 0x1000, 0x1000, PAGE_NOACCESS, &previous), 0);

        constexpr std::size_t start = 0x1000 - 16; // 16 bytes in the writable page, 16 into the no-access page
        base[start - 1] = std::byte{0xAA};         // sentinel just before the target
        std::array<std::byte, 32> src{};
        src.fill(std::byte{0x5A});

        const Result<void> result = memory::write_in_place(Address{base + start}, std::span<const std::byte>{src});
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::WriteMayBePartial);
        EXPECT_EQ(base[start - 1], std::byte{0xAA}) << "no byte before the requested span may be written";

        ASSERT_NE(VirtualProtect(base + 0x1000, 0x1000, PAGE_READWRITE, &previous), 0);
        VirtualFree(base, 0, MEM_RELEASE);
    }

    // An escalating write can reprotect a read-only tail and complete the whole span.
    TEST_F(MemoryTest, MemoryWriteProof_WriteBytesEscalatesAcrossWritableToReadOnlySeam)
    {
        std::byte *const base =
            static_cast<std::byte *>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        ASSERT_NE(base, nullptr);
        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(base + 0x1000, 0x1000, PAGE_READONLY, &previous), 0);

        constexpr std::size_t start = 0x1000 - 16; // 16 bytes in the writable page, 16 in the read-only page
        std::array<std::byte, 32> src{};
        src.fill(std::byte{0x3C});

        const Result<void> result = memory::write_bytes(Address{base + start}, std::span<const std::byte>{src});
        ASSERT_TRUE(result.has_value()) << "write_bytes must escalate and complete across a read-only seam";
        for (std::size_t i = 0; i < 32; ++i)
        {
            EXPECT_EQ(base[start + i], std::byte{0x3C}) << "byte " << i;
        }
        // Each region is restored to its own original protection.
        MEMORY_BASIC_INFORMATION mbi{};
        ASSERT_NE(VirtualQuery(base, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READWRITE));
        ASSERT_NE(VirtualQuery(base + 0x1000, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READONLY));

        VirtualFree(base, 0, MEM_RELEASE);
    }

    // An uncommitted tail cannot be reprotected, so a modified head makes the result partial.
    TEST_F(MemoryTest, MemoryWriteProof_WriteBytesWritableToUnmappedReportsPartial)
    {
        // The second page stays RESERVED and cannot accept access or reprotection. Escalation cannot complete the
        // write.
        std::byte *const base = static_cast<std::byte *>(VirtualAlloc(nullptr, 0x2000, MEM_RESERVE, PAGE_NOACCESS));
        ASSERT_NE(base, nullptr);
        ASSERT_NE(VirtualAlloc(base, 0x1000, MEM_COMMIT, PAGE_READWRITE), nullptr);

        constexpr std::size_t start = 0x1000 - 16;
        std::array<std::byte, 32> src{};
        src.fill(std::byte{0x3C});

        const Result<void> result = memory::write_bytes(Address{base + start}, std::span<const std::byte>{src});
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::WriteMayBePartial);

        VirtualFree(base, 0, MEM_RELEASE);
    }

    // Explicit restoration is observable and idempotent.
    TEST_F(MemoryTest, MemoryProtectGuardProof_ExplicitRestoreIsObservableAndIdempotent)
    {
        void *const page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(page, nullptr);
        auto guard = memory::ProtectGuard::make(Region{Address{page}, 0x1000}, Prot::RW);
        ASSERT_TRUE(guard.has_value());

        MEMORY_BASIC_INFORMATION mbi{};
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READWRITE));

        EXPECT_TRUE(guard->restore().has_value());
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READONLY));

        // Idempotent: a second restore is a success no-op, and the destructor then does nothing.
        EXPECT_TRUE(guard->restore().has_value());
        VirtualFree(page, 0, MEM_RELEASE);
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    TEST_F(MemoryTest, MemoryProtectionProof_PartialSetupRollbackFailureIsObservable)
    {
        std::byte *const base =
            static_cast<std::byte *>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY));
        ASSERT_NE(base, nullptr);
        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(base + 0x1000, 0x1000, PAGE_EXECUTE_READ, &previous), 0);

        // Change page zero, fail the page-one change, then fail page zero's rollback.
        detail::set_virtual_protect_failure_mask((std::uint64_t{1} << 1) | (std::uint64_t{1} << 2));
        const Result<memory::ProtectGuard> guard = memory::ProtectGuard::make(Region{Address{base}, 0x2000}, Prot::RW);
        detail::set_virtual_protect_failure_mask(0);

        ASSERT_FALSE(guard.has_value());
        EXPECT_EQ(guard.error().code, ErrorCode::ProtectionRestoreFailed);

        MEMORY_BASIC_INFORMATION mbi{};
        ASSERT_NE(VirtualQuery(base, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READWRITE));
        ASSERT_NE(VirtualQuery(base + 0x1000, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_EXECUTE_READ));

        ASSERT_NE(VirtualProtect(base, 0x1000, PAGE_READONLY, &previous), 0);
        auto cleanup = memory::ProtectGuard::make(Region{Address{base}, 0x1000}, Prot::RW);
        ASSERT_TRUE(cleanup.has_value());
        EXPECT_TRUE(cleanup->restore().has_value());
        VirtualFree(base, 0, MEM_RELEASE);
    }

    TEST_F(MemoryTest, MemoryProtectGuardProof_ExplicitRestoreFailureIsObservable)
    {
        void *const page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(page, nullptr);
        auto guard = memory::ProtectGuard::make(Region{Address{page}, 0x1000}, Prot::RW);
        ASSERT_TRUE(guard.has_value());

        detail::set_virtual_protect_failure_mask(1);
        const Result<void> restored = guard->restore();
        detail::set_virtual_protect_failure_mask(0);
        ASSERT_FALSE(restored.has_value());
        EXPECT_EQ(restored.error().code, ErrorCode::ProtectionRestoreFailed);

        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(page, 0x1000, PAGE_READONLY, &previous), 0);
        auto cleanup = memory::ProtectGuard::make(Region{Address{page}, 0x1000}, Prot::RW);
        ASSERT_TRUE(cleanup.has_value());
        EXPECT_TRUE(cleanup->restore().has_value());
        VirtualFree(page, 0, MEM_RELEASE);
    }

    TEST_F(MemoryTest, MemoryProtectGuardProof_BestEffortRestoreFailuresAreDiagnosed)
    {
        void *const destructor_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(destructor_page, nullptr);
        detail::reset_restore_diagnostic_count();
        {
            auto guard = memory::ProtectGuard::make(Region{Address{destructor_page}, 0x1000}, Prot::RW);
            ASSERT_TRUE(guard.has_value());
            detail::set_virtual_protect_failure_mask(1);
        }
        detail::set_virtual_protect_failure_mask(0);
        EXPECT_EQ(detail::restore_diagnostic_count(), static_cast<std::size_t>(1));

        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(destructor_page, 0x1000, PAGE_READONLY, &previous), 0);
        auto destructor_cleanup = memory::ProtectGuard::make(Region{Address{destructor_page}, 0x1000}, Prot::RW);
        ASSERT_TRUE(destructor_cleanup.has_value());
        EXPECT_TRUE(destructor_cleanup->restore().has_value());
        VirtualFree(destructor_page, 0, MEM_RELEASE);

        void *const replaced_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        void *const adopted_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(replaced_page, nullptr);
        ASSERT_NE(adopted_page, nullptr);
        auto replaced = memory::ProtectGuard::make(Region{Address{replaced_page}, 0x1000}, Prot::RW);
        auto adopted = memory::ProtectGuard::make(Region{Address{adopted_page}, 0x1000}, Prot::RW);
        ASSERT_TRUE(replaced.has_value());
        ASSERT_TRUE(adopted.has_value());

        detail::reset_restore_diagnostic_count();
        detail::set_virtual_protect_failure_mask(1);
        *replaced = std::move(*adopted);
        detail::set_virtual_protect_failure_mask(0);
        EXPECT_EQ(detail::restore_diagnostic_count(), static_cast<std::size_t>(1));
        EXPECT_TRUE(replaced->restore().has_value());

        ASSERT_NE(VirtualProtect(replaced_page, 0x1000, PAGE_READONLY, &previous), 0);
        auto replaced_cleanup = memory::ProtectGuard::make(Region{Address{replaced_page}, 0x1000}, Prot::RW);
        ASSERT_TRUE(replaced_cleanup.has_value());
        EXPECT_TRUE(replaced_cleanup->restore().has_value());
        VirtualFree(replaced_page, 0, MEM_RELEASE);
        VirtualFree(adopted_page, 0, MEM_RELEASE);
    }

    // A refused restore must still retire its ledger entry. Otherwise, the next guard restores the obsolete baseline.
    TEST_F(MemoryTest, MemoryProtectGuardProof_FailedRestoreDoesNotPoisonDifferentLaterBaseline)
    {
        void *const page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(page, nullptr);

        auto poisoning_guard = memory::ProtectGuard::make(Region{Address{page}, 0x1000}, Prot::RW);
        ASSERT_TRUE(poisoning_guard.has_value());

        detail::set_virtual_protect_failure_mask(1);
        const Result<void> failed_restore = poisoning_guard->restore();
        detail::set_virtual_protect_failure_mask(0);
        ASSERT_FALSE(failed_restore.has_value());
        EXPECT_EQ(failed_restore.error().code, ErrorCode::ProtectionRestoreFailed);

        // Move the page to a baseline that differs from the one the failed restore captured.
        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &previous), 0);

        auto later_guard = memory::ProtectGuard::make(Region{Address{page}, 0x1000}, Prot::RW);
        ASSERT_TRUE(later_guard.has_value());
        EXPECT_TRUE(later_guard->restore().has_value());

        MEMORY_BASIC_INFORMATION mbi{};
        ASSERT_NE(VirtualQuery(page, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_EXECUTE_READ))
            << "the later guard must restore the baseline it captured, not the abandoned entry's original";

        VirtualFree(page, 0, MEM_RELEASE);
    }

    // The test seam makes the changed prefix portable and exact.
    TEST_F(MemoryTest, MemoryWriteProof_ForwardCopySeamRecordsExactPrefix)
    {
        std::byte *const base =
            static_cast<std::byte *>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        ASSERT_NE(base, nullptr);
        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(base + 0x1000, 0x1000, PAGE_NOACCESS, &previous), 0);

        constexpr std::size_t start = 0x1000 - 16;
        std::array<std::byte, 32> src{};
        src.fill(std::byte{0x5A});

        detail::set_forward_copy_seam(true);
        const Result<void> result = memory::write_in_place(Address{base + start}, std::span<const std::byte>{src});
        const std::size_t prefix = detail::last_forward_copy_prefix();
        detail::set_forward_copy_seam(false);

        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::WriteMayBePartial);
        EXPECT_EQ(prefix, static_cast<std::size_t>(16));
        for (std::size_t i = 0; i < 16; ++i)
        {
            EXPECT_EQ(base[start + i], std::byte{0x5A}) << "prefix byte " << i;
        }

        ASSERT_NE(VirtualProtect(base + 0x1000, 0x1000, PAGE_READWRITE, &previous), 0);
        VirtualFree(base, 0, MEM_RELEASE);
    }

    // A partially changed executable prefix must be flushed even when protection setup for the fallback fails.
    TEST_F(MemoryTest, MemoryPatchFaultProof_PartialExecutableWriteFlushesChangedPrefix)
    {
        constexpr std::size_t page_size = 0x1000;
        constexpr std::size_t patch_start = page_size - 16;
        std::byte *const base =
            static_cast<std::byte *>(VirtualAlloc(nullptr, page_size * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        ASSERT_NE(base, nullptr);
        std::memset(base, 0xCC, page_size * 2);

        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(base, page_size, PAGE_EXECUTE_READWRITE, &previous), 0);
        ASSERT_NE(VirtualProtect(base + page_size, page_size, PAGE_NOACCESS, &previous), 0);

        std::array<std::byte, 32> source{};
        source.fill(std::byte{0x90});

        detail::set_forward_copy_seam(true);
        detail::set_flush_failure_seam(true);
        detail::set_virtual_protect_failure_mask(std::uint64_t{1} << 1);
        detail::reset_instruction_flush_observation_for_test();
        const Result<void> result = memory::patch_code(Address{base + patch_start}, std::span<const std::byte>{source});
        const std::size_t prefix = detail::last_forward_copy_prefix();
        const detail::InstructionFlushObservation flush = detail::instruction_flush_observation_for_test();
        detail::set_forward_copy_seam(false);
        detail::set_flush_failure_seam(false);
        detail::set_virtual_protect_failure_mask(0);

        ASSERT_NE(VirtualProtect(base + page_size, page_size, PAGE_READWRITE, &previous), 0);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::WriteMayBePartial);
        EXPECT_EQ(prefix, static_cast<std::size_t>(16));
        EXPECT_EQ(flush.call_count, static_cast<std::size_t>(1));
        EXPECT_EQ(flush.address, reinterpret_cast<std::uintptr_t>(base + patch_start));
        EXPECT_EQ(flush.bytes, source.size());
        EXPECT_FALSE(flush.succeeded);

        EXPECT_EQ(base[patch_start - 1], std::byte{0xCC});
        for (std::size_t i = 0; i < prefix; ++i)
        {
            EXPECT_EQ(base[patch_start + i], std::byte{0x90}) << "prefix byte " << i;
        }
        for (std::size_t i = prefix; i < source.size(); ++i)
        {
            EXPECT_EQ(base[patch_start + i], std::byte{0xCC}) << "unwritten byte " << i;
        }
        EXPECT_EQ(base[patch_start + source.size()], std::byte{0xCC});

        VirtualFree(base, 0, MEM_RELEASE);
    }

    // Restoration failure remains the most severe result after a partial executable write and failed flush.
    TEST_F(MemoryTest, MemoryPatchFaultProof_PartialExecutableWriteKeepsRestoreFailurePrecedence)
    {
        constexpr std::size_t page_size = 0x1000;
        constexpr std::size_t patch_start = page_size - 16;
        std::byte *const base =
            static_cast<std::byte *>(VirtualAlloc(nullptr, page_size * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        ASSERT_NE(base, nullptr);

        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(base, page_size, PAGE_EXECUTE_READWRITE, &previous), 0);
        ASSERT_NE(VirtualProtect(base + page_size, page_size, PAGE_NOACCESS, &previous), 0);

        std::array<std::byte, 32> source{};
        source.fill(std::byte{0x90});

        detail::set_forward_copy_seam(true);
        detail::set_flush_failure_seam(true);
        detail::set_virtual_protect_failure_mask((std::uint64_t{1} << 1) | (std::uint64_t{1} << 2));
        detail::reset_instruction_flush_observation_for_test();
        const Result<void> result = memory::patch_code(Address{base + patch_start}, std::span<const std::byte>{source});
        const std::size_t prefix = detail::last_forward_copy_prefix();
        const detail::InstructionFlushObservation flush = detail::instruction_flush_observation_for_test();
        detail::set_forward_copy_seam(false);
        detail::set_flush_failure_seam(false);
        detail::set_virtual_protect_failure_mask(0);

        auto ledger_cleanup = memory::ProtectGuard::make(Region{Address{base}, page_size}, Prot::RW);
        ASSERT_TRUE(ledger_cleanup.has_value());
        EXPECT_TRUE(ledger_cleanup->restore().has_value());
        VirtualFree(base, 0, MEM_RELEASE);

        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::ProtectionRestoreFailed);
        EXPECT_EQ(prefix, static_cast<std::size_t>(16));
        EXPECT_EQ(flush.call_count, static_cast<std::size_t>(1));
        EXPECT_EQ(flush.address, reinterpret_cast<std::uintptr_t>(base + patch_start));
        EXPECT_EQ(flush.bytes, source.size());
        EXPECT_FALSE(flush.succeeded);
    }

    // A retry that writes no bytes cannot erase the prefix already changed by the fast attempt.
    TEST_F(MemoryTest, MemoryPatchFaultProof_PartialFastWriteOutranksSlowWriteFault)
    {
        constexpr std::size_t page_size = 0x1000;
        constexpr std::size_t patch_start = page_size - 16;
        std::byte *const base =
            static_cast<std::byte *>(VirtualAlloc(nullptr, page_size * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        ASSERT_NE(base, nullptr);
        std::memset(base, 0xCC, page_size * 2);

        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(base, page_size, PAGE_EXECUTE_READWRITE, &previous), 0);
        ASSERT_NE(VirtualProtect(base + page_size, page_size, PAGE_NOACCESS, &previous), 0);

        std::array<std::byte, 32> source{};
        source.fill(std::byte{0x90});

        detail::set_forward_copy_seam(true);
        detail::set_patch_write_not_written_for_test(true);
        const Result<void> result = memory::patch_code(Address{base + patch_start}, std::span<const std::byte>{source});
        const std::size_t prefix = detail::last_forward_copy_prefix();
        detail::set_patch_write_not_written_for_test(false);
        detail::set_forward_copy_seam(false);

        ASSERT_NE(VirtualProtect(base + page_size, page_size, PAGE_READWRITE, &previous), 0);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::WriteMayBePartial);
        EXPECT_EQ(prefix, static_cast<std::size_t>(16));
        EXPECT_EQ(base[patch_start - 1], std::byte{0xCC});
        for (std::size_t i = 0; i < prefix; ++i)
        {
            EXPECT_EQ(base[patch_start + i], std::byte{0x90}) << "prefix byte " << i;
        }
        for (std::size_t i = prefix; i < source.size(); ++i)
        {
            EXPECT_EQ(base[patch_start + i], std::byte{0xCC}) << "unwritten byte " << i;
        }
        EXPECT_EQ(base[patch_start + source.size()], std::byte{0xCC});

        VirtualFree(base, 0, MEM_RELEASE);
    }

    // Both write attempts move zero bytes. The fallback reports WriteFaulted rather than a partial patch that requires
    // repair.
    TEST_F(MemoryTest, MemoryPatchFaultProof_NoFastPrefixKeepsSlowWriteFaultTruthful)
    {
        constexpr std::size_t page_size = 0x1000;
        std::byte *const base =
            static_cast<std::byte *>(VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        ASSERT_NE(base, nullptr);
        std::memset(base, 0xCC, page_size);

        // Executable and not writable, so the no-reprotect attempt faults on the FIRST byte and writes nothing.
        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(base, page_size, PAGE_EXECUTE_READ, &previous), 0);

        std::array<std::byte, 8> source{};
        source.fill(std::byte{0x90});

        detail::set_forward_copy_seam(true);
        detail::set_patch_write_not_written_for_test(true);
        const Result<void> result = memory::patch_code(Address{base}, std::span<const std::byte>{source});
        const std::size_t prefix = detail::last_forward_copy_prefix();
        detail::set_patch_write_not_written_for_test(false);
        detail::set_forward_copy_seam(false);

        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::WriteFaulted);
        EXPECT_EQ(prefix, static_cast<std::size_t>(0));

        ASSERT_NE(VirtualProtect(base, page_size, PAGE_READWRITE, &previous), 0);
        for (std::size_t i = 0; i < source.size(); ++i)
        {
            EXPECT_EQ(base[i], std::byte{0xCC}) << "untouched byte " << i;
        }

        VirtualFree(base, 0, MEM_RELEASE);
    }

    // A changed executable prefix needs a flush before fallback protection setup can fail. A data-only prefix stays
    // flush-free.
    TEST_F(MemoryTest, MemoryPatchFaultProof_PartialExecutableWriteBytesFlushesChangedPrefix)
    {
        constexpr std::size_t page_size = 0x1000;
        constexpr std::size_t patch_start = page_size - 16;
        std::array<std::byte, 32> source{};
        source.fill(std::byte{0x90});

        const auto partial_write_over = [&](DWORD head_protection) noexcept
        {
            std::byte *const base = static_cast<std::byte *>(
                VirtualAlloc(nullptr, page_size * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            );
            EXPECT_NE(base, nullptr);
            std::memset(base, 0xCC, page_size * 2);

            DWORD previous = 0;
            EXPECT_NE(VirtualProtect(base, page_size, head_protection, &previous), 0);
            EXPECT_NE(VirtualProtect(base + page_size, page_size, PAGE_NOACCESS, &previous), 0);

            detail::set_forward_copy_seam(true);
            detail::set_virtual_protect_failure_mask(std::uint64_t{1} << 1);
            detail::reset_instruction_flush_observation_for_test();
            const Result<void> result =
                memory::write_bytes(Address{base + patch_start}, std::span<const std::byte>{source});
            const std::size_t prefix = detail::last_forward_copy_prefix();
            const detail::InstructionFlushObservation flush = detail::instruction_flush_observation_for_test();
            detail::set_forward_copy_seam(false);
            detail::set_virtual_protect_failure_mask(0);

            EXPECT_NE(VirtualProtect(base + page_size, page_size, PAGE_READWRITE, &previous), 0);
            EXPECT_FALSE(result.has_value());
            if (!result.has_value())
            {
                EXPECT_EQ(result.error().code, ErrorCode::WriteMayBePartial);
            }
            EXPECT_EQ(prefix, static_cast<std::size_t>(16));
            EXPECT_EQ(base[patch_start - 1], std::byte{0xCC});
            for (std::size_t i = 0; i < prefix; ++i)
            {
                EXPECT_EQ(base[patch_start + i], std::byte{0x90}) << "prefix byte " << i;
            }
            VirtualFree(base, 0, MEM_RELEASE);
            return flush;
        };

        const detail::InstructionFlushObservation executable = partial_write_over(PAGE_EXECUTE_READWRITE);
        EXPECT_EQ(executable.call_count, static_cast<std::size_t>(1))
            << "an executable prefix left changed by the fast attempt must be flushed before the failing fallback";
        EXPECT_EQ(executable.bytes, source.size()) << "the covering flush spans the full validated request";

        const detail::InstructionFlushObservation data = partial_write_over(PAGE_READWRITE);
        EXPECT_EQ(data.call_count, static_cast<std::size_t>(0))
            << "a non-executable data prefix must stay on the flush-free route";
    }

    // The first byte lies in data, but the changed prefix crosses executable memory. The flush obligation follows every
    // region in that prefix.
    TEST_F(MemoryTest, MemoryPatchFaultProof_PartialWriteFlushesAnExecutableRegionPastTheFirst)
    {
        constexpr std::size_t page_size = 0x1000;
        constexpr std::size_t head_bytes = 16;
        constexpr std::size_t tail_bytes = 16;
        std::array<std::byte, head_bytes + page_size + tail_bytes> source{};
        source.fill(std::byte{0x90});

        // Page 0 is data, and page 1 varies its protection. Reserved page 2 fails the fallback walk before patch_bytes
        // can run its segment flush loop.
        const auto partial_write_over = [&](DWORD middle_protection) noexcept
        {
            std::byte *const base =
                static_cast<std::byte *>(VirtualAlloc(nullptr, page_size * 3, MEM_RESERVE, PAGE_NOACCESS));
            EXPECT_NE(base, nullptr);
            EXPECT_NE(VirtualAlloc(base, page_size * 2, MEM_COMMIT, PAGE_READWRITE), nullptr);
            std::memset(base, 0xCC, page_size * 2);

            DWORD previous = 0;
            EXPECT_NE(VirtualProtect(base + page_size, page_size, middle_protection, &previous), 0);

            detail::set_forward_copy_seam(true);
            detail::reset_instruction_flush_observation_for_test();
            const Result<void> result =
                memory::write_bytes(Address{base + page_size - head_bytes}, std::span<const std::byte>{source});
            const std::size_t prefix = detail::last_forward_copy_prefix();
            const detail::InstructionFlushObservation flush = detail::instruction_flush_observation_for_test();
            detail::set_forward_copy_seam(false);

            EXPECT_FALSE(result.has_value());
            if (!result.has_value())
            {
                EXPECT_EQ(result.error().code, ErrorCode::WriteMayBePartial);
            }
            // The copy stops at the reserved page, so the changed prefix reaches through the whole middle region.
            EXPECT_EQ(prefix, head_bytes + page_size);
            EXPECT_EQ(base[page_size - head_bytes - 1], std::byte{0xCC});
            EXPECT_EQ(base[page_size], std::byte{0x90}) << "the middle region was changed";
            VirtualFree(base, 0, MEM_RELEASE);
            return flush;
        };

        const detail::InstructionFlushObservation executable = partial_write_over(PAGE_EXECUTE_READWRITE);
        EXPECT_EQ(executable.call_count, static_cast<std::size_t>(1))
            << "an executable region the prefix reached must be flushed even when the request starts in data";
        EXPECT_EQ(executable.bytes, source.size()) << "the covering flush spans the full validated request";

        const detail::InstructionFlushObservation data = partial_write_over(PAGE_READWRITE);
        EXPECT_EQ(data.call_count, static_cast<std::size_t>(0))
            << "a request whose every region is data must stay on the flush-free route";
    }

    // Both code patch paths must flush. Data writes need neither execute access nor a flush.
    TEST_F(MemoryTest, MemoryPatchFaultProof_WritableExecutableFastPathChecksFlush)
    {
        constexpr std::array<std::byte, 4> nops{std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

        void *const code = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        ASSERT_NE(code, nullptr);

        // Fast path, no injection: succeeds.
        EXPECT_TRUE(memory::patch_code(Address{code}, std::span<const std::byte>{nops}).has_value());

        // Fast path, injected flush failure: the already-writable code patch reports it.
        detail::set_flush_failure_seam(true);
        const Result<void> flush_failed = memory::patch_code(Address{code}, std::span<const std::byte>{nops});
        EXPECT_FALSE(flush_failed.has_value());
        if (!flush_failed.has_value())
        {
            EXPECT_EQ(flush_failed.error().code, ErrorCode::InstructionFlushFailed);
        }

        // A DATA write to the same writable page issues no flush, so the injection does not touch it.
        EXPECT_TRUE(memory::write_in_place(Address{code}, std::span<const std::byte>{nops}).has_value());
        detail::set_flush_failure_seam(false);
        VirtualFree(code, 0, MEM_RELEASE);

        // Slow path on a read-only DATA page: write_bytes derives PAGE_READWRITE and skips the flush, while the
        // explicit code-patch operation still checks one. Both restore the page to read-only.
        void *const rodata = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        ASSERT_NE(rodata, nullptr);
        detail::set_flush_failure_seam(true);
        EXPECT_TRUE(memory::write_bytes(Address{rodata}, std::span<const std::byte>{nops}).has_value());
        const Result<void> explicit_patch = memory::patch_code(Address{rodata}, std::span<const std::byte>{nops});
        detail::set_flush_failure_seam(false);
        ASSERT_FALSE(explicit_patch.has_value());
        EXPECT_EQ(explicit_patch.error().code, ErrorCode::InstructionFlushFailed);
        MEMORY_BASIC_INFORMATION mbi{};
        ASSERT_NE(VirtualQuery(rodata, &mbi, sizeof(mbi)), static_cast<SIZE_T>(0));
        EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READONLY));
        VirtualFree(rodata, 0, MEM_RELEASE);

        // Slow path on a read-only EXECUTABLE page: the executable-region flush IS attempted and its injected failure
        // surfaces after the bytes land and protection is restored.
        void *const rocode = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
        ASSERT_NE(rocode, nullptr);
        detail::set_flush_failure_seam(true);
        const Result<void> slow = memory::patch_code(Address{rocode}, std::span<const std::byte>{nops});
        detail::set_flush_failure_seam(false);
        EXPECT_FALSE(slow.has_value());
        if (!slow.has_value())
        {
            EXPECT_EQ(slow.error().code, ErrorCode::InstructionFlushFailed);
        }
        VirtualFree(rocode, 0, MEM_RELEASE);
    }

    // Changed executable bytes need an instruction-cache flush. Only a protection change or restore invalidates the
    // protection cache. The writable fast path separates those obligations.
    TEST_F(MemoryTest, MemoryPatchFaultProof_WritableExecutableFastPathLeavesProtectionCacheIntact)
    {
        memory::shutdown_cache();
        (void)memory::init_cache(32, 60000, 4);

        void *const code = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        ASSERT_NE(code, nullptr);
        std::byte *const target = static_cast<std::byte *>(code);

        // Prime the protection cache so there is a live entry covering the target for an invalidation to drop.
        EXPECT_TRUE(is_writable(target, 64));
        const std::uint64_t baseline = memory::get_memory_stats().invalidations;

        constexpr std::array<std::byte, 4> nops{std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

        detail::reset_instruction_flush_observation_for_test();
        EXPECT_TRUE(memory::patch_code(Address{target}, std::span<const std::byte>{nops}).has_value());
        const detail::InstructionFlushObservation flush = detail::instruction_flush_observation_for_test();
        EXPECT_EQ(flush.call_count, static_cast<std::size_t>(1)) << "an already-writable code patch still flushes";
        EXPECT_EQ(memory::get_memory_stats().invalidations, baseline)
            << "no protection changed, so the fast path owes the protection cache nothing";

        // The counterpart trigger: a read-only executable target forces the protection-changing route, which restores
        // protection and therefore must drop the range it made transiently writable.
        DWORD previous = 0;
        ASSERT_NE(VirtualProtect(code, 0x1000, PAGE_EXECUTE_READ, &previous), 0);
        EXPECT_TRUE(memory::patch_code(Address{target}, std::span<const std::byte>{nops}).has_value());
        EXPECT_GT(memory::get_memory_stats().invalidations, baseline)
            << "a path that changed and restored protection must invalidate the touched range";

        VirtualFree(code, 0, MEM_RELEASE);
    }
#endif // DMK_ENABLE_TEST_SEAMS
} // namespace
