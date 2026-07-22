// Deterministic, single-threaded fault-containment proofs for DetourModKit's guarded-memory primitives. Each test
// drives a real guarded read / walk / write against a held PAGE_NOACCESS page (built by the reusable fixtures in
// tests/fixtures/fault_injection.hpp) and asserts the primitive FAILS CLOSED -- returns a typed error and leaves the
// host process alive -- instead of terminating on the access violation.
//
// SCOPE (important). The MinGW vectored-fault guard arms only the FOREIGN range an operation explicitly touches: the
// target of a read/walk/write. That is exactly the untrusted memory the primitive must survive. A write's SOURCE span
// is caller-owned and trusted, so a fault reading the source is NOT contained on MinGW (it is a caller-contract
// violation, like passing a dangling span); MSVC's whole-copy __try catches it only incidentally. These tests
// therefore inject faults into the FOREIGN target only, which is the behavior the library actually guarantees on both
// toolchains. This is also why the escalating writer's slow-path COPY-fault arm is not deterministic single-threaded:
// once the slow path has made the target writable, only a concurrent reprotect (a second thread) can fault the copy.
//
// These live outside the in-tree tests/test_*.cpp glob on purpose: fault fixtures are compiled and run by
// scripts/run_fault_tests.sh, which links them against the prebuilt library archive without reconfiguring the main test
// target.

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>

#include "DetourModKit/address.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/memory.hpp"

#include "internal/memory_fault.hpp"
#include "internal/memory_guarded.hpp"

#include "fault_injection.hpp"

using namespace DetourModKit;

// A guarded read of a committed no-access page must return an error, not fault the host. Reaching the assertion at all
// proves the fault was contained; the failed Result proves it was reported rather than silently succeeding.
TEST(FaultContainment, GuardedReadFromNoAccessPageFailsClosed)
{
    dmk_test::NoAccessPage page;
    ASSERT_TRUE(page.ok()) << "VirtualAlloc(PAGE_NOACCESS) failed to set up the fixture";

    const Result<std::uint64_t> value = memory::read<std::uint64_t>(Address{page.addr()});
    ASSERT_FALSE(value.has_value()) << "a guarded read of a no-access page must fail closed";
    EXPECT_EQ(value.error().code, ErrorCode::ReadFaulted);
}

// A pointer-chain walk that dereferences a no-access address at an intermediate hop must stop and fail closed at that
// hop, never fault the host. The chain: a readable local pointer holds the no-access address, and the walk follows it
// (hop 0 reads the local, hop 1 dereferences INTO the no-access page and must fault-and-stop before the leaf).
TEST(FaultContainment, GuardedWalkThroughNoAccessHopFailsClosed)
{
    dmk_test::NoAccessPage page;
    ASSERT_TRUE(page.ok());

    void *chain = page.data(); // a readable slot holding the no-access page address
    const std::array<std::ptrdiff_t, 3> offsets{0, 0, 0};
    const Result<Address> result = memory::walk(Address{reinterpret_cast<std::uintptr_t>(&chain)}, offsets);
    ASSERT_FALSE(result.has_value()) << "a walk that dereferences a no-access hop must fail closed";
    EXPECT_EQ(result.error().code, ErrorCode::ReadFaulted);
    EXPECT_EQ(result.error().detail, 1u);
}

// write_in_place is the strict, no-escalate writer: a no-access target IS the foreign range the guard arms, so the
// guarded copy faults writing it and the call must fail closed with WriteFaulted, never silently escalate or crash.
TEST(FaultContainment, WriteInPlaceToNoAccessTargetFailsClosed)
{
    dmk_test::NoAccessPage target;
    ASSERT_TRUE(target.ok());

    const std::array<std::byte, 8> source{};
    const Result<void> result = memory::write_in_place(Address{target.addr()}, source);
    ASSERT_FALSE(result.has_value()) << "write_in_place must not claim a write to a no-access page succeeded";
    EXPECT_EQ(result.error().code, ErrorCode::WriteFaulted);
    EXPECT_EQ(result.error().detail, target.addr());
}

// Slow-path escalate-and-restore (the deterministic arm). A read-only target forces the escalating slow path: the fast
// guarded write faults writing the RO page, so write_bytes changes protection to RWX, copies a VALID source, flushes,
// and restores. Assert the copy landed and the original PAGE_READONLY protection was restored -- the escalating writer
// guarantees the restore runs on the slow path, including failure exits. The copy-fault variant of that guarantee is
// not single-threadedly injectable; see the scope note at the top.
TEST(FaultContainment, WriteBytesEscalatesThroughReadOnlyTargetAndRestores)
{
    dmk_test::ProtectedPage target(PAGE_READONLY, 0x00);
    ASSERT_TRUE(target.ok());
    ASSERT_EQ(target.current_protection(), static_cast<DWORD>(PAGE_READONLY));

    const std::array<std::byte, 4> source{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    const Result<void> result = memory::write_bytes(Address{target.addr()}, source);
    ASSERT_TRUE(result.has_value()) << "escalating write to a committed read-only page should succeed";

    // The bytes landed through the slow path...
    EXPECT_EQ(target.byte_at(0), 0xDEu);
    EXPECT_EQ(target.byte_at(3), 0xEFu);
    // ...and the original read-only protection was restored, not left RWX.
    EXPECT_EQ(target.current_protection(), static_cast<DWORD>(PAGE_READONLY))
        << "the slow path must restore the original protection after the write";
}

namespace
{
    // Context for the nested-access region body. POD only: the body is abandoned by longjmp on a fault, so nothing in
    // it may need unwinding.
    struct NestedAccessContext
    {
        std::uintptr_t target;
        std::uintptr_t readable;
        bool inner_read_ok;
    };

    // Performs a guarded read of an address OUTSIDE the enclosing region, then touches the enclosing region. The read
    // is the nesting; the touch is what must still be contained after it.
    void nested_access_body(void *raw) noexcept
    {
        auto *const ctx = static_cast<NestedAccessContext *>(raw);
        std::uint32_t scratch = 0;
        ctx->inner_read_ok = DetourModKit::detail::guarded_read_bytes(ctx->readable, &scratch, sizeof(scratch));
        volatile const auto *const probe = reinterpret_cast<volatile const std::uint8_t *>(ctx->target);
        (void)*probe;
    }
} // namespace

// A guarded region whose body performs its own guarded read must stay armed after that read returns. The inner access
// publishes its own range to the thread's guard slot; if it cleared the slot on the way out instead of restoring the
// enclosing one, the access violation raised by the probe below would find no armed guard, escape the vectored handler,
// and terminate this process. Reaching the assertion at all is the proof; the false result proves the fault was
// reported rather than swallowed silently.
TEST(FaultContainment, GuardedRegionStaysArmedAcrossANestedGuardedRead)
{
    dmk_test::NoAccessPage page;
    ASSERT_TRUE(page.ok()) << "VirtualAlloc(PAGE_NOACCESS) failed to set up the fixture";

    const std::uint32_t readable_source = 0xA5A5A5A5u;
    NestedAccessContext ctx{page.addr(), reinterpret_cast<std::uintptr_t>(&readable_source), false};

    const bool completed = DetourModKit::detail::run_guarded_region(ctx.target, ctx.target + sizeof(std::uint32_t),
                                                                    &nested_access_body, &ctx);
    EXPECT_TRUE(ctx.inner_read_ok) << "the nested guarded read of a readable local should succeed";
    EXPECT_FALSE(completed) << "the fault inside the guarded region must be contained and reported as incomplete";
}
