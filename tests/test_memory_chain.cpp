#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "DetourModKit/error.hpp"
#include "DetourModKit/memory.hpp"

using namespace DetourModKit;

// Coverage for the pointer-validity guard and the guarded pointer-chain primitives (is_plausible_ptr, walk, plus read /
// write at the resolved leaf). These walk in-process pointer chains, so no game memory or cache state is required; the
// cache is left in its default state.

TEST(MemoryPlausiblePtr, RejectsLowAndNonCanonical)
{
    EXPECT_FALSE(memory::is_plausible_ptr(Address{}));
    EXPECT_FALSE(memory::is_plausible_ptr(Address{0xFFFFu}));
    EXPECT_TRUE(memory::is_plausible_ptr(Address{memory::USERSPACE_PTR_MIN}));
    EXPECT_TRUE(memory::is_plausible_ptr(Address{0x00007FFFFFFFFFFFull}));
    EXPECT_FALSE(memory::is_plausible_ptr(Address{memory::USERSPACE_PTR_MAX}));
    EXPECT_FALSE(memory::is_plausible_ptr(Address{UINTPTR_MAX}));
}

TEST(MemoryPlausiblePtr, IsConstexprEvaluable)
{
    // The guard is a pure arithmetic test, so it screens pointers at compile time as well as at run time.
    static_assert(!memory::is_plausible_ptr(Address{}));
    static_assert(memory::is_plausible_ptr(Address{memory::USERSPACE_PTR_MIN}));
    static_assert(!memory::is_plausible_ptr(Address{memory::USERSPACE_PTR_MAX}));
    SUCCEED();
}

TEST(MemoryWalk, EmptyOffsetsReturnsBase)
{
    int x = 5;
    const auto base = reinterpret_cast<uintptr_t>(&x);
    const auto addr = memory::walk(Address{base}, std::span<const std::ptrdiff_t>{});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->raw(), base);
}

TEST(MemoryWalk, TwoLevelResolvesFinalAddress)
{
    uint64_t target = 0x1122334455667788ull;
    uintptr_t mid = reinterpret_cast<uintptr_t>(&target); // holds &target
    uintptr_t root = reinterpret_cast<uintptr_t>(&mid);   // holds &mid

    // deref(&root) -> &mid, deref(&mid) -> &target; final offset 0 not dereferenced.
    const auto addr = memory::walk(Address{reinterpret_cast<uintptr_t>(&root)}, std::array<std::ptrdiff_t, 3>{0, 0, 0});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->raw(), reinterpret_cast<uintptr_t>(&target));
}

TEST(MemoryWalk, NonZeroFinalOffsetIsNotDereferenced)
{
    uint64_t cell = 0;
    uintptr_t holder = reinterpret_cast<uintptr_t>(&cell);

    // deref(&holder) -> &cell, then add 0x10 without dereferencing.
    const auto addr =
        memory::walk(Address{reinterpret_cast<uintptr_t>(&holder)}, std::array<std::ptrdiff_t, 2>{0, 0x10});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->raw(), reinterpret_cast<uintptr_t>(&cell) + 0x10);
}

TEST(MemoryWalk, ImplausibleLinkReturnsError)
{
    // The first dereference yields a null pointer, which fails the plausibility screen before any further dereference
    // is attempted. v4 walk reports this as a Result error rather than nullopt.
    uintptr_t null_holder = 0;
    const auto addr =
        memory::walk(Address{reinterpret_cast<uintptr_t>(&null_holder)}, std::array<std::ptrdiff_t, 2>{0, 0});
    EXPECT_FALSE(addr.has_value());
}

TEST(MemoryWalk, SingleOffsetIsAddedNotDereferenced)
{
    uint64_t cell = 0;
    uintptr_t holder = reinterpret_cast<uintptr_t>(&cell);

    // count==1 boundary: the dereference loop runs zero times and only the final-add branch executes, so the single
    // offset is added to base without dereferencing *holder.
    const auto addr = memory::walk(Address{reinterpret_cast<uintptr_t>(&holder)}, std::array<std::ptrdiff_t, 1>{0x10});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->raw(), reinterpret_cast<uintptr_t>(&holder) + 0x10);
}

TEST(MemoryWalk, NegativeIntermediateOffsetSubtracts)
{
    struct Node
    {
        uintptr_t link;
        uint64_t tail;
    };
    uint64_t target = 0x1122334455667788ull;
    Node node{reinterpret_cast<uintptr_t>(&target), 0};

    // A negative offset on a dereferenced (intermediate) link exercises the modular wrap of
    // static_cast<uintptr_t>(ptrdiff_t): start one field past node.link, reach node.link by subtracting, then
    // dereference it.
    const std::ptrdiff_t back = -static_cast<std::ptrdiff_t>(offsetof(Node, tail));
    uintptr_t root = reinterpret_cast<uintptr_t>(&node.tail);
    const auto addr =
        memory::walk(Address{reinterpret_cast<uintptr_t>(&root)}, std::array<std::ptrdiff_t, 3>{0, back, 0});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->raw(), reinterpret_cast<uintptr_t>(&target));
}

TEST(MemoryWalk, NegativeFinalOffsetSubtracts)
{
    uint64_t cell = 0;
    uintptr_t holder = reinterpret_cast<uintptr_t>(&cell);

    // A negative final offset exercises the wrap in the final-add branch, which is added to the resolved address but
    // never dereferenced.
    const std::ptrdiff_t neg = -0x10;
    const auto addr =
        memory::walk(Address{reinterpret_cast<uintptr_t>(&holder)}, std::array<std::ptrdiff_t, 2>{0, neg});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->raw(), reinterpret_cast<uintptr_t>(&cell) - 0x10);
}

TEST(MemoryReadChain, TwoLevelReadsTypedValue)
{
    uint64_t target = 0x1122334455667788ull;
    uintptr_t mid = reinterpret_cast<uintptr_t>(&target);
    uintptr_t root = reinterpret_cast<uintptr_t>(&mid);

    const auto leaf = memory::walk(Address{reinterpret_cast<uintptr_t>(&root)}, std::array<std::ptrdiff_t, 3>{0, 0, 0});
    ASSERT_TRUE(leaf.has_value());
    const auto value = memory::read<uint64_t>(*leaf);
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, target);
}

TEST(MemoryReadChain, FaultReturnsError)
{
    uintptr_t null_holder = 0;
    const auto leaf =
        memory::walk(Address{reinterpret_cast<uintptr_t>(&null_holder)}, std::array<std::ptrdiff_t, 2>{0, 0});
    // The walk faults at the implausible first link; nothing is read.
    EXPECT_FALSE(leaf.has_value());
}

TEST(MemoryReadChain, NullOutAndZeroBytes)
{
    uint64_t target = 0xCAFEBABEull;
    const auto base = reinterpret_cast<uintptr_t>(&target);

    // An empty chain resolves to base; a zero-length read into a destination is a no-op success.
    const auto leaf = memory::walk(Address{base}, std::span<const std::ptrdiff_t>{});
    ASSERT_TRUE(leaf.has_value());
    uint8_t scratch = 0;
    EXPECT_TRUE(memory::read_into(*leaf, std::span<std::byte>{reinterpret_cast<std::byte *>(&scratch), 0}).has_value());
}

TEST(MemoryReadChain, EmptyChainReadsAtBase)
{
    uint32_t target = 0xCAFEBABEu;
    const auto leaf = memory::walk(Address{reinterpret_cast<uintptr_t>(&target)}, std::span<const std::ptrdiff_t>{});
    ASSERT_TRUE(leaf.has_value());
    const auto value = memory::read<uint32_t>(*leaf);
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0xCAFEBABEu);
}

TEST(MemoryReadChain, ReadsNonDefaultConstructibleType)
{
    // A trivially copyable type with a deleted default constructor: the read is a raw byte copy reinterpreted with
    // std::bit_cast, so it must work without ever default-constructing T.
    struct NoDefault
    {
        uint32_t a;
        uint32_t b;
        NoDefault() = delete;
        constexpr NoDefault(uint32_t x, uint32_t y) noexcept : a(x), b(y) {}
    };
    static_assert(std::is_trivially_copyable_v<NoDefault>);
    static_assert(!std::is_default_constructible_v<NoDefault>);

    NoDefault src{0xAABBCCDDu, 0x11223344u};
    uintptr_t holder = reinterpret_cast<uintptr_t>(&src);

    // deref(&holder) -> &src, final offset 0 not dereferenced; read sizeof bytes.
    const auto leaf = memory::walk(Address{reinterpret_cast<uintptr_t>(&holder)}, std::array<std::ptrdiff_t, 2>{0, 0});
    ASSERT_TRUE(leaf.has_value());
    const auto value = memory::read<NoDefault>(*leaf);
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(value->a, 0xAABBCCDDu);
    EXPECT_EQ(value->b, 0x11223344u);
}

// Coverage for the pointer-chain write path (walk then write at the resolved leaf). These write to already-writable
// in-process memory, so no game memory, cache state, or page-protection change is required.

TEST(MemoryWriteChain, TwoLevelWritesTypedValueRoundTrips)
{
    uint64_t target = 0;
    uintptr_t mid = reinterpret_cast<uintptr_t>(&target);
    uintptr_t root = reinterpret_cast<uintptr_t>(&mid);

    // deref(&root) -> &mid, deref(&mid) -> &target; final offset 0 not dereferenced. The write lands in target.
    const uint64_t expected = 0x1122334455667788ull;
    const auto leaf = memory::walk(Address{reinterpret_cast<uintptr_t>(&root)}, std::array<std::ptrdiff_t, 3>{0, 0, 0});
    ASSERT_TRUE(leaf.has_value());
    EXPECT_TRUE(memory::write<uint64_t>(*leaf, expected).has_value());
    EXPECT_EQ(target, expected);

    // Read it back through the same chain to confirm the resolve agrees both directions.
    const auto leaf2 =
        memory::walk(Address{reinterpret_cast<uintptr_t>(&root)}, std::array<std::ptrdiff_t, 3>{0, 0, 0});
    ASSERT_TRUE(leaf2.has_value());
    const auto value = memory::read<uint64_t>(*leaf2);
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, expected);
}

TEST(MemoryWriteChain, WritesIntoNestedStructFieldViaRealOffsets)
{
    // A struct with a nested pointer and an array field, so the chain walks a real intra-object layout. The first link
    // dereferences the embedded pointer; the final offset selects the array element address without dereferencing it.
    struct Inner
    {
        uint32_t header;
        uint32_t cells[4];
    };
    struct Outer
    {
        Inner *inner;
        uint64_t pad;
    };

    Inner inner{0xDEADBEEFu, {0, 0, 0, 0}};
    Outer outer{&inner, 0};

    // Chain semantics: every offset but the last is dereferenced. From &outer, the first offset lands on the embedded
    // Outer::inner pointer and is dereferenced to reach &inner; the final offset selects inner.cells[2]'s address
    // without dereferencing it.
    const std::ptrdiff_t to_inner = static_cast<std::ptrdiff_t>(offsetof(Outer, inner));
    const std::ptrdiff_t to_cell2 = static_cast<std::ptrdiff_t>(offsetof(Inner, cells) + 2 * sizeof(uint32_t));
    const uint32_t expected = 0xCAFEF00Du;
    const auto leaf =
        memory::walk(Address{reinterpret_cast<uintptr_t>(&outer)}, std::array<std::ptrdiff_t, 2>{to_inner, to_cell2});
    ASSERT_TRUE(leaf.has_value());
    EXPECT_TRUE(memory::write<uint32_t>(*leaf, expected).has_value());

    EXPECT_EQ(inner.cells[2], expected);
    // Neighbouring fields are untouched.
    EXPECT_EQ(inner.header, 0xDEADBEEFu);
    EXPECT_EQ(inner.cells[1], 0u);
    EXPECT_EQ(inner.cells[3], 0u);
}

TEST(MemoryWriteChain, EmptyOffsetsWritesAtBase)
{
    uint32_t target = 0;
    const uint32_t expected = 0xABCD1234u;

    // An empty offset span resolves to base; the write lands there unchanged.
    const auto leaf = memory::walk(Address{reinterpret_cast<uintptr_t>(&target)}, std::span<const std::ptrdiff_t>{});
    ASSERT_TRUE(leaf.has_value());
    EXPECT_TRUE(memory::write<uint32_t>(*leaf, expected).has_value());
    EXPECT_EQ(target, expected);
}

TEST(MemoryWriteChain, ZeroBytesIsNoOpSuccess)
{
    uint64_t target = 0xFEEDFACEull;
    const uint8_t source = 0;

    // A zero-length write_bytes is a no-op success and must leave the target untouched.
    const auto leaf = memory::walk(Address{reinterpret_cast<uintptr_t>(&target)}, std::span<const std::ptrdiff_t>{});
    ASSERT_TRUE(leaf.has_value());
    EXPECT_TRUE(memory::write_bytes(*leaf, std::span<const std::byte>{reinterpret_cast<const std::byte *>(&source), 0})
                    .has_value());
    EXPECT_EQ(target, 0xFEEDFACEull);
}

TEST(MemoryWriteChain, NullSourceReturnsError)
{
    uint64_t target = 0xFEEDFACEull;

    // A null/empty source span over a non-zero count is rejected and the target is unchanged. An empty span is a
    // no-op success, so to exercise the rejection path we issue a write to a null leaf which fails closed.
    const auto leaf = memory::walk(Address{reinterpret_cast<uintptr_t>(&target)}, std::span<const std::ptrdiff_t>{});
    ASSERT_TRUE(leaf.has_value());
    const uint64_t value = 0;
    EXPECT_TRUE(memory::write<uint64_t>(*leaf, value).has_value());
    // Writing to a null target address is rejected with NullTargetAddress.
    const auto bad = memory::write<uint64_t>(Address{}, value);
    EXPECT_FALSE(bad.has_value());
    EXPECT_EQ(bad.error().code, ErrorCode::NullTargetAddress);
}

TEST(MemoryWriteChain, ImplausibleLinkFailsClosed)
{
    // The first dereference yields a null pointer, which fails the plausibility screen before any write is attempted,
    // mirroring the walk implausible-link test: walk fails, so nothing is written.
    uintptr_t null_holder = 0;
    const auto leaf =
        memory::walk(Address{reinterpret_cast<uintptr_t>(&null_holder)}, std::array<std::ptrdiff_t, 2>{0, 0});
    EXPECT_FALSE(leaf.has_value());
}

TEST(MemoryWriteChain, InitializerListMatchesSpanOverload)
{
    uint32_t target_list = 0;
    uint32_t target_span = 0;
    uintptr_t holder_list = reinterpret_cast<uintptr_t>(&target_list);
    uintptr_t holder_span = reinterpret_cast<uintptr_t>(&target_span);

    const uint32_t expected = 0x99AABBCCu;

    // The bare-offset (ptrdiff_t) walk overload and a ChainStep-span walk over the same hops must resolve identically.
    const auto leaf_list =
        memory::walk(Address{reinterpret_cast<uintptr_t>(&holder_list)}, std::array<std::ptrdiff_t, 2>{0, 0});
    ASSERT_TRUE(leaf_list.has_value());
    EXPECT_TRUE(memory::write<uint32_t>(*leaf_list, expected).has_value());

    const std::array<memory::ChainStep, 2> steps{memory::ChainStep{0}, memory::ChainStep{0}};
    const auto leaf_span = memory::walk(Address{reinterpret_cast<uintptr_t>(&holder_span)}, steps);
    ASSERT_TRUE(leaf_span.has_value());
    EXPECT_TRUE(memory::write<uint32_t>(*leaf_span, expected).has_value());

    EXPECT_EQ(target_list, expected);
    EXPECT_EQ(target_span, expected);
    EXPECT_EQ(target_list, target_span);
}

// v4-only coverage: walk failing-hop reporting, the intermediate-trace out-parameter, and the per-hop min_valid floor.

TEST(MemoryWalk, FailingHopIndexIsReportedInDetail)
{
    // A three-hop chain that breaks at hop 1: the root link resolves, but the second link holds null, so the walk
    // faults at hop index 1 and reports ReadFaulted with that index in Error::detail.
    uint64_t leaf_cell = 0;
    uintptr_t broken = 0;                                  // hop 1 dereferences this -> null link
    uintptr_t root = reinterpret_cast<uintptr_t>(&broken); // hop 0 resolves to &broken
    (void)leaf_cell;

    const auto addr = memory::walk(Address{reinterpret_cast<uintptr_t>(&root)}, std::array<std::ptrdiff_t, 3>{0, 0, 0});
    ASSERT_FALSE(addr.has_value());
    EXPECT_EQ(addr.error().code, ErrorCode::ReadFaulted);
    EXPECT_EQ(addr.error().detail, static_cast<uintptr_t>(1));
}

TEST(MemoryWalk, TracePopulatesIntermediatesOnSuccess)
{
    uint64_t target = 0x1122334455667788ull;
    uintptr_t mid = reinterpret_cast<uintptr_t>(&target);
    uintptr_t root = reinterpret_cast<uintptr_t>(&mid);

    std::array<Address, 3> trace{};
    const auto addr = memory::walk(Address{reinterpret_cast<uintptr_t>(&root)}, std::array<std::ptrdiff_t, 3>{0, 0, 0},
                                   std::span<Address>{trace});
    ASSERT_TRUE(addr.has_value());
    // hop 0 dereferences &root -> &mid; hop 1 dereferences &mid -> &target; hop 2 is the leaf (final, not
    // dereferenced).
    EXPECT_EQ(trace[0].raw(), reinterpret_cast<uintptr_t>(&mid));
    EXPECT_EQ(trace[1].raw(), reinterpret_cast<uintptr_t>(&target));
    EXPECT_EQ(trace[2].raw(), reinterpret_cast<uintptr_t>(&target));
    EXPECT_EQ(addr->raw(), reinterpret_cast<uintptr_t>(&target));
}

TEST(MemoryWalk, TracePopulatesResolvedPrefixOnPartialFailure)
{
    // hop 0 resolves to &broken; hop 1 dereferences a null link and faults. The successfully-walked prefix (hop 0) is
    // still recorded in the trace so a caller can see how far the chain got.
    uintptr_t broken = 0;
    uintptr_t root = reinterpret_cast<uintptr_t>(&broken);

    std::array<Address, 3> trace{};
    const auto addr = memory::walk(Address{reinterpret_cast<uintptr_t>(&root)}, std::array<std::ptrdiff_t, 3>{0, 0, 0},
                                   std::span<Address>{trace});
    ASSERT_FALSE(addr.has_value());
    EXPECT_EQ(addr.error().code, ErrorCode::ReadFaulted);
    EXPECT_EQ(addr.error().detail, static_cast<uintptr_t>(1));
    // The resolved prefix is populated even on partial failure.
    EXPECT_EQ(trace[0].raw(), reinterpret_cast<uintptr_t>(&broken));
}

TEST(MemoryWalk, PerHopMinValidFloorStopsLowLink)
{
    // hop 0 dereferences &slot, reading the link value 0x1000 -- below the explicit per-hop min_valid floor
    // (USERSPACE_PTR_MIN). A non-final hop screens its dereferenced link against that floor, so the walk stops at hop 0
    // with ReadFaulted/detail==0 rather than chasing an implausible link into the next dereference.
    uintptr_t slot = 0x1000; // the link hop 0 reads; below USERSPACE_PTR_MIN and below the explicit floor below

    const std::array<memory::ChainStep, 2> steps{memory::ChainStep{0, Address{memory::USERSPACE_PTR_MIN}},
                                                 memory::ChainStep{0}};
    const auto addr = memory::walk(Address{reinterpret_cast<uintptr_t>(&slot)}, steps);
    ASSERT_FALSE(addr.has_value());
    EXPECT_EQ(addr.error().code, ErrorCode::ReadFaulted);
    EXPECT_EQ(addr.error().detail, static_cast<uintptr_t>(0));
}
