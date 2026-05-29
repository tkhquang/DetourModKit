#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "DetourModKit/memory.hpp"

using namespace DetourModKit;

// Coverage for the pointer-validity guard and the single-fault-frame pointer
// chain primitives (plausible_userspace_ptr, seh_resolve_chain, seh_read_chain,
// seh_read_chain_bytes). These walk in-process pointer chains, so no game
// memory or cache state is required; the cache is left in its default state.

TEST(MemoryPlausiblePtr, RejectsLowAndNonCanonical)
{
    EXPECT_FALSE(Memory::plausible_userspace_ptr(0));
    EXPECT_FALSE(Memory::plausible_userspace_ptr(0xFFFFu));
    EXPECT_TRUE(Memory::plausible_userspace_ptr(Memory::USERSPACE_PTR_MIN));
    EXPECT_TRUE(Memory::plausible_userspace_ptr(0x00007FFFFFFFFFFFull));
    EXPECT_FALSE(Memory::plausible_userspace_ptr(Memory::USERSPACE_PTR_MAX));
    EXPECT_FALSE(Memory::plausible_userspace_ptr(UINTPTR_MAX));
}

TEST(MemoryPlausiblePtr, IsConstexprEvaluable)
{
    // The guard is a pure arithmetic test, so it screens pointers at compile
    // time as well as at run time.
    static_assert(!Memory::plausible_userspace_ptr(0));
    static_assert(Memory::plausible_userspace_ptr(Memory::USERSPACE_PTR_MIN));
    static_assert(!Memory::plausible_userspace_ptr(Memory::USERSPACE_PTR_MAX));
    SUCCEED();
}

TEST(MemorySehResolveChain, EmptyOffsetsReturnsBase)
{
    int x = 5;
    const auto base = reinterpret_cast<uintptr_t>(&x);
    const auto addr = Memory::seh_resolve_chain(base, std::span<const ptrdiff_t>{});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(*addr, base);
}

TEST(MemorySehResolveChain, TwoLevelResolvesFinalAddress)
{
    uint64_t target = 0x1122334455667788ull;
    uintptr_t mid = reinterpret_cast<uintptr_t>(&target); // holds &target
    uintptr_t root = reinterpret_cast<uintptr_t>(&mid);    // holds &mid

    // deref(&root) -> &mid, deref(&mid) -> &target; final offset 0 not dereferenced.
    const auto addr = Memory::seh_resolve_chain(reinterpret_cast<uintptr_t>(&root), {0, 0, 0});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(*addr, reinterpret_cast<uintptr_t>(&target));
}

TEST(MemorySehResolveChain, NonZeroFinalOffsetIsNotDereferenced)
{
    uint64_t cell = 0;
    uintptr_t holder = reinterpret_cast<uintptr_t>(&cell);

    // deref(&holder) -> &cell, then add 0x10 without dereferencing.
    const auto addr = Memory::seh_resolve_chain(reinterpret_cast<uintptr_t>(&holder), {0, 0x10});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(*addr, reinterpret_cast<uintptr_t>(&cell) + 0x10);
}

TEST(MemorySehResolveChain, ImplausibleLinkReturnsNullopt)
{
    // The first dereference yields a null pointer, which fails the plausibility
    // screen before any further dereference is attempted.
    uintptr_t null_holder = 0;
    const auto addr = Memory::seh_resolve_chain(
        reinterpret_cast<uintptr_t>(&null_holder), {0, 0});
    EXPECT_FALSE(addr.has_value());
}

TEST(MemorySehResolveChain, SingleOffsetIsAddedNotDereferenced)
{
    uint64_t cell = 0;
    uintptr_t holder = reinterpret_cast<uintptr_t>(&cell);

    // count==1 guards the `i + 1 < count` loop bound at the N==1 boundary: the
    // dereference loop runs zero times and only the final-add branch executes,
    // so the single offset is added to base without dereferencing *holder.
    const auto addr = Memory::seh_resolve_chain(
        reinterpret_cast<uintptr_t>(&holder), {0x10});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(*addr, reinterpret_cast<uintptr_t>(&holder) + 0x10);
}

TEST(MemorySehResolveChain, NegativeIntermediateOffsetSubtracts)
{
    struct Node
    {
        uintptr_t link;
        uint64_t tail;
    };
    uint64_t target = 0x1122334455667788ull;
    Node node{reinterpret_cast<uintptr_t>(&target), 0};

    // A negative offset on a dereferenced (intermediate) link exercises the
    // modular wrap of static_cast<uintptr_t>(ptrdiff_t): start one field past
    // node.link, reach node.link by subtracting, then dereference it.
    const ptrdiff_t back = -static_cast<ptrdiff_t>(offsetof(Node, tail));
    uintptr_t root = reinterpret_cast<uintptr_t>(&node.tail);
    const auto addr = Memory::seh_resolve_chain(
        reinterpret_cast<uintptr_t>(&root), {0, back, 0});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(*addr, reinterpret_cast<uintptr_t>(&target));
}

TEST(MemorySehResolveChain, NegativeFinalOffsetSubtracts)
{
    uint64_t cell = 0;
    uintptr_t holder = reinterpret_cast<uintptr_t>(&cell);

    // A negative final offset exercises the wrap in the final-add branch, which
    // is added to the resolved address but never dereferenced.
    const ptrdiff_t neg = -0x10;
    const auto addr = Memory::seh_resolve_chain(
        reinterpret_cast<uintptr_t>(&holder), {0, neg});
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(*addr, reinterpret_cast<uintptr_t>(&cell) - 0x10);
}

TEST(MemorySehReadChain, TwoLevelReadsTypedValue)
{
    uint64_t target = 0x1122334455667788ull;
    uintptr_t mid = reinterpret_cast<uintptr_t>(&target);
    uintptr_t root = reinterpret_cast<uintptr_t>(&mid);

    const auto value = Memory::seh_read_chain<uint64_t>(
        reinterpret_cast<uintptr_t>(&root), {0, 0, 0});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, target);
}

TEST(MemorySehReadChain, FaultReturnsNullopt)
{
    uintptr_t null_holder = 0;
    const auto value = Memory::seh_read_chain<uint32_t>(
        reinterpret_cast<uintptr_t>(&null_holder), {0, 0});
    EXPECT_FALSE(value.has_value());
}

TEST(MemorySehReadChain, NullOutAndZeroBytes)
{
    uint64_t target = 0xCAFEBABEull;
    const auto base = reinterpret_cast<uintptr_t>(&target);

    // nullptr destination is rejected.
    EXPECT_FALSE(Memory::seh_read_chain_bytes(base, std::span<const ptrdiff_t>{},
                                              nullptr, sizeof(target)));

    // Zero-byte read is a no-op success.
    uint8_t scratch = 0;
    EXPECT_TRUE(Memory::seh_read_chain_bytes(base, std::span<const ptrdiff_t>{},
                                             &scratch, 0));
}

TEST(MemorySehReadChain, EmptyChainReadsAtBase)
{
    uint32_t target = 0xCAFEBABEu;
    uint32_t out = 0;
    const bool ok = Memory::seh_read_chain_bytes(
        reinterpret_cast<uintptr_t>(&target),
        std::span<const ptrdiff_t>{}, &out, sizeof(out));
    EXPECT_TRUE(ok);
    EXPECT_EQ(out, 0xCAFEBABEu);
}

TEST(MemorySehReadChain, ReadsNonDefaultConstructibleType)
{
    // A trivially copyable type with a deleted default constructor: the read is
    // a raw byte copy reinterpreted with std::bit_cast, so it must work without
    // ever default-constructing T.
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
    const auto value = Memory::seh_read_chain<NoDefault>(
        reinterpret_cast<uintptr_t>(&holder), {0, 0});
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(value->a, 0xAABBCCDDu);
    EXPECT_EQ(value->b, 0x11223344u);
}
