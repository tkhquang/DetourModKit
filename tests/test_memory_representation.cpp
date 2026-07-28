/**
 * @file test_memory_representation.cpp
 * @brief Compile-time participation matrix for the representation-safe typed-read domain.
 *
 * The participation matrix is made of static assertions and is proven when this translation unit compiles. Runtime
 * cases instantiate the accepted routes and verify their decoded values.
 */

#include <gtest/gtest.h>

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

#include "DetourModKit/address.hpp"
#include "DetourModKit/memory.hpp"

#include "internal/memory_guarded.hpp"

namespace memory = DetourModKit::memory;
using DetourModKit::Address;
using DetourModKit::detail::is_representation_safe_v;

namespace
{
    enum UnfixedEnum
    {
        UnfixedZero = 0,
        UnfixedOne = 1
    };

    enum UnfixedSignedEnum
    {
        UnfixedNegative = -1,
        UnfixedPositive = 1
    };

    enum FixedUnscopedEnum : unsigned char
    {
        FixedUnscopedValue = 1
    };

    enum class ScopedDefaultEnum
    {
        Value
    };

    enum class ScopedWideEnum : std::uint64_t
    {
        Value
    };

    enum class ScopedCharEnum : char8_t
    {
        Value
    };

    // A fixed underlying type is not sufficient on its own: bool contributes only two valid object representations, so
    // an enumeration over it is exactly as unsafe to bit_cast from a foreign byte as bool itself.
    enum class ScopedBoolEnum : bool
    {
        False,
        True
    };

    struct PlainTrivial
    {
        std::uint32_t a;
        std::uint32_t b;
    };

    struct OptedAggregate
    {
        std::uint32_t a;
        float b;
    };

    union OptedUnion
    {
        std::uint64_t bits;
        double value;
    };

    struct WithMemberPointer
    {
        int field;
        void method();
    };

    struct NonTriviallyCopyable
    {
        NonTriviallyCopyable(const NonTriviallyCopyable &) {}
        NonTriviallyCopyable &operator=(const NonTriviallyCopyable &) { return *this; }
        int value;
    };
} // namespace

namespace DetourModKit::detail
{
    template <> struct enable_representation_safe_aggregate<::OptedAggregate> : std::true_type
    {
    };

    template <> struct enable_representation_safe_aggregate<::OptedUnion> : std::true_type
    {
    };
} // namespace DetourModKit::detail

namespace
{
    // These probes verify that each route's declaration is constrained by the domain. Runtime cases below instantiate
    // accepted function bodies as well, because a requires-expression alone does not do that.
    template <class T>
    concept guarded_read_participates = requires(Address address) { memory::read<T>(address); };

    template <class T>
    concept unchecked_read_participates = requires(Address address) { memory::unchecked::read<T>(address); };

    template <class T>
    concept engine_read_participates =
        requires(std::uintptr_t address) { DetourModKit::detail::guarded_read<T>(address); };

    template <class T> constexpr bool every_route_agrees_with_domain()
    {
        constexpr bool expected = is_representation_safe_v<T> && std::is_trivially_copyable_v<T>;
        return guarded_read_participates<T> == expected && unchecked_read_participates<T> == expected &&
               engine_read_participates<T> == expected;
    }
} // namespace

// Integral: every integral type except bool participates.
static_assert(is_representation_safe_v<char>);
static_assert(is_representation_safe_v<signed char>);
static_assert(is_representation_safe_v<unsigned char>);
static_assert(is_representation_safe_v<char8_t>);
static_assert(is_representation_safe_v<char16_t>);
static_assert(is_representation_safe_v<char32_t>);
static_assert(is_representation_safe_v<wchar_t>);
static_assert(is_representation_safe_v<short>);
static_assert(is_representation_safe_v<unsigned short>);
static_assert(is_representation_safe_v<int>);
static_assert(is_representation_safe_v<unsigned int>);
static_assert(is_representation_safe_v<long>);
static_assert(is_representation_safe_v<unsigned long>);
static_assert(is_representation_safe_v<long long>);
static_assert(is_representation_safe_v<unsigned long long>);
static_assert(is_representation_safe_v<std::uintptr_t>);
static_assert(is_representation_safe_v<std::ptrdiff_t>);
static_assert(is_representation_safe_v<std::size_t>);

// bool is the one integral the domain refuses: 0x02 is not a valid bool object representation.
static_assert(!is_representation_safe_v<bool>);
static_assert(!is_representation_safe_v<const bool>);
static_assert(!is_representation_safe_v<bool[4]>);
static_assert(!is_representation_safe_v<std::array<bool, 4>>);

// cv qualification never changes participation.
static_assert(is_representation_safe_v<const int>);
static_assert(is_representation_safe_v<volatile int>);
static_assert(is_representation_safe_v<const volatile int>);
static_assert(is_representation_safe_v<const Address>);

// Floating point: only a binary format with no padding bits.
static_assert(is_representation_safe_v<float>);
static_assert(is_representation_safe_v<double>);
static_assert(sizeof(float) * CHAR_BIT == 32 && std::numeric_limits<float>::digits == 24);
static_assert(sizeof(double) * CHAR_BIT == 64 && std::numeric_limits<double>::digits == 53);

#if defined(_MSC_VER)
// MSVC's long double IS double: same size, same format, so it participates.
static_assert(sizeof(long double) == sizeof(double));
static_assert(std::numeric_limits<long double>::digits == std::numeric_limits<double>::digits);
static_assert(is_representation_safe_v<long double>);
#else
// MinGW's long double is the x87 80-bit format stored in 16 bytes, so 48 bits of every object are padding whose value
// is unspecified. std::numeric_limits reports is_iec559, which is exactly why is_iec559 alone cannot be the gate: this
// pair of assertions fails the moment the padding check is weakened back to it.
static_assert(sizeof(long double) * CHAR_BIT == 128);
static_assert(std::numeric_limits<long double>::digits == 64);
static_assert(std::numeric_limits<long double>::is_iec559);
static_assert(!is_representation_safe_v<long double>);
static_assert(!is_representation_safe_v<long double[2]>);
#endif

// Enumerations: a fixed underlying type that is itself in the domain.
static_assert(is_representation_safe_v<FixedUnscopedEnum>);
static_assert(is_representation_safe_v<ScopedDefaultEnum>);
static_assert(is_representation_safe_v<ScopedWideEnum>);
static_assert(is_representation_safe_v<ScopedCharEnum>);
static_assert(is_representation_safe_v<std::byte>);
static_assert(!is_representation_safe_v<UnfixedEnum>);
static_assert(!is_representation_safe_v<UnfixedSignedEnum>);
static_assert(!is_representation_safe_v<UnfixedEnum[3]>);
static_assert(!is_representation_safe_v<ScopedBoolEnum>);

// Pointers: object and function pointers only, under the supported Windows x64 flat-pointer ABI. Member pointers and
// nullptr_t do not share that representation contract.
static_assert(is_representation_safe_v<int *>);
static_assert(is_representation_safe_v<const int *>);
static_assert(is_representation_safe_v<void *>);
static_assert(is_representation_safe_v<void (*)()>);
static_assert(is_representation_safe_v<int (*)[4]>);
static_assert(is_representation_safe_v<Address *>);
static_assert(!is_representation_safe_v<std::nullptr_t>);
static_assert(!is_representation_safe_v<int WithMemberPointer::*>);
static_assert(!is_representation_safe_v<void (WithMemberPointer::*)()>);
static_assert(!is_representation_safe_v<int WithMemberPointer::*[2]>);

// Arrays and std::array propagate the element verdict recursively.
static_assert(is_representation_safe_v<int[4]>);
static_assert(is_representation_safe_v<int[2][3]>);
static_assert(is_representation_safe_v<std::byte[16]>);
static_assert(!is_representation_safe_v<int[]>);
static_assert(!is_representation_safe_v<std::byte[]>);
static_assert(is_representation_safe_v<std::array<std::uint32_t, 4>>);
static_assert(is_representation_safe_v<std::array<std::array<int, 2>, 3>>);
static_assert(is_representation_safe_v<std::array<Address, 2>>);
static_assert(!is_representation_safe_v<std::array<std::nullptr_t, 2>>);
static_assert(!is_representation_safe_v<std::array<std::array<bool, 2>, 3>>);

// Class and union types participate only by explicit opt-in.
static_assert(std::is_trivially_copyable_v<PlainTrivial>);
static_assert(!is_representation_safe_v<PlainTrivial>);
static_assert(is_representation_safe_v<OptedAggregate>);
static_assert(is_representation_safe_v<OptedUnion>);
static_assert(is_representation_safe_v<OptedAggregate[2]>);
static_assert(!is_representation_safe_v<NonTriviallyCopyable>);

// Address is opted in by memory.hpp itself, pinned to exactly one uintptr_t, so read<Address> is the documented way to
// pull a foreign pointer straight into the addressing vocabulary.
static_assert(is_representation_safe_v<Address>);
static_assert(std::is_trivially_copyable_v<Address>);
static_assert(sizeof(Address) == sizeof(std::uintptr_t));
static_assert(alignof(Address) == alignof(std::uintptr_t));

// Non-object and non-copyable categories are rejected without a hard error.
static_assert(!is_representation_safe_v<void>);
static_assert(!is_representation_safe_v<int &>);
static_assert(!is_representation_safe_v<const int &>);
static_assert(!is_representation_safe_v<int &&>);
static_assert(!is_representation_safe_v<int()>);

// Every read route enforces the same domain.
static_assert(every_route_agrees_with_domain<std::uint32_t>());
static_assert(every_route_agrees_with_domain<float>());
static_assert(every_route_agrees_with_domain<Address>());
static_assert(every_route_agrees_with_domain<std::byte>());
static_assert(every_route_agrees_with_domain<ScopedWideEnum>());
static_assert(every_route_agrees_with_domain<OptedAggregate>());
static_assert(every_route_agrees_with_domain<int[2]>());
static_assert(every_route_agrees_with_domain<const int[2]>());
// The unbounded rejection has to hold at every route, not only in the trait: `sizeof` on an array of unknown bound is
// ill-formed, so a route that accepted one would hard-error instead of failing its constraint.
static_assert(every_route_agrees_with_domain<int[]>());
static_assert(every_route_agrees_with_domain<std::byte[]>());
static_assert(every_route_agrees_with_domain<std::array<std::uint32_t, 4>>());
static_assert(every_route_agrees_with_domain<bool>());
static_assert(every_route_agrees_with_domain<std::nullptr_t>());
static_assert(every_route_agrees_with_domain<UnfixedEnum>());
static_assert(every_route_agrees_with_domain<ScopedBoolEnum>());
static_assert(every_route_agrees_with_domain<int WithMemberPointer::*>());
static_assert(every_route_agrees_with_domain<void (WithMemberPointer::*)()>());
static_assert(every_route_agrees_with_domain<PlainTrivial>());
static_assert(every_route_agrees_with_domain<NonTriviallyCopyable>());
static_assert(every_route_agrees_with_domain<long double>());

TEST(MemoryRepresentationTest, ParticipationMatrixIsProvenAtCompileTime)
{
    // The matrix above is the proof; this case exists so ctest reports which build carried it.
    SUCCEED();
}

// Accepted types must instantiate and round-trip through their real read routes, not merely satisfy the declarations.
TEST(MemoryRepresentationTest, AcceptedTypesInstantiateAndRoundTrip)
{
    const std::uintptr_t pointer_source = 0x1122334455667788ULL;
    const auto address_value = memory::read<Address>(Address{&pointer_source});
    ASSERT_TRUE(address_value.has_value());
    EXPECT_EQ(address_value->raw(), pointer_source);

    const OptedAggregate aggregate_source{0xDEADBEEFU, 1.5F};
    const auto aggregate_value = memory::read<OptedAggregate>(Address{&aggregate_source});
    ASSERT_TRUE(aggregate_value.has_value());
    EXPECT_EQ(aggregate_value->a, aggregate_source.a);
    EXPECT_EQ(aggregate_value->b, aggregate_source.b);

    const std::array<std::byte, 4> byte_source{std::byte{0x01}, std::byte{0xFE}, std::byte{0x7F}, std::byte{0x80}};
    const auto byte_value = memory::read<std::array<std::byte, 4>>(Address{&byte_source});
    ASSERT_TRUE(byte_value.has_value());
    EXPECT_EQ(*byte_value, byte_source);

    const int built_in_source[2]{17, 42};
    const std::array<int, 2> expected_built_in{17, 42};
    static_assert(std::is_same_v<decltype(memory::read<int[2]>(Address{})), DetourModKit::Result<std::array<int, 2>>>);

    const auto guarded_built_in = memory::read<int[2]>(Address{&built_in_source});
    ASSERT_TRUE(guarded_built_in.has_value());
    EXPECT_EQ(*guarded_built_in, expected_built_in);

    const auto unchecked_built_in = memory::unchecked::read<int[2]>(Address{&built_in_source});
    EXPECT_EQ(unchecked_built_in, expected_built_in);

    const auto engine_built_in = DetourModKit::detail::guarded_read<int[2]>(Address{&built_in_source}.raw());
    ASSERT_TRUE(engine_built_in.has_value());
    EXPECT_EQ(*engine_built_in, expected_built_in);

    const int nested_source[2][3]{{1, 2, 3}, {4, 5, 6}};
    const std::array<std::array<int, 3>, 2> expected_nested{{{1, 2, 3}, {4, 5, 6}}};
    static_assert(std::is_same_v<decltype(memory::read<int[2][3]>(Address{})),
                                 DetourModKit::Result<std::array<std::array<int, 3>, 2>>>);
    const auto nested_value = memory::read<int[2][3]>(Address{&nested_source});
    ASSERT_TRUE(nested_value.has_value());
    EXPECT_EQ(*nested_value, expected_nested);
}
