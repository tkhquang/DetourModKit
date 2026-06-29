#include <gtest/gtest.h>

#include <cstdint>
#include <expected>
#include <string>
#include <type_traits>
#include <utility>

#include "DetourModKit/address.hpp"
#include "DetourModKit/defines.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/region.hpp"

using namespace DetourModKit;

// DMK_TRY / DMK_TRY_VOID propagation. The mere existence of these helpers is half the test: this translation unit
// must compile while exercising the value-bind form on a Result<T>, the void form on a Result<void>, and a nested
// use. The runtime assertions then confirm the propagation semantics (short-circuit on the first failure, move the
// value out on success).

namespace
{
    // A fallible producer that, on failure, stamps both raw context slots so the propagation tests can prove the
    // Error travels through DMK_TRY byte-for-byte rather than being reconstructed.
    [[nodiscard]] Result<int> produce_int(bool succeed)
    {
        if (!succeed)
        {
            return std::unexpected(Error{ErrorCode::NoMatch, "scan", 0xDEADBEEF, 7});
        }
        return 42;
    }

    [[nodiscard]] Result<void> produce_void(bool succeed)
    {
        if (!succeed)
        {
            return std::unexpected(Error{ErrorCode::ProtectionChangeFailed, "memory"});
        }
        return {};
    }

    // Value-bind form on Result<T>, then the void form on Result<void>, then a second value-bind in the same scope:
    // proves the per-variable temporary naming lets several DMK_TRY uses coexist without colliding.
    [[nodiscard]] Result<int> sum_two_then_gate(bool first_ok, bool gate_ok)
    {
        DMK_TRY(first, produce_int(first_ok));
        DMK_TRY_VOID(produce_void(gate_ok));
        DMK_TRY(second, produce_int(true));
        return first + second;
    }

    // Genuinely nested scopes: a DMK_TRY in an outer block and a DMK_TRY_VOID inside an inner block, to confirm the
    // void form's do/while scoping survives nesting.
    [[nodiscard]] Result<int> nested_use(bool outer_ok, bool inner_ok)
    {
        DMK_TRY(outer, produce_int(outer_ok));
        if (outer > 0)
        {
            DMK_TRY_VOID(produce_void(inner_ok));
            return outer;
        }
        return 0;
    }
} // namespace

TEST(FoundationErrorTry, ValueAndVoidFormsSucceed)
{
    const Result<int> result = sum_two_then_gate(true, true);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 84);
}

TEST(FoundationErrorTry, ValueFormPropagatesFirstFailureUnchanged)
{
    const Result<int> result = sum_two_then_gate(false, true);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NoMatch);
    EXPECT_STREQ(result.error().where, "scan");
    EXPECT_EQ(result.error().detail, 0xDEADBEEFU);
    EXPECT_EQ(result.error().extra, 7U);
}

TEST(FoundationErrorTry, VoidFormPropagatesFailure)
{
    const Result<int> result = sum_two_then_gate(true, false);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::ProtectionChangeFailed);
    EXPECT_STREQ(result.error().where, "memory");
}

TEST(FoundationErrorTry, NestedUseShortCircuits)
{
    EXPECT_EQ(nested_use(true, true).value(), 42);
    EXPECT_FALSE(nested_use(false, true).has_value());
    EXPECT_FALSE(nested_use(true, false).has_value());
}

// Compile-time proof that the high byte names the subsystem; if a block base is ever mis-assigned this fails the
// build, not a test run.
static_assert(category(ErrorCode::Ok) == ErrorCategory::General);
static_assert(category(ErrorCode::InvalidArg) == ErrorCategory::General);
static_assert(category(ErrorCode::AllocatorNotAvailable) == ErrorCategory::Hook);
static_assert(category(ErrorCode::UnknownError) == ErrorCategory::Hook);
static_assert(category(ErrorCode::EmptyCandidates) == ErrorCategory::Scan);
static_assert(category(ErrorCode::NoMatch) == ErrorCategory::Scan);
static_assert(category(ErrorCode::StoreNotFound) == ErrorCategory::Scan);
static_assert(category(ErrorCode::NullTargetAddress) == ErrorCategory::Memory);
static_assert(category(ErrorCode::BadSlotAddress) == ErrorCategory::Rtti);
static_assert(category(ErrorCode::HealAmbiguous) == ErrorCategory::Rtti);
static_assert(category(ErrorCode::MissingHeader) == ErrorCategory::Manifest);
static_assert(category(ErrorCode::FileOpenFailed) == ErrorCategory::Manifest);

TEST(FoundationErrorCode, CategoryMatchesSubsystem)
{
    EXPECT_EQ(category(ErrorCode::BackendFailed), ErrorCategory::Hook);
    EXPECT_EQ(category(ErrorCode::OperandOutOfRange), ErrorCategory::Scan);
    EXPECT_EQ(category(ErrorCode::ImplausibleTarget), ErrorCategory::Scan);
    EXPECT_EQ(category(ErrorCode::ProtectionRestoreFailed), ErrorCategory::Memory);
    EXPECT_EQ(category(ErrorCode::HealNoMatch), ErrorCategory::Rtti);
}

TEST(FoundationErrorCode, ToStringNamesCodeAndCategory)
{
    EXPECT_EQ(to_string(ErrorCode::BackendFailed), "BackendFailed");
    EXPECT_EQ(to_string(ErrorCode::HealNoMatch), "HealNoMatch");
    EXPECT_EQ(to_string(ErrorCategory::Scan), "scan");
    EXPECT_EQ(to_string(ErrorCategory::Manifest), "manifest");
}

TEST(FoundationErrorCode, MessageIsGreppableByCategoryAndCode)
{
    const Error error{ErrorCode::NoMatch, "scan", 0x1234, 9};
    const std::string text = error.message();
    EXPECT_NE(text.find("[scan]"), std::string::npos);
    EXPECT_NE(text.find("NoMatch"), std::string::npos);
    EXPECT_NE(text.find("scan"), std::string::npos);
    EXPECT_NE(text.find("1234"), std::string::npos);
}

TEST(FoundationErrorCode, ErrorIsTriviallyCopyable)
{
    EXPECT_TRUE(std::is_trivially_copyable_v<Error>);
}

TEST(FoundationAddress, NullAndBoolean)
{
    constexpr Address null_address{};
    EXPECT_EQ(null_address.raw(), 0U);
    EXPECT_FALSE(static_cast<bool>(null_address));
    EXPECT_EQ(Address{nullptr}, null_address);

    constexpr Address live{0x1000};
    EXPECT_EQ(live.raw(), 0x1000U);
    EXPECT_TRUE(static_cast<bool>(live));
}

TEST(FoundationAddress, OffsetWrapsSignedDelta)
{
    constexpr Address base{0x1000};
    EXPECT_EQ(base.offset(0x10).raw(), 0x1010U);
    EXPECT_EQ(base.offset(-0x10).raw(), 0x0FF0U);
}

TEST(FoundationAddress, AlignUpRoundsToPowerOfTwo)
{
    EXPECT_EQ(Address{0x1234}.align_up(0x1000).raw(), 0x2000U);
    EXPECT_EQ(Address{0x2000}.align_up(0x1000).raw(), 0x2000U);
    EXPECT_EQ(Address{0x0001}.align_up(0x10).raw(), 0x0010U);
}

TEST(FoundationAddress, PointerRoundTripThroughAuditedCasts)
{
    int sample = 7;
    const Address address{&sample};
    EXPECT_EQ(address.ptr<int>(), &sample);
    EXPECT_EQ(*address.ptr<int>(), 7);
    EXPECT_EQ(address.as<int *>(), &sample);
    EXPECT_EQ(address.as<std::uintptr_t>(), address.raw());
}

TEST(FoundationAddress, OrderingIsByRawValue)
{
    EXPECT_LT(Address{1}, Address{2});
    EXPECT_GT(Address{2}, Address{1});
    EXPECT_EQ(Address{0x55}, Address{0x55});
    EXPECT_NE(Address{0x55}, Address{0x56});
}

TEST(FoundationRegion, HalfOpenContainmentAndEnd)
{
    constexpr Region region{Address{0x1000}, 0x100};
    EXPECT_EQ(region.end().raw(), 0x1100U);
    EXPECT_TRUE(region.contains(Address{0x1000}));
    EXPECT_TRUE(region.contains(Address{0x10FF}));
    EXPECT_FALSE(region.contains(Address{0x1100}));
    EXPECT_FALSE(region.contains(Address{0x0FFF}));
}

TEST(FoundationRegion, EmptyRegionContainsNothing)
{
    constexpr Region empty{};
    EXPECT_EQ(empty.size, 0U);
    EXPECT_FALSE(empty.contains(Address{}));
    EXPECT_FALSE(empty.contains(Address{0x1000}));
}

TEST(FoundationRegion, SubCarvesInnerWindow)
{
    constexpr Region region{Address{0x1000}, 0x100};
    constexpr Region inner = region.sub(0x10, 0x20);
    EXPECT_EQ(inner.base.raw(), 0x1010U);
    EXPECT_EQ(inner.size, 0x20U);
}

TEST(FoundationRegion, HostAndWholeProcessResolve)
{
    const Region host = Region::host();
    EXPECT_TRUE(static_cast<bool>(host.base));
    EXPECT_GT(host.size, 0U);

    const Region whole = Region::whole_process();
    EXPECT_TRUE(static_cast<bool>(whole.base));
    EXPECT_GT(whole.size, 0U);
}

TEST(FoundationRegion, ModuleNamedResolvesLoadedAndFailsClosed)
{
    // kernel32.dll is mapped into every Win32 process, so its Region must resolve non-empty.
    const Region kernel32 = Region::module_named("kernel32.dll");
    EXPECT_TRUE(static_cast<bool>(kernel32.base));
    EXPECT_GT(kernel32.size, 0U);

    // An empty name and an unloaded module both fail closed to an empty Region.
    EXPECT_EQ(Region::module_named("").size, 0U);
    EXPECT_EQ(Region::module_named("a_module_that_is_not_loaded_zzzz.dll").size, 0U);
}

static_assert((Prot::R | Prot::W) == Prot::RW);
static_assert((Prot::R | Prot::W | Prot::X) == Prot::RWX);
static_assert((Prot::RWX & Prot::X) == Prot::X);

TEST(FoundationProt, BitwiseAndCompoundOperators)
{
    EXPECT_EQ(Prot::R | Prot::W, Prot::RW);
    EXPECT_EQ(Prot::RWX & Prot::W, Prot::W);

    Prot accumulated = Prot::R;
    accumulated |= Prot::W;
    EXPECT_EQ(accumulated, Prot::RW);
    accumulated &= Prot::R;
    EXPECT_EQ(accumulated, Prot::R);
}
