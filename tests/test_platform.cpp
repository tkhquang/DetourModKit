#include <gtest/gtest.h>
#include <cstring>

#include <windows.h>

#include "platform.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/version.hpp"

using namespace DetourModKit::detail;
using DetourModKit::diagnostics::module_pin_count;
using DetourModKit::diagnostics::ModulePinReason;

TEST(PlatformTest, IsLoaderLockHeld_FalseInNormalContext)
{
    EXPECT_FALSE(is_loader_lock_held());
}

// The acquire must identify this module and book its reason until release.
TEST(PlatformTest, AcquireModuleRef_ReturnsThisModuleAndBooksItsReason)
{
    const std::size_t pins_before = module_pin_count(ModulePinReason::Worker);
    const HMODULE ref = acquire_module_ref(ModulePinReason::Worker);
    ASSERT_NE(ref, nullptr) << "acquire_module_ref must take a reference on a loaded module";
    EXPECT_EQ(module_pin_count(ModulePinReason::Worker), pins_before + 1);

    // The reference identifies the module that owns this test's code.
    HMODULE by_address = nullptr;
    ASSERT_TRUE(
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&is_loader_lock_held), &by_address));
    EXPECT_EQ(ref, by_address);

    release_module_ref(ref, ModulePinReason::Worker);
    EXPECT_EQ(module_pin_count(ModulePinReason::Worker), pins_before);
}

// Every acquire is balanced by a release. The test binary is the process image and never unloads, so the observable
// contract is that each balanced cycle returns the same live module handle with stable loader and per-reason counts.
TEST(PlatformTest, AcquireReleaseModuleRef_BalancesAcrossCycles)
{
    const std::size_t pins_before = module_pin_count(ModulePinReason::Worker);
    const HMODULE first = acquire_module_ref(ModulePinReason::Worker);
    ASSERT_NE(first, nullptr);
    for (int i = 0; i < 8; ++i)
    {
        const HMODULE ref = acquire_module_ref(ModulePinReason::Worker);
        EXPECT_EQ(ref, first) << "each acquire identifies the same module";
        release_module_ref(ref, ModulePinReason::Worker);
    }
    release_module_ref(first, ModulePinReason::Worker);
    EXPECT_EQ(module_pin_count(ModulePinReason::Worker), pins_before);

    // The module is still loaded (the process holds it), so a fresh acquire still succeeds after the cycles.
    const HMODULE again = acquire_module_ref(ModulePinReason::Worker);
    EXPECT_EQ(again, first);
    release_module_ref(again, ModulePinReason::Worker);
}

// release_module_ref(nullptr) is a documented no-op (a failed acquire yields nullptr), so the release path can be
// invoked unconditionally without a null check at every call site. A no-op release books no pin decrement.
TEST(PlatformTest, ReleaseModuleRef_NullIsNoOp)
{
    const std::size_t pins_before = module_pin_count(ModulePinReason::Worker);
    release_module_ref(nullptr, ModulePinReason::Worker); // must not crash
    EXPECT_EQ(module_pin_count(ModulePinReason::Worker), pins_before);
}

// Version macro tests

TEST(VersionTest, MajorMinorPatchAreDefined)
{
    EXPECT_GE(DMK_VERSION_MAJOR, 0);
    EXPECT_GE(DMK_VERSION_MINOR, 0);
    EXPECT_GE(DMK_VERSION_PATCH, 0);
}

TEST(VersionTest, VersionStringIsNonEmpty)
{
    EXPECT_GT(std::strlen(DMK_VERSION_STRING), 0u);
}

TEST(VersionTest, MakeVersionEncoding)
{
    EXPECT_EQ(DMK_MAKE_VERSION(2, 3, 0), 2003000);
    EXPECT_EQ(DMK_MAKE_VERSION(1, 0, 0), 1000000);
    EXPECT_EQ(DMK_MAKE_VERSION(0, 0, 1), 1);
    // The minor and patch fields reserve three decimal digits each (0..999), so a multi-digit minor no longer collides
    // and a higher minor can never overtake the next major.
    EXPECT_EQ(DMK_MAKE_VERSION(0, 100, 0), 100000);
    EXPECT_GT(DMK_MAKE_VERSION(1, 0, 0), DMK_MAKE_VERSION(0, 999, 999));
}

TEST(VersionTest, VersionAtLeast)
{
    EXPECT_TRUE(DMK_VERSION_AT_LEAST(0, 0, 1));
    EXPECT_TRUE(DMK_VERSION_AT_LEAST(DMK_VERSION_MAJOR, DMK_VERSION_MINOR, DMK_VERSION_PATCH));
    EXPECT_FALSE(DMK_VERSION_AT_LEAST(99, 0, 0));
}

TEST(VersionTest, CompositeMatchesComponents)
{
    EXPECT_EQ(DMK_VERSION, DMK_MAKE_VERSION(DMK_VERSION_MAJOR, DMK_VERSION_MINOR, DMK_VERSION_PATCH));
}
