#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/scan.hpp"

#include "internal/export_resolution.hpp"

#include <windows.h>
#include "fixtures/anchor_fixture.hpp"
using namespace dmk_test::anchor_fixture;

// The fixture DLL exports direct symbols. GetProcAddress supplies an exact address without a kernel32 forwarder.

TEST(AnchorTest, ExportNameResolvesForeignModuleFunction)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok()) << "Failed to load " << ExportFixture::MODULE_NAME << ": " << GetLastError();
    const std::uintptr_t expected = fixture.proc("compute_damage");
    ASSERT_NE(expected, 0U);

    // The named export module differs from the host scan scope. Its address must still resolve.
    an::Anchor anchor{};
    anchor.label = "fixture.compute_damage";
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "compute_damage";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), expected);
}

TEST(AnchorTest, ExportNameResolvesWithinScopeWhenModuleEmpty)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());
    const std::uintptr_t expected = fixture.proc("compute_armor");
    ASSERT_NE(expected, 0U);

    // The empty export_module uses the passed fixture scope.
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_name = "compute_armor";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::module_named(ExportFixture::MODULE_NAME));
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), expected);
}

TEST(AnchorTest, ExportNameResolvesDataExport)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());
    const std::uintptr_t expected = fixture.proc("dmk_scan_marker");
    ASSERT_NE(expected, 0U);

    // The data RVA lies outside the export directory. A data export must not appear to be a forwarder.
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "dmk_scan_marker";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), expected);
}

TEST(AnchorTest, ExportNameFailsClosedWhenExportAbsent)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "ThisExportDoesNotExistInTheFixture";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, ExportNameFailsClosedForUnloadedModule)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = "detourmodkit_not_a_real_module_zzz.dll";
    anchor.export_name = "compute_damage";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

// The scan layer exposes precise errors beneath the anchor wrapper.
TEST(ScanExportTest, ResolvesPresentExportAndFailsClosed)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());
    const dmk::Region module = dmk::Region::module_named(ExportFixture::MODULE_NAME);

    const dmk::Result<dmk::Address> hit = sc::resolve_export("compute_speed", module);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->raw(), fixture.proc("compute_speed"));

    const dmk::Result<dmk::Address> absent = sc::resolve_export("NoSuchExportZZZ", module);
    ASSERT_FALSE(absent.has_value());
    EXPECT_EQ(absent.error().code, dmk::ErrorCode::ExportNotFound);
    EXPECT_EQ(dmk::to_string(absent.error().code), "ExportNotFound");

    const dmk::Result<dmk::Address> empty = sc::resolve_export("", module);
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(empty.error().code, dmk::ErrorCode::ExportNotFound);

    const dmk::Result<dmk::Address> no_module = sc::resolve_export("compute_speed", dmk::Region{});
    ASSERT_FALSE(no_module.has_value());
    EXPECT_EQ(no_module.error().code, dmk::ErrorCode::InvalidRange);
}

TEST(ScanExportTest, SyntheticImageResolvesDirectExport)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), image.range().base.raw() + SyntheticExportImage::TARGET_RVA);

    const dmk::Region narrow{image.range().base, SyntheticExportImage::TARGET_RVA + 1};
    const dmk::Result<dmk::Address> narrow_result = sc::resolve_export("fixture_export", narrow);
    ASSERT_TRUE(narrow_result.has_value());
    EXPECT_EQ(*narrow_result, *result);

    const dmk::Region header_truncated{image.range().base, 1};
    const dmk::Result<dmk::Address> truncated_result = sc::resolve_export("fixture_export", header_truncated);
    ASSERT_FALSE(truncated_result.has_value());
    EXPECT_EQ(truncated_result.error().code, dmk::ErrorCode::InvalidRange);

    constexpr char embedded_nul_name[] = "fixture_export\0";
    const dmk::Result<dmk::Address> embedded_nul_result =
        sc::resolve_export(std::string_view{embedded_nul_name, sizeof(embedded_nul_name) - 1}, image.range());
    ASSERT_FALSE(embedded_nul_result.has_value());
    EXPECT_EQ(embedded_nul_result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, ForwardedExportFailsClosed)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::uint32_t forwarder_rva = SyntheticExportImage::EXPORT_RVA + 0x80;
    image.put(SyntheticExportImage::FUNCTIONS_RVA, forwarder_rva);
    image.put_string(forwarder_rva, "other.fixture_export");

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportForwarded);
    EXPECT_EQ(dmk::to_string(result.error().code), "ExportForwarded");
}

TEST(ScanExportTest, TruncatedOptionalHeaderFailsClosed)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    IMAGE_NT_HEADERS64 nt = image.get<IMAGE_NT_HEADERS64>(SyntheticExportImage::NT_RVA);
    nt.FileHeader.SizeOfOptionalHeader = static_cast<WORD>(offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory));
    image.put(SyntheticExportImage::NT_RVA, nt);

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, OutOfImageExportDirectoryAndArraysFailClosed)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    IMAGE_NT_HEADERS64 nt = image.get<IMAGE_NT_HEADERS64>(SyntheticExportImage::NT_RVA);
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {
        static_cast<DWORD>(SyntheticExportImage::IMAGE_BYTES - sizeof(IMAGE_EXPORT_DIRECTORY)),
        static_cast<DWORD>(sizeof(IMAGE_EXPORT_DIRECTORY) + 1)
    };
    image.put(SyntheticExportImage::NT_RVA, nt);

    const dmk::Result<dmk::Address> directory_result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(directory_result.has_value());
    EXPECT_EQ(directory_result.error().code, dmk::ErrorCode::ExportNotFound);

    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {
        SyntheticExportImage::EXPORT_RVA,
        SyntheticExportImage::EXPORT_BYTES
    };
    image.put(SyntheticExportImage::NT_RVA, nt);
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.AddressOfNames = static_cast<DWORD>(SyntheticExportImage::IMAGE_BYTES - 2);
    image.put(SyntheticExportImage::EXPORT_RVA, exports);

    const dmk::Result<dmk::Address> array_result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(array_result.has_value());
    EXPECT_EQ(array_result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, DuplicateMatchingNamesFailClosed)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.NumberOfNames = 2;
    image.put(SyntheticExportImage::EXPORT_RVA, exports);
    image.put(SyntheticExportImage::NAMES_RVA + sizeof(std::uint32_t), SyntheticExportImage::NAME_RVA);
    image.put(SyntheticExportImage::ORDINALS_RVA + sizeof(std::uint16_t), std::uint16_t{0});

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, NegativeNtHeaderOffsetFailsClosed)
{
    // e_lfanew is signed. Its negative value must fail before an unsigned RVA conversion can wrap below the image base.
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    IMAGE_DOS_HEADER dos = image.get<IMAGE_DOS_HEADER>(0);
    dos.e_lfanew = -1;
    image.put(0, dos);

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::InvalidRange);
}

TEST(ScanExportTest, EmptyNameTableFailsClosed)
{
    // A directory advertising zero names has nothing to match. The walk must fail closed on the count rather than treat
    // a zero-length name table as a resolvable state.
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.NumberOfNames = 0;
    image.put(SyntheticExportImage::EXPORT_RVA, exports);

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, UndersizedExportDirectoryFailsClosed)
{
    // The directory starts inside the image, but its size excludes the last byte of IMAGE_EXPORT_DIRECTORY. The refusal
    // must precede any incomplete struct read.
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    IMAGE_NT_HEADERS64 nt = image.get<IMAGE_NT_HEADERS64>(SyntheticExportImage::NT_RVA);
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {
        SyntheticExportImage::EXPORT_RVA,
        static_cast<DWORD>(sizeof(IMAGE_EXPORT_DIRECTORY) - 1)
    };
    image.put(SyntheticExportImage::NT_RVA, nt);

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, NameOrdinalOutOfFunctionRangeFailsClosed)
{
    // An ordinal equal to NumberOfFunctions indexes past AddressOfFunctions. The fixture isolates that bounds check.
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    image.put(SyntheticExportImage::ORDINALS_RVA, std::uint16_t{1});

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, ZeroFunctionRvaFailsClosed)
{
    // A zero function RVA marks an absent slot. The image base cannot serve as an export result.
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    image.put(SyntheticExportImage::FUNCTIONS_RVA, std::uint32_t{0});

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, OutOfImageFunctionRvaFailsClosed)
{
    // A function RVA that lands outside the mapped image, yet outside the export directory too, is a corrupt entry, not
    // a forwarder. It resolves to no in-image address and fails ExportNotFound rather than ExportForwarded.
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    image.put(SyntheticExportImage::FUNCTIONS_RVA, std::uint32_t{SyntheticExportImage::IMAGE_BYTES});

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, DeclaredImageExtentBoundsEveryExportRead)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    IMAGE_NT_HEADERS64 nt = image.get<IMAGE_NT_HEADERS64>(SyntheticExportImage::NT_RVA);
    nt.OptionalHeader.SizeOfImage = SyntheticExportImage::TARGET_RVA;
    image.put(SyntheticExportImage::NT_RVA, nt);

    dmk::detail::ExportResolution provenance{
        .module_base = 1,
        .function_index = 1,
        .function_rva = 1,
        .target = dmk::Address{1},
    };
    const dmk::Result<dmk::Address> target_result =
        dmk::detail::resolve_export_with_provenance("fixture_export", image.range(), provenance);
    ASSERT_FALSE(target_result.has_value());
    EXPECT_EQ(target_result.error().code, dmk::ErrorCode::ExportNotFound);
    EXPECT_FALSE(provenance.present());
    EXPECT_EQ(provenance.module_base, 0U);
    EXPECT_EQ(provenance.function_index, 0U);
    EXPECT_EQ(provenance.function_rva, 0U);
    EXPECT_EQ(provenance.target, dmk::Address{});

    // The function array moves above the name and ordinal tables. The declared image excludes only its final byte, so
    // other bounds checks cannot explain refusal.
    constexpr std::uint32_t moved_functions_rva = SyntheticExportImage::NAME_RVA + 0x40;
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.AddressOfFunctions = moved_functions_rva;
    image.put(SyntheticExportImage::EXPORT_RVA, exports);
    image.put(moved_functions_rva, static_cast<std::uint32_t>(SyntheticExportImage::TARGET_RVA));
    nt.OptionalHeader.SizeOfImage = moved_functions_rva + 3;
    image.put(SyntheticExportImage::NT_RVA, nt);
    const dmk::Result<dmk::Address> array_result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(array_result.has_value());
    EXPECT_EQ(array_result.error().code, dmk::ErrorCode::ExportNotFound);

    // Control: the same relocated array resolves once the declared extent covers it, so the refusal above is the
    // extent and not the relocation.
    nt.OptionalHeader.SizeOfImage = static_cast<DWORD>(SyntheticExportImage::IMAGE_BYTES);
    image.put(SyntheticExportImage::NT_RVA, nt);
    const dmk::Result<dmk::Address> covered = sc::resolve_export("fixture_export", image.range());
    ASSERT_TRUE(covered.has_value());
    EXPECT_EQ(covered->raw(), image.range().base.raw() + SyntheticExportImage::TARGET_RVA);
}

TEST(ScanExportTest, MalformedNameAfterAMatchFailsClosed)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.NumberOfNames = 2;
    image.put(SyntheticExportImage::EXPORT_RVA, exports);
    image.put(
        SyntheticExportImage::NAMES_RVA + sizeof(std::uint32_t),
        static_cast<std::uint32_t>(SyntheticExportImage::IMAGE_BYTES)
    );

    dmk::detail::ExportResolution provenance{
        .module_base = 1,
        .function_index = 1,
        .function_rva = 1,
        .target = dmk::Address{1},
    };
    const dmk::Result<dmk::Address> result =
        dmk::detail::resolve_export_with_provenance("fixture_export", image.range(), provenance);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
    EXPECT_FALSE(provenance.present());
    EXPECT_EQ(provenance.module_base, 0U);
    EXPECT_EQ(provenance.function_index, 0U);
    EXPECT_EQ(provenance.function_rva, 0U);
    EXPECT_EQ(provenance.target, dmk::Address{});
}

TEST(ScanExportTest, UnreadableNameTerminatorAfterAMatchFailsClosed)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view export_name = "fixture_export";
    constexpr std::uint32_t second_name_rva = 0x1000 - static_cast<std::uint32_t>(export_name.size());
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.NumberOfNames = 2;
    image.put(SyntheticExportImage::EXPORT_RVA, exports);
    image.put(SyntheticExportImage::NAMES_RVA + sizeof(std::uint32_t), second_name_rva);
    image.put_string(second_name_rva, export_name);
    ASSERT_TRUE(image.protect_no_access(0x1000));

    dmk::detail::ExportResolution provenance;
    const dmk::Result<dmk::Address> result =
        dmk::detail::resolve_export_with_provenance(export_name, image.range(), provenance);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
    EXPECT_FALSE(provenance.present());
}

TEST(AnchorTest, ExportNameCaseSensitiveMatch)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    // PE export names are case-sensitive. A wrong-case name must fail closed.
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "Compute_Damage";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

// Image identities are stable across repeated reads and reject incomplete PE metadata.

TEST(ImageIdentityTest, HostImageIsPresentStableAndTokenized)
{
    const sc::ImageIdentity a = sc::image_identity(dmk::Region::host());
    const sc::ImageIdentity b = sc::image_identity(dmk::Region::host());
    EXPECT_TRUE(a.present());
    EXPECT_NE(a.size_of_image, 0U);
    EXPECT_EQ(a, b); // deterministic for one live image
    EXPECT_EQ(a.token(), b.token());
}

TEST(ImageIdentityTest, EmptyRegionHasNoIdentity)
{
    const sc::ImageIdentity none = sc::image_identity(dmk::Region{dmk::Address{std::uintptr_t{0}}, 0});
    EXPECT_FALSE(none.present());
    EXPECT_EQ(none, sc::ImageIdentity{});
}

TEST(ImageIdentityTest, DistinctModulesHaveDistinctIdentity)
{
    const sc::ImageIdentity host = sc::image_identity(dmk::Region::host());
    const sc::ImageIdentity kernel = sc::image_identity(dmk::Region::module_named("kernel32.dll"));
    ASSERT_TRUE(host.present());
    ASSERT_TRUE(kernel.present());
    EXPECT_NE(host, kernel);
    EXPECT_NE(host.token(), kernel.token());
}

TEST(ImageIdentityTest, SyntheticImageFoldsItsHeaders)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    const sc::ImageIdentity before = sc::image_identity(image.range());
    ASSERT_TRUE(before.present());
    EXPECT_EQ(before.size_of_image, static_cast<std::uint32_t>(SyntheticExportImage::IMAGE_BYTES));
    EXPECT_EQ(before.section_digest, 0x158C65B516F4C541ULL);

    IMAGE_SECTION_HEADER section =
        image.get<IMAGE_SECTION_HEADER>(SyntheticExportImage::NT_RVA + sizeof(IMAGE_NT_HEADERS64));
    section.Characteristics ^= IMAGE_SCN_MEM_WRITE;
    image.put(SyntheticExportImage::NT_RVA + sizeof(IMAGE_NT_HEADERS64), section);
    const sc::ImageIdentity after = sc::image_identity(image.range());
    ASSERT_TRUE(after.present());
    EXPECT_NE(after.section_digest, before.section_digest);
}

TEST(ImageIdentityTest, ContentChangesWithIdenticalHeadersRemainTheSameIdentity)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    const sc::ImageIdentity before = sc::image_identity(image.range());
    ASSERT_TRUE(before.present());

    image.put(SyntheticExportImage::TARGET_RVA, std::uint8_t{0xCC});
    const sc::ImageIdentity after = sc::image_identity(image.range());
    ASSERT_TRUE(after.present());
    EXPECT_EQ(after, before);
}

TEST(ImageIdentityTest, UsesTheLiveImageExtentAndRejectsMalformedSectionTables)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());

    const dmk::Region narrow{image.range().base, sizeof(IMAGE_DOS_HEADER)};
    EXPECT_TRUE(sc::image_identity(narrow).present());

    IMAGE_NT_HEADERS64 nt = image.get<IMAGE_NT_HEADERS64>(SyntheticExportImage::NT_RVA);
    nt.FileHeader.NumberOfSections = 0;
    image.put(SyntheticExportImage::NT_RVA, nt);
    EXPECT_FALSE(sc::image_identity(image.range()).present());

    nt.FileHeader.NumberOfSections = 1;
    nt.FileHeader.SizeOfOptionalHeader = static_cast<WORD>(SyntheticExportImage::IMAGE_BYTES);
    image.put(SyntheticExportImage::NT_RVA, nt);
    EXPECT_FALSE(sc::image_identity(image.range()).present());
}

TEST(ImageIdentityTest, ExcessiveAndUnreadableSectionTablesFailClosed)
{
    SyntheticExportImage excessive;
    ASSERT_TRUE(excessive.ok());
    IMAGE_NT_HEADERS64 nt = excessive.get<IMAGE_NT_HEADERS64>(SyntheticExportImage::NT_RVA);
    nt.FileHeader.NumberOfSections = 97;
    excessive.put(SyntheticExportImage::NT_RVA, nt);
    EXPECT_FALSE(sc::image_identity(excessive.range()).present());

    SyntheticExportImage unreadable;
    ASSERT_TRUE(unreadable.ok());
    nt = unreadable.get<IMAGE_NT_HEADERS64>(SyntheticExportImage::NT_RVA);
    constexpr std::uint32_t second_page_rva = 0x1000;
    constexpr std::uint32_t section_table_rva =
        second_page_rva - static_cast<std::uint32_t>(sizeof(IMAGE_SECTION_HEADER) / 2);
    nt.FileHeader.SizeOfOptionalHeader = static_cast<WORD>(
        section_table_rva - SyntheticExportImage::NT_RVA - offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
    );
    unreadable.put(SyntheticExportImage::NT_RVA, nt);
    IMAGE_SECTION_HEADER section{};
    std::memcpy(section.Name, ".data", 5);
    section.Misc.VirtualSize = 0x100;
    section.VirtualAddress = 0x1000;
    section.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    unreadable.put(section_table_rva, section);
    ASSERT_TRUE(unreadable.protect_no_access(second_page_rva));
    EXPECT_FALSE(sc::image_identity(unreadable.range()).present());
}
