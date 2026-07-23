#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/scan.hpp"

#include "fixtures/scratch_page.hpp"

#include <windows.h>

namespace dmk = DetourModKit;
namespace an = DetourModKit::anchor;
namespace sc = DetourModKit::scan;

namespace
{
    // Compiles a known-good AOB literal for a candidate site; the test patterns are all valid, so .value() is safe.
    [[nodiscard]] sc::Pattern aob(std::string_view dsl)
    {
        return sc::Pattern::compile(dsl).value();
    }

    using dmk_test::ScratchPage;

    // A committed RWX page that hosts a string literal plus a RIP-relative lea that references it, so the StringXref
    // backend has a real string (phase 1) and a real reference (phase 2) inside one Region.
    class StringImage
    {
    public:
        StringImage()
        {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            m_size = si.dwPageSize;
            m_base = static_cast<std::uint8_t *>(
                VirtualAlloc(nullptr, m_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        }

        ~StringImage()
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        StringImage(const StringImage &) = delete;
        StringImage &operator=(const StringImage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        void write_string(std::size_t off, std::string_view text) noexcept
        {
            std::memcpy(m_base + off, text.data(), text.size());
            m_base[off + text.size()] = 0x00; // NUL terminator so require_terminator matches
        }

        // Plants `48 <opcode> 05 <disp32>` (a REX.W RIP-relative lea/mov, rax destination) at instr_off whose computed
        // target is target_off.
        void plant_rip_load(std::size_t instr_off, std::size_t target_off, std::uint8_t opcode) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            p[0] = 0x48; // REX.W
            p[1] = opcode;
            p[2] = 0x05; // ModRM: mod=00, reg=rax, rm=101 (RIP-relative)
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 7);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(addr(target_off)) - next);
            std::memcpy(p + 3, &disp, sizeof(disp));
        }

        [[nodiscard]] std::uintptr_t addr(std::size_t off) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + off);
        }

        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{reinterpret_cast<std::uintptr_t>(m_base)}, m_size};
        }

    private:
        std::uint8_t *m_base = nullptr;
        std::size_t m_size = 0;
    };

    // Post-resolve validator stand-ins. Each matches an::AnchorValidator exactly (a noexcept function pointer).
    bool always_reject(std::int64_t, const void *) noexcept
    {
        return false;
    }

    bool expect_value_f0(std::int64_t value, const void *) noexcept
    {
        return value == 0xF0;
    }

    const int s_validator_context_token = 0;

    bool require_context_token(std::int64_t, const void *context) noexcept
    {
        return context == &s_validator_context_token;
    }
} // anonymous namespace

// Backend dispatch: each kind maps onto its v4 backend and maps success/failure onto AnchorStatus.

TEST(AnchorTest, ManualResolvesToLiteral)
{
    an::Anchor anchor{};
    anchor.label = "manual";
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x1234;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x1234);
    EXPECT_EQ(result.kind, an::AnchorKind::Manual);
    EXPECT_EQ(result.label, "manual");
}

TEST(AnchorTest, CallArgHomeIsUnsupported)
{
    an::Anchor anchor{};
    anchor.label = "arghome";
    anchor.kind = an::AnchorKind::CallArgHome;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Unsupported);
}

TEST(AnchorTest, CodeOperandResolvesImmediate)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    const sc::Candidate cands[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "stride";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, CodeOperandResolvesDisplacementWithByteWidth)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x8A, 0x45, 0xFF}); // mov al, byte [rbp-0x01]

    const sc::Candidate cands[] = {sc::Candidate::direct("disp8", aob("8A 45 FF"))};
    an::Anchor anchor{};
    anchor.label = "disp";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_kind = sc::OperandKind::MemoryDisplacement;
    anchor.operand_index = 1;
    anchor.byte_width = 1; // narrow to one byte; the value must stay negative

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, -1);
}

TEST(AnchorTest, RipGlobalResolvesToAddress)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});

    const sc::Candidate cands[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    an::Anchor anchor{};
    anchor.label = "global";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = cands;

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), page.addr(0x200));
}

// The RipGlobal byte ladder honors the Anchor::pages knob. A byte run planted in a readable, NON-executable data page
// resolves under the default Readable class, but is invisible once the anchor narrows to Executable -- so a caller that
// knows its RipGlobal target is reached only through in-image code can reject a coincidental data-page twin and turn a
// fail-closed ambiguity into a clean resolve. The default stays Readable, so no existing anchor changes. A dedicated
// PAGE_READWRITE region is used here because ScratchPage is now execute-readable (for the CodeOperand tests).
TEST(AnchorTest, RipGlobalPageClassKnobRejectsDataPageSite)
{
    void *data = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(data, nullptr);
    std::memset(data, 0xCC, 0x1000);
    const std::uint8_t marker[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40};
    std::memcpy(static_cast<std::uint8_t *>(data) + 0x200, marker, sizeof(marker));
    const dmk::Region scope{dmk::Address{reinterpret_cast<std::uintptr_t>(data)}, 0x1000};

    const sc::Candidate cands[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    an::Anchor anchor{};
    anchor.label = "global";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = cands;

    // The default Readable class resolves the data-page site.
    anchor.pages = sc::Pages::Readable;
    EXPECT_EQ(an::resolve(anchor, scope).status, an::AnchorStatus::Resolved);

    // Narrowing to Executable makes the same data-page site invisible, so the anchor fails closed.
    anchor.pages = sc::Pages::Executable;
    EXPECT_EQ(an::resolve(anchor, scope).status, an::AnchorStatus::Failed);

    VirtualFree(data, 0, MEM_RELEASE);
}

TEST(AnchorTest, RipGlobalAbsentSignatureFailsClosed)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());

    const sc::Candidate cands[] = {sc::Candidate::direct("absent", aob("11 22 33 44 55 66 77 88"))};
    an::Anchor anchor{};
    anchor.label = "global";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = cands;

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, StringXrefResolvesReference)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "AnchorRegistryUniqueMarkerString";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]

    an::Anchor anchor{};
    anchor.label = "message";
    anchor.kind = an::AnchorKind::StringXref;
    anchor.xref_text = literal;

    const an::ResolvedAnchor result = an::resolve(anchor, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), image.addr(0x100));
}

TEST(AnchorTest, StringXrefFailsClosedWhenAbsent)
{
    StringImage image;
    ASSERT_TRUE(image.ok());

    an::Anchor anchor{};
    anchor.label = "message";
    anchor.kind = an::AnchorKind::StringXref;
    anchor.xref_text = "ThisStringIsDefinitelyNotPresentInTheImage";

    const an::ResolvedAnchor result = an::resolve(anchor, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

// AnchorKind::ExportName: resolve a named export by walking a module's PE Export Address Table. These tests resolve
// against the hook_target_lib.dll fixture, whose extern "C" __declspec(dllexport) symbols are real, byte-stable, and
// (unlike much of kernel32, which forwards to kernelbase) never forwarders, so GetProcAddress yields an exact
// ground-truth address to compare against.
namespace
{
    // RAII loader for the export fixture DLL: LoadLibrary on construction, FreeLibrary on teardown. LoadLibraryA finds
    // it by basename because CMake copies it next to the test executable, whose directory is on the module search path.
    class ExportFixture
    {
    public:
        ExportFixture() : m_handle(LoadLibraryA(MODULE_NAME)) {}
        ExportFixture(const ExportFixture &) = delete;
        ExportFixture &operator=(const ExportFixture &) = delete;
        ~ExportFixture()
        {
            if (m_handle != nullptr)
            {
                FreeLibrary(m_handle);
            }
        }

        [[nodiscard]] bool ok() const noexcept { return m_handle != nullptr; }

        // The address the loader assigned an export, the ground truth resolve_export must reproduce.
        [[nodiscard]] std::uintptr_t proc(const char *name) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(GetProcAddress(m_handle, name));
        }

        static constexpr const char *MODULE_NAME = "hook_target_lib.dll";

    private:
        HMODULE m_handle;
    };

    // Minimal mapped PE64 image used to drive malformed-export cases that a normal loader would refuse to map. The
    // fixture writes only the headers and EAT fields resolve_export consumes; every offset is aligned and every write
    // is bounded inside one committed allocation.
    class SyntheticExportImage
    {
    public:
        static constexpr std::size_t IMAGE_BYTES = 0x2000;
        static constexpr std::uint32_t NT_RVA = 0x100;
        static constexpr std::uint32_t EXPORT_RVA = 0x300;
        static constexpr std::uint32_t EXPORT_BYTES = 0x200;
        static constexpr std::uint32_t FUNCTIONS_RVA = 0x600;
        static constexpr std::uint32_t NAMES_RVA = 0x700;
        static constexpr std::uint32_t ORDINALS_RVA = 0x800;
        static constexpr std::uint32_t NAME_RVA = 0x900;
        static constexpr std::uint32_t TARGET_RVA = 0x1000;

        SyntheticExportImage() : m_base(VirtualAlloc(nullptr, IMAGE_BYTES, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
        {
            if (m_base == nullptr)
            {
                return;
            }
            std::memset(m_base, 0, IMAGE_BYTES);

            IMAGE_DOS_HEADER dos{};
            dos.e_magic = IMAGE_DOS_SIGNATURE;
            dos.e_lfanew = static_cast<LONG>(NT_RVA);
            put(0, dos);

            IMAGE_NT_HEADERS64 nt{};
            nt.Signature = IMAGE_NT_SIGNATURE;
            nt.FileHeader.SizeOfOptionalHeader = static_cast<WORD>(sizeof(IMAGE_OPTIONAL_HEADER64));
            nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
            nt.OptionalHeader.SizeOfImage = static_cast<DWORD>(IMAGE_BYTES);
            nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {EXPORT_RVA, EXPORT_BYTES};
            put(NT_RVA, nt);

            IMAGE_EXPORT_DIRECTORY exports{};
            exports.Base = 1;
            exports.NumberOfFunctions = 1;
            exports.NumberOfNames = 1;
            exports.AddressOfFunctions = FUNCTIONS_RVA;
            exports.AddressOfNames = NAMES_RVA;
            exports.AddressOfNameOrdinals = ORDINALS_RVA;
            put(EXPORT_RVA, exports);

            put(FUNCTIONS_RVA, TARGET_RVA);
            put(NAMES_RVA, NAME_RVA);
            put(ORDINALS_RVA, std::uint16_t{0});
            put_string(NAME_RVA, "fixture_export");
        }

        ~SyntheticExportImage()
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        SyntheticExportImage(const SyntheticExportImage &) = delete;
        SyntheticExportImage &operator=(const SyntheticExportImage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        template <typename T> void put(std::size_t offset, const T &value)
        {
            ASSERT_LE(offset + sizeof(T), IMAGE_BYTES);
            std::memcpy(static_cast<std::byte *>(m_base) + offset, &value, sizeof(T));
        }

        template <typename T> [[nodiscard]] T get(std::size_t offset) const
        {
            EXPECT_LE(offset + sizeof(T), IMAGE_BYTES);
            T value{};
            std::memcpy(&value, static_cast<const std::byte *>(m_base) + offset, sizeof(T));
            return value;
        }

        void put_string(std::size_t offset, std::string_view value)
        {
            ASSERT_LE(offset + value.size() + 1, IMAGE_BYTES);
            std::memcpy(static_cast<std::byte *>(m_base) + offset, value.data(), value.size());
            static_cast<char *>(m_base)[offset + value.size()] = '\0';
        }

        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{reinterpret_cast<std::uintptr_t>(m_base)}, IMAGE_BYTES};
        }

    private:
        void *m_base;
    };
} // namespace

TEST(AnchorTest, ExportNameResolvesForeignModuleFunction)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok()) << "Failed to load " << ExportFixture::MODULE_NAME << ": " << GetLastError();
    const std::uintptr_t expected = fixture.proc("compute_damage");
    ASSERT_NE(expected, 0U);

    // export_module names a foreign module independent of the resolve scope (here the host image): a mod scanning the
    // game executable can still anchor on an export in one of its DLLs.
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

    // With export_module empty the export resolves within the passed scope, so scoping the resolve to the fixture
    // module reaches its export without naming the module on the anchor.
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

    // A data export (an exported array in .rdata) resolves the same way a function export does: its RVA points into the
    // image, outside the export directory, so it is not mistaken for a forwarder.
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

// The scan-layer backend directly, below the anchor wrapper: it reproduces the loader's address for a present export
// and fails closed with a precise ErrorCode on an absent name, an empty name, and an unloaded/invalid module.
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
        static_cast<DWORD>(sizeof(IMAGE_EXPORT_DIRECTORY) + 1)};
    image.put(SyntheticExportImage::NT_RVA, nt);

    const dmk::Result<dmk::Address> directory_result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(directory_result.has_value());
    EXPECT_EQ(directory_result.error().code, dmk::ErrorCode::ExportNotFound);

    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {SyntheticExportImage::EXPORT_RVA,
                                                                     SyntheticExportImage::EXPORT_BYTES};
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
    // e_lfanew is a signed LONG in the DOS header. A negative value is rejected before it is widened to an unsigned
    // RVA, so a corrupt offset cannot wrap below the module base and alias a high in-image address.
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
    // The directory's VirtualAddress stays in-image but its declared Size is one byte short of an
    // IMAGE_EXPORT_DIRECTORY. The explicit size floor rejects it before the struct read would trust fields past the
    // truncation, a case distinct from the out-of-image VirtualAddress the sibling test drives.
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    IMAGE_NT_HEADERS64 nt = image.get<IMAGE_NT_HEADERS64>(SyntheticExportImage::NT_RVA);
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {
        SyntheticExportImage::EXPORT_RVA, static_cast<DWORD>(sizeof(IMAGE_EXPORT_DIRECTORY) - 1)};
    image.put(SyntheticExportImage::NT_RVA, nt);

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, NameOrdinalOutOfFunctionRangeFailsClosed)
{
    // AddressOfNameOrdinals[i] is a direct index into AddressOfFunctions. A WORD >= NumberOfFunctions (here 1) would
    // index past the functions array; the bounds guard must reject it rather than read an out-of-array DWORD as a
    // function RVA.
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    image.put(SyntheticExportImage::ORDINALS_RVA, std::uint16_t{1});

    const dmk::Result<dmk::Address> result = sc::resolve_export("fixture_export", image.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, dmk::ErrorCode::ExportNotFound);
}

TEST(ScanExportTest, ZeroFunctionRvaFailsClosed)
{
    // A zero function RVA is an unused/absent slot, not a resolvable address. The guard must fail closed rather than
    // resolve span.base + 0 and hand the caller the image base (its PE header) as a bogus hook/read target.
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

TEST(AnchorTest, ExportNameCaseSensitiveMatch)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    // PE export names are case-sensitive; a wrong-case spelling must fail closed rather than resolve the real export.
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "Compute_Damage";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorFingerprintTest, ExportNameModuleAndNameAreEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::ExportName;
    a.export_module = "kernel32.dll";
    a.export_name = "Sleep";

    an::Anchor different_name = a;
    different_name.export_name = "SleepEx";
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(different_name));

    an::Anchor different_module = a;
    different_module.export_module = "ntdll.dll";
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(different_module));

    an::Anchor identical = a;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(identical));
}

// A byte pattern's bounded-jump gap structure is address-independent CONTENT the drift fingerprint must fold: two
// candidates with identical fixed bytes but different gaps are different signatures. bytes()/mask() carry only the
// fixed segments, so without folding the jump position/min/max the two would fingerprint alike and a manifest diff
// would miss a real gap edit.
TEST(AnchorFingerprintTest, PatternJumpSpanIsFoldedIntoFingerprint)
{
    const sc::Candidate narrow[] = {sc::Candidate::direct("m", aob("DE AD [2-4] BE EF 10 20 30 40 50"))};
    const sc::Candidate wide[] = {sc::Candidate::direct("m", aob("DE AD [6-10] BE EF 10 20 30 40 50"))};
    const sc::Candidate shifted[] = {sc::Candidate::direct("m", aob("DE [2-4] AD BE EF 10 20 30 40 50"))};
    const sc::Candidate adjacent[] = {sc::Candidate::direct("m", aob("DE AD BE EF 10 20 30 40 50"))};
    const sc::Candidate narrow_copy[] = {sc::Candidate::direct("m", aob("DE AD [2-4] BE EF 10 20 30 40 50"))};

    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = narrow;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = wide;
    an::Anchor c{};
    c.kind = an::AnchorKind::RipGlobal;
    c.site = adjacent;
    an::Anchor d{};
    d.kind = an::AnchorKind::RipGlobal;
    d.site = narrow_copy;
    an::Anchor e{};
    e.kind = an::AnchorKind::RipGlobal;
    e.site = shifted;

    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b)); // different gap widths
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(c)); // gapped vs adjacent
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(e)); // different gap position
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(d)); // identical structure -> identical fingerprint
}

TEST(AnchorTest, QuorumRejectsDualSameExport)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    // Two ExportName members on the same module + name resolve the identical EAT entry, even when the case-insensitive
    // Windows module basename is spelled differently. They are one signal, not independent corroboration, so the
    // export evidence atom must make the quorum fail QuorumNotIndependent.
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::ExportName;
    sub_a.export_module = ExportFixture::MODULE_NAME;
    sub_a.export_name = "compute_damage";
    an::Anchor sub_b = sub_a;
    sub_b.export_module = "HOOK_TARGET_LIB.DLL";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumAcceptsExportCorroboratedByManual)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());
    const std::uintptr_t address = fixture.proc("compute_critical");
    ASSERT_NE(address, 0U);

    // An ExportName resolves the export's address; an independent Manual pins the same address. Their evidence classes
    // differ (Export vs Manual), so the pair is independent and, agreeing on the value, corroborates the target 2-of-2.
    an::Anchor export_member{};
    export_member.kind = an::AnchorKind::ExportName;
    export_member.export_module = ExportFixture::MODULE_NAME;
    export_member.export_name = "compute_critical";
    an::Anchor manual_member{};
    manual_member.kind = an::AnchorKind::Manual;
    manual_member.manual_value = static_cast<std::int64_t>(address);

    const an::Anchor *members[] = {&export_member, &manual_member};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), address);
}

TEST(AnchorProfileTest, DenyExportNameBackendFailsClosed)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "compute_damage";

    an::ScanProfile profile{};
    profile.deny_backend[static_cast<std::size_t>(an::AnchorKind::ExportName)] = true;

    const an::ResolvedAnchor result = an::resolve_with_profile(anchor, profile, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0); // denied, never substituted with another backend's guess
}

TEST(AnchorTest, ExportNameCountsInResolvableDenominator)
{
    // A resolved ExportName is ordinary resolvable evidence: it counts toward the resolved tally and, unlike the
    // unsupported CallArgHome kind, stays in the gate's resolvable denominator.
    const an::ResolvedAnchor report[] = {
        {.label = "export", .kind = an::AnchorKind::ExportName, .status = an::AnchorStatus::Resolved, .value = 0x1000},
    };
    const an::AnchorQuality quality = an::assess_quality(report);
    EXPECT_EQ(quality.total, 1U);
    EXPECT_EQ(quality.resolved, 1U);
    EXPECT_EQ(quality.unsupported, 0U);
    EXPECT_EQ(an::evaluate_gate(quality), an::GateVerdict::Pass);
}

TEST(AnchorTest, VtableIdentityFailsClosedWhenAbsent)
{
    // The VtableIdentity SUCCESS dispatch (rtti::vtable_for_type -> commit_resolved) is not re-tested here: building a
    // resolvable target needs the ~130-line synthetic MSVC-RTTI vtable fixture from tests/test_rtti.cpp (a real
    // GCC/MSVC type would not carry the MSVC RTTI layout the walker reads on both toolchains). vtable_for_type success
    // is covered there, and the commit path is shared with the CodeOperand / RipGlobal / StringXref resolve tests
    // above; this case pins the anchor-side failure wiring (bogus name -> fail closed).
    an::Anchor anchor{};
    anchor.label = "vtable";
    anchor.kind = an::AnchorKind::VtableIdentity;
    anchor.mangled = ".?AVNoSuchTypeExistsAnywhere@dmk_test@@";

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, StatusToStringNonEmpty)
{
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::Unresolved).empty());
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::Resolved).empty());
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::Failed).empty());
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::Unsupported).empty());
    EXPECT_FALSE(an::anchor_status_to_string(an::AnchorStatus::QuorumNotIndependent).empty());
}

// Table resolution (serial, parallel, capacity).

TEST(AnchorTest, ResolveAllWritesReport)
{
    an::Anchor anchors[2]{};
    anchors[0].label = "a";
    anchors[0].kind = an::AnchorKind::Manual;
    anchors[0].manual_value = 1;
    anchors[1].label = "b";
    anchors[1].kind = an::AnchorKind::Manual;
    anchors[1].manual_value = 2;

    an::ResolvedAnchor report[2]{};
    const std::size_t written = an::resolve_all(anchors, report);
    EXPECT_EQ(written, 2u);
    EXPECT_EQ(report[0].value, 1);
    EXPECT_EQ(report[1].value, 2);
}

TEST(AnchorTest, ResolveAllParallelMatchesSerialReport)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate cands[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor anchors[3]{};
    anchors[0].label = "manual";
    anchors[0].kind = an::AnchorKind::Manual;
    anchors[0].manual_value = 0x11;
    anchors[1].label = "code";
    anchors[1].kind = an::AnchorKind::CodeOperand;
    anchors[1].site = cands;
    anchors[1].operand_index = 1;
    anchors[2].label = "arghome";
    anchors[2].kind = an::AnchorKind::CallArgHome;

    an::ResolvedAnchor serial[3]{};
    an::ResolvedAnchor parallel[3]{};
    const std::size_t serial_count = an::resolve_all(anchors, serial, page.range());
    const std::size_t parallel_count = an::resolve_all_parallel(anchors, parallel, page.range(), 4);
    ASSERT_EQ(serial_count, parallel_count);
    for (std::size_t i = 0; i < serial_count; ++i)
    {
        EXPECT_EQ(parallel[i].status, serial[i].status);
        EXPECT_EQ(parallel[i].value, serial[i].value);
        EXPECT_EQ(parallel[i].label, serial[i].label);
        EXPECT_EQ(parallel[i].kind, serial[i].kind);
    }
}

TEST(AnchorTest, ResolveAllRespectsCapacity)
{
    an::Anchor anchors[3]{};
    for (an::Anchor &a : anchors)
    {
        a.kind = an::AnchorKind::Manual;
        a.manual_value = 7;
    }

    an::ResolvedAnchor report[2]{}; // smaller than the table
    const std::size_t written = an::resolve_all(anchors, report);
    EXPECT_EQ(written, 2u); // min(anchors, out)
}

// Post-resolve validators.

TEST(AnchorTest, ValidatorRejectionFailsClosed)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0xF0;
    anchor.validate_manual = true; // route the Manual through the validator path
    anchor.validator = &always_reject;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, ValidatorAcceptSeesResolvedValue)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0xF0;
    anchor.validate_manual = true;
    anchor.validator = &expect_value_f0;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, ValidatorContextPassesThrough)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0xF0;
    anchor.validate_manual = true;
    anchor.validator = &require_context_token;
    anchor.validator_context = &s_validator_context_token;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
}

TEST(AnchorTest, ValidatorNotAppliedToManualByDefault)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x99;
    anchor.validator = &always_reject; // present but validate_manual is false

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved); // pinned literal exemption
    EXPECT_EQ(result.value, 0x99);
}

TEST(AnchorTest, ValidatorNotAppliedToCallArgHome)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::CallArgHome;
    anchor.validator = &always_reject;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Unsupported); // no resolver runs, so the validator never fires
}

TEST(AnchorTest, ManualValidatorRunsWhenOptedIn)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x01; // not 0xF0
    anchor.validate_manual = true;
    anchor.validator = &expect_value_f0;

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed); // validator opted-in and rejects
}

TEST(AnchorTest, ManualValidatorSkippedByDefault)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x01;
    anchor.validator = &expect_value_f0; // would reject, but validate_manual is false

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x01);
}

TEST(AnchorTest, RequireValidatorRejectsUnverifiedBackend)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate cands[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_index = 1;
    anchor.require_validator = true; // but no validator attached

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed); // treated as unverified
}

TEST(AnchorTest, RequireValidatorIgnoredForManualByDefault)
{
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x22;
    anchor.require_validator = true; // ignored: the default Manual path never runs commit_resolved

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x22);
}

TEST(AnchorTest, RequireValidatorExemptsManualWhenValidated)
{
    // require_validator is a backend-target policy, so it never rejects a pinned Manual literal for lacking a validator
    // -- even when validate_manual routes the Manual through the validator path with no validator attached. This
    // contradictory-but-benign config resolves rather than fails, matching the anchor.hpp contract (Manual is not a
    // resolved target). With a validator missing there is simply nothing to run.
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x44;
    anchor.validate_manual = true;   // route through the commit_resolved validator path
    anchor.require_validator = true; // but Manual is exempt from the no-validator rejection (only backends are subject)

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0x44);
}

// Quorum corroboration.

TEST(AnchorTest, QuorumAcceptsWhenSignalsAgree)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.label = "corroborated";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members; // default threshold 0 == unanimous == the strict 2-of-2

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumAcceptsAcrossBackends)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site_code[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor sub_manual{};
    sub_manual.kind = an::AnchorKind::Manual;
    sub_manual.manual_value = 0xF0;
    an::Anchor sub_code{};
    sub_code.kind = an::AnchorKind::CodeOperand;
    sub_code.site = site_code;
    sub_code.operand_index = 1;

    const an::Anchor *members[] = {&sub_manual, &sub_code};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumFailsWhenSignalsDisagree)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xE0, 0x00, 0x00, 0x00}); // add rcx, 0xE0
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 E0 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumFailsWhenOneSignalFails)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site_ok[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_absent[] = {sc::Candidate::direct("absent", aob("11 22 33 44 55 66 77 88"))};

    an::Anchor sub_ok{};
    sub_ok.kind = an::AnchorKind::CodeOperand;
    sub_ok.site = site_ok;
    sub_ok.operand_index = 1;
    an::Anchor sub_bad{};
    sub_bad.kind = an::AnchorKind::RipGlobal;
    sub_bad.site = site_absent;

    const an::Anchor *members[] = {&sub_ok, &sub_bad};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumNullSubAnchorFailsClosed)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::Manual;
    sub.manual_value = 1;

    const an::Anchor *members[] = {&sub, nullptr}; // a null member fails the quorum closed
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumRejectsNestedQuorum)
{
    an::Anchor leaf{};
    leaf.kind = an::AnchorKind::Manual;
    leaf.manual_value = 1;
    an::Anchor nested{};
    nested.kind = an::AnchorKind::Quorum; // a Quorum as a sub-anchor is rejected (nesting bounded to one level)
    const an::Anchor *members[] = {&leaf, &nested};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumWithinToleranceAcceptsCloseValues)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF2, 0x00, 0x00, 0x00}); // add rcx, 0xF2
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F2 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 4; // gap is 2

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0); // the cluster center (first member's value)
}

TEST(AnchorTest, QuorumWithinToleranceRejectsDistantValues)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xFF, 0x00, 0x00, 0x00}); // add rcx, 0xFF
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 FF 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 2; // gap is 0xF (15)

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumRejectsNegativeTolerance)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0x10;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand; // distinct kind, so the pair is independent

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x10, 0x00, 0x00, 0x00}); // add rax, 0x10 (equals sub_a's value)
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 10 00 00 00"))};
    sub_b.site = site;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = -1; // a negative tolerance never accepts, even for equal values

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumHonoursOwnValidator)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0xF0;

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.validator = &always_reject; // runs once on the corroborated value

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumRejectsPointerEqualSubAnchors)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::Manual;
    sub.manual_value = 1;

    const an::Anchor *members[] = {&sub, &sub}; // the same object twice is not independent evidence
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumRejectsDualManual)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 5;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::Manual;
    sub_b.manual_value = 5;

    const an::Anchor *members[] = {&sub_a, &sub_b}; // two hand-pinned literals are not live corroboration
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumRejectsSameBackendConfig)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site; // SAME storage
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site; // SAME storage -> same backend config
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumRejectsContentEqualCandidateArrays)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0 -- a single unique site
    // Two SEPARATELY-authored candidate arrays encoding the SAME pattern with the SAME decode params. They compile to
    // byte-identical patterns and therefore decode one identical site, so they are the same evidence and cannot
    // corroborate each other. Independence is over the pattern CONTENT, not the storage: distinct arrays that express
    // the same signature must NOT vote twice.
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    ASSERT_NE(static_cast<const void *>(site_a), static_cast<const void *>(site_b))
        << "the two ladders must live in distinct storage for this test to have teeth";

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumDistinguishesPatternJumpDescriptors)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xAD, 0xBE});

    // All three patterns resolve the same site and have identical concatenated fixed bytes. Their gap position or
    // bounds are the only independent-evidence difference.
    const sc::Candidate after_first[] = {sc::Candidate::direct("a", aob("DE [1] AD BE"))};
    const sc::Candidate after_second[] = {sc::Candidate::direct("b", aob("DE AD [1] BE"))};
    const sc::Candidate wider[] = {sc::Candidate::direct("c", aob("DE [1-2] AD BE"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = after_first;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = after_second;
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::RipGlobal;
    sub_c.site = wider;

    const an::Anchor *members[] = {&sub_a, &sub_b, &sub_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, static_cast<std::int64_t>(page.addr(0x200)));
}

// The Anchor::pages knob is scan POLICY, not resolution evidence: it changes which pages are swept, never the target
// identity. So two RipGlobal members over the same site content that differ ONLY in pages are the same evidence and
// must not corroborate each other. The independence gate (collect_independence_atoms) must ignore pages even though
// the drift fingerprint (anchor_fingerprint) folds it -- this locks that drift-vs-independence split for the pages
// flag. Distinct storage gives the test teeth: it can only pass because the CONTENT atoms match with pages dropped;
// folding pages into the independence evidence would make the pair look independent and fail this.
TEST(AnchorTest, QuorumRejectsMembersDifferingOnlyInPageClass)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});
    const sc::Candidate site_a[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    ASSERT_NE(static_cast<const void *>(site_a), static_cast<const void *>(site_b))
        << "the two ladders must live in distinct storage for this test to have teeth";

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = site_a;
    sub_a.pages = sc::Pages::Readable;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable; // differs ONLY in page policy, which is not independent evidence

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, QuorumRejectsReorderedIdenticalLadders)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    // Two ladders listing the SAME two rungs in DIFFERENT order. A fallback ladder's rungs all aim at one target, so a
    // reordered copy decodes the same site and is dependent evidence, not corroboration -- the independence gate must
    // be order-INDEPENDENT. (Here both rungs resolve to 0xF0, so a storage/order-sensitive gate would have let this
    // pair falsely corroborate; the fix reports QuorumNotIndependent before any resolve.)
    const sc::Candidate ladder_ab[] = {sc::Candidate::direct("a", aob("48 05 F0 00 00 00")),
                                       sc::Candidate::direct("b", aob("48 81 C1 F0 00 00 00"))};
    const sc::Candidate ladder_ba[] = {sc::Candidate::direct("b", aob("48 81 C1 F0 00 00 00")),
                                       sc::Candidate::direct("a", aob("48 05 F0 00 00 00"))};

    an::Anchor sub_ab{};
    sub_ab.kind = an::AnchorKind::CodeOperand;
    sub_ab.site = ladder_ab;
    sub_ab.operand_index = 1;
    an::Anchor sub_ba{};
    sub_ba.kind = an::AnchorKind::CodeOperand;
    sub_ba.site = ladder_ba;
    sub_ba.operand_index = 1;

    const an::Anchor *members[] = {&sub_ab, &sub_ba};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// The quorum independence gate must hash a StringXref by its LOCATED-LITERAL identity (text + encoding) only, never
// by scan POLICY. broad_match / require_terminator / return_mode change how the sweep runs, not WHICH literal it
// finds, so two members on one literal that differ only in a facet resolve the same reference and are a single
// signal. Folding a facet into the independence evidence would let them pass the gate and double-vote (and under a
// WithinTolerance quorum two facet-variant views of one site could even self-corroborate).
TEST(AnchorTest, QuorumRejectsStringXrefDifferingOnlyInScanPolicy)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = "CombatSystem::ApplyDamage";
    sub_a.xref_broad_match = false;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::StringXref;
    sub_b.xref_text = "CombatSystem::ApplyDamage";
    sub_b.xref_broad_match = true; // differs ONLY in scan policy, which is not independent evidence

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// A flat StringXref and a one-rung RipGlobal whose sole rung is a StringXref candidate on the SAME literal both
// resolve through find_string_xref to the identical site, so the independence gate must treat them as one signal
// despite the different AnchorKind wrapper. The gate reduces each anchor to kind-neutral evidence atoms, so the two
// spellings collide; a kind-sensitive gate would have let this cross-kind pair falsely corroborate.
TEST(AnchorTest, QuorumRejectsCrossKindStringEvidence)
{
    const sc::Candidate rip_site[] = {sc::Candidate::string_xref("wrapped", "CameraFovLiteral")};

    an::Anchor flat{};
    flat.kind = an::AnchorKind::StringXref;
    flat.xref_text = "CameraFovLiteral";
    an::Anchor wrapped{};
    wrapped.kind = an::AnchorKind::RipGlobal;
    wrapped.site = rip_site; // a RipGlobal ladder whose one rung is the same string literal

    const an::Anchor *members[] = {&flat, &wrapped};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// Regression guard for the canonicalization: two StringXref members on DIFFERENT literals are genuinely independent
// evidence and MUST pass the gate. With no matching reference to corroborate, the quorum then fails to reach its
// threshold (Failed), but it must never be rejected as QuorumNotIndependent -- that would prove the gate
// over-collapses distinct literals into one signal and would kill legitimate cross-string corroboration.
TEST(AnchorTest, QuorumAcceptsDifferentLiteralsAsIndependent)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = "FirstDistinctQuorumLiteral";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::StringXref;
    sub_b.xref_text = "SecondDistinctQuorumLiteral";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_NE(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// Two quorum members whose ladders SHARE one rung but differ in the other are dependent evidence, even though neither
// ladder equals the other. A ladder resolves to its FIRST matching rung, so the shared rung could win for both (one
// member's unique primary present and the other's absent, or both primaries patched away onto the shared fallback),
// landing both on one site to double-vote. The gate compares atom SETS, so a shared rung is caught as a partial
// overlap; a whole-anchor hash of each ladder would differ and let this pair falsely corroborate.
TEST(AnchorTest, QuorumRejectsPartialLadderOverlap)
{
    // Both ladders carry the SAME second rung ("48 05 F0 00 00 00") and a DIFFERENT first rung. Same operand selector,
    // so the shared rung yields the same evidence atom in both members.
    const sc::Candidate ladder_a[] = {sc::Candidate::direct("a-primary", aob("48 81 C1 F0 00 00 00")),
                                      sc::Candidate::direct("shared", aob("48 05 F0 00 00 00"))};
    const sc::Candidate ladder_b[] = {sc::Candidate::direct("b-primary", aob("48 81 C2 F0 00 00 00")),
                                      sc::Candidate::direct("shared", aob("48 05 F0 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = ladder_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = ladder_b;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorTest, UnsetKindFailsClosed)
{
    // A default-constructed Anchor whose kind was never set (e.g. a designated-initializer table entry that omits
    // `kind`) must fail closed, not resolve as a trusted address 0. Unset is the fail-safe default.
    an::Anchor anchor{};
    EXPECT_EQ(anchor.kind, an::AnchorKind::Unset) << "a default-constructed Anchor must default to Unset";
    anchor.label = "forgot-the-kind";
    anchor.manual_value = 0; // a populated-but-ignored field, as a real misdeclaration would carry

    const an::ResolvedAnchor result = an::resolve(anchor);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, QuorumExemptFromRequireValidator)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0xF0;

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.require_validator = true; // exempt: N-of-M corroboration is the verification, no validator needed

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, ResolveAllCarriesQuorum)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0x30;

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x30, 0x00, 0x00, 0x00}); // add rax, 0x30
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 30 00 00 00"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor table[1]{};
    table[0].label = "q";
    table[0].kind = an::AnchorKind::Quorum;
    table[0].quorum_members = members;

    an::ResolvedAnchor report[1]{};
    const std::size_t written = an::resolve_all(table, report, page.range());
    ASSERT_EQ(written, 1u);
    EXPECT_EQ(report[0].status, an::AnchorStatus::Resolved);
    EXPECT_EQ(report[0].value, 0x30);
    EXPECT_EQ(report[0].kind, an::AnchorKind::Quorum);
}

// N-of-M voting: at least N of M independent members must resolve and agree.

TEST(AnchorTest, QuorumNofMResolvesWhenThresholdMetDespiteFailure)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site_code[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_absent[] = {sc::Candidate::direct("absent", aob("11 22 33 44 55 66 77 88"))};

    an::Anchor by_hand{};
    by_hand.kind = an::AnchorKind::Manual;
    by_hand.manual_value = 0xF0;
    an::Anchor by_code{};
    by_code.kind = an::AnchorKind::CodeOperand;
    by_code.site = site_code;
    by_code.operand_index = 1;
    an::Anchor by_scan{}; // this signal is broken on the "patch": its pattern is not present
    by_scan.kind = an::AnchorKind::RipGlobal;
    by_scan.site = site_absent;

    // 2-of-3: the third member fails to resolve, but the other two independent signals agree, so the target still
    // corroborates. A strict 2-of-2 or 3-of-3 quorum would have failed here.
    const an::Anchor *members[] = {&by_hand, &by_code, &by_scan};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumNofMFailsBelowThreshold)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    // Distinct absent patterns: a CodeOperand and a flat kind over ONE site are the same failure domain, so the two
    // failing members must sit on different sites to stay independent and exercise the below-threshold path (rather
    // than tripping the independence gate first).
    const sc::Candidate site_absent_a[] = {sc::Candidate::direct("absent-a", aob("11 22 33 44 55 66 77 88"))};
    const sc::Candidate site_absent_b[] = {sc::Candidate::direct("absent-b", aob("99 AA BB CC DD EE FF 00"))};

    an::Anchor by_hand{};
    by_hand.kind = an::AnchorKind::Manual;
    by_hand.manual_value = 0xF0;
    an::Anchor by_code{}; // fails: pattern not on the page
    by_code.kind = an::AnchorKind::CodeOperand;
    by_code.site = site_absent_a;
    by_code.operand_index = 1;
    an::Anchor by_scan{}; // fails: pattern not on the page
    by_scan.kind = an::AnchorKind::RipGlobal;
    by_scan.site = site_absent_b;

    // Only one of three members resolves, below the 2-of-3 threshold, so a lone signal cannot masquerade as
    // corroborated.
    const an::Anchor *members[] = {&by_hand, &by_code, &by_scan};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumNofMOutvotesDisagreeingMember)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    page.put(0x180, {0x48, 0x81, 0xC2, 0xE0, 0x00, 0x00, 0x00}); // add rdx, 0xE0 (the odd one out)
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("add-rdx", aob("48 81 C2 E0 00 00 00"))};

    an::Anchor agree_a{};
    agree_a.kind = an::AnchorKind::CodeOperand;
    agree_a.site = site_a;
    agree_a.operand_index = 1;
    an::Anchor agree_b{};
    agree_b.kind = an::AnchorKind::CodeOperand;
    agree_b.site = site_b;
    agree_b.operand_index = 1;
    an::Anchor dissent{};
    dissent.kind = an::AnchorKind::CodeOperand;
    dissent.site = site_c;
    dissent.operand_index = 1;

    // Two of three independent members agree on 0xF0; the third resolves to a different value and is outvoted.
    const an::Anchor *members[] = {&agree_a, &agree_b, &dissent};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumDefaultThresholdResolvesWhenUnanimous)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    page.put(0x180, {0x48, 0x81, 0xC2, 0xF0, 0x00, 0x00, 0x00}); // add rdx, 0xF0
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("add-rdx", aob("48 81 C2 F0 00 00 00"))};

    an::Anchor m_a{};
    m_a.kind = an::AnchorKind::CodeOperand;
    m_a.site = site_a;
    m_a.operand_index = 1;
    an::Anchor m_b{};
    m_b.kind = an::AnchorKind::CodeOperand;
    m_b.site = site_b;
    m_b.operand_index = 1;
    an::Anchor m_c{};
    m_c.kind = an::AnchorKind::CodeOperand;
    m_c.site = site_c;
    m_c.operand_index = 1;

    // Default threshold 0 means unanimous: all three members must agree.
    const an::Anchor *members[] = {&m_a, &m_b, &m_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
}

TEST(AnchorTest, QuorumDefaultThresholdFailsWithoutUnanimity)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    page.put(0x180, {0x48, 0x81, 0xC2, 0xE0, 0x00, 0x00, 0x00}); // add rdx, 0xE0 (breaks unanimity)
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("add-rdx", aob("48 81 C2 E0 00 00 00"))};

    an::Anchor m_a{};
    m_a.kind = an::AnchorKind::CodeOperand;
    m_a.site = site_a;
    m_a.operand_index = 1;
    an::Anchor m_b{};
    m_b.kind = an::AnchorKind::CodeOperand;
    m_b.site = site_b;
    m_b.operand_index = 1;
    an::Anchor m_c{};
    m_c.kind = an::AnchorKind::CodeOperand;
    m_c.site = site_c;
    m_c.operand_index = 1;

    // Two members agree but the default threshold demands unanimity, so a 2-of-3 majority is not enough.
    const an::Anchor *members[] = {&m_a, &m_b, &m_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumWithinToleranceNofMFormsCluster)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF2, 0x00, 0x00, 0x00}); // add rcx, 0xF2 (gap 2 from 0xF0)
    page.put(0x180, {0x48, 0x81, 0xC2, 0xFF, 0x00, 0x00, 0x00}); // add rdx, 0xFF (gap 15, outside tolerance)
    const sc::Candidate site_a[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F2 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("add-rdx", aob("48 81 C2 FF 00 00 00"))};

    an::Anchor near_a{};
    near_a.kind = an::AnchorKind::CodeOperand;
    near_a.site = site_a;
    near_a.operand_index = 1;
    an::Anchor near_b{};
    near_b.kind = an::AnchorKind::CodeOperand;
    near_b.site = site_b;
    near_b.operand_index = 1;
    an::Anchor far_c{};
    far_c.kind = an::AnchorKind::CodeOperand;
    far_c.site = site_c;
    far_c.operand_index = 1;

    // Two of three members are within tolerance of 0xF0 and form the accepting cluster; the far member is excluded.
    const an::Anchor *members[] = {&near_a, &near_b, &far_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 4;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0); // the cluster center
}

TEST(AnchorTest, QuorumThresholdBelowTwoFailsClosed)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0xF0;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVAbsent@@";

    // A quorum is corroboration, so a threshold of 1 (accept any lone signal) is a malformed vote and fails closed.
    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 1;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumThresholdAboveMemberCountFailsClosed)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0xF0;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVAbsent@@";

    // Demanding more agreeing votes than there are members can never be satisfied, so it is malformed and fails closed.
    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 3;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumEmptyMembersFailsClosed)
{
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum; // quorum_members left empty

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumSingleMemberFailsClosed)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::Manual;
    sub.manual_value = 1;

    // One member is a single signal, not corroboration; a quorum needs at least two members.
    const an::Anchor *members[] = {&sub};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorTest, QuorumRejectsDependentPairAmongIndependentMembers)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF0, 0x00, 0x00, 0x00}); // add rcx, 0xF0
    const sc::Candidate site_shared[] = {sc::Candidate::direct("add-rax", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_other[] = {sc::Candidate::direct("add-rcx", aob("48 81 C1 F0 00 00 00"))};

    an::Anchor first{};
    first.kind = an::AnchorKind::CodeOperand;
    first.site = site_shared;
    first.operand_index = 1;
    an::Anchor second{};
    second.kind = an::AnchorKind::CodeOperand;
    second.site = site_other;
    second.operand_index = 1;
    an::Anchor third{}; // SAME storage as first -> a dependent pair the all-pairs check must catch
    third.kind = an::AnchorKind::CodeOperand;
    third.site = site_shared;
    third.operand_index = 1;

    // The dependent pair is (first, third), which are not adjacent in the member list: independence is checked over
    // ALL pairs, not just neighbours, so the whole vote fails as non-independent.
    const an::Anchor *members[] = {&first, &second, &third};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// Quorum winner selection is order-independent, and a quorum that reaches its threshold for two disagreeing
// values reports QuorumAmbiguous rather than letting declaration order pick a winner. Physical-source correlation
// (two operands of one instruction, an empty vs explicit export of one EAT entry) counts as one witness.

TEST(AnchorQuorumTest, MultipleQualifyingClustersAreOrderInvariantOrAmbiguous)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x10, 0x00, 0x00, 0x00});       // add rax, 0x10
    page.put(0x140, {0x48, 0x81, 0xC1, 0x10, 0x00, 0x00, 0x00}); // add rcx, 0x10
    page.put(0x180, {0x48, 0x81, 0xC2, 0x20, 0x00, 0x00, 0x00}); // add rdx, 0x20
    page.put(0x1C0, {0x48, 0x81, 0xC3, 0x20, 0x00, 0x00, 0x00}); // add rbx, 0x20
    const sc::Candidate site_a[] = {sc::Candidate::direct("a", aob("48 05 10 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("b", aob("48 81 C1 10 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("c", aob("48 81 C2 20 00 00 00"))};
    const sc::Candidate site_d[] = {sc::Candidate::direct("d", aob("48 81 C3 20 00 00 00"))};

    // Four independent CodeOperands resolving to 0x10, 0x10, 0x20, 0x20: two exact clusters of two, N = 2. Both clear
    // the threshold and disagree, so declaration order must not pick one -- the vote is ambiguous, in ANY order.
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::CodeOperand;
    sub_c.site = site_c;
    sub_c.operand_index = 1;
    an::Anchor sub_d{};
    sub_d.kind = an::AnchorKind::CodeOperand;
    sub_d.site = site_d;
    sub_d.operand_index = 1;

    const an::Anchor *forward[] = {&sub_a, &sub_b, &sub_c, &sub_d};
    const an::Anchor *reversed[] = {&sub_d, &sub_c, &sub_b, &sub_a};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_threshold = 2;

    quorum.quorum_members = forward;
    const an::ResolvedAnchor forward_result = an::resolve(quorum, page.range());
    quorum.quorum_members = reversed;
    const an::ResolvedAnchor reversed_result = an::resolve(quorum, page.range());

    EXPECT_EQ(forward_result.status, an::AnchorStatus::QuorumAmbiguous);
    EXPECT_EQ(reversed_result.status, an::AnchorStatus::QuorumAmbiguous);
}

TEST(AnchorQuorumTest, OverlappingToleranceCentersAreAmbiguous)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x10, 0x00, 0x00, 0x00});       // add rax, 0x10
    page.put(0x140, {0x48, 0x81, 0xC1, 0x14, 0x00, 0x00, 0x00}); // add rcx, 0x14
    page.put(0x180, {0x48, 0x81, 0xC2, 0x18, 0x00, 0x00, 0x00}); // add rdx, 0x18
    const sc::Candidate site_a[] = {sc::Candidate::direct("a", aob("48 05 10 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("b", aob("48 81 C1 14 00 00 00"))};
    const sc::Candidate site_c[] = {sc::Candidate::direct("c", aob("48 81 C2 18 00 00 00"))};

    // Values 0x10 / 0x14 / 0x18 at tolerance 4, N = 2. Agreement is non-transitive: 0x10 and 0x18 each anchor a cluster
    // of two but disagree with each other (gap 8), so the overlapping centers are ambiguous, not a single winner.
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::CodeOperand;
    sub_c.site = site_c;
    sub_c.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b, &sub_c};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 4;
    quorum.quorum_threshold = 2;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumAmbiguous);
}

TEST(AnchorQuorumTest, SingleClusterWinnerIsOrderInvariant)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});       // add rax, 0xF0
    page.put(0x140, {0x48, 0x81, 0xC1, 0xF2, 0x00, 0x00, 0x00}); // add rcx, 0xF2
    const sc::Candidate site_a[] = {sc::Candidate::direct("a", aob("48 05 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("b", aob("48 81 C1 F2 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    // One agreement cluster (gap 2 <= tolerance 4). The committed value is the canonical (smallest) member value,
    // 0xF0, regardless of which member is declared first.
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 4;

    const an::Anchor *forward[] = {&sub_a, &sub_b};
    const an::Anchor *reversed[] = {&sub_b, &sub_a};
    quorum.quorum_members = forward;
    const an::ResolvedAnchor forward_result = an::resolve(quorum, page.range());
    quorum.quorum_members = reversed;
    const an::ResolvedAnchor reversed_result = an::resolve(quorum, page.range());

    EXPECT_EQ(forward_result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(forward_result.value, 0xF0);
    EXPECT_EQ(reversed_result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(reversed_result.value, 0xF0);
}

TEST(AnchorQuorumTest, CorrelatedPhysicalSourceCannotDoubleVote)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    // imul rax, qword ptr [rbp+0xF0], 0xF0 -- two resolvable constants in one instruction/failure domain.
    page.put(0x100, {0x48, 0x69, 0x85, 0xF0, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00});
    const sc::Candidate site_a[] = {sc::Candidate::direct("op-a", aob("48 69 85 F0 00 00 00 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("op-b", aob("48 69 85 F0 00 00 00 F0 00 00 00"))};

    // Two CodeOperands over the SAME instruction site that merely select a different operand. One patch to that
    // instruction breaks both, so they are one witness, not two -- the site alone keys the failure domain.
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    sub_a.operand_kind = sc::OperandKind::MemoryDisplacement;
    sub_a.byte_width = 4;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 2;
    sub_b.operand_kind = sc::OperandKind::Immediate;
    sub_b.byte_width = 4;

    ASSERT_EQ(an::resolve(sub_a, page.range()).value, 0xF0);
    ASSERT_EQ(an::resolve(sub_b, page.range()).value, 0xF0);

    const an::Anchor *operand_members[] = {&sub_a, &sub_b};
    an::Anchor operand_quorum{};
    operand_quorum.kind = an::AnchorKind::Quorum;
    operand_quorum.quorum_members = operand_members;
    EXPECT_EQ(an::resolve(operand_quorum, page.range()).status, an::AnchorStatus::QuorumNotIndependent);

    // An empty export module resolves in the quorum scope, which here IS the named module, so an empty-module and an
    // explicit-module member name one EAT entry and cannot double-vote.
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());
    an::Anchor export_scoped{};
    export_scoped.kind = an::AnchorKind::ExportName;
    export_scoped.export_name = "compute_damage"; // module empty -> resolves within the scope
    an::Anchor export_named{};
    export_named.kind = an::AnchorKind::ExportName;
    export_named.export_module = ExportFixture::MODULE_NAME;
    export_named.export_name = "compute_damage";

    const an::Anchor *export_members[] = {&export_scoped, &export_named};
    an::Anchor export_quorum{};
    export_quorum.kind = an::AnchorKind::Quorum;
    export_quorum.quorum_members = export_members;
    EXPECT_EQ(an::resolve(export_quorum, dmk::Region::module_named(ExportFixture::MODULE_NAME)).status,
              an::AnchorStatus::QuorumNotIndependent);
}

TEST(AnchorQuorumTest, OrderAndPhysicalIndependenceAgree)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0x42, 0x00, 0x00, 0x00});       // add rax, 0x42
    page.put(0x140, {0x48, 0x81, 0xC1, 0x44, 0x00, 0x00, 0x00}); // add rcx, 0x44
    const sc::Candidate site_a[] = {sc::Candidate::direct("a", aob("48 05 42 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("b", aob("48 81 C1 44 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = site_a;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site_b;
    sub_b.operand_index = 1;

    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_match = an::QuorumMatch::WithinTolerance;
    quorum.quorum_tolerance = 2;

    // Physically independent members whose values (0x42, 0x44) agree within tolerance corroborate the target, and the
    // committed value is the canonical minimum (0x42) whichever member is listed first. The distinct values are what
    // give the test teeth: a first-past-the-post winner would commit 0x44 in the reversed order.
    const an::Anchor *forward[] = {&sub_a, &sub_b};
    const an::Anchor *reversed[] = {&sub_b, &sub_a};
    quorum.quorum_members = forward;
    const an::ResolvedAnchor forward_result = an::resolve(quorum, page.range());
    quorum.quorum_members = reversed;
    const an::ResolvedAnchor reversed_result = an::resolve(quorum, page.range());
    EXPECT_EQ(forward_result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(forward_result.value, 0x42);
    EXPECT_EQ(reversed_result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(reversed_result.value, 0x42);

    // Physical independence is a precondition, not just an ordering nicety: pointing both members at ONE site makes the
    // pair a single failure domain, and the quorum reports QuorumNotIndependent regardless of member order.
    an::Anchor dep_a = sub_a;
    an::Anchor dep_b = sub_b;
    dep_b.site = site_a; // the same site as dep_a
    const an::Anchor *dep_forward[] = {&dep_a, &dep_b};
    const an::Anchor *dep_reversed[] = {&dep_b, &dep_a};
    quorum.quorum_members = dep_forward;
    EXPECT_EQ(an::resolve(quorum, page.range()).status, an::AnchorStatus::QuorumNotIndependent);
    quorum.quorum_members = dep_reversed;
    EXPECT_EQ(an::resolve(quorum, page.range()).status, an::AnchorStatus::QuorumNotIndependent);
}

// ResolvedAnchor::label is a borrowed view of Anchor::label, not an owned copy. Verify it only while the source
// is alive; the report must not be read after the source anchor's storage ends.

TEST(AnchorTest, ResolvedLabelBorrowedLifetimeIsExplicit)
{
    const std::string source_label = "fixture.borrowed_label";
    an::Anchor anchor{};
    anchor.label = source_label; // a std::string_view aliasing source_label's buffer
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x1234;

    const an::ResolvedAnchor result = an::resolve(anchor);
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.label, source_label);
    // The report label ALIASES the source buffer (borrowed), it is not a fresh copy. Both views point at the same
    // storage, which is the contract the doc comment now states.
    EXPECT_EQ(static_cast<const void *>(result.label.data()), static_cast<const void *>(source_label.data()));
}

TEST(AnchorTest, StatusToStringMapsQuorumAmbiguous)
{
    EXPECT_EQ(an::anchor_status_to_string(an::AnchorStatus::QuorumAmbiguous), "QuorumAmbiguous");
}

TEST(AnchorGateTest, QuorumAmbiguousCountsAsHardFailure)
{
    // A QuorumAmbiguous entry committed no trusted value, so it is a failure the strict default gate rejects.
    const an::ResolvedAnchor report[] = {
        {"resolved", an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved, 1},
        {"ambiguous", an::AnchorKind::Quorum, an::AnchorStatus::QuorumAmbiguous, 0},
    };
    const an::AnchorQuality quality = an::assess_quality(report);
    EXPECT_EQ(quality.failed, 1u);
    EXPECT_EQ(an::evaluate_gate(quality), an::GateVerdict::Fail);
}

// A hand-built anchor with an out-of-range safety enum fails closed instead of selecting a permissive default.

TEST(PolicyDomainTest, InvalidEnumsFailClosedEverywhere)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());

    // Dispatch kind: an out-of-range AnchorKind is past the deny-list bound and matches no resolver, so it must fail
    // closed to Failed rather than returning the initial non-terminal Unresolved.
    an::Anchor bad_kind{};
    bad_kind.kind = static_cast<an::AnchorKind>(0xFF);
    EXPECT_EQ(an::resolve(bad_kind, page.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_kind), an::ResultDomain::Unknown);

    // CodeOperand: the resolve EXPECT pins the layered fail-closed chain rather than the anchor-local validator alone.
    // With the anchor guard removed the invalid kind reaches scan::read_code_constant, whose own boundary rejection
    // maps back to the same Failed (ResolvedAnchor carries no error code), so the anchor-local validator itself is
    // discriminated by the declared_domain EXPECT, which classifies the declaration without resolving. The memory
    // operand keeps the positive control meaningful and feeds the candidate-order EXPECTs below.
    page.put(0x100, {0x8A, 0x45, 0xFF}); // mov al, byte [rbp-0x01]
    const sc::Candidate disp_site[] = {sc::Candidate::direct("disp8", aob("8A 45 FF"))};
    an::Anchor code_control{};
    code_control.kind = an::AnchorKind::CodeOperand;
    code_control.site = disp_site;
    code_control.operand_index = 1;
    code_control.operand_kind = sc::OperandKind::MemoryDisplacement;
    code_control.byte_width = 1;
    ASSERT_EQ(an::resolve(code_control, page.range()).status, an::AnchorStatus::Resolved);
    an::Anchor bad_operand_kind = code_control;
    bad_operand_kind.operand_kind = static_cast<sc::OperandKind>(0xFF);
    EXPECT_EQ(an::resolve(bad_operand_kind, page.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_operand_kind), an::ResultDomain::Unknown);

    // StringXref: a resolvable reference is failed closed by an invalid encoding or an invalid return mode.
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "PolicyDomainUniqueMarkerString";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]
    an::Anchor string_control{};
    string_control.kind = an::AnchorKind::StringXref;
    string_control.xref_text = literal;
    ASSERT_EQ(an::resolve(string_control, image.range()).status, an::AnchorStatus::Resolved);
    an::Anchor bad_encoding = string_control;
    bad_encoding.xref_encoding = static_cast<sc::StringEncoding>(0xFF);
    EXPECT_EQ(an::resolve(bad_encoding, image.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_encoding), an::ResultDomain::Unknown);
    an::Anchor bad_return = string_control;
    bad_return.xref_return = static_cast<sc::XrefReturn>(0xFF);
    EXPECT_EQ(an::resolve(bad_return, image.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_return), an::ResultDomain::Unknown);

    // Quorum: two independent members agreeing on 0xF0 corroborate 2-of-2 with a valid match, but an invalid match
    // policy fails closed instead of falling through to the tolerance vote (tolerance 0 would accept the pair).
    ScratchPage imm_page;
    ASSERT_TRUE(imm_page.ok());
    imm_page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate imm_site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor manual_member{};
    manual_member.kind = an::AnchorKind::Manual;
    manual_member.manual_value = 0xF0;
    an::Anchor operand_member{};
    operand_member.kind = an::AnchorKind::CodeOperand;
    operand_member.site = imm_site;
    operand_member.operand_index = 1;
    const an::Anchor *members[] = {&manual_member, &operand_member};
    an::Anchor quorum_control{};
    quorum_control.kind = an::AnchorKind::Quorum;
    quorum_control.quorum_members = members;
    ASSERT_EQ(an::resolve(quorum_control, imm_page.range()).status, an::AnchorStatus::Resolved);
    an::Anchor bad_match = quorum_control;
    bad_match.quorum_match = static_cast<an::QuorumMatch>(0xFF);
    EXPECT_EQ(an::resolve(bad_match, imm_page.range()).status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::declared_domain(bad_match), an::ResultDomain::Unknown);

    // Candidate order: two distinct guards. RipGlobal forwards the profile order into ScanRequest::order, so its
    // EXPECT pins scan::resolve's boundary check; CodeOperand orders its ladder locally before read_code_constant
    // (which has no order parameter), so its EXPECT pins the anchor-local check.
    const sc::Candidate rip_site[] = {sc::Candidate::direct("byte", aob("8A 45 FF"))};
    an::Anchor rip_control{};
    rip_control.kind = an::AnchorKind::RipGlobal;
    rip_control.site = rip_site;
    an::ScanProfile bad_order_profile{};
    bad_order_profile.candidate_order = static_cast<sc::CandidateOrder>(0xFF);
    ASSERT_EQ(an::resolve_with_profile(rip_control, an::ScanProfile{}, page.range()).status,
              an::AnchorStatus::Resolved);
    EXPECT_EQ(an::resolve_with_profile(rip_control, bad_order_profile, page.range()).status, an::AnchorStatus::Failed);
    ASSERT_EQ(an::resolve_with_profile(code_control, an::ScanProfile{}, page.range()).status,
              an::AnchorStatus::Resolved);
    EXPECT_EQ(an::resolve_with_profile(code_control, bad_order_profile, page.range()).status, an::AnchorStatus::Failed);
}

// declared_domain maps each kind to the ResultDomain a consumer binding must accept.

TEST(AnchorDomainTest, DeclaredDomainPerKind)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::VtableIdentity;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::VtableAddress);
    a.kind = an::AnchorKind::CodeOperand;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::Scalar);
    a.kind = an::AnchorKind::Manual;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::Scalar);
    a.kind = an::AnchorKind::ExportName;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::CodeSite);
    a.kind = an::AnchorKind::CallArgHome;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::Unknown);
    a.kind = an::AnchorKind::Unset;
    EXPECT_EQ(an::declared_domain(a), an::ResultDomain::Unknown);

    an::Anchor xref{};
    xref.kind = an::AnchorKind::StringXref;
    xref.xref_return = sc::XrefReturn::ReferencingInstruction;
    EXPECT_EQ(an::declared_domain(xref), an::ResultDomain::CodeSite);
    xref.xref_return = sc::XrefReturn::EnclosingFunction;
    EXPECT_EQ(an::declared_domain(xref), an::ResultDomain::CodeSite);
    xref.xref_return = sc::XrefReturn::StringPointerSlot;
    EXPECT_EQ(an::declared_domain(xref), an::ResultDomain::DataAddress);

    an::Anchor rip{};
    rip.kind = an::AnchorKind::RipGlobal;
    rip.pages = sc::Pages::Readable;
    EXPECT_EQ(an::declared_domain(rip), an::ResultDomain::DataAddress);
    rip.pages = sc::Pages::Executable;
    EXPECT_EQ(an::declared_domain(rip), an::ResultDomain::CodeSite);
    rip.pages = static_cast<sc::Pages>(0xFF); // an out-of-range pages knob yields no trustworthy domain
    EXPECT_EQ(an::declared_domain(rip), an::ResultDomain::Unknown);
}

TEST(AnchorDomainTest, QuorumDomainAgreesOrIsUnknown)
{
    an::Anchor code_export{};
    code_export.kind = an::AnchorKind::ExportName;
    code_export.export_name = "Foo";
    an::Anchor code_rip{};
    code_rip.kind = an::AnchorKind::RipGlobal;
    code_rip.pages = sc::Pages::Executable;
    // Two code-site members agree -> CodeSite.
    const an::Anchor *code_members[] = {&code_export, &code_rip};
    an::Anchor code_quorum{};
    code_quorum.kind = an::AnchorKind::Quorum;
    code_quorum.quorum_members = code_members;
    EXPECT_EQ(an::declared_domain(code_quorum), an::ResultDomain::CodeSite);

    // A Manual (Scalar wildcard) corroborating a code site keeps the specific CodeSite domain.
    an::Anchor manual{};
    manual.kind = an::AnchorKind::Manual;
    const an::Anchor *wild_members[] = {&code_export, &manual};
    an::Anchor wild_quorum{};
    wild_quorum.kind = an::AnchorKind::Quorum;
    wild_quorum.quorum_members = wild_members;
    EXPECT_EQ(an::declared_domain(wild_quorum), an::ResultDomain::CodeSite);

    // Conflicting specific domains (a vtable and a code site) make the target ambiguous -> Unknown.
    an::Anchor vtable{};
    vtable.kind = an::AnchorKind::VtableIdentity;
    const an::Anchor *conflict_members[] = {&vtable, &code_export};
    an::Anchor conflict_quorum{};
    conflict_quorum.kind = an::AnchorKind::Quorum;
    conflict_quorum.quorum_members = conflict_members;
    EXPECT_EQ(an::declared_domain(conflict_quorum), an::ResultDomain::Unknown);
}

TEST(AnchorDomainTest, ResolvedReportStampsDomainOnlyWhenResolved)
{
    an::Anchor manual{};
    manual.kind = an::AnchorKind::Manual;
    manual.manual_value = 0x1234;
    const an::ResolvedAnchor resolved = an::resolve(manual);
    ASSERT_EQ(resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(resolved.domain, an::ResultDomain::Scalar);

    an::Anchor unset{}; // kind Unset -> fails closed, no domain
    const an::ResolvedAnchor failed = an::resolve(unset);
    ASSERT_EQ(failed.status, an::AnchorStatus::Failed);
    EXPECT_EQ(failed.domain, an::ResultDomain::Unknown);

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate cands[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor code_operand{};
    code_operand.kind = an::AnchorKind::CodeOperand;
    code_operand.site = cands;
    code_operand.operand_index = 1;
    const an::ResolvedAnchor operand_resolved = an::resolve(code_operand, page.range());
    ASSERT_EQ(operand_resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(operand_resolved.domain, an::ResultDomain::Scalar);
}

TEST(AnchorDomainTest, ResultDomainToStringMapsEveryDomain)
{
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::Unknown), "Unknown");
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::CodeSite), "CodeSite");
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::DataAddress), "DataAddress");
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::VtableAddress), "VtableAddress");
    EXPECT_EQ(an::result_domain_to_string(an::ResultDomain::Scalar), "Scalar");
}

TEST(AnchorDomainTest, ExportNameDomainFollowsResolvedPageClass)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    // A function export resolves onto executable pages -> stays CodeSite (mid-hookable).
    an::Anchor func{};
    func.kind = an::AnchorKind::ExportName;
    func.export_module = ExportFixture::MODULE_NAME;
    func.export_name = "compute_damage";
    const an::ResolvedAnchor func_resolved = an::resolve(func, dmk::Region::host());
    ASSERT_EQ(func_resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(func_resolved.domain, an::ResultDomain::CodeSite);

    // A data export resolves to a non-executable .rdata address, so the CodeSite claim is downgraded to DataAddress: a
    // mid-hook binding on a data export must not be authorized as a code site.
    an::Anchor data{};
    data.kind = an::AnchorKind::ExportName;
    data.export_module = ExportFixture::MODULE_NAME;
    data.export_name = "dmk_scan_marker";
    const an::ResolvedAnchor data_resolved = an::resolve(data, dmk::Region::host());
    ASSERT_EQ(data_resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(data_resolved.domain, an::ResultDomain::DataAddress);
}

// Quality assessment.

TEST(AnchorTest, AssessQualityTalliesReport)
{
    const an::ResolvedAnchor report[] = {
        {"a", an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved, 1},
        {"b", an::AnchorKind::CodeOperand, an::AnchorStatus::Failed, 0},
        {"c", an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported, 0},
        {"d", an::AnchorKind::Manual, an::AnchorStatus::Resolved, 2},
        {"e", an::AnchorKind::Quorum, an::AnchorStatus::Resolved, 3},
        {"f", an::AnchorKind::Quorum, an::AnchorStatus::QuorumNotIndependent, 0},
    };
    const an::AnchorQuality quality = an::assess_quality(report);
    EXPECT_EQ(quality.total, 6u);
    EXPECT_EQ(quality.resolved, 3u);
    EXPECT_EQ(quality.failed, 1u);
    EXPECT_EQ(quality.unsupported, 1u);
    EXPECT_EQ(quality.not_independent, 1u);
    EXPECT_EQ(quality.manual_at_risk, 1u);
    EXPECT_EQ(quality.corroborated, 1u); // only the RESOLVED quorum counts as corroborated
}

// Fingerprints: hash the resolution EVIDENCE, excluding the resolved address.

TEST(AnchorFingerprintTest, DeterministicForSameEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 0x1234;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(a));
}

TEST(AnchorFingerprintTest, IgnoresLabel)
{
    an::Anchor a{};
    a.label = "one";
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 7;
    an::Anchor b = a;
    b.label = "different-label"; // the label is cosmetic and excluded from the fingerprint
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, VtableMangledIsEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::VtableIdentity;
    a.mangled = ".?AVFoo@@";
    an::Anchor b = a;
    b.mangled = ".?AVBar@@";
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, KindIsEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    an::Anchor b{};
    b.kind = an::AnchorKind::CallArgHome;
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, IgnoresCandidateName)
{
    const sc::Candidate site_a[] = {sc::Candidate::direct("name-one", aob("48 8B 05 ?? ?? ?? ??"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("name-two", aob("48 8B 05 ?? ?? ?? ??"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = site_a;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = site_b;
    // The candidate's cosmetic name does not change which address resolves, so it is excluded.
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, RipGlobalNonDefaultPageClassIsEvidence)
{
    const sc::Candidate site[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
    an::Anchor readable{};
    readable.kind = an::AnchorKind::RipGlobal;
    readable.site = site;
    an::Anchor executable = readable;
    executable.pages = sc::Pages::Executable;

    // A RipGlobal folds the page class as a single trailing FNV-1a byte, and only when it is non-default. Replicate
    // that one fold step (using the FNV-1a 64 prime the fingerprint hashes with) so the check has teeth: the Executable
    // digest must equal the Readable digest with exactly the Executable byte folded on top. That equality holds ONLY if
    // the default Readable folded nothing, which is the baseline stability that keeps fingerprints captured before the
    // page class existed valid. Comparing two identical Readable anchors instead would pass unconditionally and prove
    // nothing; here a regression that started folding Readable would leave an extra byte in the Readable digest and
    // break the equality.
    constexpr std::uint64_t fnv1a_prime = 1099511628211ULL;
    const std::uint64_t readable_fp = an::anchor_fingerprint(readable);
    const std::uint64_t expected_executable_fp =
        (readable_fp ^ static_cast<std::uint8_t>(sc::Pages::Executable)) * fnv1a_prime;
    EXPECT_EQ(an::anchor_fingerprint(executable), expected_executable_fp);
    EXPECT_NE(an::anchor_fingerprint(executable), readable_fp);
}

TEST(AnchorFingerprintTest, CascadePatternContentIsEvidence)
{
    const sc::Candidate site_a[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("c", aob("48 8B 0D ?? ?? ?? ??"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = site_a;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = site_b;
    // A different compiled pattern (different literal byte) is different evidence.
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CascadeFieldBoundaryResistsByteRedistribution)
{
    // Two RipGlobal cascades of the same cardinality cover the identical "AA BB CC" stream, differing only in where
    // the boundary between patterns falls: [AA BB][CC] vs [AA][BB CC]. Each pattern's bytes/mask are length-prefixed in
    // the fingerprint, so the prefix pins each pattern's extent and moving the boundary is different evidence.
    const sc::Candidate split_left[] = {sc::Candidate::direct("c0", aob("AA BB")),
                                        sc::Candidate::direct("c1", aob("CC"))};
    const sc::Candidate split_right[] = {sc::Candidate::direct("c0", aob("AA")),
                                         sc::Candidate::direct("c1", aob("BB CC"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = split_left;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = split_right;
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CascadeCardinalityIsEvidence)
{
    // A single candidate versus the same candidate repeated: [c] vs [c, c]. Per-candidate content is byte-identical, so
    // only the cascade length differs. The cascade's leading count prefix makes cardinality evidence, so a duplicated
    // ladder row cannot alias the singleton it duplicates.
    const sc::Candidate one[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
    const sc::Candidate two[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??")),
                                 sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = one;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = two;
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CascadeWildcardMaskIsEvidence)
{
    const sc::Candidate site_a[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? 00"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::RipGlobal;
    a.site = site_a;
    an::Anchor b{};
    b.kind = an::AnchorKind::RipGlobal;
    b.site = site_b;
    // Same length, different wildcard mask (last byte literal vs wildcard) is different evidence.
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, CodeOperandDecodeParamsAreEvidence)
{
    const sc::Candidate site[] = {sc::Candidate::direct("c", aob("48 05 F0 00 00 00"))};
    an::Anchor a{};
    a.kind = an::AnchorKind::CodeOperand;
    a.site = site;
    a.operand_index = 1;
    an::Anchor b = a;
    b.operand_index = 2; // the decode parameter is evidence
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, StringXrefShapeFlagsAreEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::StringXref;
    a.xref_text = "hello";
    an::Anchor b = a;
    b.xref_broad_match = true; // a shape flag is evidence
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, ManualLiteralIsEvidence)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 1;
    an::Anchor b = a;
    b.manual_value = 2;
    EXPECT_NE(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, SameEvidenceDifferentValueMatches)
{
    // The whole point: the fingerprint hashes only the declared evidence, never the resolved value (which lives in the
    // ResolvedAnchor, not the Anchor), so two identically-declared anchors share a fingerprint even when a later diff
    // records different resolved addresses next to them.
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 0x1000;
    const an::Anchor b = a;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

TEST(AnchorFingerprintTest, QuorumIsOrderIndependent)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::VtableIdentity;
    sub_a.mangled = ".?AVA@@";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVB@@";

    const an::Anchor *members1[] = {&sub_a, &sub_b};
    const an::Anchor *members2[] = {&sub_b, &sub_a}; // swapped
    an::Anchor q1{};
    q1.kind = an::AnchorKind::Quorum;
    q1.quorum_members = members1;
    an::Anchor q2{};
    q2.kind = an::AnchorKind::Quorum;
    q2.quorum_members = members2;
    EXPECT_EQ(an::anchor_fingerprint(q1), an::anchor_fingerprint(q2));
}

TEST(AnchorFingerprintTest, QuorumMatchModeAndToleranceAreEvidence)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::VtableIdentity;
    sub_a.mangled = ".?AVA@@";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVB@@";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor base{};
    base.kind = an::AnchorKind::Quorum;
    base.quorum_members = members;

    an::Anchor mode = base;
    mode.quorum_match = an::QuorumMatch::WithinTolerance;
    EXPECT_NE(an::anchor_fingerprint(base), an::anchor_fingerprint(mode));

    an::Anchor tol = mode;
    tol.quorum_tolerance = 8;
    EXPECT_NE(an::anchor_fingerprint(mode), an::anchor_fingerprint(tol));
}

TEST(AnchorFingerprintTest, QuorumThresholdIsEvidence)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::VtableIdentity;
    sub_a.mangled = ".?AVA@@";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVB@@";
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::VtableIdentity;
    sub_c.mangled = ".?AVC@@";

    // Two quorums with the same members but a different vote threshold are a different corroboration contract, so
    // their fingerprints must differ (2-of-3 vs the unanimous default).
    const an::Anchor *members[] = {&sub_a, &sub_b, &sub_c};
    an::Anchor unanimous{};
    unanimous.kind = an::AnchorKind::Quorum;
    unanimous.quorum_members = members;
    an::Anchor two_of_three = unanimous;
    two_of_three.quorum_threshold = 2;
    EXPECT_NE(an::anchor_fingerprint(unanimous), an::anchor_fingerprint(two_of_three));
}

TEST(AnchorFingerprintTest, QuorumDefaultThresholdMatchesExplicitUnanimous)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::VtableIdentity;
    sub_a.mangled = ".?AVA@@";
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::VtableIdentity;
    sub_b.mangled = ".?AVB@@";
    an::Anchor sub_c{};
    sub_c.kind = an::AnchorKind::VtableIdentity;
    sub_c.mangled = ".?AVC@@";

    // The default threshold 0 means unanimous, so spelling a three-member quorum as 0 or 3 is the same contract.
    const an::Anchor *members[] = {&sub_a, &sub_b, &sub_c};
    an::Anchor default_unanimous{};
    default_unanimous.kind = an::AnchorKind::Quorum;
    default_unanimous.quorum_members = members;
    an::Anchor explicit_unanimous = default_unanimous;
    explicit_unanimous.quorum_threshold = 3;
    EXPECT_EQ(an::anchor_fingerprint(default_unanimous), an::anchor_fingerprint(explicit_unanimous));
}

TEST(AnchorFingerprintTest, QuorumFingerprintDistinguishesMemberMultiplicity)
{
    // Two anchors with identical evidence (same kind + inputs) hash to the same member evidence, so the quorum
    // fingerprint must fold each evidence value once PER member, not once per distinct value. Otherwise {A, A, B}
    // and {A, B, B} -- the same distinct set at different multiplicity -- would collide. This locks the
    // duplicate-counting step of the allocation-free sorted fold.
    an::Anchor a{};
    a.kind = an::AnchorKind::VtableIdentity;
    a.mangled = ".?AVA@@";
    an::Anchor a_dup{};
    a_dup.kind = an::AnchorKind::VtableIdentity;
    a_dup.mangled = ".?AVA@@"; // identical evidence to a
    an::Anchor b{};
    b.kind = an::AnchorKind::VtableIdentity;
    b.mangled = ".?AVB@@";
    an::Anchor b_dup{};
    b_dup.kind = an::AnchorKind::VtableIdentity;
    b_dup.mangled = ".?AVB@@"; // identical evidence to b

    const an::Anchor *two_a_one_b[] = {&a, &a_dup, &b};
    const an::Anchor *one_a_two_b[] = {&a, &b, &b_dup};
    an::Anchor q1{};
    q1.kind = an::AnchorKind::Quorum;
    q1.quorum_members = two_a_one_b;
    an::Anchor q2{};
    q2.kind = an::AnchorKind::Quorum;
    q2.quorum_members = one_a_two_b;
    EXPECT_NE(an::anchor_fingerprint(q1), an::anchor_fingerprint(q2));
}

TEST(AnchorFingerprintTest, QuorumFingerprintOrderIndependentWithDuplicates)
{
    // The allocation-free sorted fold must stay order-independent even when two members share evidence: {A, A, B}
    // and {A, B, A} are the same multiset and must fingerprint identically.
    an::Anchor a{};
    a.kind = an::AnchorKind::VtableIdentity;
    a.mangled = ".?AVA@@";
    an::Anchor a_dup{};
    a_dup.kind = an::AnchorKind::VtableIdentity;
    a_dup.mangled = ".?AVA@@";
    an::Anchor b{};
    b.kind = an::AnchorKind::VtableIdentity;
    b.mangled = ".?AVB@@";

    const an::Anchor *aab[] = {&a, &a_dup, &b};
    const an::Anchor *aba[] = {&a, &b, &a_dup};
    an::Anchor q1{};
    q1.kind = an::AnchorKind::Quorum;
    q1.quorum_members = aab;
    an::Anchor q2{};
    q2.kind = an::AnchorKind::Quorum;
    q2.quorum_members = aba;
    EXPECT_EQ(an::anchor_fingerprint(q1), an::anchor_fingerprint(q2));
}

TEST(AnchorFingerprintTest, QuorumNullSubAnchorIsDefined)
{
    an::Anchor sub{};
    sub.kind = an::AnchorKind::VtableIdentity;
    sub.mangled = ".?AVA@@";
    const an::Anchor *members[] = {&sub, nullptr}; // a null member contributes a fixed sentinel, never a nullptr deref
    an::Anchor q{};
    q.kind = an::AnchorKind::Quorum;
    q.quorum_members = members;
    EXPECT_EQ(an::anchor_fingerprint(q), an::anchor_fingerprint(q));
}

TEST(AnchorFingerprintTest, CallArgHomeReflectsKindOnly)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::CallArgHome;
    a.manual_value = 1; // a field another kind consumes; CallArgHome hashes only its kind
    an::Anchor b{};
    b.kind = an::AnchorKind::CallArgHome;
    b.manual_value = 2;
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(b));
}

// ScanProfile: setup-only defaults (broad-widen, deny-list, candidate order), applied without overriding explicit
// calls.

TEST(AnchorProfileTest, BroadDefaultWidensQuery)
{
    an::ScanProfile profile{};
    profile.default_broad_string_xref = true;
    sc::StringRefQuery query{};
    query.broad_match = false;
    const sc::StringRefQuery widened = an::apply_profile(profile, query);
    EXPECT_TRUE(widened.broad_match);
}

TEST(AnchorProfileTest, NeverDowngradesBroad)
{
    an::ScanProfile profile{}; // default_broad_string_xref stays false
    sc::StringRefQuery query{};
    query.broad_match = true; // an explicit broad request is never turned off by the profile
    const sc::StringRefQuery result = an::apply_profile(profile, query);
    EXPECT_TRUE(result.broad_match);
}

TEST(AnchorProfileTest, DenyBackendFailsClosed)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = site;
    anchor.operand_index = 1;

    an::ScanProfile profile{};
    profile.deny_backend[static_cast<std::size_t>(an::AnchorKind::CodeOperand)] = true;

    const an::ResolvedAnchor result = an::resolve_with_profile(anchor, profile, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0); // denied, never substituted with another backend's guess
}

TEST(AnchorProfileTest, QuorumWithDeniedSubAnchorFailsClosed)
{
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::Manual;
    sub_a.manual_value = 0xF0;

    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = site;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    an::ScanProfile profile{};
    profile.deny_backend[static_cast<std::size_t>(an::AnchorKind::CodeOperand)] = true; // threads into the sub-anchor

    const an::ResolvedAnchor result = an::resolve_with_profile(quorum, profile, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
}

TEST(AnchorProfileTest, ResolveAllWithProfileCarriesDeny)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor table[2]{};
    table[0].label = "manual";
    table[0].kind = an::AnchorKind::Manual;
    table[0].manual_value = 1;
    table[1].label = "code";
    table[1].kind = an::AnchorKind::CodeOperand;
    table[1].site = site;
    table[1].operand_index = 1;

    an::ScanProfile profile{};
    profile.deny_backend[static_cast<std::size_t>(an::AnchorKind::CodeOperand)] = true;

    an::ResolvedAnchor report[2]{};
    const std::size_t written = an::resolve_all_with_profile(table, report, profile, page.range());
    ASSERT_EQ(written, 2u);
    EXPECT_EQ(report[0].status, an::AnchorStatus::Resolved); // Manual is not denied
    EXPECT_EQ(report[1].status, an::AnchorStatus::Failed);   // CodeOperand is denied
}

TEST(AnchorProfileTest, ResolveAllWithProfileParallelMatchesSerialReport)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate site[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};

    an::Anchor table[3]{};
    table[0].kind = an::AnchorKind::Manual;
    table[0].manual_value = 9;
    table[1].kind = an::AnchorKind::CodeOperand;
    table[1].site = site;
    table[1].operand_index = 1;
    table[2].kind = an::AnchorKind::CallArgHome;

    an::ScanProfile profile{};
    profile.candidate_order = sc::CandidateOrder::UniqueFirst;

    an::ResolvedAnchor serial[3]{};
    an::ResolvedAnchor parallel[3]{};
    const std::size_t serial_count = an::resolve_all_with_profile(table, serial, profile, page.range());
    const std::size_t parallel_count = an::resolve_all_with_profile_parallel(table, parallel, profile, page.range(), 4);
    ASSERT_EQ(serial_count, parallel_count);
    for (std::size_t i = 0; i < serial_count; ++i)
    {
        EXPECT_EQ(parallel[i].status, serial[i].status);
        EXPECT_EQ(parallel[i].value, serial[i].value);
    }
}

TEST(AnchorProfileTest, AppliesCandidateOrderToRipGlobal)
{
    // Two distinct in-scope instructions; a broad candidate that would match the first-in-memory site and a specific
    // candidate for the second. UniqueFirst does not change which unique candidate wins here, but the resolve still
    // succeeds with the profile applied, proving the order path is wired through RipGlobal.
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});

    const sc::Candidate cands[] = {sc::Candidate::direct("marker", aob("DE AD BE EF 10 20 30 40"))};
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = cands;

    an::ScanProfile profile{};
    profile.candidate_order = sc::CandidateOrder::UniqueFirst;

    const an::ResolvedAnchor result = an::resolve_with_profile(anchor, profile, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), page.addr(0x200));
}

// Drift-telemetry gate: assess_quality summary -> GateVerdict startup enable/disable decision.

namespace
{
    // Builds one synthetic ResolvedAnchor so a gate test can assemble an exact drift report without resolving real
    // anchors; only kind and status feed the quality summary the gate reads.
    [[nodiscard]] an::ResolvedAnchor ra(an::AnchorKind kind, an::AnchorStatus status)
    {
        return an::ResolvedAnchor{.label = "t", .kind = kind, .status = status, .value = 0};
    }
} // namespace

TEST(AnchorGateTest, AllResolvedPassesDefaultPolicy)
{
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::VtableIdentity, an::AnchorStatus::Resolved)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, FailedAnchorFailsDefaultPolicy)
{
    // Default max_failed is 0, so a single failure disables the feature regardless of how many others resolved.
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::CodeOperand, an::AnchorStatus::Failed)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, QuorumNotIndependentCountsAsHardFailure)
{
    // A quorum whose sub-anchors were not independent committed no value; it fails closed and counts against max_failed
    // exactly like a Failed anchor.
    const std::array<an::ResolvedAnchor, 2> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::Quorum, an::AnchorStatus::QuorumNotIndependent)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, PartialResolveIsGatedByRatio)
{
    // One of three resolvable anchors resolved; the other two are Unresolved (an untouched slot still drags the ratio).
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved)};

    // 1/3 < 0.5 -> Fail.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 0.5}), an::GateVerdict::Fail);
    // 1/3 >= 0.3 -> clears the ratio; no failure and no manual, so Pass.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 0.3}), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, UnsupportedKindExcludedFromDenominator)
{
    // Two resolved plus one CallArgHome (no resolver, always Unsupported). Under the strict default ratio 1.0 the
    // unsupported kind must NOT be counted against the manifest, so 2/2 resolvable resolved -> Pass.
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, ResolvedManualDowngradesToDegraded)
{
    // Every anchor resolved, but one is a pinned Manual literal that cannot self-heal: Degraded by default...
    const std::array<an::ResolvedAnchor, 2> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::Manual, an::AnchorStatus::Resolved)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Degraded);
    // ...but a policy that opts out of the manual downgrade treats it as a plain Pass.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.manual_at_risk_degrades = false}), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, EmptyReportIsDegraded)
{
    // No anchors means no evidence for the gate to assess; never report it as healthy.
    EXPECT_EQ(an::evaluate_gate(std::span<const an::ResolvedAnchor>{}), an::GateVerdict::Degraded);
}

TEST(AnchorGateTest, AllUnsupportedReportIsDegraded)
{
    // A non-empty report with nothing assessable proves nothing about health: Degraded, never a false Pass.
    const std::array<an::ResolvedAnchor, 2> report{ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported),
                                                   ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported)};
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Degraded);
}

TEST(AnchorGateTest, MaxFailedToleratesConfiguredFailures)
{
    // Two failures with a cap of two clears the hard-failure gate; the remaining resolved fraction then decides. Here
    // 1 resolved of 3 resolvable at ratio 0.3 passes the ratio, so the verdict is Pass.
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Failed),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Failed)};
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 0.3, .max_failed = 2}),
              an::GateVerdict::Pass);
    // One below the cap still fails.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 0.3, .max_failed = 1}),
              an::GateVerdict::Fail);
}

TEST(AnchorGateTest, OutOfRangeRatioIsClamped)
{
    const std::array<an::ResolvedAnchor, 2> report{ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved)};
    // A ratio above 1.0 clamps to 1.0 (still requires every resolvable anchor): 1/2 -> Fail.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = 5.0}), an::GateVerdict::Fail);
    // A negative ratio clamps to 0.0 (any resolved fraction clears it): Pass.
    EXPECT_EQ(an::evaluate_gate(report, an::GatePolicy{.min_resolved_ratio = -1.0}), an::GateVerdict::Pass);
    // NaN is treated as the strict default, not as a threshold that silently passes every report.
    const an::GatePolicy nan_policy{.min_resolved_ratio = std::numeric_limits<double>::quiet_NaN()};
    EXPECT_EQ(an::evaluate_gate(report, nan_policy), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, SpanOverloadMatchesQualityOverload)
{
    const std::array<an::ResolvedAnchor, 3> report{ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::Manual, an::AnchorStatus::Resolved),
                                                   ra(an::AnchorKind::CodeOperand, an::AnchorStatus::Failed)};
    const an::GatePolicy policy{.min_resolved_ratio = 0.5, .max_failed = 1};
    EXPECT_EQ(an::evaluate_gate(report, policy), an::evaluate_gate(an::assess_quality(report), policy));
}

TEST(AnchorGateTest, InconsistentQualitySummaryFailsClosed)
{
    const an::AnchorQuality quality{.total = 1, .resolved = 2};
    EXPECT_EQ(an::evaluate_gate(quality), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, VerdictToStringMapsEveryVerdict)
{
    EXPECT_EQ(an::gate_verdict_to_string(an::GateVerdict::Pass), "Pass");
    EXPECT_EQ(an::gate_verdict_to_string(an::GateVerdict::Degraded), "Degraded");
    EXPECT_EQ(an::gate_verdict_to_string(an::GateVerdict::Fail), "Fail");
}

TEST(AnchorGateTest, GatesARealResolvedReport)
{
    // End-to-end: resolve a real table (one healthy Manual, one Failed backend anchor whose site is absent), then gate
    // the produced report. The Failed anchor trips the default zero-failure cap, so the feature safe-disables.
    an::Anchor anchors[2]{};
    anchors[0].label = "pinned";
    anchors[0].kind = an::AnchorKind::Manual;
    anchors[0].manual_value = 0x40;
    anchors[1].label = "absent";
    anchors[1].kind = an::AnchorKind::StringXref;
    const std::string absent_text =
        std::string{"dmk-anchor-gate-absent-"} + std::to_string(GetCurrentProcessId()) + "-marker";
    anchors[1].xref_text = absent_text;

    an::ResolvedAnchor report[2]{};
    const std::size_t written = an::resolve_all(anchors, report);
    ASSERT_EQ(written, 2u);
    ASSERT_EQ(report[1].status, an::AnchorStatus::Failed);
    EXPECT_EQ(an::evaluate_gate(std::span<const an::ResolvedAnchor>{report, written}), an::GateVerdict::Fail);
}
