#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/scan.hpp"

#include "internal/export_resolution.hpp"

#include "fixtures/loader_lock_scope.hpp"
#include "test_alloc_probe.hpp"

#include "fixtures/rtti_generation_fixture.hpp"
#include "fixtures/scratch_page.hpp"

#include <windows.h>

namespace dmk = DetourModKit;
namespace an = DetourModKit::anchor;
namespace sc = DetourModKit::scan;

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    extern void (*g_scan_after_byte_sweep_test_hook)() noexcept;
    extern void (*g_anchor_after_named_export_lookup_test_hook)() noexcept;
    extern void (*g_anchor_after_owner_identity_test_hook)() noexcept;
    extern void (*g_anchor_after_confirmed_owner_identity_test_hook)() noexcept;
    extern void (*g_anchor_after_witness_test_hook)() noexcept;
} // namespace DetourModKit::detail
#endif

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
                VirtualAlloc(nullptr, m_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            );
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

        // Plants `48 89 05 <disp32>` (mov [rip+slot], rax) at instr_off whose computed target is slot_off. Paired with
        // a preceding plant_rip_load lea, this is the store shape XrefReturn::StringPointerSlot reads its slot from.
        void plant_rip_store(std::size_t instr_off, std::size_t slot_off) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            p[0] = 0x48; // REX.W
            p[1] = 0x89; // mov r/m64, r64
            p[2] = 0x05; // ModRM: mod=00, reg=rax, rm=101 (RIP-relative)
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 7);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(addr(slot_off)) - next);
            std::memcpy(p + 3, &disp, sizeof(disp));
        }

        // Plants a no-REX `8D 05 <disp32>` (lea eax, [rip+target]) at instr_off. The narrow reference sweep models only
        // the REX.W shapes, so this reference exists solely for the broad Zydis sweep.
        void plant_broad_only_rip_load(std::size_t instr_off, std::size_t target_off) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            p[0] = 0x8D;
            p[1] = 0x05;
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 6);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(addr(target_off)) - next);
            std::memcpy(p + 2, &disp, sizeof(disp));
        }

        void put(std::size_t off, std::initializer_list<std::uint8_t> bytes) noexcept
        {
            std::uint8_t *p = m_base + off;
            std::size_t i = 0;
            for (const std::uint8_t byte : bytes)
            {
                p[i++] = byte;
            }
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

TEST(AnchorTest, CodeOperandRejectsOutOfDomainByteWidth)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x8A, 0x45, 0xFF}); // mov al, byte [rbp-0x01]

    const sc::Candidate candidates[] = {sc::Candidate::direct("disp8", aob("8A 45 FF"))};
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::MemoryDisplacement;
    anchor.operand_index = 1;

    for (std::uint8_t width = 0; width <= 8; ++width)
    {
        anchor.byte_width = width;
        EXPECT_EQ(an::declared_domain(anchor), an::ResultDomain::Scalar) << "width=" << static_cast<unsigned>(width);
        const an::ResolvedAnchor valid = an::resolve(anchor, page.range());
        EXPECT_EQ(valid.status, an::AnchorStatus::Resolved) << "width=" << static_cast<unsigned>(width);
        EXPECT_EQ(valid.value, -1) << "width=" << static_cast<unsigned>(width);
    }

    for (const std::uint8_t width : {std::uint8_t{9}, std::uint8_t{255}})
    {
        anchor.byte_width = width;
        EXPECT_EQ(an::declared_domain(anchor), an::ResultDomain::Unknown) << "width=" << static_cast<unsigned>(width);
        const an::ResolvedAnchor invalid = an::resolve(anchor, page.range());
        EXPECT_EQ(invalid.status, an::AnchorStatus::Failed) << "width=" << static_cast<unsigned>(width);
        EXPECT_EQ(invalid.value, 0);
    }
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
// resolves under the default Readable class, but is invisible once the anchor narrows to Executable, so a caller that
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
        HMODULE m_handle{};
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
            nt.FileHeader.NumberOfSections = 1;
            nt.FileHeader.SizeOfOptionalHeader = static_cast<WORD>(sizeof(IMAGE_OPTIONAL_HEADER64));
            nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
            nt.OptionalHeader.SizeOfImage = static_cast<DWORD>(IMAGE_BYTES);
            nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {EXPORT_RVA, EXPORT_BYTES};
            put(NT_RVA, nt);

            IMAGE_SECTION_HEADER section{};
            std::memcpy(section.Name, ".text", 5);
            section.Misc.VirtualSize = 0x1000;
            section.VirtualAddress = 0x1000;
            section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
            put(NT_RVA + sizeof(IMAGE_NT_HEADERS64), section);

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

        [[nodiscard]] bool protect_no_access(std::size_t offset) noexcept
        {
            if (m_base == nullptr || offset >= IMAGE_BYTES)
            {
                return false;
            }
            DWORD old_protection = 0;
            return VirtualProtect(
                       static_cast<std::byte *>(m_base) + offset,
                       IMAGE_BYTES - offset,
                       PAGE_NOACCESS,
                       &old_protection
                   ) != FALSE;
        }

    private:
        void *m_base{};
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

    // Isolate the AddressOfFunctions bound. The fixture puts that array BELOW both the name and ordinal tables, so
    // no image size can exclude it while leaving them inside; the array is relocated above them first, and only then
    // is the declared extent clipped one byte short of its four-byte slot. Clipping to NAMES_RVA instead would leave
    // the refusal attributable to the name table, which the target case above already covers.
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

// Two exported names over ONE function. The declarations differ in every respect a static evidence atom can see (two
// names, two name-table entries, two ordinals), yet AddressOfFunctions carries one RVA for both, so a single patch to
// compute_damage breaks them together. Counting them as 2-of-2 would report corroboration that no second physical
// source backs, so the resolved provenance has to correlate them.
TEST(AnchorTest, QuorumRejectsAliasedExportsOverOneTarget)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());
    const std::uintptr_t primary = fixture.proc("dmk_export_alias_one");
    const std::uintptr_t secondary = fixture.proc("dmk_export_alias_two");
    ASSERT_NE(primary, 0U);
    // Ground truth for "these really are aliases": if the linker ever stopped folding them onto one function, the
    // premise of this case would be gone and it must say so rather than pass for the wrong reason.
    ASSERT_EQ(primary, secondary) << "the fixture no longer exports an alias pair over one target";

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::ExportName;
    sub_a.export_module = ExportFixture::MODULE_NAME;
    sub_a.export_name = "dmk_export_alias_one";
    an::Anchor sub_b = sub_a;
    sub_b.export_name = "dmk_export_alias_two";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);

    // The correlation is specific to a shared physical source, not to the export backend: the same alias still casts a
    // vote when the other member reads something else.
    an::Anchor manual_member{};
    manual_member.kind = an::AnchorKind::Manual;
    manual_member.manual_value = static_cast<std::int64_t>(primary);
    const an::Anchor *mixed[] = {&sub_a, &manual_member};
    quorum.quorum_members = mixed;

    const an::ResolvedAnchor corroborated = an::resolve(quorum, dmk::Region::host());
    EXPECT_EQ(corroborated.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(corroborated.value), primary);
}

// The other alias shape: two names sharing ONE name-ordinal, so both read the same AddressOfFunctions slot. No linker
// this project builds with emits that layout, so the table is written by hand.
TEST(AnchorTest, QuorumRejectsSameOrdinalExportAliases)
{
    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());

    constexpr std::uint32_t alias_name_rva = SyntheticExportImage::NAME_RVA + 0x20;
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.NumberOfNames = 2;
    image.put(SyntheticExportImage::EXPORT_RVA, exports);
    image.put(SyntheticExportImage::NAMES_RVA + sizeof(std::uint32_t), alias_name_rva);
    // Both name entries index function slot 0, so the two names are one table entry read twice.
    image.put(SyntheticExportImage::ORDINALS_RVA + sizeof(std::uint16_t), std::uint16_t{0});
    image.put_string(alias_name_rva, "fixture_export_alias");

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::ExportName;
    sub_a.export_name = "fixture_export";
    an::Anchor sub_b = sub_a;
    sub_b.export_name = "fixture_export_alias";

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
}

// The two correlations are separate tests on separate fields, so this pins which field each alias shape actually
// exercises. A shared slot survives a concurrent rewrite of that slot's RVA, which a target comparison would not, so
// neither rule subsumes the other.
TEST(AnchorTest, ExportProvenanceNamesTheSlotAndTheTarget)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    const dmk::Region module = dmk::Region::module_named(ExportFixture::MODULE_NAME);
    dmk::detail::ExportResolution one;
    dmk::detail::ExportResolution two;
    const dmk::Result<dmk::Address> one_result =
        dmk::detail::resolve_export_with_provenance("dmk_export_alias_one", module, one);
    const dmk::Result<dmk::Address> two_result =
        dmk::detail::resolve_export_with_provenance("dmk_export_alias_two", module, two);
    ASSERT_TRUE(one_result.has_value());
    ASSERT_TRUE(two_result.has_value());
    EXPECT_TRUE(one.present());
    EXPECT_EQ(one.module_base, module.base.raw());
    EXPECT_EQ(one.module_base, two.module_base);
    EXPECT_NE(one.function_index, two.function_index);
    EXPECT_EQ(one.function_rva, two.function_rva);
    EXPECT_EQ(one.target, two.target);
    EXPECT_EQ(one.target, *one_result);
    EXPECT_EQ(two.target, *two_result);
    EXPECT_EQ(one.target.raw(), one.module_base + one.function_rva);
    EXPECT_TRUE(dmk::detail::same_export_site(one, two));

    // A genuinely different export shares neither field, so the correlation does not swallow independent evidence.
    dmk::detail::ExportResolution other;
    ASSERT_TRUE(dmk::detail::resolve_export_with_provenance("compute_armor", module, other).has_value());
    EXPECT_NE(other.function_rva, one.function_rva);
    EXPECT_FALSE(dmk::detail::same_export_site(one, other));

    SyntheticExportImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::uint32_t alias_name_rva = SyntheticExportImage::NAME_RVA + 0x20;
    IMAGE_EXPORT_DIRECTORY exports = image.get<IMAGE_EXPORT_DIRECTORY>(SyntheticExportImage::EXPORT_RVA);
    exports.NumberOfNames = 2;
    image.put(SyntheticExportImage::EXPORT_RVA, exports);
    image.put(SyntheticExportImage::NAMES_RVA + sizeof(std::uint32_t), alias_name_rva);
    image.put(SyntheticExportImage::ORDINALS_RVA + sizeof(std::uint16_t), std::uint16_t{0});
    image.put_string(alias_name_rva, "fixture_export_alias");

    dmk::detail::ExportResolution syn_one;
    dmk::detail::ExportResolution syn_two;
    const dmk::Result<dmk::Address> syn_one_result =
        dmk::detail::resolve_export_with_provenance("fixture_export", image.range(), syn_one);
    const dmk::Result<dmk::Address> syn_two_result =
        dmk::detail::resolve_export_with_provenance("fixture_export_alias", image.range(), syn_two);
    ASSERT_TRUE(syn_one_result.has_value());
    ASSERT_TRUE(syn_two_result.has_value());
    EXPECT_EQ(syn_one.module_base, image.range().base.raw());
    EXPECT_EQ(syn_one.function_index, 0U);
    EXPECT_EQ(syn_one.function_rva, SyntheticExportImage::TARGET_RVA);
    EXPECT_EQ(syn_one.target, *syn_one_result);
    EXPECT_EQ(syn_one.target.raw(), image.range().base.raw() + SyntheticExportImage::TARGET_RVA);
    EXPECT_EQ(syn_two.target, *syn_two_result);
    EXPECT_EQ(syn_one.function_index, syn_two.function_index);
    EXPECT_TRUE(dmk::detail::same_export_site(syn_one, syn_two));

    // The slot rule is what survives a table the two member resolves did not observe identically: a writer that
    // retargets AddressOfFunctions[i] between them leaves one slot with two RVAs, and comparing only the resolved
    // target would call that pair independent. Within one consistent snapshot the two rules agree, so this is the only
    // shape that separates them.
    const dmk::detail::ExportResolution rewritten{
        .module_base = syn_one.module_base,
        .function_index = syn_one.function_index,
        .function_rva = syn_one.function_rva + 0x10,
        .target = dmk::Address{syn_one.target.raw() + 0x10},
    };
    EXPECT_NE(rewritten.function_rva, syn_one.function_rva);
    EXPECT_TRUE(dmk::detail::same_export_site(syn_one, rewritten));

    SyntheticExportImage other_image;
    ASSERT_TRUE(other_image.ok());
    dmk::detail::ExportResolution other_image_resolution;
    const dmk::Result<dmk::Address> other_image_result =
        dmk::detail::resolve_export_with_provenance("fixture_export", other_image.range(), other_image_resolution);
    ASSERT_TRUE(other_image_result.has_value());
    EXPECT_NE(other_image_resolution.module_base, syn_one.module_base);
    EXPECT_EQ(other_image_resolution.function_index, syn_one.function_index);
    EXPECT_EQ(other_image_resolution.function_rva, syn_one.function_rva);
    EXPECT_EQ(other_image_resolution.target, *other_image_result);
    EXPECT_EQ(
        other_image_resolution.target.raw(),
        other_image_resolution.module_base + other_image_resolution.function_rva
    );
    EXPECT_FALSE(dmk::detail::same_export_site(syn_one, other_image_resolution));
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
        {
            .label = "export",
            .kind = an::AnchorKind::ExportName,
            .status = an::AnchorStatus::Resolved,
            .value = 0x1000,
        },
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
    // require_validator is a backend-target policy, so it never rejects a pinned Manual literal for lacking a
    // validator, even when validate_manual routes the Manual through the validator path with no validator attached.
    // This contradictory-but-benign config resolves rather than fails, matching the anchor.hpp contract (Manual is not
    // a resolved target). With a validator missing there is simply nothing to run.
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

TEST(AnchorTest, QuorumRejectsDifferentPatternsOverOneCodeOperandSite)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    const sc::Candidate exact[] = {sc::Candidate::direct("exact", aob("48 05 F0 00 00 00"))};
    const sc::Candidate wildcard[] = {sc::Candidate::direct("wildcard", aob("48 05 ?? 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::CodeOperand;
    sub_a.site = exact;
    sub_a.operand_index = 1;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = wildcard;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// The physical-overlap gate runs BEFORE value clustering, so a dependent pair is named as dependent even when its
// members disagree. Both members here read the one `add rax, 0xF0`: the byte rung commits the instruction's address
// while the operand member decodes its immediate, so the two votes differ. Ordering the checks the other way round
// would find no agreeing cluster first and report the generic Failed, hiding that the declaration reused one site.
TEST(AnchorTest, QuorumRejectsOverlappingMembersAheadOfValueClustering)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0
    // Distinct compiled patterns, so the declaration-atom gate passes them through to the physical check.
    const sc::Candidate exact[] = {sc::Candidate::direct("exact", aob("48 05 F0 00 00 00"))};
    const sc::Candidate wildcard[] = {sc::Candidate::direct("wildcard", aob("48 05 ?? 00 00 00"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = exact;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = wildcard;
    sub_b.operand_kind = sc::OperandKind::Immediate;
    sub_b.operand_index = 1;

    // Control: the members really do resolve, and really do disagree.
    const an::ResolvedAnchor alone_a = an::resolve(sub_a, page.range());
    ASSERT_EQ(alone_a.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(alone_a.value, static_cast<std::int64_t>(page.addr(0x100)));
    const an::ResolvedAnchor alone_b = an::resolve(sub_b, page.range());
    ASSERT_EQ(alone_b.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(alone_b.value, 0xF0);
    ASSERT_NE(alone_a.value, alone_b.value);

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, QuorumRejectsCrossKindVotesFromOneInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    image.plant_rip_load(0x100, 0x500, 0x8B);
    const sc::Candidate target[] = {sc::Candidate::rip_relative("target", aob("48 8B 05 ?? ?? ?? ??"), 3, 7)};
    const sc::Candidate operand[] = {sc::Candidate::direct("operand", aob("48 8B 05 ?? ?? ?? ??"))};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = target;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = operand;
    sub_b.operand_kind = sc::OperandKind::MemoryDisplacement;
    sub_b.operand_index = 1;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, QuorumRejectsCodeOperandWalkedBackOntoAnotherWinnersInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    image.plant_rip_load(0x100, 0x500, 0x8B); // 48 8B 05 <disp32>: mov rax, [rip+disp32]
    constexpr char LANDMARK[] = "\x11\x22\x33\x44\x55\x66\x77\x88";
    image.write_string(0x0F0, std::string_view{LANDMARK, 8});

    // The RIP member skips the REX prefix, so its matched span starts one byte inside the instruction and its own
    // decode is the shorter `8B 05 <disp32>` form that resolves the identical target.
    const sc::Candidate shifted[] = {sc::Candidate::rip_relative("shifted", aob("8B 05 ?? ?? ?? ??"), 2, 6)};
    // The operand member never matches the instruction at all: it matches a landmark that ends before it and walks
    // forward onto it, so neither its matched span nor the instruction's first byte meets the RIP member's span.
    const sc::Candidate landmark[] = {sc::Candidate::direct("landmark", aob("11 22 33 44 55 66 77 88"), 0x10)};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = shifted;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::CodeOperand;
    sub_b.site = landmark;
    sub_b.operand_kind = sc::OperandKind::MemoryDisplacement;
    sub_b.operand_index = 1;

    // Control: each member alone reads the same target off the one instruction, so the vote below would agree.
    const an::ResolvedAnchor alone_a = an::resolve(sub_a, image.range());
    ASSERT_EQ(alone_a.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(alone_a.value, static_cast<std::int64_t>(image.addr(0x500)));
    const an::ResolvedAnchor alone_b = an::resolve(sub_b, image.range());
    ASSERT_EQ(alone_b.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(alone_b.value, static_cast<std::int64_t>(image.addr(0x500)));

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    // One patched disp32 breaks both votes at once, so the decoded instruction's whole extent is one failure domain.
    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, QuorumRejectsDifferentResultMarkersOverOnePhysicalSpan)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});
    const sc::Candidate at_start[] = {sc::Candidate::direct("start", aob("48 05 F0 00 00 00"))};
    const sc::Candidate after_prefix[] = {sc::Candidate::direct("offset", aob("48 | 05 F0 00 00 00"), -1)};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = at_start;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = after_prefix;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

TEST(AnchorTest, QuorumAcceptsDistinctRipInstructionsWithOneTarget)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    image.plant_rip_load(0x100, 0x500, 0x8B);
    image.plant_rip_load(0x180, 0x500, 0x8D);
    const sc::Candidate mov[] = {sc::Candidate::rip_relative("mov", aob("48 8B 05 ?? ?? ?? ??"), 3, 7)};
    const sc::Candidate lea[] = {sc::Candidate::rip_relative("lea", aob("48 8D 05 ?? ?? ?? ??"), 3, 7)};

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = mov;
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = lea;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, static_cast<std::int64_t>(image.addr(0x500)));
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
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0: a single unique site
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

TEST(AnchorTest, QuorumRejectsDifferentDescriptorsOverOnePhysicalSite)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xAD, 0xBE});

    // All three patterns resolve the same physical site. Their distinct gap descriptors are authored selectors, not
    // independent runtime evidence, so they must collapse to one failure domain.
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
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// The Anchor::pages knob is scan POLICY, not resolution evidence: it changes which pages are swept, never the target
// identity. So two RipGlobal members over the same site content that differ ONLY in pages are the same evidence and
// must not corroborate each other. The independence gate (collect_independence_atoms) must ignore pages even though
// the drift fingerprint (anchor_fingerprint) folds it. This locks that drift-vs-independence split for the pages
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
    // reordered copy decodes the same site and is dependent evidence, not corroboration: the independence gate must
    // be order-INDEPENDENT. (Here both rungs resolve to 0xF0, so a storage/order-sensitive gate would have let this
    // pair falsely corroborate; the fix reports QuorumNotIndependent before any resolve.)
    const sc::Candidate ladder_ab[] = {
        sc::Candidate::direct("a", aob("48 05 F0 00 00 00")),
        sc::Candidate::direct("b", aob("48 81 C1 F0 00 00 00"))
    };
    const sc::Candidate ladder_ba[] = {
        sc::Candidate::direct("b", aob("48 81 C1 F0 00 00 00")),
        sc::Candidate::direct("a", aob("48 05 F0 00 00 00"))
    };

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
// threshold (Failed), but it must never be rejected as QuorumNotIndependent. That would prove the gate
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

// A signature need not cover the trailing immediates of the instruction it authorizes, so a RIP winner's authored
// match span stops short of the instruction its own decode consumed. Those uncovered immediates are still bytes the
// target depends on: a second rung matching THEM abuts the first span without overlapping it, and half-open adjacency
// reads as independence. Both members here are the one 10-byte `mov dword [rip+disp32], imm32`.
TEST(AnchorTest, QuorumRejectsRungMatchingAnotherWinnersTrailingImmediate)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    // C7 05 <disp32> <imm32> at 0x100; disp32 targets 0x300, imm32 is the distinctive DE C0 AD 0B.
    constexpr std::size_t instruction_offset = 0x100;
    constexpr std::size_t target_offset = 0x300;
    const std::uintptr_t instruction_address = page.addr(instruction_offset);
    const auto displacement = static_cast<std::int32_t>(
        static_cast<std::int64_t>(page.addr(target_offset)) - static_cast<std::int64_t>(instruction_address + 10)
    );
    const auto disp_byte = [displacement](unsigned shift) noexcept
    { return static_cast<std::uint8_t>((static_cast<std::uint32_t>(displacement) >> shift) & 0xFFu); };
    page.put(
        instruction_offset,
        {0xC7, 0x05, disp_byte(0), disp_byte(8), disp_byte(16), disp_byte(24), 0xDE, 0xC0, 0xAD, 0x0B}
    );

    const sc::Candidate head[] = {sc::Candidate::rip_relative("rip-head", aob("C7 05 ?? ?? ?? ??"), 2, 10)};
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = head;
    sub_a.pages = sc::Pages::Executable;

    // Direct decodes nothing: it matches the trailing immediate and walks back to the same target by arithmetic, so
    // no "it must decode a different instruction" argument keeps this pair apart.
    const auto walk_back =
        static_cast<std::ptrdiff_t>(target_offset) - static_cast<std::ptrdiff_t>(instruction_offset + 6);
    const sc::Candidate tail[] = {sc::Candidate::direct("immediate-tail", aob("DE C0 AD 0B"), walk_back)};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = tail;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// A StringXref is byte-backed evidence like any byte rung: the reference it locates is an instruction, and a selector
// authored as a byte pattern over that same instruction is the SAME physical signal wearing a different declaration.
// Their declaration atoms differ (a literal versus a compiled pattern), so only the physical-span check can catch it;
// without one the pair reaches an identical value from one instruction and double-votes to a false corroboration.
TEST(AnchorTest, QuorumRejectsStringXrefOverlappingAnotherWinnersInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumPhysicalOverlapLiteralMarker";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = literal;

    // Direct mode returns the match itself, so this rung commits the very instruction the xref reference resolved to.
    const sc::Candidate site_b[] = {sc::Candidate::direct("same-instruction", aob("48 8D 05 ?? ?? ?? ??"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// The same physical signal reached through the ladder tier instead of the flat kind: a RipGlobal whose rung is a
// StringXref candidate resolves through the identical reference, so it must carry the identical provenance. Routing
// the evidence through a ladder is a spelling change, not a second signal.
TEST(AnchorTest, QuorumRejectsStringXrefRungOverlappingAnotherWinnersInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumLadderOverlapLiteralMarker";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]

    const sc::Candidate site_a[] = {sc::Candidate::string_xref("xref-rung", std::string{literal})};
    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::RipGlobal;
    sub_a.site = site_a;

    const sc::Candidate site_b[] = {sc::Candidate::direct("same-instruction", aob("48 8D 05 ?? ?? ?? ??"))};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// The green control for the rule above: a StringXref and a byte rung that agree on one value from two DISJOINT
// instructions are genuinely separate evidence and must still corroborate. Without this, rejecting every StringXref
// that shares a value would pass the test above while destroying legitimate cross-backend corroboration.
TEST(AnchorTest, QuorumAcceptsStringXrefAndDistinctRipInstruction)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumDisjointEvidenceLiteralMarker";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]; the xref reference
    image.plant_rip_load(0x200, 0x100, 0x8B); // mov rax, [rip+lea]; a separate instruction aimed at the same address

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = literal;

    const sc::Candidate site_b[] = {
        sc::Candidate::rip_relative("distinct-instruction", aob("48 8B 05 ?? ?? ?? ??"), 3, 7)
    };
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), image.addr(0x100));
}

// StringPointerSlot returns an address decoded from the CACHING STORE's own disp32; the string reference only selects
// which store. A member matching that store therefore reads the identical four bytes and can never disagree, so it is
// one failure domain even though the store begins after the reference ends. Publishing only the reference would let
// the two spans abut instead of overlap and certify a single disp32 as 2-of-2 corroboration.
TEST(AnchorTest, QuorumRejectsStringPointerSlotOverlappingTheStoreItDecoded)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumSlotStoreOverlapLiteralMarker";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D); // lea rax, [rip+string]
    image.plant_rip_store(0x107, 0x600);      // mov [rip+slot], rax, immediately after the lea

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = literal;
    sub_a.xref_return = sc::XrefReturn::StringPointerSlot;

    const sc::Candidate site_b[] = {sc::Candidate::rip_relative("same-store", aob("48 89 05 ?? ?? ?? ??"), 3, 7)};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
}

// A reference the narrow shape sweep does not model is framed by the broad Zydis sweep instead, which knows the
// instruction's real end. The published provenance must be that whole instruction: a co-voting selector that walks
// back to the same site from a byte INSIDE the reference witnesses the same evidence, and a one-byte span at the
// instruction start would leave every later byte of it unclaimed.
TEST(AnchorTest, QuorumRejectsBroadOnlyReferenceMatchedFromItsInteriorBytes)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "QuorumBroadReferenceExtentMarker";
    image.write_string(0x400, literal);
    image.plant_broad_only_rip_load(0x100, 0x400); // lea eax, [rip+string]: no REX, so narrow-invisible
    image.put(0x106, {0xDE, 0xAD, 0xBE, 0xEF});    // distinctive tail so the co-voting rung is unique

    an::Anchor sub_a{};
    sub_a.kind = an::AnchorKind::StringXref;
    sub_a.xref_text = literal;
    sub_a.xref_broad_match = true;

    // Matches from the reference's SECOND byte and walks back one, so it commits the same site while its own span
    // starts inside the instruction the xref resolved.
    const sc::Candidate site_b[] = {sc::Candidate::direct("interior", aob("05 ?? ?? ?? ?? DE AD BE EF"), -1)};
    an::Anchor sub_b{};
    sub_b.kind = an::AnchorKind::RipGlobal;
    sub_b.site = site_b;
    sub_b.pages = sc::Pages::Executable;

    const an::Anchor *members[] = {&sub_a, &sub_b};
    an::Anchor quorum{};
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, image.range());
    EXPECT_EQ(result.status, an::AnchorStatus::QuorumNotIndependent);
    EXPECT_EQ(result.value, 0);
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
    const sc::Candidate ladder_a[] = {
        sc::Candidate::direct("a-primary", aob("48 81 C1 F0 00 00 00")),
        sc::Candidate::direct("shared", aob("48 05 F0 00 00 00"))
    };
    const sc::Candidate ladder_b[] = {
        sc::Candidate::direct("b-primary", aob("48 81 C2 F0 00 00 00")),
        sc::Candidate::direct("shared", aob("48 05 F0 00 00 00"))
    };

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
    // the threshold and disagree, so declaration order must not pick one: the vote is ambiguous, in ANY order.
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
    // imul rax, qword ptr [rbp+0xF0], 0xF0: two resolvable constants in one instruction/failure domain.
    page.put(0x100, {0x48, 0x69, 0x85, 0xF0, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00});
    const sc::Candidate site_a[] = {sc::Candidate::direct("op-a", aob("48 69 85 F0 00 00 00 F0 00 00 00"))};
    const sc::Candidate site_b[] = {sc::Candidate::direct("op-b", aob("48 69 85 F0 00 00 00 F0 00 00 00"))};

    // Two CodeOperands over the SAME instruction site that merely select a different operand. One patch to that
    // instruction breaks both, so they are one witness, not two: the site alone keys the failure domain.
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
    EXPECT_EQ(
        an::resolve(export_quorum, dmk::Region::module_named(ExportFixture::MODULE_NAME)).status,
        an::AnchorStatus::QuorumNotIndependent
    );
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
    ASSERT_EQ(
        an::resolve_with_profile(rip_control, an::ScanProfile{}, page.range()).status,
        an::AnchorStatus::Resolved
    );
    EXPECT_EQ(an::resolve_with_profile(rip_control, bad_order_profile, page.range()).status, an::AnchorStatus::Failed);
    ASSERT_EQ(
        an::resolve_with_profile(code_control, an::ScanProfile{}, page.range()).status,
        an::AnchorStatus::Resolved
    );
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
    const sc::Candidate split_left[] = {
        sc::Candidate::direct("c0", aob("AA BB")),
        sc::Candidate::direct("c1", aob("CC"))
    };
    const sc::Candidate split_right[] = {
        sc::Candidate::direct("c0", aob("AA")),
        sc::Candidate::direct("c1", aob("BB CC"))
    };
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
    const sc::Candidate two[] = {
        sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??")),
        sc::Candidate::direct("c", aob("48 8B 05 ?? ?? ?? ??"))
    };
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
    // and {A, B, B} (the same distinct set at different multiplicity) would collide. This locks the
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
        return an::ResolvedAnchor{
            .label = "t",
            .kind = kind,
            .status = status,
            .value = 0,
        };
    }
} // namespace

TEST(AnchorGateTest, AllResolvedPassesDefaultPolicy)
{
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::VtableIdentity, an::AnchorStatus::Resolved)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, FailedAnchorFailsDefaultPolicy)
{
    // Default max_failed is 0, so a single failure disables the feature regardless of how many others resolved.
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::CodeOperand, an::AnchorStatus::Failed)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, QuorumNotIndependentCountsAsHardFailure)
{
    // A quorum whose sub-anchors were not independent committed no value; it fails closed and counts against max_failed
    // exactly like a Failed anchor.
    const std::array<an::ResolvedAnchor, 2> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::Quorum, an::AnchorStatus::QuorumNotIndependent)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, PartialResolveIsGatedByRatio)
{
    // One of three resolvable anchors resolved; the other two are Unresolved (an untouched slot still drags the ratio).
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved)
    };

    // 1/3 < 0.5 -> Fail.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.5,
            }
        ),
        an::GateVerdict::Fail
    );
    // 1/3 >= 0.3 -> clears the ratio; no failure and no manual, so Pass.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.3,
            }
        ),
        an::GateVerdict::Pass
    );
}

TEST(AnchorGateTest, UnsupportedKindExcludedFromDenominator)
{
    // Two resolved plus one CallArgHome (no resolver, always Unsupported). Under the strict default ratio 1.0 the
    // unsupported kind must NOT be counted against the manifest, so 2/2 resolvable resolved -> Pass.
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Pass);
}

TEST(AnchorGateTest, ResolvedManualDowngradesToDegraded)
{
    // Every anchor resolved, but one is a pinned Manual literal that cannot self-heal: Degraded by default...
    const std::array<an::ResolvedAnchor, 2> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::Manual, an::AnchorStatus::Resolved)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Degraded);
    // ...but a policy that opts out of the manual downgrade treats it as a plain Pass.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .manual_at_risk_degrades = false,
            }
        ),
        an::GateVerdict::Pass
    );
}

TEST(AnchorGateTest, FailedManualStillCountsAtRisk)
{
    // manual_at_risk counts every Manual entry regardless of status: the pin cannot self-heal whether or not it
    // resolved this run. A policy that tolerates the failure therefore lands on Degraded, not Pass.
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::Manual, an::AnchorStatus::Failed)
    };
    EXPECT_EQ(an::assess_quality(report).manual_at_risk, 1u);
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.5,
                .max_failed = 1,
            }
        ),
        an::GateVerdict::Degraded
    );
    // Opting out of the manual downgrade restores the tolerated-failure Pass.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.5,
                .max_failed = 1,
                .manual_at_risk_degrades = false,
            }
        ),
        an::GateVerdict::Pass
    );
}

TEST(AnchorGateTest, EmptyReportIsDegraded)
{
    // No anchors means no evidence for the gate to assess; never report it as healthy.
    EXPECT_EQ(an::evaluate_gate(std::span<const an::ResolvedAnchor>{}), an::GateVerdict::Degraded);
}

TEST(AnchorGateTest, AllUnsupportedReportIsDegraded)
{
    // A non-empty report with nothing assessable proves nothing about health: Degraded, never a false Pass.
    const std::array<an::ResolvedAnchor, 2> report{
        ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported),
        ra(an::AnchorKind::CallArgHome, an::AnchorStatus::Unsupported)
    };
    EXPECT_EQ(an::evaluate_gate(report), an::GateVerdict::Degraded);
}

TEST(AnchorGateTest, MaxFailedToleratesConfiguredFailures)
{
    // Two failures with a cap of two clears the hard-failure gate; the remaining resolved fraction then decides. Here
    // 1 resolved of 3 resolvable at ratio 0.3 passes the ratio, so the verdict is Pass.
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Failed),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Failed)
    };
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.3,
                .max_failed = 2,
            }
        ),
        an::GateVerdict::Pass
    );
    // One below the cap still fails.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 0.3,
                .max_failed = 1,
            }
        ),
        an::GateVerdict::Fail
    );
}

TEST(AnchorGateTest, OutOfRangeRatioIsClamped)
{
    const std::array<an::ResolvedAnchor, 2> report{
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Unresolved)
    };
    // A ratio above 1.0 clamps to 1.0 (still requires every resolvable anchor): 1/2 -> Fail.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = 5.0,
            }
        ),
        an::GateVerdict::Fail
    );
    // A negative ratio clamps to 0.0 (any resolved fraction clears it): Pass.
    EXPECT_EQ(
        an::evaluate_gate(
            report,
            an::GatePolicy{
                .min_resolved_ratio = -1.0,
            }
        ),
        an::GateVerdict::Pass
    );
    // NaN is treated as the strict default, not as a threshold that silently passes every report.
    const an::GatePolicy nan_policy{
        .min_resolved_ratio = std::numeric_limits<double>::quiet_NaN(),
    };
    EXPECT_EQ(an::evaluate_gate(report, nan_policy), an::GateVerdict::Fail);
}

TEST(AnchorGateTest, SpanOverloadMatchesQualityOverload)
{
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::Manual, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::CodeOperand, an::AnchorStatus::Failed)
    };
    const an::GatePolicy policy{
        .min_resolved_ratio = 0.5,
        .max_failed = 1,
    };
    EXPECT_EQ(an::evaluate_gate(report, policy), an::evaluate_gate(an::assess_quality(report), policy));
}

TEST(AnchorGateTest, InconsistentQualitySummaryFailsClosed)
{
    const an::AnchorQuality quality{
        .total = 1,
        .resolved = 2,
    };
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

// Trust fingerprints bind definition evidence to an ASLR-insensitive image identity.

TEST(AnchorTrustFingerprintTest, DefinitionFingerprintIsScopeFreeButTrustFingerprintBindsScope)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::Manual;
    a.manual_value = 42;

    const sc::ImageIdentity id1{
        .timestamp = 1,
        .size_of_image = 0x1000,
        .section_digest = 0xAA,
    };
    const sc::ImageIdentity id2{
        .timestamp = 2,
        .size_of_image = 0x2000,
        .section_digest = 0xBB,
    };

    // The definition fingerprint takes no scope and is stable; the trust fingerprint differs from it and moves with
    // the bound image identity.
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(a));
    EXPECT_NE(an::anchor_trust_fingerprint(a, id1), an::anchor_fingerprint(a));
    EXPECT_EQ(an::anchor_trust_fingerprint(a, id1), an::anchor_trust_fingerprint(a, id1));
    EXPECT_NE(an::anchor_trust_fingerprint(a, id1), an::anchor_trust_fingerprint(a, id2));
}

TEST(AnchorTrustFingerprintTest, InheritedEmptyExportModuleScopeCollidesWithExplicitSameModule)
{
    an::Anchor inherited{};
    inherited.kind = an::AnchorKind::ExportName;
    inherited.export_name = "compute_damage";
    // export_module empty: the effective module is the passed scope.

    an::Anchor explicit_mod{};
    explicit_mod.kind = an::AnchorKind::ExportName;
    explicit_mod.export_name = "compute_damage";
    explicit_mod.export_module = "game.dll";

    const sc::ImageIdentity effective{
        .timestamp = 7,
        .size_of_image = 0x4000,
        .section_digest = 0xC0FFEE,
    };

    // Two ways to name one effective export collapse to one TRUST key (the declared module string is replaced by the
    // effective identity), even though their DEFINITION fingerprints differ (one folds the module string).
    EXPECT_EQ(
        an::anchor_trust_fingerprint(inherited, effective),
        an::anchor_trust_fingerprint(explicit_mod, effective)
    );
    EXPECT_NE(an::anchor_fingerprint(inherited), an::anchor_fingerprint(explicit_mod));
}

TEST(AnchorTrustFingerprintTest, SameBaseRemappedModuleChangesTrustFingerprintNotDefinition)
{
    an::Anchor a{};
    a.kind = an::AnchorKind::ExportName;
    a.export_name = "compute_damage";

    // A same-base remap keeps timestamp and size but rewrites the section table (a different PE at the same base).
    const sc::ImageIdentity before{
        .timestamp = 9,
        .size_of_image = 0x8000,
        .section_digest = 0x1111,
    };
    const sc::ImageIdentity after{
        .timestamp = 9,
        .size_of_image = 0x8000,
        .section_digest = 0x2222,
    };

    EXPECT_NE(an::anchor_trust_fingerprint(a, before), an::anchor_trust_fingerprint(a, after));
    EXPECT_EQ(an::anchor_fingerprint(a), an::anchor_fingerprint(a));
}

// A resolved report carries its image, physical source, decoded operand kind, and completeness.

TEST(AnchorWitnessTest, ResolvedExportCarriesLiveImageIdentityAndSource)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok()) << "Failed to load " << ExportFixture::MODULE_NAME << ": " << GetLastError();
    ASSERT_NE(fixture.proc("compute_damage"), 0U);

    an::Anchor anchor{};
    anchor.label = "fixture.compute_damage";
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "compute_damage";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::ExportTable);
    EXPECT_EQ(result.witness.completeness, an::WitnessCompleteness::Complete);
    ASSERT_TRUE(result.witness.image.present());
    // The witness image is the identity of the module the export actually resolved in.
    EXPECT_EQ(result.witness.image, sc::image_identity(dmk::Region::module_named(ExportFixture::MODULE_NAME)));
}

TEST(AnchorWitnessTest, ManualScalarCarriesSourceButNoImage)
{
    an::Anchor anchor{};
    anchor.label = "pinned";
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x1234;

    const an::ResolvedAnchor result = an::resolve(anchor);
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::ManualPin);
    EXPECT_EQ(result.witness.completeness, an::WitnessCompleteness::Complete);
    // A Scalar is a constant, not a location, so it carries no live-image identity.
    EXPECT_FALSE(result.witness.image.present());
    EXPECT_FALSE(result.witness.evidence.present());
}

TEST(AnchorWitnessTest, CodeOperandCarriesNoContentEvidenceDespiteLocatingByBytes)
{
    // CodeOperand is the one kind that could plausibly be read as a byte-pattern tier and is not: it locates a site
    // with a pattern, then decodes a value OUT of it, so the resolved value is a Scalar constant rather than the span.
    // Forwarding the matched span here would attach a content baseline to a number, which no mutation can be gated
    // against, so this pins the absence rather than leaving it to the resolve path's structure.
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
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
    EXPECT_EQ(result.domain, an::ResultDomain::Scalar);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::CodeOperand);
    EXPECT_FALSE(result.witness.evidence.present());
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorWitnessTest, RipGlobalReportsItsWinningStringSource)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "AnchorWitnessStringCandidate";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D);

    const sc::Candidate candidates[] = {sc::Candidate::string_xref("string", std::string{literal})};
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;

    const an::ResolvedAnchor result = an::resolve(anchor, image.range());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::StringLiteral);
    // Content evidence rides only a winning byte-pattern rung. This ladder is RipGlobal, but it won through a
    // structure, so there is no matched span to witness and the content gate must find nothing to compare.
    EXPECT_FALSE(result.witness.evidence.present());
}

TEST(AnchorWitnessTest, UnresolvedReportOmitsWitness)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    an::Anchor anchor{};
    anchor.label = "missing";
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "this_export_does_not_exist";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    ASSERT_NE(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::None);
    EXPECT_EQ(result.witness.completeness, an::WitnessCompleteness::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorWitnessTest, PhysicalSourceToStringMapsEverySource)
{
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::None), "None");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::ByteSignature), "ByteSignature");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::StringLiteral), "StringLiteral");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::TypeIdentity), "TypeIdentity");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::ExportTable), "ExportTable");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::CodeOperand), "CodeOperand");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::ManualPin), "ManualPin");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::Corroborated), "Corroborated");
    EXPECT_EQ(an::physical_source_to_string(static_cast<an::PhysicalSource>(0xFF)), "Unknown");
}

// The trust transaction: the evidence a value came from and the identity published with it must be the same image. A
// module replaced at its own base during the resolve otherwise leaves a value read from the previous image
// corroborated by the identity of the image now mapped there, which no consumer can tell from a genuine result.

namespace
{
    dmk_test::SameBaseSwap *s_anchor_swap = nullptr;
    bool s_anchor_swap_happened = false;

    [[nodiscard]] bool try_swap_anchor_fixture() noexcept
    {
        if (s_anchor_swap == nullptr)
        {
            return false;
        }
        try
        {
            return s_anchor_swap->swap_to_b();
        }
        catch (...)
        {
            return false;
        }
    }

    // Accepts the value, but replaces the fixture module at its own base on the way through, so the replacement lands
    // inside the resolve between the evidence walk and the report the caller reads.
    bool swap_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_anchor_swap != nullptr && !s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
        return true;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    void swap_after_discovery_sweep() noexcept
    {
        DetourModKit::detail::g_scan_after_byte_sweep_test_hook = nullptr;
        if (!s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
    }

    class ScopedDiscoverySweepHook
    {
    public:
        ScopedDiscoverySweepHook() noexcept
        {
            DetourModKit::detail::g_scan_after_byte_sweep_test_hook = &swap_after_discovery_sweep;
        }

        ~ScopedDiscoverySweepHook() noexcept { DetourModKit::detail::g_scan_after_byte_sweep_test_hook = nullptr; }

        ScopedDiscoverySweepHook(const ScopedDiscoverySweepHook &) = delete;
        ScopedDiscoverySweepHook &operator=(const ScopedDiscoverySweepHook &) = delete;
    };

    void swap_after_named_export_lookup() noexcept
    {
        DetourModKit::detail::g_anchor_after_named_export_lookup_test_hook = nullptr;
        if (!s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
    }

    class ScopedNamedExportLookupHook
    {
    public:
        ScopedNamedExportLookupHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_named_export_lookup_test_hook = &swap_after_named_export_lookup;
        }

        ~ScopedNamedExportLookupHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_named_export_lookup_test_hook = nullptr;
        }

        ScopedNamedExportLookupHook(const ScopedNamedExportLookupHook &) = delete;
        ScopedNamedExportLookupHook &operator=(const ScopedNamedExportLookupHook &) = delete;
    };

    void swap_between_owner_identity_samples() noexcept
    {
        DetourModKit::detail::g_anchor_after_owner_identity_test_hook = nullptr;
        if (!s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
    }

    class ScopedOwnerIdentityHook
    {
    public:
        ScopedOwnerIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_owner_identity_test_hook = &swap_between_owner_identity_samples;
        }

        ~ScopedOwnerIdentityHook() noexcept { DetourModKit::detail::g_anchor_after_owner_identity_test_hook = nullptr; }

        ScopedOwnerIdentityHook(const ScopedOwnerIdentityHook &) = delete;
        ScopedOwnerIdentityHook &operator=(const ScopedOwnerIdentityHook &) = delete;
    };

    void swap_after_witness_construction() noexcept
    {
        DetourModKit::detail::g_anchor_after_witness_test_hook = nullptr;
        if (!s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
    }

    class ScopedWitnessHook
    {
    public:
        ScopedWitnessHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_witness_test_hook = &swap_after_witness_construction;
        }

        ~ScopedWitnessHook() noexcept { DetourModKit::detail::g_anchor_after_witness_test_hook = nullptr; }

        ScopedWitnessHook(const ScopedWitnessHook &) = delete;
        ScopedWitnessHook &operator=(const ScopedWitnessHook &) = delete;
    };
#endif

    dmk_test::GenerationFixtureModule *s_private_replacement_module = nullptr;
    const std::byte *s_private_replacement_header = nullptr;
    std::size_t s_private_replacement_header_size = 0;
    std::uintptr_t s_private_replacement_base = 0;
    std::size_t s_private_replacement_image_size = 0;
    void *s_private_replacement_mapping = nullptr;
    HMODULE s_private_replacement_restored_module = nullptr;
    bool s_private_replacement_happened = false;
    bool s_private_replacement_restored = false;

    bool replace_with_private_image_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_private_replacement_module == nullptr || s_private_replacement_happened)
        {
            return true;
        }
        try
        {
            s_private_replacement_module->release();
        }
        catch (...)
        {
            return true;
        }
        void *const mapping = ::VirtualAlloc(
            reinterpret_cast<void *>(s_private_replacement_base),
            s_private_replacement_image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (reinterpret_cast<std::uintptr_t>(mapping) != s_private_replacement_base)
        {
            if (mapping != nullptr)
            {
                (void)::VirtualFree(mapping, 0, MEM_RELEASE);
            }
            return true;
        }
        std::memcpy(mapping, s_private_replacement_header, s_private_replacement_header_size);
        s_private_replacement_mapping = mapping;
        s_private_replacement_happened = true;
        return true;
    }

    class ScopedPrivateImageReplacement
    {
    public:
        ScopedPrivateImageReplacement(
            dmk_test::GenerationFixtureModule &module,
            dmk::Region image,
            std::span<const std::byte> header
        ) noexcept
        {
            s_private_replacement_module = &module;
            s_private_replacement_header = header.data();
            s_private_replacement_header_size = header.size();
            s_private_replacement_base = image.base.raw();
            s_private_replacement_image_size = image.size;
            s_private_replacement_mapping = nullptr;
            s_private_replacement_restored_module = nullptr;
            s_private_replacement_happened = false;
            s_private_replacement_restored = false;
        }

        ~ScopedPrivateImageReplacement() noexcept
        {
            s_private_replacement_module = nullptr;
            s_private_replacement_header = nullptr;
            s_private_replacement_header_size = 0;
            s_private_replacement_base = 0;
            s_private_replacement_image_size = 0;
            if (s_private_replacement_restored_module != nullptr)
            {
                ::FreeLibrary(s_private_replacement_restored_module);
                s_private_replacement_restored_module = nullptr;
            }
            if (s_private_replacement_mapping != nullptr)
            {
                (void)::VirtualFree(s_private_replacement_mapping, 0, MEM_RELEASE);
                s_private_replacement_mapping = nullptr;
            }
            s_private_replacement_happened = false;
            s_private_replacement_restored = false;
        }

        ScopedPrivateImageReplacement(const ScopedPrivateImageReplacement &) = delete;
        ScopedPrivateImageReplacement &operator=(const ScopedPrivateImageReplacement &) = delete;

        [[nodiscard]] bool happened() const noexcept { return s_private_replacement_happened; }
        [[nodiscard]] bool restored() const noexcept { return s_private_replacement_restored; }
    };

#if defined(DMK_ENABLE_TEST_SEAMS)
    void replace_with_private_image_during_owner_identity() noexcept
    {
        DetourModKit::detail::g_anchor_after_owner_identity_test_hook = nullptr;
        (void)replace_with_private_image_then_accept(0, nullptr);
    }

    class ScopedPrivateOwnerIdentityHook
    {
    public:
        ScopedPrivateOwnerIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_owner_identity_test_hook =
                &replace_with_private_image_during_owner_identity;
        }

        ~ScopedPrivateOwnerIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_owner_identity_test_hook = nullptr;
        }

        ScopedPrivateOwnerIdentityHook(const ScopedPrivateOwnerIdentityHook &) = delete;
        ScopedPrivateOwnerIdentityHook &operator=(const ScopedPrivateOwnerIdentityHook &) = delete;
    };

    void restore_image_after_confirmed_identity() noexcept
    {
        DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook = nullptr;
        if (s_private_replacement_mapping == nullptr || !::VirtualFree(s_private_replacement_mapping, 0, MEM_RELEASE))
        {
            return;
        }
        s_private_replacement_mapping = nullptr;
        HMODULE const module = ::LoadLibraryA(dmk_test::RTTI_FIXTURE_VARIANT_A);
        if (reinterpret_cast<std::uintptr_t>(module) != s_private_replacement_base)
        {
            if (module != nullptr)
            {
                ::FreeLibrary(module);
            }
            return;
        }
        s_private_replacement_restored_module = module;
        s_private_replacement_restored = true;
    }

    class ScopedImageRestoreAfterConfirmedIdentityHook
    {
    public:
        ScopedImageRestoreAfterConfirmedIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook =
                &restore_image_after_confirmed_identity;
        }

        ~ScopedImageRestoreAfterConfirmedIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook = nullptr;
        }

        ScopedImageRestoreAfterConfirmedIdentityHook(const ScopedImageRestoreAfterConfirmedIdentityHook &) = delete;
        ScopedImageRestoreAfterConfirmedIdentityHook &
        operator=(const ScopedImageRestoreAfterConfirmedIdentityHook &) = delete;
    };

    void replace_with_private_image_after_confirmed_identity() noexcept
    {
        DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook = nullptr;
        (void)replace_with_private_image_then_accept(0, nullptr);
    }

    class ScopedPrivateAfterConfirmedIdentityHook
    {
    public:
        ScopedPrivateAfterConfirmedIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook =
                &replace_with_private_image_after_confirmed_identity;
        }

        ~ScopedPrivateAfterConfirmedIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook = nullptr;
        }

        ScopedPrivateAfterConfirmedIdentityHook(const ScopedPrivateAfterConfirmedIdentityHook &) = delete;
        ScopedPrivateAfterConfirmedIdentityHook &operator=(const ScopedPrivateAfterConfirmedIdentityHook &) = delete;
    };

    class ScopedWitnessIdentityMutation;
    ScopedWitnessIdentityMutation *s_witness_identity_mutation = nullptr;

    class ScopedWitnessIdentityMutation
    {
    public:
        explicit ScopedWitnessIdentityMutation(dmk::Region image) noexcept
        {
            auto *const dos = image.base.as<IMAGE_DOS_HEADER *>();
            if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            {
                return;
            }
            auto *const nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(image.base.raw() + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.NumberOfSections == 0)
            {
                return;
            }
            m_characteristics = &IMAGE_FIRST_SECTION(nt)->Characteristics;
            if (!::VirtualProtect(m_characteristics, sizeof(*m_characteristics), PAGE_READWRITE, &m_old_protection))
            {
                m_characteristics = nullptr;
                return;
            }
            m_original_characteristics = *m_characteristics;
            m_original_identity = sc::image_identity(image);
            *m_characteristics = m_original_characteristics ^ IMAGE_SCN_MEM_WRITE;
            m_changed_identity = sc::image_identity(image);
            *m_characteristics = m_original_characteristics;
            s_witness_identity_mutation = this;
        }

        ~ScopedWitnessIdentityMutation() noexcept
        {
            restore();
            if (m_characteristics != nullptr)
            {
                DWORD ignored = 0;
                (void)::VirtualProtect(m_characteristics, sizeof(*m_characteristics), m_old_protection, &ignored);
            }
            if (s_witness_identity_mutation == this)
            {
                s_witness_identity_mutation = nullptr;
            }
        }

        ScopedWitnessIdentityMutation(const ScopedWitnessIdentityMutation &) = delete;
        ScopedWitnessIdentityMutation &operator=(const ScopedWitnessIdentityMutation &) = delete;

        [[nodiscard]] bool ok() const noexcept
        {
            return m_characteristics != nullptr && m_original_identity.present() && m_changed_identity.present() &&
                   m_original_identity != m_changed_identity;
        }
        [[nodiscard]] bool mutated() const noexcept { return m_mutated; }
        [[nodiscard]] bool restored() const noexcept { return m_restored; }
        [[nodiscard]] sc::ImageIdentity original_identity() const noexcept { return m_original_identity; }

        void mutate() noexcept
        {
            if (m_characteristics != nullptr && !m_mutated)
            {
                *m_characteristics = m_original_characteristics ^ IMAGE_SCN_MEM_WRITE;
                m_mutated = true;
                m_restored = false;
            }
        }

        void restore() noexcept
        {
            if (m_characteristics != nullptr && m_mutated && !m_restored)
            {
                *m_characteristics = m_original_characteristics;
                m_restored = true;
            }
        }

    private:
        DWORD *m_characteristics{nullptr};
        DWORD m_original_characteristics{0};
        DWORD m_old_protection{0};
        sc::ImageIdentity m_original_identity{};
        sc::ImageIdentity m_changed_identity{};
        bool m_mutated{false};
        bool m_restored{false};
    };

    bool mutate_identity_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_witness_identity_mutation != nullptr)
        {
            s_witness_identity_mutation->mutate();
        }
        return true;
    }

    void restore_identity_after_witness() noexcept
    {
        DetourModKit::detail::g_anchor_after_witness_test_hook = nullptr;
        if (s_witness_identity_mutation != nullptr)
        {
            s_witness_identity_mutation->restore();
        }
    }

    class ScopedWitnessIdentityRestoreHook
    {
    public:
        ScopedWitnessIdentityRestoreHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_witness_test_hook = &restore_identity_after_witness;
        }

        ~ScopedWitnessIdentityRestoreHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_witness_test_hook = nullptr;
        }

        ScopedWitnessIdentityRestoreHook(const ScopedWitnessIdentityRestoreHook &) = delete;
        ScopedWitnessIdentityRestoreHook &operator=(const ScopedWitnessIdentityRestoreHook &) = delete;
    };
#endif

    void *s_synthetic_image_mapping = nullptr;
    HMODULE s_synthetic_image_module = nullptr;
    std::uintptr_t s_synthetic_image_base = 0;
    bool s_synthetic_image_replacement_happened = false;

    bool replace_synthetic_with_image_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_synthetic_image_mapping == nullptr || s_synthetic_image_replacement_happened)
        {
            return true;
        }
        if (!::VirtualFree(s_synthetic_image_mapping, 0, MEM_RELEASE))
        {
            return true;
        }
        s_synthetic_image_mapping = nullptr;
        HMODULE const module = ::LoadLibraryA(dmk_test::RTTI_FIXTURE_VARIANT_A);
        if (reinterpret_cast<std::uintptr_t>(module) != s_synthetic_image_base)
        {
            if (module != nullptr)
            {
                (void)::FreeLibrary(module);
            }
            return true;
        }
        s_synthetic_image_module = module;
        s_synthetic_image_replacement_happened = true;
        return true;
    }

    class ScopedSyntheticToImageReplacement
    {
    public:
        explicit ScopedSyntheticToImageReplacement(std::uintptr_t base, bool reserved_prefix = false) noexcept
        {
            const std::size_t allocation_size = reserved_prefix ? ScratchPage::PAGE_SIZE * 2 : ScratchPage::PAGE_SIZE;
            const DWORD allocation_type = reserved_prefix ? MEM_RESERVE : MEM_COMMIT | MEM_RESERVE;
            const DWORD protection = reserved_prefix ? PAGE_NOACCESS : PAGE_EXECUTE_READWRITE;
            void *const mapping =
                ::VirtualAlloc(reinterpret_cast<void *>(base), allocation_size, allocation_type, protection);
            if (reinterpret_cast<std::uintptr_t>(mapping) != base)
            {
                if (mapping != nullptr)
                {
                    (void)::VirtualFree(mapping, 0, MEM_RELEASE);
                }
                return;
            }
            if (reserved_prefix)
            {
                void *const committed = ::VirtualAlloc(
                    reinterpret_cast<void *>(base + ScratchPage::PAGE_SIZE),
                    ScratchPage::PAGE_SIZE,
                    MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE
                );
                if (reinterpret_cast<std::uintptr_t>(committed) != base + ScratchPage::PAGE_SIZE)
                {
                    (void)::VirtualFree(mapping, 0, MEM_RELEASE);
                    return;
                }
            }
            s_synthetic_image_mapping = mapping;
            s_synthetic_image_module = nullptr;
            s_synthetic_image_base = base;
            s_synthetic_image_replacement_happened = false;
            m_size = allocation_size;
        }

        ~ScopedSyntheticToImageReplacement() noexcept
        {
            if (s_synthetic_image_module != nullptr)
            {
                (void)::FreeLibrary(s_synthetic_image_module);
                s_synthetic_image_module = nullptr;
            }
            if (s_synthetic_image_mapping != nullptr)
            {
                (void)::VirtualFree(s_synthetic_image_mapping, 0, MEM_RELEASE);
                s_synthetic_image_mapping = nullptr;
            }
            s_synthetic_image_base = 0;
            s_synthetic_image_replacement_happened = false;
            m_size = 0;
        }

        ScopedSyntheticToImageReplacement(const ScopedSyntheticToImageReplacement &) = delete;
        ScopedSyntheticToImageReplacement &operator=(const ScopedSyntheticToImageReplacement &) = delete;

        [[nodiscard]] bool ok() const noexcept { return s_synthetic_image_mapping != nullptr; }
        [[nodiscard]] bool happened() const noexcept { return s_synthetic_image_replacement_happened; }
        [[nodiscard]] std::uintptr_t address(std::size_t offset = 0) const noexcept
        {
            return s_synthetic_image_base + offset;
        }
        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{s_synthetic_image_base}, m_size};
        }
        void put(std::size_t offset, std::span<const std::uint8_t> bytes) noexcept
        {
            std::memcpy(reinterpret_cast<void *>(address(offset)), bytes.data(), bytes.size());
        }

    private:
        std::size_t m_size{0};
    };

    void *s_split_original_mapping = nullptr;
    void *s_split_first_mapping = nullptr;
    void *s_split_second_mapping = nullptr;
    std::uintptr_t s_split_base = 0;
    std::size_t s_split_granularity = 0;
    const std::uint8_t *s_split_marker = nullptr;
    std::size_t s_split_marker_size = 0;
    bool s_split_happened = false;
    constexpr std::size_t SPLIT_MARKER_OFFSET = 0x100;

    bool split_scope_allocation_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_split_original_mapping == nullptr || s_split_happened)
        {
            return true;
        }
        if (!::VirtualFree(s_split_original_mapping, 0, MEM_RELEASE))
        {
            return true;
        }
        s_split_original_mapping = nullptr;
        s_split_first_mapping = ::VirtualAlloc(
            reinterpret_cast<void *>(s_split_base),
            s_split_granularity,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        s_split_second_mapping = ::VirtualAlloc(
            reinterpret_cast<void *>(s_split_base + s_split_granularity),
            s_split_granularity,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (reinterpret_cast<std::uintptr_t>(s_split_first_mapping) != s_split_base ||
            reinterpret_cast<std::uintptr_t>(s_split_second_mapping) != s_split_base + s_split_granularity)
        {
            return true;
        }
        std::memcpy(reinterpret_cast<void *>(s_split_base + SPLIT_MARKER_OFFSET), s_split_marker, s_split_marker_size);
        std::memcpy(
            reinterpret_cast<void *>(s_split_base + s_split_granularity + SPLIT_MARKER_OFFSET),
            s_split_marker,
            s_split_marker_size
        );
        s_split_happened = true;
        return true;
    }

    class ScopedAllocationSplit
    {
    public:
        ScopedAllocationSplit() noexcept
        {
            SYSTEM_INFO system_info{};
            ::GetSystemInfo(&system_info);
            s_split_granularity = system_info.dwAllocationGranularity;
            s_split_original_mapping =
                ::VirtualAlloc(nullptr, s_split_granularity * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            s_split_base = reinterpret_cast<std::uintptr_t>(s_split_original_mapping);
            s_split_first_mapping = nullptr;
            s_split_second_mapping = nullptr;
            s_split_marker = nullptr;
            s_split_marker_size = 0;
            s_split_happened = false;
        }

        ~ScopedAllocationSplit() noexcept
        {
            if (s_split_original_mapping != nullptr)
            {
                (void)::VirtualFree(s_split_original_mapping, 0, MEM_RELEASE);
            }
            if (s_split_first_mapping != nullptr)
            {
                (void)::VirtualFree(s_split_first_mapping, 0, MEM_RELEASE);
            }
            if (s_split_second_mapping != nullptr)
            {
                (void)::VirtualFree(s_split_second_mapping, 0, MEM_RELEASE);
            }
            s_split_original_mapping = nullptr;
            s_split_first_mapping = nullptr;
            s_split_second_mapping = nullptr;
            s_split_base = 0;
            s_split_granularity = 0;
            s_split_marker = nullptr;
            s_split_marker_size = 0;
            s_split_happened = false;
        }

        ScopedAllocationSplit(const ScopedAllocationSplit &) = delete;
        ScopedAllocationSplit &operator=(const ScopedAllocationSplit &) = delete;

        [[nodiscard]] bool ok() const noexcept
        {
            return s_split_original_mapping != nullptr && s_split_granularity != 0;
        }
        [[nodiscard]] bool happened() const noexcept { return s_split_happened; }
        [[nodiscard]] std::uintptr_t address(std::size_t offset = 0) const noexcept { return s_split_base + offset; }
        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{s_split_base}, s_split_granularity * 2};
        }
        void put(std::size_t offset, std::span<const std::uint8_t> bytes) noexcept
        {
            std::memcpy(reinterpret_cast<void *>(address(offset)), bytes.data(), bytes.size());
            s_split_marker = bytes.data();
            s_split_marker_size = bytes.size();
        }
    };

    class ManyRegionScope
    {
    public:
        ManyRegionScope() noexcept
        {
            SYSTEM_INFO system_info{};
            ::GetSystemInfo(&system_info);
            m_page_size = system_info.dwPageSize;
            m_size = m_page_size * REGION_COUNT;
            m_base = static_cast<std::byte *>(
                ::VirtualAlloc(nullptr, m_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            );
            if (m_base == nullptr)
            {
                return;
            }
            for (std::size_t i = 1; i < REGION_COUNT; i += 2)
            {
                DWORD old_protection = 0;
                if (!::VirtualProtect(m_base + i * m_page_size, m_page_size, PAGE_READWRITE, &old_protection))
                {
                    (void)::VirtualFree(m_base, 0, MEM_RELEASE);
                    m_base = nullptr;
                    m_page_size = 0;
                    m_size = 0;
                    return;
                }
            }
        }

        ~ManyRegionScope() noexcept
        {
            if (m_base != nullptr)
            {
                (void)::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        ManyRegionScope(const ManyRegionScope &) = delete;
        ManyRegionScope &operator=(const ManyRegionScope &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::size_t page_size() const noexcept { return m_page_size; }
        [[nodiscard]] std::uintptr_t address(std::size_t offset = 0) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + offset);
        }
        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{reinterpret_cast<std::uintptr_t>(m_base)}, m_size};
        }
        void put(std::size_t offset, std::span<const std::uint8_t> bytes) noexcept
        {
            std::memcpy(m_base + offset, bytes.data(), bytes.size());
        }

    private:
        static constexpr std::size_t REGION_COUNT = 66;

        std::byte *m_base{nullptr};
        std::size_t m_page_size{0};
        std::size_t m_size{0};
    };

    bool accept_any(std::int64_t, const void *) noexcept
    {
        return true;
    }

    // The fixture module's own exported entry point, resolvable by name from an explicit export module.
    constexpr const char *FIXTURE_EXPORT = "dmk_rtti_fixture_vtable";

    [[nodiscard]] an::Anchor fixture_export_anchor() noexcept
    {
        an::Anchor anchor{};
        anchor.label = "fixture.export";
        anchor.kind = an::AnchorKind::ExportName;
        anchor.export_module = dmk_test::RTTI_FIXTURE_VARIANT_A;
        anchor.export_name = FIXTURE_EXPORT;
        return anchor;
    }

    constexpr std::size_t TRANSACTION_MARKER_BYTES = 32;
    constexpr std::size_t TRANSACTION_MARKER_OFFSET = 0x100;
    constexpr std::uintptr_t TRANSACTION_PAGE_GAP = 0x20000;

    class FixedExecutablePage
    {
    public:
        explicit FixedExecutablePage(std::uintptr_t requested) noexcept
        {
            m_base = static_cast<std::uint8_t *>(::VirtualAlloc(
                reinterpret_cast<void *>(requested),
                ScratchPage::PAGE_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            ));
            if (reinterpret_cast<std::uintptr_t>(m_base) != requested)
            {
                if (m_base != nullptr)
                {
                    ::VirtualFree(m_base, 0, MEM_RELEASE);
                }
                m_base = nullptr;
            }
            if (m_base != nullptr)
            {
                std::memset(m_base, 0xCC, ScratchPage::PAGE_SIZE);
            }
        }

        ~FixedExecutablePage() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        FixedExecutablePage(const FixedExecutablePage &) = delete;
        FixedExecutablePage &operator=(const FixedExecutablePage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uintptr_t address(std::size_t offset = 0) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base) + offset;
        }

        void put(std::size_t offset, std::span<const std::uint8_t> bytes) noexcept
        {
            std::memcpy(m_base + offset, bytes.data(), bytes.size());
        }

    private:
        std::uint8_t *m_base{nullptr};
    };

    [[nodiscard]] std::array<std::uint8_t, TRANSACTION_MARKER_BYTES> transaction_marker(std::uintptr_t seed) noexcept
    {
        std::array<std::uint8_t, TRANSACTION_MARKER_BYTES> bytes{};
        std::uint64_t state = static_cast<std::uint64_t>(seed) ^ 0xD4E12C77A51B9F03ULL;
        if (state == 0)
        {
            state = 1;
        }
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes[i] = static_cast<std::uint8_t>(state >> 24);
        }
        return bytes;
    }

    [[nodiscard]] std::string aob_for_bytes(std::span<const std::uint8_t> bytes)
    {
        constexpr char HEX[] = "0123456789ABCDEF";
        std::string dsl;
        dsl.reserve(bytes.size() * 3);
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            if (i != 0)
            {
                dsl.push_back(' ');
            }
            dsl.push_back(HEX[bytes[i] >> 4]);
            dsl.push_back(HEX[bytes[i] & 0x0F]);
        }
        return dsl;
    }

    [[nodiscard]] dmk::Region transaction_scope(const FixedExecutablePage &page, std::uintptr_t target) noexcept
    {
        return dmk::Region{dmk::Address{page.address()}, static_cast<std::size_t>(target - page.address() + 1)};
    }

    [[nodiscard]] std::ptrdiff_t target_delta(std::uintptr_t source, std::uintptr_t target) noexcept
    {
        if (target >= source)
        {
            return static_cast<std::ptrdiff_t>(target - source);
        }
        return -static_cast<std::ptrdiff_t>(source - target);
    }

    class ScopedMissingModuleRange
    {
    public:
        explicit ScopedMissingModuleRange(std::uintptr_t module_base) noexcept
        {
            auto *const dos = reinterpret_cast<IMAGE_DOS_HEADER *>(module_base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            {
                return;
            }
            auto *const nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(module_base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return;
            }
            m_image_size = &nt->OptionalHeader.SizeOfImage;
            if (!::VirtualProtect(m_image_size, sizeof(*m_image_size), PAGE_READWRITE, &m_old_protection))
            {
                m_image_size = nullptr;
                return;
            }
            m_original = *m_image_size;
            *m_image_size = 0;
        }

        ~ScopedMissingModuleRange() noexcept
        {
            if (m_image_size != nullptr)
            {
                *m_image_size = m_original;
                DWORD ignored = 0;
                (void)::VirtualProtect(m_image_size, sizeof(*m_image_size), m_old_protection, &ignored);
            }
        }

        ScopedMissingModuleRange(const ScopedMissingModuleRange &) = delete;
        ScopedMissingModuleRange &operator=(const ScopedMissingModuleRange &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_image_size != nullptr && m_original != 0; }

    private:
        DWORD *m_image_size{nullptr};
        DWORD m_original{0};
        DWORD m_old_protection{0};
    };

    class ScopedMissingImageIdentity
    {
    public:
        explicit ScopedMissingImageIdentity(std::uintptr_t module_base) noexcept
        {
            auto *const dos = reinterpret_cast<IMAGE_DOS_HEADER *>(module_base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            {
                return;
            }
            auto *const nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(module_base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return;
            }
            m_section_count = &nt->FileHeader.NumberOfSections;
            if (!::VirtualProtect(m_section_count, sizeof(*m_section_count), PAGE_READWRITE, &m_old_protection))
            {
                m_section_count = nullptr;
                return;
            }
            m_original = *m_section_count;
            *m_section_count = 0;
        }

        ~ScopedMissingImageIdentity() noexcept
        {
            if (m_section_count != nullptr)
            {
                *m_section_count = m_original;
                DWORD ignored = 0;
                (void)::VirtualProtect(m_section_count, sizeof(*m_section_count), m_old_protection, &ignored);
            }
        }

        ScopedMissingImageIdentity(const ScopedMissingImageIdentity &) = delete;
        ScopedMissingImageIdentity &operator=(const ScopedMissingImageIdentity &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_section_count != nullptr && m_original != 0; }

    private:
        WORD *m_section_count{nullptr};
        WORD m_original{0};
        DWORD m_old_protection{0};
    };
} // anonymous namespace

TEST(AnchorTrustTransactionTest, ImageMappingWithUnreadableExtentFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    const std::uintptr_t target = module.prepare();
    ASSERT_NE(target, 0U) << "variant A could not lay down its RTTI graph";
    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(scope.base.raw(), 0U);
    const std::uintptr_t marker_address = module.table();
    const auto marker = transaction_marker(target ^ marker_address ^ ::GetCurrentProcessId());
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(marker_address),
            marker.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(marker_address), marker.data(), marker.size());
    const sc::Candidate candidates[] = {
        sc::Candidate::direct("missing-module-range", aob(aob_for_bytes(marker)), target_delta(marker_address, target))
    };

    an::Anchor anchor{};
    anchor.label = "fixture.missing.range";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;

    const ScopedMissingModuleRange missing_range(module.base());
    ASSERT_TRUE(missing_range.ok()) << "fixture SizeOfImage could not be made invalid";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(target), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    ASSERT_EQ(memory_info.Type, static_cast<DWORD>(MEM_IMAGE));
    ASSERT_FALSE(sc::image_identity(scope).present()) << "the unreadable-extent premise was not established";

    const an::ResolvedAnchor result = an::resolve(anchor, scope);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ExplicitExportModuleReplacementFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    an::Anchor anchor = fixture_export_anchor();
    anchor.validator = &swap_then_accept;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present()) << "a refused resolve must publish no witness";
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(AnchorTrustTransactionTest, NamedExportReplacementBeforeOwnerCaptureFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    an::ResolvedAnchor result{};
    {
        ScopedNamedExportLookupHook hook;
        result = an::resolve(fixture_export_anchor(), dmk::Region::host());
    }
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "the named image was not replaced before its owner capture";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementBetweenOwnerIdentitySamplesFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);

    const std::uintptr_t instruction_address = swap.module().table();
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(instruction_address),
            instruction.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(instruction_address), instruction.data(), instruction.size());

    const sc::Candidate candidates[] = {sc::Candidate::direct("identity-sample-swap", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "fixture.identity.sample.swap";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;
    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    an::ResolvedAnchor result{};
    {
        ScopedOwnerIdentityHook hook;
        result = an::resolve(anchor, fixture);
    }
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "the image did not move between the two identity samples";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementAfterWitnessConstructionFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);

    an::Anchor anchor = fixture_export_anchor();
    anchor.export_module = {};
    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    an::ResolvedAnchor result{};
    {
        ScopedWitnessHook hook;
        result = an::resolve(anchor, fixture);
    }
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "the image did not move after witness construction";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}
#endif

TEST(AnchorTrustTransactionTest, ModuleBackedEvidenceWithoutAnIdentityFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    const ScopedMissingImageIdentity missing_identity(module.base());
    ASSERT_TRUE(missing_identity.ok()) << "fixture PE header could not be made writable";
    ASSERT_FALSE(sc::image_identity(fixture).present()) << "the identity-failure premise was not established";
    ASSERT_TRUE(sc::resolve_export(FIXTURE_EXPORT, fixture).has_value())
        << "the export backend must still resolve while only the identity section count is invalid";

    const an::ResolvedAnchor result = an::resolve(fixture_export_anchor(), dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ImageReplacementByPrivatePeCopyFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    ASSERT_GE(fixture.size, ScratchPage::PAGE_SIZE);
    const sc::ImageIdentity original_identity = sc::image_identity(fixture);
    ASSERT_TRUE(original_identity.present());
    std::array<std::byte, ScratchPage::PAGE_SIZE> header{};
    std::memcpy(header.data(), reinterpret_cast<const void *>(fixture.base.raw()), header.size());

    an::Anchor anchor = fixture_export_anchor();
    anchor.export_module = {};
    anchor.validator = &replace_with_private_image_then_accept;
    ScopedPrivateImageReplacement replacement(module, fixture, header);
    const an::ResolvedAnchor result = an::resolve(anchor, fixture);

    ASSERT_TRUE(replacement.happened()) << "the loader image was not replaced by a private mapping at the same base";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(fixture.base.raw()), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    EXPECT_EQ(memory_info.Type, static_cast<DWORD>(MEM_PRIVATE));
    EXPECT_EQ(sc::image_identity(dmk::Region{fixture.base, 1}), original_identity)
        << "the private replacement must retain the PE identity that defeated an identity-only recheck";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(AnchorTrustTransactionTest, PrivateReplacementInsideOwnerIdentityBracketFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    ASSERT_GE(fixture.size, ScratchPage::PAGE_SIZE);
    const sc::ImageIdentity original_identity = sc::image_identity(fixture);
    ASSERT_TRUE(original_identity.present());
    std::array<std::byte, ScratchPage::PAGE_SIZE> header{};
    std::memcpy(header.data(), reinterpret_cast<const void *>(fixture.base.raw()), header.size());

    const std::uintptr_t instruction_address = module.table();
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(instruction_address),
            instruction.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(instruction_address), instruction.data(), instruction.size());

    const sc::Candidate candidates[] = {sc::Candidate::direct("private-during-identity", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "fixture.private.identity.bracket";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    ScopedPrivateImageReplacement replacement(module, fixture, header);
    an::ResolvedAnchor result{};
    {
        ScopedPrivateOwnerIdentityHook hook;
        ScopedImageRestoreAfterConfirmedIdentityHook restore_hook;
        result = an::resolve(anchor, fixture);
    }

    ASSERT_TRUE(replacement.happened()) << "the image was not replaced inside the owner-identity bracket";
    EXPECT_FALSE(replacement.restored()) << "the middle mapping check did not stop before the restore seam";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(fixture.base.raw()), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    EXPECT_EQ(memory_info.Type, static_cast<DWORD>(MEM_PRIVATE));
    EXPECT_EQ(sc::image_identity(dmk::Region{fixture.base, 1}), original_identity)
        << "the private clone must remain identity-equal so only the post-read mapping check can reject it";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, PrivateReplacementAfterConfirmedIdentityFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    ASSERT_GE(fixture.size, ScratchPage::PAGE_SIZE);
    const sc::ImageIdentity original_identity = sc::image_identity(fixture);
    ASSERT_TRUE(original_identity.present());
    std::array<std::byte, ScratchPage::PAGE_SIZE> header{};
    std::memcpy(header.data(), reinterpret_cast<const void *>(fixture.base.raw()), header.size());

    const std::uintptr_t instruction_address = module.table();
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(instruction_address),
            instruction.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(instruction_address), instruction.data(), instruction.size());

    const sc::Candidate candidates[] = {
        sc::Candidate::direct("private-after-confirmed-identity", aob("48 05 F0 00 00 00"))
    };
    an::Anchor anchor{};
    anchor.label = "fixture.private.after.confirmed.identity";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    ScopedPrivateImageReplacement replacement(module, fixture, header);
    an::ResolvedAnchor result{};
    {
        ScopedPrivateAfterConfirmedIdentityHook hook;
        result = an::resolve(anchor, fixture);
    }

    ASSERT_TRUE(replacement.happened()) << "the image was not replaced after the confirmed identity sample";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(fixture.base.raw()), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    EXPECT_EQ(memory_info.Type, static_cast<DWORD>(MEM_PRIVATE));
    EXPECT_EQ(sc::image_identity(dmk::Region{fixture.base, 1}), original_identity)
        << "the private clone must remain identity-equal so only the final mapping check can reject it";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, WitnessCopiesCapturedIdentityInsteadOfResampling)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    ScopedWitnessIdentityMutation mutation(fixture);
    ASSERT_TRUE(mutation.ok()) << "changing the section header did not produce a distinct live identity";

    an::Anchor anchor = fixture_export_anchor();
    anchor.export_module = {};
    anchor.validator = &mutate_identity_then_accept;
    an::ResolvedAnchor result{};
    {
        ScopedWitnessIdentityRestoreHook hook;
        result = an::resolve(anchor, fixture);
    }

    ASSERT_TRUE(mutation.mutated()) << "the validator did not change the identity after owner capture";
    ASSERT_TRUE(mutation.restored()) << "the post-witness seam did not restore the accepted identity";
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    ASSERT_TRUE(result.witness.image.present());
    EXPECT_EQ(result.witness.image, mutation.original_identity());
    EXPECT_EQ(sc::image_identity(fixture), mutation.original_identity());
}
#endif

TEST(AnchorTrustTransactionTest, SyntheticReplacementByImageFailsClosed)
{
    std::uintptr_t preferred_base = 0;
    {
        dmk_test::GenerationFixtureModule probe(dmk_test::RTTI_FIXTURE_VARIANT_A);
        ASSERT_TRUE(probe.ok()) << "variant A did not map while discovering its fixed base";
        preferred_base = probe.base();
        probe.release();
    }
    ASSERT_NE(preferred_base, 0U);

    ScopedSyntheticToImageReplacement replacement(preferred_base);
    ASSERT_TRUE(replacement.ok()) << "a synthetic page could not reserve the fixture's fixed base";
    const auto marker = transaction_marker(preferred_base ^ ::GetCurrentProcessId());
    replacement.put(TRANSACTION_MARKER_OFFSET, marker);
    const sc::Candidate candidates[] = {sc::Candidate::direct("synthetic-to-image", aob(aob_for_bytes(marker)))};
    an::Anchor anchor{};
    anchor.label = "fixture.synthetic.to.image";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;
    anchor.validator = &replace_synthetic_with_image_then_accept;

    const an::ResolvedAnchor result = an::resolve(anchor, replacement.range());

    ASSERT_TRUE(replacement.happened()) << "the synthetic mapping was not replaced by the fixture image";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(preferred_base), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    EXPECT_EQ(memory_info.Type, static_cast<DWORD>(MEM_IMAGE));
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReservedPrefixCodeOperandReplacementByImageFailsClosed)
{
    std::uintptr_t preferred_base = 0;
    {
        dmk_test::GenerationFixtureModule probe(dmk_test::RTTI_FIXTURE_VARIANT_A);
        ASSERT_TRUE(probe.ok()) << "variant A did not map while discovering its fixed base";
        preferred_base = probe.base();
        probe.release();
    }
    ASSERT_NE(preferred_base, 0U);

    ScopedSyntheticToImageReplacement replacement(preferred_base, true);
    ASSERT_TRUE(replacement.ok()) << "a reserved-prefix synthetic scope could not claim the fixture's fixed base";
    MEMORY_BASIC_INFORMATION prefix_info{};
    MEMORY_BASIC_INFORMATION code_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(preferred_base), &prefix_info, sizeof(prefix_info)),
        sizeof(prefix_info)
    );
    ASSERT_EQ(
        ::VirtualQuery(
            reinterpret_cast<const void *>(preferred_base + ScratchPage::PAGE_SIZE),
            &code_info,
            sizeof(code_info)
        ),
        sizeof(code_info)
    );
    ASSERT_EQ(prefix_info.State, static_cast<DWORD>(MEM_RESERVE));
    ASSERT_EQ(code_info.State, static_cast<DWORD>(MEM_COMMIT));
    ASSERT_EQ(code_info.Type, static_cast<DWORD>(MEM_PRIVATE));
    ASSERT_EQ(prefix_info.AllocationBase, code_info.AllocationBase);

    constexpr std::size_t code_offset = ScratchPage::PAGE_SIZE + TRANSACTION_MARKER_OFFSET;
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    replacement.put(code_offset, instruction);
    const sc::Candidate candidates[] = {sc::Candidate::direct("reserved-prefix-code", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "fixture.reserved.prefix";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    const an::ResolvedAnchor stable = an::resolve(anchor, replacement.range());
    ASSERT_EQ(stable.status, an::AnchorStatus::Resolved)
        << "a reserved scope with later committed evidence must remain a valid single allocation";
    ASSERT_EQ(stable.value, 0xF0);
    ASSERT_FALSE(stable.witness.image.present());

    anchor.validator = &replace_synthetic_with_image_then_accept;

    const an::ResolvedAnchor result = an::resolve(anchor, replacement.range());

    ASSERT_TRUE(replacement.happened()) << "the reserved-prefix allocation was not replaced by the fixture image";
    MEMORY_BASIC_INFORMATION image_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(preferred_base), &image_info, sizeof(image_info)),
        sizeof(image_info)
    );
    EXPECT_EQ(image_info.Type, static_cast<DWORD>(MEM_IMAGE));
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, SingleAllocationWithMoreThanSixtyFourRegionsResolves)
{
    ManyRegionScope scope;
    ASSERT_TRUE(scope.ok()) << "the alternating-protection allocation could not be created";
    const std::size_t instruction_offset = scope.page_size() * 64 + TRANSACTION_MARKER_OFFSET;
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    scope.put(instruction_offset, instruction);

    const sc::Candidate candidates[] = {sc::Candidate::direct("many-region-code", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "fixture.many.regions";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    const an::ResolvedAnchor result = an::resolve(anchor, scope.range());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
    EXPECT_EQ(result.domain, an::ResultDomain::Scalar);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ScopeSplitIntoMultipleAllocationsInsideValidatorFailsClosed)
{
    ScopedAllocationSplit split;
    ASSERT_TRUE(split.ok()) << "the two-granularity synthetic scope could not be reserved";
    const auto marker = transaction_marker(split.address() ^ ::GetCurrentProcessId());
    split.put(TRANSACTION_MARKER_OFFSET, marker);
    const sc::Candidate candidates[] = {sc::Candidate::direct("split-scope", aob(aob_for_bytes(marker)))};
    an::Anchor anchor{};
    anchor.label = "fixture.scope.split";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;
    anchor.validator = &split_scope_allocation_then_accept;

    const an::ResolvedAnchor result = an::resolve(anchor, split.range());

    ASSERT_TRUE(split.happened()) << "the one-allocation scope was not split during validation";
    MEMORY_BASIC_INFORMATION first_info{};
    MEMORY_BASIC_INFORMATION second_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(split.address()), &first_info, sizeof(first_info)),
        sizeof(first_info)
    );
    ASSERT_EQ(
        ::VirtualQuery(
            reinterpret_cast<const void *>(split.address(s_split_granularity)),
            &second_info,
            sizeof(second_info)
        ),
        sizeof(second_info)
    );
    EXPECT_NE(first_info.AllocationBase, second_info.AllocationBase);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ScopeSplitBetweenQuorumMembersFailsClosed)
{
    ScopedAllocationSplit split;
    ASSERT_TRUE(split.ok()) << "the two-granularity synthetic scope could not be reserved";
    const auto marker = transaction_marker(split.address() ^ ::GetCurrentProcessId());
    split.put(TRANSACTION_MARKER_OFFSET, marker);
    const std::uintptr_t value = split.address(TRANSACTION_MARKER_OFFSET);
    const sc::Candidate candidates[] = {sc::Candidate::direct("split-member", aob(aob_for_bytes(marker)))};

    an::Anchor scanned{};
    scanned.label = "fixture.scope.member";
    scanned.kind = an::AnchorKind::RipGlobal;
    scanned.site = candidates;
    scanned.pages = sc::Pages::Executable;

    an::Anchor replacement{};
    replacement.label = "fixture.scope.split";
    replacement.kind = an::AnchorKind::Manual;
    replacement.manual_value = static_cast<std::int64_t>(value);
    replacement.validate_manual = true;
    replacement.validator = &split_scope_allocation_then_accept;

    const an::Anchor *members[] = {&scanned, &replacement};
    an::Anchor quorum{};
    quorum.label = "fixture.scope.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, split.range());

    ASSERT_TRUE(split.happened()) << "the common scope was not split between the quorum member and publication";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementBetweenQuorumMembersFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    // Pin the corroborating literal to the address the export really has, so the vote agrees and the quorum would
    // commit if the mixed generations went unnoticed.
    const an::ResolvedAnchor probed = an::resolve(fixture_export_anchor(), dmk::Region::host());
    ASSERT_EQ(probed.status, an::AnchorStatus::Resolved);

    const an::Anchor export_member = fixture_export_anchor();
    // The replacement runs while the SECOND member resolves, so the first member's evidence is already a generation
    // behind by the time the quorum commits. A Manual member reads no image, so it cannot refuse on its own.
    an::Anchor pinned{};
    pinned.label = "fixture.pinned";
    pinned.kind = an::AnchorKind::Manual;
    pinned.manual_value = probed.value;
    pinned.validate_manual = true;
    pinned.validator = &swap_then_accept;

    const an::Anchor *members[] = {&export_member, &pinned};
    an::Anchor quorum{};
    quorum.label = "fixture.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementBetweenVtableMembersFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    const std::uintptr_t target = swap.module().vtable();
    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);

    an::Anchor vtable_a{};
    vtable_a.label = "fixture.vtable.a";
    vtable_a.kind = an::AnchorKind::VtableIdentity;
    vtable_a.mangled = dmk_test::RTTI_FIXTURE_TYPE_A;

    an::Anchor replacement{};
    replacement.label = "fixture.swap";
    replacement.kind = an::AnchorKind::Manual;
    replacement.manual_value = static_cast<std::int64_t>(target);
    replacement.validate_manual = true;
    replacement.validator = &swap_then_accept;

    an::Anchor vtable_b{};
    vtable_b.label = "fixture.vtable.b";
    vtable_b.kind = an::AnchorKind::VtableIdentity;
    vtable_b.mangled = dmk_test::RTTI_FIXTURE_TYPE_B;

    const an::Anchor *members[] = {&vtable_a, &replacement, &vtable_b};
    an::Anchor quorum{};
    quorum.label = "fixture.vtable.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(quorum, scope);
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementInsideTheQuorumValidatorFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    const an::ResolvedAnchor probed = an::resolve(fixture_export_anchor(), dmk::Region::host());
    ASSERT_EQ(probed.status, an::AnchorStatus::Resolved);

    const an::Anchor export_member = fixture_export_anchor();
    an::Anchor pinned{};
    pinned.label = "fixture.pinned";
    pinned.kind = an::AnchorKind::Manual;
    pinned.manual_value = probed.value;

    const an::Anchor *members[] = {&export_member, &pinned};
    an::Anchor quorum{};
    quorum.label = "fixture.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    // The quorum validator runs after the vote and inside the commit, the last place a replacement can still slip
    // between the corroborated evidence and the published witness.
    quorum.validator = &swap_then_accept;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, StableQuorumWitnessCarriesTheCapturedOwnerIdentity)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";

    const an::ResolvedAnchor probed = an::resolve(fixture_export_anchor(), dmk::Region::host());
    ASSERT_EQ(probed.status, an::AnchorStatus::Resolved);

    const an::Anchor export_member = fixture_export_anchor();
    an::Anchor pinned{};
    pinned.label = "fixture.pinned";
    pinned.kind = an::AnchorKind::Manual;
    pinned.manual_value = probed.value;

    const an::Anchor *members[] = {&export_member, &pinned};
    an::Anchor quorum{};
    quorum.label = "fixture.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.validator = &accept_any;

    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, probed.value);
    ASSERT_TRUE(result.witness.image.present());
    // The witness copies the address owner's captured identity, which an undisturbed same-module export resolve leaves
    // equal to the module's current identity.
    EXPECT_EQ(result.witness.image, sc::image_identity(dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A)));
    EXPECT_EQ(probed.witness.image, result.witness.image) << "the flat and corroborated paths must agree";
}

TEST(AnchorTrustTransactionTest, StableCrossModuleImageOwnersCanCorroborate)
{
    dmk_test::GenerationFixtureModule target_module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(target_module.ok()) << "variant A did not map";
    ASSERT_NE(target_module.prepare(), 0U) << "variant A could not lay down its RTTI graph";
    ExportFixture evidence_module;
    ASSERT_TRUE(evidence_module.ok()) << "the independent evidence module did not map";

    const dmk::Region evidence_scope = dmk::Region::module_named(ExportFixture::MODULE_NAME);
    const sc::ImageIdentity target_identity =
        sc::image_identity(dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A));
    const sc::ImageIdentity evidence_identity = sc::image_identity(evidence_scope);
    ASSERT_TRUE(target_identity.present());
    ASSERT_TRUE(evidence_identity.present());
    ASSERT_NE(target_identity, evidence_identity);

    const an::Anchor export_member = fixture_export_anchor();
    const an::ResolvedAnchor export_result = an::resolve(export_member, evidence_scope);
    ASSERT_EQ(export_result.status, an::AnchorStatus::Resolved);
    const std::uintptr_t target = static_cast<std::uintptr_t>(export_result.value);

    const std::uintptr_t instruction_address = evidence_module.proc("dmk_scan_marker");
    ASSERT_NE(instruction_address, 0U);
    std::array<std::uint8_t, 16> original_bytes{};
    std::memcpy(original_bytes.data(), reinterpret_cast<const void *>(instruction_address), original_bytes.size());
    std::array<std::uint8_t, 10> instruction{0x48, 0xB8};
    std::memcpy(instruction.data() + 2, &target, sizeof(target));
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(instruction_address),
            original_bytes.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(instruction_address), instruction.data(), instruction.size());

    const sc::Candidate candidates[] = {sc::Candidate::direct("cross-module-operand", aob(aob_for_bytes(instruction)))};
    an::Anchor operand_member{};
    operand_member.label = "fixture.cross.module.operand";
    operand_member.kind = an::AnchorKind::CodeOperand;
    operand_member.site = candidates;
    operand_member.operand_kind = sc::OperandKind::Immediate;
    operand_member.operand_index = 1;

    const an::ResolvedAnchor operand_result = an::resolve(operand_member, evidence_scope);
    const an::Anchor *members[] = {&export_member, &operand_member};
    an::Anchor quorum{};
    quorum.label = "fixture.cross.module.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    const an::ResolvedAnchor result = an::resolve(quorum, evidence_scope);

    std::memcpy(reinterpret_cast<void *>(instruction_address), original_bytes.data(), original_bytes.size());
    DWORD ignored = 0;
    ASSERT_TRUE(
        ::VirtualProtect(reinterpret_cast<void *>(instruction_address), original_bytes.size(), old_protection, &ignored)
    );

    ASSERT_EQ(operand_result.status, an::AnchorStatus::Resolved);
    ASSERT_EQ(static_cast<std::uintptr_t>(operand_result.value), target);
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), target);
    EXPECT_EQ(result.domain, an::ResultDomain::CodeSite);
    EXPECT_EQ(result.witness.image, target_identity);
}

TEST(AnchorTrustTransactionTest, WideExecutableScopeAcrossAllocationsFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    const std::uintptr_t target = module.prepare();
    ASSERT_NE(target, 0U) << "variant A could not lay down its RTTI graph";
    ASSERT_GT(module.base(), TRANSACTION_PAGE_GAP);

    FixedExecutablePage page(module.base() - TRANSACTION_PAGE_GAP);
    ASSERT_TRUE(page.ok()) << "the fixed transaction page could not be reserved";
    const auto marker = transaction_marker(target ^ page.address() ^ ::GetCurrentProcessId());
    page.put(TRANSACTION_MARKER_OFFSET, marker);
    const std::uintptr_t marker_address = page.address(TRANSACTION_MARKER_OFFSET);
    const sc::Candidate candidates[] = {
        sc::Candidate::direct("wide-scope-target", aob(aob_for_bytes(marker)), target_delta(marker_address, target))
    };

    an::Anchor anchor{};
    anchor.label = "fixture.wide.target";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;

    const an::ResolvedAnchor result = an::resolve(anchor, transaction_scope(page, target));
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(AnchorTrustTransactionTest, ReplacementDuringDiscoveryAfterScopeOwnerCaptureFailsClosed)
{
    std::array<std::uint8_t, TRANSACTION_MARKER_BYTES> shared_header{};
    std::uintptr_t fixture_base = 0;
    {
        dmk_test::GenerationFixtureModule variant_a(dmk_test::RTTI_FIXTURE_VARIANT_A);
        ASSERT_TRUE(variant_a.ok()) << "variant A did not map while sampling its shared header";
        fixture_base = variant_a.base();
        std::memcpy(shared_header.data(), reinterpret_cast<const void *>(fixture_base), shared_header.size());
    }
    {
        dmk_test::GenerationFixtureModule variant_b(dmk_test::RTTI_FIXTURE_VARIANT_B);
        ASSERT_TRUE(variant_b.ok()) << "variant B did not map while checking its shared header";
        ASSERT_EQ(variant_b.base(), fixture_base);
        ASSERT_EQ(
            std::memcmp(shared_header.data(), reinterpret_cast<const void *>(fixture_base), shared_header.size()),
            0
        ) << "the discovery replacement needs byte-identical evidence in both images";
    }

    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    ASSERT_EQ(swap.base(), fixture_base);
    const sc::Candidate candidates[] = {sc::Candidate::direct("shared-header", aob(aob_for_bytes(shared_header)))};
    an::Anchor anchor{};
    anchor.label = "fixture.discovery.owner";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Readable;
    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    an::ResolvedAnchor result{};
    {
        ScopedDiscoverySweepHook hook;
        result = an::resolve(anchor, scope);
    }
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not replace A after the discovery sweep";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

#endif

TEST(AnchorTrustTransactionTest, TemporalDriftOverridesPhysicalDependenceStatus)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    const std::uintptr_t target = swap.module().vtable();
    const std::uintptr_t marker_address = swap.module().table();
    const auto marker = transaction_marker(target ^ marker_address ^ ::GetCurrentProcessId());
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(marker_address),
            marker.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(marker_address), marker.data(), marker.size());

    const sc::Candidate full_candidates[] = {
        sc::Candidate::direct("module-full", aob(aob_for_bytes(marker)), target_delta(marker_address, target))
    };
    constexpr std::size_t suffix_offset = 8;
    const std::span<const std::uint8_t> suffix{marker.data() + suffix_offset, marker.size() - suffix_offset};
    const sc::Candidate suffix_candidates[] = {sc::Candidate::direct(
        "module-suffix",
        aob(aob_for_bytes(suffix)),
        target_delta(marker_address + suffix_offset, target)
    )};

    an::Anchor full{};
    full.label = "fixture.module.full";
    full.kind = an::AnchorKind::RipGlobal;
    full.site = full_candidates;
    full.pages = sc::Pages::Executable;

    an::Anchor suffix_anchor{};
    suffix_anchor.label = "fixture.module.suffix";
    suffix_anchor.kind = an::AnchorKind::RipGlobal;
    suffix_anchor.site = suffix_candidates;
    suffix_anchor.pages = sc::Pages::Executable;

    an::Anchor replacement{};
    replacement.label = "fixture.swap";
    replacement.kind = an::AnchorKind::Manual;
    replacement.manual_value = static_cast<std::int64_t>(target);
    replacement.validate_manual = true;
    replacement.validator = &swap_then_accept;

    const an::Anchor *members[] = {&full, &suffix_anchor, &replacement};
    an::Anchor quorum{};
    quorum.label = "fixture.physical.drift";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A));
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed)
        << "temporal drift must override the otherwise valid QuorumNotIndependent diagnosis";
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, IdentitylessAddressScopeResolvesWithoutAnImage)
{
    // A synthetic scope belongs to no mapped image, so there is no identity to capture and none to invalidate. Those
    // resolves must stay exactly as they were rather than failing closed for want of a key.
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0xD1, 0x4A, 0x77, 0x0B, 0xC3, 0x95, 0xE2, 0x68});

    const sc::Candidate candidates[] = {sc::Candidate::direct("synthetic-address", aob("D1 4A 77 0B C3 95 E2 68"))};
    an::Anchor anchor{};
    anchor.label = "synthetic.address";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, static_cast<std::int64_t>(page.addr(0x100)));
    EXPECT_FALSE(result.witness.image.present());
}

// A scope-evidence kind reads its evidence out of the image being scanned rather than out of an explicitly named
// export module, so it captures its key on a different branch than the export cases above. Without a case that
// resolves through that branch, dropping it would leave every other case here still passing.
TEST(AnchorTrustTransactionTest, StableScopeEvidenceCarriesTheScopeImageIdentity)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(scope.base.raw(), 0U);

    an::Anchor anchor{};
    anchor.label = "fixture.vtable";
    anchor.kind = an::AnchorKind::VtableIdentity;
    anchor.mangled = dmk_test::RTTI_FIXTURE_TYPE_A;

    const an::ResolvedAnchor result = an::resolve(anchor, scope);
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, static_cast<std::int64_t>(module.vtable()));
    ASSERT_TRUE(result.witness.image.present());
    EXPECT_EQ(result.witness.image, sc::image_identity(scope));
}

TEST(AnchorTrustTransactionTest, ScopeEvidenceModuleReplacementFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(scope.base.raw(), 0U);

    an::Anchor anchor{};
    anchor.label = "fixture.vtable";
    anchor.kind = an::AnchorKind::VtableIdentity;
    anchor.mangled = dmk_test::RTTI_FIXTURE_TYPE_A;
    anchor.validator = &swap_then_accept;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(anchor, scope);
    s_anchor_swap = nullptr;

    // The validator runs only once the scan has already found the vtable, so this also asserts the resolve reached
    // its commit rather than failing for want of a match.
    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

// [B-100] anchor boundary. The Callback-safe trust and quality queries answer under the loader lock with no heap
// traffic, so a startup gate decision stays available there. Resolution can allocate, scan memory, or create threads.
TEST(AnchorLoaderBoundary, TrustAndQualityQueriesAreAllocationFree)
{
    const std::array<an::ResolvedAnchor, 3> report{
        ra(an::AnchorKind::StringXref, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::RipGlobal, an::AnchorStatus::Resolved),
        ra(an::AnchorKind::ExportName, an::AnchorStatus::Failed)
    };

    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = "kernel32.dll";
    anchor.export_name = "Sleep";

    const sc::ImageIdentity identity = sc::image_identity();
    ASSERT_TRUE(identity.present());

    // Warm every route so a first-call cost is not charged to the measured window.
    (void)an::assess_quality(report);
    (void)an::anchor_fingerprint(anchor);
    (void)an::anchor_trust_fingerprint(anchor, identity);

    an::AnchorQuality quality{};
    an::GateVerdict verdict = an::GateVerdict::Pass;
    std::uint64_t fingerprint = 0;
    std::uint64_t trust_key = 0;
    long long allocations = -1;
    long long allocation_probe_delta = -1;
    std::unique_ptr<int[]> allocation_probe;

    {
        const dmk_test::ForcedLoaderProbe held;

        const long long before = dmk_test::thread_new_calls();
        quality = an::assess_quality(report);
        verdict = an::evaluate_gate(quality);
        fingerprint = an::anchor_fingerprint(anchor);
        trust_key = an::anchor_trust_fingerprint(anchor, identity);
        allocations = dmk_test::thread_new_calls() - before;

        const long long before_probe = dmk_test::thread_new_calls();
        allocation_probe = std::make_unique<int[]>(64);
        allocation_probe_delta = dmk_test::thread_new_calls() - before_probe;
    }

    EXPECT_EQ(allocations, 0LL) << "the Callback-safe anchor surface must stay heap-free under the loader lock";
    EXPECT_EQ(quality.total, static_cast<std::size_t>(3));
    EXPECT_EQ(quality.failed, static_cast<std::size_t>(1));
    EXPECT_EQ(verdict, an::GateVerdict::Fail) << "one failed anchor still fails the default policy under the lock";
    EXPECT_NE(fingerprint, 0U);
    EXPECT_NE(trust_key, 0U);
    ASSERT_NE(allocation_probe, nullptr);
    EXPECT_GT(allocation_probe_delta, 0LL) << "the permanent counter control must detect a real allocation";
}
