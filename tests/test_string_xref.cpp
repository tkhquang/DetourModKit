#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <stop_token>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "DetourModKit/scan.hpp"

using namespace DetourModKit;

namespace
{
    struct VirtualFreeDeleter
    {
        void operator()(std::uint8_t *ptr) const noexcept
        {
            if (ptr != nullptr)
            {
                VirtualFree(ptr, 0, MEM_RELEASE);
            }
        }
    };

    using VirtualPagePtr = std::unique_ptr<std::uint8_t, VirtualFreeDeleter>;

    // A committed RWX page used as a synthetic module image. find_string_xref scans readable pages for the string
    // (phase 1) and execute-readable pages for the reference (phase 2); PAGE_EXECUTE_READWRITE satisfies both masks, so
    // a single page hosts the whole fixture and the Region spans exactly it. The page is zero-filled by
    // VirtualAlloc, so an unwritten byte is 0x00, which both terminates a planted string and never starts a
    // RIP-relative load.
    class SyntheticImage
    {
    public:
        SyntheticImage()
        {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            m_size = si.dwPageSize;
            m_base = static_cast<std::uint8_t *>(
                VirtualAlloc(nullptr, m_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        }

        ~SyntheticImage()
        {
            if (m_base)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        SyntheticImage(const SyntheticImage &) = delete;
        SyntheticImage &operator=(const SyntheticImage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uintptr_t addr(std::size_t off) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + off);
        }

        void write(std::size_t off, const void *data, std::size_t n) noexcept { std::memcpy(m_base + off, data, n); }

        // Plants `<rex> <opcode> <modrm> <disp32>` (a RIP-relative lea/mov) at instr_off whose computed target is
        // target_off. modrm 0x05 is the
        // RIP-relative form with rax as the destination register.
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

        // Plants `<rex> 89 <modrm=00 reg rm=101> <disp32>` (mov [rip+slot], reg), the store mirror of plant_rip_load,
        // at instr_off whose slot effective address is slot_off. `reg` is the x86-64 source register number (0..15);
        // for 0..7 REX is 0x48, for 8..15 REX.R is set so the (REX.R << 3 | ModRM.reg) source reconstruction is pinned.
        void plant_rip_store(std::size_t instr_off, std::size_t slot_off, std::uint8_t reg) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            p[0] = static_cast<std::uint8_t>(0x48 | (((reg >> 3) & 0x01) << 2)); // REX.W (+REX.R for r8..r15)
            p[1] = 0x89;                                                         // mov r/m, r
            p[2] = static_cast<std::uint8_t>(0x05 | ((reg & 0x07) << 3)); // mod=00, reg=src, rm=101 (RIP-relative)
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 7);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(addr(slot_off)) - next);
            std::memcpy(p + 3, &disp, sizeof(disp));
        }

        [[nodiscard]] Region range() const noexcept
        {
            return Region{Address{reinterpret_cast<std::uintptr_t>(m_base)}, m_size};
        }

    private:
        std::uint8_t *m_base = nullptr;
        std::size_t m_size = 0;
    };

    // A two-page synthetic image mirroring a real PE's split protections: page 0 is execute-readable (the .text
    // analogue swept in phase 2) and page 1 is readable data (the .rdata analogue located in phase 1). Reserving both
    // pages in one
    // VirtualAlloc keeps them contiguous so a single Region spans them, and the distinct protections keep the
    // planted string out of the executable sweep -- exactly as production strings in .rdata are never decoded as code.
    // This is the fixture the broad (Zydis) phase-2 tests use so the decoder only ever walks the code page, never the
    // string bytes.
    class SplitImage
    {
    public:
        SplitImage()
        {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            m_page = si.dwPageSize;
            m_base = static_cast<std::uint8_t *>(VirtualAlloc(nullptr, m_page * 2, MEM_RESERVE, PAGE_NOACCESS));
            if (m_base)
            {
                // Code page must be writable here so the test can plant instruction bytes; PAGE_EXECUTE_READWRITE still
                // satisfies the executable sweep.
                void *code = VirtualAlloc(m_base, m_page, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                void *data = VirtualAlloc(m_base + m_page, m_page, MEM_COMMIT, PAGE_READWRITE);
                if (code == nullptr || data == nullptr)
                {
                    VirtualFree(m_base, 0, MEM_RELEASE);
                    m_base = nullptr;
                }
            }
        }

        ~SplitImage()
        {
            if (m_base)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        SplitImage(const SplitImage &) = delete;
        SplitImage &operator=(const SplitImage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uintptr_t code_addr(std::size_t off) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + off);
        }

        [[nodiscard]] std::uintptr_t data_addr(std::size_t off) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + m_page + off);
        }

        [[nodiscard]] std::size_t page_size() const noexcept { return m_page; }

        // Writes raw bytes into the executable code page (page 0). Used to plant a byte the decoder rejects, exercising
        // the broad sweep's byte-restart recovery, which plant_code_rip_insn (which only plants well-formed
        // instructions) cannot reach.
        void write_code(std::size_t off, const void *data, std::size_t n) noexcept
        {
            std::memcpy(m_base + off, data, n);
        }

        void write_data(std::size_t off, const void *data, std::size_t n) noexcept
        {
            std::memcpy(m_base + m_page + off, data, n);
        }

        // Plants an instruction in the code page whose RIP-relative memory operand resolves to data offset target_off.
        // `head` is the bytes preceding the disp32 (prefixes, opcode, ModRM); `total_len` is the full instruction
        // length so the next-instruction anchor the disp is measured from is correct; `tail` is any bytes after the
        // disp32 (e.g. an immediate). This drives phase-2 shapes the narrow scan does not model.
        void plant_code_rip_insn(std::size_t instr_off, std::size_t target_off,
                                 std::initializer_list<std::uint8_t> head, std::size_t total_len,
                                 std::initializer_list<std::uint8_t> tail = {}) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            std::size_t i = 0;
            for (const std::uint8_t b : head)
            {
                p[i++] = b;
            }
            const std::size_t disp_off = i;
            const auto next = static_cast<std::int64_t>(code_addr(instr_off) + total_len);
            const auto data_target =
                static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(m_base + m_page + target_off));
            const auto disp = static_cast<std::int32_t>(data_target - next);
            std::memcpy(p + disp_off, &disp, sizeof(disp));
            std::size_t j = disp_off + sizeof(disp);
            for (const std::uint8_t b : tail)
            {
                p[j++] = b;
            }
        }

        [[nodiscard]] Region range() const noexcept
        {
            return Region{Address{reinterpret_cast<std::uintptr_t>(m_base)}, m_page * 2};
        }

    private:
        std::uint8_t *m_base = nullptr;
        std::size_t m_page = 0;
    };

    // A four-page synthetic image whose executable region is split in two by a non-executable interior page: page 0 and
    // page 2 are execute-readable code windows, page 1 is an uncommitted (reserved) gap that VirtualQuery reports as
    // MEM_RESERVE so collect_executable_windows skips it, and page 3 is the readable data page holding the string. This
    // is the only fixture that makes collect_executable_windows return more than one window, so it exercises the
    // cross-window accumulation in both phase-2 scans (a reference living only in the second window must still resolve;
    // one reference in each window must still report AmbiguousReference). Real PE .text is one contiguous window, so
    // this is defensive-path coverage rather than a production layout.
    class GappedCodeImage
    {
    public:
        GappedCodeImage()
        {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            m_page = si.dwPageSize;
            m_base = static_cast<std::uint8_t *>(VirtualAlloc(nullptr, m_page * 4, MEM_RESERVE, PAGE_NOACCESS));
            if (m_base)
            {
                // Commit pages 0, 2, and 3; page 1 stays reserved as the gap that splits the executable region into two
                // windows.
                void *code0 = VirtualAlloc(m_base, m_page, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                void *code1 = VirtualAlloc(m_base + m_page * 2, m_page, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                void *data = VirtualAlloc(m_base + m_page * 3, m_page, MEM_COMMIT, PAGE_READWRITE);
                if (code0 == nullptr || code1 == nullptr || data == nullptr)
                {
                    VirtualFree(m_base, 0, MEM_RELEASE);
                    m_base = nullptr;
                }
            }
        }

        ~GappedCodeImage()
        {
            if (m_base)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        GappedCodeImage(const GappedCodeImage &) = delete;
        GappedCodeImage &operator=(const GappedCodeImage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uintptr_t window1_addr(std::size_t off) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + m_page * 2 + off);
        }

        void write_string(std::size_t off, const void *data, std::size_t n) noexcept
        {
            std::memcpy(m_base + m_page * 3 + off, data, n);
        }

        // Plants a REX.W lea rax, [rip+disp32] in window 0 (page 0) whose target is the string at data offset
        // target_off.
        void plant_lea_window0(std::size_t off, std::size_t target_off) noexcept
        {
            std::uint8_t *instr = m_base + off;
            plant_lea(instr, reinterpret_cast<std::uintptr_t>(instr), target_off);
        }

        // Plants the same lea in window 1 (page 2), past the gap.
        void plant_lea_window1(std::size_t off, std::size_t target_off) noexcept
        {
            std::uint8_t *instr = m_base + m_page * 2 + off;
            plant_lea(instr, reinterpret_cast<std::uintptr_t>(instr), target_off);
        }

        [[nodiscard]] Region range() const noexcept
        {
            return Region{Address{reinterpret_cast<std::uintptr_t>(m_base)}, m_page * 4};
        }

    private:
        void plant_lea(std::uint8_t *instr, std::uintptr_t instr_addr, std::size_t target_off) noexcept
        {
            instr[0] = 0x48; // REX.W
            instr[1] = 0x8D; // lea
            instr[2] = 0x05; // ModRM: mod=00, reg=rax, rm=101 (RIP-relative)
            const auto next = static_cast<std::int64_t>(instr_addr + 7);
            const auto target =
                static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(m_base + m_page * 3 + target_off));
            const auto disp = static_cast<std::int32_t>(target - next);
            std::memcpy(instr + 3, &disp, sizeof(disp));
        }

        std::uint8_t *m_base = nullptr;
        std::size_t m_page = 0;
    };

    constexpr std::uint8_t LEA = 0x8D;
    constexpr std::uint8_t MOV = 0x8B;

    scan::StringRefQuery utf8_query(std::string_view text)
    {
        scan::StringRefQuery q{};
        q.text = text;
        q.encoding = scan::StringEncoding::Utf8;
        q.require_terminator = true;
        q.return_mode = scan::XrefReturn::ReferencingInstruction;
        return q;
    }

    scan::StringRefQuery broad_query(std::string_view text)
    {
        scan::StringRefQuery q = utf8_query(text);
        q.broad_match = true;
        return q;
    }

    scan::StringRefQuery slot_query(std::string_view text)
    {
        scan::StringRefQuery q = utf8_query(text);
        q.return_mode = scan::XrefReturn::StringPointerSlot;
        return q;
    }
} // namespace

TEST(StringXrefTest, ResolvesUniqueLeaReference)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "AnchorStringAlpha";
    img.write(0x100, str, sizeof(str));
    img.plant_rip_load(0x10, 0x100, LEA);

    const auto result = scan::find_string_xref(utf8_query("AnchorStringAlpha"), img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), img.addr(0x10));
}

TEST(StringXrefTest, ResolvesUniqueMovReference)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "AnchorStringBeta";
    img.write(0x140, str, sizeof(str));
    img.plant_rip_load(0x20, 0x140, MOV);

    const auto result = scan::find_string_xref(utf8_query("AnchorStringBeta"), img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), img.addr(0x20));
}

TEST(StringXrefTest, StringNotFound)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "PresentString";
    img.write(0x100, str, sizeof(str));

    const auto result = scan::find_string_xref(utf8_query("AbsentString"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StringNotFound);
}

TEST(StringXrefTest, StringAmbiguous)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "DuplicatedAnchor";
    img.write(0x100, str, sizeof(str));
    img.write(0x140, str, sizeof(str)); // second occurrence makes it ambiguous

    const auto result = scan::find_string_xref(utf8_query("DuplicatedAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StringAmbiguous);
}

TEST(StringXrefTest, NoReference)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "UnreferencedAnchor";
    img.write(0x100, str, sizeof(str)); // string present, no instruction loads it

    const auto result = scan::find_string_xref(utf8_query("UnreferencedAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::NoReference);
}

TEST(StringXrefTest, AmbiguousReference)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "TwiceReferenced";
    img.write(0x180, str, sizeof(str));
    img.plant_rip_load(0x10, 0x180, LEA);
    img.plant_rip_load(0x30, 0x180, LEA); // second reference to the same string

    const auto result = scan::find_string_xref(utf8_query("TwiceReferenced"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::AmbiguousReference);
}

TEST(StringXrefTest, TerminatorPreventsPrefixMatch)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "PlayerController";
    img.write(0x100, str, sizeof(str));
    img.plant_rip_load(0x10, 0x100, LEA);

    // "Player" with a required terminator must not match inside "PlayerController".
    const auto result = scan::find_string_xref(utf8_query("Player"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StringNotFound);

    // Without the terminator it matches the prefix and resolves the reference.
    scan::StringRefQuery loose = utf8_query("Player");
    loose.require_terminator = false;
    const auto loose_result = scan::find_string_xref(loose, img.range());
    ASSERT_TRUE(loose_result.has_value());
    EXPECT_EQ(loose_result->raw(), img.addr(0x10));
}

TEST(StringXrefTest, Utf16Reference)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const wchar_t wstr[] = L"QuitGame";
    img.write(0x100, wstr, sizeof(wstr)); // UTF-16LE bytes incl the wide NUL
    img.plant_rip_load(0x10, 0x100, LEA);

    scan::StringRefQuery q{};
    q.text = "QuitGame";
    q.encoding = scan::StringEncoding::Utf16le;
    q.require_terminator = true;
    const auto result = scan::find_string_xref(q, img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), img.addr(0x10));
}

TEST(StringXrefTest, EnclosingFunctionReturnsPrologue)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    // INT3 padding, then a recognizable prologue, then the referencing lea. The back-scan from the lea must cross the
    // lea-to-prologue gap (no 0xCC/0xC3), hit the 0xCC pad boundary, and return the prologue start.
    const std::uint8_t pad[] = {0xCC, 0xCC, 0xCC, 0xCC};
    img.write(0x40, pad, sizeof(pad));
    const std::uint8_t prologue[] = {0x55, 0x48, 0x8B, 0xEC}; // push rbp; mov rbp, rsp
    img.write(0x44, prologue, sizeof(prologue));
    const char str[] = "FunctionAnchor";
    img.write(0x100, str, sizeof(str));
    img.plant_rip_load(0x60, 0x100, LEA); // lea sits inside the function body

    scan::StringRefQuery q = utf8_query("FunctionAnchor");
    q.return_mode = scan::XrefReturn::EnclosingFunction;
    const auto result = scan::find_string_xref(q, img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), img.addr(0x44));
}

TEST(StringXrefTest, EnclosingFunctionNotFound)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    // No 0xCC/0xC3 boundary precedes the lea (the page is zero-filled), so the back-scan finds no function entry and
    // the resolve fails closed.
    const char str[] = "NoBoundaryAnchor";
    img.write(0x100, str, sizeof(str));
    img.plant_rip_load(0x10, 0x100, LEA);

    scan::StringRefQuery q = utf8_query("NoBoundaryAnchor");
    q.return_mode = scan::XrefReturn::EnclosingFunction;
    const auto result = scan::find_string_xref(q, img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::FunctionNotFound);
}

TEST(StringXrefTest, EnclosingFunctionBackScanCrossesPageBoundary)
{
    // The referencing lea sits in page 1 while the function boundary is near the start of page 0, so the back-scan
    // window spans more than one page and the buffered read must cover both pages (two page-aligned chunks) to reach
    // the 0xCC boundary. Pins that the page-wise back-scan finds a boundary in a lower chunk, not just within the
    // chunk containing the instruction.
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;
    auto *base =
        static_cast<std::uint8_t *>(VirtualAlloc(nullptr, page * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (base == nullptr)
    {
        GTEST_SKIP() << "could not allocate a two-page synthetic image";
    }

    const auto plant_lea = [base](std::size_t instr_off, std::size_t target_off)
    {
        std::uint8_t *p = base + instr_off;
        p[0] = 0x48; // REX.W
        p[1] = LEA;
        p[2] = 0x05; // ModRM: RIP-relative, reg = rax
        const auto next = reinterpret_cast<std::int64_t>(base + instr_off + 7);
        const auto target = reinterpret_cast<std::int64_t>(base + target_off);
        const auto disp = static_cast<std::int32_t>(target - next);
        std::memcpy(p + 3, &disp, sizeof(disp));
    };

    const std::uint8_t pad[] = {0xCC, 0xCC, 0xCC, 0xCC};
    std::memcpy(base + 0x40, pad, sizeof(pad)); // boundary near the start of page 0
    const std::uint8_t prologue[] = {0x55, 0x48, 0x8B, 0xEC};
    std::memcpy(base + 0x44, prologue, sizeof(prologue));
    const char str[] = "CrossPageAnchor";
    std::memcpy(base + 0x800, str, sizeof(str));
    plant_lea(page + 0x100, 0x800); // lea in page 1 references the page-0 string

    scan::StringRefQuery q = utf8_query("CrossPageAnchor");
    q.return_mode = scan::XrefReturn::EnclosingFunction;
    const Region range{Address{reinterpret_cast<std::uintptr_t>(base)}, page * 2};
    const auto result = scan::find_string_xref(q, range);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), reinterpret_cast<std::uintptr_t>(base) + 0x44);

    VirtualFree(base, 0, MEM_RELEASE);
}

TEST(StringXrefTest, EnclosingFunctionBackScanSkipsUnmappedLowerPage)
{
    // The back-scan window from the lea in page 2 reaches down into the reserved (unmapped) page 0, but the boundary
    // lives in the readable page 1 above it. A correct page-aligned back-scan finds the boundary without faulting the
    // whole read on the unmapped page below it; a chunk that straddled the readable/unmapped page boundary would
    // discard the readable page-1 bytes and wrongly report no function (the per-byte walk never faults here because it
    // finds the boundary before walking down into the gap).
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;
    auto *base = static_cast<std::uint8_t *>(VirtualAlloc(nullptr, page * 3, MEM_RESERVE, PAGE_NOACCESS));
    if (base == nullptr)
    {
        GTEST_SKIP() << "could not reserve a three-page region";
    }
    // Leave page 0 reserved (unmapped); commit pages 1 and 2 as execute-readable.
    void *p1 = VirtualAlloc(base + page, page, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    void *p2 = VirtualAlloc(base + page * 2, page, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (p1 == nullptr || p2 == nullptr)
    {
        VirtualFree(base, 0, MEM_RELEASE);
        GTEST_SKIP() << "could not commit the executable pages";
    }

    const auto plant_lea = [base](std::size_t instr_off, std::size_t target_off)
    {
        std::uint8_t *p = base + instr_off;
        p[0] = 0x48; // REX.W
        p[1] = LEA;
        p[2] = 0x05; // ModRM: RIP-relative, reg = rax
        const auto next = reinterpret_cast<std::int64_t>(base + instr_off + 7);
        const auto target = reinterpret_cast<std::int64_t>(base + target_off);
        const auto disp = static_cast<std::int32_t>(target - next);
        std::memcpy(p + 3, &disp, sizeof(disp));
    };

    const std::uint8_t pad[] = {0xCC, 0xCC, 0xCC, 0xCC};
    std::memcpy(base + page + 0x40, pad, sizeof(pad)); // boundary in the readable page 1
    const std::uint8_t prologue[] = {0x55, 0x48, 0x8B, 0xEC};
    std::memcpy(base + page + 0x44, prologue, sizeof(prologue));
    const char str[] = "SkipGapAnchor";
    std::memcpy(base + page + 0x800, str, sizeof(str));
    plant_lea(page * 2 + 0x100, page + 0x800); // lea in page 2 references the page-1 string

    scan::StringRefQuery q = utf8_query("SkipGapAnchor");
    q.return_mode = scan::XrefReturn::EnclosingFunction;
    const Region range{Address{reinterpret_cast<std::uintptr_t>(base)}, page * 3};
    const auto result = scan::find_string_xref(q, range);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), reinterpret_cast<std::uintptr_t>(base) + page + 0x44);

    VirtualFree(base, 0, MEM_RELEASE);
}

TEST(StringXrefTest, EmptyQueryAndInvalidRange)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const auto empty = scan::find_string_xref(utf8_query(""), img.range());
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(empty.error().code, ErrorCode::EmptyQuery);

    const auto bad_range = scan::find_string_xref(utf8_query("Anything"), Region{});
    ASSERT_FALSE(bad_range.has_value());
    EXPECT_EQ(bad_range.error().code, ErrorCode::InvalidRange);
}

TEST(StringXrefTest, BroadMatchResolvesCmpReference)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    const char str[] = "BroadCmpAnchorString";
    img.write_data(0x40, str, sizeof(str));
    // cmp dword ptr [rip+disp], 0x01  ->  83 3D <disp32> 01  (7 bytes)
    img.plant_code_rip_insn(0x10, 0x40, {0x83, 0x3D}, 7, {0x01});

    // The narrow scan models only lea/mov, so the cmp is invisible to it.
    const auto narrow = scan::find_string_xref(utf8_query("BroadCmpAnchorString"), img.range());
    ASSERT_FALSE(narrow.has_value());
    EXPECT_EQ(narrow.error().code, ErrorCode::NoReference);

    // The broad sweep decodes the cmp and resolves its RIP operand to the string.
    const auto broad = scan::find_string_xref(broad_query("BroadCmpAnchorString"), img.range());
    ASSERT_TRUE(broad.has_value());
    EXPECT_EQ(broad->raw(), img.code_addr(0x10));
}

TEST(StringXrefTest, BroadMatchResolvesPushReference)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    const char str[] = "BroadPushAnchorString";
    img.write_data(0x40, str, sizeof(str));
    // push qword ptr [rip+disp]  ->  FF 35 <disp32>  (6 bytes)
    img.plant_code_rip_insn(0x10, 0x40, {0xFF, 0x35}, 6);

    const auto broad = scan::find_string_xref(broad_query("BroadPushAnchorString"), img.range());
    ASSERT_TRUE(broad.has_value());
    EXPECT_EQ(broad->raw(), img.code_addr(0x10));
}

TEST(StringXrefTest, BroadMatchResolvesNoRexLea)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    const char str[] = "BroadNoRexLeaAnchor";
    img.write_data(0x40, str, sizeof(str));
    // lea eax, [rip+disp]  ->  8D 05 <disp32>  (6 bytes, no REX.W)
    img.plant_code_rip_insn(0x10, 0x40, {0x8D, 0x05}, 6);

    // The narrow scan requires a REX prefix (0x48..0x4F), so a 32-bit lea misses.
    const auto narrow = scan::find_string_xref(utf8_query("BroadNoRexLeaAnchor"), img.range());
    ASSERT_FALSE(narrow.has_value());
    EXPECT_EQ(narrow.error().code, ErrorCode::NoReference);

    const auto broad = scan::find_string_xref(broad_query("BroadNoRexLeaAnchor"), img.range());
    ASSERT_TRUE(broad.has_value());
    EXPECT_EQ(broad->raw(), img.code_addr(0x10));
}

TEST(StringXrefTest, BroadMatchResolvesRexLeaForm)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    const char str[] = "BroadRexLeaAnchor";
    img.write_data(0x40, str, sizeof(str));
    // lea rax, [rip+disp]  ->  48 8D 05 <disp32>  (7 bytes); also caught by the
    // narrow scan, so this proves the broad sweep is a strict superset.
    img.plant_code_rip_insn(0x10, 0x40, {0x48, 0x8D, 0x05}, 7);

    const auto broad = scan::find_string_xref(broad_query("BroadRexLeaAnchor"), img.range());
    ASSERT_TRUE(broad.has_value());
    EXPECT_EQ(broad->raw(), img.code_addr(0x10));
}

TEST(StringXrefTest, BroadMatchKeepsNarrowShapeScanCoverage)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    const char str[] = "BroadKeepsNarrowAnchor";
    img.write_data(0x40, str, sizeof(str));

    // The REX.W lea is intentionally planted at an odd byte offset. The Zydis linear sweep can step over such a site
    // after decoding preceding bytes, so broad_match must merge in the default all-offset shape scan rather than
    // replacing it.
    img.plant_code_rip_insn(0x11, 0x40, {0x48, 0x8D, 0x05}, 7);

    const auto broad = scan::find_string_xref(broad_query("BroadKeepsNarrowAnchor"), img.range());
    ASSERT_TRUE(broad.has_value());
    EXPECT_EQ(broad->raw(), img.code_addr(0x11));
}

TEST(StringXrefTest, BroadMatchAmbiguousReference)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    const char str[] = "BroadTwiceAnchorString";
    img.write_data(0x40, str, sizeof(str));
    // Two references to the same string. The second is placed immediately after the first (offset = first + its length)
    // so the linear sweep, having decoded the first instruction, lands exactly on the second and counts both -- a gap
    // would let the zero-fill cursor desync past an odd offset. Expressing the adjacency as first + len keeps that
    // invariant in code rather than a magic literal.
    constexpr std::size_t cmp_off = 0x10;
    constexpr std::size_t cmp_len = 7; // 83 3D <disp32> 01
    img.plant_code_rip_insn(cmp_off, 0x40, {0x83, 0x3D}, cmp_len, {0x01});
    img.plant_code_rip_insn(cmp_off + cmp_len, 0x40, {0xFF, 0x35}, 6);

    const auto broad = scan::find_string_xref(broad_query("BroadTwiceAnchorString"), img.range());
    ASSERT_FALSE(broad.has_value());
    EXPECT_EQ(broad.error().code, ErrorCode::AmbiguousReference);
}

TEST(StringXrefTest, BroadMatchNoReference)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    // The string is present in the data page but no instruction loads it.
    const char str[] = "BroadUnreferencedAnchor";
    img.write_data(0x40, str, sizeof(str));

    const auto broad = scan::find_string_xref(broad_query("BroadUnreferencedAnchor"), img.range());
    ASSERT_FALSE(broad.has_value());
    EXPECT_EQ(broad.error().code, ErrorCode::NoReference);
}

TEST(StringXrefTest, BroadMatchRecoversFromDecodeFailure)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    const char str[] = "BroadRecoveryAnchorString";
    img.write_data(0x40, str, sizeof(str));

    // 0x06 (PUSH ES) has no valid 64-bit encoding, so ZydisDecoderDecodeFull rejects it and the sweep must byte-restart
    // (offset += 1) to realign. The zero-filled lead-in decodes cleanly as `add [rax], al` (00 00) in 2-byte steps,
    // landing the cursor exactly on this even offset before the failure.
    const std::uint8_t invalid_opcode = 0x06;
    img.write_code(0x10, &invalid_opcode, sizeof(invalid_opcode));

    // The real reference sits at 0x11, one byte past the failure -- an odd offset the 2-byte zero-fill walk never
    // visits unless recovery advanced by exactly
    // one byte. cmp dword ptr [rip+disp], 0x01  ->  83 3D <disp32> 01 (7 bytes).
    img.plant_code_rip_insn(0x11, 0x40, {0x83, 0x3D}, 7, {0x01});

    // If the failure branch broke or stalled instead of byte-restarting, the
    // misaligned reference would be invisible and this would report NoReference;
    // resolving it proves the sweep realigns past undecodable bytes.
    const auto broad = scan::find_string_xref(broad_query("BroadRecoveryAnchorString"), img.range());
    ASSERT_TRUE(broad.has_value());
    EXPECT_EQ(broad->raw(), img.code_addr(0x11));
}

TEST(StringXrefTest, DataPageIsNeverDecodedAsCode)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    const char str[] = "DataPageNeverCodeAnchor";
    img.write_data(0x40, str, sizeof(str));

    // Plant, inside the non-executable data page, a byte sequence that -- if the data page were ever swept as code --
    // decodes to `lea rax, [rip+0x39]` whose target is the string at data offset 0x40 (0x00 + 7 + 0x39 == 0x40; the
    // displacement is a pure intra-page constant, independent of the load base). No reference is planted in the
    // executable code page.
    const std::uint8_t data_lea[] = {0x48, 0x8D, 0x05, 0x39, 0x00, 0x00, 0x00};
    img.write_data(0x00, data_lea, sizeof(data_lea));

    // collect_executable_windows must exclude the PAGE_READWRITE data page, so both scans -- which iterate only those
    // windows -- fail closed with
    // NoReference. A regression that widened the gate to readable pages would count the data-page pseudo-instruction
    // and flip this to a wrong success.
    const auto narrow = scan::find_string_xref(utf8_query("DataPageNeverCodeAnchor"), img.range());
    ASSERT_FALSE(narrow.has_value());
    EXPECT_EQ(narrow.error().code, ErrorCode::NoReference);

    const auto broad = scan::find_string_xref(broad_query("DataPageNeverCodeAnchor"), img.range());
    ASSERT_FALSE(broad.has_value());
    EXPECT_EQ(broad.error().code, ErrorCode::NoReference);
}

TEST(StringXrefTest, MultiWindowResolvesReferenceInSecondWindow)
{
    GappedCodeImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a gapped multi-window image";
    }
    const char str[] = "SecondWindowAnchorString";
    img.write_string(0x40, str, sizeof(str));

    // The only reference lives in the second executable window, past the non-executable gap page. Resolving it proves
    // both scans iterate every window collect_executable_windows returns, not just the first.
    img.plant_lea_window1(0x10, 0x40);

    const auto narrow = scan::find_string_xref(utf8_query("SecondWindowAnchorString"), img.range());
    ASSERT_TRUE(narrow.has_value());
    EXPECT_EQ(narrow->raw(), img.window1_addr(0x10));

    const auto broad = scan::find_string_xref(broad_query("SecondWindowAnchorString"), img.range());
    ASSERT_TRUE(broad.has_value());
    EXPECT_EQ(broad->raw(), img.window1_addr(0x10));
}

TEST(StringXrefTest, MultiWindowAmbiguousAcrossWindows)
{
    GappedCodeImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a gapped multi-window image";
    }
    const char str[] = "CrossWindowAnchorString";
    img.write_string(0x40, str, sizeof(str));

    // One reference in each window. found_count must accumulate across the window boundary so a hit in window 0 and a
    // hit in window 1 still report
    // AmbiguousReference rather than silently resolving the first.
    img.plant_lea_window0(0x10, 0x40);
    img.plant_lea_window1(0x10, 0x40);

    const auto narrow = scan::find_string_xref(utf8_query("CrossWindowAnchorString"), img.range());
    ASSERT_FALSE(narrow.has_value());
    EXPECT_EQ(narrow.error().code, ErrorCode::AmbiguousReference);

    const auto broad = scan::find_string_xref(broad_query("CrossWindowAnchorString"), img.range());
    ASSERT_FALSE(broad.has_value());
    EXPECT_EQ(broad.error().code, ErrorCode::AmbiguousReference);
}

// Precondition regression: phase-2 reference scanning treats each execute-readable window independently and
// carries no cross-window overlap (unlike find_pattern). A RIP-relative lea straddling a protection split inside .text
// -- two adjacent execute-readable regions VirtualQuery reports separately because their base protections differ -- is
// decoded in neither window, so find_string_xref reports NoReference (a fail-closed miss, never a wrong match). The
// common case, one contiguous .text window, has no interior boundary and is unaffected.
TEST(StringXrefTest, ReferenceStraddlingProtectionSplitReportsNoReference)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize;

    // Three contiguous pages from one reservation: page 0 RWX code, page 1 code flipped to a different executable
    // protection (so VirtualQuery splits the two into separate windows), page 2 RW data holding the anchor string.
    auto *base = static_cast<std::uint8_t *>(VirtualAlloc(nullptr, page * 3, MEM_RESERVE, PAGE_NOACCESS));
    if (base == nullptr)
    {
        GTEST_SKIP() << "could not reserve the protection-split fixture";
    }
    VirtualPagePtr owner(base);
    ASSERT_NE(VirtualAlloc(base, page, MEM_COMMIT, PAGE_EXECUTE_READWRITE), nullptr);
    ASSERT_NE(VirtualAlloc(base + page, page, MEM_COMMIT, PAGE_EXECUTE_READWRITE), nullptr);
    ASSERT_NE(VirtualAlloc(base + page * 2, page, MEM_COMMIT, PAGE_READWRITE), nullptr);

    const char str[] = "StraddleAnchorString";
    std::memcpy(base + page * 2, str, sizeof(str));

    // Plant a 7-byte `lea rax, [rip+disp32]` straddling the page0/page1 boundary: its opcode bytes (48 8D 05) end page
    // 0 and its disp32 begins page 1. Window 0's scan stops at span - instr_len so it never reaches the opcode; window
    // 1's scan starts on the disp32, not the opcode. Neither window decodes the instruction.
    const std::size_t straddle_off = page - 3;
    const auto plant_lea = [&](std::size_t off)
    {
        std::uint8_t *instr = base + off;
        instr[0] = 0x48; // REX.W
        instr[1] = 0x8D; // lea
        instr[2] = 0x05; // ModRM: mod=00, reg=rax, rm=101 (RIP-relative)
        const auto next = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(instr) + 7);
        const auto target = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(base + page * 2));
        const auto disp = static_cast<std::int32_t>(target - next);
        std::memcpy(instr + 3, &disp, sizeof(disp));
    };
    plant_lea(straddle_off);

    // Flip page 1 to a different executable protection so VirtualQuery reports it as a separate window from page 0.
    // Done after planting so the disp32 bytes in page 1 were writable.
    DWORD old_protect = 0;
    ASSERT_TRUE(VirtualProtect(base + page, page, PAGE_EXECUTE_READ, &old_protect));

    const Region range{Address{reinterpret_cast<std::uintptr_t>(base)}, page * 3};

    // The only reference straddles the window boundary, so phase 2 finds none: fail-closed NoReference, not a wrong
    // hit.
    const auto straddled = scan::find_string_xref(utf8_query("StraddleAnchorString"), range);
    ASSERT_FALSE(straddled.has_value());
    EXPECT_EQ(straddled.error().code, ErrorCode::NoReference);

    // Positive control: plant a second lea wholly inside window 0. It resolves uniquely, proving the string is findable
    // and a normal reference decodes -- so the miss above is the straddle, not a broken fixture, and the straddling lea
    // is not counted (otherwise this would report AmbiguousReference).
    plant_lea(0x10);
    const auto in_window = scan::find_string_xref(utf8_query("StraddleAnchorString"), range);
    ASSERT_TRUE(in_window.has_value());
    EXPECT_EQ(in_window->raw(), reinterpret_cast<std::uintptr_t>(base + 0x10));
}

TEST(StringXrefTest, StringPointerSlotResolvesStore)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "SlotAnchorString";
    img.write(0x100, str, sizeof(str));
    // lea rax, [rip+string] at 0x10 (7 bytes) immediately followed by mov [rip+slot], rax at 0x17 caching the loaded
    // pointer into the global slot at 0x200. The store's source reg (rax) matches the lea dest, so the slot resolves.
    img.plant_rip_load(0x10, 0x100, LEA);
    img.plant_rip_store(0x17, 0x200, 0);

    const auto result = scan::find_string_xref(slot_query("SlotAnchorString"), img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), img.addr(0x200));
}

TEST(StringXrefTest, StringPointerSlotRegisterMismatch)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "SlotMismatchAnchor";
    img.write(0x100, str, sizeof(str));
    // The lea loads into rax but the following store's source is rcx (reg 1), so it does not cache *this* pointer. The
    // source-register equality gate must reject it and the resolve fails closed.
    img.plant_rip_load(0x10, 0x100, LEA);
    img.plant_rip_store(0x17, 0x200, 1);

    const auto result = scan::find_string_xref(slot_query("SlotMismatchAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StoreNotFound);
}

TEST(StringXrefTest, StringPointerSlotNoStore)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "SlotNoStoreAnchor";
    img.write(0x100, str, sizeof(str));
    // A lone lea with no store anywhere in the forward window. The zero-filled page never forms a store shape, so the
    // forward scan finds nothing.
    img.plant_rip_load(0x10, 0x100, LEA);

    const auto result = scan::find_string_xref(slot_query("SlotNoStoreAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StoreNotFound);
}

TEST(StringXrefTest, StringPointerSlotIgnoresMisalignedStoreShape)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "SlotMisalignedAnchor";
    img.write(0x100, str, sizeof(str));
    img.plant_rip_load(0x10, 0x100, LEA); // lea rax, [rip+string]
    // A `mov rcx, imm64` whose 8-byte immediate embeds the `48 89 05 <disp32>` store shape (source reg rax, the lea
    // destination). A raw byte sweep would find that shape misaligned inside the immediate and return a bogus slot; an
    // instruction-aligned decode steps over the whole `mov rcx, imm64` and never sees it, so the resolve fails closed.
    const std::uint8_t mov_rcx_with_embedded_store[] = {0x48, 0xB9, 0x48, 0x89, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55};
    img.write(0x17, mov_rcx_with_embedded_store, sizeof(mov_rcx_with_embedded_store));

    const auto result = scan::find_string_xref(slot_query("SlotMisalignedAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StoreNotFound);
}

TEST(StringXrefTest, StringPointerSlotStopsAtRegisterClobber)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "SlotClobberAnchor";
    img.write(0x100, str, sizeof(str));
    img.plant_rip_load(0x10, 0x100, LEA); // lea rax, [rip+string]
    // `mov rax, rcx` overwrites the loaded pointer before any store, so the later store caches the clobbered value, not
    // this lea's pointer. The decode stops at the write to the loaded register and fails closed; a raw sweep that
    // ignored intervening writes would wrongly return the store's slot.
    const std::uint8_t clobber_rax[] = {0x48, 0x89, 0xC8}; // mov rax, rcx
    img.write(0x17, clobber_rax, sizeof(clobber_rax));
    img.plant_rip_store(0x1A, 0x200, 0); // mov [rip+slot], rax, after the clobber

    const auto result = scan::find_string_xref(slot_query("SlotClobberAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StoreNotFound);
}

TEST(StringXrefTest, StringPointerSlotDoesNotDecodeDataPageStore)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }

    const char str[] = "SlotDataPageStoreAnchor";
    img.write_data(0x40, str, sizeof(str));

    // Put the lea near the end of the executable page. A module-bounded forward scan would reach the next page, but
    // the slot mode must treat only the executable window as code.
    const std::size_t lea_off = img.page_size() - 0x20;
    img.plant_code_rip_insn(lea_off, 0x40, {0x48, 0x8D, 0x05}, 7);

    // Plant store-shaped bytes in the adjacent non-executable data page. They match the `mov [rip+slot], rax` shape
    // and sit within the 0x80-byte forward bound from the lea, so an implementation that scans past the code window
    // would return the data slot instead of failing closed.
    std::uint8_t data_store[] = {0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00};
    const auto next = static_cast<std::int64_t>(img.data_addr(0) + sizeof(data_store));
    const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(img.data_addr(0x100)) - next);
    std::memcpy(data_store + 3, &disp, sizeof(disp));
    img.write_data(0, data_store, sizeof(data_store));

    const auto result = scan::find_string_xref(slot_query("SlotDataPageStoreAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StoreNotFound);
}

TEST(StringXrefTest, StringPointerSlotR8Register)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "SlotR8AnchorString";
    img.write(0x100, str, sizeof(str));
    // lea r8, [rip+string]: REX.W + REX.R (0x4C), opcode 0x8D, ModRM 0x05 (reg field 0, REX.R supplies the high bit).
    // Raw-written because plant_rip_load only emits rax. The store names r8 too (plant_rip_store reg 8), so both sides
    // must apply (REX.R << 3 | ModRM.reg) -- this pins r8..r15 reconstruction on the load and the store together.
    const std::uint8_t lea_r8[] = {0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00};
    img.write(0x10, lea_r8, sizeof(lea_r8));
    const auto next = static_cast<std::int64_t>(img.addr(0x10) + 7);
    const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(img.addr(0x100)) - next);
    img.write(0x13, &disp, sizeof(disp));
    img.plant_rip_store(0x17, 0x200, 8);

    const auto result = scan::find_string_xref(slot_query("SlotR8AnchorString"), img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->raw(), img.addr(0x200));
}

TEST(StringXrefTest, StringPointerSlotOutOfWindowStore)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "SlotFarStoreAnchor";
    img.write(0x100, str, sizeof(str));
    // The store sits more than the 128-byte (0x80) forward window past the lea, so the bounded scan never reaches it
    // and the store cannot be attributed to this load.
    img.plant_rip_load(0x10, 0x100, LEA);
    img.plant_rip_store(0x10 + 7 + 0x80, 0x300, 0);

    const auto result = scan::find_string_xref(slot_query("SlotFarStoreAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StoreNotFound);
}

TEST(StringXrefTest, StringPointerSlotMovLoadHasNoStore)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const char str[] = "SlotMovLoadAnchor";
    img.write(0x100, str, sizeof(str));
    // The reference is a mov load (0x8B), not a lea, so lea_info.is_lea is false: the loaded value already went to a
    // register with no modeled store. Even with a matching store present, slot mode rejects the mov-load shape.
    img.plant_rip_load(0x10, 0x100, MOV);
    img.plant_rip_store(0x17, 0x200, 0);

    const auto result = scan::find_string_xref(slot_query("SlotMovLoadAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StoreNotFound);
}

TEST(StringXrefTest, StringPointerSlotBroadOnlyReferenceFails)
{
    SplitImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic split image";
    }
    const char str[] = "SlotBroadOnlyAnchor";
    img.write_data(0x40, str, sizeof(str));
    // The only reference is a broad-only cmp [rip+string], invisible to the narrow lea scan. With broad_match the
    // reference survives, but it came from the broad sweep, so lea_info is unpopulated and references.site != narrow
    // site. Slot mode requires the narrow lea, so it fails closed even though a unique reference exists.
    // cmp dword ptr [rip+disp], 0x01  ->  83 3D <disp32> 01  (7 bytes)
    img.plant_code_rip_insn(0x10, 0x40, {0x83, 0x3D}, 7, {0x01});

    scan::StringRefQuery q = slot_query("SlotBroadOnlyAnchor");
    q.broad_match = true;
    const auto result = scan::find_string_xref(q, img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StoreNotFound);
}

TEST(StringXrefTest, ErrorToStringIsNoexceptAndTotal)
{
    // Verify that to_string covers all string-xref ErrorCode values and is noexcept.
    static_assert(noexcept(to_string(ErrorCode::EmptyQuery)));
    const ErrorCode all[] = {
        ErrorCode::EmptyQuery,  ErrorCode::InvalidRange,       ErrorCode::StringNotFound,   ErrorCode::StringAmbiguous,
        ErrorCode::NoReference, ErrorCode::AmbiguousReference, ErrorCode::FunctionNotFound, ErrorCode::StoreNotFound,
    };
    for (const auto code : all)
    {
        EXPECT_FALSE(to_string(code).empty());
    }
}

#if defined(_MSC_VER) || defined(_WIN64)
// Mirror of the scanner region guard for the string-xref window scans. find_string_xref reads each
// execute-readable window returned by collect_executable_windows with unguarded byte reads (narrow shape scan) and
// Zydis decoding (broad scan); scan_window_narrow_guarded / scan_window_broad_guarded backstop a concurrent decommit /
// reprotect that the per-window VirtualQuery gate cannot close. This test resolves a planted anchor in the first
// executable window while a second thread decommits and recommits a separate trailing executable window. Every
// iteration returns either the stable site (no fault landed) or a fail-closed ambiguity verdict (a faulted trailing
// window is skipped, which taints uniqueness); references collected before a swallowed fault are discarded by the
// guarded wrappers, so the result is never a wrong address and never a crash. A run where the decommit never lands
// inside the read window is a valid pass for the fault path; the __except / VEH skip-the-window mechanism is pinned
// deterministically by MemoryGuardedReadFault and the seh_read_bytes NoAccess / GuardPage tests in test_memory.cpp.
// Supported builds enter this block through MSVC SEH or the MinGW x64 vectored guard; 32-bit is rejected by the global
// architecture gate in defines.hpp.
TEST(StringXrefRegionGuard, SurvivesConcurrentDecommitMidScan)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;
    const SIZE_T pages = 8;
    const SIZE_T size = page * pages;

    VirtualPagePtr allocation(static_cast<std::uint8_t *>(VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_NOACCESS)));
    ASSERT_NE(allocation.get(), nullptr);
    auto *base = allocation.get();
    auto *trailing_window = base + (pages - 2) * page;
    ASSERT_NE(VirtualAlloc(base, page, MEM_COMMIT, PAGE_EXECUTE_READWRITE), nullptr);
    ASSERT_NE(VirtualAlloc(trailing_window, page, MEM_COMMIT, PAGE_EXECUTE_READWRITE), nullptr);
    std::memset(base, 0xCC, page); // INT3 fill: never a RIP-relative string load, never part of the anchor text
    std::memset(trailing_window, 0xCC, page);

    // A unique anchor in the first page plus a single lea referencing it, so a fault-free resolve has a defined answer.
    const char anchor[] = "GuardedStringAnchor";
    std::memcpy(base + 0x40, anchor, sizeof(anchor));
    std::uint8_t *insn = base + 0x100;
    insn[0] = 0x48; // REX.W
    insn[1] = 0x8D; // lea
    insn[2] = 0x05; // ModRM: RIP-relative
    const auto next = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(insn) + 7);
    const auto target = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(base + 0x40));
    const auto disp = static_cast<std::int32_t>(target - next);
    std::memcpy(insn + 3, &disp, sizeof(disp));
    const std::uintptr_t reference_site = reinterpret_cast<std::uintptr_t>(insn);

    const Region range{Address{reinterpret_cast<std::uintptr_t>(base)}, size};

    scan::StringRefQuery query = utf8_query("GuardedStringAnchor");
    query.broad_match = true; // exercise both the narrow and the broad guarded window scans

    // Positive control with no contention: the guarded window scans resolve the planted reference to its site.
    const auto control = scan::find_string_xref(query, range);
    ASSERT_TRUE(control.has_value());
    EXPECT_EQ(control->raw(), reference_site);

    const std::uintptr_t decommit_page = reinterpret_cast<std::uintptr_t>(trailing_window);
    std::jthread toggler(
        [decommit_page, page](std::stop_token stop_token)
        {
            while (!stop_token.stop_requested())
            {
                VirtualFree(reinterpret_cast<void *>(decommit_page), page, MEM_DECOMMIT);
                VirtualAlloc(reinterpret_cast<void *>(decommit_page), page, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            }
        });

    // The toggler races every iteration; a few hundred resolves give the decommit ample chance to land mid-scan while
    // keeping the broad Zydis sweep's per-iteration cost bounded. Page 0 (anchor + reference) is never decommitted, so
    // a fault-free resolve returns reference_site; when the decommit lands mid-scan the trailing window is skipped,
    // which taints uniqueness and fails the resolve closed to ambiguous. Each result is therefore the stable site or a
    // fail-closed ambiguity verdict -- never a wrong address, never a crash.
    for (int i = 0; i < 600; ++i)
    {
        const auto result = scan::find_string_xref(query, range);
        if (result.has_value())
        {
            EXPECT_EQ(result->raw(), reference_site);
        }
        else
        {
            EXPECT_TRUE(result.error().code == ErrorCode::AmbiguousReference ||
                        result.error().code == ErrorCode::StringAmbiguous)
                << "unexpected fail-closed code: " << to_string(result.error().code);
        }
    }
}

// Incompleteness gate: a faulted execute-readable window must taint find_string_xref's uniqueness verdict. The phase-1
// readable sweep and the phase-2 narrow and broad sweeps each skip a window that faults mid-scan under the TOCTOU
// guard, which leaves the occurrence count a lower bound: a second reference (or a second pooled copy of the string)
// could hide in the skipped window. The verdict must then fail closed to ambiguous, never report the lone surviving
// reference as unique.
//
// The fixture plants exactly one copy of the string and exactly one reference to it, both in a stable page that never
// faults, so any ambiguous result is unambiguously incompleteness-driven: there is structurally no second reference or
// string that could make the verdict ambiguous by count. A background thread flips the readability of a separate
// trailing execute-readable window (its bytes are irrelevant INT3 fill that never references the string), so some scans
// read that window while it faults. Every result must therefore be either the unique reference site (no fault landed)
// or a fail-closed StringAmbiguous / AmbiguousReference (a fault was skipped). Crucially, at least one fail-closed
// result must appear across the run; without the incompleteness gate, the faulted-window skip would only be logged and
// the lone reference would still be returned as unique. broad_match runs phase 1 plus the narrow and broad phase-2
// sweeps in a single call, so one loop exercises all three uniqueness gates. This test shares the x64-guard block of
// the region-guard test above (the vectored guard is x64-only; the architecture gate forbids 32-bit outright, so on
// every supported build one of these macros is defined).
TEST(StringXrefIncompleteGate, FaultedWindowForcesAmbiguousNeverFalselyUnique)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;
    // Four pages: page 0 (string + reference), page 1 reserved gap, page 2 (the toggled window), page 3 reserved. The
    // gap keeps page 0 and page 2 as two distinct windows (VirtualQuery would coalesce adjacent same-protection pages),
    // so collect_executable_windows returns both and the sweep reads the toggled window as a separate window.
    const SIZE_T pages = 4;
    const SIZE_T size = page * pages;

    VirtualPagePtr allocation(static_cast<std::uint8_t *>(VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_NOACCESS)));
    ASSERT_NE(allocation.get(), nullptr);
    auto *base = allocation.get();
    auto *toggled_window = base + 2 * page;

    // Page 0 holds the sole string and the sole reference; it is never toggled, so a fault-free resolve is unique.
    ASSERT_NE(VirtualAlloc(base, page, MEM_COMMIT, PAGE_EXECUTE_READWRITE), nullptr);
    // A separate trailing executable window whose readability the toggler flips. Its INT3 fill never references the
    // string, so it can only ever contribute a faulted-window skip, never a real second reference or string copy.
    ASSERT_NE(VirtualAlloc(toggled_window, page, MEM_COMMIT, PAGE_EXECUTE_READWRITE), nullptr);
    std::memset(base, 0xCC, page);
    std::memset(toggled_window, 0xCC, page);

    const char anchor[] = "IncompleteGateAnchor";
    std::memcpy(base + 0x40, anchor, sizeof(anchor));
    std::uint8_t *insn = base + 0x100;
    insn[0] = 0x48; // REX.W
    insn[1] = 0x8D; // lea
    insn[2] = 0x05; // ModRM: RIP-relative, reg = rax
    const auto next = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(insn) + 7);
    const auto target = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(base + 0x40));
    const auto disp = static_cast<std::int32_t>(target - next);
    std::memcpy(insn + 3, &disp, sizeof(disp));
    const std::uintptr_t reference_site = reinterpret_cast<std::uintptr_t>(insn);

    const Region range{Address{reinterpret_cast<std::uintptr_t>(base)}, size};
    scan::StringRefQuery query = utf8_query("IncompleteGateAnchor");
    query.broad_match = true; // exercise phase 1 + narrow + broad in one call

    // Positive control with no contention: the sole reference resolves uniquely.
    const auto control = scan::find_string_xref(query, range);
    ASSERT_TRUE(control.has_value());
    EXPECT_EQ(control->raw(), reference_site);

    // Flip the trailing window between readable and no-access. VirtualProtect (not decommit) keeps the page committed
    // throughout, so it is always a gate candidate when readable and faults on read exactly when flipped mid-scan --
    // maximizing the chance a scan reads it while it faults.
    std::jthread toggler(
        [toggled_window, page](std::stop_token stop_token)
        {
            DWORD old_protect = 0;
            while (!stop_token.stop_requested())
            {
                VirtualProtect(toggled_window, page, PAGE_NOACCESS, &old_protect);
                VirtualProtect(toggled_window, page, PAGE_EXECUTE_READWRITE, &old_protect);
            }
        });

    // Loop until a faulted-window skip forces the fail-closed verdict, then stop. A generous ceiling guards against a
    // hang if the race never lands; in practice the fault lands within a few hundred iterations.
    bool saw_fail_closed = false;
    for (int i = 0; i < 30000 && !saw_fail_closed; ++i)
    {
        const auto result = scan::find_string_xref(query, range);
        if (result.has_value())
        {
            // Never a wrong address: a fault-free (or before-the-fault) resolve returns the sole planted reference.
            EXPECT_EQ(result->raw(), reference_site);
        }
        else
        {
            // The only non-value outcomes possible here are the two fail-closed ambiguity verdicts: phase 1 skipped a
            // faulted readable window (StringAmbiguous) or phase 2 skipped a faulted executable window
            // (AmbiguousReference). No second reference/string exists, so neither can arise from a real duplicate.
            EXPECT_TRUE(result.error().code == ErrorCode::AmbiguousReference ||
                        result.error().code == ErrorCode::StringAmbiguous)
                << "unexpected fail-closed code: " << to_string(result.error().code);
            saw_fail_closed = true;
        }
    }

    EXPECT_TRUE(saw_fail_closed) << "the concurrent fault never landed inside a scan window, so the incompleteness "
                                    "gate was never exercised; raise the iteration budget or window size.";
}
#endif // _MSC_VER || _WIN64
