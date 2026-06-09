#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "DetourModKit/scanner.hpp"
#include "DetourModKit/memory.hpp"

using namespace DetourModKit;

namespace
{
    // A committed RWX page used as a synthetic module image. find_string_xref
    // scans readable pages for the string (phase 1) and execute-readable pages for
    // the reference (phase 2); PAGE_EXECUTE_READWRITE satisfies both masks, so a
    // single page hosts the whole fixture and the ModuleRange spans exactly it.
    // The page is zero-filled by VirtualAlloc, so an unwritten byte is 0x00, which
    // both terminates a planted string and never starts a RIP-relative load.
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

        void write(std::size_t off, const void *data, std::size_t n) noexcept
        {
            std::memcpy(m_base + off, data, n);
        }

        // Plants `<rex> <opcode> <modrm> <disp32>` (a RIP-relative lea/mov) at
        // instr_off whose computed target is target_off. modrm 0x05 is the
        // RIP-relative form with rax as the destination register.
        void plant_rip_load(std::size_t instr_off, std::size_t target_off,
                            std::uint8_t opcode) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            p[0] = 0x48; // REX.W
            p[1] = opcode;
            p[2] = 0x05; // ModRM: mod=00, reg=rax, rm=101 (RIP-relative)
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 7);
            const auto disp = static_cast<std::int32_t>(
                static_cast<std::int64_t>(addr(target_off)) - next);
            std::memcpy(p + 3, &disp, sizeof(disp));
        }

        [[nodiscard]] Memory::ModuleRange range() const noexcept
        {
            return Memory::ModuleRange{reinterpret_cast<std::uintptr_t>(m_base),
                                       reinterpret_cast<std::uintptr_t>(m_base) + m_size};
        }

    private:
        std::uint8_t *m_base = nullptr;
        std::size_t m_size = 0;
    };

    constexpr std::uint8_t LEA = 0x8D;
    constexpr std::uint8_t MOV = 0x8B;

    Scanner::StringRefQuery utf8_query(std::string_view text)
    {
        Scanner::StringRefQuery q{};
        q.text = text;
        q.encoding = Scanner::StringEncoding::Utf8;
        q.require_terminator = true;
        q.return_mode = Scanner::XrefReturn::ReferencingInstruction;
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

    const auto result = Scanner::find_string_xref(utf8_query("AnchorStringAlpha"), img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, img.addr(0x10));
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

    const auto result = Scanner::find_string_xref(utf8_query("AnchorStringBeta"), img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, img.addr(0x20));
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

    const auto result = Scanner::find_string_xref(utf8_query("AbsentString"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::StringXrefError::StringNotFound);
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

    const auto result = Scanner::find_string_xref(utf8_query("DuplicatedAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::StringXrefError::StringAmbiguous);
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

    const auto result = Scanner::find_string_xref(utf8_query("UnreferencedAnchor"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::StringXrefError::NoReference);
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

    const auto result = Scanner::find_string_xref(utf8_query("TwiceReferenced"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::StringXrefError::AmbiguousReference);
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
    const auto result = Scanner::find_string_xref(utf8_query("Player"), img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::StringXrefError::StringNotFound);

    // Without the terminator it matches the prefix and resolves the reference.
    Scanner::StringRefQuery loose = utf8_query("Player");
    loose.require_terminator = false;
    const auto loose_result = Scanner::find_string_xref(loose, img.range());
    ASSERT_TRUE(loose_result.has_value());
    EXPECT_EQ(*loose_result, img.addr(0x10));
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

    Scanner::StringRefQuery q{};
    q.text = "QuitGame";
    q.encoding = Scanner::StringEncoding::Utf16le;
    q.require_terminator = true;
    const auto result = Scanner::find_string_xref(q, img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, img.addr(0x10));
}

TEST(StringXrefTest, EnclosingFunctionReturnsPrologue)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    // INT3 padding, then a recognizable prologue, then the referencing lea. The
    // back-scan from the lea must cross the lea-to-prologue gap (no 0xCC/0xC3),
    // hit the 0xCC pad boundary, and return the prologue start.
    const std::uint8_t pad[] = {0xCC, 0xCC, 0xCC, 0xCC};
    img.write(0x40, pad, sizeof(pad));
    const std::uint8_t prologue[] = {0x55, 0x48, 0x8B, 0xEC}; // push rbp; mov rbp, rsp
    img.write(0x44, prologue, sizeof(prologue));
    const char str[] = "FunctionAnchor";
    img.write(0x100, str, sizeof(str));
    img.plant_rip_load(0x60, 0x100, LEA); // lea sits inside the function body

    Scanner::StringRefQuery q = utf8_query("FunctionAnchor");
    q.return_mode = Scanner::XrefReturn::EnclosingFunction;
    const auto result = Scanner::find_string_xref(q, img.range());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, img.addr(0x44));
}

TEST(StringXrefTest, EnclosingFunctionNotFound)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    // No 0xCC/0xC3 boundary precedes the lea (the page is zero-filled), so the
    // back-scan finds no function entry and the resolve fails closed.
    const char str[] = "NoBoundaryAnchor";
    img.write(0x100, str, sizeof(str));
    img.plant_rip_load(0x10, 0x100, LEA);

    Scanner::StringRefQuery q = utf8_query("NoBoundaryAnchor");
    q.return_mode = Scanner::XrefReturn::EnclosingFunction;
    const auto result = Scanner::find_string_xref(q, img.range());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Scanner::StringXrefError::FunctionNotFound);
}

TEST(StringXrefTest, EmptyQueryAndInvalidRange)
{
    SyntheticImage img;
    if (!img.ok())
    {
        GTEST_SKIP() << "could not allocate a synthetic image page";
    }
    const auto empty = Scanner::find_string_xref(utf8_query(""), img.range());
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(empty.error(), Scanner::StringXrefError::EmptyQuery);

    const auto bad_range = Scanner::find_string_xref(utf8_query("Anything"), Memory::ModuleRange{});
    ASSERT_FALSE(bad_range.has_value());
    EXPECT_EQ(bad_range.error(), Scanner::StringXrefError::InvalidRange);
}

TEST(StringXrefTest, ErrorToStringIsNoexceptAndTotal)
{
    static_assert(noexcept(Scanner::string_xref_error_to_string(Scanner::StringXrefError::EmptyQuery)));
    const Scanner::StringXrefError all[] = {
        Scanner::StringXrefError::EmptyQuery,
        Scanner::StringXrefError::InvalidRange,
        Scanner::StringXrefError::StringNotFound,
        Scanner::StringXrefError::StringAmbiguous,
        Scanner::StringXrefError::NoReference,
        Scanner::StringXrefError::AmbiguousReference,
        Scanner::StringXrefError::FunctionNotFound,
    };
    for (const auto error : all)
    {
        EXPECT_FALSE(Scanner::string_xref_error_to_string(error).empty());
    }
}
