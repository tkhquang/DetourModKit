#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/scan.hpp"

using namespace DetourModKit;
using scan::Candidate;

static_assert(!std::is_default_constructible_v<Candidate>);
static_assert(!std::is_aggregate_v<Candidate>);

namespace
{
    // A committed, readable byte buffer the resolver can scan. Heap pages are MEM_COMMIT readable, and resolve() clamps
    // its page-gated scan to the Region it is handed, so the buffer is exactly the haystack. The buffer is pre-filled
    // with 0xCC (int3) so a planted, distinctive signature is unique against the noise.
    class ReadableBuffer
    {
    public:
        explicit ReadableBuffer(std::size_t size) : m_bytes(size, std::byte{0xCC}) {}

        [[nodiscard]] Region region() const noexcept { return Region{Address{m_bytes.data()}, m_bytes.size()}; }
        [[nodiscard]] std::uintptr_t address_of(std::size_t offset) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_bytes.data() + offset);
        }
        [[nodiscard]] const std::byte *data() const noexcept { return m_bytes.data(); }

        void put(std::size_t offset, std::initializer_list<unsigned char> sequence)
        {
            for (const unsigned char value : sequence)
            {
                m_bytes[offset] = std::byte{value};
                ++offset;
            }
        }
        void put_disp32(std::size_t offset, std::int32_t value)
        {
            std::memcpy(m_bytes.data() + offset, &value, sizeof(value));
        }
        // Writes the bytes of text plus a terminating NUL (an immutable string literal for the string-xref backend).
        void put_string(std::size_t offset, std::string_view text)
        {
            for (const char ch : text)
            {
                m_bytes[offset++] = static_cast<std::byte>(static_cast<unsigned char>(ch));
            }
            m_bytes[offset] = std::byte{0};
        }

    private:
        std::vector<std::byte> m_bytes;
    };

    // A committed execute-readable buffer for the hooked-prologue recovery path, which scans only executable pages.
    class ExecutableBuffer
    {
    public:
        explicit ExecutableBuffer(std::size_t size) : m_size(size)
        {
            m_base = static_cast<std::byte *>(
                ::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (m_base != nullptr)
            {
                std::memset(m_base, 0xCC, size);
            }
        }
        ExecutableBuffer(const ExecutableBuffer &) = delete;
        ExecutableBuffer &operator=(const ExecutableBuffer &) = delete;
        ~ExecutableBuffer() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        [[nodiscard]] bool valid() const noexcept { return m_base != nullptr; }
        [[nodiscard]] Region region() const noexcept { return Region{Address{m_base}, m_size}; }
        [[nodiscard]] std::uintptr_t address_of(std::size_t offset) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + offset);
        }

        void put(std::size_t offset, std::initializer_list<unsigned char> sequence)
        {
            for (const unsigned char value : sequence)
            {
                m_base[offset] = std::byte{value};
                ++offset;
            }
        }
        // Writes an E9 rel32 near JMP at function_offset whose absolute destination is destination_offset.
        void put_e9_jump(std::size_t function_offset, std::size_t destination_offset)
        {
            m_base[function_offset] = std::byte{0xE9};
            const auto next_ip = static_cast<std::int64_t>(function_offset) + 5;
            const auto displacement =
                static_cast<std::int32_t>(static_cast<std::int64_t>(destination_offset) - next_ip);
            std::memcpy(m_base + function_offset + 1, &displacement, sizeof(displacement));
        }
        // Writes a six-byte FF 25 disp32 RIP-relative indirect JMP at instr_off whose pointer slot lives at slot_off in
        // this buffer; the slot is filled with target_addr, the absolute address the decoder dereferences.
        void put_ff25_indirect(std::size_t instr_off, std::size_t slot_off, std::uintptr_t target_addr)
        {
            m_base[instr_off] = std::byte{0xFF};
            m_base[instr_off + 1] = std::byte{0x25};
            const auto next_ip = static_cast<std::int64_t>(address_of(instr_off) + 6);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(address_of(slot_off)) - next_ip);
            std::memcpy(m_base + instr_off + 2, &disp, sizeof(disp));
            std::memcpy(m_base + slot_off, &target_addr, sizeof(target_addr));
        }
        // Writes the fourteen-byte FF 25 00000000 <abs64> form: the disp32 is zero, so the eight-byte target_addr is
        // inlined right after the instruction and the decoder reads it from instr+6.
        void put_ff25_abs64(std::size_t instr_off, std::uintptr_t target_addr)
        {
            put(instr_off, {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});
            std::memcpy(m_base + instr_off + 6, &target_addr, sizeof(target_addr));
        }
        // Writes the twelve-byte `mov rax, imm64; jmp rax` (48 B8 <imm64> FF E0) absolute JMP at instr_off; the imm64
        // is the absolute destination the decoder returns directly.
        void put_mov_rax_jmp(std::size_t instr_off, std::uintptr_t target_addr)
        {
            m_base[instr_off] = std::byte{0x48};
            m_base[instr_off + 1] = std::byte{0xB8};
            std::memcpy(m_base + instr_off + 2, &target_addr, sizeof(target_addr));
            m_base[instr_off + 10] = std::byte{0xFF};
            m_base[instr_off + 11] = std::byte{0xE0};
        }
        // Writes the bytes of text plus a terminating NUL (an immutable string literal for the string-xref backend).
        void put_string(std::size_t offset, std::string_view text)
        {
            for (const char ch : text)
            {
                m_base[offset++] = static_cast<std::byte>(static_cast<unsigned char>(ch));
            }
            m_base[offset] = std::byte{0};
        }
        // Writes a seven-byte REX.W `lea rax, [rip+disp32]` at instr_off whose computed target is target_off -- the
        // dominant string-load shape the narrow phase-2 xref scan recognizes.
        void put_lea_rip(std::size_t instr_off, std::size_t target_off)
        {
            m_base[instr_off] = std::byte{0x48};
            m_base[instr_off + 1] = std::byte{0x8D};
            m_base[instr_off + 2] = std::byte{0x05};
            const auto next_ip = static_cast<std::int64_t>(address_of(instr_off) + 7);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(address_of(target_off)) - next_ip);
            std::memcpy(m_base + instr_off + 3, &disp, sizeof(disp));
        }

    private:
        std::byte *m_base = nullptr;
        std::size_t m_size = 0;
    };

    // Synthetic MSVC x64 RTTI layout for the RttiVtable tier, mirroring the dissector fixture in
    // test_rtti_dissect.cpp. The pool lives in the test executable's data segment so the reverse-RTTI prelude's
    // owning-module bound check (the COL pSelf RVA must reconstruct the test exe's image base) accepts every synthetic
    // vtable. Offsets keep the COL, TypeDescriptor, and vtable storage apart from each other and from page boundaries.
    constexpr std::size_t SR_BUF_SIZE = 4096;
    constexpr std::size_t SR_COL_OFFSET = 256;
    constexpr std::size_t SR_TD_OFFSET = SR_COL_OFFSET + 24; // COL is 24 bytes
    constexpr std::size_t SR_TD_NAME_OFFSET = SR_TD_OFFSET + 16;
    constexpr std::size_t SR_COL_PTR_OFFSET = 2048; // the vtable[-1] meta-slot
    constexpr std::size_t SR_VTABLE_OFFSET = SR_COL_PTR_OFFSET + 8;

    constexpr std::size_t SR_POOL_FIXTURES = 4;
    alignas(8) std::array<std::byte, SR_BUF_SIZE * SR_POOL_FIXTURES> s_sr_pool{};
    std::size_t s_sr_used = 0;

    void sr_reset() noexcept
    {
        s_sr_used = 0;
    }

    template <typename T> void sr_write(std::byte *buf, std::size_t off, const T &value) noexcept
    {
        std::memcpy(buf + off, &value, sizeof(T));
    }

    // Builds one synthetic COL/TypeDescriptor/vtable carrying name and returns the synthetic vtable address (0 on pool
    // exhaustion or a sub-image-base data segment). RVAs are computed against the test exe image base so the prelude
    // accepts them.
    [[nodiscard]] std::uintptr_t sr_build_synth(std::string_view name) noexcept
    {
        if (s_sr_used + SR_BUF_SIZE > s_sr_pool.size())
        {
            return 0;
        }
        std::byte *buf = s_sr_pool.data() + s_sr_used;
        s_sr_used += SR_BUF_SIZE;
        std::memset(buf, 0, SR_BUF_SIZE);

        const std::uintptr_t exe_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const std::uintptr_t buf_base = reinterpret_cast<std::uintptr_t>(buf);
        if (buf_base < exe_base)
        {
            return 0;
        }
        const std::uintptr_t buf_rva = buf_base - exe_base;

        sr_write<std::uint32_t>(buf, SR_COL_OFFSET + 0, 1); // signature (x64)
        sr_write<std::uint32_t>(buf, SR_COL_OFFSET + 4, 0); // offset in complete object
        sr_write<std::uint32_t>(buf, SR_COL_OFFSET + 8, 0); // cd_offset
        sr_write<std::uint32_t>(buf, SR_COL_OFFSET + 12,
                                static_cast<std::uint32_t>(buf_rva + SR_TD_OFFSET)); // p_type_descriptor
        sr_write<std::uint32_t>(buf, SR_COL_OFFSET + 16, 0);                         // p_class_descriptor
        sr_write<std::uint32_t>(buf, SR_COL_OFFSET + 20,
                                static_cast<std::uint32_t>(buf_rva + SR_COL_OFFSET)); // p_self

        const std::size_t max_name = SR_COL_PTR_OFFSET - SR_TD_NAME_OFFSET - 1;
        const std::size_t name_len = name.size() < max_name ? name.size() : max_name;
        std::memcpy(buf + SR_TD_NAME_OFFSET, name.data(), name_len);
        buf[SR_TD_NAME_OFFSET + name_len] = std::byte{0};

        const std::uintptr_t col_addr = buf_base + SR_COL_OFFSET;
        sr_write<std::uintptr_t>(buf, SR_COL_PTR_OFFSET, col_addr);

        return buf_base + SR_VTABLE_OFFSET;
    }

    // The pool sub-range written so far, used as a tight resolution scope. It is not a PE image, so the reverse-RTTI
    // sweep walks exactly this range while still validating each hit against the real owning module.
    [[nodiscard]] Region sr_pool_region() noexcept
    {
        return Region{Address{s_sr_pool.data()}, s_sr_used};
    }

    // A distinctive sixteen-byte marker compiled into the test executable's own image so a Region::host() resolve has a
    // real in-image target. volatile + odr-used (a test reads its address) so the linker keeps it and the compiler does
    // not fold the bytes away.
    volatile const unsigned char g_host_scan_marker[16] = {0x7A, 0x6B, 0x68, 0x71, 0x44, 0x4D, 0x4B, 0x48,
                                                           0x6F, 0x73, 0x74, 0x4D, 0x61, 0x72, 0x6B, 0x21};
} // namespace

TEST(ScanResolve, DirectResolvesAtMatchSite)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});

    const std::array<Candidate, 1> ladder = {Candidate::direct("marker", scan::Pattern::literal("DE AD BE EF"))};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x100));
    EXPECT_EQ(hit->winning_name, "marker");
}

TEST(ScanResolve, DirectWalkBackOffsetsTheResult)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});

    // A negative walk-back resolves to a point before the match site.
    const std::array<Candidate, 1> ladder = {Candidate::direct("marker", scan::Pattern::literal("DE AD BE EF"), -0x10)};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x100) - 0x10);
}

TEST(ScanResolve, RipRelativeResolvesThroughDisplacement)
{
    ReadableBuffer buffer(0x400);
    // mov rax, [rip+disp32] shape at 0x100; target sits at 0x200 inside the buffer.
    buffer.put(0x100, {0x48, 0x8B, 0x05});
    const std::size_t match = 0x100;
    const std::size_t target = 0x200;
    const auto displacement =
        static_cast<std::int32_t>(static_cast<std::int64_t>(target) - (static_cast<std::int64_t>(match) + 7));
    buffer.put_disp32(match + 3, displacement);

    const std::array<Candidate, 1> ladder = {
        Candidate::rip_relative("global", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 3, 7)};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(target));
}

TEST(ScanResolve, RequireUniqueFallsThroughAmbiguousToUniqueCandidate)
{
    ReadableBuffer buffer(0x400);
    // The first candidate's signature occurs twice (ambiguous); the second occurs once (unique).
    buffer.put(0x080, {0xDE, 0xAD, 0xBE, 0xEF});
    buffer.put(0x180, {0xDE, 0xAD, 0xBE, 0xEF});
    buffer.put(0x280, {0xCA, 0xFE, 0xBA, 0xBE});

    const std::array<Candidate, 2> ladder = {
        Candidate::direct("ambiguous", scan::Pattern::literal("DE AD BE EF")),
        Candidate::direct("unique", scan::Pattern::literal("CA FE BA BE")),
    };
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x280));
    EXPECT_EQ(hit->winning_name, "unique");
}

TEST(ScanResolve, RequireUniqueSoleAmbiguousReturnsNoMatch)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x080, {0xDE, 0xAD, 0xBE, 0xEF});
    buffer.put(0x180, {0xDE, 0xAD, 0xBE, 0xEF});

    const std::array<Candidate, 1> ladder = {Candidate::direct("ambiguous", scan::Pattern::literal("DE AD BE EF"))};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, RequireUniqueFalseAcceptsFirstAmbiguousMatch)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x080, {0xDE, 0xAD, 0xBE, 0xEF});
    buffer.put(0x180, {0xDE, 0xAD, 0xBE, 0xEF});

    const std::array<Candidate, 1> ladder = {Candidate::direct("loose", scan::Pattern::literal("DE AD BE EF"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .require_unique = false});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x080));
}

TEST(ScanResolve, ScopeExcludesMatchOutsideTheRange)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x300, {0xDE, 0xAD, 0xBE, 0xEF});

    // Narrow the scope to the first half of the buffer, where the signature is absent.
    const Region narrow = Region{Address{buffer.data()}, 0x200};
    const std::array<Candidate, 1> ladder = {Candidate::direct("marker", scan::Pattern::literal("DE AD BE EF"))};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = narrow});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, EmptyLadderReturnsEmptyCandidates)
{
    const std::span<const Candidate> empty;
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = empty, .scope = Region::host()});
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::EmptyCandidates);
}

TEST(ScanResolve, EmptyScopeReturnsInvalidRange)
{
    ReadableBuffer buffer(0x100);
    buffer.put(0x000, {0xDE, 0xAD, 0xBE, 0xEF});
    const std::array<Candidate, 1> ladder = {Candidate::direct("marker", scan::Pattern::literal("DE AD BE EF"))};

    // A default Region is empty (the fail-closed result of an unresolvable scope), which must report InvalidRange.
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = Region{}});
    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::InvalidRange);
}

TEST(ScanResolve, CandidateFactoriesExposeCoherentPayloads)
{
    const Candidate direct = Candidate::direct("direct", scan::Pattern::literal("DE AD"), -4);
    EXPECT_EQ(direct.name(), "direct");
    EXPECT_EQ(direct.mode(), scan::Mode::Direct);
    ASSERT_NE(direct.as_direct(), nullptr);
    EXPECT_EQ(direct.as_direct()->pattern.size(), 2U);
    EXPECT_EQ(direct.as_direct()->walk_back, -4);
    // The variant keeps the (mode, payload) pairing coherent: a Direct candidate carries no other tier's payload.
    EXPECT_EQ(direct.as_rip_relative(), nullptr);
    EXPECT_EQ(direct.as_rtti_vtable(), nullptr);
    EXPECT_EQ(direct.as_string_xref(), nullptr);

    const Candidate rip = Candidate::rip_relative("rip", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 3, 7);
    EXPECT_EQ(rip.mode(), scan::Mode::RipRelative);
    ASSERT_NE(rip.as_rip_relative(), nullptr);
    EXPECT_EQ(rip.as_rip_relative()->displacement_at, 3);
    EXPECT_EQ(rip.as_rip_relative()->instruction_length, 7U);

    const Candidate rtti = Candidate::rtti_vtable("rtti", ".?AVType@@");
    EXPECT_EQ(rtti.mode(), scan::Mode::RttiVtable);
    EXPECT_EQ(rtti.as_direct(), nullptr);
    ASSERT_NE(rtti.as_rtti_vtable(), nullptr);
    EXPECT_EQ(rtti.as_rtti_vtable()->mangled, ".?AVType@@");

    const Candidate xref = Candidate::string_xref("xref", "literal");
    EXPECT_EQ(xref.mode(), scan::Mode::StringXref);
    EXPECT_EQ(xref.as_direct(), nullptr);
    ASSERT_NE(xref.as_string_xref(), nullptr);
    EXPECT_EQ(xref.as_string_xref()->text, "literal");

    // Owned-string contract: build a Candidate from runtime strings that are destroyed before the assertions. A
    // borrowed-view member (instead of an owned std::string) would dangle here; an owning std::string survives.
    const Candidate owned = []
    {
        std::string name = "runtime-name";
        name += "-built";
        std::string mangled = std::string(".?AV") + "RuntimeType@@";
        return Candidate::rtti_vtable(name, mangled);
    }();
    EXPECT_EQ(owned.name(), "runtime-name-built");
    ASSERT_NE(owned.as_rtti_vtable(), nullptr);
    EXPECT_EQ(owned.as_rtti_vtable()->mangled, ".?AVRuntimeType@@");
}

TEST(ScanResolve, RttiVtableMissFallsThroughToByteCandidate)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});

    // The RTTI tier cannot resolve a bogus type name against a heap buffer, so the ladder must fall through to the
    // byte tier behind it rather than fail.
    const std::array<Candidate, 2> ladder = {
        Candidate::rtti_vtable("bogus", ".?AVDefinitelyNotARealType@@"),
        Candidate::direct("marker", scan::Pattern::literal("DE AD BE EF")),
    };
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->winning_name, "marker");
}

TEST(ScanResolve, StringXrefMissReturnsNoMatchNotInvalid)
{
    ReadableBuffer buffer(0x400);
    // A sole string-xref candidate whose literal is absent fails closed as NoMatch: a non-byte candidate that misses
    // is a clean miss, not an error.
    const std::array<Candidate, 1> ladder = {
        Candidate::string_xref("missing", "this literal does not exist in the buffer scope")};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, OrderCandidatesAsDeclaredIsIdentity)
{
    const std::array<Candidate, 3> ladder = {
        Candidate::direct("a", scan::Pattern::literal("DE AD")),
        Candidate::rtti_vtable("b", ".?AVType@@"),
        Candidate::direct("c", scan::Pattern::literal("?? ??")),
    };
    std::array<std::size_t, 3> out{};
    const std::size_t count = scan::order_candidates(scan::CandidateOrder::AsDeclared, ladder, out);

    ASSERT_EQ(count, 3U);
    EXPECT_EQ(out[0], 0U);
    EXPECT_EQ(out[1], 1U);
    EXPECT_EQ(out[2], 2U);
}

TEST(ScanResolve, OrderCandidatesUniqueFirstPartitionsByTier)
{
    // Mixed ladder: anchored byte, text tier, unanchored byte, text tier. UniqueFirst promotes the text tiers, then the
    // anchored byte pattern, then the unanchored byte pattern; declared order is preserved within each group.
    const std::array<Candidate, 4> ladder = {
        Candidate::direct("anchored", scan::Pattern::literal("DE AD BE EF")),
        Candidate::rtti_vtable("rtti", ".?AVType@@"),
        Candidate::direct("unanchored", scan::Pattern::literal("?? ??")),
        Candidate::string_xref("xref", "literal"),
    };
    std::array<std::size_t, 4> out{};
    const std::size_t count = scan::order_candidates(scan::CandidateOrder::UniqueFirst, ladder, out);

    ASSERT_EQ(count, 4U);
    EXPECT_EQ(out[0], 1U); // rtti (text tier)
    EXPECT_EQ(out[1], 3U); // string xref (text tier)
    EXPECT_EQ(out[2], 0U); // anchored byte pattern
    EXPECT_EQ(out[3], 2U); // unanchored byte pattern
}

TEST(ScanResolve, CandidateOrderChangesTheWinner)
{
    ReadableBuffer buffer(0x400);
    // Two byte patterns, each planted uniquely: an anchored one (fully-known rare bytes) and an unanchored one
    // (high-nibble-only, so it carries no fully-known byte to anchor on). The unanchored candidate is declared first,
    // so AsDeclared and UniqueFirst try a different candidate first and produce a different winner.
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF}); // anchored target
    buffer.put(0x200,
               {0x10, 0x20, 0x30, 0x40}); // unanchored target (high nibbles 1,2,3,4; the 0xCC fill never collides)

    const std::array<Candidate, 2> ladder = {
        Candidate::direct("unanchored", scan::Pattern::literal("1? 2? 3? 4?")),
        Candidate::direct("anchored", scan::Pattern::literal("DE AD BE EF")),
    };

    // AsDeclared tries the unanchored candidate (declared first), so it wins.
    const auto as_declared = scan::resolve(
        scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .order = scan::CandidateOrder::AsDeclared});
    ASSERT_TRUE(as_declared.has_value());
    EXPECT_EQ(as_declared->winning_name, "unanchored");
    EXPECT_EQ(as_declared->address.raw(), buffer.address_of(0x200));

    // UniqueFirst promotes the anchored byte pattern ahead of the unanchored one, flipping the winner.
    const auto unique_first = scan::resolve(
        scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .order = scan::CandidateOrder::UniqueFirst});
    ASSERT_TRUE(unique_first.has_value());
    EXPECT_EQ(unique_first->winning_name, "anchored");
    EXPECT_EQ(unique_first->address.raw(), buffer.address_of(0x100));
}

TEST(ScanResolve, OrNullAndAddressOrFlatten)
{
    const Result<scan::Hit> ok = scan::Hit{Address{0x1234}, "n"};
    const Result<scan::Hit> err = std::unexpected(Error{ErrorCode::NoMatch, "test"});

    EXPECT_EQ(scan::or_null(ok).raw(), 0x1234U);
    EXPECT_EQ(scan::or_null(err).raw(), 0U);
    EXPECT_EQ(scan::address_or(ok, Address{0x99}).raw(), 0x1234U);
    EXPECT_EQ(scan::address_or(err, Address{0x99}).raw(), 0x99U);
    EXPECT_EQ(scan::address_or(err).raw(), 0U);
}

TEST(ScanResolve, ScanFindsPatternAndReportsMissAndInvalidRange)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x140, {0xDE, 0xAD, 0xBE, 0xEF});

    const auto found = scan::scan(scan::Pattern::literal("DE AD BE EF"), buffer.region());
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->raw(), buffer.address_of(0x140));

    const auto missing = scan::scan(scan::Pattern::literal("CA FE BA BE"), buffer.region());
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, ErrorCode::NoMatch);

    const auto invalid = scan::scan(scan::Pattern::literal("DE AD BE EF"), Region{});
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, ErrorCode::InvalidRange);
}

TEST(ScanResolve, UncheckedFindPatternReturnsRawMatchPointer)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x1C0, {0xDE, 0xAD, 0xBE, 0xEF});

    const std::byte *match = scan::unchecked::find_pattern(buffer.region(), scan::Pattern::literal("DE AD BE EF"));
    ASSERT_NE(match, nullptr);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(match), buffer.address_of(0x1C0));

    const std::byte *miss = scan::unchecked::find_pattern(buffer.region(), scan::Pattern::literal("CA FE BA BE"));
    EXPECT_EQ(miss, nullptr);
}

TEST(ScanResolve, ResolveBatchReturnsPerRequestResultsInOrder)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});
    buffer.put(0x200, {0xCA, 0xFE, 0xBA, 0xBE});

    const std::array<Candidate, 1> first_ladder = {Candidate::direct("first", scan::Pattern::literal("DE AD BE EF"))};
    const std::array<Candidate, 1> second_ladder = {Candidate::direct("second", scan::Pattern::literal("CA FE BA BE"))};
    const std::array<Candidate, 1> missing_ladder = {
        Candidate::direct("missing", scan::Pattern::literal("01 02 03 04"))};

    const std::array<scan::ScanRequest, 3> requests = {
        scan::ScanRequest{.ladder = first_ladder, .scope = buffer.region()},
        scan::ScanRequest{.ladder = second_ladder, .scope = buffer.region()},
        scan::ScanRequest{.ladder = missing_ladder, .scope = buffer.region()},
    };

    const std::vector<Result<scan::Hit>> results = scan::resolve_batch(requests);
    ASSERT_EQ(results.size(), 3U);
    ASSERT_TRUE(results[0].has_value());
    EXPECT_EQ(results[0]->address.raw(), buffer.address_of(0x100));
    ASSERT_TRUE(results[1].has_value());
    EXPECT_EQ(results[1]->address.raw(), buffer.address_of(0x200));
    ASSERT_FALSE(results[2].has_value());
    EXPECT_EQ(results[2].error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, OwnedScanRequestViewResolves)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});

    scan::OwnedScanRequest owned;
    owned.ladder.push_back(Candidate::direct("owned", scan::Pattern::literal("DE AD BE EF")));
    owned.label = "owned-request";
    owned.scope = buffer.region();

    const auto hit = scan::resolve(owned.view());
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x100));
    EXPECT_EQ(hit->winning_name, "owned");
}

TEST(ScanResolve, BorrowBuildsAResolvableRequest)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});

    const std::array<Candidate, 1> ladder = {Candidate::direct("borrowed", scan::Pattern::literal("DE AD BE EF"))};
    const scan::ScanRequest request = scan::borrow(ladder, "borrowed-request", buffer.region());

    const auto hit = scan::resolve(request);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x100));
}

TEST(ScanResolve, PrologueFallbackRecoversAnE9HookedFunction)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // A sibling mod inline-hooked the function at 0x100 with an E9 near JMP to a trampoline at 0x800. The original
    // prologue bytes (the first five of the signature) are gone, so the direct scan misses; the surviving literal tail
    // is intact for the fallback to rebuild against.
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_e9_jump(function, trampoline);
    // A twelve-byte distinctive literal tail (>= the ten-literal floor), planted right after the five overwritten
    // bytes.
    buffer.put(function + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    // Make the trampoline target look like a real function body so the recovered jump destination passes the
    // executable + plausible gate (it lives on the execute-readable page already).
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});

    // The candidate's signature is the UNHOOKED prologue (five original bytes) plus the tail. The five leading bytes do
    // not match the E9 now present, so the direct pass misses and the fallback must rebuild the prologue as the JMP.
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .prologue_fallback = true});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function));
    EXPECT_EQ(hit->winning_name, "hooked");
}

TEST(ScanResolve, PrologueFallbackShortTailIsNotApplicable)
{
    ReadableBuffer buffer(0x400);
    // A Direct candidate that misses directly and whose literal tail (after the five prologue bytes) is only nine
    // literals, below the ten-literal floor, so no shape is applicable.
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("short", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .prologue_fallback = true});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::PrologueFallbackNotApplicable);
}

TEST(ScanResolve, PrologueFallbackRecoversFf25IndirectPrologue)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // A trampoline beyond rel32 reach is hooked with a six-byte FF 25 RIP-relative indirect JMP whose pointer slot
    // holds the absolute trampoline address. The original six prologue bytes are gone; the literal tail survives for
    // the fallback to rebuild against.
    const std::size_t function = 0x100;
    const std::size_t slot = 0x600;
    const std::size_t trampoline = 0x800;
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08}); // a plausible function body on the executable page
    buffer.put_ff25_indirect(function, slot, buffer.address_of(trampoline));
    buffer.put(function + 6, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});

    // Candidate = the unhooked six-byte prologue + the twelve-byte tail. The leading bytes no longer match the FF 25
    // now present, so the direct pass misses and the fallback rebuilds the prologue as the indirect-JMP shape.
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .prologue_fallback = true});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function));
    EXPECT_EQ(hit->winning_name, "hooked");
}

TEST(ScanResolve, PrologueFallbackRecoversFf25Abs64InlineTarget)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // The fourteen-byte FF 25 00000000 <abs64> far jump: a disp32 of zero inlines the eight-byte target right after the
    // instruction (decode_ff25_indirect reads it from match+6). Fourteen prologue bytes are overwritten.
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    buffer.put_ff25_abs64(function, buffer.address_of(trampoline));
    buffer.put(function + 14, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});

    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 90 90 90 90 90 90 90 90 90 11 22 33 44 "
                                                           "55 66 77 88 99 AA BB DD"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .prologue_fallback = true});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function));
}

TEST(ScanResolve, PrologueFallbackRecoversMovRaxJmpRax)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // The twelve-byte `mov rax, imm64; jmp rax` absolute jump some libraries emit when the trampoline is beyond rel32
    // reach. The imm64 is the absolute destination; twelve prologue bytes are overwritten.
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    buffer.put_mov_rax_jmp(function, buffer.address_of(trampoline));
    buffer.put(function + 12, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});

    // Leading byte 0x55 differs from the planted 0x48, so the direct pass misses and the fallback rebuilds the prologue
    // as the mov-rax/jmp-rax shape.
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 90 90 90 90 90 90 90 11 22 33 44 55 66 "
                                                           "77 88 99 AA BB DD"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .prologue_fallback = true});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function));
}

TEST(ScanResolve, PrologueFallbackHonorsAnchorOffsetMarker)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    buffer.put_e9_jump(function, trampoline);
    buffer.put(function + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});

    // The signature carries a `|` result marker seven bytes in. The direct pass would return (match + 7); the fallback
    // must honor the same marker, so the recovered address is function + 7, not the bare match site.
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 | 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .prologue_fallback = true});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function + 7));
}

TEST(ScanResolve, PrologueFallbackRejectsDataOnlyDestination)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // A committed but NON-executable destination: a readable heap allocation. The FF 25 slot points at it, so the
    // rebuilt prologue matches uniquely, but the decoded jump lands on data, which the executable-destination gate
    // rejects -- so recovery fails closed rather than committing to a data address.
    std::vector<std::byte> data_only(64, std::byte{0x90});
    const std::size_t function = 0x100;
    const std::size_t slot = 0x600;
    buffer.put_ff25_indirect(function, slot, reinterpret_cast<std::uintptr_t>(data_only.data()));
    buffer.put(function + 6, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});

    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .prologue_fallback = true});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, PrologueFallbackAllowsTrampolineOutsideScope)
{
    ExecutableBuffer scope(0x1000);
    ExecutableBuffer trampoline_page(0x1000);
    ASSERT_TRUE(scope.valid());
    ASSERT_TRUE(trampoline_page.valid());

    // The trampoline lives in a SEPARATE executable page, outside the scanned scope -- the canonical sibling-mod
    // inline-hook case. The destination gate must accept it (committed + executable) even though it belongs to no
    // module, while the recovered function address must still lie inside the scanned scope.
    const std::size_t function = 0x100;
    const std::size_t slot = 0x600;
    const std::size_t trampoline = 0x40;
    trampoline_page.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    scope.put_ff25_indirect(function, slot, trampoline_page.address_of(trampoline));
    scope.put(function + 6, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});

    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = scope.region(), .prologue_fallback = true});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), scope.address_of(function));
}

TEST(ScanResolve, PrologueFallbackRejectsAmbiguousRebuiltPattern)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // The same hooked-prologue shape and identical literal tail appear at two sites, so the rebuilt pattern matches
    // twice. A genuine sibling-mod hook rewrites exactly one prologue, so two matches make recovery ambiguous and must
    // fail closed rather than commit to an arbitrary site.
    const std::size_t first = 0x100;
    const std::size_t second = 0x500;
    const std::size_t trampoline = 0x800;
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    buffer.put_e9_jump(first, trampoline);
    buffer.put_e9_jump(second, trampoline);
    buffer.put(first + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(second + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});

    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .prologue_fallback = true});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, PrologueFallbackNineByteTailIsNotApplicable)
{
    ReadableBuffer buffer(0x400);
    // Exactly nine literal tail bytes after the five-byte prologue -- one below the ten-literal floor -- so no shape is
    // applicable and the resolver reports the distinct PrologueFallbackNotApplicable rather than a plain miss. Pins the
    // reject side of the floor (the recovery tests above pin the accept side at twelve).
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("nine", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99"))};
    const auto hit =
        scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .prologue_fallback = true});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::PrologueFallbackNotApplicable);
}

TEST(ScanResolve, DirectImplausibleWalkBackFallsThroughToCleanCandidate)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});
    buffer.put(0x200, {0xCA, 0xFE, 0xBA, 0xBE});

    // The first candidate matches but its walk-back underflows the resolved address to 0x8000, below the user-mode
    // floor, so the plausibility screen rejects it and the ladder falls through to the clean second candidate.
    const auto implausible_walk_back =
        static_cast<std::ptrdiff_t>(0x8000) - static_cast<std::ptrdiff_t>(buffer.address_of(0x100));
    const std::array<Candidate, 2> ladder = {
        Candidate::direct("implausible", scan::Pattern::literal("DE AD BE EF"), implausible_walk_back),
        Candidate::direct("clean", scan::Pattern::literal("CA FE BA BE")),
    };
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x200));
    EXPECT_EQ(hit->winning_name, "clean");
}

TEST(ScanResolve, DirectImplausibleWalkBackSoleCandidateReturnsNoMatch)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});

    // The sole candidate resolves below the user-mode floor, so there is nothing to fall through to: a near-null
    // address must never be returned as success.
    const auto implausible_walk_back =
        static_cast<std::ptrdiff_t>(0x8000) - static_cast<std::ptrdiff_t>(buffer.address_of(0x100));
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("implausible", scan::Pattern::literal("DE AD BE EF"), implausible_walk_back)};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, StringXrefResolvesReferenceInScope)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // An immutable string at 0x400 with a single REX.W `lea rax, [rip+string]` reference at 0x100. The execute-readable
    // page hosts both, so phase 1 locates the unique literal and phase 2 the unique reference; resolve() returns the
    // referencing-instruction site.
    const std::size_t literal = 0x400;
    const std::size_t reference = 0x100;
    buffer.put_string(literal, "DmkUniqueAnchor");
    buffer.put_lea_rip(reference, literal);

    const std::array<Candidate, 1> ladder = {Candidate::string_xref("xref", "DmkUniqueAnchor")};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(reference));
    EXPECT_EQ(hit->winning_name, "xref");
}

TEST(ScanResolve, StringXrefAmbiguousFallsThroughToByteCandidate)
{
    ReadableBuffer buffer(0x400);
    // The linker pools identical literals: planting the anchor string twice makes find_string_xref report
    // StringAmbiguous, so the string-xref tier fails closed and the ladder falls through to the byte tier behind it.
    buffer.put_string(0x080, "DmkAnchorLiteral");
    buffer.put_string(0x200, "DmkAnchorLiteral");
    buffer.put(0x300, {0xCA, 0xFE, 0xBA, 0xBE});

    const std::array<Candidate, 2> ladder = {
        Candidate::string_xref("pooled", "DmkAnchorLiteral"),
        Candidate::direct("fallback", scan::Pattern::literal("CA FE BA BE")),
    };
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x300));
    EXPECT_EQ(hit->winning_name, "fallback");
}

TEST(ScanResolve, SoleMissingRttiVtableReturnsNoMatch)
{
    ReadableBuffer buffer(0x400);
    // A sole RttiVtable candidate whose mangled name resolves to nothing fails closed as NoMatch: a non-byte candidate
    // that misses is a clean miss, and there is no byte tier to fall through to.
    const std::array<Candidate, 1> ladder = {Candidate::rtti_vtable("absent", ".?AVDefinitelyNotARealType@@")};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NoMatch);
}

class ScanResolveRttiVtable : public ::testing::Test
{
protected:
    void SetUp() override
    {
        (void)Memory::init_cache();
        sr_reset();
    }
    void TearDown() override { Memory::shutdown_cache(); }
};

TEST_F(ScanResolveRttiVtable, ResolvesPrimaryVtableInScope)
{
    // A synthetic primary vtable for ".?AVScanResolveType@@" in the test exe's data segment. resolve()'s RttiVtable
    // tier walks the reverse-RTTI backend over the pool scope and returns the synthetic vtable address.
    const std::uintptr_t expected = sr_build_synth(".?AVScanResolveType@@");
    ASSERT_NE(expected, 0u);

    const std::array<Candidate, 1> ladder = {Candidate::rtti_vtable("type", ".?AVScanResolveType@@")};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = sr_pool_region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), expected);
    EXPECT_EQ(hit->winning_name, "type");
}

TEST(ScanResolve, DirectResolvedOutOfRangeFallsThroughToNextCandidate)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x180, {0xDE, 0xAD, 0xBE, 0xEF});
    buffer.put(0x100, {0xCA, 0xFE, 0xBA, 0xBE});

    // The first candidate matches in scope, but a forward walk-back pushes the resolved address past the end of the
    // scope (still a plausible pointer). resolve() bounds the resolved address to the scope, so it falls through to the
    // in-range second candidate rather than committing out of bounds.
    const std::array<Candidate, 2> ladder = {
        Candidate::direct("out-of-range", scan::Pattern::literal("DE AD BE EF"), 0x300),
        Candidate::direct("in-range", scan::Pattern::literal("CA FE BA BE")),
    };
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x100));
    EXPECT_EQ(hit->winning_name, "in-range");
}

TEST(ScanResolve, RipRelativeResolvedOutOfRangeFallsThroughToNextCandidate)
{
    ReadableBuffer buffer(0x400);
    // A mov rax, [rip+disp32] at 0x100 whose displacement targets 0x800 -- past the end of the scope. The resolved
    // global is plausible but out of range, so resolve() falls through to the in-range byte candidate.
    buffer.put(0x100, {0x48, 0x8B, 0x05});
    const std::size_t match = 0x100;
    const std::size_t out_of_range_target = 0x800;
    const auto displacement = static_cast<std::int32_t>(static_cast<std::int64_t>(out_of_range_target) -
                                                        (static_cast<std::int64_t>(match) + 7));
    buffer.put_disp32(match + 3, displacement);
    buffer.put(0x200, {0xCA, 0xFE, 0xBA, 0xBE});

    const std::array<Candidate, 2> ladder = {
        Candidate::rip_relative("out-of-range", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 3, 7),
        Candidate::direct("in-range", scan::Pattern::literal("CA FE BA BE")),
    };
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(0x200));
    EXPECT_EQ(hit->winning_name, "in-range");
}

TEST(ScanResolve, NoCrossScopeBleedReturnsInScopeCopy)
{
    ReadableBuffer in_scope(0x400);
    ReadableBuffer decoy(0x400);
    // The identical signature sits in two independent buffers. A scoped resolve must return the copy inside the scope
    // it was handed and never the identical copy in the decoy region outside it.
    in_scope.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});
    decoy.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});

    const std::array<Candidate, 1> ladder = {Candidate::direct("marker", scan::Pattern::literal("DE AD BE EF"))};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = in_scope.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), in_scope.address_of(0x100));
}

TEST(ScanResolve, ResolvesMarkerInHostImageScope)
{
    // The marker is compiled into the test executable's image; Region::host() (the default scope) must reach it.
    const auto expected = reinterpret_cast<std::uintptr_t>(const_cast<const unsigned char *>(g_host_scan_marker));
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("host-marker", scan::Pattern::literal("7A 6B 68 71 44 4D 4B 48 6F 73 74 4D 61 72 6B 21"))};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = Region::host()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), expected);
}

TEST(ScanResolve, ResolveErrorCodesHaveNonEmptyStrings)
{
    // Every Scan-block ErrorCode the resolver surface can surface maps to a non-empty, noexcept to_string, so a
    // diagnostic log of a resolve failure never prints an empty reason.
    static_assert(noexcept(to_string(ErrorCode::NoMatch)));
    const ErrorCode codes[] = {
        ErrorCode::EmptyCandidates,
        ErrorCode::NoMatch,
        ErrorCode::InvalidRange,
        ErrorCode::PrologueFallbackNotApplicable,
        ErrorCode::OutOfMemory,
        ErrorCode::NullInput,
        ErrorCode::PrefixNotFound,
        ErrorCode::RegionTooSmall,
        ErrorCode::UnreadableDisplacement,
        ErrorCode::ImplausibleTarget,
        ErrorCode::BadPattern,
        ErrorCode::DecodeFailed,
        ErrorCode::OperandOutOfRange,
        ErrorCode::UnexpectedShape,
    };
    for (const ErrorCode code : codes)
    {
        EXPECT_FALSE(to_string(code).empty());
    }
}
