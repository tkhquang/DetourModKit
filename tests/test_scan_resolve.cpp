#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <windows.h>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/scan.hpp"

#include "internal/scan_shared.hpp"

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
        void put_disp32(std::size_t offset, std::int32_t value) noexcept
        {
            std::memcpy(m_base + offset, &value, sizeof(value));
        }
        [[nodiscard]] bool protect(std::size_t offset, std::size_t size, DWORD protection) noexcept
        {
            DWORD previous = 0;
            return ::VirtualProtect(m_base + offset, size, protection, &previous) != 0;
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

// The rip_relative factory rejects a malformed disp32 layout at construction instead of silently resolving to a
// wrong-but-plausible address at scan time. A field offset must be non-negative, the four-byte field must fit, and an
// x86-64 instruction cannot exceed 15 bytes.
TEST(ScanResolve, RipRelativeFactoryEnforcesDisplacementInvariant)
{
    // The canonical valid form (disp32 at [3, 7) inside a 7-byte instruction) constructs.
    EXPECT_NO_THROW((void)Candidate::rip_relative("ok", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 3, 7));

    // disp32 overruns the instruction end: 5 + 4 > 7.
    EXPECT_THROW((void)Candidate::rip_relative("overrun", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 5, 7),
                 std::invalid_argument);
    // A negative displacement-field offset cannot describe an instruction layout.
    EXPECT_THROW((void)Candidate::rip_relative("negative", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), -1, 7),
                 std::invalid_argument);
    // An all-zero mis-set (0 + 4 > 0) is rejected.
    EXPECT_THROW((void)Candidate::rip_relative("zero", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 0, 0),
                 std::invalid_argument);
    // x86-64 instructions are at most 15 bytes long.
    EXPECT_THROW((void)Candidate::rip_relative("too-long", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 3, 16),
                 std::invalid_argument);

    // The invariant is scoped to RipRelative: a Direct candidate with an arbitrary signed walk_back still constructs.
    EXPECT_NO_THROW((void)Candidate::direct("direct", scan::Pattern::literal("DE AD"), -0x100));
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

TEST(ScanResolve, InvalidEnumValuesCannotNormalizePermissively)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});
    const std::array<Candidate, 1> ladder = {Candidate::direct("marker", scan::Pattern::literal("DE AD BE EF"))};

    const auto valid = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});
    ASSERT_TRUE(valid.has_value());
    EXPECT_EQ(valid->address.raw(), buffer.address_of(0x100));

    const auto bad_order = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .order = static_cast<scan::CandidateOrder>(0xFF)});
    ASSERT_FALSE(bad_order.has_value());
    EXPECT_EQ(bad_order.error().code, ErrorCode::InvalidArg);

    const auto bad_fallback = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = static_cast<scan::FallbackPolicy>(0xFF)});
    ASSERT_FALSE(bad_fallback.has_value());
    EXPECT_EQ(bad_fallback.error().code, ErrorCode::InvalidArg);

    scan::StringRefQuery invalid_xref{.text = "literal"};
    invalid_xref.encoding = static_cast<scan::StringEncoding>(0xFF);
    const std::array<Candidate, 2> bad_encoding_ladder = {
        Candidate::direct("fallback", scan::Pattern::literal("DE AD BE EF")),
        Candidate::string_xref("invalid-encoding", invalid_xref),
    };
    const auto bad_encoding = scan::resolve(scan::ScanRequest{.ladder = bad_encoding_ladder, .scope = buffer.region()});
    ASSERT_FALSE(bad_encoding.has_value());
    EXPECT_EQ(bad_encoding.error().code, ErrorCode::InvalidArg);

    invalid_xref.encoding = scan::StringEncoding::Utf8;
    invalid_xref.return_mode = static_cast<scan::XrefReturn>(0xFF);
    const std::array<Candidate, 2> bad_return_ladder = {
        Candidate::direct("fallback", scan::Pattern::literal("DE AD BE EF")),
        Candidate::string_xref("invalid-return", invalid_xref),
    };
    const auto bad_return = scan::resolve(scan::ScanRequest{.ladder = bad_return_ladder, .scope = buffer.region()});
    ASSERT_FALSE(bad_return.has_value());
    EXPECT_EQ(bad_return.error().code, ErrorCode::InvalidArg);

    // A malformed request outranks an empty one: the policy-enum checks run before the EmptyCandidates verdict, so an
    // empty ladder cannot downgrade an invalid enum to a routine missing-candidates miss.
    const auto empty_invalid = scan::resolve(
        scan::ScanRequest{.ladder = {}, .scope = buffer.region(), .order = static_cast<scan::CandidateOrder>(0xFF)});
    ASSERT_FALSE(empty_invalid.has_value());
    EXPECT_EQ(empty_invalid.error().code, ErrorCode::InvalidArg);

    const std::array<scan::ScanRequest, 2> requests = {
        scan::ScanRequest{.ladder = ladder, .scope = buffer.region()},
        scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .order = static_cast<scan::CandidateOrder>(0xFF)},
    };
    const auto batch = scan::resolve_batch(requests);
    ASSERT_TRUE(batch.has_value());
    ASSERT_EQ(batch->size(), 2U);
    EXPECT_TRUE((*batch)[0].has_value());
    ASSERT_FALSE((*batch)[1].has_value());
    EXPECT_EQ((*batch)[1].error().code, ErrorCode::InvalidArg);

    const std::array<Candidate, 2> mixed = {
        Candidate::direct("byte", scan::Pattern::literal("DE AD BE EF")),
        Candidate::string_xref("xref", "literal"),
    };
    std::array<std::size_t, 2> out{};
    const std::size_t count = scan::order_candidates(static_cast<scan::CandidateOrder>(0xFF), mixed, out);
    ASSERT_EQ(count, 2U);
    EXPECT_EQ(out[0], 0U);
    EXPECT_EQ(out[1], 1U);
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

    const auto batch = scan::resolve_batch(requests);
    ASSERT_TRUE(batch.has_value());
    const auto &results = *batch;
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

// The resolver's page-class knob (ScanRequest::pages). A byte candidate can restrict its sweep to executable pages so a
// signature that has to land on an instruction cannot alias an identical run in a data section. The discriminating case
// is a match that lives only on a non-executable page: Readable resolves it, Executable excludes it.
TEST(ScanResolve, ExecutablePagesExcludeDataMatchThatReadableResolves)
{
    ReadableBuffer data(0x400); // A heap page: committed and readable, but NOT executable -- a data-section stand-in.
    data.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22});
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("data-sig", scan::Pattern::literal("DE AD BE EF 11 22"))};

    // Readable accepts data pages, so the data-section match resolves at its planted address.
    const scan::ScanRequest readable_request{
        .ladder = ladder, .label = "readable-data", .scope = data.region(), .pages = scan::Pages::Readable};
    const auto readable_hit = scan::resolve(readable_request);
    ASSERT_TRUE(readable_hit.has_value()) << readable_hit.error().message();
    EXPECT_EQ(readable_hit->address.raw(), data.address_of(0x100));

    // Executable narrows to code pages; the same match sits on a non-executable heap page, so it is now unreachable and
    // the resolve fails closed rather than committing to a data-page address.
    const scan::ScanRequest executable_request{
        .ladder = ladder, .label = "executable-only", .scope = data.region(), .pages = scan::Pages::Executable};
    const auto executable_hit = scan::resolve(executable_request);
    ASSERT_FALSE(executable_hit.has_value());
    EXPECT_EQ(executable_hit.error().code, ErrorCode::NoMatch);
}

// The other direction: Executable is not merely "always empty" -- a match that genuinely sits on an executable page
// resolves under it, so the knob selects code pages rather than rejecting everything.
TEST(ScanResolve, ExecutablePagesResolveGenuineCodeMatch)
{
    ExecutableBuffer code(0x1000); // VirtualAlloc PAGE_EXECUTE_READWRITE: a real executable page.
    ASSERT_TRUE(code.valid());
    code.put(0x080, {0x0F, 0x1F, 0x44, 0x00, 0x00, 0x90}); // A distinctive byte run against the 0xCC fill.
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("code-sig", scan::Pattern::literal("0F 1F 44 00 00 90"))};

    const scan::ScanRequest executable_request{
        .ladder = ladder, .label = "code", .scope = code.region(), .pages = scan::Pages::Executable};
    const auto hit = scan::resolve(executable_request);
    ASSERT_TRUE(hit.has_value()) << hit.error().message();
    EXPECT_EQ(hit->address.raw(), code.address_of(0x080));
}

// candidate_order_to_string is a constexpr, noexcept, total value map. Its switch has no default, so -Wswitch guards a
// missing enumerator at compile time; these checks additionally pin the callback-safe noexcept contract and the
// "Unknown" out-of-range fallback for a value read from possibly corrupted memory. The static_asserts prove the map is
// usable in a constant expression.
static_assert(noexcept(scan::candidate_order_to_string(scan::CandidateOrder::AsDeclared)),
              "candidate_order_to_string must be noexcept: it is a callback-safe pure value map.");
static_assert(scan::candidate_order_to_string(scan::CandidateOrder::AsDeclared) == "AsDeclared");
static_assert(scan::candidate_order_to_string(scan::CandidateOrder::UniqueFirst) == "UniqueFirst");
static_assert(scan::candidate_order_to_string(static_cast<scan::CandidateOrder>(0xFF)) == "Unknown");

TEST(ScanResolve, CandidateOrderToStringIsTotalAndDistinct)
{
    // Every declared enumerator maps to its own non-empty name.
    EXPECT_EQ(scan::candidate_order_to_string(scan::CandidateOrder::AsDeclared), "AsDeclared");
    EXPECT_EQ(scan::candidate_order_to_string(scan::CandidateOrder::UniqueFirst), "UniqueFirst");
    EXPECT_NE(scan::candidate_order_to_string(scan::CandidateOrder::AsDeclared),
              scan::candidate_order_to_string(scan::CandidateOrder::UniqueFirst));

    // An out-of-range value (e.g. a byte read from corrupted state cast to the enum) degrades to a stable sentinel
    // rather than returning a dangling or empty view.
    EXPECT_EQ(scan::candidate_order_to_string(static_cast<scan::CandidateOrder>(0xFF)), "Unknown");
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
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function));
    EXPECT_EQ(hit->winning_name, "hooked");
}

// The structural recovery above is address-blind: a unique rebuilt match plus a valid redirect proves a hooked site
// exists, not that it is the intended function. A game reshape can leave a coincidental near-twin whose surviving tail
// matches and which is itself inline-hooked, so the rebuilt pattern resolves uniquely to the wrong address. The
// FallbackPolicy + FallbackWitness gate turns that fail-open into a fail-closed. These tests drive the gate through the
// same E9-hooked fixture as the recovery test, varying only the policy and witness. Each keeps that fixture inline on
// purpose: the exact hooked bytes a test asserts on sit next to the assertion, so it stays auditable in isolation.

TEST(ScanResolve, PrologueFallbackRequireIdentityRejectsAWitnessMismatch)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_e9_jump(function, trampoline);
    buffer.put(function + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};

    // A witness that always rejects the recovered site models a near-twin: structural recovery still finds the unique
    // hooked match, but the site is not the intended function. RequireIdentity must fail closed with a distinct code
    // rather than return the possibly-wrong address, so a caller can tell "hooked near-twin found" from "nothing
    // matched at all".
    const scan::FallbackWitness witness{.predicate = +[](std::int64_t, const void *) noexcept { return false; },
                                        .context = nullptr};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder,
                                                     .scope = buffer.region(),
                                                     .fallback_policy = scan::FallbackPolicy::RequireIdentity,
                                                     .fallback_witness = witness});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::PrologueIdentityRejected);
}

TEST(ScanResolve, BorrowCodeTargetStrictPinsRequireIdentityAndGatesTheWitness)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_e9_jump(function, trampoline);
    buffer.put(function + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};

    // borrow_code_target_strict pins FallbackPolicy::RequireIdentity and takes the witness as a MANDATORY argument, so
    // a caller cannot request the strict fallback without one (which would silently fail closed on every recovery). A
    // rejecting witness models a near-twin: the strict preset must fail the recovery closed with the identity code.
    const scan::FallbackWitness reject{.predicate = +[](std::int64_t, const void *) noexcept { return false; },
                                       .context = nullptr};
    const scan::ScanRequest request = scan::borrow_code_target_strict(ladder, "strict-target", reject, buffer.region());
    EXPECT_EQ(request.fallback_policy, scan::FallbackPolicy::RequireIdentity);
    EXPECT_TRUE(request.require_executable_result);
    EXPECT_TRUE(request.require_unique);

    const auto rejected = scan::resolve(request);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, ErrorCode::PrologueIdentityRejected);

    // A confirming witness recovers exactly the intended function, proving the preset only tightens identity and keeps
    // the underlying code-target recovery capability intact.
    const scan::FallbackWitness accept{.predicate = +[](std::int64_t, const void *) noexcept { return true; },
                                       .context = nullptr};
    const auto recovered =
        scan::resolve(scan::borrow_code_target_strict(ladder, "strict-target", accept, buffer.region()));
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered->address.raw(), buffer.address_of(function));
}

TEST(ScanResolve, PrologueFallbackRequireIdentityWithoutWitnessFailsClosed)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_e9_jump(function, trampoline);
    buffer.put(function + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};

    // RequireIdentity with no witness has nothing to confirm the recovered site with, so it must refuse it. This
    // mirrors anchor::Anchor::require_validator rejecting a resolvable anchor that carries no validator: the strict
    // policy never trusts an unverifiable recovery.
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::RequireIdentity});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::PrologueIdentityRejected);
}

TEST(ScanResolve, PrologueFallbackRequireIdentityAcceptsAConfirmingWitness)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_e9_jump(function, trampoline);
    buffer.put(function + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};

    // A realistic witness corroborates the recovered address against an independently known landmark (here the true
    // function address, passed through context). It confirms the site, so RequireIdentity recovers exactly as the
    // structural path would, proving the gate does not reject a genuine recovery.
    const std::uintptr_t expected = buffer.address_of(function);
    const scan::FallbackWitness witness{
        .predicate = +[](std::int64_t addr, const void *ctx) noexcept
                     { return static_cast<std::uintptr_t>(addr) == *static_cast<const std::uintptr_t *>(ctx); },
        .context = &expected};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder,
                                                     .scope = buffer.region(),
                                                     .fallback_policy = scan::FallbackPolicy::RequireIdentity,
                                                     .fallback_witness = witness});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function));
    EXPECT_EQ(hit->winning_name, "hooked");
}

TEST(ScanResolve, PrologueFallbackRequireIdentityKeepsTryingUntilAWitnessConfirms)
{
    // Two independently E9-hooked functions in one image, each with its own distinctive literal tail. The ladder lists
    // the near-twin (candidate 0) ahead of the intended function (candidate 1). Under RequireIdentity the witness
    // rejects the twin's recovered site and confirms only the intended one, so the gate must reject candidate 0's
    // structural recovery, keep walking the ladder, and accept candidate 1. A gate that returned on the first rejection
    // instead of continuing would fail the whole request closed and never reach the intended function, so this pins the
    // multi-candidate keep-trying behavior the single-candidate tests above cannot exercise.
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    const std::size_t twin = 0x100;
    const std::size_t twin_trampoline = 0x800;
    buffer.put_e9_jump(twin, twin_trampoline);
    buffer.put(twin + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(twin_trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});

    const std::size_t intended = 0x300;
    const std::size_t intended_trampoline = 0x900;
    buffer.put_e9_jump(intended, intended_trampoline);
    buffer.put(intended + 5, {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C});
    buffer.put(intended_trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});

    // Each candidate's signature is its own function's UNHOOKED prologue plus that function's distinctive tail, so the
    // rebuilt E9 pattern for candidate 0 matches uniquely at the twin and the one for candidate 1 uniquely at the
    // intended function.
    const std::array<Candidate, 2> ladder = {
        Candidate::direct("twin", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD")),
        Candidate::direct("intended", scan::Pattern::literal("55 48 89 E5 90 A1 B2 C3 D4 E5 F6 17 28 39 4A 5B 6C"))};

    // The witness confirms only the intended function's address (passed through context), so it rejects the twin.
    const std::uintptr_t expected = buffer.address_of(intended);
    const scan::FallbackWitness witness{
        .predicate = +[](std::int64_t addr, const void *ctx) noexcept
                     { return static_cast<std::uintptr_t>(addr) == *static_cast<const std::uintptr_t *>(ctx); },
        .context = &expected};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder,
                                                     .scope = buffer.region(),
                                                     .fallback_policy = scan::FallbackPolicy::RequireIdentity,
                                                     .fallback_witness = witness});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(intended));
    EXPECT_EQ(hit->winning_name, "intended");
}

TEST(ScanResolve, PrologueFallbackWarnOnlyRecoversDespiteAWitnessMismatch)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_e9_jump(function, trampoline);
    buffer.put(function + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};

    // WarnOnly surfaces a witness disagreement as a log line but does not veto the recovery, so a rejecting witness
    // must leave the resolved address unchanged. This is the observe-before-enforce mode: a consumer wires the witness
    // to detect near-twin drift in logs first, then promotes the policy to RequireIdentity once confident.
    const scan::FallbackWitness witness{.predicate = +[](std::int64_t, const void *) noexcept { return false; },
                                        .context = nullptr};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder,
                                                     .scope = buffer.region(),
                                                     .fallback_policy = scan::FallbackPolicy::WarnOnly,
                                                     .fallback_witness = witness});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function));
    EXPECT_EQ(hit->winning_name, "hooked");
}

TEST(ScanResolve, PrologueFallbackOffAttemptsNoRecovery)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_e9_jump(function, trampoline);
    buffer.put(function + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};

    // The default Off policy attempts no prologue reconstruction, so a function only reachable through the fallback
    // (its direct prologue is overwritten by the E9) stays a clean miss rather than resolving to its hooked site.
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, PrologueFallbackShortTailIsNotApplicable)
{
    ReadableBuffer buffer(0x400);
    // A Direct candidate that misses directly and whose literal tail (after the five prologue bytes) is only nine
    // literals, below the ten-literal floor, so no shape is applicable.
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("short", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88"))};
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::PrologueFallbackNotApplicable);
}

TEST(ScanResolve, PrologueFallbackRejectsBoundedJumpPattern)
{
    // A Direct candidate that carries a bounded jump cannot be prologue-rebuilt: flat byte/mask concatenation would
    // drop the variable gap and match a wrong, gap-collapsed shape. Even with a literal tail well above the ten-literal
    // floor the fallback must fail closed as not-applicable (a clean miss), never a silently-wrong recovery. The
    // jump-bearing tail still resolves through the normal direct scan when it is present.
    ReadableBuffer buffer(0x400);
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("jumpy", scan::Pattern::literal("55 48 89 E5 90 [1-2] 11 22 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

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
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

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
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

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
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

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
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

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
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

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
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = scope.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), scope.address_of(function));
}

TEST(ScanResolve, PrologueFallbackRejectsAmbiguousRebuiltPattern)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // The same hooked-prologue shape and identical literal tail appear at two sites, so the rebuilt pattern matches
    // twice. A genuine sibling-mod hook rewrites exactly one prologue, so two matches make recovery ambiguous: it must
    // fail closed with the distinct PrologueFallbackAmbiguous rather than commit to an arbitrary site, so a caller can
    // tell "the surviving tail is not unique" from a plain miss.
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
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::PrologueFallbackAmbiguous);
}

// A jump patch that splits an instruction steals the whole straddling instruction, so the overwritten span rounds up
// past the patch minimum and the installer NOP-pads (or orphans) the excess. Recovery must decode the original leading
// instructions to that rounded boundary and match the excess don't-care, rather than assume a fixed patch width --
// otherwise a prologue whose instructions do not sum to exactly five bytes never recovers.
TEST(ScanResolve, PrologueFallbackUsesInstructionRoundedStolenSpan)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // Unhooked prologue: push rbp; mov rbp, rsp; sub rsp, 0x20 == 55 | 48 89 E5 | 48 83 EC 20 (1 + 3 + 4 = 8 bytes).
    // The five-byte E9 patch splits the sub at offset four, so the installer steals eight bytes and NOP-pads bytes five
    // through seven. The direct scan misses (the eight leading bytes are gone), and recovery must round to eight.
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_e9_jump(function, trampoline);
    buffer.put(function + 5, {0x90, 0x90, 0x90}); // NOP pad for the three-byte rounded excess
    buffer.put(function + 8, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});

    const std::array<Candidate, 1> ladder = {Candidate::direct(
        "hooked", scan::Pattern::literal("55 48 89 E5 48 83 EC 20 11 22 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function));
    EXPECT_EQ(hit->winning_name, "hooked");

    // Some installers write only the five-byte jump and leave the rest of the straddled instruction in place.
    buffer.put(function + 5, {0x83, 0xEC, 0x20});
    const auto orphaned_tail = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});
    ASSERT_TRUE(orphaned_tail.has_value());
    EXPECT_EQ(orphaned_tail->address.raw(), buffer.address_of(function));
}

TEST(ScanResolve, PrologueFallbackRoundsFf25StolenSpan)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // The 14-byte absolute FF 25 patch splits the final four-byte instruction in this 17-byte prologue. Recovery must
    // round the stolen span to 17 and ignore the three padding bytes before matching the surviving tail.
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_ff25_abs64(function, buffer.address_of(trampoline));
    buffer.put(function + 14, {0x90, 0x90, 0x90});
    buffer.put(function + 17, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});

    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 48 83 EC 20 48 89 5C 24 08 48 83 EC 20 "
                                                           "11 22 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(function));
}

// When the original leading bytes cannot be decoded to the patch minimum -- a wildcard sits inside the span the jump
// would overwrite -- the stolen span is unknown, so no shape applies and recovery reports the distinct
// PrologueFallbackNotApplicable rather than guessing a fixed width against undecodable bytes.
TEST(ScanResolve, PrologueFallbackUndecodableLeadingSpanIsNotApplicable)
{
    ReadableBuffer buffer(0x400);
    // A wildcard at the fourth prologue byte truncates the mov before it decodes, so the five-byte span cannot be
    // instruction-rounded. The literal tail is well over the floor, so only the undecodable leading span is at issue.
    const std::array<Candidate, 1> ladder = {Candidate::direct(
        "wildcard-prologue", scan::Pattern::literal("55 48 89 ?? 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::PrologueFallbackNotApplicable);
}

// A wildcarded RipRelative pattern can byte-match an instruction whose opcode or addressing form drifted from the
// declared layout. Applying the declared displacement to that instruction would read a plausible-but-wrong disp32 and
// resolve a wrong target, so resolution decode-verifies the live instruction and rejects a drifted or non-RIP match.
TEST(ScanResolve, RipRelativeRejectsInstructionDrift)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());

    // 48 89 E5 == mov rbp, rsp: a three-byte register-to-register move with no RIP-relative operand. The four trailing
    // bytes are a displacement that WOULD resolve into the buffer if the (wrong) declared seven-byte RIP layout were
    // trusted. The wildcarded pattern byte-matches the 48 89 prefix, but decode-verify sees a length-three non-memory
    // instruction and refuses it, so the drifted site never resolves to the wrong address.
    const std::size_t match = 0x100;
    buffer.put(match, {0x48, 0x89, 0xE5});
    buffer.put_disp32(match + 3, 0x10);

    const std::array<Candidate, 1> ladder = {
        Candidate::rip_relative("drift", scan::Pattern::literal("48 89 ?? ?? ?? ?? ??"), 3, 7)};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, RipRelativeSemanticDecodeStopsAtTheInstructionBoundary)
{
    constexpr std::size_t PAGE_SIZE = 0x1000;
    ExecutableBuffer buffer(PAGE_SIZE * 2);
    ASSERT_TRUE(buffer.valid());

    // A complete seven-byte instruction ends at the last byte of the first page. The next page is inaccessible, so a
    // decoder that unnecessarily reads a 15-byte maximum window rejects this otherwise valid candidate.
    const std::size_t instruction = PAGE_SIZE - 7;
    const std::size_t target = 0x100;
    buffer.put(instruction, {0x48, 0x8B, 0x05});
    const auto displacement = static_cast<std::int32_t>(static_cast<std::int64_t>(target) - PAGE_SIZE);
    buffer.put_disp32(instruction + 3, displacement);
    ASSERT_TRUE(buffer.protect(PAGE_SIZE, PAGE_SIZE, PAGE_NOACCESS));

    const std::array<Candidate, 1> ladder = {
        Candidate::rip_relative("boundary", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 3, 7)};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = buffer.region()});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->address.raw(), buffer.address_of(target));
}

TEST(ScanResolve, RipRelativeSignedDisplacementArithmeticIsModular)
{
    constexpr std::uintptr_t near_signed_max =
        static_cast<std::uintptr_t>(std::numeric_limits<std::int64_t>::max()) - 100;
    constexpr std::uintptr_t positive =
        detail::add_rip_displacement(near_signed_max, 7, std::numeric_limits<std::int32_t>::max());
    constexpr std::uintptr_t negative = detail::add_rip_displacement(100, 7, std::numeric_limits<std::int32_t>::min());

    static_assert(positive == near_signed_max + 7 + std::uintptr_t{0x7FFFFFFF});
    static_assert(negative == std::uintptr_t{107} - std::uintptr_t{0x80000000});
    SUCCEED();
}

TEST(ScanResolve, PrologueFallbackNineByteTailIsNotApplicable)
{
    ReadableBuffer buffer(0x400);
    // Exactly nine literal tail bytes after the five-byte prologue -- one below the ten-literal floor -- so no shape is
    // applicable and the resolver reports the distinct PrologueFallbackNotApplicable rather than a plain miss. Pins the
    // reject side of the floor (the recovery tests above pin the accept side at twelve).
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("nine", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99"))};
    const auto hit = scan::resolve(scan::ScanRequest{
        .ladder = ladder, .scope = buffer.region(), .fallback_policy = scan::FallbackPolicy::WarnOnly});

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
        (void)memory::init_cache();
        sr_reset();
    }
    void TearDown() override { memory::shutdown_cache(); }
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

    // The AOB is derived from the marker's own bytes at run time rather than spelled as a `Pattern::literal`. A
    // consteval literal is a compile-time constant, and an optimizing build materializes it into THIS image's
    // read-only data beside the marker, where it is a second, genuine occurrence of the sixteen bytes and correctly
    // demotes a uniqueness check to ambiguous. That copy is an initializer constant, not a live object, so no
    // exclusion API can enumerate it; the only sound fix is for the test not to plant it. `g_host_scan_marker` is
    // volatile, so these reads cannot be folded back into a second copy either.
    std::string aob;
    for (std::size_t i = 0; i < sizeof(g_host_scan_marker); ++i)
    {
        static constexpr char hex_digits[] = "0123456789ABCDEF";
        const auto value = static_cast<unsigned char>(g_host_scan_marker[i]);
        if (i != 0)
        {
            aob.push_back(' ');
        }
        aob.push_back(hex_digits[value >> 4]);
        aob.push_back(hex_digits[value & 0x0F]);
    }
    const auto pattern = scan::Pattern::compile(aob);
    ASSERT_TRUE(pattern.has_value());

    const std::array<Candidate, 1> ladder = {Candidate::direct("host-marker", *pattern)};
    const auto hit = scan::resolve(scan::ScanRequest{.ladder = ladder, .scope = Region::host()});

    ASSERT_TRUE(hit.has_value()) << DetourModKit::to_string(hit.error().code);
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
        ErrorCode::PrologueFallbackAmbiguous,
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
        ErrorCode::BudgetExceeded,
        ErrorCode::IncompleteScan,
        ErrorCode::NotAuthoritative,
        ErrorCode::MalformedQueryText,
    };
    for (const ErrorCode code : codes)
    {
        EXPECT_FALSE(to_string(code).empty());
    }

    // Non-emptiness alone is satisfied by the trailing UnknownCode arm, so a code with no case label of its own would
    // still pass the loop above. to_string is constexpr, so pin the scan-group spellings at compile time instead: a
    // dropped case label fails the build rather than silently degrading a typed outcome to an unnamed one.
    static_assert(to_string(ErrorCode::BudgetExceeded) == "BudgetExceeded");
    static_assert(to_string(ErrorCode::IncompleteScan) == "IncompleteScan");
    static_assert(to_string(ErrorCode::NotAuthoritative) == "NotAuthoritative");
    static_assert(to_string(ErrorCode::MalformedQueryText) == "MalformedQueryText");
    static_assert(to_string(ErrorCode::PrologueFallbackAmbiguous) == "PrologueFallbackAmbiguous");
}

// borrow_code_target packs the code/hook-target resolution policy into a borrowed ScanRequest: Pages::Executable so an
// instruction signature cannot alias a data-section run, a final executable-address gate for every backend, UniqueFirst
// so the unique-only tiers lead, a WarnOnly fallback policy so a target another mod already inline-hooked is recovered,
// and require_unique kept true. The default request keeps Pages::Readable for the data / RTTI / string tiers.
TEST(ScanResolve, BorrowCodeTargetPresetsTheCodeTargetPolicy)
{
    ReadableBuffer buffer(0x400);
    const std::array<Candidate, 1> ladder = {Candidate::direct("code-sig", scan::Pattern::literal("DE AD BE EF"))};

    const scan::ScanRequest request = scan::borrow_code_target(ladder, "hook-target", buffer.region());

    EXPECT_EQ(request.pages, scan::Pages::Executable);
    EXPECT_EQ(request.order, scan::CandidateOrder::UniqueFirst);
    EXPECT_EQ(request.fallback_policy, scan::FallbackPolicy::WarnOnly);
    EXPECT_TRUE(request.require_unique);
    EXPECT_TRUE(request.require_executable_result);
    EXPECT_EQ(request.label, "hook-target");
    EXPECT_EQ(request.scope.base.raw(), buffer.region().base.raw());
    ASSERT_EQ(request.ladder.size(), 1U);
    EXPECT_EQ(request.ladder[0].name(), "code-sig");
}

TEST(ScanResolve, BorrowCodeTargetForwardsRequireIdentityAndWitness)
{
    ExecutableBuffer buffer(0x1000);
    ASSERT_TRUE(buffer.valid());
    const std::size_t function = 0x100;
    const std::size_t trampoline = 0x800;
    buffer.put_e9_jump(function, trampoline);
    buffer.put(function + 5, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xDD});
    buffer.put(trampoline, {0x48, 0x89, 0x5C, 0x24, 0x08});
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("hooked", scan::Pattern::literal("55 48 89 E5 90 11 22 33 44 55 66 77 88 99 AA BB DD"))};

    // borrow_code_target must forward the RequireIdentity policy AND the witness into the request, not merely set its
    // own WarnOnly default. A rejecting witness proves the whole preset path fails closed end-to-end: a mis-forward
    // that dropped the witness would recover the hooked site instead of refusing it.
    const scan::FallbackWitness witness{.predicate = +[](std::int64_t, const void *) noexcept { return false; },
                                        .context = nullptr};
    const auto hit = scan::resolve(scan::borrow_code_target(ladder, "hook-target", buffer.region(),
                                                            scan::FallbackPolicy::RequireIdentity, witness));

    ASSERT_FALSE(hit.has_value());
    EXPECT_EQ(hit.error().code, ErrorCode::PrologueIdentityRejected);
}

// End-to-end: a request built by borrow_code_target resolves a genuine code match (the Executable narrowing it presets
// does not reject a match that really sits on an executable page), and excludes a match that lives only on a
// non-executable data page (the aliasing footgun the preset closes).
TEST(ScanResolve, BorrowCodeTargetResolvesCodeAndExcludesDataMatch)
{
    ExecutableBuffer code(0x400);
    if (!code.valid())
    {
        GTEST_SKIP() << "could not allocate an executable buffer";
    }
    code.put(0x80, {0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22});
    const std::array<Candidate, 1> ladder = {
        Candidate::direct("code-sig", scan::Pattern::literal("DE AD BE EF 11 22"))};

    const auto code_hit = scan::resolve(scan::borrow_code_target(ladder, "code", code.region()));
    ASSERT_TRUE(code_hit.has_value()) << code_hit.error().message();
    EXPECT_EQ(code_hit->address.raw(), code.address_of(0x80));

    // The same signature planted only on a readable-but-not-executable heap page is excluded by the preset's
    // Pages::Executable, so the resolve fails closed instead of committing to a data-page address.
    ReadableBuffer data(0x400);
    data.put(0x80, {0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22});
    const auto data_hit = scan::resolve(scan::borrow_code_target(ladder, "data", data.region()));
    // Excluded: the match sits only on a non-executable page, so the preset's Pages::Executable never sees it and the
    // resolve fails closed. The exact failure code depends on the preset's prologue fallback (which then also finds no
    // executable prologue to rebuild), so assert the fail-closed outcome rather than a specific enum.
    ASSERT_FALSE(data_hit.has_value());
}

// Pages::Executable filters only the byte-match location. A RIP-relative candidate can match an instruction then
// resolve its displacement into a data page, so borrow_code_target must apply its final-address gate after resolution.
TEST(ScanResolve, BorrowCodeTargetRejectsCodeMatchThatResolvesToData)
{
    ExecutableBuffer image(0x2000);
    if (!image.valid())
    {
        GTEST_SKIP() << "could not allocate a split-protection image";
    }
    ASSERT_TRUE(image.protect(0x1000, 0x1000, PAGE_READWRITE));

    constexpr std::size_t code_offset = 0x100;
    constexpr std::size_t data_offset = 0x1100;
    image.put(code_offset, {0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00}); // mov rax, [rip+disp32]
    const auto next_ip = static_cast<std::int64_t>(image.address_of(code_offset) + 7);
    const auto displacement =
        static_cast<std::int32_t>(static_cast<std::int64_t>(image.address_of(data_offset)) - next_ip);
    image.put_disp32(code_offset + 3, displacement);
    image.put(data_offset, {0x11, 0x22, 0x33, 0x44});

    const std::array<Candidate, 1> ladder = {
        Candidate::rip_relative("code-to-data", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 3, 7)};
    const scan::ScanRequest byte_filtered{
        .ladder = ladder,
        .label = "code-to-data",
        .scope = image.region(),
        .pages = scan::Pages::Executable,
    };
    const auto unconstrained = scan::resolve(byte_filtered);
    ASSERT_TRUE(unconstrained.has_value()) << unconstrained.error().message();
    EXPECT_EQ(unconstrained->address.raw(), image.address_of(data_offset));

    const auto code_target = scan::resolve(scan::borrow_code_target(ladder, "code-to-data", image.region()));
    ASSERT_FALSE(code_target.has_value());
    EXPECT_EQ(code_target.error().code, ErrorCode::NoMatch);
}

TEST(ScanResolve, InvalidPageClassFailsClosed)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x80, {0xDE, 0xAD, 0xBE, 0xEF});
    const std::array<Candidate, 1> ladder = {Candidate::direct("invalid-pages", scan::Pattern::literal("DE AD BE EF"))};
    constexpr auto invalid_pages = static_cast<scan::Pages>(0xFFU);

    const scan::ScanRequest request{
        .ladder = ladder,
        .scope = buffer.region(),
        .pages = invalid_pages,
    };
    const auto resolved = scan::resolve(request);
    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error().code, ErrorCode::InvalidArg);

    const auto matched = scan::scan(scan::Pattern::literal("DE AD BE EF"), buffer.region(), 1, invalid_pages);
    ASSERT_FALSE(matched.has_value());
    EXPECT_EQ(matched.error().code, ErrorCode::InvalidArg);
}
