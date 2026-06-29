#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include <windows.h>

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

    private:
        std::byte *m_base = nullptr;
        std::size_t m_size = 0;
    };
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
    ASSERT_NE(direct.pattern(), nullptr);
    EXPECT_EQ(direct.pattern()->size(), 2U);
    EXPECT_EQ(direct.displacement(), -4);
    EXPECT_EQ(direct.instruction_length(), 0U);
    EXPECT_TRUE(direct.query().empty());

    const Candidate rip = Candidate::rip_relative("rip", scan::Pattern::literal("48 8B 05 ?? ?? ?? ??"), 3, 7);
    EXPECT_EQ(rip.mode(), scan::Mode::RipRelative);
    ASSERT_NE(rip.pattern(), nullptr);
    EXPECT_EQ(rip.displacement(), 3);
    EXPECT_EQ(rip.instruction_length(), 7U);

    const Candidate rtti = Candidate::rtti_vtable("rtti", ".?AVType@@");
    EXPECT_EQ(rtti.mode(), scan::Mode::RttiVtable);
    EXPECT_EQ(rtti.pattern(), nullptr);
    EXPECT_EQ(rtti.query(), ".?AVType@@");

    const Candidate xref = Candidate::string_xref("xref", "literal");
    EXPECT_EQ(xref.mode(), scan::Mode::StringXref);
    EXPECT_EQ(xref.pattern(), nullptr);
    EXPECT_EQ(xref.query(), "literal");
}

TEST(ScanResolve, RttiVtableMissFallsThroughToByteCandidate)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});

    // The RTTI tier cannot resolve a bogus type name against a heap buffer, so the cascade must fall through to the
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
    // A sole string-xref candidate whose literal is absent fails closed as NoMatch, not AllPatternsInvalid (a
    // non-byte candidate counts as a valid attempt).
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

TEST(ScanResolve, UniqueFirstOrderingReachesTheTextTierFirst)
{
    ReadableBuffer buffer(0x400);
    buffer.put(0x100, {0xDE, 0xAD, 0xBE, 0xEF});

    // With AsDeclared the byte candidate (declared first) wins; with UniqueFirst the text tier is tried first, misses
    // against a heap buffer, and the cascade still falls through to the byte candidate. Either way the byte candidate
    // resolves, proving the order field is threaded into resolve() without changing the valid outcome.
    const std::array<Candidate, 2> ladder = {
        Candidate::direct("marker", scan::Pattern::literal("DE AD BE EF")),
        Candidate::rtti_vtable("bogus", ".?AVNope@@"),
    };
    const auto hit = scan::resolve(
        scan::ScanRequest{.ladder = ladder, .scope = buffer.region(), .order = scan::CandidateOrder::UniqueFirst});

    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->winning_name, "marker");
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
