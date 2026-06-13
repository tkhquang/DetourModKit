#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>

#include "DetourModKit/anchors.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/profile.hpp"
#include "DetourModKit/scanner.hpp"

// windows.h after project headers to avoid macro conflicts.
#include <windows.h>

using namespace DetourModKit;

namespace
{
    // A committed page (0xCC filled) for planting instruction bytes / markers that the cascade- and decode-backed
    // anchor kinds resolve against. Mirrors the Region fixture from test_anchors.cpp.
    class Region
    {
    public:
        Region()
        {
            m_base = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (m_base)
            {
                std::memset(m_base, 0xCC, 0x1000);
            }
        }

        ~Region()
        {
            if (m_base)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        Region(const Region &) = delete;
        Region &operator=(const Region &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        void put(std::size_t off, std::initializer_list<std::uint8_t> bytes) noexcept
        {
            auto *p = static_cast<std::uint8_t *>(m_base);
            std::size_t i = 0;
            for (const std::uint8_t b : bytes)
            {
                p[off + i++] = b;
            }
        }

        [[nodiscard]] std::uintptr_t addr(std::size_t off) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base) + off;
        }

        [[nodiscard]] Memory::ModuleRange range() const noexcept
        {
            const auto base = reinterpret_cast<std::uintptr_t>(m_base);
            return Memory::ModuleRange{base, base + 0x1000};
        }

    private:
        void *m_base = nullptr;
    };

    // Deny slot for the CodeOperand backend, by enum index, used across the deny-list tests.
    constexpr std::size_t CODE_OPERAND_SLOT = static_cast<std::size_t>(Anchors::AnchorKind::CodeOperand);
    // Deny slot for the StringXref backend, used to prove a denied kind never substitutes another value.
    constexpr std::size_t STRING_XREF_SLOT = static_cast<std::size_t>(Anchors::AnchorKind::StringXref);
} // anonymous namespace

// --- apply_profile: broad-mode default is widen-only ---

TEST(ProfileTest, ProfileBroadDefaultWidensQuery)
{
    ScanProfile profile{};
    profile.default_broad_string_xref = true;

    Scanner::StringRefQuery narrow{};
    narrow.text = "marker";
    narrow.broad_match = false;
    // A query that left broad_match at its default is widened on by the profile default.
    EXPECT_TRUE(apply_profile(profile, narrow).broad_match);

    Scanner::StringRefQuery already_broad{};
    already_broad.text = "marker";
    already_broad.broad_match = true;
    // An explicit broad query stays broad.
    EXPECT_TRUE(apply_profile(profile, already_broad).broad_match);
}

TEST(ProfileTest, ProfileNeverDowngradesBroad)
{
    ScanProfile profile{};
    profile.default_broad_string_xref = false; // profile does not default broad on

    Scanner::StringRefQuery query{};
    query.text = "marker";
    query.broad_match = true; // explicit per-call choice

    // The profile can only widen, never disable: an explicit broad_match=true is never downgraded.
    EXPECT_TRUE(apply_profile(profile, query).broad_match);
}

// --- order_candidates: index permutation ---

TEST(ProfileTest, OrderCandidatesAsDeclaredIsIdentity)
{
    ScanProfile profile{}; // CandidateOrder::AsDeclared by default

    Scanner::AddrCandidate cands[] = {
        {"a", "AA", Scanner::ResolveMode::Direct, 0, 0},
        {"b", "BB", Scanner::ResolveMode::Direct, 0, 0},
        {"c", "CC", Scanner::ResolveMode::Direct, 0, 0},
    };
    std::array<std::size_t, 3> out{};

    const std::size_t n = order_candidates(profile, cands, out);
    ASSERT_EQ(n, 3u);
    EXPECT_EQ(out[0], 0u);
    EXPECT_EQ(out[1], 1u);
    EXPECT_EQ(out[2], 2u);
}

TEST(ProfileTest, OrderCandidatesUniqueFirstPromotes)
{
    ScanProfile profile{};
    profile.candidate_order = CandidateOrder::UniqueFirst;

    // Declared order [non-unique, unique]; UniqueFirst must promote the strict candidate ahead -> indices [1, 0].
    Scanner::AddrCandidate cands[] = {
        {"broad", "AA", Scanner::ResolveMode::Direct, 0, 0, false}, // require_unique = false
        {"strict", "BB", Scanner::ResolveMode::Direct, 0, 0, true}, // require_unique = true
    };
    std::array<std::size_t, 2> out{};

    const std::size_t n = order_candidates(profile, cands, out);
    ASSERT_EQ(n, 2u);
    EXPECT_EQ(out[0], 1u); // the unique candidate is tried first
    EXPECT_EQ(out[1], 0u); // the non-unique fallback follows
}

TEST(ProfileTest, ResolveWithProfileAppliesCandidateOrderToRipGlobal)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0xAA});
    reg.put(0x180, {0xAA}); // second broad occurrence
    reg.put(0x200, {0xBB}); // unique strict occurrence

    Scanner::AddrCandidate cands[] = {
        {"broad", "AA", Scanner::ResolveMode::Direct, 0, 0, false},
        {"strict", "BB", Scanner::ResolveMode::Direct, 0, 0, true},
    };

    Anchors::Anchor anchor{};
    anchor.label = "ordered-global";
    anchor.kind = Anchors::AnchorKind::RipGlobal;
    anchor.site = cands;

    ScanProfile as_declared{};
    const auto declared = Anchors::resolve_with_profile(anchor, as_declared, reg.range());
    ASSERT_EQ(declared.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(declared.value), reg.addr(0x100));

    ScanProfile unique_first{};
    unique_first.candidate_order = CandidateOrder::UniqueFirst;
    const auto promoted = Anchors::resolve_with_profile(anchor, unique_first, reg.range());
    ASSERT_EQ(promoted.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(promoted.value), reg.addr(0x200));

    // The caller-owned candidate table remains in declared order; the profile builds a local reordered span.
    EXPECT_EQ(cands[0].name, "broad");
    EXPECT_EQ(cands[1].name, "strict");
}

// --- CandidateOrder mapping totality ---

TEST(ProfileTest, CandidateOrderToStringTotal)
{
    constexpr CandidateOrder all[] = {CandidateOrder::AsDeclared, CandidateOrder::UniqueFirst};
    static_assert(noexcept(candidate_order_to_string(CandidateOrder::AsDeclared)));
    for (const CandidateOrder order : all)
    {
        EXPECT_FALSE(candidate_order_to_string(order).empty());
    }
}

// --- Backend deny-list: fail closed, never substitute ---

TEST(ProfileTest, ProfileDenyBackendFailsClosed)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor anchor{};
    anchor.label = "stride";
    anchor.kind = Anchors::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_kind = Scanner::OperandKind::Immediate;
    anchor.operand_index = 1;

    // Control: without a deny, the CodeOperand backend resolves the planted immediate.
    ScanProfile allow{};
    const auto allowed = Anchors::resolve_with_profile(anchor, allow, reg.range());
    EXPECT_EQ(allowed.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(allowed.value, 0xF0);

    // Denying the CodeOperand backend fails closed before any scan: Failed, value reset to 0.
    ScanProfile deny{};
    deny.deny_backend[CODE_OPERAND_SLOT] = true;
    const auto denied = Anchors::resolve_with_profile(anchor, deny, reg.range());
    EXPECT_EQ(denied.status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(denied.value, 0);
}

TEST(ProfileTest, ProfileDenyDoesNotSubstitute)
{
    Region reg;
    ASSERT_TRUE(reg.ok());

    Anchors::Anchor anchor{};
    anchor.label = "string-xref";
    anchor.kind = Anchors::AnchorKind::StringXref;
    anchor.xref_text = "AnchorRegistryString";

    // A denied StringXref must report Failed and never silently swap to another backend or invent a value.
    ScanProfile deny{};
    deny.deny_backend[STRING_XREF_SLOT] = true;
    const auto result = Anchors::resolve_with_profile(anchor, deny, reg.range());
    EXPECT_EQ(result.status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.kind, Anchors::AnchorKind::StringXref);
}

TEST(ProfileTest, QuorumWithDeniedSubAnchorFailsClosed)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };
    Anchors::Anchor code{};
    code.kind = Anchors::AnchorKind::CodeOperand;
    code.site = cands;
    code.operand_index = 1;

    Anchors::Anchor expected{};
    expected.kind = Anchors::AnchorKind::Manual;
    expected.manual_value = 0xF0;

    Anchors::Anchor quorum{};
    quorum.label = "quorum";
    quorum.kind = Anchors::AnchorKind::Quorum;
    quorum.quorum_a = &code;
    quorum.quorum_b = &expected;

    // Without a deny the two signals corroborate and the quorum resolves.
    ScanProfile allow{};
    const auto allowed = Anchors::resolve_with_profile(quorum, allow, reg.range());
    EXPECT_EQ(allowed.status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(allowed.value, 0xF0);

    // The profile threads into sub-anchors: denying the CodeOperand sub-anchor fails the quorum closed.
    ScanProfile deny{};
    deny.deny_backend[CODE_OPERAND_SLOT] = true;
    const auto denied = Anchors::resolve_with_profile(quorum, deny, reg.range());
    EXPECT_EQ(denied.status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(denied.value, 0);
}

TEST(ProfileTest, ProfileResolveAllWithProfileCarriesDeny)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    Scanner::AddrCandidate cands[] = {
        {"add-imm", "48 05 F0 00 00 00", Scanner::ResolveMode::Direct, 0, 0},
    };

    Anchors::Anchor lit{};
    lit.label = "lit";
    lit.kind = Anchors::AnchorKind::Manual;
    lit.manual_value = 7;

    Anchors::Anchor code{};
    code.label = "code";
    code.kind = Anchors::AnchorKind::CodeOperand;
    code.site = cands;
    code.operand_index = 1;

    const Anchors::Anchor table[] = {lit, code};
    Anchors::ResolvedAnchor out[2];

    // Deny the CodeOperand backend: the Manual entry still resolves, the denied entry fails closed in parallel.
    ScanProfile deny{};
    deny.deny_backend[CODE_OPERAND_SLOT] = true;
    const std::size_t n = Anchors::resolve_all_with_profile(table, out, deny, reg.range());
    ASSERT_EQ(n, 2u);
    EXPECT_EQ(out[0].status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(out[0].value, 7);
    EXPECT_EQ(out[1].status, Anchors::AnchorStatus::Failed);
    EXPECT_EQ(out[1].value, 0);
    EXPECT_EQ(out[1].kind, Anchors::AnchorKind::CodeOperand);
}

TEST(ProfileTest, ResolveAllWithProfileParallelMatchesSerialReport)
{
    Region reg;
    ASSERT_TRUE(reg.ok());
    reg.put(0x100, {0xAA});
    reg.put(0x180, {0xAA}); // second broad occurrence
    reg.put(0x200, {0xBB}); // unique strict occurrence

    Scanner::AddrCandidate cands[] = {
        {"broad", "AA", Scanner::ResolveMode::Direct, 0, 0, false},
        {"strict", "BB", Scanner::ResolveMode::Direct, 0, 0, true},
    };

    Anchors::Anchor manual{};
    manual.label = "manual";
    manual.kind = Anchors::AnchorKind::Manual;
    manual.manual_value = 7;

    Anchors::Anchor ordered{};
    ordered.label = "ordered-global";
    ordered.kind = Anchors::AnchorKind::RipGlobal;
    ordered.site = cands;

    Anchors::Anchor denied{};
    denied.label = "denied-code";
    denied.kind = Anchors::AnchorKind::CodeOperand;
    denied.site = cands;

    const Anchors::Anchor table[] = {manual, ordered, denied};

    ScanProfile profile{};
    profile.candidate_order = CandidateOrder::UniqueFirst;
    profile.deny_backend[CODE_OPERAND_SLOT] = true;

    Anchors::ResolvedAnchor serial[3];
    Anchors::ResolvedAnchor parallel[3];
    const std::size_t serial_count = Anchors::resolve_all_with_profile(table, serial, profile, reg.range());
    const std::size_t parallel_count =
        Anchors::resolve_all_with_profile_parallel(table, parallel, profile, reg.range(), 4);
    ASSERT_EQ(parallel_count, serial_count);

    for (std::size_t i = 0; i < serial_count; ++i)
    {
        EXPECT_EQ(parallel[i].label, serial[i].label) << "entry=" << i;
        EXPECT_EQ(parallel[i].kind, serial[i].kind) << "entry=" << i;
        EXPECT_EQ(parallel[i].status, serial[i].status) << "entry=" << i;
        EXPECT_EQ(parallel[i].value, serial[i].value) << "entry=" << i;
    }
    ASSERT_EQ(parallel[1].status, Anchors::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(parallel[1].value), reg.addr(0x200));
    EXPECT_EQ(parallel[2].status, Anchors::AnchorStatus::Failed);
}
