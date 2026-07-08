#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <initializer_list>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/manifest.hpp"
#include "DetourModKit/scan.hpp"

#include <process.h>
// windows.h after project headers to avoid macro conflicts.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace dmk = DetourModKit;
namespace mf = DetourModKit::manifest;
namespace an = DetourModKit::anchor;
namespace sc = DetourModKit::scan;
namespace hk = DetourModKit::hook;

namespace
{
    // A committed 0xCC-filled page into which a test plants known byte markers, so the byte-scanned signature kinds
    // have a real, uniquely matchable site to resolve inside a bounded Region. PAGE_READWRITE is enough: the bytes are
    // scanned as data, never executed.
    class ScratchPage
    {
    public:
        ScratchPage()
        {
            m_base = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (m_base != nullptr)
            {
                std::memset(m_base, 0xCC, 0x1000);
            }
        }

        ~ScratchPage()
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        ScratchPage(const ScratchPage &) = delete;
        ScratchPage &operator=(const ScratchPage &) = delete;

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

        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{reinterpret_cast<std::uintptr_t>(m_base)}, 0x1000};
        }

    private:
        void *m_base = nullptr;
    };

    // Builds a Manual signature record with an explicit captured fingerprint baseline.
    [[nodiscard]] mf::SignatureRecord manual_record(std::string label, std::int64_t value,
                                                    std::uint64_t expected_fingerprint = 0)
    {
        mf::SignatureRecord record;
        record.label = std::move(label);
        record.kind = an::AnchorKind::Manual;
        record.manual_value = value;
        record.expected_fingerprint = expected_fingerprint;
        return record;
    }

    // Compiles a Manual signature (its ladder is empty by construction, so compile always succeeds).
    [[nodiscard]] mf::Signature manual_signature(std::string label, std::int64_t value,
                                                 std::uint64_t expected_fingerprint = 0)
    {
        return mf::Signature::compile(manual_record(std::move(label), value, expected_fingerprint)).value();
    }

    std::atomic_uint s_temp_path_counter{0};

    [[nodiscard]] std::filesystem::path unique_manifest_path(std::string_view stem)
    {
        const unsigned int counter = s_temp_path_counter.fetch_add(1, std::memory_order_relaxed);
        std::string name = "dmk_manifest_";
        name += stem;
        name += "_";
        name += std::to_string(_getpid());
        name += "_";
        name += std::to_string(counter);
        name += ".signatures.ini";
        return std::filesystem::temp_directory_path() / name;
    }

    // Owns a unique temp manifest path and deletes the file on every scope exit. A gtest ASSERT_* returns early from
    // the test body on failure, so a trailing std::filesystem::remove would be skipped and leak the artifact; tying the
    // cleanup to this guard's destructor keeps the temp directory clean whether the test passes or an assertion aborts
    // it. The constructor also clears any stale file so a test starts from a known-absent state, and both paths use the
    // noexcept remove(path, ec) overload so the destructor never throws.
    class ScopedManifestFile
    {
    public:
        explicit ScopedManifestFile(std::string_view stem) : m_path(unique_manifest_path(stem))
        {
            std::error_code ec;
            std::filesystem::remove(m_path, ec);
        }

        ~ScopedManifestFile()
        {
            std::error_code ec;
            std::filesystem::remove(m_path, ec);
        }

        ScopedManifestFile(const ScopedManifestFile &) = delete;
        ScopedManifestFile &operator=(const ScopedManifestFile &) = delete;

        [[nodiscard]] const std::filesystem::path &path() const noexcept { return m_path; }

    private:
        std::filesystem::path m_path;
    };
} // namespace

// Serialization round-trip: every kind and binding survives serialize -> parse unchanged.

TEST(ManifestSerializeTest, RoundTripsEveryKindAndBinding)
{
    std::vector<mf::SignatureRecord> records;

    // RipGlobal with a two-rung fallback ladder and a mid-hook-register binding.
    {
        mf::SignatureRecord record;
        record.label = "camera.fov_write";
        record.kind = an::AnchorKind::RipGlobal;
        record.module = "engine.dll";
        record.binding.kind = mf::BindingKind::MidHookRegister;
        record.binding.read_register = hk::Gpr::Rcx;
        record.expected_fingerprint = 0x41BB02C9DE7715A0ULL;
        mf::CandidateSpec rung0;
        rung0.name = "fov-direct";
        rung0.mode = sc::Mode::RipRelative;
        rung0.pattern = "F3 0F 11 8D ?? ?? ?? ?? 48 8B";
        rung0.displacement_at = 4;
        rung0.instruction_length = 8;
        mf::CandidateSpec rung1;
        rung1.mode = sc::Mode::StringXref;
        rung1.string_text = "CameraFov";
        rung1.string_broad_match = true;
        record.ladder = {rung0, rung1};
        records.push_back(std::move(record));
    }

    // PointerChain read through a data pointer.
    {
        mf::SignatureRecord record;
        record.label = "player.health";
        record.kind = an::AnchorKind::CodeOperand;
        record.operand_kind = sc::OperandKind::MemoryDisplacement;
        record.operand_index = 1;
        record.byte_width = 4;
        record.binding.kind = mf::BindingKind::PointerChain;
        record.binding.offsets = {0x1C8, -0x40};
        record.binding.value_width = 4;
        mf::CandidateSpec rung;
        rung.mode = sc::Mode::Direct;
        rung.pattern = "48 8B 05 ?? ?? ?? ?? 48 85 C0";
        rung.walk_back = -3;
        record.ladder = {rung};
        records.push_back(std::move(record));
    }

    // VtableIdentity with a vmt-method binding.
    {
        mf::SignatureRecord record;
        record.label = "ai.think_vmethod";
        record.kind = an::AnchorKind::VtableIdentity;
        record.mangled = ".?AVCAIController@@";
        record.binding.kind = mf::BindingKind::VmtMethod;
        record.binding.vmt_index = 7;
        records.push_back(std::move(record));
    }

    // StringXref with an address binding and non-default facets.
    {
        mf::SignatureRecord record;
        record.label = "combat.apply_damage";
        record.kind = an::AnchorKind::StringXref;
        record.xref_text = "CombatSystem::ApplyDamage";
        record.xref_encoding = sc::StringEncoding::Utf16le;
        record.xref_return = sc::XrefReturn::EnclosingFunction;
        record.xref_require_terminator = false;
        records.push_back(std::move(record));
    }

    // Manual literal.
    records.push_back(manual_record("debug.flag_ptr", 0x14000ABCD, 0x9F2C7A10B3D45E88ULL));

    const std::string text = mf::serialize(mf::Manifest{.records = records});
    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), records.size());

    // Re-serializing the parsed records reproduces the exact text: a full structural round-trip.
    EXPECT_EQ(mf::serialize(*parsed), text);

    // Spot-check the fields that carry the repair semantics.
    const mf::SignatureRecord &fov = parsed->records[0];
    EXPECT_EQ(fov.label, "camera.fov_write");
    EXPECT_EQ(fov.kind, an::AnchorKind::RipGlobal);
    EXPECT_EQ(fov.module, "engine.dll");
    EXPECT_EQ(fov.binding.kind, mf::BindingKind::MidHookRegister);
    EXPECT_EQ(fov.binding.read_register, hk::Gpr::Rcx);
    EXPECT_EQ(fov.expected_fingerprint, 0x41BB02C9DE7715A0ULL);
    ASSERT_EQ(fov.ladder.size(), 2u);
    EXPECT_EQ(fov.ladder[0].mode, sc::Mode::RipRelative);
    EXPECT_EQ(fov.ladder[0].pattern, "F3 0F 11 8D ?? ?? ?? ?? 48 8B");
    EXPECT_EQ(fov.ladder[0].displacement_at, 4);
    EXPECT_EQ(fov.ladder[0].instruction_length, 8u);
    EXPECT_EQ(fov.ladder[1].mode, sc::Mode::StringXref);
    EXPECT_EQ(fov.ladder[1].string_text, "CameraFov");
    EXPECT_TRUE(fov.ladder[1].string_broad_match);

    const mf::SignatureRecord &health = parsed->records[1];
    EXPECT_EQ(health.kind, an::AnchorKind::CodeOperand);
    EXPECT_EQ(health.operand_kind, sc::OperandKind::MemoryDisplacement);
    EXPECT_EQ(health.byte_width, 4);
    EXPECT_EQ(health.binding.kind, mf::BindingKind::PointerChain);
    ASSERT_EQ(health.binding.offsets.size(), 2u);
    EXPECT_EQ(health.binding.offsets[0], 0x1C8);
    EXPECT_EQ(health.binding.offsets[1], -0x40);
    EXPECT_EQ(health.binding.value_width, 4);
    EXPECT_EQ(health.ladder[0].walk_back, -3);

    const mf::SignatureRecord &think = parsed->records[2];
    EXPECT_EQ(think.kind, an::AnchorKind::VtableIdentity);
    EXPECT_EQ(think.mangled, ".?AVCAIController@@");
    EXPECT_EQ(think.binding.kind, mf::BindingKind::VmtMethod);
    EXPECT_EQ(think.binding.vmt_index, 7u);

    const mf::SignatureRecord &damage = parsed->records[3];
    EXPECT_EQ(damage.kind, an::AnchorKind::StringXref);
    EXPECT_EQ(damage.xref_text, "CombatSystem::ApplyDamage");
    EXPECT_EQ(damage.xref_encoding, sc::StringEncoding::Utf16le);
    EXPECT_EQ(damage.xref_return, sc::XrefReturn::EnclosingFunction);
    EXPECT_FALSE(damage.xref_require_terminator);

    const mf::SignatureRecord &flag = parsed->records[4];
    EXPECT_EQ(flag.kind, an::AnchorKind::Manual);
    EXPECT_EQ(flag.manual_value, 0x14000ABCD);
    EXPECT_EQ(flag.expected_fingerprint, 0x9F2C7A10B3D45E88ULL);
}

TEST(ManifestSerializeTest, EmptyRecordSetProducesParsableHeaderOnly)
{
    const std::string text = mf::serialize(mf::Manifest{});
    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->records.empty());
}

TEST(ManifestSerializeTest, SignedMinimumManualValueRoundTrips)
{
    std::vector<mf::SignatureRecord> records;
    records.push_back(manual_record("floor", std::numeric_limits<std::int64_t>::min()));

    const std::string text = mf::serialize(mf::Manifest{.records = records});
    EXPECT_NE(text.find("-0x8000000000000000"), std::string::npos);

    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), 1u);
    EXPECT_EQ(parsed->records[0].manual_value, std::numeric_limits<std::int64_t>::min());
}

// Parse fails closed: a manifest that cannot be trusted to describe the signatures faithfully is rejected whole.

TEST(ManifestParseTest, MissingHeaderIsRejected)
{
    const auto parsed = mf::parse("[sig.x]\nkind = manual\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MissingHeader);
}

TEST(ManifestParseTest, EmptyTextReportsMissingHeader)
{
    const auto parsed = mf::parse("");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MissingHeader);
}

TEST(ManifestParseTest, UnsupportedSchemaIsRejected)
{
    const auto parsed = mf::parse("[manifest]\nschema = 2\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MissingHeader);
}

TEST(ManifestParseTest, UnknownKindIsMalformed)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = teleport\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, NonSerializableQuorumKindIsRejected)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = quorum\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, MissingKindIsMalformed)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nbinding = address\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, EmptyLabelIsMalformed)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.]\nkind = manual\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, BadOffsetTokenIsMalformed)
{
    const auto parsed =
        mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = manual\nbinding = pointer_chain\noffsets = 0x10, nope\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, SignedIntegerOverflowIsMalformed)
{
    const auto too_positive =
        mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = manual\nmanual_value = 0x8000000000000000\n");
    ASSERT_FALSE(too_positive.has_value());
    EXPECT_EQ(too_positive.error().code, dmk::ErrorCode::MalformedLine);

    const auto too_negative =
        mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = manual\nmanual_value = -0x8000000000000001\n");
    ASSERT_FALSE(too_negative.has_value());
    EXPECT_EQ(too_negative.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, UnknownBindingIsMalformed)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = manual\nbinding = telepathy\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, BadRungModeIsMalformed)
{
    const auto parsed =
        mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n[sig.x.rung.0]\nmode = quantum\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, RungMissingPatternIsMalformed)
{
    const auto parsed =
        mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n[sig.x.rung.0]\nmode = direct\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, OrphanRungSectionIsMalformed)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x.rung.0]\nmode = direct\npattern = 90\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, GappedRungSectionIsMalformed)
{
    const auto parsed =
        mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n[sig.x.rung.1]\nmode = direct\npattern = 90\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, LabelWithDotsRoundTripsWithLadder)
{
    // A label that itself contains dots must not confuse the rung-section probe, which keys on a trailing ".rung.<N>".
    const std::string text = "[manifest]\nschema = 1\n[sig.a.b.c]\nkind = rip_global\n"
                             "[sig.a.b.c.rung.0]\nmode = direct\npattern = 90 90\n";
    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), 1u);
    EXPECT_EQ(parsed->records[0].label, "a.b.c");
    ASSERT_EQ(parsed->records[0].ladder.size(), 1u);
    EXPECT_EQ(parsed->records[0].ladder[0].pattern, "90 90");
}

// Signature::compile: valid records compile; invalid ones fail closed with a typed error.

TEST(ManifestCompileTest, BadPatternRungFailsClosed)
{
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::RipGlobal;
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::Direct;
    rung.pattern = "ZZ QQ"; // not a valid AOB
    record.ladder = {rung};

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::BadPattern);
}

TEST(ManifestCompileTest, EmptyLadderForByteKindFailsClosed)
{
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::RipGlobal; // needs a ladder, has none

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::EmptyCandidates);
}

TEST(ManifestCompileTest, NonSerializableKindFailsClosed)
{
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::Quorum;

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

TEST(ManifestCompileTest, UnsetKindFailsClosed)
{
    // A record whose kind was never set must not compile into a Signature that would resolve to a trusted zero.
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::Unset;

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

TEST(ManifestCompileTest, VtableIdentityWithEmptyMangledFailsClosed)
{
    // A VtableIdentity record with no mangled name has no evidence: rtti::vtable_for_type("") could only fail, so
    // reject at compile rather than build a Signature that overlays an empty lookup over a working default.
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::VtableIdentity; // mangled left empty

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

TEST(ManifestCompileTest, StringXrefWithEmptyTextFailsClosed)
{
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::StringXref; // xref_text left empty

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

TEST(ManifestCompileTest, RipRelativeRungWithUnsetDecodeFieldsFailsClosed)
{
    // A programmatic record whose RipRelative rung never set its decode offsets leaves both at 0, which would resolve
    // to match + 0 + disp32 -- the R3.1 defect reached through the compile path instead of the file parser. compile
    // must apply the same fail-closed decode-field constraint parse_rung does.
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::RipGlobal;
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::RipRelative;
    rung.pattern = "48 8B 05 ?? ?? ?? ??"; // a valid pattern, but displacement_at / instruction_length default to 0
    record.ladder = {rung};

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

TEST(ManifestCompileTest, RipRelativeRungWithValidDecodeFieldsCompiles)
{
    // The gate is scoped to the decode values, so a rung with a well-formed offset pair (disp32 fits in the
    // instruction) still compiles -- only unset/malformed decode fields fail closed.
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::RipGlobal;
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::RipRelative;
    rung.pattern = "48 8B 05 ?? ?? ?? ??";
    rung.displacement_at = 3;
    rung.instruction_length = 7;
    record.ladder = {rung};

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_TRUE(compiled.has_value()) << compiled.error().message();
}

namespace
{
    // Post-resolve validators used to prove the manifest path can reach an Anchor::validator.
    bool reject_all_validator(std::int64_t, const void *) noexcept
    {
        return false;
    }
    bool accept_all_validator(std::int64_t, const void *) noexcept
    {
        return true;
    }
} // namespace

TEST(ManifestCompileTest, CompiledSignatureThreadsValidatorToAnchor)
{
    // A Manual record with validate_manual routes the pinned literal through its validator. If make_anchor did not
    // carry the validator across, the rejecting validator would be ignored and the Manual would resolve.
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::Manual;
    record.manual_value = 0x1234;
    record.validate_manual = true;
    record.validator = &reject_all_validator;

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_TRUE(compiled.has_value()) << compiled.error().message();
    const an::ResolvedAnchor resolved = compiled->resolve(dmk::Region::host());
    EXPECT_EQ(resolved.status, an::AnchorStatus::Failed) << "validator must be reachable from a compiled Signature";

    // Control: the same record with an accepting validator resolves, so the Failed above is the validator's verdict.
    mf::SignatureRecord ok_record;
    ok_record.label = "x";
    ok_record.kind = an::AnchorKind::Manual;
    ok_record.manual_value = 0x1234;
    ok_record.validate_manual = true;
    ok_record.validator = &accept_all_validator;
    const auto ok_compiled = mf::Signature::compile(std::move(ok_record));
    ASSERT_TRUE(ok_compiled.has_value()) << ok_compiled.error().message();
    const an::ResolvedAnchor ok_resolved = ok_compiled->resolve(dmk::Region::host());
    EXPECT_EQ(ok_resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(ok_resolved.value, 0x1234);
}

TEST(ManifestAdoptTest, PreservesSourceValidator)
{
    // Adopting an in-code Anchor into a Signature must not silently drop its validator (a fail-open regression).
    an::Anchor source{};
    source.label = "x";
    source.kind = an::AnchorKind::Manual;
    source.manual_value = 0x99;
    source.validate_manual = true;
    source.validator = &reject_all_validator;

    const auto adopted = mf::Signature::adopt(source);
    ASSERT_TRUE(adopted.has_value()) << adopted.error().message();
    const an::ResolvedAnchor resolved = adopted->resolve(dmk::Region::host());
    EXPECT_EQ(resolved.status, an::AnchorStatus::Failed) << "adopt must preserve the source validator";
}

TEST(ManifestAdoptTest, UnsetKindFailsClosed)
{
    an::Anchor source{}; // kind defaults to Unset
    source.label = "x";

    const auto adopted = mf::Signature::adopt(source);
    ASSERT_FALSE(adopted.has_value());
    EXPECT_EQ(adopted.error().code, dmk::ErrorCode::InvalidArg);
}

TEST(ManifestAdoptTest, EmptyRequiredEvidenceFailsClosed)
{
    an::Anchor byte_source{};
    byte_source.label = "byte";
    byte_source.kind = an::AnchorKind::RipGlobal;
    const auto byte_adopted = mf::Signature::adopt(byte_source);
    ASSERT_FALSE(byte_adopted.has_value());
    EXPECT_EQ(byte_adopted.error().code, dmk::ErrorCode::InvalidArg);

    an::Anchor vtable_source{};
    vtable_source.label = "vt";
    vtable_source.kind = an::AnchorKind::VtableIdentity;
    const auto vtable_adopted = mf::Signature::adopt(vtable_source);
    ASSERT_FALSE(vtable_adopted.has_value());
    EXPECT_EQ(vtable_adopted.error().code, dmk::ErrorCode::InvalidArg);

    an::Anchor xref_source{};
    xref_source.label = "xref";
    xref_source.kind = an::AnchorKind::StringXref;
    const auto xref_adopted = mf::Signature::adopt(xref_source);
    ASSERT_FALSE(xref_adopted.has_value());
    EXPECT_EQ(xref_adopted.error().code, dmk::ErrorCode::InvalidArg);
}

TEST(ManifestParseTest, RipRelativeRungMissingInstructionLengthIsMalformed)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = rip_relative\npattern = 48 8B 05 ?? ?? ?? ??\n"
                                  "displacement_at = 3\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, RipRelativeRungMissingDisplacementIsMalformed)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = rip_relative\npattern = 48 8B 05 ?? ?? ?? ??\n"
                                  "instruction_length = 7\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, RipRelativeRungWithBothDecodeFieldsParses)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = rip_relative\npattern = 48 8B 05 ?? ?? ?? ??\n"
                                  "displacement_at = 3\ninstruction_length = 7\n");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records[0].ladder.size(), 1u);
    EXPECT_EQ(parsed->records[0].ladder[0].mode, sc::Mode::RipRelative);
    EXPECT_EQ(parsed->records[0].ladder[0].displacement_at, 3);
    EXPECT_EQ(parsed->records[0].ladder[0].instruction_length, 7u);
}

TEST(ManifestParseTest, RipRelativeRungWithDisplacementPastInstructionEndIsMalformed)
{
    // disp32 at offset 5 would occupy bytes [5, 9) but the instruction is only 7 bytes: the disp runs off the end.
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = rip_relative\npattern = 48 8B 05 ?? ?? ?? ??\n"
                                  "displacement_at = 5\ninstruction_length = 7\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, RipRelativeRungWithNegativeDisplacementIsMalformed)
{
    // A negative displacement_at is rejected by its own guard, independent of the disp-fits-inside check. The two are
    // not redundant: were the `< 0` guard dropped, -1 would cast to ~SIZE_MAX and (~SIZE_MAX + 4) wraps to 3, so the
    // `instruction_length < displacement_at + 4` test reads `7 < 3` (false) and the malformed rung fails OPEN. This
    // exercises the sign guard directly so a regression that reorders it past the cast cannot slip through.
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = rip_relative\npattern = 48 8B 05 ?? ?? ?? ??\n"
                                  "displacement_at = -1\ninstruction_length = 7\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, DirectRungWithoutDecodeFieldsStaysValid)
{
    // The required-key gate must stay scoped to rip_relative; a Direct rung legitimately carries no decode offsets.
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = direct\npattern = 90 90\n");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records[0].ladder.size(), 1u);
    EXPECT_EQ(parsed->records[0].ladder[0].mode, sc::Mode::Direct);
}

TEST(ManifestParseTest, ManualRecordMissingManualValueIsMalformed)
{
    // An omitted manual_value would default to a trusted Address{0}; require the key.
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = manual\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, ManualRecordWithExplicitZeroValueParses)
{
    // The presence of the key, not the value, is the gate: an author who genuinely pins zero writes it explicitly.
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = manual\nmanual_value = 0\n");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), 1u);
    EXPECT_EQ(parsed->records[0].manual_value, 0);
}

// Resolution: a compiled signature resolves through its anchor backend, honouring scope.

TEST(ManifestResolveTest, RipGlobalDirectResolvesInScope)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});

    mf::SignatureRecord record;
    record.label = "marker";
    record.kind = an::AnchorKind::RipGlobal;
    mf::CandidateSpec rung;
    rung.name = "marker-direct";
    rung.mode = sc::Mode::Direct;
    rung.pattern = "DE AD BE EF 10 20 30 40";
    record.ladder = {rung};

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_TRUE(compiled.has_value()) << compiled.error().message();

    const an::ResolvedAnchor resolved = compiled->resolve(page.range());
    EXPECT_EQ(resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(resolved.value), page.addr(0x200));
}

TEST(ManifestResolveTest, CodeOperandResolvesImmediate)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    mf::SignatureRecord record;
    record.label = "stride";
    record.kind = an::AnchorKind::CodeOperand;
    record.operand_kind = sc::OperandKind::Immediate;
    record.operand_index = 1;
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::Direct;
    rung.pattern = "48 05 F0 00 00 00";
    record.ladder = {rung};

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_TRUE(compiled.has_value()) << compiled.error().message();

    const an::ResolvedAnchor resolved = compiled->resolve(page.range());
    EXPECT_EQ(resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(resolved.value, 0xF0);
}

TEST(ManifestResolveTest, ManualResolvesRegardlessOfScope)
{
    const mf::Signature sig = manual_signature("pinned", 0x1234);
    const an::ResolvedAnchor resolved = sig.resolve();
    EXPECT_EQ(resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(resolved.value, 0x1234);
}

TEST(ManifestResolveTest, ModuleFieldRoutesScopeAndFailsClosedWhenAbsent)
{
    mf::SignatureRecord record;
    record.label = "elsewhere";
    record.kind = an::AnchorKind::RipGlobal;
    record.module = "definitely_not_loaded_dmk_xyz.dll";
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::Direct;
    rung.pattern = "DE AD BE EF";
    record.ladder = {rung};

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_TRUE(compiled.has_value());

    // The module names an unloaded image, so its scope is empty and resolution fails closed even though a fallback
    // scope is offered.
    const an::ResolvedAnchor resolved = compiled->resolve(dmk::Region::host());
    EXPECT_EQ(resolved.status, an::AnchorStatus::Failed);
}

TEST(ManifestResolveTest, ScopeIsHostWhenNoModuleNamed)
{
    const mf::Signature sig = manual_signature("pinned", 1);
    EXPECT_EQ(sig.scope().base.raw(), dmk::Region::host().base.raw());
}

// adopt: an in-code anchor becomes an owning signature whose views survive the source going out of scope.

TEST(ManifestAdoptTest, AdoptsManualAnchor)
{
    an::Anchor anchor{};
    anchor.label = "pinned";
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x777;

    const auto adopted = mf::Signature::adopt(anchor);
    ASSERT_TRUE(adopted.has_value());
    EXPECT_EQ(adopted->label(), "pinned");
    EXPECT_EQ(adopted->fingerprint_state(), mf::FingerprintState::Unset); // no captured baseline
    EXPECT_EQ(adopted->resolve().value, 0x777);
}

TEST(ManifestAdoptTest, AdoptsByteKindAndOutlivesSourceLadder)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});

    // The adopted signature must deep-copy the borrowed site, so it resolves after the source candidate array dies.
    const std::optional<mf::Signature> adopted = [&page]() -> std::optional<mf::Signature>
    {
        const sc::Candidate cands[] = {
            sc::Candidate::direct("marker", sc::Pattern::compile("DE AD BE EF 10 20 30 40").value())};
        an::Anchor anchor{};
        anchor.label = "marker";
        anchor.kind = an::AnchorKind::RipGlobal;
        anchor.site = cands;
        auto result = mf::Signature::adopt(anchor);
        return result ? std::optional<mf::Signature>(std::move(*result)) : std::nullopt;
    }();

    ASSERT_TRUE(adopted.has_value());
    const an::ResolvedAnchor resolved = adopted->resolve(page.range());
    EXPECT_EQ(resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(resolved.value), page.addr(0x200));
}

TEST(ManifestAdoptTest, RejectsCompositeAnchor)
{
    an::Anchor anchor{};
    anchor.label = "vote";
    anchor.kind = an::AnchorKind::Quorum;

    const auto adopted = mf::Signature::adopt(anchor);
    ASSERT_FALSE(adopted.has_value());
    EXPECT_EQ(adopted.error().code, dmk::ErrorCode::InvalidArg);
}

// Fingerprint drift: the baseline distinguishes a moved address from a rewritten signature.

TEST(ManifestFingerprintTest, UnsetMatchAndDrift)
{
    const std::uint64_t fingerprint = manual_signature("probe", 100).current_fingerprint();

    EXPECT_EQ(manual_signature("u", 100, 0).fingerprint_state(), mf::FingerprintState::Unset);
    EXPECT_EQ(manual_signature("m", 100, fingerprint).fingerprint_state(), mf::FingerprintState::Match);
    EXPECT_EQ(manual_signature("d", 100, fingerprint ^ 1ULL).fingerprint_state(), mf::FingerprintState::Drifted);
}

TEST(ManifestFingerprintTest, RecaptureAdoptsCurrentAsBaseline)
{
    mf::Signature sig = manual_signature("probe", 100, 0);
    ASSERT_EQ(sig.fingerprint_state(), mf::FingerprintState::Unset);
    sig.recapture_fingerprint();
    EXPECT_EQ(sig.fingerprint_state(), mf::FingerprintState::Match);
    EXPECT_EQ(sig.record().expected_fingerprint, sig.current_fingerprint());
}

// The gate: resolve a manifest and partition it into trusted vs safe-disabled.

TEST(ManifestGateTest, TrustsResolvedRejectsDrifted)
{
    const std::uint64_t fp = manual_signature("probe", 100).current_fingerprint();

    std::vector<mf::Signature> sigs;
    sigs.push_back(manual_signature("ok", 100, fp));         // Match -> trusted
    sigs.push_back(manual_signature("bad", 100, fp ^ 1ULL)); // Drifted -> rejected under default policy

    const mf::GateResult gate = mf::resolve_and_gate(sigs);
    ASSERT_EQ(gate.trusted.size(), 1u);
    ASSERT_EQ(gate.rejected.size(), 1u);
    EXPECT_EQ(gate.trusted[0].label, "ok");
    EXPECT_EQ(gate.trusted[0].address.raw(), 100u);
    EXPECT_EQ(gate.rejected[0].label, "bad");
    EXPECT_EQ(gate.rejected[0].fingerprint, mf::FingerprintState::Drifted);
    EXPECT_NE(gate.find("ok"), nullptr);
    EXPECT_EQ(gate.find("bad"), nullptr);
}

TEST(ManifestGateTest, DriftToleratedWhenPolicyDisablesRejection)
{
    const std::uint64_t fp = manual_signature("probe", 100).current_fingerprint();

    std::vector<mf::Signature> sigs;
    sigs.push_back(manual_signature("bad", 100, fp ^ 1ULL));

    mf::GatePolicy policy;
    policy.reject_on_fingerprint_drift = false;
    const mf::GateResult gate = mf::resolve_and_gate(sigs, policy);
    EXPECT_EQ(gate.trusted.size(), 1u);
    EXPECT_TRUE(gate.rejected.empty());
}

TEST(ManifestGateTest, UnsetBaselineTrustedByDefaultRejectedWhenStrict)
{
    std::vector<mf::Signature> sigs;
    sigs.push_back(manual_signature("unknown", 100, 0)); // Unset

    EXPECT_EQ(mf::resolve_and_gate(sigs).trusted.size(), 1u); // default: unset is trusted

    mf::GatePolicy strict;
    strict.reject_unset_fingerprint = true;
    const mf::GateResult gate = mf::resolve_and_gate(sigs, strict);
    EXPECT_TRUE(gate.trusted.empty());
    ASSERT_EQ(gate.rejected.size(), 1u);
    EXPECT_EQ(gate.rejected[0].fingerprint, mf::FingerprintState::Unset);
}

TEST(ManifestGateTest, ResolveFailureIsRejected)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok()); // 0xCC filled; the pattern below is absent

    mf::SignatureRecord record;
    record.label = "absent";
    record.kind = an::AnchorKind::RipGlobal;
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::Direct;
    rung.pattern = "11 22 33 44 55 66 77 88";
    record.ladder = {rung};

    std::vector<mf::Signature> sigs;
    sigs.push_back(mf::Signature::compile(std::move(record)).value());

    const mf::GateResult gate = mf::resolve_and_gate(sigs, {}, page.range());
    EXPECT_TRUE(gate.trusted.empty());
    ASSERT_EQ(gate.rejected.size(), 1u);
    EXPECT_EQ(gate.rejected[0].label, "absent");
    EXPECT_EQ(gate.rejected[0].status, an::AnchorStatus::Failed);
}

TEST(ManifestGateTest, WholeManifestFloorDemotesAllWhenTooUnhealthy)
{
    const std::uint64_t fp = manual_signature("probe", 100).current_fingerprint();

    std::vector<mf::Signature> sigs;
    sigs.push_back(manual_signature("ok", 100, fp));         // would be trusted
    sigs.push_back(manual_signature("bad", 100, fp ^ 1ULL)); // drifted -> rejected

    mf::GatePolicy policy;
    policy.min_resolved_fraction = 0.75; // only 1 of 2 trusts -> 0.5 < 0.75 -> demote all
    const mf::GateResult gate = mf::resolve_and_gate(sigs, policy);
    EXPECT_TRUE(gate.trusted.empty());
    EXPECT_EQ(gate.rejected.size(), 2u);
}

TEST(ManifestGateTest, TrustedSignatureCarriesItsBinding)
{
    mf::SignatureRecord record = manual_record("hp", 0x5000);
    record.binding.kind = mf::BindingKind::PointerChain;
    record.binding.offsets = {0x10, 0x20};
    record.binding.value_width = 4;

    std::vector<mf::Signature> sigs;
    sigs.push_back(mf::Signature::compile(std::move(record)).value());

    const mf::GateResult gate = mf::resolve_and_gate(sigs);
    const mf::GatedSignature *hp = gate.find("hp");
    ASSERT_NE(hp, nullptr);
    EXPECT_EQ(hp->address.raw(), 0x5000u);
    ASSERT_NE(hp->binding, nullptr);
    EXPECT_EQ(hp->binding->kind, mf::BindingKind::PointerChain);
    ASSERT_EQ(hp->binding->offsets.size(), 2u);
    EXPECT_EQ(hp->binding->offsets[1], 0x20);
}

// Overlay: file records override in-code defaults by label; the rest of the defaults pass through.

TEST(ManifestOverlayTest, FileOverridesCodeByLabelAndAdoptsTheRest)
{
    an::Anchor defaults[2]{};
    defaults[0].label = "a";
    defaults[0].kind = an::AnchorKind::Manual;
    defaults[0].manual_value = 111;
    defaults[1].label = "b";
    defaults[1].kind = an::AnchorKind::Manual;
    defaults[1].manual_value = 222;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(manual_record("b", 999)); // overrides only "b"

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 2u);

    const mf::GateResult gate = mf::resolve_and_gate(*merged);
    const mf::GatedSignature *a = gate.find("a");
    const mf::GatedSignature *b = gate.find("b");
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(a->address.raw(), 111u); // in-code default kept
    EXPECT_EQ(b->address.raw(), 999u); // file override won
}

TEST(ManifestOverlayTest, MissingOverridesPassDefaultsThrough)
{
    an::Anchor defaults[1]{};
    defaults[0].label = "only";
    defaults[0].kind = an::AnchorKind::Manual;
    defaults[0].manual_value = 42;

    const auto merged = mf::overlay(defaults, {}); // no file
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ((*merged)[0].resolve().value, 42);
}

TEST(ManifestOverlayTest, UnmatchedOverrideIsInert)
{
    an::Anchor defaults[1]{};
    defaults[0].label = "a";
    defaults[0].kind = an::AnchorKind::Manual;
    defaults[0].manual_value = 1;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(manual_record("nobody_queries_this", 5));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    // Only the one default label survives; the file-only label is inert (nothing in code queries it).
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ((*merged)[0].label(), "a");
}

TEST(ManifestOverlayTest, MalformedOverrideFallsBackToDefault)
{
    an::Anchor defaults[1]{};
    defaults[0].label = "a";
    defaults[0].kind = an::AnchorKind::Manual;
    defaults[0].manual_value = 111;

    // An override that names "a" but cannot compile (a rip_global with a bad pattern) must fall back to the in-code
    // default rather than dropping the feature.
    mf::SignatureRecord broken;
    broken.label = "a";
    broken.kind = an::AnchorKind::RipGlobal;
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::Direct;
    rung.pattern = "GG HH";
    broken.ladder = {rung};

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(std::move(broken));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ((*merged)[0].resolve().value, 111); // fell back to the in-code Manual default
}

// File I/O: load / save round-trips through a real file.

TEST(ManifestFileTest, SaveThenLoadRoundTrips)
{
    std::vector<mf::SignatureRecord> records;
    records.push_back(manual_record("flag", 0xABCD, 0x1122334455667788ULL));
    {
        mf::SignatureRecord record;
        record.label = "sig.data";
        record.kind = an::AnchorKind::RipGlobal;
        mf::CandidateSpec rung;
        rung.mode = sc::Mode::Direct;
        rung.pattern = "48 8B 05 ?? ?? ?? ??";
        record.ladder = {rung};
        records.push_back(std::move(record));
    }

    const ScopedManifestFile file("roundtrip");

    const auto saved = mf::save(file.path(), mf::Manifest{.records = records});
    ASSERT_TRUE(saved.has_value()) << saved.error().message();

    const auto loaded = mf::load(file.path());
    ASSERT_TRUE(loaded.has_value()) << loaded.error().message();
    EXPECT_EQ(mf::serialize(*loaded), mf::serialize(mf::Manifest{.records = records}));
}

TEST(ManifestFileTest, LoadMissingFileReportsFileOpenFailed)
{
    // The guard's constructor clears any stale file, so the path starts absent.
    const ScopedManifestFile file("absent");

    const auto loaded = mf::load(file.path());
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, dmk::ErrorCode::FileOpenFailed);
}

// Enum-to-string helpers.

TEST(ManifestStringTest, BindingKindTokens)
{
    EXPECT_EQ(mf::binding_kind_to_string(mf::BindingKind::Address), "address");
    EXPECT_EQ(mf::binding_kind_to_string(mf::BindingKind::PointerChain), "pointer_chain");
    EXPECT_EQ(mf::binding_kind_to_string(mf::BindingKind::MidHookRegister), "mid_hook_register");
    EXPECT_EQ(mf::binding_kind_to_string(mf::BindingKind::VmtMethod), "vmt_method");
}

TEST(ManifestStringTest, FingerprintStateTokens)
{
    EXPECT_EQ(mf::fingerprint_state_to_string(mf::FingerprintState::Unset), "unset");
    EXPECT_EQ(mf::fingerprint_state_to_string(mf::FingerprintState::Match), "match");
    EXPECT_EQ(mf::fingerprint_state_to_string(mf::FingerprintState::Drifted), "drifted");
}

// Contract revision: the manifest-level version stamp and the gate that ignores a stale file.

TEST(ManifestRevisionTest, RevisionRoundTripsAndOmitsWhenZero)
{
    mf::Manifest versioned;
    versioned.header.revision = 7;
    versioned.records.push_back(manual_record("flag", 0x1234));

    const std::string text = mf::serialize(versioned);
    // The exact `revision = N` key line is emitted, not just the substring (which would also match a comment or a
    // hypothetical payload key prefix).
    EXPECT_NE(text.find("revision = 7"), std::string::npos);

    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    EXPECT_EQ(parsed->header.schema, mf::SCHEMA_VERSION);
    EXPECT_EQ(parsed->header.revision, 7u);

    // An unversioned (revision 0) manifest omits the key entirely, so an un-gated file stays clean.
    mf::Manifest unversioned;
    unversioned.records.push_back(manual_record("flag", 0x1234));
    EXPECT_EQ(mf::serialize(unversioned).find("revision"), std::string::npos);
}

TEST(ManifestRevisionTest, AbsentRevisionParsesAsZero)
{
    // A Manual record must carry an explicit manual_value (the fail-closed required-key gate); this test exercises
    // revision defaulting, so the record just needs to be well-formed.
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = manual\nmanual_value = 0\n");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    EXPECT_EQ(parsed->header.revision, 0u);
}

TEST(ManifestRevisionTest, MalformedRevisionIsRejected)
{
    const auto bad_token = mf::parse("[manifest]\nschema = 1\nrevision = nope\n");
    ASSERT_FALSE(bad_token.has_value());
    EXPECT_EQ(bad_token.error().code, dmk::ErrorCode::MalformedLine);

    // A value beyond the 32-bit field is rejected rather than silently truncated.
    const auto too_big = mf::parse("[manifest]\nschema = 1\nrevision = 0x100000000\n");
    ASSERT_FALSE(too_big.has_value());
    EXPECT_EQ(too_big.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestRevisionTest, RevisionCompatibleGatesStaleFiles)
{
    // build_revision 0 opts out of gating: any file is accepted.
    EXPECT_TRUE(mf::revision_compatible(mf::ManifestHeader{.revision = 3}, 0));

    // Otherwise the file must target this build's exact contract epoch. A mismatch -- an older file, or an
    // unversioned file under a versioned build -- is rejected so the consumer falls back to its in-code defaults.
    EXPECT_TRUE(mf::revision_compatible(mf::ManifestHeader{.revision = 2}, 2));
    EXPECT_FALSE(mf::revision_compatible(mf::ManifestHeader{.revision = 1}, 2));
    EXPECT_FALSE(mf::revision_compatible(mf::ManifestHeader{.revision = 0}, 2));
}

TEST(ManifestRevisionTest, FileLoadPreservesRevision)
{
    // The on-disk round-trip must carry the header through save/load too, not just the in-memory serialize/parse.
    // load() parses the file and parse() rebuilds the Manifest, so a non-zero revision survives the same path a
    // consumer hits at startup.
    mf::Manifest manifest;
    manifest.header.revision = 42;
    manifest.records.push_back(manual_record("flag", 0xABCD));

    const ScopedManifestFile file("revision_roundtrip");
    ASSERT_TRUE(mf::save(file.path(), manifest).has_value());

    const auto loaded = mf::load(file.path());
    ASSERT_TRUE(loaded.has_value()) << loaded.error().message();
    EXPECT_EQ(loaded->header.schema, mf::SCHEMA_VERSION);
    EXPECT_EQ(loaded->header.revision, 42u);
    EXPECT_EQ(loaded->records.size(), 1u);
}

TEST(ManifestRevisionTest, SchemaEmittedBeforeRevisionInHeader)
{
    // The [manifest] section is read top-down; a hand-edit that reorders the keys must not change the parsed
    // header, but a serialize/parse round-trip must keep schema first and revision after it so the output is
    // canonical.
    mf::Manifest manifest;
    manifest.header.revision = 3;
    const std::string text = mf::serialize(manifest);

    const std::size_t schema_pos = text.find("schema");
    const std::size_t revision_pos = text.find("revision");
    ASSERT_NE(schema_pos, std::string::npos);
    ASSERT_NE(revision_pos, std::string::npos);
    EXPECT_LT(schema_pos, revision_pos);
}
