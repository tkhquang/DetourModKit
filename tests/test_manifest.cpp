#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/manifest.hpp"
#include "DetourModKit/scan.hpp"

#include "test_alloc_probe.hpp"

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
    // have a real, uniquely matchable site to resolve inside a bounded Region. PAGE_EXECUTE_READWRITE, not
    // PAGE_READWRITE: a CodeOperand record resolves a code operand through read_code_constant, which scans
    // Pages::Executable, so a planted instruction must live on an execute-readable page. The bytes are still only
    // decoded, never executed. Byte-marker signatures resolve on this superset page too.
    class ScratchPage
    {
    public:
        ScratchPage()
        {
            m_base = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

    // Builds a valid CodeOperand record whose width is the only policy value varied by its tests.
    [[nodiscard]] mf::SignatureRecord code_operand_record(std::uint8_t byte_width)
    {
        mf::SignatureRecord record;
        record.label = "width";
        record.kind = an::AnchorKind::CodeOperand;
        record.operand_kind = sc::OperandKind::MemoryDisplacement;
        record.operand_index = 1;
        record.byte_width = byte_width;
        mf::CandidateSpec rung;
        rung.mode = sc::Mode::Direct;
        rung.pattern = "8A 45 FF";
        record.ladder.push_back(std::move(rung));
        return record;
    }

    // Serializes a manifest expected to round-trip and records an assertion if validation rejects it.
    [[nodiscard]] std::string serialize_ok(const mf::Manifest &manifest)
    {
        auto encoded = mf::serialize_checked(manifest);
        if (!encoded.has_value())
        {
            ADD_FAILURE() << "serialize_checked rejected a manifest expected to round-trip: "
                          << encoded.error().message();
            return std::string{};
        }
        return std::move(*encoded);
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
        record.pages = sc::Pages::Executable;
        mf::CandidateSpec rung0;
        rung0.name = "fov-direct";
        rung0.mode = sc::Mode::RipRelative;
        rung0.pattern = "F3 0F 11 05 ?? ?? ?? ?? 48 8B";
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

    // ExportName with a module and an address binding: the owning module rides the shared `module` field, the export
    // symbol is kind-specific.
    {
        mf::SignatureRecord record;
        record.label = "platform.timer";
        record.kind = an::AnchorKind::ExportName;
        record.module = "kernel32.dll";
        record.export_name = "QueryPerformanceCounter";
        records.push_back(std::move(record));
    }

    const std::string text = serialize_ok(mf::Manifest{.records = records});
    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), records.size());

    // Re-serializing the parsed records reproduces the exact text: a full structural round-trip.
    EXPECT_EQ(serialize_ok(*parsed), text);

    // Spot-check the fields that carry the repair semantics.
    const mf::SignatureRecord &fov = parsed->records[0];
    EXPECT_EQ(fov.label, "camera.fov_write");
    EXPECT_EQ(fov.kind, an::AnchorKind::RipGlobal);
    EXPECT_EQ(fov.module, "engine.dll");
    EXPECT_EQ(fov.binding.kind, mf::BindingKind::MidHookRegister);
    EXPECT_EQ(fov.binding.read_register, hk::Gpr::Rcx);
    EXPECT_EQ(fov.expected_fingerprint, 0x41BB02C9DE7715A0ULL);
    EXPECT_EQ(fov.pages, sc::Pages::Executable);
    ASSERT_EQ(fov.ladder.size(), 2u);
    EXPECT_EQ(fov.ladder[0].mode, sc::Mode::RipRelative);
    EXPECT_EQ(fov.ladder[0].pattern, "F3 0F 11 05 ?? ?? ?? ?? 48 8B");
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

    const mf::SignatureRecord &timer = parsed->records[5];
    EXPECT_EQ(timer.kind, an::AnchorKind::ExportName);
    EXPECT_EQ(timer.module, "kernel32.dll");
    EXPECT_EQ(timer.export_name, "QueryPerformanceCounter");
}

TEST(ManifestSerializeTest, EmptyRecordSetProducesParsableHeaderOnly)
{
    const std::string text = serialize_ok(mf::Manifest{});
    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->records.empty());
}

TEST(ManifestSerializeTest, SignedMinimumManualValueRoundTrips)
{
    std::vector<mf::SignatureRecord> records;
    records.push_back(manual_record("floor", std::numeric_limits<std::int64_t>::min()));

    const std::string text = serialize_ok(mf::Manifest{.records = records});
    EXPECT_NE(text.find("-0x8000000000000000"), std::string::npos);

    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), 1u);
    EXPECT_EQ(parsed->records[0].manual_value, std::numeric_limits<std::int64_t>::min());
}

// A StringXref literal carrying an embedded '\n' -- routine in a log / format string an anchor keys on -- must
// survive serialize -> parse verbatim. Without multi-line values, SimpleIni ends the value at the first newline and
// re-reads the tail as a spurious key, truncating the literal (and potentially injecting a `binding =` key the drift
// gate could not see).
TEST(ManifestSerializeTest, NewlineBearingLiteralRoundTrips)
{
    mf::SignatureRecord rec;
    rec.label = "log.error_format";
    rec.kind = an::AnchorKind::StringXref;
    rec.xref_text = "Error: %s\n";

    mf::Manifest m;
    m.header.revision = 1;
    m.records.push_back(rec);

    const std::string text = serialize_ok(m);
    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), 1u);
    EXPECT_EQ(parsed->records[0].xref_text, rec.xref_text);
}

// Property coverage for the remaining structural characters an INI value could break on: a bracket (]), an equals
// (=), and a trailing newline. SimpleIni carries ] and = inside a value natively, and the multi-line mode carries the
// trailing '\n'; all must round-trip unchanged.
TEST(ManifestSerializeTest, StructuralCharactersInLiteralRoundTrip)
{
    const std::string_view literals[] = {"bracket]inside", "key = value", "embedded]and = both", "trailing-line\n"};
    for (const std::string_view literal : literals)
    {
        mf::SignatureRecord rec;
        rec.label = "probe";
        rec.kind = an::AnchorKind::StringXref;
        rec.xref_text = std::string(literal);
        mf::Manifest m;
        m.records.push_back(rec);

        const std::string text = serialize_ok(m);
        const auto parsed = mf::parse(text);
        ASSERT_TRUE(parsed.has_value()) << "literal '" << literal << "': " << parsed.error().message();
        ASSERT_EQ(parsed->records.size(), 1u);
        EXPECT_EQ(parsed->records[0].xref_text, literal) << "literal '" << literal << "' did not round-trip";
    }
}

// The section-name whitespace trim is a TRAILING-edge hazard only: a leading blank sits interior to `sig.<label>` (the
// fixed prefix starts the section name, not the blank) and interior whitespace is preserved, so such labels round-trip
// and must not be rejected -- rejecting them would be a capability regression the trailing-blank guard must not cause.
TEST(ManifestSerializeTest, LeadingAndInteriorWhitespaceLabelRoundTrips)
{
    for (const std::string_view label : {" leading.blank", "interior blank"})
    {
        mf::SignatureRecord rec;
        rec.label = std::string(label);
        rec.kind = an::AnchorKind::Manual;
        rec.manual_value = 0x1000;
        mf::Manifest m;
        m.records.push_back(rec);

        // compile() must accept it (the guard rejects only a trailing blank) ...
        ASSERT_TRUE(mf::Signature::compile(rec).has_value()) << "label '" << label << "' should compile";
        // ... and it must survive serialize -> parse unchanged.
        const std::string text = serialize_ok(m);
        const auto parsed = mf::parse(text);
        ASSERT_TRUE(parsed.has_value()) << "label '" << label << "': " << parsed.error().message();
        ASSERT_EQ(parsed->records.size(), 1u);
        EXPECT_EQ(parsed->records[0].label, label) << "label '" << label << "' did not round-trip";
    }
}

// The multi-line value mode normalizes a carriage return to '\n' on read, so a '\r'-bearing match literal cannot
// round-trip byte-for-byte and would silently mis-anchor. compile() fails it closed instead. '\n' (above) is fine.
TEST(ManifestCompileTest, CarriageReturnLiteralFailsClosed)
{
    mf::SignatureRecord rec;
    rec.label = "log.crlf";
    rec.kind = an::AnchorKind::StringXref;
    rec.xref_text = "line\r\nbreak";

    const auto compiled = mf::Signature::compile(rec);
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

// Values are serialized through SimpleIni's C-string API, so an embedded NUL would truncate the literal on save and
// reload as a different anchor. Signature::compile rejects it before the record can be trusted or serialized.
TEST(ManifestCompileTest, NulBearingLiteralFailsClosed)
{
    mf::SignatureRecord rec;
    rec.label = "log.nul";
    rec.kind = an::AnchorKind::StringXref;
    rec.xref_text = std::string{"line\0break", 10};

    const auto compiled = mf::Signature::compile(rec);
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

// A NUL-bearing label would truncate the `[sig.<label>]` section name before parse() sees it. Rejecting it at compile
// time keeps the file section grammar one-to-one with the in-memory label.
TEST(ManifestCompileTest, NulBearingLabelFailsClosed)
{
    mf::SignatureRecord rec;
    rec.label = std::string{"camera\0fov", 10};
    rec.kind = an::AnchorKind::Manual;
    rec.manual_value = 0x1000;

    const auto compiled = mf::Signature::compile(rec);
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

// A label matching the reserved `.rung.<digits>` grammar can never denote a top-level record (parse() always reads
// `sig.<parent>.rung.<N>` as a candidate sub-section), so compile() rejects it rather than emit a section a re-parse
// would misattribute or reject.
TEST(ManifestCompileTest, RungGrammarLabelFailsClosed)
{
    mf::SignatureRecord rec;
    rec.label = "camera.rung.0";
    rec.kind = an::AnchorKind::Manual;
    rec.manual_value = 0x1000;

    const auto compiled = mf::Signature::compile(rec);
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

// A bracket or line break in a label is an INI-structural character: the reader ends a section name at the FIRST `]`,
// so `[sig.a]b]` would reload as label "a" -- a silent identity change the emitted file's own grammar check cannot
// see, because trailing bytes after a closing bracket are ignored on read. Each character fails closed in isolation
// through compile, adopt, and checked serialization, so dropping any one term of the label validator regresses here.
TEST(ManifestCompileTest, StructuralCharacterLabelFailsClosed)
{
    for (const std::string_view label : {"a]b", "a[b", "a\rb", "a\nb"})
    {
        mf::SignatureRecord rec;
        rec.label = std::string(label);
        rec.kind = an::AnchorKind::Manual;
        rec.manual_value = 0x1000;

        const auto compiled = mf::Signature::compile(rec);
        ASSERT_FALSE(compiled.has_value()) << label;
        EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg) << label;

        const auto encoded = mf::serialize_checked(mf::Manifest{.records = {rec}});
        ASSERT_FALSE(encoded.has_value()) << label;
        EXPECT_EQ(encoded.error().code, dmk::ErrorCode::InvalidArg) << label;

        an::Anchor source;
        source.label = label;
        source.kind = an::AnchorKind::Manual;
        const auto adopted = mf::Signature::adopt(source);
        ASSERT_FALSE(adopted.has_value()) << label;
        EXPECT_EQ(adopted.error().code, dmk::ErrorCode::InvalidArg) << label;
    }
}

// The multi-line value form is bounded by a fixed terminator line, and the reader ends the value at the first line
// that equals it. A literal that both carries a newline (so it takes the heredoc path) and contains that terminator
// as one of its lines would reload truncated -- a different, shorter contract -- so compile() fails it closed. This is
// the one multi-line value SimpleIni cannot round-trip; a plain '\n' literal (no terminator line) still round-trips.
TEST(ManifestCompileTest, HeredocTerminatorLiteralFailsClosed)
{
    mf::SignatureRecord rec;
    rec.label = "log.heredoc";
    rec.kind = an::AnchorKind::StringXref;
    rec.xref_text = "prefix\nEND_OF_TEXT\nsuffix";

    const auto compiled = mf::Signature::compile(rec);
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

// A single-line value can take SimpleIni's heredoc path too: a leading/trailing whitespace edge trips IsMultiLineData
// (ParseQuotes is never enabled, so the quote-preservation path is dead), and the reader trailing-trims each heredoc
// body line before comparing it to the terminator. A value that trims to the terminator token -- "END_OF_TEXT " or
// "END_OF_TEXT\t" -- is thus accepted by a newline-only guard but reloads truncated. compile() must fail those closed.
// Values whose trimmed form differs from the terminator (plain edge whitespace, or a leading-only edge) still take the
// heredoc path but round-trip verbatim, and a bare "END_OF_TEXT" (no edge) is emitted raw and round-trips -- none of
// those may be over-rejected.
TEST(ManifestSerializeTest, WhitespaceEdgeValueRoundTripsOrFailsClosed)
{
    // Terminator-collision cases: compile() must reject these outright (they cannot round-trip).
    for (const std::string_view corrupting : {"END_OF_TEXT ", "END_OF_TEXT\t"})
    {
        mf::SignatureRecord rec;
        rec.label = "terminator_collision";
        rec.kind = an::AnchorKind::StringXref;
        rec.xref_text = std::string(corrupting);

        const auto compiled = mf::Signature::compile(rec);
        ASSERT_FALSE(compiled.has_value()) << "value '" << corrupting << "' must be rejected (heredoc truncation)";
        EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
    }

    // Serializable controls must round-trip byte-for-byte, so the guard cannot be a blanket whitespace-edge or
    // terminator reject. "trailing space " / " leading space" take the heredoc path; "END_OF_TEXT" is emitted raw.
    for (const std::string_view intact : {"trailing space ", " leading space", "END_OF_TEXT", " END_OF_TEXT"})
    {
        mf::SignatureRecord rec;
        rec.label = "whitespace_round_trip";
        rec.kind = an::AnchorKind::StringXref;
        rec.xref_text = std::string(intact);

        ASSERT_TRUE(mf::Signature::compile(rec).has_value()) << "value '" << intact << "' should compile";
        mf::Manifest m;
        m.records.push_back(rec);
        const std::string text = serialize_ok(m);
        const auto parsed = mf::parse(text);
        ASSERT_TRUE(parsed.has_value()) << "value '" << intact << "': " << parsed.error().message();
        ASSERT_EQ(parsed->records.size(), 1u);
        EXPECT_EQ(parsed->records[0].xref_text, intact) << "value '" << intact << "' did not round-trip";
    }

    // Prove the hazard the write guard prevents is real, not just that compile() reacts to it. Build the manifest text
    // from a genuine serialize_checked() (so the framing and terminator token are authoritative), confirm the tag, then
    // poison the heredoc body into one line that trims to that tag. The poisoned block's first body line is now its
    // terminator, a shape the backend does not read as an empty value (it would load the tag line plus following
    // bytes), so the raw parser rejects it as unsafe framing: the intended "END_OF_TEXT " value can neither survive
    // verbatim nor masquerade as a truncated form.
    {
        mf::SignatureRecord probe;
        probe.label = "poison_probe";
        probe.kind = an::AnchorKind::StringXref;
        probe.xref_text = "POISONMARKERALPHA\nPOISONMARKERBETA"; // embedded newline -> real heredoc, no collision
        mf::Manifest src;
        src.records.push_back(probe);
        const std::string good = serialize_ok(src);
        ASSERT_NE(good.find("<<<END_OF_TEXT"), std::string::npos) << "the emitter must open the heredoc with the tag";

        // Bound the body by its two marker tokens (line-ending agnostic: the emitted heredoc separates them with the
        // INI line ending, CRLF here) and replace the whole body with one line that trims to the terminator tag.
        std::string poisoned = good;
        const std::size_t b0 = poisoned.find("POISONMARKERALPHA");
        const std::size_t b1 = poisoned.find("POISONMARKERBETA");
        ASSERT_NE(b0, std::string::npos);
        ASSERT_NE(b1, std::string::npos);
        poisoned.replace(b0, (b1 + std::string("POISONMARKERBETA").size()) - b0, "END_OF_TEXT ");

        const auto reparsed = mf::parse(poisoned);
        ASSERT_FALSE(reparsed.has_value());
        EXPECT_EQ(reparsed.error().code, dmk::ErrorCode::ManifestFramingUnsafe);
    }
}

// SimpleIni strips leading and trailing whitespace from a section name on read, so a label ending in a space or tab
// would reload as its trimmed form (`[sig.foo ]` -> `sig.foo`), silently changing the lookup key. compile() rejects a
// trailing blank; a trailing '\r' / '\n' is caught by the structural-character guard instead.
TEST(ManifestCompileTest, TrailingWhitespaceLabelFailsClosed)
{
    for (const std::string_view bad : {"camera.fov ", "camera.fov\t"})
    {
        mf::SignatureRecord rec;
        rec.label = std::string(bad);
        rec.kind = an::AnchorKind::Manual;
        rec.manual_value = 0x1000;

        const auto compiled = mf::Signature::compile(rec);
        ASSERT_FALSE(compiled.has_value()) << "label '" << bad << "' should be rejected";
        EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
    }
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

TEST(ManifestParseTest, CodeOperandByteWidthDomainFailsClosed)
{
    const auto parse_width = [](unsigned width)
    {
        return mf::parse(std::format("[manifest]\nschema = 1\n[sig.width]\nkind = code_operand\n"
                                     "operand_kind = memory_displacement\noperand_index = 1\nbyte_width = {}\n"
                                     "[sig.width.rung.0]\nmode = direct\npattern = 8A 45 FF\n",
                                     width));
    };

    const auto valid = parse_width(8);
    ASSERT_TRUE(valid.has_value()) << valid.error().message();
    ASSERT_EQ(valid->records.size(), 1u);
    EXPECT_EQ(valid->records[0].byte_width, 8);

    for (const unsigned width : {9u, 255u})
    {
        const auto invalid = parse_width(width);
        ASSERT_FALSE(invalid.has_value()) << "width=" << width;
        EXPECT_EQ(invalid.error().code, dmk::ErrorCode::MalformedLine);
    }
}

TEST(ManifestCompileTest, CodeOperandByteWidthDomainFailsClosed)
{
    const auto valid = mf::Signature::compile(code_operand_record(8));
    ASSERT_TRUE(valid.has_value()) << valid.error().message();
    EXPECT_EQ(valid->record().byte_width, 8);

    for (const std::uint8_t width : {std::uint8_t{9}, std::uint8_t{255}})
    {
        const auto invalid = mf::Signature::compile(code_operand_record(width));
        ASSERT_FALSE(invalid.has_value()) << "width=" << static_cast<unsigned>(width);
        EXPECT_EQ(invalid.error().code, dmk::ErrorCode::InvalidArg);
    }
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

    const auto short_parent = mf::parse("[manifest]\nschema = 1\n[sig.rung.0]\nmode = direct\npattern = 90\n");
    ASSERT_FALSE(short_parent.has_value());
    EXPECT_EQ(short_parent.error().code, dmk::ErrorCode::MalformedLine);
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

TEST(ManifestCompileTest, ExportNameWithEmptyExportNameFailsClosed)
{
    // The export symbol is the mandatory evidence: without it the record would overlay an empty EAT lookup over a
    // working in-code default. The module may be empty (an empty module resolves in the fallback scope), so only the
    // export name is required.
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::ExportName;
    record.module = "kernel32.dll"; // export_name left empty

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
}

TEST(ManifestCompileTest, RipRelativeRungWithUnsetDecodeFieldsFailsClosed)
{
    // A programmatic record whose RipRelative rung never set its decode offsets leaves both at 0, which would resolve
    // to match + 0 + disp32 -- an in-module address wrong by exactly the instruction length, reached through the
    // compile path instead of the file parser. compile must apply the same fail-closed decode-field constraint
    // parse_rung does.
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
    // The pattern must cover the disp32, while trailing instruction bytes may sit beyond its evidence span.
    mf::SignatureRecord record;
    record.label = "x";
    record.kind = an::AnchorKind::RipGlobal;
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::RipRelative;
    rung.pattern = "C7 05 ?? ?? ?? ??";
    rung.displacement_at = 2;
    rung.instruction_length = 10;
    record.ladder = {rung};

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_TRUE(compiled.has_value()) << compiled.error().message();
}

TEST(ManifestCompileTest, RipRelativePatternMustSpanDisplacement)
{
    mf::SignatureRecord record;
    record.label = "short-rip";
    record.kind = an::AnchorKind::RipGlobal;
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::RipRelative;
    rung.pattern = "48 8B 05";
    rung.displacement_at = 3;
    rung.instruction_length = 7;
    record.ladder = {rung};

    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
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

    an::Anchor export_source{};
    export_source.label = "export";
    export_source.kind = an::AnchorKind::ExportName; // export_name left empty
    const auto export_adopted = mf::Signature::adopt(export_source);
    ASSERT_FALSE(export_adopted.has_value());
    EXPECT_EQ(export_adopted.error().code, dmk::ErrorCode::InvalidArg);
}

TEST(ManifestParseTest, RipGlobalPagesDefaultsToReadable)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = direct\npattern = DE AD BE EF\n");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), 1u);
    EXPECT_EQ(parsed->records[0].pages, sc::Pages::Readable);
}

TEST(ManifestParseTest, RipGlobalRejectsUnknownPageClass)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\npages = writable\n"
                                  "[sig.x.rung.0]\nmode = direct\npattern = DE AD BE EF\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestPageClassTest, CompileAndAdoptPreserveExecutableFilter)
{
    void *data = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(data, nullptr);
    std::memset(data, 0xCC, 0x1000);
    const std::uint8_t marker[] = {0xDE, 0xAD, 0xBE, 0xEF};
    std::memcpy(static_cast<std::uint8_t *>(data) + 0x100, marker, sizeof(marker));
    const dmk::Region scope{dmk::Address{reinterpret_cast<std::uintptr_t>(data)}, 0x1000};

    mf::CandidateSpec rung;
    rung.mode = sc::Mode::Direct;
    rung.pattern = "DE AD BE EF";

    mf::SignatureRecord readable;
    readable.label = "page-class";
    readable.kind = an::AnchorKind::RipGlobal;
    readable.ladder = {rung};
    const auto readable_signature = mf::Signature::compile(readable);
    ASSERT_TRUE(readable_signature.has_value()) << readable_signature.error().message();
    EXPECT_EQ(readable_signature->resolve(scope).status, an::AnchorStatus::Resolved);

    mf::SignatureRecord executable = readable;
    executable.pages = sc::Pages::Executable;
    const auto executable_signature = mf::Signature::compile(executable);
    ASSERT_TRUE(executable_signature.has_value()) << executable_signature.error().message();
    EXPECT_EQ(executable_signature->record().pages, sc::Pages::Executable);
    EXPECT_EQ(executable_signature->resolve(scope).status, an::AnchorStatus::Failed);

    const sc::Candidate candidates[] = {sc::Candidate::direct("data-marker", sc::Pattern::literal("DE AD BE EF"))};
    an::Anchor source{};
    source.label = "page-class-adopt";
    source.kind = an::AnchorKind::RipGlobal;
    source.site = candidates;
    source.pages = sc::Pages::Executable;
    const auto adopted = mf::Signature::adopt(source);
    ASSERT_TRUE(adopted.has_value()) << adopted.error().message();
    EXPECT_EQ(adopted->record().pages, sc::Pages::Executable);
    EXPECT_EQ(adopted->resolve(scope).status, an::AnchorStatus::Failed);

    VirtualFree(data, 0, MEM_RELEASE);
}

TEST(ManifestPageClassTest, CompileAndAdoptRejectInvalidPageClass)
{
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::Direct;
    rung.pattern = "DE AD BE EF";

    mf::SignatureRecord record;
    record.label = "invalid-page-class";
    record.kind = an::AnchorKind::RipGlobal;
    record.ladder = {rung};
    record.pages = static_cast<sc::Pages>(0xFFU);
    const auto compiled = mf::Signature::compile(record);
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);

    // The checked encoder must not normalize an out-of-range page class to a permissive token.
    const mf::Manifest malformed_manifest{.records = {record}};
    const auto encoded = mf::serialize_checked(malformed_manifest);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, dmk::ErrorCode::InvalidArg);

    const sc::Candidate candidates[] = {
        sc::Candidate::direct("invalid-page-class", sc::Pattern::literal("DE AD BE EF"))};
    an::Anchor source{};
    source.label = "invalid-page-class";
    source.kind = an::AnchorKind::RipGlobal;
    source.site = candidates;
    source.pages = static_cast<sc::Pages>(0xFFU);
    const auto adopted = mf::Signature::adopt(source);
    ASSERT_FALSE(adopted.has_value());
    EXPECT_EQ(adopted.error().code, dmk::ErrorCode::InvalidArg);
}

// A RipRelative rung whose disp32 window falls outside an architecturally valid instruction is refused by parse
// and compile; the checked encoder must refuse it too, or save() would truncate a last-known-good file and write
// output its own load() rejects.
TEST(ManifestSerializeTest, InvalidRipRelativeDecodeLayoutFailsClosed)
{
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::RipRelative;
    rung.pattern = "48 8B 05 ?? ?? ?? ??";
    // Decode offsets left at their defaults: displacement_at 0 with instruction_length 0 leaves no room for a
    // disp32, the forgotten-field shape a programmatic caller most easily produces.
    mf::SignatureRecord record;
    record.label = "invalid-rip-layout";
    record.kind = an::AnchorKind::RipGlobal;
    record.ladder = {rung};

    const auto compiled = mf::Signature::compile(record);
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);

    const auto encoded = mf::serialize_checked(mf::Manifest{.records = {record}});
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, dmk::ErrorCode::InvalidArg);

    // The gate covers every emitted rung, including a ladder rung on a kind compile never reads: the emitter writes
    // the rung section regardless of record kind, and parse_rung gates it by the rung's own mode on reload.
    mf::SignatureRecord stray = record;
    stray.label = "stray-rung";
    stray.kind = an::AnchorKind::ExportName;
    stray.module = "kernel32.dll";
    stray.export_name = "CreateFileW";
    const auto stray_encoded = mf::serialize_checked(mf::Manifest{.records = {stray}});
    ASSERT_FALSE(stray_encoded.has_value());
    EXPECT_EQ(stray_encoded.error().code, dmk::ErrorCode::InvalidArg);

    ScopedManifestFile rejected_save("rip_layout_save");
    {
        std::ofstream out(rejected_save.path(), std::ios::binary);
        out << "last-known-good";
    }
    const auto saved = mf::save(rejected_save.path(), mf::Manifest{.records = {record}});
    ASSERT_FALSE(saved.has_value());
    EXPECT_EQ(saved.error().code, dmk::ErrorCode::InvalidArg);
    std::ifstream retained_stream(rejected_save.path(), std::ios::binary);
    const std::string retained{std::istreambuf_iterator<char>(retained_stream), std::istreambuf_iterator<char>()};
    EXPECT_EQ(retained, "last-known-good");

    // Acceptance control: evidence through the disp32 is sufficient even when an immediate trails it.
    rung.pattern = "C7 05 ?? ?? ?? ??";
    rung.displacement_at = 2;
    rung.instruction_length = 10;
    record.ladder = {rung};
    const auto valid_encoded = mf::serialize_checked(mf::Manifest{.records = {record}});
    ASSERT_TRUE(valid_encoded.has_value()) << valid_encoded.error().message();
}

TEST(ManifestSerializeTest, RipRelativePatternMustSpanDisplacement)
{
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::RipRelative;
    rung.pattern = "48 8B 05";
    rung.displacement_at = 3;
    rung.instruction_length = 7;
    mf::SignatureRecord record;
    record.label = "short-rip";
    record.kind = an::AnchorKind::RipGlobal;
    record.ladder = {rung};

    const auto encoded = mf::serialize_checked(mf::Manifest{.records = {record}});
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, dmk::ErrorCode::InvalidArg);
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

TEST(ManifestParseTest, RipRelativeRungWithCoveredDisplacementParses)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = rip_relative\npattern = C7 05 ?? ?? ?? ??\n"
                                  "displacement_at = 2\ninstruction_length = 10\n");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records[0].ladder.size(), 1u);
    EXPECT_EQ(parsed->records[0].ladder[0].mode, sc::Mode::RipRelative);
    EXPECT_EQ(parsed->records[0].ladder[0].displacement_at, 2);
    EXPECT_EQ(parsed->records[0].ladder[0].instruction_length, 10u);
}

TEST(ManifestParseTest, RipRelativePatternMustSpanDisplacement)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = rip_relative\npattern = 48 8B 05\n"
                                  "displacement_at = 3\ninstruction_length = 7\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
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

TEST(ManifestParseTest, RipRelativeRungAboveX86InstructionLimitIsMalformed)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\n[sig.x]\nkind = rip_global\n"
                                  "[sig.x.rung.0]\nmode = rip_relative\npattern = 48 8B 05 ?? ?? ?? ??\n"
                                  "displacement_at = 3\ninstruction_length = 16\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, RipRelativeRungWithNegativeDisplacementIsMalformed)
{
    // A negative displacement_at is invalid before the helper converts it to an unsigned field offset.
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

TEST(ManifestBindingTest, InvalidBindingStructureFailsClosed)
{
    constexpr std::size_t MAX_VMT_BINDING_SLOTS = 4096;
    mf::SignatureRecord base;
    base.label = "b";
    base.kind = an::AnchorKind::Manual;
    base.manual_value = 1;
    ASSERT_TRUE(mf::Signature::compile(base).has_value()); // the default binding is structurally valid

    mf::SignatureRecord bad_kind = base;
    bad_kind.binding.kind = static_cast<mf::BindingKind>(0xFF);
    EXPECT_FALSE(mf::Signature::compile(bad_kind).has_value());

    // value_width is range-validated for a PointerChain (the only kind that reads it): a bad width on a chain fails,
    mf::SignatureRecord bad_width = base;
    bad_width.binding.kind = mf::BindingKind::PointerChain;
    bad_width.binding.offsets = {0x10};
    bad_width.binding.value_width = 3; // not one of {1, 2, 4, 8}
    EXPECT_FALSE(mf::Signature::compile(bad_width).has_value());

    // and a non-default value in a field the active kind never reads also fails closed: the inert value would fold
    // into the drift fingerprint yet never serialize, so a recaptured baseline could not survive its own
    // save/reload. One arm per inert field, each beside an otherwise valid binding.
    mf::SignatureRecord inert_width = base;
    inert_width.binding.kind = mf::BindingKind::Address;
    inert_width.binding.value_width = 3;
    EXPECT_FALSE(mf::Signature::compile(inert_width).has_value());

    mf::SignatureRecord inert_vmt = base;
    inert_vmt.binding.kind = mf::BindingKind::Address;
    inert_vmt.binding.vmt_index = 42;
    EXPECT_FALSE(mf::Signature::compile(inert_vmt).has_value());

    mf::SignatureRecord inert_offsets = base;
    inert_offsets.binding.kind = mf::BindingKind::VmtMethod;
    inert_offsets.binding.vmt_index = 1;
    inert_offsets.binding.offsets = {0x10};
    EXPECT_FALSE(mf::Signature::compile(inert_offsets).has_value());

    mf::SignatureRecord inert_register = base;
    inert_register.binding.kind = mf::BindingKind::PointerChain;
    inert_register.binding.offsets = {0x10};
    inert_register.binding.value_width = 4;
    inert_register.binding.read_register = hk::Gpr::Rbx;
    EXPECT_FALSE(mf::Signature::compile(inert_register).has_value());

    mf::SignatureRecord inert_xmm = base;
    inert_xmm.binding.kind = mf::BindingKind::VmtMethod;
    inert_xmm.binding.vmt_index = 1;
    inert_xmm.binding.xmm_index = 2;
    EXPECT_FALSE(mf::Signature::compile(inert_xmm).has_value());

    // The same validator guards checked serialization, so an inert edit cannot ride into the file either.
    const auto inert_encoded = mf::serialize_checked(mf::Manifest{.records = {inert_vmt}});
    ASSERT_FALSE(inert_encoded.has_value());
    EXPECT_EQ(inert_encoded.error().code, dmk::ErrorCode::InvalidArg);

    mf::SignatureRecord bad_gpr = base;
    bad_gpr.binding.kind = mf::BindingKind::MidHookRegister;
    bad_gpr.binding.read_register = static_cast<hk::Gpr>(0xFF);
    EXPECT_FALSE(mf::Signature::compile(bad_gpr).has_value());

    mf::SignatureRecord bad_xmm = base;
    bad_xmm.binding.kind = mf::BindingKind::MidHookRegister;
    bad_xmm.binding.xmm_index = 16; // out of range and not the unused sentinel
    EXPECT_FALSE(mf::Signature::compile(bad_xmm).has_value());

    mf::SignatureRecord bad_vmt = base;
    bad_vmt.binding.kind = mf::BindingKind::VmtMethod;
    bad_vmt.binding.vmt_index = MAX_VMT_BINDING_SLOTS;
    EXPECT_FALSE(mf::Signature::compile(bad_vmt).has_value());

    mf::SignatureRecord last_vmt = base;
    last_vmt.binding.kind = mf::BindingKind::VmtMethod;
    last_vmt.binding.vmt_index = MAX_VMT_BINDING_SLOTS - 1;
    EXPECT_TRUE(mf::Signature::compile(last_vmt).has_value());

    mf::SignatureRecord empty_chain = base;
    empty_chain.binding.kind = mf::BindingKind::PointerChain;
    empty_chain.binding.offsets.clear(); // a pointer chain with no offsets is not a chain
    EXPECT_FALSE(mf::Signature::compile(empty_chain).has_value());

    mf::SignatureRecord ok_chain = base;
    ok_chain.binding.kind = mf::BindingKind::PointerChain;
    ok_chain.binding.offsets = {0x10};
    ok_chain.binding.value_width = 4;
    EXPECT_TRUE(mf::Signature::compile(ok_chain).has_value());
}

// Binding keys are kind-scoped exactly as the emitter writes them, and rung decode keys are mode-scoped the same way.
// A key parsed into a field the active kind or mode never reads would fold into the drift fingerprint (or vanish from
// the next save) without an error, so each inert key fails closed as MalformedLine.
TEST(ManifestParseTest, InertBindingOrDecodeKeyFailsClosed)
{
    const auto rejects = [](std::string_view body)
    {
        const std::string text = std::format("[manifest]\nschema = 1\n{}", body);
        const auto parsed = mf::parse(text);
        ASSERT_FALSE(parsed.has_value()) << body;
        EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine) << body;
    };
    rejects("[sig.a]\nkind = manual\nmanual_value = 1\nbinding = address\noffsets = 0x10\n");
    rejects("[sig.a]\nkind = manual\nmanual_value = 1\nbinding = address\nvalue_width = 4\n");
    rejects("[sig.a]\nkind = manual\nmanual_value = 1\nbinding = address\nread_register = rax\n");
    rejects("[sig.a]\nkind = manual\nmanual_value = 1\nbinding = address\nxmm_index = 1\n");
    rejects("[sig.a]\nkind = manual\nmanual_value = 1\nbinding = address\nvmt_index = 42\n");
    rejects("[sig.a]\nkind = manual\nmanual_value = 1\nbinding = vmt_method\nvmt_index = 1\noffsets = 0x10\n");
    rejects("[sig.a]\nkind = manual\nmanual_value = 1\nbinding = pointer_chain\noffsets = 0x10\nvalue_width = 4\n"
            "read_register = rax\n");
    // With no `binding` key the record carries the Address default, so every binding key is inert.
    rejects("[sig.a]\nkind = manual\nmanual_value = 1\nvmt_index = 42\n");
    // Rung decode keys: walk_back is Direct-only; the RIP decode offsets are RipRelative-only.
    rejects("[sig.a]\nkind = rip_global\n[sig.a.rung.0]\nmode = rip_relative\npattern = DE AD\n"
            "displacement_at = 0x3\ninstruction_length = 0x7\nwalk_back = 0x8\n");
    rejects("[sig.a]\nkind = rip_global\n[sig.a.rung.0]\nmode = direct\npattern = DE AD\ndisplacement_at = 0x3\n");
    rejects("[sig.a]\nkind = rip_global\n[sig.a.rung.0]\nmode = direct\npattern = DE AD\ninstruction_length = 0x7\n");

    // Control: the active keys for the declared kind still parse and populate the binding.
    const auto accepted = mf::parse("[manifest]\nschema = 1\n[sig.a]\nkind = manual\nmanual_value = 1\n"
                                    "binding = vmt_method\nvmt_index = 3\n");
    ASSERT_TRUE(accepted.has_value()) << accepted.error().message();
    ASSERT_EQ(accepted->records.size(), 1u);
    EXPECT_EQ(accepted->records[0].binding.vmt_index, 3u);
}

// mutation_strict trusts a signature to authorize a write only when its binding matches the resolved typed
// domain and its kind is not a self-heal-incapable Manual. The tests below tolerate an unset baseline (a bare
// require_mutation_safe_binding policy, not the full strict() preset) so a rejection is attributable to the mutation
// gate rather than strict()'s reject_unset arm; a separate case pins the preset composition.

TEST(MutationStrictTest, RejectsRipDataAnchorBoundAsMidHook)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});

    mf::SignatureRecord record;
    record.label = "data.as.midhook";
    record.kind = an::AnchorKind::RipGlobal;
    record.pages = sc::Pages::Readable; // a data-page global -> DataAddress domain
    record.binding.kind = mf::BindingKind::MidHookRegister;
    record.binding.read_register = hk::Gpr::Rcx;
    mf::CandidateSpec rung;
    rung.mode = sc::Mode::Direct;
    rung.pattern = "DE AD BE EF 10 20 30 40";
    record.ladder = {rung};
    const auto compiled = mf::Signature::compile(std::move(record));
    ASSERT_TRUE(compiled.has_value()) << compiled.error().message();
    const mf::Signature sigs[] = {std::move(*compiled)};

    // The default gate trusts a resolved signature regardless of its binding.
    EXPECT_EQ(mf::resolve_and_gate(sigs, mf::GatePolicy{}, page.range()).trusted.size(), 1u);

    // mutation_strict safe-disables the RIP-data/MidHook mismatch.
    mf::GatePolicy mutation_only;
    mutation_only.require_mutation_safe_binding = true;
    const mf::GateResult gated = mf::resolve_and_gate(sigs, mutation_only, page.range());
    EXPECT_TRUE(gated.trusted.empty());
    ASSERT_EQ(gated.rejected.size(), 1u);
    EXPECT_EQ(gated.rejected[0].status, an::AnchorStatus::Resolved); // resolved, but not mutation-safe
    EXPECT_EQ(gated.rejected[0].reason, mf::GateReason::BindingCannotMutate);
}

TEST(MutationStrictTest, TrustsMatchingBindings)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x200, {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40});
    mf::GatePolicy mutation_only;
    mutation_only.require_mutation_safe_binding = true;

    // An executable-page RipGlobal (CodeSite) bound as a mid-hook matches.
    mf::SignatureRecord code;
    code.label = "code.midhook";
    code.kind = an::AnchorKind::RipGlobal;
    code.pages = sc::Pages::Executable;
    code.binding.kind = mf::BindingKind::MidHookRegister;
    code.binding.read_register = hk::Gpr::Rcx;
    mf::CandidateSpec code_rung;
    code_rung.mode = sc::Mode::Direct;
    code_rung.pattern = "DE AD BE EF 10 20 30 40";
    code.ladder = {code_rung};
    const auto code_sig = mf::Signature::compile(std::move(code));
    ASSERT_TRUE(code_sig.has_value()) << code_sig.error().message();
    const mf::Signature code_sigs[] = {std::move(*code_sig)};
    EXPECT_EQ(mf::resolve_and_gate(code_sigs, mutation_only, page.range()).trusted.size(), 1u);

    // A data-page RipGlobal (DataAddress) with an Address write binding matches: an address is a writable target.
    mf::SignatureRecord data;
    data.label = "data.write";
    data.kind = an::AnchorKind::RipGlobal;
    data.pages = sc::Pages::Readable;
    data.binding.kind = mf::BindingKind::Address;
    mf::CandidateSpec data_rung;
    data_rung.mode = sc::Mode::Direct;
    data_rung.pattern = "DE AD BE EF 10 20 30 40";
    data.ladder = {data_rung};
    const auto data_sig = mf::Signature::compile(std::move(data));
    ASSERT_TRUE(data_sig.has_value()) << data_sig.error().message();
    const mf::Signature data_sigs[] = {std::move(*data_sig)};
    EXPECT_EQ(mf::resolve_and_gate(data_sigs, mutation_only, page.range()).trusted.size(), 1u);
}

TEST(MutationStrictTest, RejectsManualFromAuthorizingMutation)
{
    const mf::Signature manual_sigs[] = {manual_signature("pinned", 0x14000)};
    // The default gate trusts a resolved Manual.
    EXPECT_EQ(mf::resolve_and_gate(manual_sigs, mf::GatePolicy{}, dmk::Region::host()).trusted.size(), 1u);

    // mutation_strict bars a Manual pin from authorizing a write: it carries no live evidence and cannot self-heal.
    mf::GatePolicy mutation_only;
    mutation_only.require_mutation_safe_binding = true;
    const mf::GateResult gated = mf::resolve_and_gate(manual_sigs, mutation_only, dmk::Region::host());
    EXPECT_TRUE(gated.trusted.empty());
    ASSERT_EQ(gated.rejected.size(), 1u);
    EXPECT_EQ(gated.rejected[0].reason, mf::GateReason::BindingCannotMutate);
}

TEST(MutationStrictTest, PresetComposesStrictPlusMutationSafety)
{
    constexpr mf::GatePolicy policy = mf::GatePolicy::mutation_strict();
    EXPECT_TRUE(policy.require_mutation_safe_binding);
    EXPECT_TRUE(policy.reject_on_fingerprint_drift);
    EXPECT_TRUE(policy.reject_unset_fingerprint);
    EXPECT_DOUBLE_EQ(policy.min_resolved_fraction, 1.0);
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

TEST(ManifestAdoptTest, AdoptsExportNameAnchor)
{
    // A fully-formed ExportName anchor adopts and round-trips the export symbol and its owning module through the
    // record's shared module field. Resolution against a real module is covered in test_anchor.cpp against the fixture
    // DLL.
    an::Anchor anchor{};
    anchor.label = "timer";
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = "kernel32.dll";
    anchor.export_name = "QueryPerformanceCounter";

    const auto adopted = mf::Signature::adopt(anchor);
    ASSERT_TRUE(adopted.has_value());
    EXPECT_EQ(adopted->kind(), an::AnchorKind::ExportName);
    EXPECT_EQ(adopted->record().module, "kernel32.dll");
    EXPECT_EQ(adopted->record().export_name, "QueryPerformanceCounter");
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

TEST(ManifestAdoptTest, CodeOperandByteWidthDomainFailsClosed)
{
    const sc::Candidate candidates[] = {sc::Candidate::direct("disp8", sc::Pattern::literal("8A 45 FF"))};
    an::Anchor anchor{};
    anchor.label = "width";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::MemoryDisplacement;
    anchor.operand_index = 1;
    anchor.byte_width = 8;

    const auto valid = mf::Signature::adopt(anchor);
    ASSERT_TRUE(valid.has_value()) << valid.error().message();
    EXPECT_EQ(valid->record().byte_width, 8);

    for (const std::uint8_t width : {std::uint8_t{9}, std::uint8_t{255}})
    {
        anchor.byte_width = width;
        const auto invalid = mf::Signature::adopt(anchor);
        ASSERT_FALSE(invalid.has_value()) << "width=" << static_cast<unsigned>(width);
        EXPECT_EQ(invalid.error().code, dmk::ErrorCode::InvalidArg);
    }
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
    // The fingerprint binds the record label, so each baseline is captured from a signature carrying the same label it
    // is applied to; a baseline from a different label would itself read as drift.
    EXPECT_EQ(manual_signature("u", 100, 0).fingerprint_state(), mf::FingerprintState::Unset);
    const std::uint64_t match_fp = manual_signature("m", 100).current_fingerprint();
    EXPECT_EQ(manual_signature("m", 100, match_fp).fingerprint_state(), mf::FingerprintState::Match);
    const std::uint64_t drift_fp = manual_signature("d", 100).current_fingerprint();
    EXPECT_EQ(manual_signature("d", 100, drift_fp ^ 1ULL).fingerprint_state(), mf::FingerprintState::Drifted);
}

TEST(ManifestFingerprintTest, RecaptureAdoptsCurrentAsBaseline)
{
    mf::Signature sig = manual_signature("probe", 100, 0);
    ASSERT_EQ(sig.fingerprint_state(), mf::FingerprintState::Unset);
    sig.recapture_fingerprint();
    EXPECT_EQ(sig.fingerprint_state(), mf::FingerprintState::Match);
    EXPECT_EQ(sig.record().expected_fingerprint, sig.current_fingerprint());
}

// The drift fingerprint must cover the Binding (the consumer "read it there" contract), not only the locate evidence.
// Mutating ANY binding field -- register, offset chain, value width, XMM lane, or vtable slot -- must change the
// fingerprint, so an un-recaptured binding edit is caught. Every case shares the same Manual locate value (0x1000), so
// the ONLY thing that can move the fingerprint is the binding fold; if it did not fold the binding, a rcx -> rax churn
// or a +0x1C8 -> +0x1D0 field move would leave the fingerprint identical and slip past the gate unverified.
TEST(ManifestFingerprintTest, DriftGateCoversEveryBindingField)
{
    const auto fingerprint_of = [](const mf::Binding &binding)
    {
        mf::SignatureRecord record = manual_record("bind.probe", 0x1000);
        record.binding = binding;
        return mf::Signature::compile(record).value().current_fingerprint();
    };

    const std::uint64_t baseline = fingerprint_of(mf::Binding{});

    // read_register: a rcx -> rax mid-hook register churn.
    mf::Binding reg_a{};
    reg_a.kind = mf::BindingKind::MidHookRegister;
    reg_a.read_register = hk::Gpr::Rax;
    mf::Binding reg_b = reg_a;
    reg_b.read_register = hk::Gpr::Rbx;
    EXPECT_NE(baseline, fingerprint_of(reg_a));
    EXPECT_NE(fingerprint_of(reg_a), fingerprint_of(reg_b));

    // offsets: a shifted field offset in a pointer chain.
    mf::Binding off_a{};
    off_a.kind = mf::BindingKind::PointerChain;
    off_a.offsets = {0x1C8};
    off_a.value_width = 4;
    mf::Binding off_b = off_a;
    off_b.offsets = {0x1D0};
    EXPECT_NE(fingerprint_of(off_a), fingerprint_of(off_b));

    // value_width: a narrowed leaf read.
    mf::Binding width_b = off_a;
    width_b.value_width = 8;
    EXPECT_NE(fingerprint_of(off_a), fingerprint_of(width_b));

    // xmm_index: a moved float lane on a mid-hook register binding (the same register, a different XMM slot).
    mf::Binding xmm_a{};
    xmm_a.kind = mf::BindingKind::MidHookRegister;
    xmm_a.read_register = hk::Gpr::Rax;
    xmm_a.xmm_index = 0;
    mf::Binding xmm_b = xmm_a;
    xmm_b.xmm_index = 1;
    EXPECT_NE(fingerprint_of(xmm_a), fingerprint_of(xmm_b));

    // vmt_index: a moved virtual slot.
    mf::Binding vmt_a{};
    vmt_a.kind = mf::BindingKind::VmtMethod;
    vmt_a.vmt_index = 7;
    mf::Binding vmt_b = vmt_a;
    vmt_b.vmt_index = 8;
    EXPECT_NE(fingerprint_of(vmt_a), fingerprint_of(vmt_b));

    // The drift GATE (fingerprint_state) is the observable safe-disable: capture a baseline, then a binding edit with
    // the same captured fingerprint must read as Drifted.
    mf::SignatureRecord recorded = manual_record("bind.gate", 0x1000);
    recorded.binding = off_a;
    mf::Signature captured = mf::Signature::compile(recorded).value();
    captured.recapture_fingerprint();
    ASSERT_EQ(captured.fingerprint_state(), mf::FingerprintState::Match);

    recorded.binding = off_b;
    recorded.expected_fingerprint = captured.record().expected_fingerprint;
    const mf::Signature edited = mf::Signature::compile(recorded).value();
    EXPECT_EQ(edited.fingerprint_state(), mf::FingerprintState::Drifted);
}

// The gate: resolve a manifest and partition it into trusted vs safe-disabled.

TEST(ManifestGateTest, TrustsResolvedRejectsDrifted)
{
    const std::uint64_t ok_fp = manual_signature("ok", 100).current_fingerprint();
    const std::uint64_t bad_fp = manual_signature("bad", 100).current_fingerprint();

    std::vector<mf::Signature> sigs;
    sigs.push_back(manual_signature("ok", 100, ok_fp));          // Match -> trusted
    sigs.push_back(manual_signature("bad", 100, bad_fp ^ 1ULL)); // Drifted -> rejected under default policy

    const mf::GateResult gate = mf::resolve_and_gate(sigs);
    ASSERT_EQ(gate.trusted.size(), 1u);
    ASSERT_EQ(gate.rejected.size(), 1u);
    EXPECT_EQ(gate.trusted[0].label, "ok");
    EXPECT_EQ(gate.trusted[0].address.raw(), 100u);
    EXPECT_EQ(gate.rejected[0].label, "bad");
    EXPECT_EQ(gate.rejected[0].fingerprint, mf::FingerprintState::Drifted);
    EXPECT_EQ(gate.rejected[0].reason, mf::GateReason::FingerprintDrifted);
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
    EXPECT_EQ(gate.rejected[0].reason, mf::GateReason::FingerprintUnset);
}

TEST(ManifestGateTest, StrictPresetRejectsUnsetAndRequiresFullResolution)
{
    // The strict() preset bundles the security-conscious posture; the default-constructed policy stays lenient.
    const mf::GatePolicy strict = mf::GatePolicy::strict();
    EXPECT_TRUE(strict.reject_on_fingerprint_drift);
    EXPECT_TRUE(strict.reject_unset_fingerprint);
    EXPECT_DOUBLE_EQ(strict.min_resolved_fraction, 1.0);
    EXPECT_FALSE(mf::GatePolicy{}.reject_unset_fingerprint); // default is unchanged (opt-in, not a new default)

    // An unset baseline the default trusts is rejected under strict().
    std::vector<mf::Signature> unset;
    unset.push_back(manual_signature("unknown", 100, 0));
    EXPECT_EQ(mf::resolve_and_gate(unset).trusted.size(), 1u);
    const mf::GateResult unset_gate = mf::resolve_and_gate(unset, strict);
    EXPECT_TRUE(unset_gate.trusted.empty());
    ASSERT_EQ(unset_gate.rejected.size(), 1u);
    EXPECT_EQ(unset_gate.rejected[0].fingerprint, mf::FingerprintState::Unset);
    EXPECT_EQ(unset_gate.rejected[0].reason, mf::GateReason::FingerprintUnset);

    // The 1.0 floor demotes the entire manifest when a single signature drifts, even though the other would trust.
    const std::uint64_t ok_fp = manual_signature("ok", 200).current_fingerprint();
    const std::uint64_t bad_fp = manual_signature("bad", 200).current_fingerprint();
    std::vector<mf::Signature> mixed;
    mixed.push_back(manual_signature("ok", 200, ok_fp));          // matches its baseline -> would be trusted alone
    mixed.push_back(manual_signature("bad", 200, bad_fp ^ 1ULL)); // drifted -> rejected, so 1/2 < 1.0 floor
    const mf::GateResult mixed_gate = mf::resolve_and_gate(mixed, strict);
    EXPECT_TRUE(mixed_gate.trusted.empty());
    ASSERT_EQ(mixed_gate.rejected.size(), 2u);
    EXPECT_EQ(mixed_gate.rejected[0].reason, mf::GateReason::FingerprintDrifted);
    EXPECT_EQ(mixed_gate.rejected[1].reason, mf::GateReason::HealthFloor);
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
    EXPECT_EQ(gate.rejected[0].reason, mf::GateReason::Unresolved);
}

TEST(ManifestGateTest, WholeManifestFloorDemotesAllWhenTooUnhealthy)
{
    const std::uint64_t ok_fp = manual_signature("ok", 100).current_fingerprint();
    const std::uint64_t bad_fp = manual_signature("bad", 100).current_fingerprint();

    std::vector<mf::Signature> sigs;
    sigs.push_back(manual_signature("ok", 100, ok_fp));          // would be trusted
    sigs.push_back(manual_signature("bad", 100, bad_fp ^ 1ULL)); // drifted -> rejected

    mf::GatePolicy policy;
    policy.min_resolved_fraction = 0.75; // only 1 of 2 trusts -> 0.5 < 0.75 -> demote all
    const mf::GateResult gate = mf::resolve_and_gate(sigs, policy);
    EXPECT_TRUE(gate.trusted.empty());
    ASSERT_EQ(gate.rejected.size(), 2u);
    EXPECT_EQ(gate.rejected[0].reason, mf::GateReason::FingerprintDrifted);
    EXPECT_EQ(gate.rejected[1].reason, mf::GateReason::HealthFloor);
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

    // The Manual/backend posture gate keeps the in-code default before compile sees the bad pattern.
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

namespace
{
    bool policy_reject_all(std::int64_t, const void *) noexcept
    {
        return false;
    }

    bool policy_accept_all(std::int64_t, const void *) noexcept
    {
        return true;
    }

    constexpr int POLICY_CONTEXT_TOKEN = 0;

    bool policy_accept_context(std::int64_t, const void *context) noexcept
    {
        return context == &POLICY_CONTEXT_TOKEN;
    }

    // Distinct markers identify the selected ladder.
    constexpr std::size_t POLICY_DEFAULT_OFFSET = 0x100;
    constexpr std::size_t POLICY_OVERRIDE_OFFSET = 0x200;

    void plant_policy_markers(ScratchPage &page)
    {
        page.put(POLICY_DEFAULT_OFFSET, {0x10, 0x21, 0x32, 0x43, 0x54, 0x65});
        page.put(POLICY_OVERRIDE_OFFSET, {0x16, 0x27, 0x38, 0x49, 0x5A, 0x6B});
    }

    [[nodiscard]] mf::SignatureRecord policy_override_record(std::string label)
    {
        mf::SignatureRecord record;
        record.label = std::move(label);
        record.kind = an::AnchorKind::RipGlobal;
        mf::CandidateSpec rung;
        rung.mode = sc::Mode::Direct;
        rung.pattern = "16 27 38 49 5A 6B";
        record.ladder.push_back(std::move(rung));
        return record;
    }
} // namespace

TEST(ManifestOverlayTest, OverrideInheritsTheDefaultsRejectingValidator)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_policy_markers(page);

    const sc::Candidate default_ladder[] = {
        sc::Candidate::direct("default-marker", sc::Pattern::compile("10 21 32 43 54 65").value())};
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.v";
    defaults[0].kind = an::AnchorKind::RipGlobal;
    defaults[0].site = default_ladder;
    defaults[0].validator = &policy_reject_all;
    defaults[0].require_validator = true;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(policy_override_record("policy.v"));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);

    const an::ResolvedAnchor resolved = (*merged)[0].resolve(page.range());
    EXPECT_EQ(resolved.status, an::AnchorStatus::Failed);
    EXPECT_EQ(resolved.value, 0);
}

TEST(ManifestOverlayTest, OverrideStillResolvesUnderAnAcceptingValidator)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_policy_markers(page);

    const sc::Candidate default_ladder[] = {
        sc::Candidate::direct("default-marker", sc::Pattern::compile("10 21 32 43 54 65").value())};
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.v";
    defaults[0].kind = an::AnchorKind::RipGlobal;
    defaults[0].site = default_ladder;
    defaults[0].validator = &policy_accept_all;
    defaults[0].require_validator = true;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(policy_override_record("policy.v"));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);

    const an::ResolvedAnchor resolved = (*merged)[0].resolve(page.range());
    ASSERT_EQ(resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(resolved.value), page.addr(POLICY_OVERRIDE_OFFSET));
}

TEST(ManifestOverlayTest, OverrideInheritsTheDefaultsValidatorContext)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_policy_markers(page);

    const sc::Candidate default_ladder[] = {
        sc::Candidate::direct("default-marker", sc::Pattern::compile("10 21 32 43 54 65").value())};
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.context";
    defaults[0].kind = an::AnchorKind::RipGlobal;
    defaults[0].site = default_ladder;
    defaults[0].validator = &policy_accept_context;
    defaults[0].validator_context = &POLICY_CONTEXT_TOKEN;
    defaults[0].require_validator = true;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(policy_override_record("policy.context"));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    const an::ResolvedAnchor resolved = (*merged)[0].resolve(page.range());
    ASSERT_EQ(resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(resolved.value), page.addr(POLICY_OVERRIDE_OFFSET));
}

TEST(ManifestOverlayTest, OverrideCannotStripRequireValidator)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_policy_markers(page);

    const sc::Candidate default_ladder[] = {
        sc::Candidate::direct("default-marker", sc::Pattern::compile("10 21 32 43 54 65").value())};
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.v";
    defaults[0].kind = an::AnchorKind::RipGlobal;
    defaults[0].site = default_ladder;
    defaults[0].require_validator = true;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(policy_override_record("policy.v"));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ((*merged)[0].resolve(page.range()).status, an::AnchorStatus::Failed);
}

TEST(ManifestOverlayTest, ValidateManualRidesOntoAManualOverride)
{
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.m";
    defaults[0].kind = an::AnchorKind::Manual;
    defaults[0].manual_value = 111;
    defaults[0].validator = &policy_reject_all;
    defaults[0].validate_manual = true;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(manual_record("policy.m", 999));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);

    const an::ResolvedAnchor resolved = (*merged)[0].resolve();
    EXPECT_EQ(resolved.status, an::AnchorStatus::Failed);
    EXPECT_EQ(resolved.value, 0);
}

TEST(ManifestOverlayTest, ManualOverrideCannotBypassACodeOperandValidator)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(POLICY_DEFAULT_OFFSET, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});

    const sc::Candidate default_ladder[] = {
        sc::Candidate::direct("default-operand", sc::Pattern::compile("48 05 F0 00 00 00").value())};
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.scalar-validator";
    defaults[0].kind = an::AnchorKind::CodeOperand;
    defaults[0].site = default_ladder;
    defaults[0].operand_kind = sc::OperandKind::Immediate;
    defaults[0].operand_index = 1;
    defaults[0].validator = &policy_reject_all;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(manual_record("policy.scalar-validator", 999));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ((*merged)[0].kind(), an::AnchorKind::CodeOperand);
    EXPECT_EQ((*merged)[0].resolve(page.range()).status, an::AnchorStatus::Failed);
}

TEST(ManifestOverlayTest, ManualOverrideCannotBypassARequiredBackendValidator)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(POLICY_DEFAULT_OFFSET, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00});

    const sc::Candidate default_ladder[] = {
        sc::Candidate::direct("default-operand", sc::Pattern::compile("48 05 F0 00 00 00").value())};
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.scalar-required";
    defaults[0].kind = an::AnchorKind::CodeOperand;
    defaults[0].site = default_ladder;
    defaults[0].operand_kind = sc::OperandKind::Immediate;
    defaults[0].operand_index = 1;
    defaults[0].require_validator = true;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(manual_record("policy.scalar-required", 999));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ((*merged)[0].kind(), an::AnchorKind::CodeOperand);
    EXPECT_EQ((*merged)[0].resolve(page.range()).status, an::AnchorStatus::Failed);
}

TEST(ManifestOverlayTest, BackendOverrideCannotBypassAManualValidator)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_policy_markers(page);

    an::Anchor defaults[1]{};
    defaults[0].label = "policy.manual-validator";
    defaults[0].kind = an::AnchorKind::Manual;
    defaults[0].manual_value = 111;
    defaults[0].validator = &policy_reject_all;
    defaults[0].validate_manual = true;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(policy_override_record("policy.manual-validator"));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ((*merged)[0].kind(), an::AnchorKind::Manual);
    EXPECT_EQ((*merged)[0].resolve(page.range()).status, an::AnchorStatus::Failed);
}

TEST(ManifestOverlayTest, ResultDomainChangingOverrideFallsBackToTheDefault)
{
    an::Anchor scalar_default[1]{};
    scalar_default[0].label = "policy.scalar";
    scalar_default[0].kind = an::AnchorKind::Manual;
    scalar_default[0].manual_value = 111;

    std::vector<mf::SignatureRecord> address_overrides;
    address_overrides.push_back(policy_override_record("policy.scalar"));

    const auto scalar_merged = mf::overlay(scalar_default, address_overrides);
    ASSERT_TRUE(scalar_merged.has_value());
    ASSERT_EQ(scalar_merged->size(), 1u);
    EXPECT_EQ((*scalar_merged)[0].kind(), an::AnchorKind::Manual);
    EXPECT_EQ((*scalar_merged)[0].resolve().value, 111);

    const sc::Candidate default_ladder[] = {
        sc::Candidate::direct("default-marker", sc::Pattern::compile("10 21 32 43 54 65").value())};
    an::Anchor address_default[1]{};
    address_default[0].label = "policy.addr";
    address_default[0].kind = an::AnchorKind::RipGlobal;
    address_default[0].site = default_ladder;

    std::vector<mf::SignatureRecord> scalar_overrides;
    scalar_overrides.push_back(manual_record("policy.addr", 999));

    const auto address_merged = mf::overlay(address_default, scalar_overrides);
    ASSERT_TRUE(address_merged.has_value());
    ASSERT_EQ(address_merged->size(), 1u);
    EXPECT_EQ((*address_merged)[0].kind(), an::AnchorKind::RipGlobal);
}

TEST(ManifestOverlayTest, PageClassFlipIsADomainChange)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_policy_markers(page);

    const sc::Candidate default_ladder[] = {
        sc::Candidate::direct("default-marker", sc::Pattern::compile("10 21 32 43 54 65").value())};
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.page";
    defaults[0].kind = an::AnchorKind::RipGlobal;
    defaults[0].site = default_ladder;
    defaults[0].pages = sc::Pages::Executable;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(policy_override_record("policy.page"));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ(static_cast<std::uintptr_t>((*merged)[0].resolve(page.range()).value), page.addr(POLICY_DEFAULT_OFFSET));

    std::vector<mf::SignatureRecord> matching;
    matching.push_back(policy_override_record("policy.page"));
    matching[0].pages = sc::Pages::Executable;

    const auto kept = mf::overlay(defaults, matching);
    ASSERT_TRUE(kept.has_value());
    ASSERT_EQ(kept->size(), 1u);
    EXPECT_EQ(static_cast<std::uintptr_t>((*kept)[0].resolve(page.range()).value), page.addr(POLICY_OVERRIDE_OFFSET));
}

TEST(ManifestOverlayTest, StringXrefReturnModeChangeFallsBack)
{
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.xref";
    defaults[0].kind = an::AnchorKind::StringXref;
    defaults[0].xref_text = "default literal";
    defaults[0].xref_return = sc::XrefReturn::StringPointerSlot;

    mf::SignatureRecord override_record;
    override_record.label = "policy.xref";
    override_record.kind = an::AnchorKind::StringXref;
    override_record.xref_text = "override literal";
    override_record.xref_return = sc::XrefReturn::ReferencingInstruction;
    const std::array overrides{std::move(override_record)};

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ((*merged)[0].record().xref_return, sc::XrefReturn::StringPointerSlot);
    EXPECT_EQ((*merged)[0].record().xref_text, "default literal");
}

TEST(ManifestOverlayTest, SameDomainBackendChangeKeepsTheOverride)
{
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.code-site";
    defaults[0].kind = an::AnchorKind::ExportName;
    defaults[0].export_name = "DefaultExport";

    mf::SignatureRecord override_record = policy_override_record("policy.code-site");
    override_record.pages = sc::Pages::Executable;
    const std::array overrides{std::move(override_record)};

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    EXPECT_EQ((*merged)[0].kind(), an::AnchorKind::RipGlobal);
    EXPECT_EQ((*merged)[0].record().pages, sc::Pages::Executable);
}

TEST(ManifestOverlayTest, SameKindMalformedOverrideFallsBackToTheDefault)
{
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    plant_policy_markers(page);

    const sc::Candidate default_ladder[] = {
        sc::Candidate::direct("default-marker", sc::Pattern::compile("10 21 32 43 54 65").value())};
    an::Anchor defaults[1]{};
    defaults[0].label = "policy.broken";
    defaults[0].kind = an::AnchorKind::RipGlobal;
    defaults[0].site = default_ladder;

    // Same kind, posture, and domain as the default, so only Signature::compile can reject it.
    mf::SignatureRecord broken = policy_override_record("policy.broken");
    broken.ladder[0].pattern = "GG HH";
    const std::array overrides{std::move(broken)};

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    ASSERT_EQ(merged->size(), 1u);
    const an::ResolvedAnchor resolved = (*merged)[0].resolve(page.range());
    ASSERT_EQ(resolved.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(resolved.value), page.addr(POLICY_DEFAULT_OFFSET));
}

TEST(ManifestOverlayTest, CompositeDefaultIgnoresAFileOverride)
{
    an::Anchor member_a{};
    member_a.label = "policy.q.a";
    member_a.kind = an::AnchorKind::Manual;
    member_a.manual_value = 7;
    an::Anchor member_b{};
    member_b.label = "policy.q.b";
    member_b.kind = an::AnchorKind::Manual;
    member_b.manual_value = 7;
    const an::Anchor *members[] = {&member_a, &member_b};

    an::Anchor defaults[1]{};
    defaults[0].label = "policy.quorum";
    defaults[0].kind = an::AnchorKind::Quorum;
    defaults[0].quorum_members = members;

    std::vector<mf::SignatureRecord> overrides;
    overrides.push_back(manual_record("policy.quorum", 999));

    const auto merged = mf::overlay(defaults, overrides);
    ASSERT_TRUE(merged.has_value());
    EXPECT_TRUE(merged->empty());
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
    EXPECT_EQ(serialize_ok(*loaded), serialize_ok(mf::Manifest{.records = records}));
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

TEST(ManifestStringTest, GateReasonTokens)
{
    EXPECT_EQ(mf::gate_reason_to_string(mf::GateReason::None), "none");
    EXPECT_EQ(mf::gate_reason_to_string(mf::GateReason::Unresolved), "unresolved");
    EXPECT_EQ(mf::gate_reason_to_string(mf::GateReason::FingerprintDrifted), "fingerprint-drifted");
    EXPECT_EQ(mf::gate_reason_to_string(mf::GateReason::FingerprintUnset), "fingerprint-unset");
    EXPECT_EQ(mf::gate_reason_to_string(mf::GateReason::BindingCannotMutate), "binding-cannot-mutate");
    EXPECT_EQ(mf::gate_reason_to_string(mf::GateReason::ContractRevision), "contract-revision");
    EXPECT_EQ(mf::gate_reason_to_string(mf::GateReason::ImageIdentity), "image-identity");
    EXPECT_EQ(mf::gate_reason_to_string(mf::GateReason::WinningEvidence), "winning-evidence");
    EXPECT_EQ(mf::gate_reason_to_string(mf::GateReason::HealthFloor), "health-floor");
}

// Contract revision: the manifest-level version stamp and the gate that ignores a stale file.

TEST(ManifestRevisionTest, RevisionRoundTripsAndOmitsWhenZero)
{
    mf::Manifest versioned;
    versioned.header.revision = 7;
    versioned.records.push_back(manual_record("flag", 0x1234));

    const std::string text = serialize_ok(versioned);
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
    EXPECT_EQ(serialize_ok(unversioned).find("revision"), std::string::npos);
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
    const std::string text = serialize_ok(manifest);

    const std::size_t schema_pos = text.find("schema");
    const std::size_t revision_pos = text.find("revision");
    ASSERT_NE(schema_pos, std::string::npos);
    ASSERT_NE(revision_pos, std::string::npos);
    EXPECT_LT(schema_pos, revision_pos);
}

namespace
{
    [[nodiscard]] std::string header_text()
    {
        return "[manifest]\nschema = 1\n";
    }

    // A canonical Manual record section: kind plus an explicit manual_value.
    [[nodiscard]] std::string manual_section(std::string_view label, long long value)
    {
        return std::format("[sig.{}]\nkind = manual\nmanual_value = {}\n", label, value);
    }
} // namespace

// Ambiguous persistent identities must be rejected before parsing or trust evaluation.
TEST(ManifestCollisionTest, CaseVariantOrDuplicateIdentityCannotReachGate)
{
    struct Rejection
    {
        std::string text;
        dmk::ErrorCode code;
        const char *what;
    };

    const std::vector<Rejection> rejected = {
        {header_text() + manual_section("dup", 0x111) + manual_section("dup", 0x222),
         dmk::ErrorCode::ManifestIdentityCollision, "exact duplicate section"},
        {header_text() + manual_section("Foo", 0x111) + manual_section("foo", 0x222),
         dmk::ErrorCode::ManifestIdentityCollision, "case-variant section"},
        {header_text() + manual_section("bar", 0x111) + "[sig.bar ]\nkind = manual\nmanual_value = 546\n",
         dmk::ErrorCode::ManifestIdentityCollision, "trailing-blank section"},
        {header_text() + "[manifest]\nschema = 1\n" + manual_section("x", 1), dmk::ErrorCode::ManifestIdentityCollision,
         "duplicate manifest header"},
        {header_text() + "[sig.x]\nkind = manual\nmanual_value = 1\nmanual_value = 2\n",
         dmk::ErrorCode::ManifestIdentityCollision, "duplicate key"},
        {header_text() + "[sig.x]\nkind = rip_global\n[sig.x.rung.0]\nmode = direct\npattern = DE AD\n"
                         "[sig.x.rung.0]\nmode = direct\npattern = BE EF\n",
         dmk::ErrorCode::ManifestIdentityCollision, "duplicate rung section"},
        // A leading-zero index spelling is a distinct store identity for a rung index the canonical probe already
        // consumed; accepting it would silently drop the shadow rung instead of failing closed.
        {header_text() + "[sig.x]\nkind = rip_global\n[sig.x.rung.0]\nmode = direct\npattern = DE AD\n"
                         "[sig.x.rung.00]\nmode = direct\npattern = BE EF\n",
         dmk::ErrorCode::MalformedLine, "non-canonical rung index spelling"},
        // A rung nested under another rung has no record to attach to; accepting it would silently drop it.
        {header_text() + "[sig.x]\nkind = rip_global\n[sig.x.rung.0]\nmode = direct\npattern = DE AD\n"
                         "[sig.x.rung.0.rung.1]\nmode = direct\npattern = BE EF\n",
         dmk::ErrorCode::MalformedLine, "rung nested under a rung"},
        // Escape guards: the backend tokenizes these such that a second [sig.foo] survives, so the prepass must see it
        // too. (1) An empty-key line never opens a heredoc, so the block below it is not swallowed.
        {header_text() + "[sig.foo]\nkind = manual\nmanual_value = 0\n= <<<END\n[sig.foo]\nkind = export_name\n"
                         "export_name = Sleep\nEND\n",
         dmk::ErrorCode::ManifestIdentityCollision, "empty-key heredoc hides a duplicate"},
        // (2) A section name ends at the FIRST ']', so [sig.foo]bar] folds to the same identity as [sig.foo].
        {header_text() + "[sig.foo]\nkind = manual\nmanual_value = 0\n[sig.foo]bar]\nkind = manual\nmanual_value = 1\n",
         dmk::ErrorCode::ManifestIdentityCollision, "first-bracket section name"},
        // (3) A lone carriage return is a line break, so CR-separated duplicate sections still collide.
        {"[manifest]\rschema = 1\r[sig.x]\rkind = manual\rmanual_value = 0\r[sig.x]\rkind = manual\rmanual_value = 1\r",
         dmk::ErrorCode::ManifestIdentityCollision, "carriage-return line breaks"},
        // (4) An empty-named section (here whitespace-only) re-opens the backend's implicit default section; rejecting
        // it stops a key collision from being split across the `[]` and escaping the per-section namespace.
        {header_text() + "[sig.a]\nkind = manual\nmanual_value = 1\n[   ]\nmanual_value = 2\n",
         dmk::ErrorCode::MalformedLine, "empty-named section re-opens default namespace"},
        // (5) The backend strips a leading UTF-8 BOM before tokenizing, so the prepass would validate a byte stream
        // one invisible prefix out of step with the store; any BOM fails closed before the two can diverge.
        {std::string("\xEF\xBB\xBF") + header_text() + manual_section("x", 1) + manual_section("x", 2),
         dmk::ErrorCode::MalformedLine, "utf-8 bom shifts the backend's byte stream"},
        // (6) The backend's tokenizer stops at the first NUL, so every byte after it would be validated here but never
        // loaded; any embedded NUL fails closed rather than letting a record vanish.
        {header_text() + manual_section("x", 1) + std::string(1, '\0') + manual_section("x", 2),
         dmk::ErrorCode::MalformedLine, "embedded NUL truncates the backend's parse"},
        {header_text() + "[SIG.x]\nkind = manual\nmanual_value = 1\n", dmk::ErrorCode::MalformedLine,
         "miscased sig prefix"},
        {"[Manifest]\nschema = 1\n" + manual_section("x", 1), dmk::ErrorCode::MalformedLine,
         "miscased manifest header"},
        {header_text() + "[sig.x]\nKind = manual\nmanual_value = 1\n", dmk::ErrorCode::MalformedLine, "miscased key"},
        // (7) A bracket line with no closing ']' is not discarded by the backend: FindEntry points its section cursor
        // at the name before testing for ']', so the next key line's terminator folds the unterminated name plus an
        // embedded newline into a `sig.`-prefixed record the prepass never validated. Fail closed on the open bracket.
        {header_text() + "[sig.foo]\nkind = manual\nmanual_value = 0\n[sig.evil\nkind = export_name\n"
                         "export_name = Sleep\n",
         dmk::ErrorCode::MalformedLine, "unterminated section bracket folds into the next line"},
    };

    for (const Rejection &r : rejected)
    {
        const auto parsed = mf::parse(r.text);
        ASSERT_FALSE(parsed.has_value()) << r.what << ": expected rejection";
        EXPECT_EQ(parsed.error().code, r.code) << r.what;
    }

    mf::Manifest collided;
    collided.records.push_back(manual_record("Writer", 0x111));
    collided.records.push_back(manual_record("writer", 0x222));
    const auto encoded = mf::serialize_checked(collided);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, dmk::ErrorCode::ManifestIdentityCollision);

    mf::Manifest duplicated;
    duplicated.records.push_back(manual_record("same", 0x111));
    duplicated.records.push_back(manual_record("same", 0x222));
    const auto duplicate_encoded = mf::serialize_checked(duplicated);
    ASSERT_FALSE(duplicate_encoded.has_value());
    EXPECT_EQ(duplicate_encoded.error().code, dmk::ErrorCode::ManifestIdentityCollision);

    ScopedManifestFile destination("collision_save");
    {
        std::ofstream out(destination.path(), std::ios::binary);
        out << "last-known-good";
    }
    const auto saved = mf::save(destination.path(), collided);
    ASSERT_FALSE(saved.has_value());
    EXPECT_EQ(saved.error().code, dmk::ErrorCode::ManifestIdentityCollision);
    std::ifstream retained_stream(destination.path(), std::ios::binary);
    const std::string retained{std::istreambuf_iterator<char>(retained_stream), std::istreambuf_iterator<char>()};
    EXPECT_EQ(retained, "last-known-good");

    // Labels aaa and AAA pin distinct values but occupy the same reserved case-folded identity.
    const auto crossed = mf::parse(header_text() + manual_section("aaa", 0x111) + manual_section("AAA", 0x222));
    ASSERT_FALSE(crossed.has_value());
    EXPECT_EQ(crossed.error().code, dmk::ErrorCode::ManifestIdentityCollision);

    // A canonical, collision-free manifest still parses and gates both records.
    const auto clean = mf::parse(header_text() + manual_section("aaa", 0x111) + manual_section("bbb", 0x222));
    ASSERT_TRUE(clean.has_value()) << clean.error().message();
    ASSERT_EQ(clean->records.size(), 2u);
    std::vector<mf::Signature> sigs;
    for (const mf::SignatureRecord &rec : clean->records)
    {
        auto compiled = mf::Signature::compile(rec);
        ASSERT_TRUE(compiled.has_value()) << compiled.error().message();
        sigs.push_back(std::move(*compiled));
    }
    const mf::GateResult gate = mf::resolve_and_gate(sigs);
    EXPECT_EQ(gate.trusted.size(), 2u);
    EXPECT_NE(gate.find("aaa"), nullptr);
    EXPECT_NE(gate.find("bbb"), nullptr);
}

// A record label carrying a miscased '.RUNG.' marker is an ordinary record, not a candidate rung: parse reads the
// marker case-sensitively, and the raw grammar prepass must classify identically, so such records are counted against
// max_records and never charged to the per-record rung cap.
TEST(ManifestRoundTripTest, MiscasedRungMarkerInLabelIsARecordNotARung)
{
    const mf::ManifestLimits defaults = mf::ManifestLimits::conservative();
    const std::size_t count = defaults.max_rungs_per_record + 1; // one past the rung cap, far below max_records
    std::string text = header_text();
    for (std::size_t i = 0; i < count; ++i)
    {
        text += std::format("[sig.a.RUNG.{}]\nkind = manual\nmanual_value = {}\n", i, i);
    }
    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), count);
    EXPECT_EQ(parsed->records.front().label, "a.RUNG.0");

    // The same records round-trip through the checked encoder, whose grammar re-pass must also treat them as records.
    const auto reencoded = mf::serialize_checked(*parsed);
    ASSERT_TRUE(reencoded.has_value()) << reencoded.error().message();
    const auto reparsed = mf::parse(*reencoded);
    ASSERT_TRUE(reparsed.has_value()) << reparsed.error().message();
    EXPECT_EQ(reparsed->records.size(), count);
}

// Heredoc framing must not truncate content or swallow a later record.
TEST(ManifestRoundTripTest, HeredocFramingCannotSwallowRecords)
{
    // Write side: a value whose leading-trimmed form opens with the framing marker would re-parse as a heredoc opener
    // and swallow the lines below it; refuse it.
    for (std::string_view opener : {"<<<END", "  <<<TAG", "<<<END_OF_TEXT", "<<<"})
    {
        mf::SignatureRecord rec;
        rec.label = "opener";
        rec.kind = an::AnchorKind::StringXref;
        rec.xref_text = std::string(opener);
        const auto compiled = mf::Signature::compile(rec);
        ASSERT_FALSE(compiled.has_value()) << "value '" << opener << "' must be refused";
        EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
    }

    an::Anchor adopted_source;
    adopted_source.label = "adopted";
    adopted_source.kind = an::AnchorKind::StringXref;
    adopted_source.xref_text = "<<<TAG";
    const auto adopted = mf::Signature::adopt(adopted_source);
    ASSERT_FALSE(adopted.has_value());
    EXPECT_EQ(adopted.error().code, dmk::ErrorCode::InvalidArg);

    mf::SignatureRecord hand_built;
    hand_built.label = "hand_built";
    hand_built.kind = an::AnchorKind::StringXref;
    hand_built.xref_text = "<<<TAG";
    const auto hand_built_encoded = mf::serialize_checked(mf::Manifest{.records = {hand_built}});
    ASSERT_FALSE(hand_built_encoded.has_value());
    EXPECT_EQ(hand_built_encoded.error().code, dmk::ErrorCode::InvalidArg);

    ScopedManifestFile rejected_save("framing_save");
    {
        std::ofstream out(rejected_save.path(), std::ios::binary);
        out << "last-known-good";
    }
    const auto saved = mf::save(rejected_save.path(), mf::Manifest{.records = {hand_built}});
    ASSERT_FALSE(saved.has_value());
    EXPECT_EQ(saved.error().code, dmk::ErrorCode::InvalidArg);
    std::ifstream retained_stream(rejected_save.path(), std::ios::binary);
    const std::string retained{std::istreambuf_iterator<char>(retained_stream), std::istreambuf_iterator<char>()};
    EXPECT_EQ(retained, "last-known-good");

    // Write side: a heredoc-path value (embedded newline) whose body reaches the EXACT terminator under the
    // case-sensitive store, including trailing-blank variants that trim to it, truncates on reload; refuse those.
    for (std::string_view poison : {"a\nEND_OF_TEXT\nb", "a\nEND_OF_TEXT  \nb", "a\nEND_OF_TEXT\t\nb"})
    {
        mf::SignatureRecord rec;
        rec.label = "terminator";
        rec.kind = an::AnchorKind::StringXref;
        rec.xref_text = std::string(poison);
        const auto compiled = mf::Signature::compile(rec);
        ASSERT_FALSE(compiled.has_value()) << "value must be refused (terminator collision)";
        EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);
    }

    // Write side: the one validator guards every string-bearing record and rung field on compile, adopt, and checked
    // serialization, so a framing-poisoned value cannot ride into the file through any single field the record or
    // ladder loop would otherwise wave through. Each poison sits alone with the rest of the record clean, so dropping
    // that one field's term regresses it to fail-open with a failing arm here.
    const auto record_rejects = [](const mf::SignatureRecord &rec, std::string_view what)
    {
        const auto compiled = mf::Signature::compile(rec);
        EXPECT_FALSE(compiled.has_value()) << what << " must not compile";
        if (!compiled.has_value())
        {
            EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg) << what;
        }
        const auto encoded = mf::serialize_checked(mf::Manifest{.records = {rec}});
        EXPECT_FALSE(encoded.has_value()) << what << " must not encode";
        if (!encoded.has_value())
        {
            EXPECT_EQ(encoded.error().code, dmk::ErrorCode::InvalidArg) << what;
        }
    };
    const auto anchor_rejects = [](const an::Anchor &source, std::string_view what)
    {
        const auto adopt_result = mf::Signature::adopt(source);
        EXPECT_FALSE(adopt_result.has_value()) << what << " must not adopt";
        if (!adopt_result.has_value())
        {
            EXPECT_EQ(adopt_result.error().code, dmk::ErrorCode::InvalidArg) << what;
        }
    };
    const auto rung_rejects = [](mf::CandidateSpec spec, std::string_view what)
    {
        mf::SignatureRecord rec;
        rec.label = "rung_poison";
        rec.kind = an::AnchorKind::RipGlobal;
        rec.ladder.push_back(std::move(spec));
        const auto compiled = mf::Signature::compile(rec);
        EXPECT_FALSE(compiled.has_value()) << what << " must not compile";
        if (!compiled.has_value())
        {
            EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg) << what;
        }
        const auto encoded = mf::serialize_checked(mf::Manifest{.records = {rec}});
        EXPECT_FALSE(encoded.has_value()) << what << " must not encode";
        if (!encoded.has_value())
        {
            EXPECT_EQ(encoded.error().code, dmk::ErrorCode::InvalidArg) << what;
        }
    };
    for (std::string_view poison : {"<<<TAG", "line\rbreak", "a\nEND_OF_TEXT\nb"})
    {
        {
            mf::SignatureRecord rec;
            rec.label = "module_poison";
            rec.kind = an::AnchorKind::ExportName;
            rec.export_name = "Symbol";
            rec.module = std::string(poison);
            record_rejects(rec, "record.module");
        }
        {
            mf::SignatureRecord rec;
            rec.label = "mangled_poison";
            rec.kind = an::AnchorKind::VtableIdentity;
            rec.mangled = std::string(poison);
            record_rejects(rec, "record.mangled");
        }
        {
            mf::SignatureRecord rec;
            rec.label = "export_poison";
            rec.kind = an::AnchorKind::ExportName;
            rec.export_name = std::string(poison);
            record_rejects(rec, "record.export_name");
        }
        // Anchor string fields are borrowed views: assign the loop's literal-backed view directly, because an
        // owning temporary would be destroyed before adopt reads it.
        {
            an::Anchor source;
            source.label = "adopt_module";
            source.kind = an::AnchorKind::ExportName;
            source.export_name = "Symbol";
            source.export_module = poison;
            anchor_rejects(source, "anchor.export_module");
        }
        {
            an::Anchor source;
            source.label = "adopt_mangled";
            source.kind = an::AnchorKind::VtableIdentity;
            source.mangled = poison;
            anchor_rejects(source, "anchor.mangled");
        }
        {
            an::Anchor source;
            source.label = "adopt_export";
            source.kind = an::AnchorKind::ExportName;
            source.export_name = poison;
            anchor_rejects(source, "anchor.export_name");
        }
        {
            mf::CandidateSpec spec;
            spec.mode = sc::Mode::Direct;
            spec.pattern = "DE AD";
            spec.name = std::string(poison);
            rung_rejects(spec, "rung.name");
        }
        {
            mf::CandidateSpec spec;
            spec.mode = sc::Mode::Direct;
            spec.pattern = std::string(poison);
            rung_rejects(spec, "rung.pattern");
        }
        {
            mf::CandidateSpec spec;
            spec.mode = sc::Mode::Direct;
            spec.pattern = "DE AD";
            spec.mangled = std::string(poison);
            rung_rejects(spec, "rung.mangled");
        }
        {
            mf::CandidateSpec spec;
            spec.mode = sc::Mode::Direct;
            spec.pattern = "DE AD";
            spec.string_text = std::string(poison);
            rung_rejects(spec, "rung.string_text");
        }
    }

    // A case variant of the terminator is NOT the terminator under the case-sensitive store, so it is ordinary content
    // that round-trips rather than truncating; it must not be over-rejected.
    for (std::string_view safe : {"a\nend_of_text\nb", "a\nEnD_oF_tExT\nb"})
    {
        mf::SignatureRecord rec;
        rec.label = "case_variant";
        rec.kind = an::AnchorKind::StringXref;
        rec.xref_text = std::string(safe);
        mf::Manifest m;
        m.records.push_back(rec);
        const std::string text = serialize_ok(m);
        const auto parsed = mf::parse(text);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
        ASSERT_EQ(parsed->records.size(), 1u);
        EXPECT_EQ(parsed->records[0].xref_text, safe) << "value must round-trip";
    }

    // A legitimate multi-line value is framed as a heredoc, and a following sentinel record survives the round trip:
    // the body's section-looking line is data, not a section.
    mf::SignatureRecord multiline;
    multiline.label = "multiline";
    multiline.kind = an::AnchorKind::StringXref;
    multiline.xref_text = "first line\nsecond line\n[sig.decoy] is body text, not a section";
    mf::Manifest m;
    m.records.push_back(multiline);
    m.records.push_back(manual_record("sentinel", 0x5150));
    const std::string text = serialize_ok(m);
    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), 2u);
    EXPECT_EQ(parsed->records[0].xref_text, multiline.xref_text);
    EXPECT_EQ(parsed->records[1].label, "sentinel");

    // Parse side: an unterminated heredoc would absorb every record below it to EOF; the prepass rejects it rather than
    // letting [sig.victim] vanish into the value.
    const std::string unterminated = "[manifest]\nschema = 1\n[sig.attacker]\nkind = string_xref\n"
                                     "xref_text = <<<NEVER_CLOSED\nbody line\n[sig.victim]\nkind = manual\n"
                                     "manual_value = 1\n";
    const auto swallowed = mf::parse(unterminated);
    ASSERT_FALSE(swallowed.has_value());
    EXPECT_EQ(swallowed.error().code, dmk::ErrorCode::ManifestFramingUnsafe);

    // A heredoc whose FIRST body line is its terminator is not an empty value in the backend: LoadMultiLineText
    // leaves the value cursor on the terminator line and restores its line break, so the store would load the tag
    // line plus every byte up to the next parser-written NUL (here, a raw CR or a following key's name) -- content
    // the prepass models as empty and never charges against the caps. Each row must fail closed at the prepass.
    for (const std::string_view tag_first : {
             "[manifest]\nschema = 1\n[sig.a]\nkind = string_xref\nxref_text = <<<TAG\nTAG\n",
             "[manifest]\r\nschema = 1\r\n[sig.a]\r\nkind = string_xref\r\n"
             "xref_text = <<<TAG\r\nTAG\r\nmodule = m\r\n",
             "[manifest]\nschema = 1\n[sig.a]\nkind = string_xref\nxref_text = <<<<<<X\n<<<X\n",
         })
    {
        const auto rejected = mf::parse(tag_first);
        ASSERT_FALSE(rejected.has_value()) << tag_first;
        EXPECT_EQ(rejected.error().code, dmk::ErrorCode::ManifestFramingUnsafe) << tag_first;
    }
    // Control: a blank body line before the terminator is a genuinely empty value in both tokenizers, so it parses.
    const auto blank_body = mf::parse("[manifest]\nschema = 1\n[sig.a]\nkind = string_xref\n"
                                      "xref_text = <<<TAG\n\nTAG\n");
    ASSERT_TRUE(blank_body.has_value()) << blank_body.error().message();
    ASSERT_EQ(blank_body->records.size(), 1u);
    EXPECT_EQ(blank_body->records[0].xref_text, "");

    ScopedManifestFile rejected_load("framing_load");
    {
        std::ofstream out(rejected_load.path(), std::ios::binary);
        out << unterminated;
    }
    const auto loaded = mf::load(rejected_load.path());
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, dmk::ErrorCode::ManifestFramingUnsafe);

    // Parse side: a heredoc opener whose tag is empty terminates differently here and in the backend (the backend's
    // terminator trim never removes a line's first character, so a whitespace-only line closes the block only for the
    // prepass); reject it before the two tokenizers can desynchronize section context.
    for (std::string_view tagless : {"xref_text = <<<\n", "xref_text = <<<   \n"})
    {
        const std::string desync = "[manifest]\nschema = 1\n[sig.a]\nkind = string_xref\n" + std::string(tagless) +
                                   " \n[sig.b]\nkind = manual\nmanual_value = 2\n";
        const auto tagless_parsed = mf::parse(desync);
        ASSERT_FALSE(tagless_parsed.has_value());
        EXPECT_EQ(tagless_parsed.error().code, dmk::ErrorCode::ManifestFramingUnsafe);
    }
}

// Every persistent resource limit is enforced atomically at its boundary.
TEST(ManifestLimitsTest, EveryPersistentResourceLimitIsEnforcedAtomically)
{
    // max_records.
    {
        const auto records_text = [](std::size_t n)
        {
            std::string t = header_text();
            for (std::size_t i = 0; i < n; ++i)
            {
                t += manual_section(std::format("r{}", i), static_cast<long long>(i) + 1);
            }
            return t;
        };
        mf::ManifestLimits limits;
        limits.max_records = 3;
        ASSERT_TRUE(mf::parse(records_text(3), limits).has_value());
        const auto over = mf::parse(records_text(4), limits);
        ASSERT_FALSE(over.has_value());
        EXPECT_EQ(over.error().code, dmk::ErrorCode::SizeTooLarge);

        mf::Manifest manifest;
        for (std::size_t i = 0; i < 3; ++i)
        {
            manifest.records.push_back(manual_record(std::format("s{}", i), static_cast<long long>(i) + 1));
        }
        ASSERT_TRUE(mf::serialize_checked(manifest, limits).has_value());
        manifest.records.push_back(manual_record("s3", 4));
        const auto encode_over = mf::serialize_checked(manifest, limits);
        ASSERT_FALSE(encode_over.has_value());
        EXPECT_EQ(encode_over.error().code, dmk::ErrorCode::SizeTooLarge);
    }

    // max_rungs_per_record.
    {
        const auto rungs_text = [](std::size_t n)
        {
            std::string t = header_text() + "[sig.laddered]\nkind = rip_global\n";
            for (std::size_t i = 0; i < n; ++i)
            {
                t += std::format("[sig.laddered.rung.{}]\nmode = direct\npattern = DE AD\n", i);
            }
            return t;
        };
        mf::ManifestLimits limits;
        limits.max_rungs_per_record = 2;
        ASSERT_TRUE(mf::parse(rungs_text(2), limits).has_value());
        const auto over = mf::parse(rungs_text(3), limits);
        ASSERT_FALSE(over.has_value());
        EXPECT_EQ(over.error().code, dmk::ErrorCode::SizeTooLarge);

        mf::SignatureRecord record;
        record.label = "laddered";
        record.kind = an::AnchorKind::RipGlobal;
        for (std::size_t i = 0; i < 2; ++i)
        {
            mf::CandidateSpec spec;
            spec.mode = sc::Mode::Direct;
            spec.pattern = "DE AD";
            record.ladder.push_back(std::move(spec));
        }
        mf::Manifest manifest{.records = {record}};
        ASSERT_TRUE(mf::serialize_checked(manifest, limits).has_value());
        record.ladder.push_back(record.ladder.front());
        manifest.records[0] = std::move(record);
        const auto encode_over = mf::serialize_checked(manifest, limits);
        ASSERT_FALSE(encode_over.has_value());
        EXPECT_EQ(encode_over.error().code, dmk::ErrorCode::SizeTooLarge);
    }

    // The raw structural cap runs before semantic validation. Valid optional keys keep this independent of the
    // unknown-key rejection.
    {
        const auto keyed = [](std::size_t pad)
        {
            static constexpr std::array<std::string_view, 3> pool{"module = m\n", "fingerprint = 0x1\n",
                                                                  "binding = address\n"};
            std::string t = header_text() + "[sig.k]\nkind = manual\nmanual_value = 1\n";
            for (std::size_t i = 0; i < pad; ++i)
            {
                t += pool[i % pool.size()];
            }
            return t;
        };
        mf::ManifestLimits limits;
        limits.max_keys_per_section = 4; // kind + manual_value + 2 valid pad keys
        ASSERT_TRUE(mf::parse(keyed(2), limits).has_value());
        const auto over = mf::parse(keyed(3), limits);
        ASSERT_FALSE(over.has_value());
        EXPECT_EQ(over.error().code, dmk::ErrorCode::SizeTooLarge);

        mf::Manifest manifest{.records = {manual_record("k", 1)}};
        limits.max_keys_per_section = 3; // kind + binding + manual_value
        ASSERT_TRUE(mf::serialize_checked(manifest, limits).has_value());
        limits.max_keys_per_section = 2;
        const auto encode_over = mf::serialize_checked(manifest, limits);
        ASSERT_FALSE(encode_over.has_value());
        EXPECT_EQ(encode_over.error().code, dmk::ErrorCode::SizeTooLarge);
    }

    // max_sections (unknown padding sections are counted before the merge).
    {
        const auto padded = [](std::size_t pad)
        {
            std::string t = header_text(); // one section
            for (std::size_t i = 0; i < pad; ++i)
            {
                t += std::format("[pad.{}]\n", i);
            }
            return t;
        };
        mf::ManifestLimits limits;
        limits.max_sections = 3; // manifest + 2 pad
        ASSERT_TRUE(mf::parse(padded(2), limits).has_value());
        const auto over = mf::parse(padded(3), limits);
        ASSERT_FALSE(over.has_value());
        EXPECT_EQ(over.error().code, dmk::ErrorCode::SizeTooLarge);

        mf::Manifest manifest{.records = {manual_record("section", 1)}};
        limits.max_sections = 2; // manifest + one record
        ASSERT_TRUE(mf::serialize_checked(manifest, limits).has_value());
        limits.max_sections = 1;
        const auto encode_over = mf::serialize_checked(manifest, limits);
        ASSERT_FALSE(encode_over.has_value());
        EXPECT_EQ(encode_over.error().code, dmk::ErrorCode::SizeTooLarge);
    }

    // max_field_bytes.
    {
        // The cap must clear the fixed field values in the record (the "string_xref" kind token is 11 bytes); it is
        // the variable xref_text that is exercised at cap and cap+1.
        const auto field = [](std::size_t len)
        { return header_text() + "[sig.f]\nkind = string_xref\nxref_text = " + std::string(len, 'x') + "\n"; };
        mf::ManifestLimits limits;
        limits.max_field_bytes = 16;
        ASSERT_TRUE(mf::parse(field(16), limits).has_value());
        const auto over = mf::parse(field(17), limits);
        ASSERT_FALSE(over.has_value());
        EXPECT_EQ(over.error().code, dmk::ErrorCode::SizeTooLarge);

        limits.max_field_bytes = 11;
        const std::string heredoc_at_cap =
            header_text() + "[sig.h]\nkind = string_xref\nxref_text = <<<TAG\n12345\n12345\nTAG\n";
        ASSERT_TRUE(mf::parse(heredoc_at_cap, limits).has_value());
        const std::string heredoc_over =
            header_text() + "[sig.h]\nkind = string_xref\nxref_text = <<<TAG\n123456\n12345\nTAG\n";
        const auto heredoc_result = mf::parse(heredoc_over, limits);
        ASSERT_FALSE(heredoc_result.has_value());
        EXPECT_EQ(heredoc_result.error().code, dmk::ErrorCode::SizeTooLarge);

        ASSERT_TRUE(mf::parse(header_text() + manual_section(std::string(11, 'l'), 1), limits).has_value());
        const auto label_over = mf::parse(header_text() + manual_section(std::string(12, 'l'), 1), limits);
        ASSERT_FALSE(label_over.has_value());
        EXPECT_EQ(label_over.error().code, dmk::ErrorCode::SizeTooLarge);

        mf::Manifest label_manifest{.records = {manual_record(std::string(11, 'l'), 1)}};
        ASSERT_TRUE(mf::serialize_checked(label_manifest, limits).has_value());
        label_manifest.records[0].label.push_back('l');
        const auto encoded_label_over = mf::serialize_checked(label_manifest, limits);
        ASSERT_FALSE(encoded_label_over.has_value());
        EXPECT_EQ(encoded_label_over.error().code, dmk::ErrorCode::SizeTooLarge);
    }

    // max_total_decoded_bytes (the sum of every value byte). One manual record's values total 8 bytes; a second pushes
    // past the cap.
    {
        mf::ManifestLimits limits;
        limits.max_total_decoded_bytes = 10;
        ASSERT_TRUE(mf::parse(header_text() + manual_section("a", 1), limits).has_value());
        const auto over = mf::parse(header_text() + manual_section("a", 1) + manual_section("b", 1), limits);
        ASSERT_FALSE(over.has_value());
        EXPECT_EQ(over.error().code, dmk::ErrorCode::SizeTooLarge);

        mf::Manifest manifest{.records = {manual_record("a", 1)}};
        limits.max_total_decoded_bytes = 17; // schema + kind + binding + manual_value
        ASSERT_TRUE(mf::serialize_checked(manifest, limits).has_value());
        limits.max_total_decoded_bytes = 16;
        const auto encode_over = mf::serialize_checked(manifest, limits);
        ASSERT_FALSE(encode_over.has_value());
        EXPECT_EQ(encode_over.error().code, dmk::ErrorCode::SizeTooLarge);
    }

    // max_file_bytes through parse(), checked serialization, and load().
    {
        const std::string text = header_text() + manual_section("a", 1);
        mf::ManifestLimits limits;
        limits.max_file_bytes = text.size();
        ASSERT_TRUE(mf::parse(text, limits).has_value());
        --limits.max_file_bytes;
        const auto parse_over = mf::parse(text, limits);
        ASSERT_FALSE(parse_over.has_value());
        EXPECT_EQ(parse_over.error().code, dmk::ErrorCode::SizeTooLarge);

        const mf::Manifest empty_manifest;
        const auto encoded = mf::serialize_checked(empty_manifest);
        ASSERT_TRUE(encoded.has_value());
        limits = mf::ManifestLimits::conservative();
        limits.max_file_bytes = encoded->size();
        ASSERT_TRUE(mf::serialize_checked(empty_manifest, limits).has_value());
        --limits.max_file_bytes;
        const auto encode_over = mf::serialize_checked(empty_manifest, limits);
        ASSERT_FALSE(encode_over.has_value());
        EXPECT_EQ(encode_over.error().code, dmk::ErrorCode::SizeTooLarge);

        ScopedManifestFile file("oversize");
        {
            std::ofstream out(file.path(), std::ios::binary);
            out << text;
        }
        limits = mf::ManifestLimits::conservative();
        limits.max_file_bytes = text.size();
        ASSERT_TRUE(mf::load(file.path(), limits).has_value());
        --limits.max_file_bytes;
        const auto load_over = mf::load(file.path(), limits);
        ASSERT_FALSE(load_over.has_value());
        EXPECT_EQ(load_over.error().code, dmk::ErrorCode::SizeTooLarge);
    }

    // Pin the conservative values themselves at their exact boundaries.
    {
        const mf::ManifestLimits defaults = mf::ManifestLimits::conservative();

        std::string records_at_cap = header_text();
        for (std::size_t i = 0; i < defaults.max_records; ++i)
        {
            records_at_cap += manual_section(std::format("default_record_{}", i), static_cast<long long>(i));
        }
        ASSERT_TRUE(mf::parse(records_at_cap).has_value());
        const auto records_over = mf::parse(records_at_cap + manual_section("default_record_over", 1));
        ASSERT_FALSE(records_over.has_value());
        EXPECT_EQ(records_over.error().code, dmk::ErrorCode::SizeTooLarge);

        std::string rungs_at_cap = header_text() + "[sig.default_rungs]\nkind = rip_global\n";
        for (std::size_t i = 0; i < defaults.max_rungs_per_record; ++i)
        {
            rungs_at_cap += std::format("[sig.default_rungs.rung.{}]\nmode = direct\npattern = DE AD\n", i);
        }
        ASSERT_TRUE(mf::parse(rungs_at_cap).has_value());
        const auto rungs_over =
            mf::parse(rungs_at_cap + std::format("[sig.default_rungs.rung.{}]\nmode = direct\npattern = DE AD\n",
                                                 defaults.max_rungs_per_record));
        ASSERT_FALSE(rungs_over.has_value());
        EXPECT_EQ(rungs_over.error().code, dmk::ErrorCode::SizeTooLarge);

        // The default 64-key ceiling cannot be reached with valid padding, so use every valid Manual key under a
        // matching custom cap. The over case trips the raw count before semantic validation.
        mf::ManifestLimits key_limits = defaults;
        key_limits.max_keys_per_section = 6; // kind, manual_value, module, binding, fingerprint, image_identity
        const std::string keys_at_cap = header_text() + "[sig.default_keys]\nkind = manual\nmanual_value = 1\n"
                                                        "module = m\nbinding = address\nfingerprint = 0x1\n"
                                                        "image_identity = 1:1:1\n";
        ASSERT_TRUE(mf::parse(keys_at_cap, key_limits).has_value());
        const auto keys_over = mf::parse(keys_at_cap + "padding_over = x\n", key_limits);
        ASSERT_FALSE(keys_over.has_value());
        EXPECT_EQ(keys_over.error().code, dmk::ErrorCode::SizeTooLarge);

        std::string sections_at_cap = header_text();
        for (std::size_t i = 1; i < defaults.max_sections; ++i)
        {
            sections_at_cap += std::format("[padding.{}]\n", i);
        }
        ASSERT_TRUE(mf::parse(sections_at_cap).has_value());
        const auto sections_over = mf::parse(sections_at_cap + "[padding.over]\n");
        ASSERT_FALSE(sections_over.has_value());
        EXPECT_EQ(sections_over.error().code, dmk::ErrorCode::SizeTooLarge);

        const auto field_text = [](std::size_t size)
        {
            return header_text() + "[sig.default_field]\nkind = string_xref\nxref_text = " + std::string(size, 'x') +
                   "\n";
        };
        ASSERT_TRUE(mf::parse(field_text(defaults.max_field_bytes)).has_value());
        const auto field_over = mf::parse(field_text(defaults.max_field_bytes + 1));
        ASSERT_FALSE(field_over.has_value());
        EXPECT_EQ(field_over.error().code, dmk::ErrorCode::SizeTooLarge);

        std::string file_at_cap = header_text();
        file_at_cap.push_back('#');
        file_at_cap.append(defaults.max_file_bytes - file_at_cap.size() - 1, 'x');
        file_at_cap.push_back('\n');
        ASSERT_EQ(file_at_cap.size(), defaults.max_file_bytes);
        ASSERT_TRUE(mf::parse(file_at_cap).has_value());
        file_at_cap.push_back('x');
        const auto file_over = mf::parse(file_at_cap);
        ASSERT_FALSE(file_over.has_value());
        EXPECT_EQ(file_over.error().code, dmk::ErrorCode::SizeTooLarge);

        constexpr std::size_t FIXED_DECODED_BYTES = 12; // schema + kind
        const std::size_t aggregate_field_size = defaults.max_total_decoded_bytes - FIXED_DECODED_BYTES;
        const auto aggregate_text = [](std::size_t size)
        {
            return header_text() + "[sig.default_total]\nkind = string_xref\nxref_text = " + std::string(size, 'x') +
                   "\n";
        };
        mf::ManifestLimits aggregate_limits = defaults;
        aggregate_limits.max_field_bytes = aggregate_field_size + 1;
        aggregate_limits.max_file_bytes = aggregate_text(aggregate_field_size + 1).size();
        ASSERT_TRUE(mf::parse(aggregate_text(aggregate_field_size), aggregate_limits).has_value());
        const auto aggregate_over = mf::parse(aggregate_text(aggregate_field_size + 1), aggregate_limits);
        ASSERT_FALSE(aggregate_over.has_value());
        EXPECT_EQ(aggregate_over.error().code, dmk::ErrorCode::SizeTooLarge);
    }

    // The explicit authoring override raises numeric caps but keeps grammar validation active.
    {
        const std::size_t oversized_field = mf::ManifestLimits::conservative().max_field_bytes + 1;
        mf::SignatureRecord record;
        record.label = "advanced";
        record.kind = an::AnchorKind::StringXref;
        record.xref_text = std::string(oversized_field, 'x');
        const mf::Manifest manifest{.records = {record}};

        const auto conservative = mf::serialize_checked(manifest);
        ASSERT_FALSE(conservative.has_value());
        EXPECT_EQ(conservative.error().code, dmk::ErrorCode::SizeTooLarge);

        const mf::ManifestLimits advanced = mf::ManifestLimits::advanced();
        const auto encoded = mf::serialize_checked(manifest, advanced);
        ASSERT_TRUE(encoded.has_value()) << encoded.error().message();
        const auto parsed = mf::parse(*encoded, advanced);
        ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
        ASSERT_EQ(parsed->records.size(), 1u);
        EXPECT_EQ(parsed->records[0].xref_text.size(), oversized_field);
    }

    // Allocation failure at any materialization stage is a typed, atomic OutOfMemory, and the identical input is
    // retryable once memory returns. Only this exact-budget section needs a proxy-free STL; the limit checks above
    // run on every STL, so the guard sits here rather than at the top of the test.
    DMK_REQUIRE_PROXY_FREE_STL();
    {
        const std::string text = header_text() + manual_section("a", 1) + manual_section("b", 2);
        ASSERT_TRUE(mf::parse(text).has_value());
        const long long parse_before = dmk_test::thread_new_calls();
        const auto parse_control = mf::parse(text);
        const long long parse_allocation_count = dmk_test::thread_new_calls() - parse_before;
        ASSERT_TRUE(parse_control.has_value()) << parse_control.error().message();
        ASSERT_GT(parse_allocation_count, 0);

        for (long long budget = 0; budget < parse_allocation_count; ++budget)
        {
            bool ok = false;
            dmk::ErrorCode code = dmk::ErrorCode::Ok;
            {
                dmk_test::AllocFailScope guard(budget);
                const auto result = mf::parse(text);
                ok = result.has_value();
                if (!ok)
                {
                    code = result.error().code;
                }
            }
            EXPECT_FALSE(ok) << "budget=" << budget;
            if (!ok)
            {
                EXPECT_EQ(code, dmk::ErrorCode::OutOfMemory) << "budget=" << budget;
            }
        }
        const auto retry = mf::parse(text);
        ASSERT_TRUE(retry.has_value()) << retry.error().message();
        EXPECT_EQ(retry->records.size(), 2u);

        const mf::Manifest manifest{.records = {manual_record("a", 1), manual_record("b", 2)}};
        // Stabilize library-managed lazy initialization before measuring repeat-call allocations.
        ASSERT_TRUE(mf::serialize_checked(manifest).has_value());
        const long long before = dmk_test::thread_new_calls();
        const auto control = mf::serialize_checked(manifest);
        const long long allocation_count = dmk_test::thread_new_calls() - before;
        ASSERT_TRUE(control.has_value()) << control.error().message();
        ASSERT_GT(allocation_count, 0);

        for (long long budget = 0; budget < allocation_count; ++budget)
        {
            bool ok = false;
            dmk::ErrorCode code = dmk::ErrorCode::Ok;
            {
                dmk_test::AllocFailScope guard(budget);
                const auto result = mf::serialize_checked(manifest);
                ok = result.has_value();
                if (!ok)
                {
                    code = result.error().code;
                }
            }
            EXPECT_FALSE(ok) << "budget=" << budget;
            if (!ok)
            {
                EXPECT_EQ(code, dmk::ErrorCode::OutOfMemory) << "budget=" << budget;
            }
        }

        const auto encode_retry = mf::serialize_checked(manifest);
        ASSERT_TRUE(encode_retry.has_value()) << encode_retry.error().message();
        const auto reparsed = mf::parse(*encode_retry);
        ASSERT_TRUE(reparsed.has_value()) << reparsed.error().message();
        EXPECT_EQ(reparsed->records.size(), 2u);
    }

    // A failed reload never replaces a caller's trusted generation, and the same input is retryable.
    {
        ScopedManifestFile file("atomic");
        {
            std::ofstream out(file.path(), std::ios::binary);
            out << header_text() << manual_section("keep", 0x1234);
        }
        auto initial = mf::load(file.path());
        ASSERT_TRUE(initial.has_value()) << initial.error().message();
        mf::Manifest trusted = std::move(*initial);
        ASSERT_EQ(trusted.records.size(), 1u);

        std::string before;
        {
            std::ifstream before_stream(file.path(), std::ios::binary);
            before.assign(std::istreambuf_iterator<char>(before_stream), std::istreambuf_iterator<char>());
        }

        mf::ManifestLimits tight;
        tight.max_file_bytes = 4;
        const auto reloaded = mf::load(file.path(), tight);
        ASSERT_FALSE(reloaded.has_value());
        EXPECT_EQ(reloaded.error().code, dmk::ErrorCode::SizeTooLarge);

        // The rejected reload consumed nothing: the source bytes are untouched and the identical input re-reads into
        // the same generation the caller already trusts.
        std::string after;
        {
            std::ifstream after_stream(file.path(), std::ios::binary);
            after.assign(std::istreambuf_iterator<char>(after_stream), std::istreambuf_iterator<char>());
        }
        EXPECT_EQ(after, before);
        const auto retried = mf::load(file.path());
        ASSERT_TRUE(retried.has_value()) << retried.error().message();
        ASSERT_EQ(retried->records.size(), trusted.records.size());
        EXPECT_EQ(retried->records[0].label, trusted.records[0].label);
        EXPECT_EQ(retried->records[0].manual_value, trusted.records[0].manual_value);

        // The trusted generation survives an OutOfMemory rejection too: an allocation failure at any stage of a reload
        // (the path conversion caught in load(), the bounded reader's buffer, or the parse store) is a typed, atomic
        // OutOfMemory that leaves the source bytes and the caller's held records intact and the identical input
        // retryable. Sweeping every stage also exercises load()'s own bad_alloc catch, reachable no other way.
        ASSERT_TRUE(mf::load(file.path()).has_value());
        const long long load_before = dmk_test::thread_new_calls();
        const auto load_control = mf::load(file.path());
        const long long load_allocations = dmk_test::thread_new_calls() - load_before;
        ASSERT_TRUE(load_control.has_value()) << load_control.error().message();
        ASSERT_GT(load_allocations, 0);
        for (long long budget = 0; budget < load_allocations; ++budget)
        {
            bool ok = false;
            dmk::ErrorCode code = dmk::ErrorCode::Ok;
            {
                dmk_test::AllocFailScope guard(budget);
                const auto result = mf::load(file.path());
                ok = result.has_value();
                if (!ok)
                {
                    code = result.error().code;
                }
            }
            EXPECT_FALSE(ok) << "budget=" << budget;
            if (!ok)
            {
                EXPECT_EQ(code, dmk::ErrorCode::OutOfMemory) << "budget=" << budget;
            }
        }
        std::string after_oom;
        {
            std::ifstream after_stream(file.path(), std::ios::binary);
            after_oom.assign(std::istreambuf_iterator<char>(after_stream), std::istreambuf_iterator<char>());
        }
        EXPECT_EQ(after_oom, before);
        const auto oom_retry = mf::load(file.path());
        ASSERT_TRUE(oom_retry.has_value()) << oom_retry.error().message();
        ASSERT_EQ(oom_retry->records.size(), trusted.records.size());
        EXPECT_EQ(oom_retry->records[0].label, trusted.records[0].label);
        EXPECT_EQ(oom_retry->records[0].manual_value, trusted.records[0].manual_value);
    }
}

// An out-of-range persisted enum must not normalize to a valid token.
TEST(ManifestSerializeTest, OutOfRangePersistedEnumFailsClosed)
{
    const auto rejects = [](mf::SignatureRecord record)
    {
        mf::Manifest m;
        m.records.push_back(std::move(record));
        const auto encoded = mf::serialize_checked(m);
        ASSERT_FALSE(encoded.has_value());
        EXPECT_EQ(encoded.error().code, dmk::ErrorCode::InvalidArg);
    };

    {
        auto r = manual_record("k", 1);
        r.kind = static_cast<an::AnchorKind>(0xFF);
        rejects(r);
    }
    {
        auto r = manual_record("k", 1);
        r.kind = an::AnchorKind::Quorum; // composite, not serializable
        rejects(r);
    }
    {
        auto r = manual_record("k", 1);
        r.binding.kind = static_cast<mf::BindingKind>(0xFF);
        rejects(r);
    }
    {
        auto r = manual_record("k", 1);
        r.binding.kind = mf::BindingKind::MidHookRegister;
        r.binding.read_register = static_cast<hk::Gpr>(0xFF);
        rejects(r);
    }
    {
        auto r = manual_record("k", 1);
        r.operand_kind = static_cast<sc::OperandKind>(0xFF);
        rejects(r);
    }
    {
        auto r = manual_record("k", 1);
        r.xref_encoding = static_cast<sc::StringEncoding>(0xFF);
        rejects(r);
    }
    {
        auto r = manual_record("k", 1);
        r.xref_return = static_cast<sc::XrefReturn>(0xFF);
        rejects(r);
    }
    {
        auto r = manual_record("k", 1);
        r.pages = static_cast<sc::Pages>(0xFF);
        rejects(r);
    }
    {
        mf::SignatureRecord r;
        r.label = "ladder";
        r.kind = an::AnchorKind::RipGlobal;
        mf::CandidateSpec spec;
        spec.mode = static_cast<sc::Mode>(0xFF);
        spec.pattern = "DE AD";
        r.ladder.push_back(spec);
        rejects(r);
    }
    // The rung-level persisted enums are gated even when the rung's mode never reads them: an inert-but-garbage
    // field would still emit a permissive token on serialization.
    {
        mf::SignatureRecord r;
        r.label = "ladder";
        r.kind = an::AnchorKind::RipGlobal;
        mf::CandidateSpec spec;
        spec.mode = sc::Mode::Direct;
        spec.pattern = "DE AD";
        spec.string_encoding = static_cast<sc::StringEncoding>(0xFF);
        r.ladder.push_back(spec);
        rejects(r);
    }
    {
        mf::SignatureRecord r;
        r.label = "ladder";
        r.kind = an::AnchorKind::RipGlobal;
        mf::CandidateSpec spec;
        spec.mode = sc::Mode::Direct;
        spec.pattern = "DE AD";
        spec.string_return = static_cast<sc::XrefReturn>(0xFF);
        r.ladder.push_back(spec);
        rejects(r);
    }

    const auto rejects_adopt = [](an::Anchor source)
    {
        const auto adopted = mf::Signature::adopt(source);
        ASSERT_FALSE(adopted.has_value());
        EXPECT_EQ(adopted.error().code, dmk::ErrorCode::InvalidArg);
    };
    {
        an::Anchor source;
        source.label = "operand";
        source.kind = an::AnchorKind::Manual;
        source.operand_kind = static_cast<sc::OperandKind>(0xFF);
        rejects_adopt(source);
    }
    {
        an::Anchor source;
        source.label = "encoding";
        source.kind = an::AnchorKind::Manual;
        source.xref_encoding = static_cast<sc::StringEncoding>(0xFF);
        rejects_adopt(source);
    }
    {
        an::Anchor source;
        source.label = "return";
        source.kind = an::AnchorKind::Manual;
        source.xref_return = static_cast<sc::XrefReturn>(0xFF);
        rejects_adopt(source);
    }
}

TEST(ManifestSerializeTest, CodeOperandByteWidthDomainFailsClosed)
{
    const auto serialize_width = [](std::uint8_t byte_width)
    {
        mf::Manifest manifest;
        manifest.records.push_back(code_operand_record(byte_width));
        return mf::serialize_checked(manifest);
    };

    const auto valid = serialize_width(8);
    ASSERT_TRUE(valid.has_value()) << valid.error().message();
    const auto round_trip = mf::parse(*valid);
    ASSERT_TRUE(round_trip.has_value()) << round_trip.error().message();
    EXPECT_EQ(round_trip->records[0].byte_width, 8);

    for (const std::uint8_t width : {std::uint8_t{9}, std::uint8_t{255}})
    {
        const auto invalid = serialize_width(width);
        ASSERT_FALSE(invalid.has_value()) << "width=" << static_cast<unsigned>(width);
        EXPECT_EQ(invalid.error().code, dmk::ErrorCode::InvalidArg);
    }
}

// Record fingerprints bind the exact label as well as the anchor and binding contract.
TEST(ManifestFingerprintTest, RecordFingerprintBindsLabel)
{
    mf::SignatureRecord alpha;
    alpha.label = "alpha";
    alpha.kind = an::AnchorKind::Manual;
    alpha.manual_value = 0x99;
    mf::SignatureRecord beta = alpha;
    beta.label = "beta";

    const auto sa = mf::Signature::compile(alpha);
    const auto sb = mf::Signature::compile(beta);
    ASSERT_TRUE(sa.has_value());
    ASSERT_TRUE(sb.has_value());
    EXPECT_NE(sa->current_fingerprint(), sb->current_fingerprint());

    // The fold is exact-bytes: a case variant of the label is a different fingerprint, so a normalizing or
    // truncating fold cannot slip in as an equivalent.
    mf::SignatureRecord alpha_case = alpha;
    alpha_case.label = "Alpha";
    const auto sa_case = mf::Signature::compile(alpha_case);
    ASSERT_TRUE(sa_case.has_value());
    EXPECT_NE(sa->current_fingerprint(), sa_case->current_fingerprint());
}

// resolve() scopes its walk by record.module for EVERY kind, so a retargeted module is a signature change the
// baseline must catch as drift: an edited module under an unchanged fingerprint would hand out a wrong-module
// address as trusted (RTTI mangled names such as CRT types genuinely resolve in multiple modules).
TEST(ManifestFingerprintTest, RecordFingerprintBindsModule)
{
    mf::SignatureRecord vt;
    vt.label = "vt";
    vt.kind = an::AnchorKind::VtableIdentity;
    vt.mangled = ".?AVFoo@@";
    mf::SignatureRecord vt_retargeted = vt;
    vt_retargeted.module = "other.dll";
    mf::SignatureRecord vt_case = vt_retargeted;
    vt_case.module = "Other.dll";

    const auto s_base = mf::Signature::compile(vt);
    const auto s_retargeted = mf::Signature::compile(vt_retargeted);
    const auto s_case = mf::Signature::compile(vt_case);
    ASSERT_TRUE(s_base.has_value());
    ASSERT_TRUE(s_retargeted.has_value());
    ASSERT_TRUE(s_case.has_value());
    EXPECT_NE(s_base->current_fingerprint(), s_retargeted->current_fingerprint());
    // The fold is exact-bytes: a case variant of the module is a different fingerprint.
    EXPECT_NE(s_retargeted->current_fingerprint(), s_case->current_fingerprint());

    // The gate observable: a module edit under a captured baseline reads as Drifted.
    mf::Signature captured = mf::Signature::compile(vt).value();
    captured.recapture_fingerprint();
    mf::SignatureRecord edited = vt;
    edited.expected_fingerprint = captured.record().expected_fingerprint;
    edited.module = "other.dll";
    EXPECT_EQ(mf::Signature::compile(edited).value().fingerprint_state(), mf::FingerprintState::Drifted);
}

// Unknown and kind-inert keys fail before resolution.

TEST(ManifestParseTest, UnknownRecordKeyFailsClosed)
{
    const auto parsed = mf::parse(header_text() + "[sig.k]\nkind = manual\nmanual_value = 1\nnot_a_real_key = 1\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, EvidenceKeyForWrongKindFailsClosed)
{
    // xref_text belongs to StringXref; on a VtableIdentity record the parser never reads it, so it fails closed
    // instead of drifting from what the record actually resolves.
    const auto parsed =
        mf::parse(header_text() + "[sig.k]\nkind = vtable_identity\nmangled = .?AVFoo@@\nxref_text = hello\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, UnknownManifestHeaderKeyFailsClosed)
{
    const auto parsed = mf::parse("[manifest]\nschema = 1\nbogus = 1\n" + manual_section("k", 1));
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, UnknownRungKeyFailsClosed)
{
    const auto parsed = mf::parse(header_text() + "[sig.k]\nkind = rip_global\n[sig.k.rung.0]\nmode = direct\n"
                                                  "pattern = DE AD\nnot_a_rung_key = 1\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine);
}

TEST(ManifestParseTest, MalformedImageIdentityValueFailsClosed)
{
    for (const std::string_view value : {"zz:00:00", "0:0:0", "1:0:1"})
    {
        const auto parsed = mf::parse(
            header_text() + "[sig.k]\nkind = manual\nmanual_value = 1\nimage_identity = " + std::string(value) + "\n");
        ASSERT_FALSE(parsed.has_value()) << value;
        EXPECT_EQ(parsed.error().code, dmk::ErrorCode::MalformedLine) << value;
    }
}

TEST(ManifestImageIdentityTest, IncompleteProgrammaticIdentityFailsClosed)
{
    mf::SignatureRecord record = manual_record("k", 1);
    record.expected_image_identity = sc::ImageIdentity{.timestamp = 1, .section_digest = 1};

    const auto compiled = mf::Signature::compile(record);
    ASSERT_FALSE(compiled.has_value());
    EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg);

    const auto serialized = mf::serialize_checked(mf::Manifest{.records = {record}});
    ASSERT_FALSE(serialized.has_value());
    EXPECT_EQ(serialized.error().code, dmk::ErrorCode::InvalidArg);
}

// Captured image baselines round-trip and reject mismatched mutation targets.

TEST(ManifestImageIdentityTest, CapturedImageIdentityRoundTrips)
{
    mf::SignatureRecord record = manual_record("k", 1);
    record.expected_image_identity = sc::ImageIdentity{
        .timestamp = 0x5F3A1B2C, .size_of_image = 0x00120000, .section_digest = 0xA1B2C3D4E5F60718ULL};
    const mf::Manifest manifest{.records = {record}};

    const std::string text = serialize_ok(manifest);
    ASSERT_FALSE(text.empty());
    const auto parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->records.size(), 1U);
    EXPECT_TRUE(parsed->records[0].expected_image_identity.present());
    EXPECT_EQ(parsed->records[0].expected_image_identity, record.expected_image_identity);
}

namespace
{
    class LoadedLibrary
    {
    public:
        LoadedLibrary() : m_handle(LoadLibraryA("hook_target_lib.dll")) {}
        ~LoadedLibrary()
        {
            if (m_handle != nullptr)
            {
                FreeLibrary(m_handle);
            }
        }
        LoadedLibrary(const LoadedLibrary &) = delete;
        LoadedLibrary &operator=(const LoadedLibrary &) = delete;
        LoadedLibrary(LoadedLibrary &&) = delete;
        LoadedLibrary &operator=(LoadedLibrary &&) = delete;

        [[nodiscard]] HMODULE get() const noexcept { return m_handle; }

    private:
        HMODULE m_handle;
    };

    // A mutation-capable ExportName record: an Address binding authorizes a write to the resolved executable export.
    [[nodiscard]] mf::SignatureRecord export_mutation_record()
    {
        mf::SignatureRecord record;
        record.label = "export.compute_damage";
        record.kind = an::AnchorKind::ExportName;
        record.module = "hook_target_lib.dll";
        record.export_name = "compute_damage";
        record.binding.kind = mf::BindingKind::Address;
        return record;
    }
} // namespace

TEST(ManifestImageIdentityTest, MutationEntryRequiresMatchingLiveImageIdentity)
{
    LoadedLibrary library;
    ASSERT_NE(library.get(), nullptr) << "Failed to load hook_target_lib.dll: " << GetLastError();

    // Learn the live image identity by resolving once with no gate.
    auto probe_sig = mf::Signature::compile(export_mutation_record());
    ASSERT_TRUE(probe_sig.has_value());
    const an::ResolvedAnchor probe = probe_sig->resolve(dmk::Region::host());
    ASSERT_EQ(probe.status, an::AnchorStatus::Resolved);
    ASSERT_TRUE(probe.witness.image.present());
    const sc::ImageIdentity live = probe.witness.image;

    mf::GatePolicy policy;
    policy.require_live_image_identity = true; // isolate the identity gate from the strict fingerprint gates

    // A matching captured baseline is trusted.
    {
        mf::SignatureRecord record = export_mutation_record();
        record.expected_image_identity = live;
        std::array<mf::Signature, 1> signatures{mf::Signature::compile(record).value()};
        const mf::GateResult gated = mf::resolve_and_gate(signatures, policy, dmk::Region::host());
        EXPECT_NE(gated.find("export.compute_damage"), nullptr);
    }
    // A mismatched baseline (a same-base remap: identical timestamp and size, a rewritten section digest) is
    // safe-disabled.
    {
        mf::SignatureRecord record = export_mutation_record();
        record.expected_image_identity = sc::ImageIdentity{.timestamp = live.timestamp,
                                                           .size_of_image = live.size_of_image,
                                                           .section_digest = live.section_digest ^ 1U};
        std::array<mf::Signature, 1> signatures{mf::Signature::compile(record).value()};
        const mf::GateResult gated = mf::resolve_and_gate(signatures, policy, dmk::Region::host());
        EXPECT_EQ(gated.find("export.compute_damage"), nullptr);
        ASSERT_EQ(gated.rejected.size(), 1U);
    }
    // An uncaptured baseline leaves the identity gate inert (the fingerprint gate governs), so it is trusted:
    // recapturing the baseline is what re-arms the gate.
    {
        std::array<mf::Signature, 1> signatures{mf::Signature::compile(export_mutation_record()).value()};
        const mf::GateResult gated = mf::resolve_and_gate(signatures, policy, dmk::Region::host());
        EXPECT_NE(gated.find("export.compute_damage"), nullptr);
    }
}

TEST(ManifestImageIdentityTest, MutationEntryRevisionMismatchIsSafeDisabled)
{
    LoadedLibrary library;
    ASSERT_NE(library.get(), nullptr) << "Failed to load hook_target_lib.dll: " << GetLastError();

    const mf::ManifestHeader header{.schema = mf::SCHEMA_VERSION, .revision = 5};
    const mf::GatePolicy policy{}; // Only the revision gate constrains the mutation-capable entry here.

    // A matching build revision trusts the mutation entry.
    {
        std::array<mf::Signature, 1> signatures{mf::Signature::compile(export_mutation_record()).value()};
        const mf::GateResult gated = mf::resolve_and_gate(signatures, header, 5, policy, dmk::Region::host());
        EXPECT_NE(gated.find("export.compute_damage"), nullptr);
    }
    // A mismatched build revision safe-disables it: a contract epoch the build no longer understands cannot authorize
    // a live write.
    {
        std::array<mf::Signature, 1> signatures{mf::Signature::compile(export_mutation_record()).value()};
        const mf::GateResult gated = mf::resolve_and_gate(signatures, header, 7, policy, dmk::Region::host());
        EXPECT_EQ(gated.find("export.compute_damage"), nullptr);
    }
    // Build revision 0 opts out of the revision check, so the entry is trusted again.
    {
        std::array<mf::Signature, 1> signatures{mf::Signature::compile(export_mutation_record()).value()};
        const mf::GateResult gated = mf::resolve_and_gate(signatures, header, 0, policy, dmk::Region::host());
        EXPECT_NE(gated.find("export.compute_damage"), nullptr);
    }
}

namespace
{
    // A byte-signature target that lives INSIDE the host module image, so a resolved anchor carries a present
    // scan::ImageIdentity exactly as a real game target does. A VirtualAlloc scratch page cannot: memory::module_of
    // finds no owning module for it, so its witness image is absent and the identity gate has nothing to compare.
    //
    // Filled at run time rather than from a static initializer, so the image holds exactly one copy of the run and the
    // ladder's uniqueness requirement stays satisfiable.
    constexpr std::size_t EVIDENCE_LEN = 24;
    // The byte the mutation control rewrites. The pattern wildcards this position, so a rewrite here still MATCHES and
    // the entry still resolves; only the captured content differs. Patching a literal position instead would merely
    // stop the pattern resolving, which proves nothing about the content gate.
    constexpr std::size_t EVIDENCE_WILDCARD_INDEX = 8;
    // Large enough to span MAX_MUTATION_WITNESS_BYTES + 1, so the cap and cap-plus-one cases have a real target. The
    // 0x5A + 7i generator has period 256, so any window shorter than that occurs exactly once in the site.
    constexpr std::size_t EVIDENCE_SITE_BYTES = sc::MAX_MUTATION_WITNESS_BYTES + 8;

    std::uint8_t g_evidence_site[EVIDENCE_SITE_BYTES];

    [[nodiscard]] std::uint8_t evidence_byte(std::size_t index) noexcept
    {
        // The seed is read through a volatile so the optimizer cannot fold the whole run into a constant table in the
        // image. At -O3 it otherwise does exactly that, and the resulting .rdata copy makes the fixture ambiguous
        // inside the scanned module: two matches, so the ladder's uniqueness requirement rejects and every case here
        // fails in Release while passing in Debug.
        static volatile std::uint8_t seed = 0x5Au;
        return static_cast<std::uint8_t>(seed + index * 7u);
    }

    void fill_evidence_site() noexcept
    {
        for (std::size_t i = 0; i < EVIDENCE_SITE_BYTES; ++i)
        {
            g_evidence_site[i] = evidence_byte(i);
        }
    }

    // Every byte literal except the wildcard slot, which is emitted only when it falls inside the run.
    [[nodiscard]] std::string evidence_aob_of(std::size_t length)
    {
        static constexpr char hex_digits[] = "0123456789ABCDEF";
        std::string aob;
        for (std::size_t i = 0; i < length; ++i)
        {
            if (i != 0)
            {
                aob.push_back(' ');
            }
            if (i == EVIDENCE_WILDCARD_INDEX)
            {
                aob.append("??");
                continue;
            }
            const std::uint8_t value = evidence_byte(i);
            aob.push_back(hex_digits[value >> 4]);
            aob.push_back(hex_digits[value & 0x0F]);
        }
        return aob;
    }

    [[nodiscard]] std::string evidence_aob()
    {
        return evidence_aob_of(EVIDENCE_LEN);
    }

    // A bounded-jump AOB whose total matched SPAN is prefix + gap + suffix. A run of literals cannot reach
    // MAX_MUTATION_WITNESS_BYTES on its own -- scan::Pattern caps the fixed byte count at MAX_PATTERN_BYTES (128) --
    // so an exact `[N]` gap is the only way to build a span at and past the evidence cap. It is also the realistic
    // shape: the gap bytes are ones the matcher never reads, yet they are part of what a mutation baseline must cover.
    [[nodiscard]] std::string spanning_aob(std::size_t prefix_len, std::size_t gap, std::size_t suffix_len)
    {
        static constexpr char hex_digits[] = "0123456789ABCDEF";
        const auto emit = [](std::string &out, std::uint8_t value)
        {
            out.push_back(hex_digits[value >> 4]);
            out.push_back(hex_digits[value & 0x0F]);
        };
        std::string aob;
        for (std::size_t i = 0; i < prefix_len; ++i)
        {
            if (i != 0)
            {
                aob.push_back(' ');
            }
            emit(aob, evidence_byte(i));
        }
        aob.append(std::format(" [{}] ", gap));
        for (std::size_t i = 0; i < suffix_len; ++i)
        {
            if (i != 0)
            {
                aob.push_back(' ');
            }
            emit(aob, evidence_byte(prefix_len + gap + i));
        }
        return aob;
    }

    // A mutation-capable byte-signature record over g_evidence_site: an Address binding on a DataAddress domain.
    [[nodiscard]] mf::SignatureRecord evidence_record()
    {
        mf::SignatureRecord record;
        record.label = "data.evidence";
        record.kind = an::AnchorKind::RipGlobal;
        record.pages = sc::Pages::Readable;
        record.binding.kind = mf::BindingKind::Address;
        mf::CandidateSpec rung;
        rung.mode = sc::Mode::Direct;
        rung.pattern = evidence_aob();
        record.ladder = {rung};
        return record;
    }

    struct EvidenceRejection
    {
        an::AnchorStatus status = an::AnchorStatus::Unresolved;
        mf::GateReason reason = mf::GateReason::None;
    };

    struct EvidenceGateOutcome
    {
        std::optional<dmk::Address> trusted;
        std::optional<EvidenceRejection> rejected;
    };

    [[nodiscard]] EvidenceGateOutcome gate_evidence(const mf::SignatureRecord &record, const mf::GatePolicy &policy,
                                                    std::uint32_t build_revision)
    {
        const mf::ManifestHeader header{.schema = mf::SCHEMA_VERSION, .revision = 7};
        std::array<mf::Signature, 1> signatures{mf::Signature::compile(record).value()};
        const mf::GateResult gated =
            mf::resolve_and_gate(signatures, header, build_revision, policy, dmk::Region::host());
        EvidenceGateOutcome outcome;
        if (const mf::GatedSignature *trusted = gated.find(record.label))
        {
            outcome.trusted = trusted->address;
        }
        for (const mf::RejectedSignature &entry : gated.rejected)
        {
            if (entry.label == record.label)
            {
                outcome.rejected = EvidenceRejection{.status = entry.status, .reason = entry.reason};
                break;
            }
        }
        return outcome;
    }

    // A record whose three baselines were captured from the live image.
    [[nodiscard]] std::optional<mf::SignatureRecord> captured_evidence_record()
    {
        auto signature = mf::Signature::compile(evidence_record());
        if (!signature.has_value() || !signature->recapture(dmk::Region::host()).has_value())
        {
            return std::nullopt;
        }
        return signature->record();
    }
} // namespace

TEST(MutationStrictTest, PresetArmsEveryMutationRequirement)
{
    constexpr mf::GatePolicy policy = mf::GatePolicy::mutation_strict();
    EXPECT_TRUE(policy.require_mutation_safe_binding);
    EXPECT_TRUE(policy.require_live_image_identity);
    EXPECT_TRUE(policy.require_captured_image_identity);
    EXPECT_TRUE(policy.require_winning_evidence_baseline);
    EXPECT_TRUE(policy.require_contract_revision);
    EXPECT_TRUE(policy.reject_on_fingerprint_drift);
    EXPECT_TRUE(policy.reject_unset_fingerprint);
    EXPECT_DOUBLE_EQ(policy.min_resolved_fraction, 1.0);
}

TEST(ManifestMutationEvidenceTest, MalformedWinningEvidenceFailsClosedBeforeAccess)
{
    // length is public and unclamped, so a hand-built value can claim more bytes than the array holds. Reading it
    // must not walk past the array, and it must never satisfy a baseline comparison.
    sc::WinningEvidence over_long;
    over_long.length = static_cast<std::uint16_t>(sc::MAX_MUTATION_WITNESS_BYTES + 1);
    EXPECT_FALSE(over_long.present());
    EXPECT_TRUE(over_long.span().empty());

    // The in-bounds malformed shape: bytes claimed alongside truncation, which capture never produces. This one is
    // fully defined to evaluate under the old semantics too, so it -- not the over-long case -- is what pins the
    // equality guard: without it these two compare EQUAL, and a malformed baseline would authorize a write.
    sc::WinningEvidence truncated_with_bytes;
    truncated_with_bytes.length = 4;
    truncated_with_bytes.truncated = true;
    truncated_with_bytes.bytes[0] = std::byte{0xAB};
    const sc::WinningEvidence identical_copy = truncated_with_bytes;
    EXPECT_FALSE(truncated_with_bytes.present());
    EXPECT_TRUE(truncated_with_bytes.span().empty());
    EXPECT_FALSE(truncated_with_bytes == identical_copy);

    // A well-formed value still compares normally, so the guard did not simply break equality.
    sc::WinningEvidence well_formed;
    well_formed.length = 4;
    well_formed.bytes[0] = std::byte{0xAB};
    EXPECT_TRUE(well_formed.present());
    EXPECT_EQ(well_formed.span().size(), 4U);
    EXPECT_TRUE(well_formed == well_formed);
}

TEST(ManifestMutationEvidenceTest, RecaptureCapturesAllThreeBaselinesAndIsTrusted)
{
    fill_evidence_site();
    auto signature = mf::Signature::compile(evidence_record());
    ASSERT_TRUE(signature.has_value()) << signature.error().message();

    // Nothing is captured before recapture, so the strict preset cannot authorize a write.
    EXPECT_EQ(signature->record().expected_fingerprint, 0U);
    EXPECT_FALSE(signature->record().expected_image_identity.present());
    EXPECT_FALSE(signature->record().expected_winning_bytes.present());

    const dmk::Result<void> captured = signature->recapture(dmk::Region::host());
    ASSERT_TRUE(captured.has_value()) << captured.error().message();

    const mf::SignatureRecord &record = signature->record();
    EXPECT_NE(record.expected_fingerprint, 0U);
    EXPECT_TRUE(record.expected_image_identity.present());
    ASSERT_TRUE(record.expected_winning_bytes.present());
    EXPECT_EQ(record.expected_winning_bytes.length, EVIDENCE_LEN);

    // The captured span is the LIVE bytes, including the concrete byte under the wildcard -- not the pattern, whose
    // wildcard slot carries no value at all.
    for (std::size_t i = 0; i < EVIDENCE_LEN; ++i)
    {
        EXPECT_EQ(std::to_integer<std::uint8_t>(record.expected_winning_bytes.bytes[i]), evidence_byte(i))
            << "byte " << i;
    }

    // Positive control: a fully captured entry under the strict preset IS trusted, so every rejection below is proven
    // to come from its own gate rather than from a preset that denies everything.
    const EvidenceGateOutcome gated = gate_evidence(record, mf::GatePolicy::mutation_strict(), 7);
    EXPECT_TRUE(gated.trusted.has_value());
    EXPECT_FALSE(gated.rejected.has_value());
}

TEST(ManifestMutationEvidenceTest, EqualImageLayoutWithChangedContentIsSafeDisabled)
{
    fill_evidence_site();
    const std::optional<mf::SignatureRecord> record = captured_evidence_record();
    ASSERT_TRUE(record.has_value());
    ASSERT_TRUE(gate_evidence(*record, mf::GatePolicy::mutation_strict(), 7).trusted.has_value());

    const sc::ImageIdentity before = sc::image_identity(dmk::Region::host());
    ASSERT_TRUE(before.present());

    // Rewrite one byte of image CONTENT at the wildcard slot. No PE header, section header, timestamp, or SizeOfImage
    // is touched.
    const std::uint8_t original = g_evidence_site[EVIDENCE_WILDCARD_INDEX];
    g_evidence_site[EVIDENCE_WILDCARD_INDEX] = static_cast<std::uint8_t>(original ^ 0xFFu);

    // The layout gate is structurally blind to this: the identity is bit-identical.
    const sc::ImageIdentity after = sc::image_identity(dmk::Region::host());
    EXPECT_EQ(before, after);

    // The entry still RESOLVES -- the wildcard tolerates the new byte -- so this is not a locate failure. Only the
    // content baseline disagrees, and that alone must refuse the write.
    const EvidenceGateOutcome gated = gate_evidence(*record, mf::GatePolicy::mutation_strict(), 7);
    EXPECT_FALSE(gated.trusted.has_value());
    EXPECT_TRUE(gated.rejected.has_value());
    if (gated.rejected)
    {
        EXPECT_EQ(gated.rejected->status, an::AnchorStatus::Resolved);
        EXPECT_EQ(gated.rejected->reason, mf::GateReason::WinningEvidence);
    }

    g_evidence_site[EVIDENCE_WILDCARD_INDEX] = original;

    // Restoring the content restores trust, so the gate tracks live content rather than latching.
    EXPECT_TRUE(gate_evidence(*record, mf::GatePolicy::mutation_strict(), 7).trusted.has_value());
}

TEST(ManifestMutationEvidenceTest, EveryMissingCredentialSafeDisablesTheWrite)
{
    fill_evidence_site();
    const std::optional<mf::SignatureRecord> captured = captured_evidence_record();
    ASSERT_TRUE(captured.has_value());
    constexpr mf::GatePolicy strict = mf::GatePolicy::mutation_strict();

    // The plain overload compares no contract revision at all.
    {
        std::array<mf::Signature, 1> signatures{mf::Signature::compile(*captured).value()};
        const mf::GateResult gated = mf::resolve_and_gate(signatures, strict, dmk::Region::host());
        EXPECT_EQ(gated.find("data.evidence"), nullptr);
        ASSERT_EQ(gated.rejected.size(), 1U);
        EXPECT_EQ(gated.rejected[0].reason, mf::GateReason::ContractRevision);
    }
    // A zero build revision opts the header overload out of the comparison, which is equally unchecked.
    {
        const EvidenceGateOutcome gated = gate_evidence(*captured, strict, 0);
        ASSERT_TRUE(gated.rejected.has_value());
        EXPECT_EQ(gated.rejected->reason, mf::GateReason::ContractRevision);
    }
    // An incompatible revision.
    {
        const EvidenceGateOutcome gated = gate_evidence(*captured, strict, 9);
        ASSERT_TRUE(gated.rejected.has_value());
        EXPECT_EQ(gated.rejected->reason, mf::GateReason::ContractRevision);
    }
    // No captured image baseline.
    {
        mf::SignatureRecord record = *captured;
        record.expected_image_identity = sc::ImageIdentity{};
        const EvidenceGateOutcome gated = gate_evidence(record, strict, 7);
        ASSERT_TRUE(gated.rejected.has_value());
        EXPECT_EQ(gated.rejected->reason, mf::GateReason::ImageIdentity);
    }
    // A mismatched image baseline.
    {
        mf::SignatureRecord record = *captured;
        record.expected_image_identity.section_digest ^= 1U;
        const EvidenceGateOutcome gated = gate_evidence(record, strict, 7);
        ASSERT_TRUE(gated.rejected.has_value());
        EXPECT_EQ(gated.rejected->reason, mf::GateReason::ImageIdentity);
    }
    // No captured content baseline.
    {
        mf::SignatureRecord record = *captured;
        record.expected_winning_bytes = sc::WinningEvidence{};
        const EvidenceGateOutcome gated = gate_evidence(record, strict, 7);
        ASSERT_TRUE(gated.rejected.has_value());
        EXPECT_EQ(gated.rejected->reason, mf::GateReason::WinningEvidence);
    }
    // A content baseline that is a strict PREFIX of the live span must not read as agreement.
    {
        mf::SignatureRecord record = *captured;
        record.expected_winning_bytes.length = static_cast<std::uint16_t>(EVIDENCE_LEN - 1);
        const EvidenceGateOutcome gated = gate_evidence(record, strict, 7);
        ASSERT_TRUE(gated.rejected.has_value());
        EXPECT_EQ(gated.rejected->reason, mf::GateReason::WinningEvidence);
    }
    // An uncaptured fingerprint.
    {
        mf::SignatureRecord record = *captured;
        record.expected_fingerprint = 0;
        const EvidenceGateOutcome gated = gate_evidence(record, strict, 7);
        ASSERT_TRUE(gated.rejected.has_value());
        EXPECT_EQ(gated.rejected->reason, mf::GateReason::FingerprintUnset);
    }
}

TEST(ManifestMutationEvidenceTest, EvidenceCapIsPinnedAtTheBoundary)
{
    fill_evidence_site();

    // Exactly at the cap: the whole span is captured, so it can still authorize a write.
    {
        mf::SignatureRecord record = evidence_record();
        record.label = "data.at_cap";
        record.ladder[0].pattern = spanning_aob(8, sc::MAX_MUTATION_WITNESS_BYTES - 24, 16);
        auto signature = mf::Signature::compile(record);
        ASSERT_TRUE(signature.has_value()) << signature.error().message();
        const dmk::Result<void> captured = signature->recapture(dmk::Region::host());
        ASSERT_TRUE(captured.has_value()) << captured.error().message();
        const sc::WinningEvidence &evidence = signature->record().expected_winning_bytes;
        EXPECT_EQ(evidence.length, sc::MAX_MUTATION_WITNESS_BYTES);
        EXPECT_FALSE(evidence.truncated);

        // Every byte of the span, not just its length. The interior here is a 232-byte jump gap, so these are the
        // bytes the matcher never reads and only the capture can witness. Length and trust alone do not reach them: a
        // capture that copied a short prefix and reported the full length would leave the tail zero on BOTH the
        // baseline and the live side, so the gate would compare zero against zero and still authorize the write.
        for (std::size_t i = 0; i < sc::MAX_MUTATION_WITNESS_BYTES; ++i)
        {
            ASSERT_EQ(std::to_integer<std::uint8_t>(evidence.bytes[i]), evidence_byte(i)) << "byte " << i;
        }
        EXPECT_TRUE(gate_evidence(signature->record(), mf::GatePolicy::mutation_strict(), 7).trusted.has_value());

        // A content change strictly inside the gap. The matcher provably never inspects this byte, so the entry still
        // resolves and the layout identity is untouched; only a capture that really covers the whole span can refuse.
        constexpr std::size_t gap_interior_index = 128;
        static_assert(gap_interior_index > 8 && gap_interior_index < sc::MAX_MUTATION_WITNESS_BYTES - 16,
                      "the probed byte must sit inside the jump gap, not in the literal prefix or suffix");
        const std::uint8_t original = g_evidence_site[gap_interior_index];
        g_evidence_site[gap_interior_index] = static_cast<std::uint8_t>(original ^ 0xFFu);
        const EvidenceGateOutcome patched = gate_evidence(signature->record(), mf::GatePolicy::mutation_strict(), 7);
        EXPECT_FALSE(patched.trusted.has_value());
        ASSERT_TRUE(patched.rejected.has_value());
        EXPECT_EQ(patched.rejected->status, an::AnchorStatus::Resolved);
        EXPECT_EQ(patched.rejected->reason, mf::GateReason::WinningEvidence);

        g_evidence_site[gap_interior_index] = original;
        EXPECT_TRUE(gate_evidence(signature->record(), mf::GatePolicy::mutation_strict(), 7).trusted.has_value());
    }

    // One byte past it: the span is reported truncated and carries NO bytes. A captured prefix would compare equal
    // against a prefix baseline and quietly authorize a write on partial evidence.
    {
        mf::SignatureRecord record = evidence_record();
        record.label = "data.past_cap";
        record.ladder[0].pattern = spanning_aob(8, sc::MAX_MUTATION_WITNESS_BYTES - 23, 16);
        auto signature = mf::Signature::compile(record);
        ASSERT_TRUE(signature.has_value()) << signature.error().message();

        // It still RESOLVES: over-long evidence stays valid for read-only lookup.
        const an::ResolvedAnchor resolved = signature->resolve(dmk::Region::host());
        ASSERT_EQ(resolved.status, an::AnchorStatus::Resolved);
        EXPECT_TRUE(resolved.witness.evidence.truncated);
        EXPECT_FALSE(resolved.witness.evidence.present());
        EXPECT_EQ(resolved.witness.evidence.length, 0U);

        // It cannot be recaptured into a strict baseline, and cannot authorize a write.
        const dmk::Result<void> captured = signature->recapture(dmk::Region::host());
        ASSERT_FALSE(captured.has_value());
        EXPECT_EQ(captured.error().code, dmk::ErrorCode::UnexpectedShape);

        // Satisfy every OTHER credential by hand, so the refusal can only come from the content gate.
        signature->recapture_fingerprint();
        mf::SignatureRecord forced = signature->record();
        forced.expected_image_identity = sc::image_identity(dmk::Region::host());
        const EvidenceGateOutcome gated = gate_evidence(forced, mf::GatePolicy::mutation_strict(), 7);
        ASSERT_TRUE(gated.rejected.has_value());
        EXPECT_EQ(gated.rejected->reason, mf::GateReason::WinningEvidence);
    }
}

TEST(ManifestMutationEvidenceTest, ReadOnlyLookupSurvivesEveryMissingCredential)
{
    fill_evidence_site();
    // The same record that cannot authorize a write still resolves for a read-only consumer through the plain overload
    // with no baselines at all. Read-only capability is not collateral damage of the strict gate.
    std::array<mf::Signature, 1> signatures{mf::Signature::compile(evidence_record()).value()};
    const mf::GateResult gated = mf::resolve_and_gate(signatures, mf::GatePolicy{}, dmk::Region::host());
    const mf::GatedSignature *found = gated.find("data.evidence");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->address.raw(), reinterpret_cast<std::uintptr_t>(&g_evidence_site[0]));
}

TEST(ManifestMutationEvidenceTest, RecaptureFailsClosedWhereNoContentSpanExists)
{
    LoadedLibrary library;
    ASSERT_NE(library.get(), nullptr) << "Failed to load hook_target_lib.dll: " << GetLastError();

    // An ExportName rung resolves through the export table, not a literal run, so it witnesses no content span and
    // cannot seed a strict baseline. Refusing beats writing a record that looks captured but can never gate.
    auto exported = mf::Signature::compile(export_mutation_record());
    ASSERT_TRUE(exported.has_value());
    const dmk::Result<void> export_result = exported->recapture(dmk::Region::host());
    ASSERT_FALSE(export_result.has_value());
    EXPECT_EQ(export_result.error().code, dmk::ErrorCode::UnexpectedShape);
    EXPECT_EQ(exported->record().expected_fingerprint, 0U);
    EXPECT_FALSE(exported->record().expected_image_identity.present());

    // A Manual pin has no live evidence at all.
    mf::Signature manual = manual_signature("pinned", 0x14000);
    EXPECT_FALSE(manual.recapture(dmk::Region::host()).has_value());

    // A signature that does not resolve leaves every baseline untouched.
    mf::SignatureRecord missing = evidence_record();
    missing.label = "data.absent";
    missing.ladder[0].pattern = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE F0 F1";
    auto absent = mf::Signature::compile(missing);
    ASSERT_TRUE(absent.has_value());
    const dmk::Result<void> absent_result = absent->recapture(dmk::Region::host());
    ASSERT_FALSE(absent_result.has_value());
    EXPECT_EQ(absent_result.error().code, dmk::ErrorCode::NoMatch);
    EXPECT_EQ(absent->record().expected_fingerprint, 0U);
    EXPECT_FALSE(absent->record().expected_winning_bytes.present());
}

TEST(ManifestMutationEvidenceTest, WinningBytesRoundTripAndFailClosedWhenMalformed)
{
    fill_evidence_site();
    const std::optional<mf::SignatureRecord> captured = captured_evidence_record();
    ASSERT_TRUE(captured.has_value());

    mf::Manifest manifest;
    manifest.header = mf::ManifestHeader{.schema = mf::SCHEMA_VERSION, .revision = 7};
    manifest.records = {*captured};
    const std::string text = serialize_ok(manifest);
    EXPECT_NE(text.find("winning_bytes"), std::string::npos);

    const dmk::Result<mf::Manifest> parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), 1U);
    EXPECT_EQ(parsed->records[0].expected_winning_bytes, captured->expected_winning_bytes);

    // A hand-edited baseline that is not a whole number of bytes, carries a non-hex digit, or is empty fails closed
    // rather than yielding a shorter baseline that would compare equal against a prefix of the live span.
    for (const std::string_view bad : {std::string_view{"0a1"}, std::string_view{"zz"}, std::string_view{}})
    {
        static constexpr std::string_view key_prefix = "winning_bytes = ";
        std::string mutated = text;
        const std::size_t key = mutated.find(key_prefix);
        ASSERT_NE(key, std::string::npos);
        const std::size_t value_start = key + key_prefix.size();
        std::size_t line_end = mutated.find('\n', value_start);
        ASSERT_NE(line_end, std::string::npos);
        // The emitted file is CRLF; keep the terminator intact so only the value is replaced.
        if (line_end > value_start && mutated[line_end - 1] == '\r')
        {
            --line_end;
        }
        mutated.replace(value_start, line_end - value_start, bad);
        EXPECT_FALSE(mf::parse(mutated).has_value()) << "accepted malformed winning_bytes: '" << bad << "'";
    }
}

TEST(ManifestMutationEvidenceTest, UnrepresentableWinningBytesRejectedByCompileAndSerialize)
{
    fill_evidence_site();

    // The control: a well-formed baseline passes both doors, so every refusal below is attributable to the
    // evidence shape rather than to the rest of the record.
    {
        mf::SignatureRecord control = evidence_record();
        control.expected_winning_bytes.length = 4;
        control.expected_winning_bytes.bytes[0] = std::byte{0xAB};
        EXPECT_TRUE(mf::Signature::compile(control).has_value());
        EXPECT_TRUE(mf::serialize_checked(mf::Manifest{.records = {control}}).has_value());
    }

    // A persisted baseline is only ever a COMPLETE capture, so a record may hold neither an over-long length nor a
    // truncation flag. Both would slip through silently if only the emitter guarded them: present() is false for
    // each, so serialize_checked would omit the key and report success while dropping the baseline, and the reloaded
    // manifest would then be missing the very credential mutation_strict turns on. Both doors fail closed instead.
    const auto expect_rejected = [](std::string_view name, const sc::WinningEvidence &shape)
    {
        mf::SignatureRecord record = evidence_record();
        record.expected_winning_bytes = shape;

        const auto compiled = mf::Signature::compile(record);
        ASSERT_FALSE(compiled.has_value()) << "compile accepted " << name;
        EXPECT_EQ(compiled.error().code, dmk::ErrorCode::InvalidArg) << name;

        const auto encoded = mf::serialize_checked(mf::Manifest{.records = {record}});
        ASSERT_FALSE(encoded.has_value()) << "serialize_checked accepted " << name;
        EXPECT_EQ(encoded.error().code, dmk::ErrorCode::InvalidArg) << name;
    };

    sc::WinningEvidence over_long;
    over_long.length = static_cast<std::uint16_t>(sc::MAX_MUTATION_WITNESS_BYTES + 1);
    expect_rejected("over-long length", over_long);

    // capture_winning_evidence really does produce this shape for a span past the cap; recapture refuses to adopt
    // it, so a record can only carry it by hand, and it must not become a Signature or a file either.
    sc::WinningEvidence truncated_empty;
    truncated_empty.truncated = true;
    expect_rejected("truncated with no bytes", truncated_empty);

    sc::WinningEvidence truncated_with_bytes;
    truncated_with_bytes.length = 4;
    truncated_with_bytes.truncated = true;
    truncated_with_bytes.bytes[0] = std::byte{0xAB};
    expect_rejected("truncated while claiming bytes", truncated_with_bytes);
}

TEST(ManifestMutationEvidenceTest, MaximumLengthWinningBytesRoundTripsAndOverLongHexIsRejected)
{
    // The persisted form is two hex characters per byte, so a baseline at MAX_MUTATION_WITNESS_BYTES is the longest
    // legal value: exactly 512 characters. Both sides of that bound matter and neither is reachable from the shorter
    // round-trip above -- a parser one off in either direction would reject the largest capture the engine can make,
    // or accept a length that no longer fits the array it is copied into.
    static constexpr std::string_view key_prefix = "winning_bytes = ";

    mf::SignatureRecord record = evidence_record();
    record.expected_winning_bytes.length = static_cast<std::uint16_t>(sc::MAX_MUTATION_WITNESS_BYTES);
    for (std::size_t i = 0; i < sc::MAX_MUTATION_WITNESS_BYTES; ++i)
    {
        record.expected_winning_bytes.bytes[i] = static_cast<std::byte>(evidence_byte(i));
    }

    const std::string text = serialize_ok(mf::Manifest{.records = {record}});
    const dmk::Result<mf::Manifest> parsed = mf::parse(text);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
    ASSERT_EQ(parsed->records.size(), 1U);
    EXPECT_EQ(parsed->records[0].expected_winning_bytes.length, sc::MAX_MUTATION_WITNESS_BYTES);
    EXPECT_EQ(parsed->records[0].expected_winning_bytes, record.expected_winning_bytes);

    // One byte past the cap. Still even-length and still valid hex, so the bound is the only thing that can reject
    // it, and rejecting is required: the value describes 257 bytes of a 256-byte span.
    std::string over_long = text;
    const std::size_t key = over_long.find(key_prefix);
    ASSERT_NE(key, std::string::npos);
    over_long.insert(key + key_prefix.size(), "ff");
    EXPECT_FALSE(mf::parse(over_long).has_value());
}
