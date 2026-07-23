#include <gtest/gtest.h>

#include <cstdio>
#include <span>
#include <string>

#include "DetourModKit/detail/drift_manifest.hpp"
#include "DetourModKit/rtti_dissect.hpp"

#include <process.h> // _getpid for collision-free temp paths under parallel CTest

using DetourModKit::ErrorCode;
using DetourModKit::rtti::DriftEntry;
namespace rtti = DetourModKit::rtti;

TEST(DriftManifestTest, RoundTripPreservesEntries)
{
    const std::string name_a = ".?AVFoo@@";
    const std::string name_b = ".?AVBar@@";
    DriftEntry entries[2];
    entries[0].name = name_a;
    entries[0].nominal_offset = 0x10;
    entries[0].healed_offset = 0x18;
    entries[0].delta = 0x8;
    entries[0].ok = true;
    entries[1].name = name_b;
    entries[1].nominal_offset = 0x40;
    entries[1].ok = false;
    entries[1].error = ErrorCode::HealNoMatch;

    const auto parsed = rtti::parse_drift_report(rtti::serialize_drift_report(entries));
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 2u);

    EXPECT_EQ((*parsed)[0].name, name_a);
    EXPECT_EQ((*parsed)[0].nominal_offset, 0x10);
    EXPECT_EQ((*parsed)[0].healed_offset, 0x18);
    EXPECT_EQ((*parsed)[0].delta, 0x8);
    EXPECT_TRUE((*parsed)[0].ok);
    // A successful entry's error is Ok and must round-trip as Ok, not collapse into a failure token.
    EXPECT_EQ((*parsed)[0].error, ErrorCode::Ok);

    EXPECT_EQ((*parsed)[1].name, name_b);
    EXPECT_FALSE((*parsed)[1].ok);
    EXPECT_EQ((*parsed)[1].error, ErrorCode::HealNoMatch);
}

TEST(DriftManifestTest, NameSurvivesSourceDestruction)
{
    std::string text;
    {
        // DriftEntry.name aliases this buffer; it goes out of scope before parse.
        const std::string transient_name = ".?AVTransient@@";
        DriftEntry entry;
        entry.name = transient_name;
        entry.nominal_offset = 4;
        text = rtti::serialize_drift_report(std::span<const DriftEntry>(&entry, 1));
    }
    const auto parsed = rtti::parse_drift_report(text);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 1u);
    // The parsed record owns its name, so it stays valid after the source is gone.
    EXPECT_EQ((*parsed)[0].name, ".?AVTransient@@");
}

TEST(DriftManifestTest, NegativeOffsetsRoundTrip)
{
    DriftEntry entry;
    entry.name = "neg";
    entry.nominal_offset = -16;
    entry.healed_offset = -8;
    entry.delta = 8;
    entry.ok = true;
    const auto parsed = rtti::parse_drift_report(rtti::serialize_drift_report(std::span<const DriftEntry>(&entry, 1)));
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 1u);
    EXPECT_EQ((*parsed)[0].nominal_offset, -16);
    EXPECT_EQ((*parsed)[0].healed_offset, -8);
    EXPECT_EQ((*parsed)[0].delta, 8);
}

TEST(DriftManifestTest, EmptyReportHasHeaderOnlyAndParsesEmpty)
{
    const auto parsed = rtti::parse_drift_report(rtti::serialize_drift_report({}));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->empty());
}

TEST(DriftManifestTest, ParseRejectsMissingHeader)
{
    const auto parsed = rtti::parse_drift_report("not a header\nfoo\t1\t2\t3\t1\tNoMatch\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, ErrorCode::MissingHeader);
}

TEST(DriftManifestTest, ParseRejectsMalformedLine)
{
    // Header present, but a record line with too few fields.
    const auto parsed = rtti::parse_drift_report("# DetourModKit drift manifest v1\nfoo\t1\t2\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, ErrorCode::MalformedLine);
}

TEST(DriftManifestTest, ParseRejectsNonNumericOffset)
{
    const auto parsed = rtti::parse_drift_report("# DetourModKit drift manifest v1\nfoo\tNaN\t2\t3\t1\tNoMatch\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, ErrorCode::MalformedLine);
}

// Names may contain the manifest's record delimiters, so framing characters and the escape character must round-trip.
TEST(DriftManifestTest, ControlCharacterNamesRoundTripExactly)
{
    DriftEntry entries[3];
    entries[0].name = "tab\there\nand\rmore";
    entries[0].nominal_offset = 8;
    entries[1].name = "trailing_cr\r"; // a raw trailing CR would be eaten by the parser's CRLF tolerance
    entries[1].nominal_offset = 16;
    entries[2].name = "back\\slash\\"; // the escape character itself must round-trip
    entries[2].nominal_offset = 24;

    const auto parsed = rtti::parse_drift_report(rtti::serialize_drift_report(entries));
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 3u);
    EXPECT_EQ((*parsed)[0].name, "tab\there\nand\rmore");
    EXPECT_EQ((*parsed)[1].name, "trailing_cr\r");
    EXPECT_EQ((*parsed)[2].name, "back\\slash\\");
}

// A truncated escape (lone backslash at field end) or an unknown escape letter is a malformed line, not a silently
// altered name.
TEST(DriftManifestTest, ParseRejectsTruncatedOrUnknownNameEscape)
{
    const std::string header = "# DetourModKit drift manifest v1\n";

    const auto truncated = rtti::parse_drift_report(header + "bad\\\t1\t2\t3\t1\tOk\n");
    ASSERT_FALSE(truncated.has_value());
    EXPECT_EQ(truncated.error().code, ErrorCode::MalformedLine);

    const auto unknown = rtti::parse_drift_report(header + "bad\\x\t1\t2\t3\t1\tOk\n");
    ASSERT_FALSE(unknown.has_value());
    EXPECT_EQ(unknown.error().code, ErrorCode::MalformedLine);
}

TEST(DriftManifestTest, ParseToleratesBlankLinesAndCrlf)
{
    const std::string text = "# DetourModKit drift manifest v1\r\n\r\nfoo\t1\t2\t1\t1\tBadDescriptor\r\n\r\n";
    const auto parsed = rtti::parse_drift_report(text);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 1u);
    EXPECT_EQ((*parsed)[0].name, "foo");
    EXPECT_EQ((*parsed)[0].delta, 1);
}

TEST(DriftManifestTest, FileRoundTrip)
{
    DriftEntry entry;
    entry.name = ".?AVFileFoo@@";
    entry.nominal_offset = 0x20;
    entry.healed_offset = 0x28;
    entry.delta = 8;
    entry.ok = true;

    const std::string path = std::string("dmk_drift_manifest_test_") + std::to_string(_getpid()) + ".tmp";
    const auto written = rtti::write_drift_report_to_file(path, std::span<const DriftEntry>(&entry, 1));
    ASSERT_TRUE(written.has_value());
    const auto parsed = rtti::read_drift_report_from_file(path);
    std::remove(path.c_str());

    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 1u);
    EXPECT_EQ((*parsed)[0].name, ".?AVFileFoo@@");
    EXPECT_EQ((*parsed)[0].healed_offset, 0x28);
}

TEST(DriftManifestTest, WriteToUnopenablePathFailsClosed)
{
    DriftEntry entry;
    entry.name = ".?AVFoo@@";
    entry.ok = true;

    // A path under a directory that does not exist cannot be opened for writing. The Result surfaces that as
    // FileOpenFailed -- distinct from a bare false and from the mid-write FileWriteFailed case -- so a caller can tell
    // "never created" from "created but truncated".
    const std::string path = "dmk_no_such_dir_xyzzy/report.tmp";
    const auto written = rtti::write_drift_report_to_file(path, std::span<const DriftEntry>(&entry, 1));
    ASSERT_FALSE(written.has_value());
    EXPECT_EQ(written.error().code, ErrorCode::FileOpenFailed);
}

TEST(DriftManifestTest, ReadMissingFileFailsClosed)
{
    const auto parsed = rtti::read_drift_report_from_file("dmk_definitely_no_such_manifest.tmp");
    ASSERT_FALSE(parsed.has_value());
    // A file that cannot be opened is an open failure, distinct from a present-but-corrupt manifest.
    EXPECT_EQ(parsed.error().code, ErrorCode::FileOpenFailed);
}

TEST(DriftManifestTest, ReadPresentButCorruptIsParseError)
{
    // The file opens fine, so this is a parse failure (no header), not an open failure.
    const std::string path = std::string("dmk_drift_corrupt_") + std::to_string(_getpid()) + ".tmp";
    {
        std::FILE *f = std::fopen(path.c_str(), "wb");
        ASSERT_NE(f, nullptr);
        const char body[] = "not a header\nfoo\t1\t2\n";
        std::fwrite(body, 1, sizeof(body) - 1, f);
        std::fclose(f);
    }
    const auto parsed = rtti::read_drift_report_from_file(path);
    std::remove(path.c_str());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, ErrorCode::MissingHeader);
}

TEST(DriftManifestTest, ReadEmptyFileFailsAsCorrupt)
{
    // An opened-but-empty file is corrupt (no header seen), not an open failure.
    const std::string path = std::string("dmk_drift_empty_") + std::to_string(_getpid()) + ".tmp";
    {
        std::FILE *f = std::fopen(path.c_str(), "wb");
        ASSERT_NE(f, nullptr);
        std::fclose(f);
    }
    const auto parsed = rtti::read_drift_report_from_file(path);
    std::remove(path.c_str());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, ErrorCode::MissingHeader);
}

TEST(DriftManifestTest, ManifestErrorCodesStringifyDistinctly)
{
    // The former ManifestError enum folded into the unified ErrorCode's ErrorCategory::Manifest block; the four
    // manifest codes must still stringify to distinct, non-empty labels through the single to_string(ErrorCode).
    using DetourModKit::to_string;
    EXPECT_NE(to_string(ErrorCode::MissingHeader), to_string(ErrorCode::MalformedLine));
    EXPECT_NE(to_string(ErrorCode::MalformedLine), to_string(ErrorCode::FileOpenFailed));
    EXPECT_NE(to_string(ErrorCode::MissingHeader), to_string(ErrorCode::FileOpenFailed));
    EXPECT_NE(to_string(ErrorCode::FileOpenFailed), to_string(ErrorCode::FileWriteFailed));
    EXPECT_FALSE(to_string(ErrorCode::MissingHeader).empty());
    EXPECT_FALSE(to_string(ErrorCode::MalformedLine).empty());
    EXPECT_FALSE(to_string(ErrorCode::FileOpenFailed).empty());
    EXPECT_FALSE(to_string(ErrorCode::FileWriteFailed).empty());
}
