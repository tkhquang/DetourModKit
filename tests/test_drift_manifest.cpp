#include <gtest/gtest.h>

#include <cstdio>
#include <span>
#include <string>

#include "DetourModKit/drift_manifest.hpp"
#include "DetourModKit/rtti_dissect.hpp"

#include <process.h> // _getpid for collision-free temp paths under parallel CTest

using DetourModKit::ErrorCode;
using DetourModKit::rtti::DriftEntry;
using DetourModKit::rtti::ManifestError;
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
    EXPECT_EQ(parsed.error(), ManifestError::MissingHeader);
}

TEST(DriftManifestTest, ParseRejectsMalformedLine)
{
    // Header present, but a record line with too few fields.
    const auto parsed = rtti::parse_drift_report("# DetourModKit drift manifest v1\nfoo\t1\t2\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), ManifestError::MalformedLine);
}

TEST(DriftManifestTest, ParseRejectsNonNumericOffset)
{
    const auto parsed = rtti::parse_drift_report("# DetourModKit drift manifest v1\nfoo\tNaN\t2\t3\t1\tNoMatch\n");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), ManifestError::MalformedLine);
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
    ASSERT_TRUE(rtti::write_drift_report_to_file(path, std::span<const DriftEntry>(&entry, 1)));
    const auto parsed = rtti::read_drift_report_from_file(path);
    std::remove(path.c_str());

    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 1u);
    EXPECT_EQ((*parsed)[0].name, ".?AVFileFoo@@");
    EXPECT_EQ((*parsed)[0].healed_offset, 0x28);
}

TEST(DriftManifestTest, ReadMissingFileFailsClosed)
{
    const auto parsed = rtti::read_drift_report_from_file("dmk_definitely_no_such_manifest.tmp");
    ASSERT_FALSE(parsed.has_value());
    // A file that cannot be opened is an open failure, distinct from a present-but-corrupt manifest.
    EXPECT_EQ(parsed.error(), ManifestError::FileOpenFailed);
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
    EXPECT_EQ(parsed.error(), ManifestError::MissingHeader);
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
    EXPECT_EQ(parsed.error(), ManifestError::MissingHeader);
}

TEST(DriftManifestTest, ManifestErrorStringsAreDistinct)
{
    EXPECT_NE(rtti::manifest_error_to_string(ManifestError::MissingHeader),
              rtti::manifest_error_to_string(ManifestError::MalformedLine));
    EXPECT_NE(rtti::manifest_error_to_string(ManifestError::MalformedLine),
              rtti::manifest_error_to_string(ManifestError::FileOpenFailed));
    EXPECT_NE(rtti::manifest_error_to_string(ManifestError::MissingHeader),
              rtti::manifest_error_to_string(ManifestError::FileOpenFailed));
    EXPECT_FALSE(rtti::manifest_error_to_string(ManifestError::MissingHeader).empty());
    EXPECT_FALSE(rtti::manifest_error_to_string(ManifestError::MalformedLine).empty());
    EXPECT_FALSE(rtti::manifest_error_to_string(ManifestError::FileOpenFailed).empty());
}
