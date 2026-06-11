#include <gtest/gtest.h>

#include <cstdio>
#include <span>
#include <string>

#include "DetourModKit/drift_manifest.hpp"
#include "DetourModKit/rtti_dissect.hpp"

#include <process.h> // _getpid for collision-free temp paths under parallel CTest

using DetourModKit::Rtti::DriftEntry;
using DetourModKit::Rtti::HealError;
using DetourModKit::Rtti::ManifestError;
namespace rtti = DetourModKit::Rtti;

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
    entries[1].error = HealError::NoMatch;

    const auto parsed = rtti::parse_drift_report(rtti::serialize_drift_report(entries));
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 2u);

    EXPECT_EQ((*parsed)[0].name, name_a);
    EXPECT_EQ((*parsed)[0].nominal_offset, 0x10);
    EXPECT_EQ((*parsed)[0].healed_offset, 0x18);
    EXPECT_EQ((*parsed)[0].delta, 0x8);
    EXPECT_TRUE((*parsed)[0].ok);

    EXPECT_EQ((*parsed)[1].name, name_b);
    EXPECT_FALSE((*parsed)[1].ok);
    EXPECT_EQ((*parsed)[1].error, HealError::NoMatch);
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
    EXPECT_EQ(parsed.error(), ManifestError::MissingHeader);
}
