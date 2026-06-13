#ifndef DETOURMODKIT_DRIFT_MANIFEST_HPP
#define DETOURMODKIT_DRIFT_MANIFEST_HPP

/**
 * @file drift_manifest.hpp
 * @brief Durable serialization of self-heal drift reports (@ref DetourModKit::Rtti::DriftEntry).
 * @details Lets a consumer persist a @ref DetourModKit::Rtti::heal_report across game versions and diff the saved
 *          manifests to see which offsets moved between patches, instead of only logging the live telemetry once per
 *          run.
 */

#include "DetourModKit/rtti_dissect.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace Rtti
    {
        /**
         * @struct DriftRecord
         * @brief An owning, parsed drift entry read back from a manifest.
         * @details The persisted counterpart to @ref DriftEntry. Unlike DriftEntry, whose @c name aliases caller
         *          storage, DriftRecord owns its name so it stays valid after the manifest text or file buffer is gone.
         */
        struct DriftRecord
        {
            /// The landmark name (owned).
            std::string name;
            /// Last-known offset recorded at write time.
            std::ptrdiff_t nominal_offset = 0;
            /// Resolved offset (meaningful only when @ref ok).
            std::ptrdiff_t healed_offset = 0;
            /// healed_offset - nominal_offset (meaningful only when @ref ok).
            std::ptrdiff_t delta = 0;
            /// Whether the landmark healed.
            bool ok = false;
            /// Failure reason (meaningful only when @ref ok is false).
            HealError error{};
        };

        /**
         * @enum ManifestError
         * @brief Why reading or parsing a drift manifest failed. Fails closed: no partial result.
         */
        enum class ManifestError : std::uint8_t
        {
            /// The first non-blank line was not the manifest header (file present but corrupt).
            MissingHeader,
            /// A record line had the wrong field count or an unparseable field (file present but corrupt).
            MalformedLine,
            /// The file could not be opened (missing, locked, permission denied, or not a regular file).
            FileOpenFailed
        };

        /**
         * @brief Human-readable mapping for @ref ManifestError.
         * @param error The error code.
         * @return A string view describing the error.
         */
        [[nodiscard]] constexpr std::string_view manifest_error_to_string(ManifestError error) noexcept
        {
            switch (error)
            {
            case ManifestError::MissingHeader:
                return "Manifest header line is missing or wrong";
            case ManifestError::MalformedLine:
                return "A manifest record line is malformed";
            case ManifestError::FileOpenFailed:
                return "Manifest file could not be opened";
            }
            return "Unknown manifest error";
        }

        /**
         * @brief Serializes a drift report to a durable, line-oriented manifest.
         * @details Emits a versioned header line followed by one tab-separated line per entry (name, nominal_offset,
         *          healed_offset, delta, ok, error). The error is written as a stable token, not the human-readable
         *          @ref heal_error_to_string text, so the manifest round-trips. Names are assumed free of tab and
         *          newline (MSVC mangled type names are).
         * @param entries The drift entries to serialize (e.g. from @ref heal_report).
         * @return The manifest text.
         */
        [[nodiscard]] std::string serialize_drift_report(std::span<const DriftEntry> entries);

        /**
         * @brief Parses a drift manifest produced by @ref serialize_drift_report.
         * @details Tolerates blank lines and trailing carriage returns (CRLF input). Fails closed on a missing header
         *          or any malformed record line.
         * @param text The manifest text.
         * @return The parsed records, or a @ref ManifestError.
         */
        [[nodiscard]] std::expected<std::vector<DriftRecord>, ManifestError> parse_drift_report(std::string_view text);

        /**
         * @brief Writes a drift report to a file via @ref serialize_drift_report.
         * @param path Destination file path (UTF-8).
         * @param entries The drift entries to serialize.
         * @return true on success, false if the file could not be opened or written.
         * @note The write is not atomic: it truncates @p path in place, so a crash or power loss mid-write can leave a
         *       partial manifest. That is acceptable here because the manifest is a regenerable diagnostic/diff
         *       artifact (offsets are re-healed every session, never loaded as load-bearing state); a torn file is
         *       reported as MalformedLine / MissingHeader on the next read and overwritten. Do not route load-bearing
         *       data through this path without first making the write atomic (temp file + replace).
         */
        [[nodiscard]] bool write_drift_report_to_file(const std::string &path, std::span<const DriftEntry> entries);

        /**
         * @brief Reads and parses a drift manifest file.
         * @param path Source file path (UTF-8).
         * @return The parsed records, or a @ref ManifestError: @ref ManifestError::FileOpenFailed when the file cannot
         *         be opened, or a parse error (@ref ManifestError::MissingHeader / @ref ManifestError::MalformedLine)
         *         when the file is present but its contents are corrupt. An opened-but-empty file reports
         *         MissingHeader.
         */
        [[nodiscard]] std::expected<std::vector<DriftRecord>, ManifestError>
        read_drift_report_from_file(const std::string &path);
    } // namespace Rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_DRIFT_MANIFEST_HPP
