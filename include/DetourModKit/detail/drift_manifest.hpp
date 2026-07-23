#ifndef DETOURMODKIT_DRIFT_MANIFEST_HPP
#define DETOURMODKIT_DRIFT_MANIFEST_HPP

/**
 * @file drift_manifest.hpp
 * @brief Durable serialization of self-heal drift reports (@ref DetourModKit::rtti::DriftEntry).
 * @details Lets a consumer persist a @ref DetourModKit::rtti::heal_report across game versions and diff the saved
 *          manifests to see which offsets moved between patches, instead of only logging the live telemetry once per
 *          run.
 * @note This header sits in the detail/ directory for compile visibility: the umbrella includes it. It declares its
 *       types in the rtti namespace because they extend the rtti drift surface; diagnostics.hpp and manifest.hpp name
 *       rtti::DriftEntry / rtti::parse_drift_report directly. Directory placement and namespace placement are
 *       independent; the directory reflects compile visibility, not privacy.
 */

#include "DetourModKit/error.hpp"
#include "DetourModKit/rtti_dissect.hpp"

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    namespace rtti
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
            /// Failure code (its category is @ref ErrorCategory::Rtti); meaningful only when @ref ok is false.
            ErrorCode error{ErrorCode::Ok};
        };

        /**
         * @brief Serializes a drift report to a durable, line-oriented manifest.
         * @details Emits a versioned header line followed by one tab-separated line per entry (name, nominal_offset,
         *          healed_offset, delta, ok, error). The error is written as a stable token, not the human-readable
         *          @ref Error::message() text. Record delimiters and backslashes in a name use C-style escapes so every
         *          name round-trips exactly through @ref parse_drift_report.
         * @param entries The drift entries to serialize (e.g. from @ref heal_report).
         * @return The manifest text.
         */
        [[nodiscard]] std::string serialize_drift_report(std::span<const DriftEntry> entries);

        /**
         * @brief Parses a drift manifest produced by @ref serialize_drift_report.
         * @details Tolerates blank lines and CRLF input. Decodes the name field's C-style escapes. Fails closed on a
         *          missing header or any malformed record line, including a truncated or unknown name escape.
         * @param text The manifest text.
         * @return The parsed records, or an Error carrying ErrorCode::MissingHeader (no header line) or
         *         ErrorCode::MalformedLine (a bad record line).
         */
        [[nodiscard]] Result<std::vector<DriftRecord>> parse_drift_report(std::string_view text);

        /**
         * @brief Writes a drift report to a file via @ref serialize_drift_report.
         * @param path Destination file path (UTF-8).
         * @param entries The drift entries to serialize.
         * @return An empty Result on success; or an Error: ErrorCode::FileOpenFailed when @p path cannot be opened
         *         for writing, or ErrorCode::FileWriteFailed when it opened but the write did not complete (disk full,
         *         an I/O error). Mirrors the Result contract of @ref read_drift_report_from_file, not a bare bool, so
         *         a caller can tell an open failure from a truncated write.
         * @note The write is not atomic: it truncates @p path in place, so a crash or power loss mid-write can leave a
         *       partial manifest. That is acceptable here because the manifest is a regenerable diagnostic/diff
         *       artifact (offsets are re-healed every session, never loaded as load-bearing state); a torn file is
         *       reported as MalformedLine / MissingHeader on the next read and overwritten. Do not route load-bearing
         *       data through this path without first making the write atomic (temp file + replace).
         */
        [[nodiscard]] Result<void> write_drift_report_to_file(const std::string &path,
                                                              std::span<const DriftEntry> entries);

        /**
         * @brief Reads and parses a drift manifest file.
         * @param path Source file path (UTF-8).
         * @return The parsed records, or an Error: ErrorCode::FileOpenFailed when the file cannot be opened, or a parse
         *         error (ErrorCode::MissingHeader / ErrorCode::MalformedLine) when the file is present but its contents
         *         are corrupt. An opened-but-empty file reports MissingHeader.
         */
        [[nodiscard]] Result<std::vector<DriftRecord>> read_drift_report_from_file(const std::string &path);
    } // namespace rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_DRIFT_MANIFEST_HPP
