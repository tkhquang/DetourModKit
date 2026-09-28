#ifndef DETOURMODKIT_DRIFT_MANIFEST_HPP
#define DETOURMODKIT_DRIFT_MANIFEST_HPP

/**
 * @file drift_manifest.hpp
 * @brief Durable serialization of self-heal drift reports (@ref DetourModKit::rtti::DriftEntry).
 * @note The `detail/` path reflects compile visibility, not privacy. docs/design/public-api.md owns the rule.
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
        /** @brief A drift entry parsed from a manifest. It owns its name, so it outlives the manifest text. */
        struct DriftRecord
        {
            /// The landmark name.
            std::string name;
            /// Last-known offset recorded at write time.
            std::ptrdiff_t nominal_offset = 0;
            /// Resolved offset, meaningful only when @ref ok is true.
            std::ptrdiff_t healed_offset = 0;
            /// `healed_offset - nominal_offset`, meaningful only when @ref ok is true.
            std::ptrdiff_t delta = 0;
            /// Whether the landmark healed.
            bool ok = false;
            /// Failure code in @ref ErrorCategory::Rtti, meaningful only when @ref ok is false.
            ErrorCode error{ErrorCode::Ok};
        };

        /**
         * @brief Serializes a drift report to a versioned manifest with one tab-separated line per entry.
         * @details The fields are name, nominal_offset, healed_offset, delta, ok, and a stable error token (not
         *          @ref Error::message()). A name escapes tab, LF, CR, and backslash in C style and round-trips through
         *          @ref parse_drift_report.
         */
        [[nodiscard]] std::string serialize_drift_report(std::span<const DriftEntry> entries);

        /**
         * @brief Parses a drift manifest produced by @ref serialize_drift_report. It accepts blank lines and CRLF.
         * @return The records, ErrorCode::MissingHeader without a header line, or ErrorCode::MalformedLine for a bad
         *         record line or a truncated or unknown name escape.
         */
        [[nodiscard]] Result<std::vector<DriftRecord>> parse_drift_report(std::string_view text);

        /**
         * @brief Writes a drift report through @ref serialize_drift_report to @p path, a UTF-8 file path.
         * @return ErrorCode::FileOpenFailed when @p path is ill-formed UTF-8 or the file does not open for writing.
         *         ErrorCode::FileWriteFailed when the write does not complete, for example on a full disk.
         * @note The write truncates @p path in place and is not atomic. A crash can leave a partial manifest. The next
         *       read reports MalformedLine or MissingHeader, or returns fewer records when the partial manifest ends
         *       right after a complete header or record. Do not route load-bearing data through it.
         */
        [[nodiscard]] Result<void>
        write_drift_report_to_file(const std::string &path, std::span<const DriftEntry> entries);

        /**
         * @brief Reads and parses the drift manifest at @p path, a UTF-8 file path.
         * @return The records, ErrorCode::FileOpenFailed when @p path is ill-formed UTF-8 or the file does not open,
         *         or a @ref parse_drift_report error for corrupt contents. An empty file reports MissingHeader.
         */
        [[nodiscard]] Result<std::vector<DriftRecord>> read_drift_report_from_file(const std::string &path);
    } // namespace rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_DRIFT_MANIFEST_HPP
