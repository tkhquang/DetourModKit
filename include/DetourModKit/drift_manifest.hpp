#ifndef DETOURMODKIT_DRIFT_MANIFEST_HPP
#define DETOURMODKIT_DRIFT_MANIFEST_HPP

/**
 * @file drift_manifest.hpp
 * @brief Durable serialization of self-heal drift reports (@ref DetourModKit::Rtti::DriftEntry).
 * @details Lets a consumer persist a @ref DetourModKit::Rtti::heal_report across game
 *          versions and diff the saved manifests to see which offsets moved between
 *          patches, instead of only logging the live telemetry once per run.
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
         * @details The persisted counterpart to @ref DriftEntry. Unlike DriftEntry,
         *          whose @c name aliases caller storage, DriftRecord owns its name so
         *          it stays valid after the manifest text or file buffer is gone.
         */
        struct DriftRecord
        {
            std::string name;                  ///< The landmark name (owned).
            std::ptrdiff_t nominal_offset = 0; ///< Last-known offset recorded at write time.
            std::ptrdiff_t healed_offset = 0;  ///< Resolved offset (meaningful only when @ref ok).
            std::ptrdiff_t delta = 0;          ///< healed_offset - nominal_offset (meaningful only when @ref ok).
            bool ok = false;                   ///< Whether the landmark healed.
            HealError error{};                 ///< Failure reason (meaningful only when @ref ok is false).
        };

        /**
         * @enum ManifestError
         * @brief Why parsing a drift manifest failed. Fails closed: no partial result.
         */
        enum class ManifestError : std::uint8_t
        {
            MissingHeader, ///< The first non-blank line was not the manifest header.
            MalformedLine  ///< A record line had the wrong field count or an unparseable field.
        };

        /**
         * @brief Serializes a drift report to a durable, line-oriented manifest.
         * @details Emits a versioned header line followed by one tab-separated line
         *          per entry (name, nominal_offset, healed_offset, delta, ok, error).
         *          The error is written as a stable token, not the human-readable
         *          @ref heal_error_to_string text, so the manifest round-trips. Names
         *          are assumed free of tab and newline (MSVC mangled type names are).
         * @param entries The drift entries to serialize (e.g. from @ref heal_report).
         * @return The manifest text.
         */
        [[nodiscard]] std::string serialize_drift_report(std::span<const DriftEntry> entries);

        /**
         * @brief Parses a drift manifest produced by @ref serialize_drift_report.
         * @details Tolerates blank lines and trailing carriage returns (CRLF input).
         *          Fails closed on a missing header or any malformed record line.
         * @param text The manifest text.
         * @return The parsed records, or a @ref ManifestError.
         */
        [[nodiscard]] std::expected<std::vector<DriftRecord>, ManifestError>
        parse_drift_report(std::string_view text);

        /**
         * @brief Writes a drift report to a file via @ref serialize_drift_report.
         * @param path Destination file path (UTF-8).
         * @param entries The drift entries to serialize.
         * @return true on success, false if the file could not be opened or written.
         */
        [[nodiscard]] bool write_drift_report_to_file(const std::string &path,
                                                      std::span<const DriftEntry> entries);

        /**
         * @brief Reads and parses a drift manifest file.
         * @param path Source file path (UTF-8).
         * @return The parsed records, or a @ref ManifestError (MissingHeader is also
         *         returned when the file cannot be opened or is empty).
         */
        [[nodiscard]] std::expected<std::vector<DriftRecord>, ManifestError>
        read_drift_report_from_file(const std::string &path);
    } // namespace Rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_DRIFT_MANIFEST_HPP
