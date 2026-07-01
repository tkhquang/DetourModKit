/**
 * @file drift_manifest.cpp
 * @brief Durable serialization of self-heal drift reports.
 */

#include "DetourModKit/drift_manifest.hpp"

#include <charconv>
#include <fstream>
#include <iterator>
#include <string>

namespace DetourModKit
{
    namespace rtti
    {
        namespace
        {
            constexpr std::string_view MANIFEST_HEADER = "# DetourModKit drift manifest v1";
            constexpr char FIELD_SEP = '\t';

            // Stable round-trip tokens for the Rtti-block heal ErrorCodes, deliberately distinct from the verbose
            // human-readable Error::message() text (which is for logs): a manifest must parse back even if the log
            // wording is reworded, so the token strings are frozen independently of the enumerator spellings.
            [[nodiscard]] std::string_view heal_error_token(ErrorCode error) noexcept
            {
                switch (error)
                {
                case ErrorCode::BadDescriptor:
                    return "BadDescriptor";
                case ErrorCode::HealNoMatch:
                    return "NoMatch";
                case ErrorCode::HealAmbiguous:
                    return "Ambiguous";
                default:
                    return "BadDescriptor";
                }
            }

            [[nodiscard]] bool parse_heal_error(std::string_view token, ErrorCode &out) noexcept
            {
                if (token == "BadDescriptor")
                {
                    out = ErrorCode::BadDescriptor;
                    return true;
                }
                if (token == "NoMatch")
                {
                    out = ErrorCode::HealNoMatch;
                    return true;
                }
                if (token == "Ambiguous")
                {
                    out = ErrorCode::HealAmbiguous;
                    return true;
                }
                return false;
            }

            // Parses a decimal (possibly negative) offset that must span the whole field.
            [[nodiscard]] bool parse_offset(std::string_view field, std::ptrdiff_t &out) noexcept
            {
                if (field.empty())
                {
                    return false;
                }
                const char *const begin = field.data();
                const char *const end = field.data() + field.size();
                const auto result = std::from_chars(begin, end, out);
                return result.ec == std::errc{} && result.ptr == end;
            }
        } // anonymous namespace

        std::string serialize_drift_report(std::span<const DriftEntry> entries)
        {
            std::string out;
            out.append(MANIFEST_HEADER.data(), MANIFEST_HEADER.size());
            out.push_back('\n');
            for (const DriftEntry &entry : entries)
            {
                out.append(entry.name.data(), entry.name.size());
                out.push_back(FIELD_SEP);
                out.append(std::to_string(entry.nominal_offset));
                out.push_back(FIELD_SEP);
                out.append(std::to_string(entry.healed_offset));
                out.push_back(FIELD_SEP);
                out.append(std::to_string(entry.delta));
                out.push_back(FIELD_SEP);
                out.push_back(entry.ok ? '1' : '0');
                out.push_back(FIELD_SEP);
                const std::string_view token = heal_error_token(entry.error);
                out.append(token.data(), token.size());
                out.push_back('\n');
            }
            return out;
        }

        std::expected<std::vector<DriftRecord>, ManifestError> parse_drift_report(std::string_view text)
        {
            std::vector<DriftRecord> records;
            bool header_seen = false;
            std::size_t pos = 0;
            while (pos <= text.size())
            {
                const std::size_t newline = text.find('\n', pos);
                std::string_view line =
                    (newline == std::string_view::npos) ? text.substr(pos) : text.substr(pos, newline - pos);
                pos = (newline == std::string_view::npos) ? text.size() + 1 : newline + 1;

                // Strip a trailing CR (CRLF input) and skip blank lines.
                if (!line.empty() && line.back() == '\r')
                {
                    line.remove_suffix(1);
                }
                if (line.empty())
                {
                    continue;
                }

                if (!header_seen)
                {
                    if (line != MANIFEST_HEADER)
                    {
                        return std::unexpected(ManifestError::MissingHeader);
                    }
                    header_seen = true;
                    continue;
                }

                // Split into exactly six tab-separated fields; any other count is malformed.
                std::string_view fields[6];
                std::size_t field_count = 0;
                std::size_t field_pos = 0;
                bool too_many = false;
                while (true)
                {
                    const std::size_t sep = line.find(FIELD_SEP, field_pos);
                    const std::string_view field = (sep == std::string_view::npos)
                                                       ? line.substr(field_pos)
                                                       : line.substr(field_pos, sep - field_pos);
                    if (field_count >= 6)
                    {
                        too_many = true;
                        break;
                    }
                    fields[field_count++] = field;
                    if (sep == std::string_view::npos)
                    {
                        break;
                    }
                    field_pos = sep + 1;
                }
                if (too_many || field_count != 6)
                {
                    return std::unexpected(ManifestError::MalformedLine);
                }

                DriftRecord record;
                record.name = std::string(fields[0]);
                if (!parse_offset(fields[1], record.nominal_offset) || !parse_offset(fields[2], record.healed_offset) ||
                    !parse_offset(fields[3], record.delta))
                {
                    return std::unexpected(ManifestError::MalformedLine);
                }
                if (fields[4] == "1")
                {
                    record.ok = true;
                }
                else if (fields[4] == "0")
                {
                    record.ok = false;
                }
                else
                {
                    return std::unexpected(ManifestError::MalformedLine);
                }
                if (!parse_heal_error(fields[5], record.error))
                {
                    return std::unexpected(ManifestError::MalformedLine);
                }
                records.push_back(std::move(record));
            }

            if (!header_seen)
            {
                return std::unexpected(ManifestError::MissingHeader);
            }
            return records;
        }

        bool write_drift_report_to_file(const std::string &path, std::span<const DriftEntry> entries)
        {
            // Binary mode so the '\n' line endings written here are not translated to
            // CRLF; the parser tolerates either, but a stable on-disk form is clearer.
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!file)
            {
                return false;
            }
            const std::string text = serialize_drift_report(entries);
            file.write(text.data(), static_cast<std::streamsize>(text.size()));
            return static_cast<bool>(file);
        }

        std::expected<std::vector<DriftRecord>, ManifestError> read_drift_report_from_file(const std::string &path)
        {
            std::ifstream file(path, std::ios::binary);
            if (!file)
            {
                // An open failure (missing file, lock, permission, or a directory) is distinct from a
                // present-but-corrupt manifest: the latter flows through parse_drift_report and reports MissingHeader /
                // MalformedLine.
                return std::unexpected(ManifestError::FileOpenFailed);
            }
            const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            return parse_drift_report(text);
        }
    } // namespace rtti
} // namespace DetourModKit
