/**
 * @file manifest_grammar.cpp
 * @brief Raw-text prepass that closes manifest identity and framing collisions before the INI backend can merge them.
 * @details CSimpleIniCaseA merges duplicate sections, retains the last duplicate key, and absorbs an unterminated
 *          heredoc through end of file. This pass uses the same whitespace, section, line-break, and heredoc rules.
 *          It rejects lost identities, unclosed heredocs, discarded key lines, and resource-cap excesses before store
 *          allocation. One shared token model prevents a collision from escape through a backend difference.
 */

#include "internal/manifest_grammar.hpp"

#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace DetourModKit::manifest::detail
{
    namespace
    {
        // The backend's IsSpace: a space, tab, or either newline character. Used for blank-line and trailing-name
        // trimming exactly as FindEntry does.
        [[nodiscard]] bool is_space(char c) noexcept
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }

        [[nodiscard]] bool is_newline(char c) noexcept
        {
            return c == '\r' || c == '\n';
        }

        [[nodiscard]] std::string_view rtrim(std::string_view text) noexcept
        {
            while (!text.empty() && is_space(text.back()))
            {
                text.remove_suffix(1);
            }
            return text;
        }

        [[nodiscard]] std::string to_lower(std::string_view text)
        {
            std::string out(text);
            for (char &c : out)
            {
                if (c >= 'A' && c <= 'Z')
                {
                    c = static_cast<char>(c - 'A' + 'a');
                }
            }
            return out;
        }

        [[nodiscard]] std::unexpected<Error> fail(ErrorCode code, const char *context) noexcept
        {
            return std::unexpected(Error{code, context});
        }

        [[nodiscard]] bool consume_bytes(std::size_t bytes, std::size_t limit, std::size_t &total) noexcept
        {
            if (bytes > limit - total)
            {
                return false;
            }
            total += bytes;
            return true;
        }

        [[nodiscard]] std::string_view rung_parent(std::string_view name) noexcept
        {
            const std::size_t marker = name.rfind(".rung.");
            if (marker == std::string_view::npos)
            {
                return {};
            }
            const std::string_view tail = name.substr(marker + 6);
            if (tail.empty())
            {
                return {};
            }
            std::size_t index = 0;
            for (const char c : tail)
            {
                if (c < '0' || c > '9')
                {
                    return {};
                }
                const std::size_t digit = static_cast<std::size_t>(c - '0');
                constexpr std::size_t MAX_INDEX = std::numeric_limits<std::size_t>::max();
                if (index > (MAX_INDEX - digit) / 10U)
                {
                    return {};
                }
                index = (index * 10U) + digit;
            }
            return name.substr(0, marker);
        }
    } // namespace

    Result<void> validate_manifest_grammar(std::string_view text, const GrammarLimits &limits, const char *context)
    {
        if (text.size() > limits.max_file_bytes)
        {
            return fail(ErrorCode::SizeTooLarge, context);
        }
        // The backend strips a leading UTF-8 BOM before tokenizing, so a BOM-prefixed first line is invisible here yet
        // parsed by the store: its section or key identities would escape collision detection. The checked serializer
        // never emits a BOM, so rejection is round-trip safe.
        if (text.starts_with("\xEF\xBB\xBF"))
        {
            return fail(ErrorCode::MalformedLine, context);
        }
        // The backend's tokenizer is NUL-terminated and silently stops at the first '\0', so every byte after it would
        // be validated here yet never loaded: a record could vanish without an error. The checked serializer never
        // emits a NUL, so rejection is round-trip safe.
        if (text.find('\0') != std::string_view::npos)
        {
            return fail(ErrorCode::MalformedLine, context);
        }

        std::unordered_set<std::string> seen_sections;
        std::unordered_set<std::string> seen_keys; // reset on each section
        std::unordered_map<std::string, std::size_t> rung_counts;
        std::size_t section_count = 0;
        std::size_t key_count = 0;
        std::size_t record_count = 0;
        std::size_t total_bytes = 0;

        const std::size_t size = text.size();
        std::size_t pos = 0;

        const auto line_end_from = [&](std::size_t start) noexcept
        {
            while (start < size && !is_newline(text[start]))
            {
                ++start;
            }
            return start;
        };
        // Consume one line terminator: a lone `\r`, a lone `\n`, or a `\r\n` pair, matching the backend's SkipNewLine.
        const auto skip_newline = [&](std::size_t at) noexcept
        {
            if (at < size && text[at] == '\r')
            {
                ++at;
                if (at < size && text[at] == '\n')
                {
                    ++at;
                }
            }
            else if (at < size && text[at] == '\n')
            {
                ++at;
            }
            return at;
        };

        while (pos < size)
        {
            // Skip whitespace runs, which folds away leading indentation, blank lines, and every line terminator.
            while (pos < size && is_space(text[pos]))
            {
                ++pos;
            }
            if (pos >= size)
            {
                break;
            }

            // Comment line.
            if (text[pos] == ';' || text[pos] == '#')
            {
                pos = line_end_from(pos);
                continue;
            }

            // Section header.
            if (text[pos] == '[')
            {
                ++pos;
                while (pos < size && is_space(text[pos]))
                {
                    ++pos;
                }
                const std::size_t name_start = pos;
                while (pos < size && text[pos] != ']' && !is_newline(text[pos]))
                {
                    ++pos;
                }
                if (pos >= size || text[pos] != ']')
                {
                    // No closing bracket. The backend does not discard this line: FindEntry points its section cursor
                    // at the name before testing for `]`, and on the miss it resumes the scan without clearing that
                    // cursor, so the next key line's NUL terminator folds the unterminated name plus an embedded
                    // newline into a section identity this pass never validated. A `sig.`-prefixed record can reach
                    // the store past every collision, prefix, and size check. A canonical manifest never opens a
                    // bracket it does not close, so fail closed.
                    return fail(ErrorCode::MalformedLine, context);
                }
                const std::string_view name = rtrim(text.substr(name_start, pos - name_start));
                pos = line_end_from(pos);

                std::string folded = to_lower(name);
                // An empty section name (`[]`, `[   ]`) is the backend's implicit default section, which also holds any
                // keys before the first header; re-opening it would let a key collision split across the `[]` escape
                // the per-section namespace. A canonical manifest never names it, so reject it outright.
                if (folded.empty())
                {
                    return fail(ErrorCode::MalformedLine, context);
                }
                // The `manifest` header and every `sig.` prefix must be canonical lowercase, else the case-sensitive
                // store would silently drop the section (a lost record). Fail closed instead.
                if ((folded == "manifest" && name != "manifest") ||
                    (folded.starts_with("sig.") && !name.starts_with("sig.")))
                {
                    return fail(ErrorCode::MalformedLine, context);
                }
                // The folded, trimmed name is the merge key: two sections reaching it by case, whitespace, or exact
                // repetition would collapse into one before the trust gate.
                if (section_count >= limits.max_sections)
                {
                    return fail(ErrorCode::SizeTooLarge, context);
                }
                if (!seen_sections.insert(std::move(folded)).second)
                {
                    return fail(ErrorCode::ManifestIdentityCollision, context);
                }
                ++section_count;

                // Classify record vs rung on the raw name, not the fold: parse() reads `.rung.` case-sensitively and
                // treats a miscased marker as an ordinary label, so folding here would charge a legitimate record
                // (e.g. `sig.a.RUNG.0`, label `a.RUNG.0`) against the rung cap the two passes must agree on.
                if (name.starts_with("sig."))
                {
                    const std::string_view parent = rung_parent(name);
                    if (!parent.empty() && parent.size() <= 4U)
                    {
                        return fail(ErrorCode::MalformedLine, context);
                    }
                    const std::string_view label = parent.empty() ? name.substr(4) : parent.substr(4);
                    if (label.size() > limits.max_field_bytes)
                    {
                        return fail(ErrorCode::SizeTooLarge, context);
                    }
                    if (parent.empty())
                    {
                        if (record_count >= limits.max_records)
                        {
                            return fail(ErrorCode::SizeTooLarge, context);
                        }
                        ++record_count;
                    }
                    else
                    {
                        auto count_it = rung_counts.try_emplace(std::string(parent), 0).first;
                        if (count_it->second >= limits.max_rungs_per_record)
                        {
                            return fail(ErrorCode::SizeTooLarge, context);
                        }
                        ++count_it->second;
                    }
                }
                seen_keys.clear();
                key_count = 0;
                continue;
            }

            // Key line. The key runs to the first `=` or newline.
            const std::size_t key_start = pos;
            while (pos < size && text[pos] != '=' && !is_newline(text[pos]))
            {
                ++pos;
            }
            if (pos >= size || text[pos] != '=')
            {
                // The backend discards a noncomment line with no `=`. A dropped separator can restore a default value.
                return fail(ErrorCode::MalformedLine, context);
            }
            if (pos == key_start)
            {
                // The backend discards an empty key without entry into heredoc mode.
                return fail(ErrorCode::MalformedLine, context);
            }
            const std::string_view key = rtrim(text.substr(key_start, pos - key_start));
            ++pos; // past '='
            while (pos < size && !is_newline(text[pos]) && (text[pos] == ' ' || text[pos] == '\t'))
            {
                ++pos;
            }
            const std::size_t value_start = pos;
            const std::size_t value_end = line_end_from(pos);
            const std::string_view value = rtrim(text.substr(value_start, value_end - value_start));
            pos = value_end;

            std::string folded_key = to_lower(key);
            if (key != folded_key)
            {
                return fail(ErrorCode::MalformedLine, context);
            }
            if (key_count >= limits.max_keys_per_section)
            {
                return fail(ErrorCode::SizeTooLarge, context);
            }
            if (!seen_keys.insert(std::move(folded_key)).second)
            {
                return fail(ErrorCode::ManifestIdentityCollision, context);
            }
            ++key_count;

            if (value.starts_with("<<<"))
            {
                // A heredoc runs until a line whose trailing-trimmed form EQUALS the tag (case-sensitive, matching the
                // case-sensitive store). An unterminated block would absorb every record below it into this value.
                const std::string_view tag = value.substr(3);
                // An empty tag terminates differently here and in the backend: the backend's terminator trim never
                // removes a line's first character, so a whitespace-only line closes the block for this pass but not
                // for the store, desynchronizing every section below. The checked serializer never emits a tagless
                // heredoc, so rejection is round-trip safe.
                if (tag.empty())
                {
                    return fail(ErrorCode::ManifestFramingUnsafe, context);
                }
                pos = skip_newline(pos);
                std::size_t body_bytes = 0;
                bool has_body_line = false;
                bool closed = false;
                while (pos < size)
                {
                    const std::size_t body_start = pos;
                    const std::size_t body_end = line_end_from(pos);
                    const std::string_view body_line = text.substr(body_start, body_end - body_start);
                    pos = skip_newline(body_end);
                    if (rtrim(body_line) == tag)
                    {
                        // A terminator as the first body line is not an empty value in the backend: its
                        // LoadMultiLineText leaves the value cursor on that line and restores the line break it
                        // NUL-tested, so the store loads the tag line plus every byte up to the next NUL the parser
                        // writes. This pass models that content as empty and never charges it against the caps, and
                        // the content can carry a raw `\r` or a leading `<<<` past the shared validator. An empty
                        // value is emitted raw, never as a heredoc, so rejection is round-trip safe. A blank body line
                        // before the terminator is a genuinely empty value in both tokenizers and stays accepted.
                        if (!has_body_line)
                        {
                            return fail(ErrorCode::ManifestFramingUnsafe, context);
                        }
                        closed = true;
                        break;
                    }
                    if ((has_body_line && !consume_bytes(1, limits.max_field_bytes, body_bytes)) ||
                        !consume_bytes(body_line.size(), limits.max_field_bytes, body_bytes))
                    {
                        return fail(ErrorCode::SizeTooLarge, context);
                    }
                    has_body_line = true;
                }
                if (!closed)
                {
                    return fail(ErrorCode::ManifestFramingUnsafe, context);
                }
                if (!consume_bytes(body_bytes, limits.max_total_decoded_bytes, total_bytes))
                {
                    return fail(ErrorCode::SizeTooLarge, context);
                }
            }
            else
            {
                if (value.size() > limits.max_field_bytes)
                {
                    return fail(ErrorCode::SizeTooLarge, context);
                }
                if (!consume_bytes(value.size(), limits.max_total_decoded_bytes, total_bytes))
                {
                    return fail(ErrorCode::SizeTooLarge, context);
                }
            }
        }
        return {};
    }
} // namespace DetourModKit::manifest::detail
