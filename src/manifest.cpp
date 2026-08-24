/**
 * @file manifest.cpp
 * @brief This TU implements manifest parse and checked serialization over the INI grammar.
 * @details The INI parser and emitter are confined to this translation unit, so the simpleini dependency never
 *          reaches a consumer's include path. The schema is a versioned `[manifest]` header, one `[sig.<label>]`
 *          section per contract, and ordered `[sig.<label>.rung.<N>]` sub-sections for the candidate ladder.
 *          Signature compile/adopt, the overlay merge, and the trust gate live in the sibling TU
 *          manifest_overlay.cpp over the shared internal/manifest_record_rules.hpp rule set.
 */

#include "DetourModKit/manifest.hpp"

#include "DetourModKit/hook.hpp"

#include "internal/manifest_grammar.hpp"
#include "internal/manifest_record_rules.hpp"
#include "internal/scan_shared.hpp"
#include "internal/win_file_stream.hpp"

#include <SimpleIni.h>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <fstream>
#include <limits>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace DetourModKit::manifest
{
    namespace
    {
        // The manifest uses a case-sensitive INI store after the raw prepass rejects exact, whitespace, and ASCII case
        // collisions. Canonical keys and verbatim labels then load without another case fold.
        using ManifestIni = CSimpleIniCaseA;

        // The register token table mirrors hook::Gpr one for one. Both omit rsp and rip deliberately. A token maps to a
        // register and back without a second source of truth.
        constexpr std::array<std::string_view, 15> GPR_TOKENS =
            {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
        static_assert(GPR_TOKENS.size() == static_cast<std::size_t>(hook::Gpr::R15) + 1);
        static_assert(
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::Rax)] == "rax" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::Rbx)] == "rbx" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::Rcx)] == "rcx" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::Rdx)] == "rdx" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::Rsi)] == "rsi" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::Rdi)] == "rdi" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::Rbp)] == "rbp" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::R8)] == "r8" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::R9)] == "r9" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::R10)] == "r10" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::R11)] == "r11" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::R12)] == "r12" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::R13)] == "r13" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::R14)] == "r14" &&
            GPR_TOKENS[static_cast<std::size_t>(hook::Gpr::R15)] == "r15"
        );

        [[nodiscard]] std::string to_lower(std::string_view text)
        {
            std::string out(text);
            for (char &c : out)
            {
                // Fold ASCII A-Z by hand: std::tolower on a negative char is undefined behavior, and manifest
                // tokens are ASCII keywords.
                if (c >= 'A' && c <= 'Z')
                {
                    c = static_cast<char>(c - 'A' + 'a');
                }
            }
            return out;
        }

        [[nodiscard]] std::string_view trim(std::string_view text) noexcept
        {
            const auto is_space = [](char c) noexcept { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
            while (!text.empty() && is_space(text.front()))
            {
                text.remove_prefix(1);
            }
            while (!text.empty() && is_space(text.back()))
            {
                text.remove_suffix(1);
            }
            return text;
        }

        // The whole token must match. A garbage suffix such as "0x1G" or "12abc" causes rejection instead of prefix
        // truncation. Magnitude is parsed unsigned then signed at the end so a value like INT64_MIN (whose magnitude
        // does not fit a signed type) still round-trips.

        [[nodiscard]] std::optional<unsigned long long> parse_magnitude(std::string_view body) noexcept
        {
            int base = 10;
            if (body.size() >= 2 && body[0] == '0' && (body[1] == 'x' || body[1] == 'X'))
            {
                base = 16;
                body.remove_prefix(2);
            }
            if (body.empty())
            {
                return std::nullopt;
            }
            unsigned long long value = 0;
            const char *first = body.data();
            const char *last = body.data() + body.size();
            const auto [ptr, ec] = std::from_chars(first, last, value, base);
            if (ec != std::errc{} || ptr != last)
            {
                return std::nullopt;
            }
            return value;
        }

        [[nodiscard]] std::optional<long long> parse_signed(std::string_view token) noexcept
        {
            token = trim(token);
            if (token.empty())
            {
                return std::nullopt;
            }
            bool negative = false;
            if (token.front() == '+' || token.front() == '-')
            {
                negative = token.front() == '-';
                token.remove_prefix(1);
            }
            const std::optional<unsigned long long> magnitude = parse_magnitude(token);
            if (!magnitude)
            {
                return std::nullopt;
            }

            constexpr unsigned long long MAX_SIGNED =
                static_cast<unsigned long long>(std::numeric_limits<long long>::max());
            if (negative)
            {
                constexpr unsigned long long MIN_MAGNITUDE = MAX_SIGNED + 1ULL;
                if (*magnitude > MIN_MAGNITUDE)
                {
                    return std::nullopt;
                }
                if (*magnitude == MIN_MAGNITUDE)
                {
                    return std::numeric_limits<long long>::min();
                }
                return -static_cast<long long>(*magnitude);
            }
            if (*magnitude > MAX_SIGNED)
            {
                return std::nullopt;
            }
            return static_cast<long long>(*magnitude);
        }

        [[nodiscard]] std::optional<unsigned long long> parse_unsigned(std::string_view token) noexcept
        {
            token = trim(token);
            if (token.empty() || token.front() == '-')
            {
                return std::nullopt;
            }
            if (token.front() == '+')
            {
                token.remove_prefix(1);
            }
            return parse_magnitude(token);
        }

        // Parse an unsigned token that must fit a byte-wide field (value_width, operand_index, byte_width, xmm_index).
        [[nodiscard]] std::optional<std::uint8_t> parse_u8(std::string_view token) noexcept
        {
            const std::optional<unsigned long long> value = parse_unsigned(token);
            if (!value || *value > 0xFFULL)
            {
                return std::nullopt;
            }
            return static_cast<std::uint8_t>(*value);
        }

        [[nodiscard]] std::optional<bool> parse_bool(std::string_view token)
        {
            const std::string lowered = to_lower(trim(token));
            if (lowered == "true" || lowered == "1" || lowered == "yes" || lowered == "on")
            {
                return true;
            }
            if (lowered == "false" || lowered == "0" || lowered == "no" || lowered == "off")
            {
                return false;
            }
            return std::nullopt;
        }

        // The enum token maps emit lowercase tokens and accept them case-insensitively for hand edits.

        [[nodiscard]] std::string_view anchor_kind_token(anchor::AnchorKind kind) noexcept
        {
            switch (kind)
            {
            case anchor::AnchorKind::VtableIdentity:
                return "vtable_identity";
            case anchor::AnchorKind::RipGlobal:
                return "rip_global";
            case anchor::AnchorKind::CodeOperand:
                return "code_operand";
            case anchor::AnchorKind::StringXref:
                return "string_xref";
            case anchor::AnchorKind::ExportName:
                return "export_name";
            case anchor::AnchorKind::Manual:
                return "manual";
            case anchor::AnchorKind::CallArgHome:
                return "call_arg_home";
            case anchor::AnchorKind::Quorum:
                return "quorum";
            case anchor::AnchorKind::Unset:
                return "unset";
            }
            return "manual";
        }

        // Accepts only the six serializable kinds. The composite Quorum and resolver-less CallArgHome remain in-code
        // constructs, so reject their tokens.
        [[nodiscard]] std::optional<anchor::AnchorKind> parse_anchor_kind(std::string_view token)
        {
            const std::string lowered = to_lower(trim(token));
            if (lowered == "vtable_identity")
            {
                return anchor::AnchorKind::VtableIdentity;
            }
            if (lowered == "rip_global")
            {
                return anchor::AnchorKind::RipGlobal;
            }
            if (lowered == "code_operand")
            {
                return anchor::AnchorKind::CodeOperand;
            }
            if (lowered == "string_xref")
            {
                return anchor::AnchorKind::StringXref;
            }
            if (lowered == "export_name")
            {
                return anchor::AnchorKind::ExportName;
            }
            if (lowered == "manual")
            {
                return anchor::AnchorKind::Manual;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::string_view scan_mode_token(scan::Mode mode) noexcept
        {
            switch (mode)
            {
            case scan::Mode::Direct:
                return "direct";
            case scan::Mode::RipRelative:
                return "rip_relative";
            case scan::Mode::RttiVtable:
                return "rtti_vtable";
            case scan::Mode::StringXref:
                return "string_xref";
            }
            return "direct";
        }

        [[nodiscard]] std::optional<scan::Mode> parse_scan_mode(std::string_view token)
        {
            const std::string lowered = to_lower(trim(token));
            if (lowered == "direct")
            {
                return scan::Mode::Direct;
            }
            if (lowered == "rip_relative")
            {
                return scan::Mode::RipRelative;
            }
            if (lowered == "rtti_vtable")
            {
                return scan::Mode::RttiVtable;
            }
            if (lowered == "string_xref")
            {
                return scan::Mode::StringXref;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::string_view operand_kind_token(scan::OperandKind kind) noexcept
        {
            return kind == scan::OperandKind::MemoryDisplacement ? "memory_displacement" : "immediate";
        }

        [[nodiscard]] std::optional<scan::OperandKind> parse_operand_kind(std::string_view token)
        {
            const std::string lowered = to_lower(trim(token));
            if (lowered == "immediate")
            {
                return scan::OperandKind::Immediate;
            }
            if (lowered == "memory_displacement")
            {
                return scan::OperandKind::MemoryDisplacement;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::string_view encoding_token(scan::StringEncoding encoding) noexcept
        {
            return encoding == scan::StringEncoding::Utf16le ? "utf16le" : "utf8";
        }

        [[nodiscard]] std::optional<scan::StringEncoding> parse_encoding(std::string_view token)
        {
            const std::string lowered = to_lower(trim(token));
            if (lowered == "utf8")
            {
                return scan::StringEncoding::Utf8;
            }
            if (lowered == "utf16le")
            {
                return scan::StringEncoding::Utf16le;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::string_view pages_token(scan::Pages pages) noexcept
        {
            switch (pages)
            {
            case scan::Pages::Readable:
                return "readable";
            case scan::Pages::Executable:
                return "executable";
            }
            return "invalid";
        }

        [[nodiscard]] std::optional<scan::Pages> parse_pages(std::string_view token)
        {
            const std::string lowered = to_lower(trim(token));
            if (lowered == "readable")
            {
                return scan::Pages::Readable;
            }
            if (lowered == "executable")
            {
                return scan::Pages::Executable;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::string_view xref_return_token(scan::XrefReturn mode) noexcept
        {
            switch (mode)
            {
            case scan::XrefReturn::ReferencingInstruction:
                return "instruction";
            case scan::XrefReturn::EnclosingFunction:
                return "function";
            case scan::XrefReturn::StringPointerSlot:
                return "pointer_slot";
            }
            return "instruction";
        }

        [[nodiscard]] std::optional<scan::XrefReturn> parse_xref_return(std::string_view token)
        {
            const std::string lowered = to_lower(trim(token));
            if (lowered == "instruction")
            {
                return scan::XrefReturn::ReferencingInstruction;
            }
            if (lowered == "function")
            {
                return scan::XrefReturn::EnclosingFunction;
            }
            if (lowered == "pointer_slot")
            {
                return scan::XrefReturn::StringPointerSlot;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<BindingKind> parse_binding_kind(std::string_view token)
        {
            const std::string lowered = to_lower(trim(token));
            if (lowered == "address")
            {
                return BindingKind::Address;
            }
            if (lowered == "pointer_chain")
            {
                return BindingKind::PointerChain;
            }
            if (lowered == "mid_hook_register")
            {
                return BindingKind::MidHookRegister;
            }
            if (lowered == "vmt_method")
            {
                return BindingKind::VmtMethod;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<hook::Gpr> parse_gpr(std::string_view token)
        {
            const std::string lowered = to_lower(trim(token));
            for (std::size_t index = 0; index < GPR_TOKENS.size(); ++index)
            {
                if (lowered == GPR_TOKENS[index])
                {
                    return static_cast<hook::Gpr>(index);
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] std::string_view gpr_token(hook::Gpr reg) noexcept
        {
            const auto index = static_cast<std::size_t>(reg);
            return index < GPR_TOKENS.size() ? GPR_TOKENS[index] : GPR_TOKENS[0];
        }

        // Format a signed offset as human-editable hex. Preserve the sign so a negative field offset reads naturally.
        [[nodiscard]] std::string format_signed_hex(long long value)
        {
            const unsigned long long magnitude =
                value < 0 ? 0ULL - static_cast<unsigned long long>(value) : static_cast<unsigned long long>(value);
            if (value < 0)
            {
                return std::format("-0x{:X}", magnitude);
            }
            return std::format("0x{:X}", magnitude);
        }

        class ManifestIniBuilder
        {
        public:
            ManifestIniBuilder(ManifestIni &ini, const ManifestLimits &limits) noexcept : m_ini(ini), m_limits(limits)
            {
            }

            [[nodiscard]] Result<void> begin_section() noexcept
            {
                if (m_section_count >= m_limits.max_sections)
                {
                    return fail(ErrorCode::SizeTooLarge, "manifest::serialize_checked");
                }
                ++m_section_count;
                m_key_count = 0;
                return {};
            }

            [[nodiscard]] Result<void> set(const char *section, const char *key, const char *value)
            {
                const std::string_view value_view{value};
                if (m_key_count >= m_limits.max_keys_per_section || value_view.size() > m_limits.max_field_bytes ||
                    value_view.size() > m_limits.max_total_decoded_bytes - m_total_decoded_bytes)
                {
                    return fail(ErrorCode::SizeTooLarge, "manifest::serialize_checked");
                }
                if (m_ini.SetValue(section, key, value) < 0)
                {
                    return fail(ErrorCode::OutOfMemory, "manifest::serialize_checked");
                }
                ++m_key_count;
                m_total_decoded_bytes += value_view.size();
                return {};
            }

        private:
            ManifestIni &m_ini;
            const ManifestLimits &m_limits;
            std::size_t m_section_count{0};
            std::size_t m_key_count{0};
            std::size_t m_total_decoded_bytes{0};
        };

        class BoundedStringWriter final : public ManifestIni::OutputWriter
        {
        public:
            BoundedStringWriter(std::string &output, std::size_t max_bytes) noexcept
                : m_output(output), m_max_bytes(max_bytes)
            {
            }

            void Write(const char *text) override
            {
                if (m_exceeded)
                {
                    return;
                }
                const std::string_view chunk{text};
                if (chunk.size() > m_max_bytes - m_output.size() ||
                    chunk.size() > m_output.max_size() - m_output.size())
                {
                    m_exceeded = true;
                    return;
                }
                m_output.append(chunk);
            }

            [[nodiscard]] bool exceeded() const noexcept { return m_exceeded; }

        private:
            std::string &m_output;
            std::size_t m_max_bytes;
            bool m_exceeded{false};
        };

        // Reads one candidate-ladder rung out of its sub-section. Returns nullopt-shaped failure via the Result so a
        // bad field fails the whole parse closed (a partially-trusted ladder is worse than none).
        [[nodiscard]] Result<CandidateSpec> parse_rung(const ManifestIni &ini, const char *section)
        {
            CandidateSpec spec;
            if (const char *name = ini.GetValue(section, "name", nullptr))
            {
                spec.name = name;
            }

            const char *mode_raw = ini.GetValue(section, "mode", nullptr);
            if (mode_raw == nullptr)
            {
                return fail(ErrorCode::MalformedLine, "manifest::parse");
            }
            const std::optional<scan::Mode> mode = parse_scan_mode(mode_raw);
            if (!mode)
            {
                return fail(ErrorCode::MalformedLine, "manifest::parse");
            }
            spec.mode = *mode;

            switch (*mode)
            {
            case scan::Mode::Direct:
            case scan::Mode::RipRelative:
            {
                if (const char *pattern = ini.GetValue(section, "pattern", nullptr))
                {
                    spec.pattern = pattern;
                }
                else
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                // Each decode key belongs to the mode that the emitter uses. Reject a key that the active mode does
                // not emit. Otherwise the next save drops it without an error.
                if (const char *walk = ini.GetValue(section, "walk_back", nullptr))
                {
                    const std::optional<long long> value = parse_signed(walk);
                    if (*mode != scan::Mode::Direct || !value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    spec.walk_back = static_cast<std::ptrdiff_t>(*value);
                }
                bool has_displacement = false;
                if (const char *disp = ini.GetValue(section, "displacement_at", nullptr))
                {
                    const std::optional<long long> value = parse_signed(disp);
                    if (*mode != scan::Mode::RipRelative || !value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    spec.displacement_at = static_cast<std::ptrdiff_t>(*value);
                    has_displacement = true;
                }
                bool has_instruction_length = false;
                if (const char *len = ini.GetValue(section, "instruction_length", nullptr))
                {
                    const std::optional<unsigned long long> value = parse_unsigned(len);
                    if (*mode != scan::Mode::RipRelative || !value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    spec.instruction_length = static_cast<std::size_t>(*value);
                    has_instruction_length = true;
                }
                // RipRelative requires both decode offsets. A silent zero default shifts the result by the instruction
                // length, which resolve_and_gate trusts. The disp32 must occupy four bytes before the instruction end,
                // with a nonnegative offset and a maximum 15-byte instruction. The rung pattern must witness those four
                // bytes. A Direct rung carries neither field.
                if (*mode == scan::Mode::RipRelative)
                {
                    if (!has_instruction_length || !has_displacement)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    if (spec.displacement_at < 0 || !scan::is_valid_rip_relative_layout(
                                                        static_cast<std::size_t>(spec.displacement_at),
                                                        spec.instruction_length
                                                    ))
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    const Result<scan::Pattern> pattern = scan::Pattern::compile(spec.pattern);
                    if (pattern &&
                        !rip_pattern_spans_displacement(*pattern, static_cast<std::size_t>(spec.displacement_at)))
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                }
                break;
            }
            case scan::Mode::RttiVtable:
            {
                if (const char *mangled = ini.GetValue(section, "mangled", nullptr))
                {
                    spec.mangled = mangled;
                }
                else
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                break;
            }
            case scan::Mode::StringXref:
            {
                if (const char *text = ini.GetValue(section, "string_text", nullptr))
                {
                    spec.string_text = text;
                }
                else
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                if (const char *encoding = ini.GetValue(section, "string_encoding", nullptr))
                {
                    const std::optional<scan::StringEncoding> value = parse_encoding(encoding);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    spec.string_encoding = *value;
                }
                if (const char *ret = ini.GetValue(section, "string_return", nullptr))
                {
                    const std::optional<scan::XrefReturn> value = parse_xref_return(ret);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    spec.string_return = *value;
                }
                if (const char *term = ini.GetValue(section, "string_require_terminator", nullptr))
                {
                    const std::optional<bool> value = parse_bool(term);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    spec.string_require_terminator = *value;
                }
                if (const char *broad = ini.GetValue(section, "string_broad_match", nullptr))
                {
                    const std::optional<bool> value = parse_bool(broad);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    spec.string_broad_match = *value;
                }
                break;
            }
            }
            return spec;
        }

        // Each accepted-key set mirrors serialize_impl. Reject every other key. Otherwise the parser ignores a
        // hand-edited value and the next save silently drops it.
        [[nodiscard]] bool manifest_header_key_is_read(std::string_view key) noexcept
        {
            return key == "schema" || key == "revision";
        }

        [[nodiscard]] bool
        record_key_is_read(std::string_view key, anchor::AnchorKind kind, BindingKind binding) noexcept
        {
            if (key == "kind" || key == "module" || key == "binding" || key == "fingerprint" ||
                key == "image_identity" || key == "winning_bytes")
            {
                return true;
            }
            // Binding sub-keys belong to the BindingKind that emits them.
            if (binding == BindingKind::PointerChain && (key == "offsets" || key == "value_width"))
            {
                return true;
            }
            if (binding == BindingKind::MidHookRegister && (key == "read_register" || key == "xmm_index"))
            {
                return true;
            }
            if (binding == BindingKind::VmtMethod && key == "vmt_index")
            {
                return true;
            }
            // The anchor kind scopes each evidence key.
            switch (kind)
            {
            case anchor::AnchorKind::VtableIdentity:
                return key == "mangled";
            case anchor::AnchorKind::CodeOperand:
                return key == "operand_kind" || key == "operand_index" || key == "byte_width";
            case anchor::AnchorKind::StringXref:
                return key == "xref_text" || key == "xref_encoding" || key == "xref_return" ||
                       key == "xref_require_terminator" || key == "xref_broad_match";
            case anchor::AnchorKind::Manual:
                return key == "manual_value";
            case anchor::AnchorKind::RipGlobal:
                return key == "pages";
            case anchor::AnchorKind::ExportName:
                return key == "export_name";
            case anchor::AnchorKind::Quorum:
            case anchor::AnchorKind::CallArgHome:
            case anchor::AnchorKind::Unset:
                return false;
            }
            return false;
        }

        [[nodiscard]] bool rung_key_is_read(std::string_view key, scan::Mode mode) noexcept
        {
            if (key == "mode" || key == "name")
            {
                return true;
            }
            switch (mode)
            {
            case scan::Mode::Direct:
                return key == "pattern" || key == "walk_back";
            case scan::Mode::RipRelative:
                return key == "pattern" || key == "displacement_at" || key == "instruction_length";
            case scan::Mode::RttiVtable:
                return key == "mangled";
            case scan::Mode::StringXref:
                return key == "string_text" || key == "string_encoding" || key == "string_return" ||
                       key == "string_require_terminator" || key == "string_broad_match";
            }
            return false;
        }

        // Parses the persisted winning-span hex value. Every malformed shape fails closed. This prevents equality
        // between a short baseline and a live-span prefix.
        [[nodiscard]] std::optional<scan::WinningEvidence> parse_winning_bytes(std::string_view text) noexcept
        {
            if (text.empty() || (text.size() % 2) != 0 || text.size() > scan::MAX_MUTATION_WITNESS_BYTES * 2)
            {
                return std::nullopt;
            }
            const auto nibble = [](char ch, unsigned &out) noexcept -> bool
            {
                if (ch >= '0' && ch <= '9')
                {
                    out = static_cast<unsigned>(ch - '0');
                }
                else if (ch >= 'a' && ch <= 'f')
                {
                    out = static_cast<unsigned>(ch - 'a') + 10U;
                }
                else if (ch >= 'A' && ch <= 'F')
                {
                    out = static_cast<unsigned>(ch - 'A') + 10U;
                }
                else
                {
                    return false;
                }
                return true;
            };

            scan::WinningEvidence evidence{};
            for (std::size_t i = 0; i < text.size(); i += 2)
            {
                unsigned hi = 0;
                unsigned lo = 0;
                if (!nibble(text[i], hi) || !nibble(text[i + 1], lo))
                {
                    return std::nullopt;
                }
                evidence.bytes[i / 2] = static_cast<std::byte>((hi << 4) | lo);
            }
            evidence.length = static_cast<std::uint16_t>(text.size() / 2);
            return evidence;
        }

        // Parses the persisted image-identity value `<timestamp_hex>:<size_of_image_hex>:<section_digest_hex>` into a
        // scan::ImageIdentity, or nullopt when a field is absent, non-hex, over-wide, or exceeds its 32-bit bound.
        [[nodiscard]] std::optional<scan::ImageIdentity> parse_image_identity(std::string_view text) noexcept
        {
            const auto hex64 = [](std::string_view field, std::uint64_t &out) noexcept -> bool
            {
                if (field.empty() || field.size() > 16)
                {
                    return false;
                }
                std::uint64_t value = 0;
                for (const char ch : field)
                {
                    std::uint64_t digit = 0;
                    if (ch >= '0' && ch <= '9')
                    {
                        digit = static_cast<std::uint64_t>(ch - '0');
                    }
                    else if (ch >= 'a' && ch <= 'f')
                    {
                        digit = static_cast<std::uint64_t>(ch - 'a') + 10;
                    }
                    else if (ch >= 'A' && ch <= 'F')
                    {
                        digit = static_cast<std::uint64_t>(ch - 'A') + 10;
                    }
                    else
                    {
                        return false;
                    }
                    value = (value << 4) | digit;
                }
                out = value;
                return true;
            };

            const std::size_t first = text.find(':');
            if (first == std::string_view::npos)
            {
                return std::nullopt;
            }
            const std::size_t second = text.find(':', first + 1);
            if (second == std::string_view::npos)
            {
                return std::nullopt;
            }
            std::uint64_t timestamp = 0;
            std::uint64_t size_of_image = 0;
            std::uint64_t digest = 0;
            if (!hex64(text.substr(0, first), timestamp) ||
                !hex64(text.substr(first + 1, second - first - 1), size_of_image) ||
                !hex64(text.substr(second + 1), digest) || timestamp > 0xFFFFFFFFULL || size_of_image > 0xFFFFFFFFULL)
            {
                return std::nullopt;
            }
            return scan::ImageIdentity{
                .timestamp = static_cast<std::uint32_t>(timestamp),
                .size_of_image = static_cast<std::uint32_t>(size_of_image),
                .section_digest = digest,
            };
        }

        // Rejects any key in @p section that @p is_read does not recognize, as MalformedLine.
        template <class Predicate>
        [[nodiscard]] Result<void> reject_unread_keys(const ManifestIni &ini, const char *section, Predicate is_read)
        {
            ManifestIni::TNamesDepend keys;
            ini.GetAllKeys(section, keys);
            for (const ManifestIni::Entry &key : keys)
            {
                if (!is_read(std::string_view{key.pItem}))
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
            }
            return {};
        }

        [[nodiscard]] Result<SignatureRecord>
        parse_record(const ManifestIni &ini, const char *section, std::string label)
        {
            SignatureRecord record;
            record.label = std::move(label);

            const char *kind_raw = ini.GetValue(section, "kind", nullptr);
            if (kind_raw == nullptr)
            {
                return fail(ErrorCode::MalformedLine, "manifest::parse");
            }
            const std::optional<anchor::AnchorKind> kind = parse_anchor_kind(kind_raw);
            if (!kind)
            {
                return fail(ErrorCode::MalformedLine, "manifest::parse");
            }
            record.kind = *kind;

            if (const char *module = ini.GetValue(section, "module", nullptr))
            {
                record.module = module;
            }

            if (const char *binding_raw = ini.GetValue(section, "binding", nullptr))
            {
                const std::optional<BindingKind> binding_kind = parse_binding_kind(binding_raw);
                if (!binding_kind)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                record.binding.kind = *binding_kind;
            }
            // Binding keys belong to the kind that emits them. An inert key still enters the drift fingerprint but
            // never returns to the file. Reject it instead of silent data loss.
            if (const char *offsets = ini.GetValue(section, "offsets", nullptr))
            {
                if (record.binding.kind != BindingKind::PointerChain)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                std::string_view rest = offsets;
                while (!rest.empty())
                {
                    const std::size_t comma = rest.find(',');
                    const std::string_view token = trim(rest.substr(0, comma));
                    if (!token.empty())
                    {
                        const std::optional<long long> value = parse_signed(token);
                        if (!value)
                        {
                            return fail(ErrorCode::MalformedLine, "manifest::parse");
                        }
                        record.binding.offsets.push_back(static_cast<std::ptrdiff_t>(*value));
                    }
                    if (comma == std::string_view::npos)
                    {
                        break;
                    }
                    rest.remove_prefix(comma + 1);
                }
            }
            if (const char *width = ini.GetValue(section, "value_width", nullptr))
            {
                const std::optional<std::uint8_t> value = parse_u8(width);
                if (record.binding.kind != BindingKind::PointerChain || !value)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                record.binding.value_width = *value;
            }
            if (const char *reg = ini.GetValue(section, "read_register", nullptr))
            {
                const std::optional<hook::Gpr> value = parse_gpr(reg);
                if (record.binding.kind != BindingKind::MidHookRegister || !value)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                record.binding.read_register = *value;
            }
            if (const char *xmm = ini.GetValue(section, "xmm_index", nullptr))
            {
                const std::optional<std::uint8_t> value = parse_u8(xmm);
                if (record.binding.kind != BindingKind::MidHookRegister || !value)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                record.binding.xmm_index = *value;
            }
            if (const char *vmt = ini.GetValue(section, "vmt_index", nullptr))
            {
                const std::optional<unsigned long long> value = parse_unsigned(vmt);
                if (record.binding.kind != BindingKind::VmtMethod || !value)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                record.binding.vmt_index = static_cast<std::size_t>(*value);
            }

            if (const char *fingerprint = ini.GetValue(section, "fingerprint", nullptr))
            {
                const std::optional<unsigned long long> value = parse_unsigned(fingerprint);
                if (!value)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                record.expected_fingerprint = static_cast<std::uint64_t>(*value);
            }
            if (const char *image_identity = ini.GetValue(section, "image_identity", nullptr))
            {
                const std::optional<scan::ImageIdentity> parsed = parse_image_identity(image_identity);
                if (!parsed || !parsed->present())
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                record.expected_image_identity = *parsed;
            }
            if (const char *winning_bytes = ini.GetValue(section, "winning_bytes", nullptr))
            {
                const std::optional<scan::WinningEvidence> parsed = parse_winning_bytes(winning_bytes);
                if (!parsed || !parsed->present())
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                record.expected_winning_bytes = *parsed;
            }

            switch (record.kind)
            {
            case anchor::AnchorKind::VtableIdentity:
                if (const char *mangled = ini.GetValue(section, "mangled", nullptr))
                {
                    record.mangled = mangled;
                }
                break;
            case anchor::AnchorKind::CodeOperand:
                if (const char *operand_kind = ini.GetValue(section, "operand_kind", nullptr))
                {
                    const std::optional<scan::OperandKind> value = parse_operand_kind(operand_kind);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    record.operand_kind = *value;
                }
                if (const char *index = ini.GetValue(section, "operand_index", nullptr))
                {
                    const std::optional<std::uint8_t> value = parse_u8(index);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    record.operand_index = *value;
                }
                if (const char *width = ini.GetValue(section, "byte_width", nullptr))
                {
                    const std::optional<std::uint8_t> value = parse_u8(width);
                    if (!value || !DetourModKit::detail::valid_code_constant_byte_width(*value))
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    record.byte_width = *value;
                }
                break;
            case anchor::AnchorKind::StringXref:
                if (const char *text = ini.GetValue(section, "xref_text", nullptr))
                {
                    record.xref_text = text;
                }
                if (const char *encoding = ini.GetValue(section, "xref_encoding", nullptr))
                {
                    const std::optional<scan::StringEncoding> value = parse_encoding(encoding);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    record.xref_encoding = *value;
                }
                if (const char *ret = ini.GetValue(section, "xref_return", nullptr))
                {
                    const std::optional<scan::XrefReturn> value = parse_xref_return(ret);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    record.xref_return = *value;
                }
                if (const char *term = ini.GetValue(section, "xref_require_terminator", nullptr))
                {
                    const std::optional<bool> value = parse_bool(term);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    record.xref_require_terminator = *value;
                }
                if (const char *broad = ini.GetValue(section, "xref_broad_match", nullptr))
                {
                    const std::optional<bool> value = parse_bool(broad);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    record.xref_broad_match = *value;
                }
                break;
            case anchor::AnchorKind::Manual:
            {
                // Require manual_value. Without it, the parser silently overlays a trusted Address{0} over the active
                // default. An author who means zero writes `manual_value = 0` explicitly.
                const char *manual = ini.GetValue(section, "manual_value", nullptr);
                if (manual == nullptr)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                const std::optional<long long> value = parse_signed(manual);
                if (!value)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                record.manual_value = static_cast<std::int64_t>(*value);
                break;
            }
            case anchor::AnchorKind::RipGlobal:
                if (const char *pages = ini.GetValue(section, "pages", nullptr))
                {
                    const std::optional<scan::Pages> value = parse_pages(pages);
                    if (!value)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    record.pages = *value;
                }
                break;
            case anchor::AnchorKind::ExportName:
                // record.module already contains the export module. The compile() empty-evidence gate rejects an empty
                // export_name. This mirrors the optional StringXref xref_text read here.
                if (const char *export_name = ini.GetValue(section, "export_name", nullptr))
                {
                    record.export_name = export_name;
                }
                break;
            case anchor::AnchorKind::CallArgHome:
            case anchor::AnchorKind::Quorum:
            case anchor::AnchorKind::Unset:
                // CallArgHome / Quorum / Unset are unreachable here because parse_anchor_kind rejects their tokens,
                // but they are listed so the switch is exhaustive.
                break;
            }
            return record;
        }
    } // namespace

    namespace
    {
        /// Maps the public limits onto the grammar limits, so the reader and writer passes share one map.
        [[nodiscard]] detail::GrammarLimits to_grammar_limits(const ManifestLimits &limits) noexcept
        {
            return detail::GrammarLimits{
                .max_file_bytes = limits.max_file_bytes,
                .max_sections = limits.max_sections,
                .max_keys_per_section = limits.max_keys_per_section,
                .max_records = limits.max_records,
                .max_rungs_per_record = limits.max_rungs_per_record,
                .max_field_bytes = limits.max_field_bytes,
                .max_total_decoded_bytes = limits.max_total_decoded_bytes,
            };
        }

        [[nodiscard]] Result<Manifest> parse_impl(std::string_view text, const ManifestLimits &limits)
        {
            // Reject ambiguous grammar and every encoded, structural, field, and aggregate excess before the backend
            // allocates its store.
            DMK_TRY_VOID(detail::validate_manifest_grammar(text, to_grammar_limits(limits), "manifest::parse"));

            ManifestIni ini;
            ini.SetMultiKey(false);
            // Read heredoc values as multi-line data so an embedded newline stays within one literal. Otherwise, the
            // tail becomes a new key and can inject a spurious `binding =` outside the fingerprint gate. Serialization
            // enables the same mode, so the pair round-trips.
            ini.SetMultiLine(true);
            // The backend reports allocation failure as SI_NOMEM instead of an exception. Return typed OutOfMemory
            // rather than a generic MalformedLine.
            const int load_result = ini.LoadData(text.data(), text.size());
            if (load_result == SI_NOMEM)
            {
                return fail(ErrorCode::OutOfMemory, "manifest::parse");
            }
            // The backend reports data above its size ceiling as SI_FILE. This path occurs only when max_file_bytes
            // exceeds that ceiling. Keep the typed size code.
            if (load_result == SI_FILE)
            {
                return fail(ErrorCode::SizeTooLarge, "manifest::parse");
            }
            if (load_result < 0)
            {
                return fail(ErrorCode::MalformedLine, "manifest::parse");
            }

            // The `[manifest]` header both proves this is a manifest (not some unrelated INI) and pins the schema. A
            // header omission or a schema this build does not understand fails closed, so a future format is never
            // misread under the wrong grammar.
            const char *schema_raw = ini.GetValue("manifest", "schema", nullptr);
            if (schema_raw == nullptr)
            {
                return fail(ErrorCode::MissingHeader, "manifest::parse");
            }
            const std::optional<unsigned long long> schema = parse_unsigned(schema_raw);
            if (!schema || *schema != static_cast<unsigned long long>(SCHEMA_VERSION))
            {
                return fail(ErrorCode::MissingHeader, "manifest::parse");
            }

            // An absent author contract revision is zero and means unversioned. A present value must parse and fit 32
            // bits, or the file fails closed.
            std::uint32_t revision = 0;
            if (const char *revision_raw = ini.GetValue("manifest", "revision", nullptr))
            {
                const std::optional<unsigned long long> parsed_revision = parse_unsigned(revision_raw);
                if (!parsed_revision || *parsed_revision > 0xFFFFFFFFULL)
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
                revision = static_cast<std::uint32_t>(*parsed_revision);
            }
            // Reject any unread header key before record traversal. An unknown `[manifest]` key fails closed.
            DMK_TRY_VOID(reject_unread_keys(
                ini,
                "manifest",
                [](std::string_view key) { return manifest_header_key_is_read(key); }
            ));

            ManifestIni::TNamesDepend sections;
            ini.GetAllSections(sections);
            // Emit records in the file's load order, so a round-trip and a hand-diff stay stable.
            sections.sort(ManifestIni::Entry::LoadOrder());

            for (const ManifestIni::Entry &entry : sections)
            {
                const std::string_view name = entry.pItem;
                if (!name.starts_with("sig."))
                {
                    continue;
                }

                const std::optional<RungSectionName> rung = parse_rung_section_name(name);
                if (!rung)
                {
                    continue;
                }

                const std::string parent{rung->parent};
                // Each rung needs a record parent that exists. A parent that is itself a rung has no record. Reject
                // that parent instead of silent loss.
                if (ini.GetSection(parent.c_str()) == nullptr || parse_rung_section_name(parent).has_value())
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }
            }

            std::vector<SignatureRecord> records;
            for (const ManifestIni::Entry &entry : sections)
            {
                const std::string_view name = entry.pItem;
                if (!name.starts_with("sig.") || parse_rung_section_name(name).has_value())
                {
                    continue;
                }

                const std::string_view label = name.substr(4);
                if (label.empty())
                {
                    return fail(ErrorCode::MalformedLine, "manifest::parse");
                }

                Result<SignatureRecord> record = parse_record(ini, entry.pItem, std::string(label));
                if (!record)
                {
                    return std::unexpected(record.error());
                }
                // Reject any key this record's kind and binding do not read (unknown, or evidence inert for the kind).
                DMK_TRY_VOID(reject_unread_keys(
                    ini,
                    entry.pItem,
                    [&](std::string_view key) { return record_key_is_read(key, record->kind, record->binding.kind); }
                ));

                // Probe rung sub-sections by name until the first gap. This preserves order despite store enumeration.
                // Labels that contain dots still work.
                std::size_t first_missing_rung = 0;
                for (;; ++first_missing_rung)
                {
                    const std::string rung_section = std::format("{}.rung.{}", entry.pItem, first_missing_rung);
                    if (ini.GetValue(rung_section.c_str(), "mode", nullptr) == nullptr)
                    {
                        break;
                    }
                    Result<CandidateSpec> rung = parse_rung(ini, rung_section.c_str());
                    if (!rung)
                    {
                        return std::unexpected(rung.error());
                    }
                    // Reject any key this rung's mode does not read (unknown, or a decode key inert for the mode).
                    DMK_TRY_VOID(reject_unread_keys(
                        ini,
                        rung_section.c_str(),
                        [&](std::string_view key) { return rung_key_is_read(key, rung->mode); }
                    ));
                    record->ladder.push_back(std::move(*rung));
                }

                // Reject a past-gap orphan or noncanonical index such as `rung.00`. Otherwise, the parser silently
                // drops that rung-shaped section.
                for (const ManifestIni::Entry &maybe_rung_entry : sections)
                {
                    const std::string_view maybe_rung = maybe_rung_entry.pItem;
                    const std::optional<RungSectionName> rung = parse_rung_section_name(maybe_rung);
                    if (rung && rung->parent == name &&
                        (rung->index >= first_missing_rung ||
                         maybe_rung != std::format("{}.rung.{}", name, rung->index)))
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                }

                records.push_back(std::move(*record));
            }
            return Manifest{
                .header = {.schema = static_cast<std::uint32_t>(*schema), .revision = revision},
                .records = std::move(records),
            };
        }
    } // namespace

    Result<Manifest> parse(std::string_view text, const ManifestLimits &limits)
    {
        // Every materialization stage can throw std::bad_alloc. Convert it to a typed atomic failure. No partial
        // manifest escapes, and the caller's trusted generation remains untouched.
        try
        {
            return parse_impl(text, limits);
        }
        catch (const std::bad_alloc &)
        {
            return fail(ErrorCode::OutOfMemory, "manifest::parse");
        }
    }

    namespace
    {
        [[nodiscard]] Result<std::string> serialize_impl(const Manifest &manifest, const ManifestLimits &limits)
        {
            // Validate fields and enums before insertion into the bounded INI store. The builder checks every section,
            // key, and decoded value before insertion. The output writer caps encoded bytes at emission.
            if (manifest.records.size() > limits.max_records)
            {
                return fail(ErrorCode::SizeTooLarge, "manifest::serialize_checked");
            }
            const auto field_exceeds_limit = [&limits](std::string_view field) noexcept
            { return field.size() > limits.max_field_bytes; };
            std::unordered_set<std::string> seen_labels;
            for (const SignatureRecord &record : manifest.records)
            {
                if (field_exceeds_limit(record.label) || field_exceeds_limit(record.module) ||
                    field_exceeds_limit(record.mangled) || field_exceeds_limit(record.xref_text) ||
                    field_exceeds_limit(record.export_name))
                {
                    return fail(ErrorCode::SizeTooLarge, "manifest::serialize_checked");
                }
                if (!label_is_serializable(record.label) || value_is_unserializable(record.module) ||
                    value_is_unserializable(record.mangled) || value_is_unserializable(record.xref_text) ||
                    value_is_unserializable(record.export_name) || !record_policy_domains_are_valid(record) ||
                    !binding_structure_is_valid(record.binding) ||
                    !image_identity_is_valid(record.expected_image_identity) ||
                    !winning_bytes_are_valid(record.expected_winning_bytes))
                {
                    return fail(ErrorCode::InvalidArg, "manifest::serialize_checked");
                }
                if (!seen_labels.insert(to_lower(record.label)).second)
                {
                    return fail(ErrorCode::ManifestIdentityCollision, "manifest::serialize_checked");
                }
                if (record.ladder.size() > limits.max_rungs_per_record)
                {
                    return fail(ErrorCode::SizeTooLarge, "manifest::serialize_checked");
                }
                for (const CandidateSpec &spec : record.ladder)
                {
                    if (field_exceeds_limit(spec.name) || field_exceeds_limit(spec.pattern) ||
                        field_exceeds_limit(spec.mangled) || field_exceeds_limit(spec.string_text))
                    {
                        return fail(ErrorCode::SizeTooLarge, "manifest::serialize_checked");
                    }
                    if (value_is_unserializable(spec.name) || value_is_unserializable(spec.pattern) ||
                        value_is_unserializable(spec.mangled) || value_is_unserializable(spec.string_text))
                    {
                        return fail(ErrorCode::InvalidArg, "manifest::serialize_checked");
                    }
                    // save() truncates its destination first. Reject a rung that parse_rung's RipRelative gate refuses.
                    // This preserves the last-known-good file because load() cannot accept the invalid replacement.
                    if (spec.mode == scan::Mode::RipRelative)
                    {
                        const Result<scan::Pattern> pattern = scan::Pattern::compile(spec.pattern);
                        if (spec.displacement_at < 0 ||
                            !scan::is_valid_rip_relative_layout(
                                static_cast<std::size_t>(spec.displacement_at),
                                spec.instruction_length
                            ) ||
                            (pattern &&
                             !rip_pattern_spans_displacement(*pattern, static_cast<std::size_t>(spec.displacement_at))))
                        {
                            return fail(ErrorCode::InvalidArg, "manifest::serialize_checked");
                        }
                    }
                }
            }

            ManifestIni ini;
            ini.SetMultiKey(false);
            // Emit a value with an embedded newline or edge whitespace as multi-line heredoc data. parse() enables the
            // same mode and reconstructs the value verbatim. This completes newline round-trip. Without it, raw output
            // truncates an xref literal at `\n`.
            ini.SetMultiLine(true);
            ManifestIniBuilder builder{ini, limits};
            DMK_TRY_VOID(builder.begin_section());
            DMK_TRY_VOID(builder.set("manifest", "schema", std::to_string(SCHEMA_VERSION).c_str()));
            // The revision is the author's contract epoch. Omit an unversioned revision to keep its manifest clean.
            if (manifest.header.revision != 0)
            {
                DMK_TRY_VOID(builder.set("manifest", "revision", std::to_string(manifest.header.revision).c_str()));
            }

            for (const SignatureRecord &record : manifest.records)
            {
                const std::string section = std::format("sig.{}", record.label);
                const char *sec = section.c_str();
                DMK_TRY_VOID(builder.begin_section());

                DMK_TRY_VOID(builder.set(sec, "kind", std::string(anchor_kind_token(record.kind)).c_str()));
                if (!record.module.empty())
                {
                    DMK_TRY_VOID(builder.set(sec, "module", record.module.c_str()));
                }

                DMK_TRY_VOID(
                    builder.set(sec, "binding", std::string(binding_kind_to_string(record.binding.kind)).c_str())
                );
                switch (record.binding.kind)
                {
                case BindingKind::PointerChain:
                {
                    std::string offsets;
                    for (std::size_t index = 0; index < record.binding.offsets.size(); ++index)
                    {
                        const std::string token =
                            format_signed_hex(static_cast<long long>(record.binding.offsets[index]));
                        const std::size_t separator_bytes = index == 0 ? 0 : 2;
                        if (separator_bytes > limits.max_field_bytes - offsets.size() ||
                            token.size() > limits.max_field_bytes - offsets.size() - separator_bytes)
                        {
                            return fail(ErrorCode::SizeTooLarge, "manifest::serialize_checked");
                        }
                        if (index != 0)
                        {
                            offsets += ", ";
                        }
                        offsets += token;
                    }
                    DMK_TRY_VOID(builder.set(sec, "offsets", offsets.c_str()));
                    DMK_TRY_VOID(builder.set(sec, "value_width", std::to_string(record.binding.value_width).c_str()));
                    break;
                }
                case BindingKind::MidHookRegister:
                    DMK_TRY_VOID(
                        builder.set(sec, "read_register", std::string(gpr_token(record.binding.read_register)).c_str())
                    );
                    if (record.binding.xmm_index != XMM_INDEX_UNUSED)
                    {
                        DMK_TRY_VOID(builder.set(sec, "xmm_index", std::to_string(record.binding.xmm_index).c_str()));
                    }
                    break;
                case BindingKind::VmtMethod:
                    DMK_TRY_VOID(builder.set(sec, "vmt_index", std::to_string(record.binding.vmt_index).c_str()));
                    break;
                case BindingKind::Address:
                    break;
                }

                if (record.expected_fingerprint != 0)
                {
                    DMK_TRY_VOID(
                        builder.set(sec, "fingerprint", std::format("0x{:X}", record.expected_fingerprint).c_str())
                    );
                }
                // A captured image identity round-trips as `timestamp:size_of_image:section_digest` in hex. An absent
                // value keeps a schema-v1 manifest free of an image baseline.
                if (record.expected_image_identity.present())
                {
                    DMK_TRY_VOID(builder.set(
                        sec,
                        "image_identity",
                        std::format(
                            "{:X}:{:X}:{:X}",
                            record.expected_image_identity.timestamp,
                            record.expected_image_identity.size_of_image,
                            record.expected_image_identity.section_digest
                        )
                            .c_str()
                    ));
                }
                // The captured matched span round-trips as lowercase hex. An absent value is the default for every
                // non-byte rung and keeps the manifest free of a content baseline.
                if (record.expected_winning_bytes.present())
                {
                    std::string hex;
                    hex.reserve(static_cast<std::size_t>(record.expected_winning_bytes.length) * 2U);
                    for (const std::byte value : record.expected_winning_bytes.span())
                    {
                        hex += std::format("{:02x}", std::to_integer<unsigned>(value));
                    }
                    DMK_TRY_VOID(builder.set(sec, "winning_bytes", hex.c_str()));
                }

                switch (record.kind)
                {
                case anchor::AnchorKind::VtableIdentity:
                    DMK_TRY_VOID(builder.set(sec, "mangled", record.mangled.c_str()));
                    break;
                case anchor::AnchorKind::CodeOperand:
                    DMK_TRY_VOID(
                        builder.set(sec, "operand_kind", std::string(operand_kind_token(record.operand_kind)).c_str())
                    );
                    DMK_TRY_VOID(builder.set(sec, "operand_index", std::to_string(record.operand_index).c_str()));
                    DMK_TRY_VOID(builder.set(sec, "byte_width", std::to_string(record.byte_width).c_str()));
                    break;
                case anchor::AnchorKind::StringXref:
                    DMK_TRY_VOID(builder.set(sec, "xref_text", record.xref_text.c_str()));
                    DMK_TRY_VOID(
                        builder.set(sec, "xref_encoding", std::string(encoding_token(record.xref_encoding)).c_str())
                    );
                    DMK_TRY_VOID(
                        builder.set(sec, "xref_return", std::string(xref_return_token(record.xref_return)).c_str())
                    );
                    DMK_TRY_VOID(
                        builder.set(sec, "xref_require_terminator", record.xref_require_terminator ? "true" : "false")
                    );
                    DMK_TRY_VOID(builder.set(sec, "xref_broad_match", record.xref_broad_match ? "true" : "false"));
                    break;
                case anchor::AnchorKind::Manual:
                    DMK_TRY_VOID(builder.set(
                        sec,
                        "manual_value",
                        format_signed_hex(static_cast<long long>(record.manual_value)).c_str()
                    ));
                    break;
                case anchor::AnchorKind::RipGlobal:
                    if (record.pages != scan::Pages::Readable)
                    {
                        DMK_TRY_VOID(builder.set(sec, "pages", std::string(pages_token(record.pages)).c_str()));
                    }
                    break;
                case anchor::AnchorKind::ExportName:
                    // The shared `module` key above stores the export module. Only the export symbol is kind-specific.
                    DMK_TRY_VOID(builder.set(sec, "export_name", record.export_name.c_str()));
                    break;
                case anchor::AnchorKind::CallArgHome:
                case anchor::AnchorKind::Quorum:
                case anchor::AnchorKind::Unset:
                    break;
                }

                for (std::size_t index = 0; index < record.ladder.size(); ++index)
                {
                    const CandidateSpec &spec = record.ladder[index];
                    const std::string rung_section = std::format("{}.rung.{}", section, index);
                    const char *rsec = rung_section.c_str();
                    DMK_TRY_VOID(builder.begin_section());

                    DMK_TRY_VOID(builder.set(rsec, "mode", std::string(scan_mode_token(spec.mode)).c_str()));
                    if (!spec.name.empty())
                    {
                        DMK_TRY_VOID(builder.set(rsec, "name", spec.name.c_str()));
                    }
                    switch (spec.mode)
                    {
                    case scan::Mode::Direct:
                        DMK_TRY_VOID(builder.set(rsec, "pattern", spec.pattern.c_str()));
                        if (spec.walk_back != 0)
                        {
                            DMK_TRY_VOID(builder.set(
                                rsec,
                                "walk_back",
                                format_signed_hex(static_cast<long long>(spec.walk_back)).c_str()
                            ));
                        }
                        break;
                    case scan::Mode::RipRelative:
                        DMK_TRY_VOID(builder.set(rsec, "pattern", spec.pattern.c_str()));
                        DMK_TRY_VOID(builder.set(
                            rsec,
                            "displacement_at",
                            format_signed_hex(static_cast<long long>(spec.displacement_at)).c_str()
                        ));
                        DMK_TRY_VOID(
                            builder.set(rsec, "instruction_length", std::to_string(spec.instruction_length).c_str())
                        );
                        break;
                    case scan::Mode::RttiVtable:
                        DMK_TRY_VOID(builder.set(rsec, "mangled", spec.mangled.c_str()));
                        break;
                    case scan::Mode::StringXref:
                        DMK_TRY_VOID(builder.set(rsec, "string_text", spec.string_text.c_str()));
                        DMK_TRY_VOID(builder.set(
                            rsec,
                            "string_encoding",
                            std::string(encoding_token(spec.string_encoding)).c_str()
                        ));
                        DMK_TRY_VOID(builder.set(
                            rsec,
                            "string_return",
                            std::string(xref_return_token(spec.string_return)).c_str()
                        ));
                        DMK_TRY_VOID(builder.set(
                            rsec,
                            "string_require_terminator",
                            spec.string_require_terminator ? "true" : "false"
                        ));
                        DMK_TRY_VOID(
                            builder.set(rsec, "string_broad_match", spec.string_broad_match ? "true" : "false")
                        );
                        break;
                    }
                }
            }

            std::string out;
            BoundedStringWriter writer{out, limits.max_file_bytes};
            const SI_Error save_result = ini.Save(writer);
            if (writer.exceeded())
            {
                return fail(ErrorCode::SizeTooLarge, "manifest::serialize_checked");
            }
            if (save_result < 0)
            {
                return fail(ErrorCode::OutOfMemory, "manifest::serialize_checked");
            }
            // Re-run the reader's grammar over the emitted bytes so identity and frame checks cannot diverge.
            DMK_TRY_VOID(
                detail::validate_manifest_grammar(out, to_grammar_limits(limits), "manifest::serialize_checked")
            );
            return out;
        }
    } // namespace

    Result<std::string> serialize_checked(const Manifest &manifest, const ManifestLimits &limits)
    {
        // Any emit-stage allocation failure becomes a typed atomic OutOfMemory. The caller retains its current value
        // because the partial string never escapes.
        try
        {
            return serialize_impl(manifest, limits);
        }
        catch (const std::bad_alloc &)
        {
            return fail(ErrorCode::OutOfMemory, "manifest::serialize_checked");
        }
    }

    Result<Manifest> load(const std::filesystem::path &path, const ManifestLimits &limits)
    {
        // Materialize only a regular file that stays within the encoded-byte cap. The catch also covers the path
        // conversion allocation, which happens before the bounded reader receives the path.
        try
        {
            DMK_TRY(text, ::DetourModKit::detail::read_regular_file_bounded(path.wstring(), limits.max_file_bytes));
            return parse(text, limits);
        }
        catch (const std::bad_alloc &)
        {
            return fail(ErrorCode::OutOfMemory, "manifest::load");
        }
    }

    Result<void> save(const std::filesystem::path &path, const Manifest &manifest, const ManifestLimits &limits)
    {
        // Validate and encode before file open. An invalid manifest never truncates a prior readable file.
        DMK_TRY(text, serialize_checked(manifest, limits));
        if (text.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max()))
        {
            return fail(ErrorCode::SizeTooLarge, "manifest::save");
        }
        try
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!out)
            {
                return fail(ErrorCode::FileOpenFailed, "manifest::save");
            }
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            out.flush();
            if (!out)
            {
                return fail(ErrorCode::FileWriteFailed, "manifest::save");
            }
            return {};
        }
        catch (const std::bad_alloc &)
        {
            return fail(ErrorCode::OutOfMemory, "manifest::save");
        }
    }

    std::string_view binding_kind_to_string(BindingKind kind) noexcept
    {
        switch (kind)
        {
        case BindingKind::Address:
            return "address";
        case BindingKind::PointerChain:
            return "pointer_chain";
        case BindingKind::MidHookRegister:
            return "mid_hook_register";
        case BindingKind::VmtMethod:
            return "vmt_method";
        }
        return "address";
    }

} // namespace DetourModKit::manifest
