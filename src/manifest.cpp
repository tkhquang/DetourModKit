/**
 * @file manifest.cpp
 * @brief Signature manifest implementation: INI serialization, ladder compilation, and the resolve-time trust gate.
 * @details The INI parser and emitter are confined to this translation unit: manifest.hpp names no INI type, so the
 *          simpleini dependency never reaches a consumer's include path. The file schema is a versioned `[manifest]`
 *          header followed by one `[sig.<label>]` section per contract, with the candidate ladder for the byte-scanned
 *          kinds spilling into ordered `[sig.<label>.rung.<N>]` sub-sections. Uniform rung sub-sections (rather than an
 *          inline first rung) keep the parse unambiguous: a section-level key never has to serve double duty as both an
 *          anchor field and a candidate field, so round-tripping is mechanical and a hand-edit cannot be misread.
 */

#include "DetourModKit/manifest.hpp"

#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/manifest_grammar.hpp"
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
#include <type_traits>
#include <unordered_set>
#include <utility>

namespace DetourModKit::manifest
{
    namespace
    {
        // The manifest uses a case-sensitive INI store after the raw prepass has rejected exact, whitespace, and
        // ASCII-case-folded identity collisions. Canonical keys and verbatim labels then load without further folding.
        using ManifestIni = CSimpleIniCaseA;

        // The general-purpose register token table, indexed by the hook::Gpr enumerator value. It mirrors hook::Gpr one
        // for one (rsp and rip are deliberately absent from that enum, so they are absent here too), so a token maps to
        // a register and back without a second source of truth.
        constexpr std::array<std::string_view, 15> GPR_TOKENS = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8",
                                                                 "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};

        [[nodiscard]] std::string to_lower(std::string_view text)
        {
            std::string out(text);
            for (char &c : out)
            {
                // Lowercase only ASCII A-Z by hand: std::tolower with a char that is negative on a signed-char platform
                // is undefined behaviour, and manifest tokens are ASCII keywords, so a locale-aware fold is neither
                // needed nor safe here.
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

        // The whole token must consume, so a trailing-garbage value ("0x1G", "12abc") is rejected rather than silently
        // truncated to its valid prefix. Magnitude is parsed unsigned then signed at the end so a value like INT64_MIN
        // (whose magnitude does not fit a signed type) still round-trips.

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

        // Enum <-> token maps: emit lowercase tokens, accept them case-insensitively for hand-edit tolerance.

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

        // Accepts only the six serializable kinds; the composite Quorum and the resolver-less CallArgHome are in-code
        // constructs (a Quorum composes its M voting sub-anchors by pointer), so their tokens are rejected here on
        // purpose.
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

        // Format a signed offset as human-editable hex, preserving the sign so a negative field offset reads naturally.
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

        [[nodiscard]] std::unexpected<Error> fail(ErrorCode code, const char *where) noexcept
        {
            return std::unexpected(Error{code, where});
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

        struct RungSectionName
        {
            std::string_view parent;
            std::size_t index = 0;
        };

        // A rung section is always `[sig.<label>.rung.<N>]`. The parent is the anchor section, and N must be a decimal
        // index that fits size_t; malformed tails are treated as ordinary labels so a label containing ".rung." in the
        // middle is still legal.
        [[nodiscard]] std::optional<RungSectionName> parse_rung_section_name(std::string_view name) noexcept
        {
            const std::size_t pos = name.rfind(".rung.");
            if (pos == std::string_view::npos)
            {
                return std::nullopt;
            }
            const std::string_view tail = name.substr(pos + 6);
            if (tail.empty())
            {
                return std::nullopt;
            }
            std::size_t index = 0;
            for (const char c : tail)
            {
                if (c < '0' || c > '9')
                {
                    return std::nullopt;
                }
                const std::size_t digit = static_cast<std::size_t>(c - '0');
                constexpr std::size_t MAX_INDEX = std::numeric_limits<std::size_t>::max();
                if (index > (MAX_INDEX - digit) / 10U)
                {
                    return std::nullopt;
                }
                index = (index * 10U) + digit;
            }
            return RungSectionName{.parent = name.substr(0, pos), .index = index};
        }

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
                // The decode keys are mode-scoped exactly as the emitter writes them: `walk_back` is Direct-only and
                // the two RIP decode offsets are RipRelative-only. A key parsed into a field the active mode never
                // compiles or re-emits would vanish on the next save without an error, so reject it instead.
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
                // A RIP-relative repair rung resolves target = match + instruction_length + *(int32*)(match +
                // displacement_at). If either decode offset silently defaults to 0 the rung resolves to match + 0 +
                // disp32 -- an address wrong by exactly the instruction length but still in-module, which
                // resolve_and_gate would then hand out as trusted (a hook placed there splits an instruction). Both
                // offsets are therefore mandatory for RipRelative, and the disp32 must lie WITHIN an architecturally
                // valid x86-64 instruction: its four bytes have to fit before the instruction end
                // (displacement_at + 4 <= instruction_length), the offset itself cannot be negative, and the length
                // cannot exceed 15 bytes. A plain Direct rung legitimately carries neither field, so this gate is
                // scoped to RipRelative alone and never rejects a Direct rung.
                if (*mode == scan::Mode::RipRelative)
                {
                    if (!has_instruction_length || !has_displacement)
                    {
                        return fail(ErrorCode::MalformedLine, "manifest::parse");
                    }
                    if (spec.displacement_at < 0 ||
                        !scan::is_valid_rip_relative_layout(static_cast<std::size_t>(spec.displacement_at),
                                                            spec.instruction_length))
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

        // Reads one signature's anchor-level fields out of its `[sig.<label>]` section. The candidate ladder is
        // attached by the caller (it lives in sub-sections), so this handles only the fields keyed directly on the
        // section.
        [[nodiscard]] Result<SignatureRecord> parse_record(const ManifestIni &ini, const char *section,
                                                           std::string label)
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
            // Binding keys are kind-scoped exactly as the emitter writes them. An inert key (a stray `vmt_index`
            // beside `binding = address`) would populate a field the emitter never writes back, yet its value still
            // folds into the drift fingerprint, so a baseline recaptured over it could never survive its own
            // save/reload. Reject the key rather than silently dropping data.
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
                    if (!value)
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
                // A Manual record pins a literal with no backend, so an omitted manual_value would silently default to
                // 0 and overlay a trusted Address{0} over a working in-code default. Require the key: an author who
                // genuinely means zero writes `manual_value = 0` explicitly (the presence check, not the value, is what
                // distinguishes a deliberate pin from a forgotten field). Mirrors the RipRelative required-key gate.
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
                // The export symbol; the owning module was read into record.module above. An empty/absent export_name
                // is rejected by compile()'s empty-evidence gate, mirroring StringXref's optional xref_text read here.
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

        // Compiles one CandidateSpec into the scan::Candidate that backs a compiled Signature's ladder, failing closed
        // on an unset or malformed rung. Only Signature::compile calls this; adopt copies an already-resolved ladder.
        [[nodiscard]] Result<scan::Candidate> compile_rung(const CandidateSpec &spec)
        {
            switch (spec.mode)
            {
            case scan::Mode::Direct:
            {
                const Result<scan::Pattern> pattern = scan::Pattern::compile(spec.pattern);
                if (!pattern)
                {
                    return std::unexpected(pattern.error());
                }
                return scan::Candidate::direct(spec.name, *pattern, spec.walk_back);
            }
            case scan::Mode::RipRelative:
            {
                const Result<scan::Pattern> pattern = scan::Pattern::compile(spec.pattern);
                if (!pattern)
                {
                    return std::unexpected(pattern.error());
                }
                // A RipRelative rung resolves target = match + instruction_length + *(int32*)(match + displacement_at).
                // A programmatic CandidateSpec that never set the decode offsets leaves both at 0, which would resolve
                // to match + 0 + disp32 -- an in-module address wrong by the instruction length that resolve_and_gate
                // then trusts. parse_rung guards the file path; enforce the same fail-closed constraint here so the
                // programmatic Signature::compile path cannot smuggle an unset (or malformed) rung past the gate: the
                // offset is non-negative, the disp32's four bytes fit inside the instruction, and the instruction is
                // no longer than the architectural 15-byte maximum.
                if (spec.displacement_at < 0 ||
                    !scan::is_valid_rip_relative_layout(static_cast<std::size_t>(spec.displacement_at),
                                                        spec.instruction_length))
                {
                    return fail(ErrorCode::InvalidArg, "manifest::compile");
                }
                return scan::Candidate::rip_relative(spec.name, *pattern, spec.displacement_at,
                                                     spec.instruction_length);
            }
            case scan::Mode::RttiVtable:
                return scan::Candidate::rtti_vtable(spec.name, spec.mangled);
            case scan::Mode::StringXref:
            {
                const scan::StringRefQuery query{
                    .text = spec.string_text,
                    .encoding = spec.string_encoding,
                    .require_terminator = spec.string_require_terminator,
                    .return_mode = spec.string_return,
                    .broad_match = spec.string_broad_match,
                };
                return scan::Candidate::string_xref(spec.name, query);
            }
            }
            return fail(ErrorCode::BadPattern, "manifest::compile");
        }

        // A record's label becomes its `[sig.<label>]` section name, so a label that cannot round-trip as that section
        // is rejected at construction (fail closed) rather than serialized into a file parse() would then reject or
        // silently misattribute. Hazards: INI-structural characters (`[` / `]` end the section token; `\r` / `\n` split
        // the header line), an embedded NUL (the C-string API truncates the section name), a trailing space or tab
        // (SimpleIni strips leading and trailing whitespace from a section name on read, so `[sig.foo ]` reloads as
        // `sig.foo` and silently changes the lookup key), and a label matching the `.rung.<digits>` grammar -- parse()
        // always reads `sig.<parent>.rung.<N>` as a candidate sub-section, so no top-level record can carry such a
        // label. A leading blank is safe (the fixed `sig.` prefix, not the blank, starts the section name) and interior
        // whitespace is preserved, so only a trailing blank is rejected here; a trailing `\r` / `\n` is already caught
        // by the structural-character loop. The rung check runs against the full section name exactly as parse() forms
        // it, so a bare `rung.0` label (which only becomes ambiguous once the `sig.` prefix is prepended) is caught
        // too.
        [[nodiscard]] bool label_is_serializable(std::string_view label)
        {
            if (label.empty())
            {
                return false;
            }
            if (label.back() == ' ' || label.back() == '\t')
            {
                return false;
            }
            for (const char c : label)
            {
                if (c == '\0' || c == '\r' || c == '\n' || c == '[' || c == ']')
                {
                    return false;
                }
            }
            return !parse_rung_section_name(std::format("sig.{}", label)).has_value();
        }

        // The one validator every write path shares (compile, adopt, checked serialization): whether a free-text value
        // could fail to round-trip through the INI backend. Rejects four hazards:
        //   - A NUL truncates the C-string API, and '\r' is normalized to '\n' by the multi-line reader; either reloads
        //     as a different contract.
        //   - A value whose leading whitespace strips to a "<<<" prefix opens a heredoc when emitted raw and swallows
        //     the lines below it. The framing marker is reserved and cannot be carried verbatim.
        //   - A value emitted as a heredoc (it carries an embedded newline or a leading/trailing whitespace edge, and
        //     DMK never enables ParseQuotes so no single-line-quoted path can save it) whose body contains a line that
        //     equals the terminator "END_OF_TEXT". The case-sensitive store ends the value at the first body line that,
        //     after its own trailing-blank strip, matches the terminator exactly, so a trailing-blank variant truncates
        //     it; a case variant ("end_of_text") is NOT a terminator and round-trips, so it is not rejected here.
        // A value with neither newline nor whitespace edge (and no "<<<" opener) is written raw and round-trips
        // verbatim, so a terminator token inside it is harmless and the terminator scan is scoped to the heredoc path.
        [[nodiscard]] bool value_is_unserializable(std::string_view value) noexcept
        {
            if (value.find('\0') != std::string_view::npos || value.find('\r') != std::string_view::npos)
            {
                return true;
            }
            std::string_view lead = value;
            while (!lead.empty() && (lead.front() == ' ' || lead.front() == '\t'))
            {
                lead.remove_prefix(1);
            }
            if (lead.starts_with("<<<"))
            {
                return true;
            }
            const auto is_edge_whitespace = [](char c) noexcept { return c == ' ' || c == '\t'; };
            const bool takes_heredoc_path =
                value.find('\n') != std::string_view::npos ||
                (!value.empty() && (is_edge_whitespace(value.front()) || is_edge_whitespace(value.back())));
            if (!takes_heredoc_path)
            {
                return false;
            }
            constexpr std::string_view heredoc_terminator = "END_OF_TEXT";
            std::size_t line_start = 0;
            while (line_start <= value.size())
            {
                std::size_t line_end = value.find('\n', line_start);
                if (line_end == std::string_view::npos)
                {
                    line_end = value.size();
                }
                std::string_view line = value.substr(line_start, line_end - line_start);
                while (!line.empty() && (line.back() == ' ' || line.back() == '\t'))
                {
                    line.remove_suffix(1);
                }
                if (line == heredoc_terminator)
                {
                    return true;
                }
                line_start = line_end + 1;
            }
            return false;
        }

        // Structural validation is independent of what the anchor resolves. The active kind's fields must be values
        // the consumer primitive can interpret, and every inert field must keep its default: an inert edit still
        // folds into the drift fingerprint (see fold_binding) yet is never emitted, so a recaptured baseline could
        // not survive its own save/reload and would resurface as spurious, unfixable drift.
        [[nodiscard]] bool binding_structure_is_valid(const Binding &binding) noexcept
        {
            const Binding defaults{};
            const bool offsets_inert = binding.offsets.empty();
            const bool width_inert = binding.value_width == defaults.value_width;
            const bool register_inert = binding.read_register == defaults.read_register;
            const bool xmm_inert = binding.xmm_index == XMM_INDEX_UNUSED;
            const bool vmt_inert = binding.vmt_index == 0;
            switch (binding.kind)
            {
            case BindingKind::Address:
                return offsets_inert && width_inert && register_inert && xmm_inert && vmt_inert;
            case BindingKind::PointerChain:
                return !binding.offsets.empty() &&
                       (binding.value_width == 1 || binding.value_width == 2 || binding.value_width == 4 ||
                        binding.value_width == 8) &&
                       register_inert && xmm_inert && vmt_inert;
            case BindingKind::MidHookRegister:
                return offsets_inert && width_inert && vmt_inert &&
                       static_cast<std::uint8_t>(binding.read_register) <= static_cast<std::uint8_t>(hook::Gpr::R15) &&
                       (binding.xmm_index == XMM_INDEX_UNUSED || binding.xmm_index < 16);
            case BindingKind::VmtMethod:
            {
                // VmtHook bounds its captured table to 4096 methods, so no valid handle can expose a larger index.
                constexpr std::size_t MAX_VMT_BINDING_SLOTS = 4096;
                return offsets_inert && width_inert && register_inert && xmm_inert &&
                       binding.vmt_index < MAX_VMT_BINDING_SLOTS;
            }
            }
            return false;
        }

        // Whether a binding may AUTHORIZE A WRITE against a resolved typed domain, for the mutation-strict gate. A
        // MidHook needs an executable code site, VmtMethod needs a vtable, and Address / PointerChain accepts only a
        // code or data address. Scalar, Unknown, and an out-of-range kind authorize nothing.
        [[nodiscard]] constexpr bool binding_authorizes_mutation(BindingKind binding_kind,
                                                                 anchor::ResultDomain domain) noexcept
        {
            switch (binding_kind)
            {
            case BindingKind::VmtMethod:
                return domain == anchor::ResultDomain::VtableAddress;
            case BindingKind::MidHookRegister:
                return domain == anchor::ResultDomain::CodeSite;
            case BindingKind::Address:
            case BindingKind::PointerChain:
                return domain == anchor::ResultDomain::CodeSite || domain == anchor::ResultDomain::DataAddress;
            }
            return false;
        }

        // Persisted-enum range guards. A record or rung reaching adoption, compilation, or serialization with an enum
        // field cast from an out-of-range integer must fail closed, never normalize to a permissive token: an emitter
        // that wrote a valid token for a static_cast<Enum>(0xFF) would persist a contract the author never expressed,
        // and the case labels below fall through to false for exactly such a value. AnchorKind's serializable set is
        // not a contiguous range of the enum (serializable and composite kinds interleave), so it needs an explicit
        // membership test rather than a range compare.
        [[nodiscard]] constexpr bool is_serializable_anchor_kind(anchor::AnchorKind kind) noexcept
        {
            switch (kind)
            {
            case anchor::AnchorKind::VtableIdentity:
            case anchor::AnchorKind::RipGlobal:
            case anchor::AnchorKind::CodeOperand:
            case anchor::AnchorKind::StringXref:
            case anchor::AnchorKind::ExportName:
            case anchor::AnchorKind::Manual:
                return true;
            case anchor::AnchorKind::CallArgHome:
            case anchor::AnchorKind::Quorum:
            case anchor::AnchorKind::Unset:
                return false;
            }
            return false;
        }

        [[nodiscard]] constexpr bool is_valid_scan_mode(scan::Mode mode) noexcept
        {
            switch (mode)
            {
            case scan::Mode::Direct:
            case scan::Mode::RipRelative:
            case scan::Mode::RttiVtable:
            case scan::Mode::StringXref:
                return true;
            }
            return false;
        }

        [[nodiscard]] constexpr bool is_valid_operand_kind(scan::OperandKind kind) noexcept
        {
            return kind == scan::OperandKind::Immediate || kind == scan::OperandKind::MemoryDisplacement;
        }

        [[nodiscard]] constexpr bool is_valid_encoding(scan::StringEncoding encoding) noexcept
        {
            return encoding == scan::StringEncoding::Utf8 || encoding == scan::StringEncoding::Utf16le;
        }

        [[nodiscard]] constexpr bool is_valid_xref_return(scan::XrefReturn mode) noexcept
        {
            switch (mode)
            {
            case scan::XrefReturn::ReferencingInstruction:
            case scan::XrefReturn::EnclosingFunction:
            case scan::XrefReturn::StringPointerSlot:
                return true;
            }
            return false;
        }

        [[nodiscard]] constexpr bool is_valid_pages(scan::Pages pages) noexcept
        {
            return pages == scan::Pages::Readable || pages == scan::Pages::Executable;
        }

        [[nodiscard]] constexpr bool is_valid_binding_kind(BindingKind kind) noexcept
        {
            switch (kind)
            {
            case BindingKind::Address:
            case BindingKind::PointerChain:
            case BindingKind::MidHookRegister:
            case BindingKind::VmtMethod:
                return true;
            }
            return false;
        }

        // Whether every persisted enum on a record (and each of its rungs) is a named enumerator. The kind must be one
        // of the six serializable anchor kinds; the remaining enum fields must each be in range whether or not the
        // active kind reads them, because an inert-but-garbage field would still emit a permissive token on
        // serialization.
        [[nodiscard]] bool record_enums_in_range(const SignatureRecord &record) noexcept
        {
            if (!is_serializable_anchor_kind(record.kind) || !is_valid_operand_kind(record.operand_kind) ||
                !is_valid_encoding(record.xref_encoding) || !is_valid_xref_return(record.xref_return) ||
                !is_valid_pages(record.pages) || !is_valid_binding_kind(record.binding.kind))
            {
                return false;
            }
            for (const CandidateSpec &spec : record.ladder)
            {
                if (!is_valid_scan_mode(spec.mode) || !is_valid_encoding(spec.string_encoding) ||
                    !is_valid_xref_return(spec.string_return))
                {
                    return false;
                }
            }
            return true;
        }

        // FNV-1a folding used to extend anchor_fingerprint with the Binding contract. The Binding lives on the
        // SignatureRecord, not on the borrowed anchor::Anchor view that anchor_fingerprint hashes, so a register /
        // offset / value-width / vtable-slot edit would otherwise be invisible to the drift gate. These fold with the
        // same endianness-independent, length-prefixed discipline anchor.cpp uses (integers least-significant-byte
        // first) so the extended fingerprint stays stable across runs and builds. Kept local to this TU: anchor.cpp's
        // FNV primitives are private to its own module.
        inline constexpr std::uint64_t FNV1A64_PRIME = 1099511628211ULL;

        [[nodiscard]] std::uint64_t fnv1a_fold_byte(std::uint64_t hash, std::uint8_t value) noexcept
        {
            return (hash ^ value) * FNV1A64_PRIME;
        }

        template <typename T> [[nodiscard]] std::uint64_t fnv1a_fold_int(std::uint64_t hash, T value) noexcept
        {
            auto bits = static_cast<std::uint64_t>(static_cast<std::make_unsigned_t<T>>(value));
            for (std::size_t i = 0; i < sizeof(T); ++i)
            {
                hash = fnv1a_fold_byte(hash, static_cast<std::uint8_t>(bits & 0xFFu));
                bits >>= 8;
            }
            return hash;
        }

        // Length-prefixed so "ab" and "a" + "b" cannot collide across two folded fields.
        [[nodiscard]] std::uint64_t fnv1a_fold_string(std::uint64_t hash, std::string_view text) noexcept
        {
            hash = fnv1a_fold_int(hash, static_cast<std::uint64_t>(text.size()));
            for (const char c : text)
            {
                hash = fnv1a_fold_byte(hash, static_cast<std::uint8_t>(c));
            }
            return hash;
        }

        // Continues an existing fingerprint chain with the Binding's contract fields. Every field is folded
        // unconditionally -- not just the ones the active BindingKind reads -- so ANY edit to the binding data, up to
        // and including a change of BindingKind, registers as drift; over-reporting a change to an inert field is the
        // safe, fail-closed direction. offsets is length-prefixed so [0x10] and [0x10, 0x00] cannot collide.
        [[nodiscard]] std::uint64_t fold_binding(std::uint64_t hash, const Binding &binding) noexcept
        {
            hash = fnv1a_fold_byte(hash, static_cast<std::uint8_t>(binding.kind));
            hash = fnv1a_fold_int(hash, static_cast<std::uint64_t>(binding.offsets.size()));
            for (const std::ptrdiff_t offset : binding.offsets)
            {
                hash = fnv1a_fold_int(hash, static_cast<std::int64_t>(offset));
            }
            hash = fnv1a_fold_byte(hash, binding.value_width);
            hash = fnv1a_fold_byte(hash, static_cast<std::uint8_t>(binding.read_register));
            hash = fnv1a_fold_byte(hash, binding.xmm_index);
            return fnv1a_fold_int(hash, static_cast<std::uint64_t>(binding.vmt_index));
        }
    } // namespace

    Signature::Signature(SignatureRecord record, std::vector<scan::Candidate> ladder) noexcept
        : m_record(std::move(record)), m_ladder(std::move(ladder))
    {
    }

    anchor::Anchor Signature::make_anchor() const noexcept
    {
        // Rebuild a borrowed anchor view over this object's owned storage. It is a set of view/POD assignments only, so
        // it never allocates; the returned Anchor's label/mangled/xref_text string_views alias m_record's strings and
        // its site span aliases m_ladder, all valid for the duration of the resolve/fingerprint call it feeds.
        anchor::Anchor anchor{};
        anchor.label = m_record.label;
        anchor.kind = m_record.kind;
        anchor.mangled = m_record.mangled;
        anchor.site = m_ladder;
        anchor.operand_kind = m_record.operand_kind;
        anchor.operand_index = m_record.operand_index;
        anchor.byte_width = m_record.byte_width;
        anchor.pages = m_record.pages;
        anchor.xref_text = m_record.xref_text;
        anchor.xref_encoding = m_record.xref_encoding;
        anchor.xref_return = m_record.xref_return;
        anchor.xref_require_terminator = m_record.xref_require_terminator;
        anchor.xref_broad_match = m_record.xref_broad_match;
        // ExportName evidence: the export symbol plus the owning module (the shared module field, which resolve() also
        // uses to scope the walk). anchor_fingerprint folds export_module only for ExportName evidence;
        // current_fingerprint folds record.module for every kind.
        anchor.export_module = m_record.module;
        anchor.export_name = m_record.export_name;
        anchor.manual_value = m_record.manual_value;
        // Thread the post-resolve validator onto the borrowed view so a compiled (file-loaded or adopted) signature can
        // assert a domain invariant, exactly as an in-code Anchor can. Without these the manifest path could never
        // reach a validator, silently trusting whatever raw address the backend returned.
        anchor.validator = m_record.validator;
        anchor.validator_context = m_record.validator_context;
        anchor.validate_manual = m_record.validate_manual;
        anchor.require_validator = m_record.require_validator;
        return anchor;
    }

    Result<Signature> Signature::compile(SignatureRecord record)
    {
        // The composite and unset kinds have no flat record form, and any persisted enum cast from an out-of-range
        // integer must fail closed rather than compile into a Signature whose emitter would later normalize the garbage
        // to a valid token. A mod using Quorum / CallArgHome keeps them as in-code anchors gated via evaluate_gate();
        // an Unset kind resolving to a trusted zero is exactly the fail-open this rejects.
        if (!record_enums_in_range(record))
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }

        // A label that cannot round-trip as a `[sig.<label>]` section (a structural INI character, or the reserved
        // `.rung.<digits>` grammar) fails closed here rather than compiling into a Signature that the checked encoder
        // cannot faithfully persist.
        if (!label_is_serializable(record.label))
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }

        if (value_is_unserializable(record.module) || value_is_unserializable(record.mangled) ||
            value_is_unserializable(record.xref_text) || value_is_unserializable(record.export_name))
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }
        for (const CandidateSpec &rung : record.ladder)
        {
            if (value_is_unserializable(rung.name) || value_is_unserializable(rung.pattern) ||
                value_is_unserializable(rung.mangled) || value_is_unserializable(rung.string_text))
            {
                return fail(ErrorCode::InvalidArg, "manifest::compile");
            }
        }

        // Each resolvable kind fails closed when its mandatory evidence is empty, so a hand-built record cannot compile
        // into a Signature that overlays a trusted zero over a working default. The ladder kinds require a non-empty
        // ladder (checked below); the string-evidence kinds require their name / literal here. Manual has no "empty"
        // evidence (any int64 is a valid pin, and the parse path already requires the key be present).
        if (record.kind == anchor::AnchorKind::VtableIdentity && record.mangled.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }
        if (record.kind == anchor::AnchorKind::StringXref && record.xref_text.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }
        // An ExportName with no export symbol has no evidence to resolve; the owning module may be empty (an empty
        // module resolves the export within the fallback scope, e.g. a host-exe export), so only the name is mandatory.
        if (record.kind == anchor::AnchorKind::ExportName && record.export_name.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }

        // Reject bindings the corresponding consumer primitive could never interpret safely.
        if (!binding_structure_is_valid(record.binding))
        {
            return fail(ErrorCode::InvalidArg, "manifest::compile");
        }

        std::vector<scan::Candidate> ladder;
        const bool uses_ladder =
            record.kind == anchor::AnchorKind::RipGlobal || record.kind == anchor::AnchorKind::CodeOperand;
        if (uses_ladder)
        {
            if (record.ladder.empty())
            {
                return fail(ErrorCode::EmptyCandidates, "manifest::compile");
            }
            ladder.reserve(record.ladder.size());
            for (const CandidateSpec &spec : record.ladder)
            {
                Result<scan::Candidate> candidate = compile_rung(spec);
                if (!candidate)
                {
                    return std::unexpected(candidate.error());
                }
                ladder.push_back(std::move(*candidate));
            }
        }
        return Signature(std::move(record), std::move(ladder));
    }

    Result<Signature> Signature::adopt(const anchor::Anchor &source)
    {
        SignatureRecord record;
        record.label = std::string(source.label);
        record.kind = source.kind;
        // ExportName carries its owning module on the anchor's export_module; every other kind leaves it empty, so this
        // maps onto the shared record.module field without a per-kind branch (an empty export_module stays empty here).
        record.module = std::string(source.export_module);
        record.export_name = std::string(source.export_name);
        record.mangled = std::string(source.mangled);
        record.operand_kind = source.operand_kind;
        record.operand_index = source.operand_index;
        record.byte_width = source.byte_width;
        record.pages = source.pages;
        record.xref_text = std::string(source.xref_text);
        record.xref_encoding = source.xref_encoding;
        record.xref_return = source.xref_return;
        record.xref_require_terminator = source.xref_require_terminator;
        record.xref_broad_match = source.xref_broad_match;
        record.manual_value = source.manual_value;
        // Preserve the source anchor's post-resolve validator across adoption. Dropping it would silently downgrade a
        // validated in-code anchor into an unchecked one once it became a Signature -- a fail-open regression.
        record.validator = source.validator;
        record.validator_context = source.validator_context;
        record.validate_manual = source.validate_manual;
        record.require_validator = source.require_validator;

        // Reject the composite / unset kinds and any persisted enum cast from an out-of-range integer through the
        // same validator compile and checked serialization run, so an adopted signature never carries a value the
        // emitter would normalize to a permissive token. The adopted binding is default-constructed and the ladder
        // text stays empty, so those arms hold trivially.
        if (!record_enums_in_range(record))
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if (!label_is_serializable(record.label) || value_is_unserializable(record.module) ||
            value_is_unserializable(record.mangled) || value_is_unserializable(record.xref_text) ||
            value_is_unserializable(record.export_name))
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if ((record.kind == anchor::AnchorKind::RipGlobal || record.kind == anchor::AnchorKind::CodeOperand) &&
            source.site.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if (record.kind == anchor::AnchorKind::VtableIdentity && record.mangled.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if (record.kind == anchor::AnchorKind::StringXref && record.xref_text.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }
        if (record.kind == anchor::AnchorKind::ExportName && record.export_name.empty())
        {
            return fail(ErrorCode::InvalidArg, "manifest::adopt");
        }

        // An adopted signature carries no captured baseline (an in-code default has no persisted fingerprint), so its
        // record.ladder text stays empty (a compiled Pattern cannot be turned back into source AOB) and the resolved
        // anchor view is fed from the copied site candidates below.
        std::vector<scan::Candidate> ladder(source.site.begin(), source.site.end());
        return Signature(std::move(record), std::move(ladder));
    }

    anchor::ResolvedAnchor Signature::resolve(Region fallback_scope) const
    {
        const Region effective = m_record.module.empty() ? fallback_scope : Region::module_named(m_record.module);
        return anchor::resolve(make_anchor(), effective);
    }

    Region Signature::scope() const noexcept
    {
        return m_record.module.empty() ? Region::host() : Region::module_named(m_record.module);
    }

    std::uint64_t Signature::current_fingerprint() const noexcept
    {
        // anchor_fingerprint covers the "locate" evidence (pattern bytes, mangled name, xref literal). Extend it with
        // the Binding -- the "read it there" contract (register / offset chain / value width / vtable slot) -- so a
        // binding-only repair is caught by the drift gate too. The anchor view make_anchor() builds carries no binding,
        // so without this fold a rcx -> rax register churn or a +0x1C8 -> +0x1D0 offset move would leave the
        // fingerprint unchanged and slip past the gate unverified. Fold the record label and module in last
        // (anchor_fingerprint deliberately excludes the label, and folds the module only as ExportName evidence) so
        // the drift baseline is label-specific and scope-sensitive for every kind: resolve() scopes its walk by
        // record.module regardless of kind, so a retargeted module is a signature change the baseline must catch as
        // drift, and a record whose evidence was copied under a different label carries a different fingerprint -- a
        // second line of defence behind the collision prepass.
        std::uint64_t hash = fold_binding(anchor::anchor_fingerprint(make_anchor()), m_record.binding);
        hash = fnv1a_fold_string(hash, m_record.label);
        return fnv1a_fold_string(hash, m_record.module);
    }

    FingerprintState Signature::fingerprint_state() const noexcept
    {
        if (m_record.expected_fingerprint == 0)
        {
            return FingerprintState::Unset;
        }
        return current_fingerprint() == m_record.expected_fingerprint ? FingerprintState::Match
                                                                      : FingerprintState::Drifted;
    }

    void Signature::recapture_fingerprint() noexcept
    {
        m_record.expected_fingerprint = current_fingerprint();
    }

    std::string_view Signature::label() const noexcept
    {
        return m_record.label;
    }

    anchor::AnchorKind Signature::kind() const noexcept
    {
        return m_record.kind;
    }

    const Binding &Signature::binding() const noexcept
    {
        return m_record.binding;
    }

    const SignatureRecord &Signature::record() const noexcept
    {
        return m_record;
    }

    namespace
    {
        [[nodiscard]] Result<Manifest> parse_impl(std::string_view text, const ManifestLimits &limits)
        {
            // Reject ambiguous grammar and every encoded, structural, field, and aggregate excess before the backend
            // allocates its store.
            DMK_TRY_VOID(detail::validate_manifest_grammar(
                text, detail::GrammarLimits{.max_file_bytes = limits.max_file_bytes,
                                            .max_sections = limits.max_sections,
                                            .max_keys_per_section = limits.max_keys_per_section,
                                            .max_records = limits.max_records,
                                            .max_rungs_per_record = limits.max_rungs_per_record,
                                            .max_field_bytes = limits.max_field_bytes,
                                            .max_total_decoded_bytes = limits.max_total_decoded_bytes},
                "manifest::parse"));

            ManifestIni ini;
            ini.SetMultiKey(false);
            // Read values as multi-line (heredoc) data so a literal carrying an embedded '\n' / '\r' -- routine in log
            // and format strings a StringXref anchors on -- is reassembled whole. Without this, SimpleIni ends the
            // value at the first newline and re-reads the tail as a new key: the literal truncates and an
            // attacker-shaped tail could even inject a spurious `binding =` key the fingerprint gate cannot see.
            // Serialize enables the same mode, so the pair round-trips. See the paired SetMultiLine in
            // serialize_checked().
            ini.SetMultiLine(true);
            // The backend catches its own allocation failure and reports SI_NOMEM rather than throwing; surface that as
            // a typed OutOfMemory instead of folding every negative result into MalformedLine.
            const int load_result = ini.LoadData(text.data(), text.size());
            if (load_result == SI_NOMEM)
            {
                return fail(ErrorCode::OutOfMemory, "manifest::parse");
            }
            // The backend refuses data above its own size ceiling with SI_FILE; that is a size violation (reachable
            // only when the caller's max_file_bytes exceeds the backend's ceiling), so keep the typed code.
            if (load_result == SI_FILE)
            {
                return fail(ErrorCode::SizeTooLarge, "manifest::parse");
            }
            if (load_result < 0)
            {
                return fail(ErrorCode::MalformedLine, "manifest::parse");
            }

            // The `[manifest]` header both proves this is a manifest (not some unrelated INI) and pins the schema. A
            // missing header or a schema this build does not understand fails closed, so a future format is never
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

            // The author's signature-contract revision (optional; absent is 0 = unversioned). DetourModKit does not
            // interpret it -- a consumer gates on it through revision_compatible -- but a present value must parse and
            // fit a 32-bit field, else the file is not trustworthy and fails closed.
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
                // A rung must hang off a record section that exists; a parent that is itself rung-shaped (a rung
                // nested under a rung) has no record to attach to and would otherwise be silently dropped.
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

                // Attach the candidate ladder by probing rung sub-sections in order until the first gap. Probing by
                // name (rather than filtering the enumerated section list) keeps the rungs correctly ordered regardless
                // of how the underlying store enumerated them, and works even for a label that itself contains dots.
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
                    record->ladder.push_back(std::move(*rung));
                }

                // Every rung-shaped section under this record must be one the probe actually consumed: an index at or
                // past the first gap is an orphan, and a non-canonical index spelling (a leading zero, e.g. `rung.00`
                // beside `rung.0`) is a distinct store identity for the same rung index that the probe by canonical
                // name can never read. Both would otherwise be silently dropped.
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
            return Manifest{.header = {.schema = static_cast<std::uint32_t>(*schema), .revision = revision},
                            .records = std::move(records)};
        }
    } // namespace

    Result<Manifest> parse(std::string_view text, const ManifestLimits &limits)
    {
        // Every materialization stage below (the prepass sets, the backend store, the record and ladder vectors) can
        // throw std::bad_alloc under true memory pressure. Convert it to a typed, atomic failure: the local result is
        // discarded on the throw, so no partial manifest is published and a caller's previously trusted generation is
        // untouched.
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
            // Validate fields and enums before populating the bounded INI store. The builder checks every section, key,
            // and decoded value before insertion, and the output writer caps encoded bytes while they are emitted.
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
                    value_is_unserializable(record.export_name) || !record_enums_in_range(record) ||
                    !binding_structure_is_valid(record.binding))
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
                    // parse_rung refuses a RipRelative rung whose disp32 window falls outside an architecturally
                    // valid instruction, and the emitter below writes both decode offsets unconditionally. save()
                    // truncates its destination before writing, so encoding such a rung would replace a
                    // last-known-good file with one load() can never accept again; refuse every rung this
                    // serialization's own re-parse would refuse, for every record kind the ladder rides on.
                    if (spec.mode == scan::Mode::RipRelative &&
                        (spec.displacement_at < 0 ||
                         !scan::is_valid_rip_relative_layout(static_cast<std::size_t>(spec.displacement_at),
                                                             spec.instruction_length)))
                    {
                        return fail(ErrorCode::InvalidArg, "manifest::serialize_checked");
                    }
                }
            }

            ManifestIni ini;
            ini.SetMultiKey(false);
            // Emit any value carrying an embedded newline (or edge whitespace) as multi-line heredoc data instead of a
            // raw single line, so parse() -- which enables the same mode -- reassembles it verbatim. This is the write
            // half of the newline round-trip: without it a `\n` in an xref literal would be written raw and truncate on
            // re-parse.
            ini.SetMultiLine(true);
            ManifestIniBuilder builder{ini, limits};
            DMK_TRY_VOID(builder.begin_section());
            DMK_TRY_VOID(builder.set("manifest", "schema", std::to_string(SCHEMA_VERSION).c_str()));
            // The revision is the author's contract epoch; omit it when unversioned so an un-gated manifest stays
            // clean.
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
                    builder.set(sec, "binding", std::string(binding_kind_to_string(record.binding.kind)).c_str()));
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
                    DMK_TRY_VOID(builder.set(sec, "read_register",
                                             std::string(gpr_token(record.binding.read_register)).c_str()));
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
                        builder.set(sec, "fingerprint", std::format("0x{:X}", record.expected_fingerprint).c_str()));
                }

                switch (record.kind)
                {
                case anchor::AnchorKind::VtableIdentity:
                    DMK_TRY_VOID(builder.set(sec, "mangled", record.mangled.c_str()));
                    break;
                case anchor::AnchorKind::CodeOperand:
                    DMK_TRY_VOID(
                        builder.set(sec, "operand_kind", std::string(operand_kind_token(record.operand_kind)).c_str()));
                    DMK_TRY_VOID(builder.set(sec, "operand_index", std::to_string(record.operand_index).c_str()));
                    DMK_TRY_VOID(builder.set(sec, "byte_width", std::to_string(record.byte_width).c_str()));
                    break;
                case anchor::AnchorKind::StringXref:
                    DMK_TRY_VOID(builder.set(sec, "xref_text", record.xref_text.c_str()));
                    DMK_TRY_VOID(
                        builder.set(sec, "xref_encoding", std::string(encoding_token(record.xref_encoding)).c_str()));
                    DMK_TRY_VOID(
                        builder.set(sec, "xref_return", std::string(xref_return_token(record.xref_return)).c_str()));
                    DMK_TRY_VOID(
                        builder.set(sec, "xref_require_terminator", record.xref_require_terminator ? "true" : "false"));
                    DMK_TRY_VOID(builder.set(sec, "xref_broad_match", record.xref_broad_match ? "true" : "false"));
                    break;
                case anchor::AnchorKind::Manual:
                    DMK_TRY_VOID(builder.set(sec, "manual_value",
                                             format_signed_hex(static_cast<long long>(record.manual_value)).c_str()));
                    break;
                case anchor::AnchorKind::RipGlobal:
                    if (record.pages != scan::Pages::Readable)
                    {
                        DMK_TRY_VOID(builder.set(sec, "pages", std::string(pages_token(record.pages)).c_str()));
                    }
                    break;
                case anchor::AnchorKind::ExportName:
                    // The owning module is written above as the shared `module` key; only the export symbol is
                    // kind-specific.
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
                                rsec, "walk_back", format_signed_hex(static_cast<long long>(spec.walk_back)).c_str()));
                        }
                        break;
                    case scan::Mode::RipRelative:
                        DMK_TRY_VOID(builder.set(rsec, "pattern", spec.pattern.c_str()));
                        DMK_TRY_VOID(
                            builder.set(rsec, "displacement_at",
                                        format_signed_hex(static_cast<long long>(spec.displacement_at)).c_str()));
                        DMK_TRY_VOID(
                            builder.set(rsec, "instruction_length", std::to_string(spec.instruction_length).c_str()));
                        break;
                    case scan::Mode::RttiVtable:
                        DMK_TRY_VOID(builder.set(rsec, "mangled", spec.mangled.c_str()));
                        break;
                    case scan::Mode::StringXref:
                        DMK_TRY_VOID(builder.set(rsec, "string_text", spec.string_text.c_str()));
                        DMK_TRY_VOID(builder.set(rsec, "string_encoding",
                                                 std::string(encoding_token(spec.string_encoding)).c_str()));
                        DMK_TRY_VOID(builder.set(rsec, "string_return",
                                                 std::string(xref_return_token(spec.string_return)).c_str()));
                        DMK_TRY_VOID(builder.set(rsec, "string_require_terminator",
                                                 spec.string_require_terminator ? "true" : "false"));
                        DMK_TRY_VOID(
                            builder.set(rsec, "string_broad_match", spec.string_broad_match ? "true" : "false"));
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
            // Re-run the reader's grammar over the emitted bytes so identity and framing checks cannot diverge.
            DMK_TRY_VOID(detail::validate_manifest_grammar(
                out, detail::GrammarLimits{.max_file_bytes = limits.max_file_bytes,
                                           .max_sections = limits.max_sections,
                                           .max_keys_per_section = limits.max_keys_per_section,
                                           .max_records = limits.max_records,
                                           .max_rungs_per_record = limits.max_rungs_per_record,
                                           .max_field_bytes = limits.max_field_bytes,
                                           .max_total_decoded_bytes = limits.max_total_decoded_bytes},
                "manifest::serialize_checked"));
            return out;
        }
    } // namespace

    Result<std::string> serialize_checked(const Manifest &manifest, const ManifestLimits &limits)
    {
        // As in parse, convert an allocation failure in any emit stage to a typed, atomic OutOfMemory: the partial
        // string is discarded, so the caller keeps whatever it already held.
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
        // Validate and encode before opening the file, so a manifest that could not round-trip never truncates an
        // existing good file to write an unreadable one.
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

    bool revision_compatible(const ManifestHeader &header, std::uint32_t build_revision) noexcept
    {
        // build_revision 0 opts out (no gating). Otherwise the file must target this build's exact contract epoch; any
        // other value means it was authored for a different in-code contract and must be safe-ignored.
        return build_revision == 0 || header.revision == build_revision;
    }

    Result<std::vector<Signature>> overlay(std::span<const anchor::Anchor> defaults,
                                           std::span<const SignatureRecord> overrides)
    {
        std::vector<Signature> merged;
        merged.reserve(defaults.size());

        for (const anchor::Anchor &def : defaults)
        {
            // Find a file override that speaks to this exact in-code label. The file overrides only what it names, so a
            // default with no matching entry keeps its in-code form.
            const SignatureRecord *override_record = nullptr;
            for (const SignatureRecord &candidate : overrides)
            {
                if (candidate.label == def.label)
                {
                    override_record = &candidate;
                    break;
                }
            }

            if (override_record != nullptr)
            {
                Result<Signature> compiled = Signature::compile(*override_record);
                if (compiled)
                {
                    merged.push_back(std::move(*compiled));
                    continue;
                }
                // A malformed override falls back to the in-code default rather than dropping the feature: an override
                // must never make things worse than not shipping the file.
                log().warning("manifest overlay: override '{}' failed to compile ({}); keeping in-code default",
                              def.label, compiled.error().message());
            }

            Result<Signature> adopted = Signature::adopt(def);
            if (adopted)
            {
                merged.push_back(std::move(*adopted));
            }
            else
            {
                // A Quorum / CallArgHome default cannot be flattened into a Signature; it stays an in-code concern
                // gated through anchor::evaluate_gate, so it is skipped here rather than silently mis-adopted.
                log().warning("manifest overlay: default '{}' is not a serializable anchor kind; gate it in code",
                              def.label);
            }
        }
        return merged;
    }

    const GatedSignature *GateResult::find(std::string_view label) const noexcept
    {
        for (const GatedSignature &entry : trusted)
        {
            if (entry.label == label)
            {
                return &entry;
            }
        }
        return nullptr;
    }

    GateResult resolve_and_gate(std::span<const Signature> signatures, const GatePolicy &policy, Region scope)
    {
        GateResult result;

        // Resolve every signature first, then summarize: assess_quality needs the whole report, and a signature's
        // fingerprint verdict is independent of the resolve outcome.
        std::vector<anchor::ResolvedAnchor> report;
        report.reserve(signatures.size());
        for (const Signature &signature : signatures)
        {
            report.push_back(signature.resolve(scope));
        }
        result.quality = anchor::assess_quality(report);

        // The fingerprint state of each provisionally-trusted signature, kept parallel to result.trusted so a
        // whole-manifest floor demotion below can report the true drift state rather than guessing it.
        std::vector<FingerprintState> trusted_fingerprints;
        trusted_fingerprints.reserve(signatures.size());

        for (std::size_t index = 0; index < signatures.size(); ++index)
        {
            const Signature &signature = signatures[index];
            const anchor::ResolvedAnchor &resolved = report[index];
            const FingerprintState fingerprint = signature.fingerprint_state();

            // A non-unique or missed locate is never trusted: acting on an un-resolved address is the corruption this
            // gate exists to prevent.
            if (resolved.status != anchor::AnchorStatus::Resolved)
            {
                result.rejected.push_back(RejectedSignature{
                    .label = signature.label(), .status = resolved.status, .fingerprint = fingerprint});
                continue;
            }
            // A drifted fingerprint means the signature's declared definition was edited without re-capturing the
            // baseline, so the edited binding is unverified and must not be trusted even though something resolved at
            // that address.
            if (policy.reject_on_fingerprint_drift && fingerprint == FingerprintState::Drifted)
            {
                result.rejected.push_back(RejectedSignature{.label = signature.label(),
                                                            .status = anchor::AnchorStatus::Resolved,
                                                            .fingerprint = FingerprintState::Drifted});
                continue;
            }
            if (policy.reject_unset_fingerprint && fingerprint == FingerprintState::Unset)
            {
                result.rejected.push_back(RejectedSignature{.label = signature.label(),
                                                            .status = anchor::AnchorStatus::Resolved,
                                                            .fingerprint = FingerprintState::Unset});
                continue;
            }
            // mutation_strict: a signature is trusted to AUTHORIZE A WRITE only when its binding can safely mutate what
            // the anchor resolved. A Manual pin carries no live evidence and cannot self-heal, so it never authorizes a
            // mutation; and the binding kind must match the resolved typed domain (a MidHook needs a code site, a
            // VmtMethod a vtable, an Address / PointerChain a real address -- never a Scalar constant). A read-only
            // consumer leaves this policy off and keeps a Manual or a value-only binding.
            if (policy.require_mutation_safe_binding &&
                (resolved.kind == anchor::AnchorKind::Manual ||
                 !binding_authorizes_mutation(signature.binding().kind, resolved.domain)))
            {
                result.rejected.push_back(RejectedSignature{
                    .label = signature.label(), .status = anchor::AnchorStatus::Resolved, .fingerprint = fingerprint});
                continue;
            }

            result.trusted.push_back(GatedSignature{.label = signature.label(),
                                                    .kind = signature.kind(),
                                                    .address = Address{static_cast<std::uintptr_t>(resolved.value)},
                                                    .binding = &signature.binding()});
            trusted_fingerprints.push_back(fingerprint);
        }

        // Whole-manifest health floor: if too small a fraction of the manifest is trustworthy, none of it is. The guard
        // `!(floor >= 0)` folds a negative or NaN floor to "no floor", matching the anchor gate's strict-default
        // handling of a nonsensical threshold.
        double floor = policy.min_resolved_fraction;
        if (!(floor >= 0.0))
        {
            floor = 0.0;
        }
        if (floor > 1.0)
        {
            floor = 1.0;
        }
        if (!signatures.empty() && floor > 0.0)
        {
            const double fraction = static_cast<double>(result.trusted.size()) / static_cast<double>(signatures.size());
            if (fraction < floor)
            {
                for (std::size_t index = 0; index < result.trusted.size(); ++index)
                {
                    result.rejected.push_back(RejectedSignature{.label = result.trusted[index].label,
                                                                .status = anchor::AnchorStatus::Resolved,
                                                                .fingerprint = trusted_fingerprints[index]});
                }
                result.trusted.clear();
            }
        }

        return result;
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

    std::string_view fingerprint_state_to_string(FingerprintState state) noexcept
    {
        switch (state)
        {
        case FingerprintState::Unset:
            return "unset";
        case FingerprintState::Match:
            return "match";
        case FingerprintState::Drifted:
            return "drifted";
        }
        return "unset";
    }
} // namespace DetourModKit::manifest
