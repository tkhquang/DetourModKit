#ifndef DETOURMODKIT_INTERNAL_MANIFEST_RECORD_RULES_HPP
#define DETOURMODKIT_INTERNAL_MANIFEST_RECORD_RULES_HPP

/**
 * @file internal/manifest_record_rules.hpp
 * @brief Shared record validation rules for the manifest sibling TUs.
 * @details src/manifest.cpp (checked serialization) and src/manifest_overlay.cpp (Signature compile/adopt) enforce
 *          the same record, label, value, binding, and baseline rules, so each rule is stated exactly once here.
 */

#include "DetourModKit/hook.hpp"
#include "DetourModKit/manifest.hpp"

#include "internal/scan_shared.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <limits>
#include <optional>
#include <string_view>

namespace DetourModKit::manifest
{
    [[nodiscard]] inline std::unexpected<Error> fail(ErrorCode code, const char *where) noexcept
    {
        return std::unexpected(Error{code, where});
    }

    [[nodiscard]] constexpr bool
    rip_pattern_spans_displacement(const scan::Pattern &pattern, std::size_t displacement_at) noexcept
    {
        return DetourModKit::detail::min_match_suffix_length(DetourModKit::detail::pattern_buffer(pattern)) >=
               displacement_at + sizeof(std::int32_t);
    }

    struct RungSectionName
    {
        std::string_view parent;
        std::size_t index = 0;
    };

    // A rung section always uses `[sig.<label>.rung.<N>]`. Treat malformed tails as ordinary labels. A label with
    // ".rung." in the middle remains legal.
    [[nodiscard]] inline std::optional<RungSectionName> parse_rung_section_name(std::string_view name) noexcept
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
        return RungSectionName{
            .parent = name.substr(0, pos),
            .index = index,
        };
    }

    // A record label becomes its `[sig.<label>]` section name. Reject a label that cannot round-trip. Reject INI
    // structural characters and embedded NUL. Reject a blank suffix because SimpleIni strips it and changes the
    // key. Reject the reserved `.rung.<digits>` grammar. Check the full section name that parse() creates so a bare
    // `rung.0` label also fails.
    [[nodiscard]] inline bool label_is_serializable(std::string_view label)
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

    // Validates every free-text value before compile, adopt, or checked serialization. Reject embedded NUL or '\r'
    // because reload changes the contract. Reject a whitespace-prefixed "<<<" because raw output opens a heredoc.
    // Reject a heredoc body line equal to "END_OF_TEXT" because the store truncates there. Apply the terminator
    // scan only to values that use a heredoc. Raw values round-trip verbatim.
    [[nodiscard]] inline bool value_is_unserializable(std::string_view value) noexcept
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

    // Every inert field must keep its default. An inert edit enters the drift fingerprint but is never emitted.
    // A recaptured baseline therefore cannot survive its own save and reload. See fold_binding.
    [[nodiscard]] inline bool binding_structure_is_valid(const Binding &binding) noexcept
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

    // Persisted-enum range guards reject an out-of-range cast. Such an enum never becomes a permissive token that
    // the author never expressed. AnchorKind's serializable set is not contiguous, so it needs an explicit
    // membership test.
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

    // record_policy_domains_are_valid checks whether each persisted policy field belongs to its named domain.
    // Checked serialization also rejects invalid fields that the active kind ignores, so it never normalizes
    // garbage into valid syntax.
    [[nodiscard]] inline bool record_policy_domains_are_valid(const SignatureRecord &record) noexcept
    {
        if (!is_serializable_anchor_kind(record.kind) || !is_valid_operand_kind(record.operand_kind) ||
            !is_valid_encoding(record.xref_encoding) || !is_valid_xref_return(record.xref_return) ||
            !is_valid_pages(record.pages) || !is_valid_binding_kind(record.binding.kind) ||
            !DetourModKit::detail::valid_code_constant_byte_width(record.byte_width))
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

    [[nodiscard]] constexpr bool image_identity_is_absent(const scan::ImageIdentity &identity) noexcept
    {
        return identity.timestamp == 0 && identity.size_of_image == 0 && identity.section_digest == 0;
    }

    [[nodiscard]] constexpr bool image_identity_is_valid(const scan::ImageIdentity &identity) noexcept
    {
        return image_identity_is_absent(identity) || identity.present();
    }

    // A persisted content baseline is only ever a complete capture, which keeps "present in the file" and
    // "usable to authorize a mutation" the same condition.
    [[nodiscard]] constexpr bool winning_bytes_are_valid(const scan::WinningEvidence &evidence) noexcept
    {
        return !evidence.truncated && evidence.length <= scan::MAX_MUTATION_WITNESS_BYTES;
    }
} // namespace DetourModKit::manifest

#endif // DETOURMODKIT_INTERNAL_MANIFEST_RECORD_RULES_HPP
