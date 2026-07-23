#ifndef DETOURMODKIT_INTERNAL_MANIFEST_GRAMMAR_HPP
#define DETOURMODKIT_INTERNAL_MANIFEST_GRAMMAR_HPP

#include "DetourModKit/error.hpp"

#include <cstddef>
#include <string_view>

namespace DetourModKit::manifest::detail
{
    /**
     * @struct GrammarLimits
     * @brief The structural and byte caps the raw prepass enforces on untrusted manifest text.
     * @details Mirrors the public ManifestLimits fields that can be decided from raw bytes before the INI backend
     *          allocates its store.
     */
    struct GrammarLimits
    {
        std::size_t max_file_bytes;
        std::size_t max_sections;
        std::size_t max_keys_per_section;
        std::size_t max_records;
        std::size_t max_rungs_per_record;
        std::size_t max_field_bytes;
        std::size_t max_total_decoded_bytes;
    };

    /**
     * @brief Validates raw manifest text for identity collisions, unsafe framing, and size before the INI merge.
     * @param text The raw manifest bytes.
     * @param limits The structural and byte caps to enforce.
     * @param context Static/literal label naming the raising operation for Error::where (e.g. "manifest::parse").
     * @return Empty on success, or an Error: ManifestIdentityCollision (a section or key that folds to one already
     *         seen, whether by case, surrounding whitespace, or exact repetition), MalformedLine (a section whose
     *         `manifest` / `sig.` structural prefix is not canonical lowercase, a non-lowercase key, an empty section
     *         name, a bracket line the file never closes with `]`, a rung section with no parent label, a leading
     *         UTF-8 BOM, or an embedded NUL byte), ManifestFramingUnsafe (a `<<<` heredoc that the file never closes,
     *         or one whose terminator tag is empty), or SizeTooLarge (encoded text, a section, key, record, rung,
     *         field, or aggregate that exceeds @p limits).
     * @details The case-sensitive backend still merges exact/whitespace-equivalent identities, while the manifest
     *          contract also reserves ASCII-case-folded identities. This pass tokenizes the raw bytes before the store,
     *          rejects every ambiguous identity, and applies structural and byte limits before backend allocation. A
     *          BOM or NUL would make the backend read a different byte stream than this pass validated (the backend
     *          strips a leading BOM and stops parsing at the first NUL), so both fail closed; the checked serializer
     *          can emit neither.
     */
    [[nodiscard]] Result<void> validate_manifest_grammar(std::string_view text, const GrammarLimits &limits,
                                                         const char *context);
} // namespace DetourModKit::manifest::detail

#endif // DETOURMODKIT_INTERNAL_MANIFEST_GRAMMAR_HPP
