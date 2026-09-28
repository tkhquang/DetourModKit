#ifndef DETOURMODKIT_SCAN_HPP
#define DETOURMODKIT_SCAN_HPP

/**
 * @file scan.hpp
 * @brief Pattern matching, candidate-ladder resolution, and the RIP-relative, string-xref, code-constant, and export
 *        resolvers. docs/design/resolution.md owns the mechanism.
 * @warning `[B-100]` Under the loader lock, call only Callback-safe entry points, with any Region argument built
 *          during setup. Ladder construction and resolution can allocate, scan memory, or create threads.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/defines.hpp"
#include "DetourModKit/detail/pattern_core.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/region.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace DetourModKit::scan
{
    class Pattern;
} // namespace DetourModKit::scan

namespace DetourModKit::detail
{
    /// Returns @p pattern's immutable compiled buffer for internal scan adapters.
    [[nodiscard]] constexpr const PatternBuffer &pattern_buffer(const scan::Pattern &pattern) noexcept;
} // namespace DetourModKit::detail

namespace DetourModKit::scan
{
    /**
     * @brief A value-semantic compiled AOB pattern that owns its bytes and mask inline.
     * @note Setup/control-plane only: compile(). Callback-safe: size(), the accessors, and matches_at().
     */
    class Pattern
    {
    public:
        /**
         * @brief Compiles a runtime AOB DSL string, for example "48 8B 05 ?? ?? ?? ??".
         * @return The Pattern, or BadPattern (parse status in `extra`) for a malformed, empty, or oversized @p dsl.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] static Result<Pattern> compile(std::string_view dsl)
        {
            const detail::PatternParse parsed = detail::parse_pattern(dsl);
            if (parsed.status != detail::PatternStatus::Ok)
            {
                return std::unexpected(
                    Error{ErrorCode::BadPattern, "scan::compile", 0, static_cast<std::uint32_t>(parsed.status)}
                );
            }
            return Pattern{parsed.buffer};
        }

        /** @brief Compiles an in-source AOB DSL literal at compile time. A malformed literal is a compile error. */
        [[nodiscard]] static consteval Pattern literal(std::string_view dsl)
        {
            const detail::PatternParse parsed = detail::parse_pattern(dsl);
            if (parsed.status != detail::PatternStatus::Ok)
            {
                throw "DetourModKit: scan::Pattern::literal() received a malformed AOB pattern";
            }
            return Pattern{parsed.buffer};
        }

        /// The fixed byte count, without gap bytes.
        [[nodiscard]] constexpr std::size_t size() const noexcept { return m_data.length; }

        /** @brief The `|` offset in fixed bytes, or 0 without a marker. A match result also adds skipped gap bytes. */
        [[nodiscard]] constexpr std::size_t offset() const noexcept { return m_data.offset; }

        /// The fixed bytes of all segments, concatenated without gap bytes (length == size()).
        [[nodiscard]] constexpr std::span<const std::byte> bytes() const noexcept
        {
            return std::span<const std::byte>(m_data.bytes.data(), m_data.length);
        }

        /// The per-byte match mask, parallel to bytes() (length == size()).
        [[nodiscard]] constexpr std::span<const std::byte> mask() const noexcept
        {
            return std::span<const std::byte>(m_data.mask.data(), m_data.length);
        }

        /// True when the pattern carries at least one bounded jump.
        [[nodiscard]] constexpr bool has_jumps() const noexcept { return m_data.jump_count > 0; }

        /// Number of fixed segments.
        [[nodiscard]] constexpr std::size_t segment_count() const noexcept { return m_data.jump_count + 1; }

        /// Fewest bytes any match can occupy: the fixed byte count plus every gap's minimum skip.
        [[nodiscard]] constexpr std::size_t min_match_length() const noexcept
        {
            return detail::min_match_length(m_data);
        }

        /// Most bytes any match can occupy: the fixed byte count plus every gap's maximum skip.
        [[nodiscard]] constexpr std::size_t max_match_length() const noexcept
        {
            return detail::max_match_length(m_data);
        }

        /// True when the run before the first bounded jump has a fully-known byte for the prefilter anchor.
        [[nodiscard]] constexpr bool has_anchor() const noexcept { return m_data.anchor < m_data.length; }

        /// Index of the rarest fully-known byte before the first bounded jump, valid only when has_anchor() is true.
        [[nodiscard]] constexpr std::size_t anchor_index() const noexcept { return m_data.anchor; }

        /// The anchor byte value, or a zero byte when has_anchor() is false.
        [[nodiscard]] constexpr std::byte anchor_byte() const noexcept
        {
            return has_anchor() ? m_data.bytes[m_data.anchor] : std::byte{0x00};
        }

        /**
         * @brief Tests for a match at the start of @p window. A byte agrees when (memory ^ pattern) & mask is zero.
         * @return True when the bounded search, shortest gaps first, places every segment. False also covers an
         *         exhausted per-position budget, so it is not proof of absence. A match needs min_match_length() bytes.
         * @note Callback-safe: no allocation, I/O, or lock.
         */
        [[nodiscard]] constexpr bool matches_at(std::span<const std::byte> window) const noexcept
        {
            return detail::matches_buffer_at(m_data, window);
        }

    private:
        friend constexpr const detail::PatternBuffer &detail::pattern_buffer(const Pattern &pattern) noexcept;

        // Private: every Pattern comes from a successful compile() or literal() parse.
        constexpr explicit Pattern(const detail::PatternBuffer &data) noexcept : m_data{data} {}

        detail::PatternBuffer m_data{};
    };

} // namespace DetourModKit::scan

namespace DetourModKit::detail
{
    /// Returns @p pattern's immutable compiled buffer for internal scan adapters.
    [[nodiscard]] constexpr const PatternBuffer &pattern_buffer(const scan::Pattern &pattern) noexcept
    {
        return pattern.m_data;
    }
} // namespace DetourModKit::detail

namespace DetourModKit::scan
{

    /**
     * @brief Which page-protection class a page-gated scan accepts.
     * @details Readable authority rule: a Readable scan returns @ref ErrorCode::NotAuthoritative when its scope
     *          declares no exclusions and lies inside neither one mapped image nor one reserved allocation. Outside a
     *          mapped image, a scope in one allocation that crosses more than 64 `VirtualQuery` regions is unconfined.
     *          Such a scope also covers caller copies of the query bytes that DMK cannot enumerate, so a match can be
     *          the query storage itself. DMK always excludes the query storage that it owns.
     *
     *          The remedies are a confined scope, an Executable scan, or exclusions that name every live caller copy.
     *          Proof: `ScannerTrustProof.WholeProcessReadableScanCannotAuthorizeQueryOwnedMatch`.
     */
    enum class Pages : std::uint8_t
    {
        /// Every committed readable page, a superset of Executable.
        Readable,
        /// Committed execute-readable pages only, for a pattern that must land on code.
        Executable
    };

    /** @brief Largest x86-64 instruction length, in bytes. The RIP-relative helpers reject a longer instruction. */
    inline constexpr std::size_t MAX_X86_INSTRUCTION_LENGTH = 15;

    /**
     * @brief Tests whether a disp32 at @p displacement_offset lies within @p instruction_length. A length above
     *        @ref MAX_X86_INSTRUCTION_LENGTH returns false. It checks bounds only, not the RIP-relative operand.
     * @note Callback-safe: pure constexpr arithmetic.
     */
    [[nodiscard]] constexpr bool
    is_valid_rip_relative_layout(std::size_t displacement_offset, std::size_t instruction_length) noexcept
    {
        return instruction_length <= MAX_X86_INSTRUCTION_LENGTH && displacement_offset <= instruction_length &&
               instruction_length - displacement_offset >= sizeof(std::int32_t);
    }

    /** @brief The highest SIMD verification tier the engine selects at runtime. */
    enum class SimdLevel : std::uint8_t
    {
        /// Byte-by-byte verification (no SIMD).
        Scalar,
        /// SSE2.
        Sse2,
        /// AVX2.
        Avx2,
        /// AVX-512F and AVX-512BW, only in a DMK_ENABLE_AVX512 build on an AVX-512 host.
        Avx512
    };

    /**
     * @brief Returns the static enumerator name for a SimdLevel, or "Unknown" for an out-of-range value.
     * @note Callback-safe: a pure constexpr value map.
     */
    [[nodiscard]] constexpr std::string_view to_string(SimdLevel level) noexcept
    {
        switch (level)
        {
        case SimdLevel::Scalar:
            return "Scalar";
        case SimdLevel::Sse2:
            return "Sse2";
        case SimdLevel::Avx2:
            return "Avx2";
        case SimdLevel::Avx512:
            return "Avx512";
        }
        return "Unknown";
    }

    /**
     * @brief Reports the SIMD tier that pattern matching uses, the highest that both the build and the host support.
     * @note Callback-safe: a CPU-feature read with no allocation or lock.
     */
    [[nodiscard]] SimdLevel active_simd_level() noexcept;

    /** @brief Byte encoding of an anchor string as it is stored in the image. */
    enum class StringEncoding : std::uint8_t
    {
        /** @brief The query bytes verbatim, as a char literal stores them. Ill-formed UTF-8 is searched as given. */
        Utf8,
        /** @brief UTF-16LE (wchar_t), transcoded from the UTF-8 query. Ill-formed UTF-8 returns MalformedQueryText. */
        Utf16le
    };

    /** @brief What a resolved string cross-reference returns. */
    enum class XrefReturn : std::uint8_t
    {
        /// Exact address of the instruction that loads the string.
        ReferencingInstruction,
        /** @brief Enclosing-function entry from `.pdata` (chains to the primary), else a bounded RET/INT3 back-scan. */
        EnclosingFunction,
        /**
         * @brief The global slot that a `mov [rip+slot], reg` fills shortly after the unique `lea reg, [rip+string]`.
         *        A `mov` load, a rarer shape that broad_match finds, or no such store returns StoreNotFound.
         */
        StringPointerSlot
    };

    /** @brief A string-reference query that borrows @ref text for one call. A Candidate::string_xref owns its copy. */
    struct StringRefQuery
    {
        /** @brief Literal content without quotes. An embedded NUL returns @ref ErrorCode::MalformedQueryText. */
        std::string_view text;
        /// How the image stores the literal, and therefore how @ref text is read (see @ref StringEncoding).
        StringEncoding encoding = StringEncoding::Utf8;
        /// Match a trailing NUL, so "Player" does not match the prefix of "PlayerController".
        bool require_terminator = true;
        /// Selects the exact instruction site, the enclosing-function heuristic, or the cached global pointer slot.
        XrefReturn return_mode = XrefReturn::ReferencingInstruction;
        /**
         * @brief With false, phase 2 finds only the REX.W `lea`/`mov reg, [rip+disp32]` shapes. With true, a Zydis
         *        sweep also finds rarer shapes such as `cmp [rip+d], imm`. That sweep decodes only for a displacement
         *        field whose arithmetic can reach the string. See find_string_xref() for the broad confirmation sweep.
         */
        bool broad_match = false;
    };

    /**
     * @brief Resolves a string-reference anchor inside one mapped image.
     * @param scope Module image to search, which must pass the Readable authority rule of @ref Pages.
     * @return The address that @ref StringRefQuery::return_mode selects, or an Error.
     * @details Phase 1 finds the one copy of @p query.text in readable pages, or returns @ref ErrorCode::StringNotFound
     *          or @ref ErrorCode::StringAmbiguous. Phase 2 finds the one RIP-relative reference to that copy, or
     *          returns @ref ErrorCode::NoReference or @ref ErrorCode::AmbiguousReference. An observed second copy or
     *          reference stays ambiguous in a truncated sweep. Any other truncated sweep returns
     *          @ref ErrorCode::IncompleteScan. Unencodable text returns @ref ErrorCode::MalformedQueryText, and an
     *          out-of-range encoding or return mode returns @ref ErrorCode::InvalidArg before phase 1 starts.
     * @note Phase 1 excludes the storage of @p query.text. If that buffer is the only copy in scope, the result is
     *       @ref ErrorCode::StringNotFound. Anchor on a literal that the scanned image owns.
     * @note With broad_match false, an EnclosingFunction or StringPointerSlot return confirms a single narrow hit with
     *       a broad sweep. A rarer second reference then returns @ref ErrorCode::AmbiguousReference, and a broad-only
     *       reference never becomes a hit.
     * @note Setup/control-plane only. An allocation failure in either phase throws `std::bad_alloc`, never a miss.
     */
    [[nodiscard]] Result<Address> find_string_xref(const StringRefQuery &query, Region scope = Region::host());

    /**
     * @brief Resolves a named export to its address through one module's PE Export Address Table.
     * @param export_name The exact, case-sensitive export name, for example "Sleep".
     * @param module The image that exports the name, for example @ref Region::module_named("kernel32.dll").
     * @details The walk parses the mapped IMAGE_EXPORT_DIRECTORY and never calls GetProcAddress, so it never enters the
     *          loader or runs a DllMain. A truncated or hostile export section returns an Error, unless the guard-page
     *          re-arm in `[B-20]` fails. A missing export directory, an absent or duplicate name, an ordinal-only
     *          export, an out-of-image RVA, or an empty @p export_name returns ExportNotFound. A null or invalid module
     *          image returns InvalidRange. A forwarded export returns ExportForwarded.
     * @note Setup/control-plane only by convention. It does not allocate.
     */
    [[nodiscard]] Result<Address> resolve_export(std::string_view export_name, Region module = Region::host()) noexcept;

    /** @brief Which operand field @ref read_code_constant extracts. */
    enum class OperandKind : std::uint8_t
    {
        /// An immediate operand, for example the imm of `add reg, imm`.
        Immediate,
        /// A memory operand's displacement, for example the disp of `[reg + disp]`.
        MemoryDisplacement
    };

    /** @brief The resolution strategy of a Candidate. RttiVtable and StringXref are unique-only text tiers. */
    enum class Mode : std::uint8_t
    {
        /// Scan for the Pattern, then add a fixed signed walk-back to the match.
        Direct,
        /// Scan for the Pattern, then read the RIP-relative disp32 it spans and compute the absolute target.
        RipRelative,
        /// Resolve the primary vtable of an MSVC-mangled type name through the reverse-RTTI walk.
        RttiVtable,
        /// Anchor on an immutable string literal and resolve the unique RIP-relative reference to it.
        StringXref
    };

    /** @brief The ladder order before resolution. It can change which @ref Hit wins, never the verification rules. */
    enum class CandidateOrder : std::uint8_t
    {
        /// Try candidates in the order the caller wrote them.
        AsDeclared,
        /// Try unique-only text tiers, then anchored byte patterns, then the rest, each group in declared order.
        UniqueFirst
    };

    /**
     * @brief Returns the static enumerator name for a CandidateOrder, or "Unknown" for an out-of-range value.
     * @note Callback-safe: a pure constexpr value map.
     */
    [[nodiscard]] constexpr std::string_view candidate_order_to_string(CandidateOrder order) noexcept
    {
        switch (order)
        {
        case CandidateOrder::AsDeclared:
            return "AsDeclared";
        case CandidateOrder::UniqueFirst:
            return "UniqueFirst";
        }
        return "Unknown";
    }

    /** @brief The Direct-tier payload: a compiled Pattern plus the signed walk-back applied to the match. */
    struct DirectPattern
    {
        /// The compiled pattern to scan for.
        Pattern pattern;
        /// Signed byte delta added to the match, where a negative value walks backward.
        std::ptrdiff_t walk_back{0};
    };

    /** @brief The RipRelative-tier payload. It targets `match + instruction_length + disp32`. A bad disp32 misses. */
    struct RipRelativePattern
    {
        /// The compiled pattern to scan for.
        Pattern pattern;
        /// Byte offset from the match to the signed 4-byte displacement field.
        std::ptrdiff_t displacement_at{0};
        /// Total length of the referencing instruction (the next-IP base for the disp).
        std::size_t instruction_length{0};
    };

    /** @brief The RttiVtable-tier payload: an owned mangled type name. An ambiguous name fails closed. */
    struct RttiVtable
    {
        /// The MSVC decorated type name, for example ".?AVCameraManager@@".
        std::string mangled;
    };

    /** @brief The StringXref-tier payload: owned literal and facets. A second copy or reference fails closed. */
    struct StringXref
    {
        /// The exact string content to anchor on, without quotes.
        std::string text;
        /// How the literal is stored in the image.
        StringEncoding encoding{StringEncoding::Utf8};
        /// Match a trailing NUL so a prefix of a longer literal is not matched.
        bool require_terminator{true};
        /// What the resolution returns (see @ref XrefReturn).
        XrefReturn return_mode{XrefReturn::ReferencingInstruction};
        /// Add the Zydis broad sweep (see @ref StringRefQuery::broad_match).
        bool broad_match{false};
    };

    /** @brief One ladder tier, built only by the factories. It copies its strings, so it never aliases the caller. */
    class Candidate
    {
    public:
        /// The variant payload, whose alternative order matches the Mode enumerator order.
        using Payload = std::variant<DirectPattern, RipRelativePattern, RttiVtable, StringXref>;

        /**
         * @brief A Direct byte-scan candidate: the resolved address is the match plus a fixed walk-back.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] static Candidate direct(std::string name, Pattern pattern, std::ptrdiff_t walk_back = 0)
        {
            return Candidate{std::move(name), DirectPattern{std::move(pattern), walk_back}};
        }

        /**
         * @brief A RIP-relative byte-scan candidate: the address is the target of the disp32 that the match spans.
         * @throws std::invalid_argument for an invalid layout: a negative @p displacement_at, a disp32 that ends past
         *         @p instruction_length, or a length above 15. It also throws for a pattern suffix from `|` that does
         *         not span the disp32.
         * @details The matched instruction must decode to @p instruction_length bytes, with a RIP-relative memory
         *          disp32 at @p displacement_at, or the candidate never resolves. A rel32 branch (`E8` call, `E9` jmp)
         *          has none. For a branch target, use scan() plus resolve_rip_relative(). The resolver computes the
         *          target from one immutable sweep snapshot, never from a reread after the sweep.
         * @note Setup/control-plane only. The manifest loader checks the same layout and returns an error, not a throw.
         */
        [[nodiscard]] static Candidate
        rip_relative(std::string name, Pattern pattern, std::ptrdiff_t displacement_at, std::size_t instruction_length)
        {
            if (displacement_at < 0 ||
                !is_valid_rip_relative_layout(static_cast<std::size_t>(displacement_at), instruction_length) ||
                detail::min_match_suffix_length(detail::pattern_buffer(pattern)) <
                    static_cast<std::size_t>(displacement_at) + sizeof(std::int32_t))
            {
                throw std::invalid_argument(
                    "scan::Candidate::rip_relative: the matched suffix must span a valid x86-64 RIP disp32 "
                    "(0 <= displacement_at, displacement_at + 4 <= instruction_length <= 15, and the pattern's "
                    "shortest suffix from the result marker covers displacement_at + 4 bytes)"
                );
            }
            return Candidate{
                std::move(name),
                RipRelativePattern{std::move(pattern), displacement_at, instruction_length}
            };
        }

        /**
         * @brief An RTTI-vtable candidate: resolves the primary vtable of an MSVC-mangled type name.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] static Candidate rtti_vtable(std::string name, std::string mangled)
        {
            return Candidate{std::move(name), RttiVtable{std::move(mangled)}};
        }

        /**
         * @brief A string-xref candidate with the default @ref StringXref facets.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] static Candidate string_xref(std::string name, std::string literal)
        {
            return Candidate{std::move(name), StringXref{std::move(literal)}};
        }

        /**
         * @brief A string-xref candidate with the facets of @p query. It owns a copy of @p query.text.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] static Candidate string_xref(std::string name, StringRefQuery query)
        {
            return Candidate{
                std::move(name),
                StringXref{
                    std::string{query.text},
                    query.encoding,
                    query.require_terminator,
                    query.return_mode,
                    query.broad_match
                }
            };
        }

        /// Human-readable label, copied into the winning Hit.
        [[nodiscard]] const std::string &name() const noexcept { return m_name; }

        /// The resolution strategy of this tier.
        [[nodiscard]] Mode mode() const noexcept { return static_cast<Mode>(m_payload.index()); }

        /// The full variant payload.
        [[nodiscard]] const Payload &payload() const noexcept { return m_payload; }

        /// Returns the Direct payload, or nullptr when this is not a Direct candidate.
        [[nodiscard]] const DirectPattern *as_direct() const noexcept { return std::get_if<DirectPattern>(&m_payload); }

        /// Returns the RipRelative payload, or nullptr when this is not a RipRelative candidate.
        [[nodiscard]] const RipRelativePattern *as_rip_relative() const noexcept
        {
            return std::get_if<RipRelativePattern>(&m_payload);
        }

        /// Returns the RttiVtable payload, or nullptr when this is not an RTTI-vtable candidate.
        [[nodiscard]] const RttiVtable *as_rtti_vtable() const noexcept { return std::get_if<RttiVtable>(&m_payload); }

        /// Returns the StringXref payload, or nullptr when this is not a string-xref candidate.
        [[nodiscard]] const StringXref *as_string_xref() const noexcept { return std::get_if<StringXref>(&m_payload); }

    private:
        // Private: every Candidate comes from a factory, so its name and payload stay coherent.
        Candidate(std::string name, Payload payload) : m_name{std::move(name)}, m_payload{std::move(payload)} {}

        std::string m_name;
        Payload m_payload;
    };

    // mode() casts the variant index, so the alternative order must match the Mode order.
    static_assert(std::is_same_v<
                  std::variant_alternative_t<static_cast<std::size_t>(Mode::Direct), Candidate::Payload>,
                  DirectPattern>);
    static_assert(std::is_same_v<
                  std::variant_alternative_t<static_cast<std::size_t>(Mode::RipRelative), Candidate::Payload>,
                  RipRelativePattern>);
    static_assert(std::is_same_v<
                  std::variant_alternative_t<static_cast<std::size_t>(Mode::RttiVtable), Candidate::Payload>,
                  RttiVtable>);
    static_assert(std::is_same_v<
                  std::variant_alternative_t<static_cast<std::size_t>(Mode::StringXref), Candidate::Payload>,
                  StringXref>);

    /** @brief Declares a constant encoded in machine code, so read_code_constant() can re-derive it after a patch. */
    struct CodeConstant
    {
        /// Borrowed candidate ladder that resolves to an execute-readable instruction site.
        std::span<const Candidate> site;
        /// Which operand field to read: an immediate or a memory displacement.
        OperandKind kind = OperandKind::Immediate;
        /// Index into the instruction's visible operands, as a disassembler counts them.
        std::uint8_t operand_index = 0;
        /// 0 keeps the decoded value, and 1 through 8 narrows a non-RIP constant to its low bytes and sign-extends it.
        std::uint8_t byte_width = 0;
        /// Last-known value for telemetry or a baseline, never returned in place of a live decode.
        std::int64_t nominal = 0;
        /// True when @ref nominal holds a value, so nominal == 0 does not mean "unset".
        bool has_nominal = false;
    };

    /**
     * @brief Resolves @p code_constant.site, decodes the instruction there, and returns the requested operand's value.
     * @return The sign-extended live value, or an Error. A RIP-relative memory operand returns its absolute target.
     * @details A candidate whose final site is not execute-readable is skipped, and the next candidate runs. A selected
     *          site that loses execute protection, crosses into a non-executable page, or no longer decodes returns
     *          DecodeFailed. A wrong operand kind returns UnexpectedShape, and an operand index out of range returns
     *          OperandOutOfRange. An out-of-range kind or byte_width returns @ref ErrorCode::InvalidArg first.
     * @note `[B-75]` The value decodes from a fresh snapshot after site resolution. A byte tier must still match its
     *       physical span and resolve the decoded site at that epoch, or the result is EvidenceMismatch. A wildcarded
     *       operand byte can drift, and the result is its current value.
     * @note Setup/control-plane only. Site resolution allocates.
     */
    [[nodiscard]] Result<std::int64_t>
    read_code_constant(const CodeConstant &code_constant, Region scope = Region::host());

    /**
     * @brief Ceiling on the bytes a @ref WinningEvidence carries. A longer span still resolves, but its truncated
     *        evidence never authorizes a mutation or seeds a strict baseline.
     */
    inline constexpr std::size_t MAX_MUTATION_WITNESS_BYTES = 256;

    /**
     * @brief The literal bytes at the winning match span, captured by the match and never re-read. They include the
     *        wildcard and gap bytes, so they detect a same-layout code change that @ref ImageIdentity cannot see.
     */
    struct WinningEvidence
    {
        /// The captured span in the first @ref length elements, with zero in the trailing elements.
        std::array<std::byte, MAX_MUTATION_WITNESS_BYTES> bytes{};
        /// The count of valid leading elements in @ref bytes, or 0 when nothing was captured.
        std::uint16_t length = 0;
        /** @brief True when the winning span exceeded @ref MAX_MUTATION_WITNESS_BYTES. @ref length is then 0. */
        bool truncated = false;

        /// True when a complete, internally valid winning span was captured.
        [[nodiscard]] constexpr bool present() const noexcept
        {
            return length != 0 && length <= MAX_MUTATION_WITNESS_BYTES && !truncated;
        }

        /// The captured bytes as a span, empty unless @ref present.
        [[nodiscard]] constexpr std::span<const std::byte> span() const noexcept
        {
            if (!present())
            {
                return {};
            }
            return std::span<const std::byte>{bytes.data(), length};
        }

        /** @brief Value equality. A malformed value (bad @ref length, or bytes while @ref truncated) equals nothing. */
        [[nodiscard]] constexpr bool operator==(const WinningEvidence &other) const noexcept
        {
            const bool malformed = length > MAX_MUTATION_WITNESS_BYTES || (truncated && length != 0);
            const bool other_malformed =
                other.length > MAX_MUTATION_WITNESS_BYTES || (other.truncated && other.length != 0);
            if (malformed || other_malformed)
            {
                return false;
            }
            if (length != other.length || truncated != other.truncated)
            {
                return false;
            }
            for (std::size_t i = 0; i < length; ++i)
            {
                if (bytes[i] != other.bytes[i])
                {
                    return false;
                }
            }
            return true;
        }
    };

    /** @brief A resolved address with the owned name and the mode of the candidate that produced it. */
    struct Hit
    {
        /// The resolved absolute address.
        Address address;
        /// A copy of the winning candidate's name.
        std::string winning_name;
        /// The resolution mode of the winning candidate.
        Mode winning_mode = Mode::Direct;
        /** @brief Matched-span bytes. Only a byte-pattern tier fills them, so no other tier can seed a baseline. */
        WinningEvidence evidence{};
    };

    /** @brief `[B-53]` How strictly hooked-prologue recovery, which is address-blind, confirms a recovered target. */
    enum class FallbackPolicy : std::uint8_t
    {
        /// Recovery disabled: a full direct miss stays a miss.
        Off,
        /// Recover structurally and return the address. A @ref FallbackWitness rejection only logs a warning.
        WarnOnly,
        /// Recover structurally, then require a @ref FallbackWitness to confirm the recovered address.
        RequireIdentity,
    };

    /** @brief Returns false to reject a recovered site. It has the same type as @ref anchor::AnchorValidator. */
    using FallbackValidator = bool (*)(std::int64_t value, const void *context) noexcept;

    /** @brief The FallbackPolicy witness. With a null predicate, WarnOnly recovers and RequireIdentity fails closed. */
    struct FallbackWitness
    {
        /// Predicate run on the recovered address, or nullptr for no identity check.
        FallbackValidator predicate = nullptr;
        /// Opaque pointer forwarded verbatim to @ref predicate.
        const void *context = nullptr;
    };

    /** @brief A non-owning resolution request for use within one expression. To store one, use OwnedScanRequest. */
    struct ScanRequest
    {
        /// Candidates tried in @ref order, where the first one that resolves wins.
        std::span<const Candidate> ladder;
        /// Optional non-owning label for diagnostics.
        std::string_view label{};
        /// The memory range to resolve within.
        Region scope = Region::host();
        /// Hooked-prologue recovery strictness on a full direct miss (see @ref FallbackPolicy).
        FallbackPolicy fallback_policy = FallbackPolicy::Off;
        /// The identity witness the fallback runs on a recovered site (see @ref FallbackPolicy). Unused when Off.
        FallbackWitness fallback_witness{};
        /// Fail closed on an ambiguous byte match (a second occurrence in scope). False takes the first match.
        bool require_unique = true;
        /// How the ladder is ordered before it is tried.
        CandidateOrder order = CandidateOrder::AsDeclared;
        /// Page-protection class the Direct / RipRelative byte tiers scan.
        Pages pages = Pages::Readable;
        /**
         * @brief Rejects each candidate or recovered site whose final address is off an execute-readable page. A
         *        rejected candidate is skipped, not fatal. A RIP-relative data global needs false.
         */
        bool require_executable_result = false;
        /**
         * @brief Every live caller copy of the query bytes. The byte and string-xref tiers do not count a match that
         *        intersects one. A non-empty span satisfies the Readable authority rule.
         */
        std::span<const Region> exclusions{};
    };

    /**
     * @brief Builds a borrowed ScanRequest. Clang and MSVC code analysis can flag a temporary ladder or label.
     * @note Callback-safe with an explicit Region: no allocation. The default scope query is setup/control-plane only.
     */
    [[nodiscard]] ScanRequest borrow(
        std::span<const Candidate> ladder DMK_LIFETIMEBOUND,
        std::string_view label DMK_LIFETIMEBOUND = {},
        Region scope = Region::host(),
        FallbackPolicy fallback_policy = FallbackPolicy::Off,
        FallbackWitness fallback_witness = {},
        bool require_unique = true,
        CandidateOrder order = CandidateOrder::AsDeclared,
        Pages pages = Pages::Readable
    ) noexcept;

    /**
     * @brief Builds a borrowed ScanRequest preset for a code (hook) target.
     * @details The preset sets `Pages::Executable`, `require_executable_result`, and @ref CandidateOrder::UniqueFirst.
     *          For a data, RTTI, or string target, use @ref borrow.
     * @note Callback-safe with an explicit Region: no allocation. The default scope query is setup/control-plane only.
     */
    [[nodiscard]] ScanRequest borrow_code_target(
        std::span<const Candidate> ladder DMK_LIFETIMEBOUND,
        std::string_view label DMK_LIFETIMEBOUND = {},
        Region scope = Region::host(),
        FallbackPolicy fallback_policy = FallbackPolicy::WarnOnly,
        FallbackWitness fallback_witness = {}
    ) noexcept;

    /**
     * @brief The @ref borrow_code_target preset under @ref FallbackPolicy::RequireIdentity. For no label, pass {}.
     * @note Callback-safe with an explicit Region: no allocation. The default scope query is setup/control-plane only.
     */
    [[nodiscard]] ScanRequest borrow_code_target_strict(
        std::span<const Candidate> ladder DMK_LIFETIMEBOUND,
        std::string_view label DMK_LIFETIMEBOUND,
        FallbackWitness fallback_witness,
        Region scope = Region::host()
    ) noexcept;

    /** @brief An owning resolution request for stored or deferred resolution. Stored entry points take this type. */
    struct OwnedScanRequest
    {
        /// Owned candidate ladder.
        std::vector<Candidate> ladder;
        /// Owned diagnostic label.
        std::string label;
        /// The resolution scope.
        Region scope = Region::host();
        /// Hooked-prologue recovery strictness on a full direct miss (see @ref FallbackPolicy).
        FallbackPolicy fallback_policy = FallbackPolicy::Off;
        /// The identity witness the fallback runs on a recovered site (see @ref FallbackPolicy). Unused when Off.
        FallbackWitness fallback_witness{};
        /// Fail closed on an ambiguous byte match.
        bool require_unique = true;
        /// Ladder ordering policy.
        CandidateOrder order = CandidateOrder::AsDeclared;
        /// Page-protection class the byte tiers scan (see @ref ScanRequest::pages).
        Pages pages = Pages::Readable;
        /// Whether the final resolved address must be execute-readable.
        bool require_executable_result = false;
        /// Owned copies of the caller-declared query exclusions (see @ref ScanRequest::exclusions).
        std::vector<Region> exclusions;

        /** @brief Returns a ScanRequest that views this object's storage, valid only while this object lives. */
        [[nodiscard]] ScanRequest view() const noexcept DMK_LIFETIMEBOUND
        {
            return ScanRequest{
                .ladder = ladder,
                .label = label,
                .scope = scope,
                .fallback_policy = fallback_policy,
                .fallback_witness = fallback_witness,
                .require_unique = require_unique,
                .order = order,
                .pages = pages,
                .require_executable_result = require_executable_result,
                .exclusions = exclusions,
            };
        }
    };

    /**
     * @brief Writes the index permutation that @p order implies for @p ladder into @p out.
     * @return The number of indices written, at most min(ladder.size(), out.size()).
     * @details AsDeclared and any out-of-range value yield the identity permutation.
     * @note Callback-safe: pure index math with no allocation.
     */
    [[nodiscard]] std::size_t
    order_candidates(CandidateOrder order, std::span<const Candidate> ladder, std::span<std::size_t> out) noexcept;

    /**
     * @brief Returns the Hit of the first candidate, in @ref ScanRequest::order, that resolves, or an Error.
     * @details A byte tier resolves when it matches in scope, passes the uniqueness gate when required, and yields an
     *          in-scope plausible address. A text tier resolves through its unique-only backend. After a full direct
     *          miss with a non-Off fallback_policy, the resolver rebuilds each Direct prologue as a near or far JMP.
     *          Only a unique match of the rebuilt shape resolves, regardless of require_unique. A byte tier whose own
     *          sweep was truncated (BudgetExceeded or IncompleteScan) preempts that recovery. A recovery sweep that
     *          skips a faulted region reports IncompleteScan, not a miss.
     *
     *          A text tier failure does not preempt recovery. That failure is MalformedQueryText, or NotAuthoritative
     *          or IncompleteScan from its own readable sweep. If nothing resolves, the result reports it in place of
     *          the generic miss. A scope that fails the Readable authority rule of @ref Pages refuses the request
     *          before the resolver grades any candidate. An out-of-range pages, order, fallback_policy, or StringXref
     *          encoding or return mode returns @ref ErrorCode::InvalidArg. Only an allocation failure throws.
     * @note Setup/control-plane only.
     */
    [[nodiscard]] Result<Hit> resolve(const ScanRequest &request);

    /**
     * @brief Resolves a batch of requests concurrently and returns one Result per request in input order.
     * @param max_workers Upper bound on worker threads, or 0 to select from the hardware concurrency.
     * @return The outer Result fails with OutOfMemory if the result vector cannot be allocated, and with Unknown on any
     *         other whole-batch exception. A slot holds OutOfMemory after its own allocation failure, and NoMatch after
     *         any other exception.
     * @note Setup/control-plane only: it spawns a worker pool and allocates.
     */
    [[nodiscard]] Result<std::vector<Result<Hit>>>
    resolve_batch(std::span<const ScanRequest> requests, std::size_t max_workers = 0) noexcept;

    /**
     * @brief Scans one Pattern over a known scope and returns the Nth match address.
     * @return The @p occurrence-th (1-based) match, adjusted by the `|` offset, or an Error. 0 returns NoMatch.
     * @details The sweep reads only committed pages of the @p pages class. It skips an unmapped or guard page without a
     *          host fault and still finds a match that straddles two adjacent accepted regions. Each call repeats its
     *          setup, which can query the loader for the authority check. For a cursor walk over a range that the
     *          caller proves readable, use @ref unchecked::find_pattern.
     *
     *          @ref ErrorCode::NoMatch means the sweep read the whole scope and found fewer than @p occurrence matches.
     *          @ref ErrorCode::IncompleteScan means the sweep skipped a faulted region, so the pattern can live in
     *          unread bytes. @ref ErrorCode::BudgetExceeded means a bounded-jump pattern spent its backtracking budget.
     *          Neither truncation is a miss. An out-of-range @p pages returns @ref ErrorCode::InvalidArg before the
     *          sweep starts. A Readable scan follows the Readable authority rule of @ref Pages.
     * @note Setup/control-plane only. An allocation failure while the scan is prepared returns OutOfMemory.
     */
    [[nodiscard]] Result<Address>
    scan(const Pattern &pattern, Region scope, std::size_t occurrence = 1, Pages pages = Pages::Readable) noexcept;

    /**
     * @brief The four-argument scan() that does not count a match that intersects one of @p exclusions.
     * @param exclusions The live caller copies of the query bytes, as @ref ScanRequest::exclusions describes.
     * @details DMK adds @p exclusions to its own query-storage exclusions. The combined set has 32 slots after touching
     *          spans merge. If the set cannot hold every span, the result is @ref ErrorCode::NotAuthoritative.
     * @note Setup/control-plane only.
     */
    [[nodiscard]] Result<Address> scan(
        const Pattern &pattern,
        Region scope,
        std::span<const Region> exclusions,
        std::size_t occurrence = 1,
        Pages pages = Pages::Readable
    ) noexcept;

    /// Common x86-64 opcode prefixes, the bytes before the disp32 field, for find_and_resolve_rip_relative().
    inline constexpr std::array<std::byte, 3> PREFIX_MOV_RAX_RIP = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};
    inline constexpr std::array<std::byte, 3> PREFIX_MOV_RCX_RIP = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x0D}};
    inline constexpr std::array<std::byte, 3> PREFIX_MOV_RDX_RIP = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x15}};
    inline constexpr std::array<std::byte, 3> PREFIX_MOV_RBX_RIP = {std::byte{0x48}, std::byte{0x8B}, std::byte{0x1D}};
    inline constexpr std::array<std::byte, 3> PREFIX_LEA_RAX_RIP = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x05}};
    inline constexpr std::array<std::byte, 3> PREFIX_LEA_RCX_RIP = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x0D}};
    inline constexpr std::array<std::byte, 3> PREFIX_LEA_RDX_RIP = {std::byte{0x48}, std::byte{0x8D}, std::byte{0x15}};
    inline constexpr std::array<std::byte, 1> PREFIX_CALL_REL32 = {std::byte{0xE8}};
    inline constexpr std::array<std::byte, 1> PREFIX_JMP_REL32 = {std::byte{0xE9}};

    /**
     * @brief Resolves `instruction + instruction_length + disp32` for an x86-64 RIP-relative instruction.
     * @details An invalid layout returns InvalidArg before a read. A target that is not a plausible user-mode address
     *          returns ImplausibleTarget. The `FF 15` and `FF 25` shapes return the pointer slot.
     * @note Callback-safe: a guarded read and pointer arithmetic, with no allocation.
     */
    [[nodiscard]] Result<Address>
    resolve_rip_relative(Address instruction, std::size_t displacement_offset, std::size_t instruction_length) noexcept;

    /**
     * @brief Scans @p search for @p opcode_prefix and resolves the disp32 after the first resolvable occurrence.
     * @param instruction_length Total instruction length, at most 15. The disp32 immediately follows @p opcode_prefix.
     * @details An occurrence is a decoy when its target is implausible or the first target byte is unreadable at scan
     *          time. The scan skips each decoy. After it exhausts the region, it reports the last concrete failure,
     *          for example @ref ErrorCode::ImplausibleTarget or @ref ErrorCode::UnreadableTarget. The `FF 15` and
     *          `FF 25` shapes return the pointer slot. An invalid layout returns @ref ErrorCode::InvalidArg before the
     *          sweep starts.
     * @note The prefix search reads @p search unguarded, so it must be readable. While the memory cache runs, the
     *       one-byte @ref memory::is_readable target check can allocate a cache entry. A failed allocation leaves the
     *       result unchanged.
     * @note Setup/control-plane only: the sweep cost scales with @p search.
     */
    [[nodiscard]] Result<Address> find_and_resolve_rip_relative(
        Region search,
        std::span<const std::byte> opcode_prefix,
        std::size_t instruction_length
    ) noexcept;

    /**
     * @brief Cheap heuristic: tests whether @p addr looks like the first byte of a real function body.
     * @return True when @p addr is non-null and its guarded byte is readable and not 0x00, 0xCC, 0xC2, or 0xC3.
     * @details A jump opcode (0xE9, 0xEB, or the 0xFF of `FF 25`) passes, so a prologue that a hook rewrote passes.
     * @note Callback-safe: a single guarded byte read, no allocation.
     */
    [[nodiscard]] bool is_likely_function_prologue(Address addr) noexcept;

    /**
     * @brief An ASLR-insensitive fingerprint of a loaded module's PE timestamp, image size, and section-table layout.
     * @warning This is layout identity, not content identity. It reads no section body, so code patched in place under
     *          equal headers keeps a bit-identical identity. Use @ref WinningEvidence to witness content.
     */
    struct ImageIdentity
    {
        /// PE @c IMAGE_FILE_HEADER::TimeDateStamp of the resolved image (0 when the read failed).
        std::uint32_t timestamp = 0;
        /// PE @c IMAGE_OPTIONAL_HEADER::SizeOfImage of the resolved image (0 when the read failed).
        std::uint32_t size_of_image = 0;
        /// A fold of every section header's name, RVA, virtual size, and characteristics.
        std::uint64_t section_digest = 0;

        /// True when a live image was read.
        [[nodiscard]] constexpr bool present() const noexcept { return size_of_image != 0; }

        /// A 64-bit token that folds all three fields, for a fingerprint or an equality key.
        [[nodiscard]] constexpr std::uint64_t token() const noexcept
        {
            std::uint64_t seed = section_digest;
            seed ^= static_cast<std::uint64_t>(timestamp) + 0x9E3779B97F4A7C15ULL + (seed << 6) + (seed >> 2);
            seed ^= static_cast<std::uint64_t>(size_of_image) + 0x9E3779B97F4A7C15ULL + (seed << 6) + (seed >> 2);
            return seed;
        }

        /// Value equality across all three fields.
        [[nodiscard]] constexpr bool operator==(const ImageIdentity &other) const noexcept = default;
    };

    /**
     * @brief Reads the @ref ImageIdentity of the module mapped at @p range.base. The extent comes from its PE headers.
     * @return The identity, or an absent value when @p range is empty or its PE headers do not validate completely.
     * @note Callback-safe with an explicit Region: guarded PE header reads, with no allocation or loader call. The
     *       default scope query is setup/control-plane only.
     */
    [[nodiscard]] ImageIdentity image_identity(Region range = Region::host()) noexcept;

    /**
     * @brief Flattens a resolve Result to its address, or a null Address on failure.
     * @note Callback-safe: a pure Result read.
     */
    [[nodiscard]] inline Address or_null(const Result<Hit> &result) noexcept
    {
        return result ? result->address : Address{};
    }

    /**
     * @brief Flattens a resolve Result to its address, or @p fallback on failure.
     * @note Callback-safe: a pure Result read.
     */
    [[nodiscard]] inline Address address_or(const Result<Hit> &result, Address fallback = Address{}) noexcept
    {
        return result ? result->address : fallback;
    }

    namespace unchecked
    {
        /**
         * @brief Raw single-pattern scan with no page filter. An unreadable byte in @p region faults the host.
         * @return The @p occurrence-th (1-based) match, adjusted by the `|` offset. 0, a miss, and a pattern allocation
         *         failure return nullptr.
         * @note Setup/control-plane only: each call copies @p pattern into two heap buffers, or three with bounded
         *       jumps, and restarts from `region.base`. For a pattern whose `offset()` is zero, a cursor walk passes
         *       occurrence 1 and advances `region.base` past each hit. For a nonzero offset, raise only @p occurrence.
         *       Proof: `ScannerUncheckedAllocationTest.CursorWalkFindsEveryNeedleAtAFixedPerCallCost`.
         */
        [[nodiscard]] const std::byte *
        find_pattern(Region region, const Pattern &pattern, std::size_t occurrence = 1) noexcept;
    } // namespace unchecked

} // namespace DetourModKit::scan

#endif // DETOURMODKIT_SCAN_HPP
