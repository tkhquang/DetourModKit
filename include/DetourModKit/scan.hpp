#ifndef DETOURMODKIT_SCAN_HPP
#define DETOURMODKIT_SCAN_HPP

/**
 * @file scan.hpp
 * @brief The public scan surface: pattern matching, candidate-ladder resolution, and the
 *        standalone RIP-relative, string-xref, code-constant, and export resolvers.
 * @details `Pattern` compiles an AOB mini-DSL string and holds its bytes and mask inline.
 *          @ref scan locates one `Pattern` in a `Region`. @ref resolve runs an ordered
 *          @ref Candidate ladder until one strategy produces a confident address. The free
 *          resolvers expose a single backend for a caller that holds one piece of evidence.
 *          The resolution note in docs/design/resolution.md owns the mechanism.
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
     * @class Pattern
     * @brief A value-semantic compiled AOB pattern that owns its bytes and mask inline.
     * @details Construct with compile() (runtime, returns Result) or literal() (compile-time, returns by value). The
     *          compiled form exposes its bytes, mask, result offset, and the cached compile-time anchor so the scan
     *          engine can prefilter and verify without re-parsing, and matches_at() applies the same masked compare
     *          the engine uses for a single position. Copyable and trivially comparable in cost to its inline arrays.
     * @note The compile() / literal() factories are setup/control-plane; size(), the byte/mask/anchor accessors, and
     *       matches_at() are callback-safe (pure value reads with no allocation, I/O, or locking).
     */
    class Pattern
    {
    public:
        /**
         * @brief Compiles a runtime AOB DSL string.
         * @param dsl The whitespace-separated pattern, e.g. "48 8B 05 ?? ?? ?? ??".
         * @return A Pattern on success, or Error{ErrorCode::BadPattern} when the string is malformed/empty/over-cap.
         * @details Never undefined behaviour on bad input: a parse failure becomes a recoverable Error. The specific
         *          parse status is stashed in the Error's extra slot so a caller can distinguish, for example, an
         *          over-long pattern from an invalid token without the resolver surface growing more error codes.
         * @note Setup/control-plane only -- compile patterns at init, not inside a hot callback.
         */
        [[nodiscard]] static Result<Pattern> compile(std::string_view dsl)
        {
            const detail::PatternParse parsed = detail::parse_pattern(dsl);
            if (parsed.status != detail::PatternStatus::Ok)
            {
                return std::unexpected(
                    Error{ErrorCode::BadPattern, "scan::compile", 0, static_cast<std::uint32_t>(parsed.status)});
            }
            return Pattern{parsed.buffer};
        }

        /**
         * @brief Compiles an in-source AOB DSL literal at compile time.
         * @param dsl A constant-expression pattern string.
         * @return The compiled Pattern by value.
         * @details consteval, so a malformed literal is a compile error rather than a runtime Result to deref. On any
         *          non-Ok parse status the throw below is evaluated during constant evaluation, which makes the call a
         *          non-constant expression and fails the build at the offending literal site. A valid literal never
         *          reaches the throw and compiles to a plain Pattern value, keeping hard-coded candidate ladders
         *          constexpr-friendly.
         * @note Compile-time only: consteval, so it runs during compilation and has no runtime call site to classify.
         */
        [[nodiscard]] static consteval Pattern literal(std::string_view dsl)
        {
            const detail::PatternParse parsed = detail::parse_pattern(dsl);
            if (parsed.status != detail::PatternStatus::Ok)
            {
                throw "DetourModKit: scan::Pattern::literal() received a malformed AOB pattern";
            }
            return Pattern{parsed.buffer};
        }

        /// Number of bytes in the compiled pattern.
        [[nodiscard]] constexpr std::size_t size() const noexcept { return m_data.length; }

        /**
         * @brief The `|` result offset as an index into the fixed byte stream (0 when there is no offset marker).
         * @details For a pattern with bounded jumps the resolver adds the actual gap bytes at match time, so the
         *          returned address still points at the intended run; this reports only the fixed-byte portion.
         */
        [[nodiscard]] constexpr std::size_t offset() const noexcept { return m_data.offset; }

        /**
         * @brief View over the compiled fixed pattern bytes, all segments concatenated (length == size()).
         * @details Gap bytes are not stored, so for a jump-bearing pattern this is the fixed bytes only, not the span.
         */
        [[nodiscard]] constexpr std::span<const std::byte> bytes() const noexcept
        {
            return std::span<const std::byte>(m_data.bytes.data(), m_data.length);
        }

        /// View over the per-byte match mask paralleling bytes() (length == size()).
        [[nodiscard]] constexpr std::span<const std::byte> mask() const noexcept
        {
            return std::span<const std::byte>(m_data.mask.data(), m_data.length);
        }

        /// True when the pattern carries at least one bounded jump (and therefore more than one segment).
        [[nodiscard]] constexpr bool has_jumps() const noexcept { return m_data.jump_count > 0; }

        /// Number of fixed segments the pattern splits into (1 for a plain pattern; one more than the jump count).
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

        /// True when the pattern has at least one fully-known byte the prefilter can anchor on.
        [[nodiscard]] constexpr bool has_anchor() const noexcept { return m_data.anchor < m_data.length; }

        /// Index of the rarest fully-known byte; only meaningful when has_anchor() is true.
        [[nodiscard]] constexpr std::size_t anchor_index() const noexcept { return m_data.anchor; }

        /// The anchor byte value, or a zero byte when has_anchor() is false.
        [[nodiscard]] constexpr std::byte anchor_byte() const noexcept
        {
            return has_anchor() ? m_data.bytes[m_data.anchor] : std::byte{0x00};
        }

        /**
         * @brief Tests whether the pattern matches the bytes at the start of @p window, honoring any bounded jumps.
         * @param window The candidate byte window; must be at least min_match_length() bytes for a match to be
         * possible.
         * @return True when the pattern (every segment placed across its gaps) matches beginning at the window start.
         * @details Applies the same compare the scan engine uses, expressed per byte: a position matches when
         *          (memory ^ pattern) & mask is zero for every byte, so wildcard bytes (mask 0x00) always agree and a
         *          nibble mask (0xF0 / 0x0F) compares only the fixed nibble. A jump-free pattern is a single
         *          fixed-width compare; a pattern with bounded jumps runs the same bounded backtracking search the
         *          engine uses,
         *          trying each gap width in ascending order. A window too short to hold the pattern cannot match.
         * @note Callback-safe -- a pure masked byte compare with no allocation, I/O, or locking.
         */
        [[nodiscard]] constexpr bool matches_at(std::span<const std::byte> window) const noexcept
        {
            return detail::matches_buffer_at(m_data, window);
        }

    private:
        friend constexpr const detail::PatternBuffer &detail::pattern_buffer(const Pattern &pattern) noexcept;

        // Private so the only ways to obtain a Pattern are the validating factories; a default-constructed or
        // arbitrary-buffer Pattern can never exist.
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
     * @enum Pages
     * @brief Which page-protection class a page-gated scan accepts.
     * @details A scan over arbitrary process memory must walk the OS page map and skip pages it cannot safely read.
     *          This flag selects how wide that acceptance is. Readable accepts every committed readable page (.text +
     *          .rdata / .data + read-only heaps), so one pass covers both code and data candidates. Executable narrows
     *          to committed execute-readable code pages only, which is the correct, lower-false-positive choice when a
     *          signature must land on code (a function prologue, an instruction site); a match in a data page is then
     *          a coincidence the narrower gate rejects outright.
     */
    enum class Pages : std::uint8_t
    {
        /// Every committed readable page (a superset of Executable); the default for a data-capable sweep.
        Readable,
        /// Committed execute-readable code pages only.
        Executable
    };

    /**
     * @brief Largest architectural x86-64 instruction length, in bytes.
     * @details x86-64 instructions are at most 15 bytes long. RIP-relative helpers validate their disp32 layout against
     *          this bound before using the instruction length as the next-instruction base.
     */
    inline constexpr std::size_t MAX_X86_INSTRUCTION_LENGTH = 15;

    /**
     * @brief Tests whether a disp32 field fits within an x86-64 instruction of the given length.
     * @param displacement_offset Byte offset of the signed 4-byte displacement field.
     * @param instruction_length Total instruction length in bytes.
     * @return True when the field lies entirely within a non-empty instruction no longer than
     *         @ref MAX_X86_INSTRUCTION_LENGTH.
     * @details This checks structural bounds only; the caller remains responsible for supplying an opcode whose operand
     *          is actually RIP-relative. Subtraction after the offset comparison avoids unsigned-overflow arithmetic.
     * @note Callback-safe: pure constexpr arithmetic.
     */
    [[nodiscard]] constexpr bool is_valid_rip_relative_layout(std::size_t displacement_offset,
                                                              std::size_t instruction_length) noexcept
    {
        return instruction_length <= MAX_X86_INSTRUCTION_LENGTH && displacement_offset <= instruction_length &&
               instruction_length - displacement_offset >= sizeof(std::int32_t);
    }

    /**
     * @enum SimdLevel
     * @brief The highest SIMD verification tier the engine selects at runtime.
     */
    enum class SimdLevel : std::uint8_t
    {
        /// Byte-by-byte verification (no SIMD).
        Scalar,
        /// SSE2 (16 bytes per iteration).
        Sse2,
        /// AVX2 (32 bytes per iteration, with an SSE2 + scalar tail).
        Avx2,
        /// AVX-512F + AVX-512BW (64 bytes per iteration). Opt-in: a DMK_ENABLE_AVX512 build on an AVX-512 host.
        Avx512
    };

    /**
     * @brief Returns the enumerator name for a SimdLevel.
     * @param level The tier.
     * @return A static string view; "Unknown" for an out-of-range value.
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
     * @brief Reports the SIMD tier find-pattern matching uses at runtime.
     * @details Reflects both compile-time support (which intrinsics were built) and runtime CPU detection (CPUID plus
     *          OS XGETBV). Reports Avx512 only when the library was built with the opt-in DMK_ENABLE_AVX512 option and
     *          the host has AVX-512F + AVX-512BW; otherwise it reports the highest available lower tier.
     * @note Callback-safe: pure CPU-feature read, no allocation or locking.
     */
    [[nodiscard]] SimdLevel active_simd_level() noexcept;

    /**
     * @enum StringEncoding
     * @brief Byte encoding of an anchor string as it is stored in the image.
     */
    enum class StringEncoding : std::uint8_t
    {
        /**
         * @brief The literal is stored as the query's bytes verbatim (char / std::string literals).
         * @details Byte-transparent: the query text is searched for exactly as given, so a caller may anchor on a byte
         *          sequence that is not well-formed UTF-8.
         */
        Utf8,
        /**
         * @brief The literal is stored as UTF-16LE (wchar_t / L"" on Windows).
         * @details The query text is UTF-8 and is transcoded, so it must be well-formed: a supplementary code point
         *          becomes a surrogate pair, and ill-formed input returns @ref ErrorCode::MalformedQueryText rather
         *          than searching for something else.
         */
        Utf16le
    };

    /**
     * @enum XrefReturn
     * @brief What a resolved string cross-reference returns.
     */
    enum class XrefReturn : std::uint8_t
    {
        /// Exact address of the instruction that loads the string.
        ReferencingInstruction,
        /**
         * @brief Enclosing-function entry of the referencing instruction.
         * @details Authoritative x64 `.pdata` bounds via RtlLookupFunctionEntry (following chained fragments to the
         *          primary function), with a bounded RET/INT3 prologue back-scan as the fallback for leaf functions and
         *          code regions with no registered exception table.
         */
        EnclosingFunction,
        /**
         * @brief Address of the global data slot a `mov [rip+slot], reg` stores the loaded string pointer into.
         * @details Applies when the unique reference is a `lea reg, [rip+string]` shortly followed by that store; it
         *          resolves a cached global string pointer rather than the load site. Reports
         *          ErrorCode::StoreNotFound when no such store follows the reference.
         */
        StringPointerSlot
    };

    /**
     * @struct StringRefQuery
     * @brief A string-reference anchor query, with the string text borrowed for the duration of the call.
     * @details Anchors a target on an immutable string literal in the image's read-only data, then resolves the unique
     *          RIP-relative reference to it. Strings survive game updates far better than the code bytes around them,
     *          so a string xref is the most update-resilient anchor source. @ref text is a non-owning view into caller
     *          storage; this query is for the immediate find_string_xref() call. A stored string-xref Candidate owns
     *          its literal independently (see Candidate::string_xref) and rebuilds a view of this shape at resolve
     *          time.
     */
    struct StringRefQuery
    {
        /**
         * @brief Literal content (no quotes); borrowed for the call.
         * @details Must not contain an embedded NUL on either encoding: it would contradict @ref require_terminator and
         *          cannot occur in the C string literals these anchors name, so it returns
         *          @ref ErrorCode::MalformedQueryText.
         */
        std::string_view text;
        /// How it is stored in the image, and therefore how @ref text is interpreted (see @ref StringEncoding).
        StringEncoding encoding = StringEncoding::Utf8;
        /**
         * @brief Match a trailing NUL so a prefix of a longer literal is not matched (e.g. "Player" inside
         *        "PlayerController").
         */
        bool require_terminator = true;
        /// Selects the exact instruction site, the enclosing-function heuristic, or the cached global pointer slot.
        XrefReturn return_mode = XrefReturn::ReferencingInstruction;
        /**
         * @brief Selects the phase-2 reference scan breadth.
         * @details false (default) runs the fast, desync-immune all-offset shape scan that recognizes the REX.W
         *          `lea`/`mov reg, [rip+disp32]` forms. true keeps that scan and also runs a Zydis-verified linear
         *          sweep that recognizes the rarer RIP-relative shapes (`cmp [rip+d], imm`, `push [rip+d]`, a no-REX
         *          `lea`/`mov`, ...), at the cost of a full decode per instruction. Derived return modes may still run
         *          that broad sweep as a confirmation pass when this flag is false, so a shape-local narrow hit is not
         *          certified while a rarer second reference exists.
         */
        bool broad_match = false;
    };

    /**
     * @brief Resolves a string-reference anchor inside one mapped image.
     * @param query The string and how to interpret its reference.
     * @param scope Module image to search; defaults to the host executable. A scope confined to neither one mapped
     *        image nor one reserved allocation returns @ref ErrorCode::NotAuthoritative. This entry point takes no
     *        exclusion span and no page selector, so a confined scope is the only remedy.
     * @return The referencing-instruction (or enclosing-function, or pointer-slot) address, or an Error.
     * @details Two fail-closed phases. Phase 1 locates the single occurrence of @p query.text in the scope's readable
     *          pages. Zero returns @ref ErrorCode::StringNotFound, and more than one returns
     *          @ref ErrorCode::StringAmbiguous. Phase 2 finds the single RIP-relative reference whose resolved target
     *          equals that string address. Zero returns @ref ErrorCode::NoReference, and more than one returns
     *          @ref ErrorCode::AmbiguousReference. An observed second copy or second reference stays ambiguous even
     *          when the sweep was also truncated. A truncated sweep that observed no multiplicity certifies neither
     *          absence nor uniqueness and returns @ref ErrorCode::IncompleteScan. Text that cannot be encoded as
     *          asked returns
     *          @ref ErrorCode::MalformedQueryText. An out-of-range @ref StringRefQuery::encoding or
     *          @ref StringRefQuery::return_mode returns @ref ErrorCode::InvalidArg before phase 1 starts. The result
     *          is ASLR-correct because the reference is RIP-relative.
     * @note Phase 1 excludes @p query.text's own storage when that storage lies inside @p scope. If the caller's
     *       buffer is the only copy in scope, the result is @ref ErrorCode::StringNotFound. Anchor on a literal that
     *       the scanned image owns.
     * @note With @ref StringRefQuery::broad_match false, @ref XrefReturn::ReferencingInstruction reports uniqueness
     *       among the fast REX.W `lea`/`mov reg, [rip+disp32]` shapes only. A derived return
     *       (@ref XrefReturn::EnclosingFunction or @ref XrefReturn::StringPointerSlot) runs a broad confirmation
     *       sweep after a single narrow hit, so a rarer second reference fails closed as
     *       @ref ErrorCode::AmbiguousReference. That sweep does not promote a broad-only reference into a hit. Set
     *       @ref StringRefQuery::broad_match to accept the rarer shapes. @ref anchor::Anchor::xref_broad_match and
     *       @ref anchor::ScanProfile::default_broad_string_xref expose the same knob.
     * @note Not noexcept: the broad-match phase may allocate during its decode. Setup/control-plane only.
     */
    [[nodiscard]] Result<Address> find_string_xref(const StringRefQuery &query, Region scope = Region::host());

    /**
     * @brief Resolves a named export to its address through one module's PE Export Address Table.
     * @param export_name The exact export symbol, for example "Sleep". PE export names are case-sensitive.
     * @param module The mapped image whose export directory to search; defaults to the host executable. An export
     *               usually lives in a different module from the code a mod scans, so pass the export's own module,
     *               for example @ref Region::module_named("kernel32.dll").
     * @return The absolute address of the exported symbol, or an Error.
     * @details The walk parses the mapped image's own IMAGE_EXPORT_DIRECTORY. It never calls GetProcAddress, so it
     *          never enters the loader and never runs a DllMain. Every RVA is bound-checked against the image and
     *          every read is guarded, so a truncated or hostile export section returns an Error, never a host fault.
     *          A missing export directory, an absent name, an ordinal-only export, an out-of-image RVA, and an empty
     *          @p export_name all return @ref ErrorCode::ExportNotFound. A null or invalid module image returns
     *          @ref ErrorCode::InvalidRange. A forwarded export returns @ref ErrorCode::ExportForwarded instead of
     *          the address of the forwarder string, because only the loader can follow a forwarder.
     * @note Allocation-free and noexcept: the name compare runs against a fixed-length window. Setup/control-plane
     *       only by convention, because it queries a module image, not a per-frame quantity.
     */
    [[nodiscard]] Result<Address> resolve_export(std::string_view export_name, Region module = Region::host()) noexcept;

    /**
     * @enum OperandKind
     * @brief Which operand field @ref read_code_constant extracts.
     */
    enum class OperandKind : std::uint8_t
    {
        /// An immediate operand (e.g. the imm of `add reg, imm`).
        Immediate,
        /// A memory operand's displacement (e.g. the disp of `[reg + disp]`).
        MemoryDisplacement
    };

    /**
     * @enum Mode
     * @brief The resolution strategy a Candidate uses to turn a signature into an address.
     * @details The mode is data on the Candidate (the active std::variant alternative), not a function name, so a
     *          ladder can interleave the tiers freely and the resolver dispatches on the active payload. The two byte
     *          tiers (Direct, RipRelative) scan a compiled Pattern; the two text tiers (RttiVtable, StringXref) resolve
     *          a name/literal through a dedicated backend and are unique-only by construction (they fail closed on
     *          ambiguity regardless of the request's require_unique). The enumerator order matches the Candidate
     *          variant alternative order, so Candidate::mode() is a cast of the active index.
     */
    enum class Mode : std::uint8_t
    {
        /// Scan for the Pattern, then add a fixed signed walk-back to the hit (the address IS at the match site).
        Direct,
        /// Scan for the Pattern, then read the RIP-relative disp32 it spans and compute the absolute target.
        RipRelative,
        /// Resolve the primary vtable of an MSVC-mangled type name through the reverse-RTTI walk.
        RttiVtable,
        /// Anchor on an immutable string literal and resolve the unique RIP-relative reference to it.
        StringXref
    };

    /**
     * @enum CandidateOrder
     * @brief How a ScanRequest's ladder is ordered before the resolver tries it.
     * @details AsDeclared preserves the caller's array order. UniqueFirst promotes the tiers least likely to
     *          mis-resolve so a confident hit is reached before a looser fallback is consulted: the unique-only text
     *          tiers (RttiVtable, StringXref) lead, then anchored byte patterns (a fully-known rarest byte makes a
     *          Pattern far more selective), then the remaining byte patterns. Reordering never changes which addresses
     *          are valid: every candidate is still verified (unique-in-scope when required, in-scope, plausibly
     *          resolved), so a promoted candidate can only be tried earlier, never accepted on weaker evidence.
     */
    enum class CandidateOrder : std::uint8_t
    {
        /// Try candidates in the order the caller wrote them.
        AsDeclared,
        /// Try unique-only text tiers, then anchored byte patterns, then the rest; declared order kept within a group.
        UniqueFirst
    };

    /**
     * @brief Returns the enumerator name for a CandidateOrder.
     * @param order The ordering policy.
     * @return A static string view; "Unknown" for an out-of-range value.
     * @note Callback-safe: a pure constexpr value map with no allocation, I/O, or locking.
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

    /**
     * @struct DirectPattern
     * @brief The Direct-tier payload: a compiled Pattern plus the signed walk-back applied to the match.
     */
    struct DirectPattern
    {
        /// The compiled signature to scan for.
        Pattern pattern;
        /// Signed byte delta added to the match (negative walks backward); 0 returns the match itself.
        std::ptrdiff_t walk_back{0};
    };

    /**
     * @struct RipRelativePattern
     * @brief The RipRelative-tier payload: a compiled Pattern plus the disp32 location and instruction length.
     * @details The resolved target is `(match + instruction_length) + sign_extend(disp32 @ (match + displacement_at))`,
     *          read under a fault guard, so a corrupt displacement is a miss rather than a host fault.
     */
    struct RipRelativePattern
    {
        /// The compiled signature to scan for.
        Pattern pattern;
        /// Byte offset from the match to the signed 4-byte displacement field.
        std::ptrdiff_t displacement_at{0};
        /// Total length of the referencing instruction (the next-IP base for the disp).
        std::size_t instruction_length{0};
    };

    /**
     * @struct RttiVtable
     * @brief The RttiVtable-tier payload: the MSVC-mangled type name to resolve through the reverse-RTTI walk. Owned.
     * @details Unique-only: an ambiguous name (two primaries) fails closed and the ladder falls through.
     */
    struct RttiVtable
    {
        /// The MSVC decorated type name, e.g. ".?AVCameraManager@@". Owned.
        std::string mangled;
    };

    /**
     * @struct StringXref
     * @brief The StringXref-tier payload: an OWNED string literal plus the reference-resolution facets.
     * @details The literal is held as an owned std::string (not the borrowed std::string_view of StringRefQuery)
     *          because a Candidate is stored and resolved later, long after the expression that built it; the resolver
     *          rebuilds a StringRefQuery view over this owned text at resolve time. Unique-only: a pooled literal or a
     *          second reference fails closed.
     */
    struct StringXref
    {
        /// The exact string content to anchor on (no quotes). Owned.
        std::string text;
        /// How the literal is stored in the image.
        StringEncoding encoding{StringEncoding::Utf8};
        /// Match a trailing NUL so a prefix of a longer literal is not matched.
        bool require_terminator{true};
        /// Instruction site, enclosing function, or cached global pointer slot.
        XrefReturn return_mode{XrefReturn::ReferencingInstruction};
        /// Keep the lea/mov shape scan and add the Zydis broad sweep for rarer reference shapes.
        bool broad_match{false};
    };

    /**
     * @class Candidate
     * @brief One resilience tier in a resolution ladder: a strategy plus the signature it resolves, owning its strings.
     * @details The payload is a std::variant over the four typed tiers, so the (mode, payload) pairing is coherent by
     *          construction: a Direct candidate cannot accidentally carry a string-xref query, and there are no
     *          parallel optional fields that can drift out of sync. The four factories are the only way to build one
     *          (the default
     *          constructor and the variant-taking constructor are private, the payload is private, and the class is not
     *          an aggregate), so a Candidate can only exist with a valid alternative. Every owned string (the name, the
     *          RttiVtable mangled name, the StringXref literal) is copied in, so a winning Hit or a stored ladder never
     *          aliases caller storage that later goes out of scope.
     */
    class Candidate
    {
    public:
        /// The active variant payload type. The alternative order matches the Mode enumerator order.
        using Payload = std::variant<DirectPattern, RipRelativePattern, RttiVtable, StringXref>;

        /**
         * @brief A Direct byte-scan candidate: the resolved address is at the match site plus a fixed walk-back.
         * @note Setup/control-plane only: builds an owned Candidate (string + Pattern copy); assemble ladders at init.
         */
        [[nodiscard]] static Candidate direct(std::string name, Pattern pattern, std::ptrdiff_t walk_back = 0)
        {
            return Candidate{std::move(name), DirectPattern{std::move(pattern), walk_back}};
        }

        /**
         * @brief A RIP-relative byte-scan candidate: the resolved address is read from a disp32 the match spans.
         * @param displacement_at Byte offset from the match to the signed 4-byte displacement field; must be >= 0.
         * @param instruction_length Total length of the referencing instruction; must be no more than 15 bytes and
         *        contain the disp32 field.
         * @throws std::invalid_argument when the declared layout is invalid or the matched suffix does not span the
         *         complete disp32 field.
         * @details Setup/control-plane only: it builds an owned Candidate. Assemble each ladder at init. The matched
         *          evidence must cover the disp32 it authorizes. The resolver computes
         *          match + instruction_length + disp from one immutable sweep snapshot, never from a post-sweep
         *          reread.
         * @note The manifest loader validates the same bound through @ref is_valid_rip_relative_layout, so a bad
         *       manifest fails closed with an error value instead of a throw.
         */
        [[nodiscard]] static Candidate rip_relative(std::string name, Pattern pattern, std::ptrdiff_t displacement_at,
                                                    std::size_t instruction_length)
        {
            if (displacement_at < 0 ||
                !is_valid_rip_relative_layout(static_cast<std::size_t>(displacement_at), instruction_length) ||
                detail::min_match_suffix_length(detail::pattern_buffer(pattern)) <
                    static_cast<std::size_t>(displacement_at) + sizeof(std::int32_t))
            {
                throw std::invalid_argument(
                    "scan::Candidate::rip_relative: the matched suffix must span a valid x86-64 RIP disp32 "
                    "(0 <= displacement_at, displacement_at + 4 <= instruction_length <= 15, and the pattern's "
                    "shortest suffix from the result marker covers displacement_at + 4 bytes)");
            }
            return Candidate{std::move(name),
                             RipRelativePattern{std::move(pattern), displacement_at, instruction_length}};
        }

        /**
         * @brief An RTTI-vtable candidate: resolves the primary vtable of an MSVC-mangled type name.
         * @note Setup/control-plane only: copies the name and mangled query strings.
         */
        [[nodiscard]] static Candidate rtti_vtable(std::string name, std::string mangled)
        {
            return Candidate{std::move(name), RttiVtable{std::move(mangled)}};
        }

        /**
         * @brief A string-xref candidate with default facets (UTF-8, referencing-instruction, terminator-required).
         * @note Setup/control-plane only: copies the name and literal query strings.
         */
        [[nodiscard]] static Candidate string_xref(std::string name, std::string literal)
        {
            return Candidate{std::move(name), StringXref{std::move(literal)}};
        }

        /**
         * @brief A string-xref candidate carrying explicit facets (encoding, return mode, terminator, broad match).
         * @details The query's borrowed text is copied into the Candidate's owned StringXref payload, so the Candidate
         *          outlives the StringRefQuery and its backing storage. The remaining facets are taken verbatim.
         * @note Setup/control-plane only: copies the name and the query literal.
         */
        [[nodiscard]] static Candidate string_xref(std::string name, StringRefQuery query)
        {
            return Candidate{std::move(name),
                             StringXref{std::string{query.text}, query.encoding, query.require_terminator,
                                        query.return_mode, query.broad_match}};
        }

        /// Human-readable label; carried verbatim into the winning Hit.
        [[nodiscard]] const std::string &name() const noexcept { return m_name; }

        /// The resolution strategy this tier uses (a cast of the active variant alternative index).
        [[nodiscard]] Mode mode() const noexcept { return static_cast<Mode>(m_payload.index()); }

        /// The full variant payload, for the resolver's std::visit dispatch.
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
        // Private so the four validating factories are the only construction path; a stray `Candidate{...}` does not
        // compile, and the (name, payload) coherence is established at the factory.
        Candidate(std::string name, Payload payload) : m_name{std::move(name)}, m_payload{std::move(payload)} {}

        std::string m_name;
        Payload m_payload;
    };

    // The resolver derives Mode from the active variant index, so the alternative order MUST track the Mode order. Pin
    // it here: a future reorder of either list that breaks the mapping fails the build rather than silently misrouting
    // a candidate to the wrong backend.
    static_assert(std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Mode::Direct), Candidate::Payload>,
                                 DirectPattern>);
    static_assert(
        std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Mode::RipRelative), Candidate::Payload>,
                       RipRelativePattern>);
    static_assert(
        std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Mode::RttiVtable), Candidate::Payload>,
                       RttiVtable>);
    static_assert(
        std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Mode::StringXref), Candidate::Payload>,
                       StringXref>);

    /**
     * @struct CodeConstant
     * @brief Declares a constant encoded in the engine's machine code so DMK can re-derive it after a patch.
     * @details The code-side twin of the RTTI self-heal: where a struct stride or field displacement is an immediate or
     *          `[reg + disp]` in a dispatch loop, declare the candidate ladder that lands ON the instruction plus which
     *          operand to read, and read_code_constant() decodes the live instruction and returns the current value, so
     *          a consumer stops hand-reading the immediate every patch.
     */
    struct CodeConstant
    {
        /// Candidate ladder that resolves to an execute-readable instruction site. Borrowed.
        std::span<const Candidate> site;
        /// Which operand field to read: an immediate or a memory displacement.
        OperandKind kind = OperandKind::Immediate;
        /// Index into the instruction's VISIBLE operands, as counted in a disassembler.
        std::uint8_t operand_index = 0;
        /// 0 preserves the decoded value; 1 through 8 narrows a non-RIP constant to low bytes and sign-extends.
        std::uint8_t byte_width = 0;
        /// Last-known value, for telemetry/baseline ONLY; never returned in place of a live decode.
        std::int64_t nominal = 0;
        /// Set true to make @ref nominal meaningful (do not overload nominal == 0 as "unset").
        bool has_nominal = false;
    };

    /**
     * @brief Resolves @p code_constant.site, decodes the instruction there, and returns the requested operand's value.
     * @param code_constant The code-constant declaration.
     * @param scope Module image to resolve the site in; defaults to the host executable.
     * @return The decoded value (sign-extended), or an Error.
     * @details Always decodes and returns the LIVE operand; @c nominal is never a short-circuit, so a same-shape
     *          different-value drift (e.g. a stride 232 -> 240) is reported as the new value, which is the point.
     *          Fail-closed: a candidate whose final site is not execute-readable is skipped so a later ladder rung can
     *          resolve; if the selected site loses executable protection before decoding, or its decoded instruction
     *          crosses into a non-executable page, it returns DecodeFailed. A site that no longer decodes
     *          (DecodeFailed), whose operand is the wrong kind (UnexpectedShape), or whose operand index is out of
     *          range (OperandOutOfRange) also returns a typed error rather than a guess. An out-of-range
     *          @ref CodeConstant::kind or @ref CodeConstant::byte_width returns @ref ErrorCode::InvalidArg before site
     *          resolution. A RIP-relative memory operand is resolved to its absolute target without narrowing.
     *          The value decodes from a fresh snapshot after site resolution.
     *          A byte rung must still match its physical span and resolve the decoded site at that epoch.
     *          Otherwise, the function returns @ref ErrorCode::EvidenceMismatch.
     *          A wildcarded operand byte at the selected site may drift. The function returns its current value.
     *          T-CODE-EPOCH supplies the permanent proof.
     * @note Not noexcept: resolving the site allocates. Setup/control-plane only.
     */
    [[nodiscard]] Result<std::int64_t> read_code_constant(const CodeConstant &code_constant,
                                                          Region scope = Region::host());

    /**
     * @brief Ceiling on the winning-span bytes a @ref WinningEvidence can carry.
     * @details A mutation baseline is compared byte for byte, so it must hold the WHOLE winning span or it would
     *          authorize a write on partial evidence. Evidence longer than this is reported truncated: still valid for
     *          read-only resolution, never usable to authorize a mutation or to seed a strict baseline.
     */
    inline constexpr std::size_t MAX_MUTATION_WITNESS_BYTES = 256;

    /**
     * @struct WinningEvidence
     * @brief The literal bytes present at the winning match span, captured during the match that produced them.
     * @details Content evidence, as opposed to the layout evidence in @ref ImageIdentity: it records what the target
     *          actually contained, including the concrete values that matched wildcard positions and the bytes a
     *          variable-length gap skipped over. That is what lets a caller distinguish a same-layout image whose code
     *          was changed under it from one that is genuinely unchanged, which no PE-header identity can do.
     *
     *          Captured from the same traversal that matched, never a re-read, so it witnesses the span the resolver
     *          actually accepted rather than whatever occupies that address later.
     */
    struct WinningEvidence
    {
        /// The captured span, valid over the first @ref length elements; trailing elements are zero.
        std::array<std::byte, MAX_MUTATION_WITNESS_BYTES> bytes{};
        /// How many leading elements of @ref bytes are meaningful; 0 when nothing was captured.
        std::uint16_t length = 0;
        /**
         * @brief True when the winning span exceeded @ref MAX_MUTATION_WITNESS_BYTES and was not captured.
         * @details Set with @ref length 0: a partial prefix would compare equal against a prefix baseline and silently
         *          weaken the gate, so an over-long span carries no evidence at all rather than misleading evidence.
         */
        bool truncated = false;

        /// True when a complete, internally valid winning span was captured.
        [[nodiscard]] constexpr bool present() const noexcept
        {
            return length != 0 && length <= MAX_MUTATION_WITNESS_BYTES && !truncated;
        }

        /// The captured bytes as a span; empty unless @ref present.
        [[nodiscard]] constexpr std::span<const std::byte> span() const noexcept
        {
            if (!present())
            {
                return {};
            }
            return std::span<const std::byte>{bytes.data(), length};
        }

        /**
         * @brief Value equality over the captured prefix and the truncation flag.
         * @details Fails closed on a malformed value rather than walking it: @ref length is public and is not
         *          clamped on assignment, so a hand-built evidence whose length exceeds
         *          @ref MAX_MUTATION_WITNESS_BYTES, or which claims bytes while @ref truncated, would otherwise read
         *          past @ref bytes. Such a value compares equal to nothing, including a copy of itself, so it can
         *          never satisfy a baseline comparison.
         */
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

    /**
     * @struct Hit
     * @brief A resolved address paired with the owning name and mode of the candidate that produced it.
     * @details @ref winning_name remains valid for the lifetime of the Hit.
     */
    struct Hit
    {
        /// The resolved absolute address.
        Address address;
        /// A copy of the winning candidate's name.
        std::string winning_name;
        /// The resolution mode of the winning candidate.
        Mode winning_mode = Mode::Direct;
        /**
         * @brief The literal bytes at the span this candidate matched; absent for a backend that matches no span.
         * @details Only a byte-pattern tier witnesses a span. An RTTI, export, or string-xref rung resolves through a
         *          structure rather than a literal run, so it leaves this absent and cannot seed a mutation baseline.
         */
        WinningEvidence evidence{};
    };

    /**
     * @enum FallbackPolicy
     * @brief How strictly hooked-prologue recovery confirms the identity of a recovered target.
     * @details Hooked-prologue recovery rebuilds a Direct candidate's prologue as an inline-hook jump shape and
     *          resolves the single site that uniquely matches. That structural gate (a unique rebuilt match, a decoded
     *          redirect into executable memory, an in-scope walk-back) is strong but address-blind: a game reshape can
     *          leave a different function whose surviving literal tail coincidentally matches and which is itself
     *          inline-hooked, so the rebuilt pattern resolves uniquely to the wrong near-twin. FallbackPolicy chooses
     *          what happens after structural recovery, mirroring the anchor validator discipline
     *          (@ref anchor::Anchor::require_validator): pair a @ref FallbackWitness with RequireIdentity to fail
     *          closed on an unconfirmed site instead of trusting a possibly-wrong one.
     */
    enum class FallbackPolicy : std::uint8_t
    {
        /// Recovery disabled: a full direct miss stays a miss.
        Off,
        /// Recover structurally; log a rejecting @ref FallbackWitness but still return the address.
        WarnOnly,
        /// Recover structurally, then require a @ref FallbackWitness to confirm the recovered address.
        RequireIdentity,
    };

    /**
     * @brief A post-recovery identity check for hooked-prologue recovery.
     * @details Signature-compatible with @ref anchor::AnchorValidator (a plain function pointer, so one predicate shape
     *          serves the resolver), kept as its own alias because anchor.hpp already includes this header and the
     *          dependency cannot run the other way without a cycle. The recovered absolute address is passed as @p
     *          value; return false to reject it as a coincidental near-twin.
     * @param value The recovered absolute address, as a signed integer (a hook target is a code address).
     * @param context The opaque @ref FallbackWitness::context pointer, forwarded verbatim (nullptr if unused).
     */
    using FallbackValidator = bool (*)(std::int64_t value, const void *context) noexcept;

    /**
     * @struct FallbackWitness
     * @brief The witness a @ref FallbackPolicy runs against a recovered prologue-fallback target.
     * @details A null @ref predicate means "no witness": WarnOnly then behaves as a plain structural recovery, and
     *          RequireIdentity fails closed (it has nothing to confirm the site with). A typical witness corroborates
     *          the recovered address against an independently resolved landmark, or reads a distinguishing byte past
     *          the overwritten prologue.
     */
    struct FallbackWitness
    {
        /// Predicate run on the recovered address; nullptr for no identity check.
        FallbackValidator predicate = nullptr;
        /// Opaque pointer forwarded verbatim to @ref predicate.
        const void *context = nullptr;
    };

    /**
     * @struct ScanRequest
     * @brief A non-owning resolution request: a candidate ladder plus the scope and policy to resolve it under.
     * @details ladder, label, and exclusions are NON-owning views, so a ScanRequest is for a request built and consumed
     *          in one expression (a temporary handed straight to resolve() outlives the call). To store or pass a
     *          request around, use OwnedScanRequest, or build a borrowed one through borrow() so the lifetime-bound
     *          diagnostic can ride its parameters (the attribute cannot annotate a data member).
     */
    struct ScanRequest
    {
        /// Candidates tried in order (after applying @ref order); the first that resolves uniquely wins.
        std::span<const Candidate> ladder;
        /// Optional label for diagnostics; non-owning.
        std::string_view label{};
        /// The memory range to resolve within; defaults to the host process image.
        Region scope = Region::host();
        /// Hooked-prologue recovery mode for a full direct miss (see @ref FallbackPolicy).
        FallbackPolicy fallback_policy = FallbackPolicy::Off;
        /// The identity witness the fallback runs on a recovered site (see @ref FallbackPolicy). Unused when Off.
        FallbackWitness fallback_witness{};
        /// Fail closed on an ambiguous byte match (a second occurrence in scope) rather than taking the first.
        bool require_unique = true;
        /// How the ladder is ordered before it is tried.
        CandidateOrder order = CandidateOrder::AsDeclared;
        /// Page-protection class the Direct / RipRelative byte tiers scan.
        Pages pages = Pages::Readable;
        /**
         * @brief Rejects a candidate whose final resolved address is not on a committed execute-readable page.
         * @details Applies after each byte, RTTI, string-xref, or prologue-recovery backend resolves its final address.
         *          Use it for a hook target that must be executable even when a byte candidate matches code then
         *          transforms its match into a data address. Defaults false because a RipGlobal may intentionally
         *          resolve a data global from an executable instruction reference.
         */
        bool require_executable_result = false;
        /**
         * @brief Caller-owned copies of the ladder's query bytes a match may not come from.
         * @details Only needed for a @ref Pages::Readable scope confined to neither one mapped image nor one reserved
         *          allocation, where a match could otherwise be the query finding its own storage; such a scope
         *          resolves to @ref ErrorCode::NotAuthoritative while this is empty. DMK's own representations (the
         *          ladder, its Patterns, and the compiled forms) are excluded regardless. Non-owning, like @ref ladder.
         */
        std::span<const Region> exclusions{};
    };

    /**
     * @brief Builds a borrowed ScanRequest whose lifetime-bound diagnostic rides its view parameters.
     * @details DMK_LIFETIMEBOUND on the borrowed parameters lets Clang/MSVC warn when a temporary ladder/label is
     *          passed. MinGW GCC has no such attribute, so the build there relies on the owning/borrowed split plus
     *          `-Wdangling-reference`. For a stored or deferred request, prefer OwnedScanRequest.
     * @note Callback-safe: packs the borrowed views into a ScanRequest; noexcept, no allocation.
     */
    [[nodiscard]] ScanRequest borrow(std::span<const Candidate> ladder DMK_LIFETIMEBOUND,
                                     std::string_view label DMK_LIFETIMEBOUND = {}, Region scope = Region::host(),
                                     FallbackPolicy fallback_policy = FallbackPolicy::Off,
                                     FallbackWitness fallback_witness = {}, bool require_unique = true,
                                     CandidateOrder order = CandidateOrder::AsDeclared,
                                     Pages pages = Pages::Readable) noexcept;

    /**
     * @brief Builds a borrowed ScanRequest preset for resolving a CODE (hook) target.
     * @param ladder Candidates tried in order; borrowed for the call.
     * @param label Optional diagnostic label; borrowed.
     * @param scope Module image to resolve within; defaults to the host process image.
     * @param fallback_policy Hooked-prologue recovery strictness (see @ref FallbackPolicy). Defaults to WarnOnly:
     *        recover a target another mod inline-hooked, structurally. Pass RequireIdentity with @p fallback_witness to
     *        fail closed on a recovered site the witness cannot confirm.
     * @param fallback_witness The identity witness the fallback runs on a recovered site (see @ref FallbackWitness).
     * @return A ScanRequest carrying the code-target resolution policy.
     * @details A hook target must land on an instruction, so this preset differs from the default data-capable
     *          request in four ways: `Pages::Executable`, `require_executable_result`,
     *          @ref CandidateOrder::UniqueFirst, and an enabled @p fallback_policy. `require_unique` stays true.
     *          `Pages::Executable` narrows the Direct and RipRelative byte scans only. The final-result gate also
     *          rejects a byte tier that resolves code bytes to a data address, and any RTTI or string-xref result
     *          that is not executable. For a data, RTTI, or string target, use the default ScanRequest or
     *          @ref borrow.
     * @note Callback-safe: packs the borrowed views into a ScanRequest; noexcept, no allocation. For a stored or
     *       deferred request, copy the fields onto an OwnedScanRequest (Pages::Executable,
     *       require_executable_result, UniqueFirst, a WarnOnly fallback policy) so the ladder is owned.
     */
    [[nodiscard]] ScanRequest borrow_code_target(std::span<const Candidate> ladder DMK_LIFETIMEBOUND,
                                                 std::string_view label DMK_LIFETIMEBOUND = {},
                                                 Region scope = Region::host(),
                                                 FallbackPolicy fallback_policy = FallbackPolicy::WarnOnly,
                                                 FallbackWitness fallback_witness = {}) noexcept;

    /**
     * @brief Builds a borrowed ScanRequest preset for a CODE (hook) target that fails closed on unconfirmed recovery.
     * @param ladder Candidates tried in order; borrowed for the call.
     * @param label Optional diagnostic label; borrowed. Required positionally because the witness that follows has no
     *        default -- pass {} for none.
     * @param fallback_witness The identity witness a recovered hooked-prologue site must satisfy. It has no default.
     * @param scope Module image to resolve within; defaults to the host process image.
     * @return A ScanRequest carrying the code-target policy under @ref FallbackPolicy::RequireIdentity.
     * @details The strict counterpart to @ref borrow_code_target. Every field is identical except the fallback
     *          strictness. Recovery runs under @ref FallbackPolicy::RequireIdentity, so a Direct candidate recovered
     *          from an already inline-hooked target resolves only when @p fallback_witness confirms it. A
     *          coincidental near-twin fails closed instead. The witness has no default because RequireIdentity
     *          without a witness fails closed on every recovery, which is a silent always-miss.
     * @note Callback-safe: packs the borrowed views into a ScanRequest; noexcept, no allocation.
     */
    [[nodiscard]] ScanRequest borrow_code_target_strict(std::span<const Candidate> ladder DMK_LIFETIMEBOUND,
                                                        std::string_view label DMK_LIFETIMEBOUND,
                                                        FallbackWitness fallback_witness,
                                                        Region scope = Region::host()) noexcept;

    /**
     * @struct OwnedScanRequest
     * @brief An owning resolution request for stored or deferred resolution.
     * @details Owns its ladder, label, and exclusions, so it is the safe shape to keep inside a registration or any
     *          structure that outlives the expression that built it. The structural guarantee that stored entry points
     *          take OwnedScanRequest (never a borrowed ScanRequest) is the primary defense against dangling views;
     *          @ref view rebuilds a borrowed ScanRequest over this object's storage on demand.
     */
    struct OwnedScanRequest
    {
        /// Owned candidate ladder.
        std::vector<Candidate> ladder;
        /// Owned diagnostic label.
        std::string label;
        /// The resolution scope; defaults to the host image.
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

        /**
         * @brief Returns a borrowed ScanRequest viewing this object's owned storage.
         * @return A ScanRequest whose ladder/label/exclusions alias *this; valid only while this object lives.
         */
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
     * @brief Writes the index permutation @p order implies for @p ladder into @p out.
     * @param order The ordering policy.
     * @param ladder The candidate ladder to order.
     * @param out Destination for the permutation; receives up to min(ladder.size(), out.size()) indices.
     * @return The number of indices written.
     * @details Pure index math, no allocation. UniqueFirst is a stable three-pass partition (unique-only text tiers,
     *          then anchored byte patterns, then the rest), declared order preserved within each group. Every other
     *          value, including an out-of-range one, yields the identity permutation, so a mis-declared order can never
     *          select the UniqueFirst promotion; the fallible @ref resolve boundary rejects it with
     *          @ref ErrorCode::InvalidArg.
     * @note Callback-safe: pure index math, noexcept, no allocation.
     */
    [[nodiscard]] std::size_t order_candidates(CandidateOrder order, std::span<const Candidate> ladder,
                                               std::span<std::size_t> out) noexcept;

    /**
     * @brief Resolves a candidate ladder to a single address, trying each tier until one resolves uniquely.
     * @param request The ladder, scope, and policy to resolve.
     * @return The resolved Hit, or an Error describing why no candidate resolved.
     * @details The whole resolver surface in one call. Candidates are tried in @ref ScanRequest::order order; the first
     *          that (for a byte tier) matches in scope, passes the uniqueness gate when required, and resolves to an
     *          in-scope plausible address, or (for a text tier) resolves through its unique-only backend, wins. When
     *          @ref ScanRequest::require_executable_result is true, every final address must also be execute-readable.
     *          On a full direct miss with a non-Off fallback_policy, each Direct candidate's prologue is rebuilt as a
     *          near/far JMP and retried to recover a target another mod already inline-hooked, subject to the policy's
     *          identity witness. A byte tier whose own sweep was truncated (@ref ErrorCode::BudgetExceeded or
     *          @ref ErrorCode::IncompleteScan) preempts that recovery, because "the direct candidates fully missed" is
     *          the premise recovery rests on and a partly-read scope does not establish it; a recovery sweep that
     *          itself skips a faulted region reports @ref ErrorCode::IncompleteScan rather than a miss. A text tier's
     *          failure (@ref ErrorCode::MalformedQueryText, or @ref ErrorCode::NotAuthoritative or
     *          @ref ErrorCode::IncompleteScan from its own readable sweep) does not preempt recovery, but is reported
     *          in place of the generic miss when nothing resolves. An unconfined Pages::Readable scope that declares
     *          no @ref ScanRequest::exclusions refuses the whole request with @ref ErrorCode::NotAuthoritative before
     *          any candidate is graded. An out-of-range @ref ScanRequest::pages, @ref ScanRequest::order,
     *          @ref ScanRequest::fallback_policy, or StringXref candidate encoding/return mode fails closed with
     *          @ref ErrorCode::InvalidArg rather than selecting a permissive default. May allocate, so it is NOT
     *          noexcept; the only throwing path is allocation failure.
     * @note Setup/control-plane only: a cascade resolve walks the image and is a startup-time operation.
     */
    [[nodiscard]] Result<Hit> resolve(const ScanRequest &request);

    /**
     * @brief Resolves a batch of requests concurrently, returning one Result per request in input order.
     * @param requests The requests to resolve.
     * @param max_workers Upper bound on worker threads (0 = auto-select from hardware concurrency).
     * @return On success, the inner vector holds one @ref Hit-or-Error per input request, in order. On a WHOLE-BATCH
     *         failure (the per-request result container itself could not be allocated under true out-of-memory) the
     *         OUTER Result carries Error{OutOfMemory} and there is no inner vector.
     * @details noexcept by contract, and the two failure layers are distinct so no failure is ever silent. A
     *          PER-REQUEST allocation failure is reported as that slot's Error{OutOfMemory}, and any other per-request
     *          exception leaves that slot at the seeded Error{NoMatch}, so one failing request never sinks the batch.
     *          A WHOLE-BATCH allocation failure -- when even the seeded result vector cannot be built -- is reported on
     *          the outer Result instead of an easily-ignored empty vector, so a caller must unwrap the outer Result
     *          before indexing and cannot silently proceed on a truncated batch. This mirrors @ref hook::install_all,
     *          whose outer Result is likewise the whole-batch signal.
     * @note Setup/control-plane only: spawns a worker pool and allocates; a startup-time batch, not a per-frame call.
     */
    [[nodiscard]] Result<std::vector<Result<Hit>>> resolve_batch(std::span<const ScanRequest> requests,
                                                                 std::size_t max_workers = 0) noexcept;

    /**
     * @brief Scans one Pattern over a known scope and returns the Nth match address.
     * @param pattern The compiled signature.
     * @param scope The memory range to search.
     * @param occurrence Which match to return (1-based). 1 = first match. 0 yields NoMatch.
     * @param pages Which page-protection class to accept (Readable superset by default, or Executable code-only).
     * @return The address of the Nth match (adjusted by the Pattern's `|` offset), or an Error.
     * @details Page-gated. The sweep walks @p scope through the OS page map and reads only committed pages of the
     *          requested class under a fault guard, so an unmapped or guard page inside the scope is skipped instead
     *          of a host fault. A match that straddles two adjacent accepted regions is still found. For the raw
     *          primitive where the caller guarantees readability, use @ref unchecked::find_pattern.
     *
     *          A miss is typed, because "not found" and "not searched" are different answers.
     *          @ref ErrorCode::NoMatch means the sweep traversed the whole scope and the pattern is absent.
     *          @ref ErrorCode::IncompleteScan means a region faulted mid-scan and was skipped, so the pattern can
     *          live in bytes that the sweep never read. @ref ErrorCode::BudgetExceeded means a bounded-jump pattern
     *          spent its backtracking budget before the traversal was exhaustive. Neither truncation is a miss. An
     *          out-of-range @p pages value returns @ref ErrorCode::InvalidArg before the sweep starts.
     *
     *          A @ref Pages::Readable scan returns @ref ErrorCode::NotAuthoritative when its scope is confined to
     *          neither one mapped image nor one reserved allocation and declares no exclusions. Such a scope covers
     *          the caller's own copies of the pattern bytes, which DMK cannot enumerate, so a match can be the query
     *          that finds itself. Confine the scope, scan @ref Pages::Executable, or use the exclusion-taking
     *          overload. DMK always excludes its own query representations, on every scope.
     * @note Setup/control-plane only: walks the scope through the OS page map; a startup-time scan, not a per-frame
     *       call. noexcept; an allocation failure while preparing the scan surfaces as Error{OutOfMemory}.
     */
    [[nodiscard]] Result<Address> scan(const Pattern &pattern, Region scope, std::size_t occurrence = 1,
                                       Pages pages = Pages::Readable) noexcept;

    /**
     * @brief Scans one Pattern over a known scope while excluding caller-owned copies of the query bytes.
     * @param pattern The compiled signature.
     * @param scope The memory range to search.
     * @param exclusions Spans holding the caller's own copies of the query material; a match intersecting one is not
     *        counted. Passing a non-empty span is what makes an otherwise unprovable readable scope authoritative, so
     *        it must actually name every live copy the caller holds.
     * @param occurrence Which match to return (1-based). 1 = first match. 0 yields NoMatch.
     * @param pages Which page-protection class to accept.
     * @return The address of the Nth non-excluded match, or an Error.
     * @details Identical to the four-argument overload except that @p exclusions is added to the set DMK already
     *          excludes for its own query storage. The combined set has 32 slots after merging touching spans; if it
     *          cannot hold every span, the scan fails closed with @ref ErrorCode::NotAuthoritative.
     * @note Setup/control-plane only, same constraints as the four-argument overload.
     */
    [[nodiscard]] Result<Address> scan(const Pattern &pattern, Region scope, std::span<const Region> exclusions,
                                       std::size_t occurrence = 1, Pages pages = Pages::Readable) noexcept;

    /// Common x86-64 RIP-relative opcode prefixes (the bytes preceding the disp32 field), for find_and_resolve.
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
     * @brief Resolves an absolute address from an x86-64 RIP-relative instruction at a known address.
     * @param instruction Address of the first byte of the instruction.
     * @param displacement_offset Byte offset from @p instruction to the disp32 field.
     * @param instruction_length Total length of the instruction in bytes; must be at most 15 and contain the disp32.
     * @return The resolved absolute address (`instruction + instruction_length + disp32`), or an Error.
     * @details The displacement is read under an SEH fault guard. A resolved address that is not a plausible user-mode
     *          pointer is rejected with ErrorCode::ImplausibleTarget rather than returned. For `FF 15`/`FF 25` forms
     *          the resolved value is the pointer slot, itself an in-image address. A malformed field layout returns
     *          ErrorCode::InvalidArg before any read.
     * @note Callback-safe: a guarded read plus pointer arithmetic, no allocation.
     */
    [[nodiscard]] Result<Address> resolve_rip_relative(Address instruction, std::size_t displacement_offset,
                                                       std::size_t instruction_length) noexcept;

    /**
     * @brief Scans forward in @p search for an opcode prefix, then resolves the RIP-relative target that follows it.
     * @param search The region to scan; the disp32 is assumed to immediately follow the matched prefix.
     * @param opcode_prefix The opcode byte sequence to search for.
     * @param instruction_length Total length of the instruction in bytes; must be at most 15 and contain the disp32
     *        that follows @p opcode_prefix.
     * @return The resolved absolute address, or an Error.
     * @details The first resolvable prefix wins. An occurrence whose disp32 resolves to an implausible or unreadable
     *          target is a coincidental decoy, so the scan skips it and continues. The scan fails only after it
     *          exhausts the region, and then reports the last decode failure. The prefix search reads @p search
     *          directly with no page filter, so the caller must guarantee that the region is committed and readable.
     *          To resolve one instruction whose address is uncertain, use @ref resolve_rip_relative, whose
     *          displacement read is guarded. For the `FF 15` and `FF 25` indirect forms the returned address is the
     *          pointer slot, not the final target. The same ImplausibleTarget gate applies. For an ambiguous
     *          signature, anchor through @ref resolve, which enforces per-candidate uniqueness. A malformed field
     *          layout returns @ref ErrorCode::InvalidArg before the sweep starts.
     * @note The prefix scan reads @p search unguarded (caller-guaranteed readable); the displacement read is guarded.
     *       No allocation.
     */
    [[nodiscard]] Result<Address> find_and_resolve_rip_relative(Region search, std::span<const std::byte> opcode_prefix,
                                                                std::size_t instruction_length) noexcept;

    /**
     * @brief Cheap heuristic: does @p addr look like the first byte of a real function body?
     * @param addr Absolute address to probe. A null @p addr returns false without reading memory.
     * @return true if the byte at @p addr is readable and not on the poison list; false otherwise.
     * @details Reads exactly one byte from @p addr under an SEH fault guard and rejects a small blacklist of bytes that
     *          are never the first opcode of a callable x86-64 function: 0x00 (zero-fill / NULL page), 0xCC (int3 pad),
     *          and 0xC2 / 0xC3 (bare RET stub). It returns true for 0xE9 / 0xEB / the 0xFF 0x25 prefix of an indirect
     *          JMP, so a target whose prologue is already overwritten by another inline hook still passes, which is
     *          required for nested-hook scenarios. This is the negative complement to the resolve() prologue-recovery
     *          fallback: use it to filter scan poison (a zero page or an alignment pad) after a resolve.
     * @note Callback-safe: a single guarded byte read, no allocation.
     */
    [[nodiscard]] bool is_likely_function_prologue(Address addr) noexcept;

    /**
     * @struct ImageIdentity
     * @brief An ASLR-insensitive fingerprint of a loaded module's PE build identity.
     * @details Folds the PE timestamp, image size, and section-table layout. The module base is excluded; a malformed
     *          or incomplete header read yields an absent identity.
     * @warning Layout identity, NOT content identity. Every input is an
     *          @c IMAGE_FILE_HEADER / @c IMAGE_OPTIONAL_HEADER / @c IMAGE_SECTION_HEADER field; no section body is
     *          ever read. Executable content patched in place, leaving the timestamp, @c SizeOfImage, and the section
     *          table equal, produces a bit-identical identity. Use @ref WinningEvidence to witness content.
     */
    struct ImageIdentity
    {
        /// PE @c IMAGE_FILE_HEADER::TimeDateStamp of the resolved image (0 when the read failed).
        std::uint32_t timestamp = 0;
        /// PE @c IMAGE_OPTIONAL_HEADER::SizeOfImage of the resolved image (0 when the read failed).
        std::uint32_t size_of_image = 0;
        /// A fold of every section header's name, RVA, virtual size, and characteristics.
        std::uint64_t section_digest = 0;

        /// True when a live image was read (@ref size_of_image is non-zero); a default value is absent.
        [[nodiscard]] constexpr bool present() const noexcept { return size_of_image != 0; }

        /// A single 64-bit token folding all three fields, for a fingerprint or an equality key.
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
     * @brief Reads the ASLR-insensitive @ref ImageIdentity of the module mapped at @p range's base.
     * @param range The module image to identify; defaults to the host executable. Only @p range.base is used, since
     *              the live PE headers there carry the authoritative SizeOfImage and section table.
     * @return The identity, or an absent value when @p range is empty or its PE headers do not validate completely.
     * @details Uses guarded reads and consults no loader.
     * @note Callback-safe: bounded guarded reads of the PE headers, no allocation or loader call.
     */
    [[nodiscard]] ImageIdentity image_identity(Region range = Region::host()) noexcept;

    /**
     * @brief Flattens a resolve Result to its address, or a null Address on failure.
     * @details The single blessed convenience for the address-or-nothing shape. It is a convenience adapter, not the
     *          primary contract: new code resolves through Result and handles the Error. or_null on a happy path is a
     *          smell. Header-inline because Hit and Result<Hit> are complete here.
     * @note Callback-safe: a pure noexcept Result read with no allocation, I/O, or locking.
     */
    [[nodiscard]] inline Address or_null(const Result<Hit> &result) noexcept
    {
        return result ? result->address : Address{};
    }

    /**
     * @brief Flattens a resolve Result to its address, or a caller-chosen fallback on failure.
     * @details The general, non-default form of or_null (`or_null(r)` is `address_or(r, Address{})`). Same
     *          convenience-adapter status: prefer handling the Error in new code.
     * @note Callback-safe: a pure noexcept Result read with no allocation, I/O, or locking.
     */
    [[nodiscard]] inline Address address_or(const Result<Hit> &result, Address fallback = Address{}) noexcept
    {
        return result ? result->address : fallback;
    }

    namespace unchecked
    {
        /**
         * @brief Raw single-pattern scan over a region the caller guarantees is fully readable.
         * @param region The byte range to scan; every byte MUST be committed and readable.
         * @param pattern The compiled signature.
         * @param occurrence Which match to return (1-based). 1 = first match. 0 returns nullptr.
         * @return A pointer to the Nth match (adjusted by the Pattern's `|` offset), or nullptr if not found.
         * @details The unsafe twin of scan(): it performs no page filtering and uses raw SIMD/memchr loads, so an
         *          unreadable byte in @p region faults the host. It is quarantined in `unchecked` precisely because its
         *          contract is "caller proved readability"; the return is a raw pointer, not a Result, because there is
         *          no recoverable error to report. noexcept; an allocation failure preparing the scan returns nullptr.
         * @note Setup/control-plane only: prepares the engine pattern and performs a raw, page-unfiltered scan.
         */
        [[nodiscard]] const std::byte *find_pattern(Region region, const Pattern &pattern,
                                                    std::size_t occurrence = 1) noexcept;
    } // namespace unchecked

} // namespace DetourModKit::scan

#endif // DETOURMODKIT_SCAN_HPP
